"""A logging TCP tee between a PostgreSQL client and a server: records what the client sends.

Used by scripts/measure_m1.py to measure what psql puts on the wire (docs/m1-proxy.md section 2). It forwards bytes
untouched in both directions and keeps, per client connection, a list of the client's startup and typed messages.
"""
import socket
import struct
import subprocess
import threading


def ensure_database(port, name, host="127.0.0.1"):
    """Make the database `name` if the server has none (the proxy tests run in a database of their own: the proxy installs an event trigger there that refuses a table without
    a primary key, which would break the differential suites that share the server's `postgres` database)."""
    if name == "postgres":
        return
    have = subprocess.run(["psql", "-At", "-h", host, "-p", str(port), "-U", "postgres", "-d", "postgres", "-c", "select 1 from pg_database where datname = '%s'" % name],
                          capture_output=True, text=True).stdout.strip()
    if have != "1":
        subprocess.run(["psql", "-q", "-h", host, "-p", str(port), "-U", "postgres", "-d", "postgres", "-c", 'create database "%s"' % name], capture_output=True, text=True)


class Tee:
    def __init__(self, upstream_port, host="127.0.0.1"):
        self.host, self.upstream = host, upstream_port
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.messages = []          # (kind, detail) of every client message, in order, all connections
        self.faults = []            # [prefix, when, action] one-shot rules, see fault()
        self.blackhole = False      # when set, a new connection is accepted and then ignored: a server that never answers
        self.socks = []             # every socket opened, so that stop() can close them
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def fault(self, prefix, when, action):
        """Run `action` (kill the proxy) once, at the first Query whose text starts with `prefix`. `when` is "before": the Query is
        dropped, never reaching the server; "reply": the Query is forwarded and the server's answer to it is dropped, never reaching
        the proxy; "after": the Query is forwarded and `action` runs at once; "drop": the Query is dropped and the connection (both ends) closed, `action` unused. Each reaches one window of docs/m1-commit-path.md section 4."""
        with self.lock:
            self.faults.append([prefix, when, action])

    def _fault_for(self, query):
        with self.lock:
            for f in self.faults:
                if query.startswith(f[0]):
                    self.faults.remove(f)
                    return f
        return None

    def stop(self):
        """Close the listening socket and every connection: the server is gone."""
        for how in (lambda x: x.shutdown(socket.SHUT_RDWR), lambda x: x.close()):
            try:
                how(self.sock)
            except OSError:
                pass
        with self.lock:
            socks, self.socks = self.socks, []
        for s in socks:
            for how in (lambda x: x.shutdown(socket.SHUT_RDWR), lambda x: x.close()):
                try:
                    how(s)
                except OSError:
                    pass

    def clear(self):
        with self.lock:
            self.messages = []

    def queries(self):
        """The simple Queries, and the proxy's own commands (BEGIN, COMMIT, PREPARE TRANSACTION...), which it sends as a Parse under the name `cdb_x`."""
        with self.lock:
            out, msgs = [], list(self.messages)
        for i, (k, d) in enumerate(msgs):
            if k == "Query":
                out.append(d)
            elif k == "Parse" and i + 1 < len(msgs) and msgs[i + 1][0] == "Parse.detail" and "name='cdb_x'" in msgs[i + 1][1]:
                out.append(d)
        return out

    def kinds(self):
        with self.lock:
            return [k for k, _ in self.messages]

    def _note(self, kind, detail=None):
        with self.lock:
            self.messages.append((kind, detail))

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    @staticmethod
    def _pump(a, b, held=None):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                if held is not None and held:
                    held.pop()()          # the answer the proxy was to get is dropped, and the proxy is killed instead
                    continue
                b.sendall(d)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _serve(self, c):
        with self.lock:
            self.socks.append(c)
        if self.blackhole:
            return
        u = socket.create_connection((self.host, self.upstream))
        with self.lock:
            self.socks.append(u)
        held = []
        threading.Thread(target=self._pump, args=(u, c, held), daemon=True).start()
        buf, started = b"", False

        def need(n):
            nonlocal buf
            while len(buf) < n:
                d = c.recv(65536)
                if not d:
                    raise EOFError
                buf += d

        try:
            while True:
                if not started:
                    need(4)
                    (ln,) = struct.unpack(">I", buf[:4])
                    need(ln)
                    msg, buf = buf[:ln], buf[ln:]
                    code = struct.unpack(">I", msg[4:8])[0]
                    if code == 80877103:
                        self._note("SSLRequest")
                    elif code == 80877104:
                        self._note("GSSENCRequest")
                    elif code == 80877102:
                        self._note("CancelRequest")
                    else:
                        parts = msg[8:].split(b"\0")
                        kv = {k.decode(): v.decode() for k, v in zip(parts[0::2], parts[1::2]) if k}
                        self._note("Startup", kv)
                        started = True
                    u.sendall(msg)
                    continue
                need(5)
                t = buf[:1]
                (ln,) = struct.unpack(">I", buf[1:5])
                need(1 + ln)
                msg, buf = buf[:1 + ln], buf[1 + ln:]
                body = msg[5:]
                if t == b"Q":
                    text = body[:-1].decode(errors="replace")
                    self._note("Query", text)
                    f = self._fault_for(text)
                    if f is not None:
                        if f[1] == "drop":
                            # the connection to the server is lost, the proxy is not: the Query never arrives and both ends are closed
                            for sock in (u, c):
                                try:
                                    sock.shutdown(socket.SHUT_RDWR)
                                except OSError:
                                    pass
                            return
                        if f[1] == "before":
                            f[2]()
                            continue
                        if f[1] == "reply":
                            held.append(f[2])
                        elif f[1] == "after":
                            u.sendall(msg)
                            f[2]()
                            continue
                elif t == b"P":
                    name, sql, rest = body.split(b"\0", 2)
                    self._note("Parse", sql.decode(errors="replace"))
                    self._note("Parse.detail", "name=%r params=%d" % (name.decode(errors="replace"), struct.unpack(">H", rest[:2])[0]))
                    # the proxy's own commands go by the extended protocol (src/commitpath.cho): the fault rules match a Parse's text as a Query's
                    f = self._fault_for(sql.decode(errors="replace"))
                    if f is not None:
                        if f[1] == "drop":
                            for sock in (u, c):
                                try:
                                    sock.shutdown(socket.SHUT_RDWR)
                                except OSError:
                                    pass
                            return
                        if f[1] == "before":
                            f[2]()
                            continue
                        if f[1] == "reply":
                            held.append(f[2])
                        elif f[1] == "after":
                            u.sendall(msg)
                            f[2]()
                            continue
                elif t == b"B":
                    portal, rest = body.split(b"\0", 1)
                    stmt, rest = rest.split(b"\0", 1)
                    nf = struct.unpack(">H", rest[:2])[0]
                    fmts = struct.unpack(">%dH" % nf, rest[2:2 + 2 * nf])
                    rest = rest[2 + 2 * nf:]
                    npar = struct.unpack(">H", rest[:2])[0]
                    rest = rest[2:]
                    vals = []
                    for _ in range(npar):
                        ln = struct.unpack(">i", rest[:4])[0]
                        rest = rest[4:]
                        if ln < 0:
                            vals.append(None)
                        else:
                            vals.append(rest[:ln].decode(errors="replace") if True else None)
                            rest = rest[ln:]
                    nr = struct.unpack(">H", rest[:2])[0]
                    rf = struct.unpack(">%dH" % nr, rest[2:2 + 2 * nr])
                    self._note("Bind", "stmt=%r portal=%r paramformats=%s params=%s resultformats=%s" % (stmt.decode(errors="replace"), portal.decode(errors="replace"), list(fmts), vals, list(rf)))
                elif t == b"D":
                    self._note("Describe", "%s %r" % (chr(body[0]), body[1:-1].decode(errors="replace")))
                elif t == b"E":
                    self._note("Execute", "portal=%r max=%d" % (body[:-5].decode(errors="replace"), struct.unpack(">I", body[-4:])[0]))
                elif t == b"C":
                    self._note("Close", "%s %r" % (chr(body[0]), body[1:-1].decode(errors="replace")))
                elif t == b"p":
                    self._note("Password", len(body))
                else:
                    self._note(t.decode(errors="replace"), len(body))
                u.sendall(msg)
        except (EOFError, OSError):
            pass
        for s in (u, c):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
