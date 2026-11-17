"""A logging TCP tee between a PostgreSQL client and a server: records what the client sends.

Used by scripts/measure_m1.py to measure what psql puts on the wire (docs/m1-proxy.md section 2). It forwards bytes
untouched in both directions and keeps, per client connection, a list of the client's startup and typed messages.
"""
import socket
import struct
import threading


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
        the proxy; "after": the Query is forwarded and `action` runs at once. Each reaches one window of docs/m1-commit-path.md section 4."""
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
        with self.lock:
            return [d for k, d in self.messages if k == "Query"]

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
                    self._note("Parse", body.split(b"\0")[1].decode(errors="replace"))
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
