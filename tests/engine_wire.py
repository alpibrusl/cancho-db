#!/usr/bin/env python3
"""The engine's server, over a socket, against the test program (docs/m3-engine.md 6al).

    python3 tests/engine_wire.py ENGINE_SERVER ENGINECHECK STATEMENTS SEED

The oracle is the test program (build/enginecheck), whose answers tests/engine_check.py holds against PostgreSQL's. A history (the differential's fixed statements, then
random ones from its generator) is run through the test program and through the server: a statement with parameters by the extended protocol as cancho-pg sends it
(Parse, Bind, Describe, Execute, Sync), the others as simple queries. For every statement
the two must agree: the command's tag, or the SQLSTATE, or the refusal's tag; the names and type oids of the columns; every row's text; the transaction's state. Then the
server is stopped and the test program reads THE SERVER'S page file: every table must answer as the test program's own file does.

Then, each on a server of its own:

  * killed (SIGKILL) right after a commit was acknowledged, restarted: the rows are there;
  * a connection closed inside a transaction: nothing of it is there, and the next connection writes what it wrote;
  * the extended protocol beyond what the history sends: statements prepared and run by name, each refusal with its tag, an error skipping to the Sync;
  * an SSLRequest is answered N and the startup goes on;
  * garbage (random bytes for a startup, a message of a huge length, of no known type, half a message and a close, a query that is no string): the server answers the next
    connection as if nothing had happened;
  * a login (6at): who is not let in and why, what a token that may only read, or only write one table, is refused, who and when in every record, and the log at L2;
  * more than one connection (6aq): statements interleaved, a statement that waits for another connection's transaction (to commit, to roll back, to be dropped), a
    transaction ended for idling while another waits, a 17th connection, a message over 1 MiB, a client that does not read its answer, eight clients at once.

If a PostgreSQL is reachable (PG_E2E_PORT) and `psql` is installed, a script is run with psql against both and what psql prints must be the same: a client this project did
not write. And cancho-pg's own example client, built from its repository if it is beside this one, the same. Without them those steps are skipped, and say so.
"""
import atexit
import difflib
import os
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

SERVER, HARNESS, COUNT, SEED = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
VERIFIERS = sys.argv[5:] or ["python3 tools/l3a.py"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.argv = ["engine_check.py", HARNESS, str(COUNT), str(SEED)]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine_check as ec  # noqa: E402  (the generator, the fixed statements, and how the test program is run)

FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:700]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


STARTED = []


def stop_all():
    """No server this test started outlives it, however the test ends (a mutant of the server may loop for ever, and did, for 38 minutes of every processor, before this)."""
    for p in STARTED:
        if p.poll() is None:
            p.kill()
            p.wait()


atexit.register(stop_all)


def die_with_parent():
    """In the server, before it starts: if this test is killed (a mutant runner's time limit), the kernel kills the server too (Linux; elsewhere `stop_all` is what there is)."""
    try:
        import ctypes
        ctypes.CDLL("libc.so.6").prctl(1, signal.SIGKILL)       # PR_SET_PDEATHSIG
    except (OSError, AttributeError):
        pass


class Server:
    def __init__(self, path, *limits, key=True, login=False):
        self.path, self.port = path, free_port()
        args = [SERVER, path, str(self.port)]
        if key:
            # the seed of the key that signs the log (6as)
            with open(path + ".key", "w") as f:
                f.write(bytes(range(32)).hex() + "\n")
            args += [path + ".key"]
            root = "-"
            if login:
                # the root's public key: clients log in with a token it signed (6at)
                root = path + ".root"
                with open(root, "w") as f:
                    f.write(ROOT_KEY + "\n")
            if login or limits:
                args += [root] + [str(x) for x in limits]
        self.p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, preexec_fn=die_with_parent)
        STARTED.append(self.p)
        line = self.p.stderr.readline()
        if line != b"listening\n":
            raise SystemExit("engine_wire: the server did not start: %r (status %s)" % (line, self.p.poll()))

    def stop(self, sig=signal.SIGTERM):
        self.p.send_signal(sig)
        self.p.wait()
        self.p.stderr.close()

    def alive(self):
        return self.p.poll() is None


def message(t, body):
    return t + struct.pack(">I", len(body) + 4) + body


class Client:
    """The simple query protocol, and the bytes of anything else."""

    def __init__(self, port, ssl_first=False, rcvbuf=None, password=None, database="anything"):
        self.s = socket.socket()
        if rcvbuf:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self.s.settimeout(20)
        self.s.connect(("127.0.0.1", port))
        self.buf, self.status, self.names, self.params = b"", "?", [], {}
        if ssl_first:
            self.s.sendall(struct.pack(">II", 8, 80877103))
            self.ssl_answer = self.s.recv(1)
        body = struct.pack(">I", 196608) + b"user\0tester\0database\0" + database.encode() + b"\0\0"
        self.s.sendall(struct.pack(">I", len(body) + 4) + body)
        self.asked = None
        if password is not None:
            # a server with a login asks for a password (AuthenticationCleartextPassword) before anything else
            self.asked = self.msg()
            self.s.sendall(message(b"p", password.encode() + b"\0"))
        self.first = self.until_ready()

    def msg(self):
        while len(self.buf) < 5 or len(self.buf) < 1 + struct.unpack(">I", self.buf[1:5])[0]:
            got = self.s.recv(65536)
            if not got:
                raise EOFError
            self.buf += got
        n = struct.unpack(">I", self.buf[1:5])[0]
        t, body, self.buf = self.buf[0:1], self.buf[5:1 + n], self.buf[1 + n:]
        return t, body

    def until_ready(self):
        out = []
        while True:
            try:
                t, body = self.msg()
            except EOFError:
                # the server closed the connection: what it said before is the answer (a login refused)
                self.status = "closed"
                return out
            out.append((t, body))
            if t == b"S":
                k, v = body.rstrip(b"\0").split(b"\0")
                self.params[k.decode()] = v.decode()
            if t == b"Z":
                self.status = body.decode()
                return out

    def answer(self, msgs):
        """(SQLSTATE or None, message, names, oids, rows, tag, which messages came)"""
        err, text, names, oids, rows, tag = None, None, None, None, [], None
        for t, body in msgs:
            if t == b"E":
                fields = body.split(b"\0")
                # severity twice (S, and V which is never translated), the SQLSTATE, the message; then the zero that ends the list
                if [f[:1] for f in fields] != [b"S", b"V", b"C", b"M", b"", b""] or fields[0][1:] != fields[1][1:] or fields[0][1:] not in (b"ERROR", b"FATAL"):
                    check("an error has its fields as PostgreSQL's protocol has them", False, body)
                for f in fields:
                    if f[:1] == b"C":
                        err = f[1:].decode()
                    elif f[:1] == b"M":
                        text = f[1:].decode()
            elif t == b"T":
                n = struct.unpack(">H", body[:2])[0]
                at, names, oids = 2, [], []
                for _ in range(n):
                    end = body.index(b"\0", at)
                    names.append(body[at:end])
                    table, col, oid, size, mod, fmt = struct.unpack(">IHIhiH", body[end + 1:end + 19])
                    oids.append(oid)
                    if (table, col, mod, fmt) != (0, 0, -1, 0) or size != {16: 1, 20: 8, 21: 2, 23: 4}.get(oid, -1):
                        check("a column is described as PostgreSQL's protocol has it", False, (table, col, oid, size, mod, fmt))
                    at = end + 19
            elif t == b"D":
                n = struct.unpack(">H", body[:2])[0]
                at, row = 2, []
                for _ in range(n):
                    ln = struct.unpack(">i", body[at:at + 4])[0]
                    at += 4
                    if ln < 0:
                        row.append(None)
                    else:
                        row.append(body[at:at + ln])
                        at += ln
                rows.append(row)
            elif t == b"C":
                if body[-1:] != b"\0" or b"\0" in body[:-1]:
                    check("a command's tag is a string", False, body)
                tag = body[:-1].decode()
        return err, text, names, oids, rows, tag, b"".join(t for t, _ in msgs)

    def query(self, sql):
        self.s.sendall(message(b"Q", sql.encode() + b"\0"))
        return self.answer(self.until_ready())

    def ask(self, sql):
        """Send a query and do not wait for its answer."""
        self.s.sendall(message(b"Q", sql.encode() + b"\0"))

    def answered(self, within):
        """Whether an answer comes within so many seconds: the answer, or None."""
        self.s.settimeout(within)
        try:
            return self.answer(self.until_ready())
        except (socket.timeout, TimeoutError):
            return None
        finally:
            self.s.settimeout(20)

    @staticmethod
    def bind(name, params):
        body = b"\0" + name + b"\0" + struct.pack(">HH", 0, len(params))
        for v in params:
            body += struct.pack(">i", -1) if v is None else struct.pack(">i", len(v.encode())) + v.encode()
        return message(b"B", body + struct.pack(">H", 0))

    def extended(self, sql, params):
        """As cancho-pg's `execute`: Parse (unnamed, no types), Bind (text), Describe the portal, Execute, Sync."""
        self.s.sendall(message(b"P", b"\0" + sql.encode() + b"\0" + struct.pack(">H", 0)) + self.bind(b"", params) + message(b"D", b"P\0") + message(b"E", b"\0" + struct.pack(">I", 0)) + message(b"S", b""))
        return self.answer(self.until_ready())

    def prepare(self, name, sql):
        """As cancho-pg's `parse_named`: Parse under a name, Sync."""
        self.s.sendall(message(b"P", name + b"\0" + sql.encode() + b"\0" + struct.pack(">H", 0)) + message(b"S", b""))
        return self.answer(self.until_ready())

    def run_named(self, name, params):
        """As cancho-pg's `bind_named`: Bind, Execute, Sync; no Describe."""
        self.s.sendall(self.bind(name, params) + message(b"E", b"\0" + struct.pack(">I", 0)) + message(b"S", b""))
        return self.answer(self.until_ready())

    def raw(self, data):
        self.s.sendall(data)
        return self.answer(self.until_ready())

    def close(self, terminate=True):
        if terminate:
            self.s.sendall(message(b"X", b""))
        self.s.close()


def harness_view(block):
    """A block of the test program's output as the client would see the same answer: (SQLSTATE or None, message, names, oids, rows, tag, state)."""
    head, state = block[0], block[-1].split()[1]
    if head.startswith("refused "):
        return "0A000", "cancho-db: refused " + head.split()[1], None, None, [], None, state
    if head.startswith("error "):
        return head.split()[1], None, None, None, [], None, state
    tag = [l[2:] for l in block if l.startswith("G ")][0]
    names = oids = None
    rows = []
    for l in block[1:]:
        if l == "N" or l.startswith("N "):
            names = [ec.unhex(x) for x in l.split()[1:]]
        elif l == "T" or l.startswith("T "):
            oids = [int(x) for x in l.split()[1:]]
        elif l == "R" or l.startswith("R "):
            rows.append([None if v == "-" else ec.unhex(v) for v in l.split()[1:]])
    return None, None, names, oids, rows, tag, state


def mint(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "mint.py")] + list(args), capture_output=True, text=True, check=True).stdout.strip()


ROOT_KEY = mint("root")
ALL = "r:*,w:*,d:*,c:*,n:*"


def verified(d, path, history, what, login=False):
    """The log the server left in its page file (6as), read out by the test program and given to the verifiers with the rows the file holds: the number of commits."""
    import hashlib
    tables = sorted(set(re.findall(r"create table (?:if not exists )?(\w+)", " ".join(history)) + re.findall(r"rename to (\w+)", " ".join(history))))
    out = [l for b in ec.run_engine(path, ["select 1 from nosuchtable"]) for l in b]      # (the file opens)
    r = subprocess.run([HARNESS, path], input="\n".join(["!records", "!store", "!tokens", "!stmts", "!mark"] + ["!rows " + t for t in tables]) + "\n", capture_output=True, text=True)
    out = r.stdout.split("\n")
    cut = out.index("mark")
    tokens = [bytes.fromhex(l.split()[1]) for l in out[:cut] if l.startswith("K ")]
    stmts = [bytes.fromhex(l.split()[1]) for l in out[:cut] if l.startswith("Y ")]
    recs = [bytes.fromhex(l.split()[1]) for l in out[:cut] if l.startswith("L ")]
    if not recs:
        check("%s: the server's page file has a log" % what, False, out[:3])
        return 0
    ids = [hashlib.sha256(b"cancho-db/commit/v1\0" + rec[4:4 + int.from_bytes(rec[:4], "big")]).digest() for rec in recs[1:]]
    lines, live, t = ["CHODBDL2"], ["CHODBLV2"], iter(tables)
    for l in out[:cut]:
        f = l.split()
        if f and f[0] == "X":
            lines.append("\t".join([str(len(lines) - 1), ids[int(f[1])].hex(), "public", f[2], f[3], "" if f[4] == "-" else f[4], "" if f[5] == "-" else f[5], "", "", "", "", "", ""]))
    table = next(t)
    for l in out[cut + 1:]:
        f = l.split()
        if f and f[0] == "D":
            live.append("\t".join(["public", table.encode().hex(), f[1], f[2], "" if f[3] == "." else f[3], f[4]]))
        elif f and f[0] == "rows":
            table = next(t, None)
    for name, data in (("log", b"".join(recs)), ("deltas", ("\n".join(lines) + "\n").encode()), ("live", ("\n".join(live) + "\n").encode())):
        with open(os.path.join(d, "v." + name), "wb") as fh:
            fh.write(data)
    v = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "verify.py"), os.path.join(d, "v.log")], capture_output=True, text=True).stdout.strip()
    check("%s: the log out of the server's page file verifies (chain, numbers, signatures; %d commits)" % (what, len(ids)), v.startswith("ok ") and "commits=%d" % len(ids) in v and len(ids) > 3, v)
    if login:
        # L2 (docs/spec/token.md): every commit was made under a token of the root's that allows what the commit records, and was not expired then
        with open(os.path.join(d, "v.tokens"), "wb") as fh:
            fh.write(b"CHODBTK1" + b"".join(struct.pack(">I", len(t)) + t for t in tokens))
        # and with the statements (6au): each commit's statements are in the store the file kept, and its effects are exactly what they infer
        with open(os.path.join(d, "v.stmts"), "wb") as fh:
            fh.write(b"CHODBST3" + b"".join(struct.pack(">I", len(x)) + x for x in stmts))
        l2 = lambda root, toks: subprocess.run([sys.executable, os.path.join(ROOT, "tools", "verify.py"), os.path.join(d, "v.log"), "--root", root, "--tokens", toks, "--stmts", os.path.join(d, "v.stmts")], capture_output=True, text=True).stdout.strip()
        with open(os.path.join(d, "v.none"), "wb") as fh:
            fh.write(b"CHODBTK1")
        v, other, none = l2(ROOT_KEY, os.path.join(d, "v.tokens")), l2("00" * 32, os.path.join(d, "v.tokens")), l2(ROOT_KEY, os.path.join(d, "v.none"))
        check("%s: the log verifies at L2 with statements under the root's key, with the tokens (%d) and the statements (%d) the file kept; not under another key, and not without the tokens" % (what, len(tokens), len(stmts)),
              v.startswith("ok ") and v.endswith("level=2+ir") and tokens and other.startswith("reject rule=token-bad-signature") and none.startswith("reject "), (v, other, none))
    for cmd in VERIFIERS:
        v = subprocess.run(cmd.split() + [os.path.join(d, "v.log"), "--deltas", os.path.join(d, "v.deltas"), "--live-dump", os.path.join(d, "v.live")], capture_output=True, text=True, cwd=ROOT)
        v = (v.stdout + v.stderr).strip()
        check("%s: %s: every commit's changes, every state, and the replay ends at the rows the file holds (%d facts, %d rows)" % (what, cmd, len(lines) - 1, len(live) - 1),
              v.startswith("ok commits=%d " % len(ids)) and v.endswith(" final"), v)
    return len(ids)


def differential(d):
    # the statements with parameters go as cancho-pg sends them (the extended protocol), the others as simple queries
    fixed = [sql for sql, _ in ec.FIXED]
    rnd = [st[0] for st in ec.generate(random.Random(SEED), COUNT)]
    history = fixed + rnd
    blocks = ec.run_engine(os.path.join(d, "harness.db"), ec.lines(history) + ["!commit"])
    if len(blocks) != len(history):
        raise SystemExit("engine_wire: %d answers of the test program for %d statements" % (len(blocks), len(history)))
    srv = Server(os.path.join(d, "server.db"))
    c = Client(srv.port)
    check("the startup is answered: AuthenticationOk, the parameters, a key, ReadyForQuery", b"".join(t for t, _ in c.first) == b"RSSSSSSKZ" and c.status == "I" and c.params.get("client_encoding") == "UTF8"
          and c.params.get("server_version", "").startswith("16."), (c.first, c.params))
    kinds, bad, sent = {}, 0, 0
    for i, sql in enumerate(history):
        params = getattr(sql, "params", None)
        if params is None:
            err, text, names, oids, rows, tag, seen = c.query(str(sql))
        else:
            sent += 1
            err, text, names, oids, rows, tag, seen = c.extended(str(sql), params)
        want = harness_view(blocks[i])
        got = (err, text if err == "0A000" else None, names, oids, rows, tag, c.status)
        k = "refused" if want[0] == "0A000" else "error" if want[0] else "rows" if want[2] is not None else "command"
        kinds[k] = kinds.get(k, 0) + 1
        if params is not None:
            # the order of the messages: PostgreSQL's for a statement that succeeds (6am)
            order = b"12EZ" if err else b"12T" + b"D" * len(rows) + b"CZ" if names is not None else b"12nCZ"
            if seen != order:
                got = (got, seen)
        if got != want:
            bad += 1
            if bad <= 5:
                print("FAIL %d: %s\n     server:       %s\n     test program: %s" % (i, sql[:200], str(got)[:500], str(want)[:500]))
    check("%d statements, %d of them with parameters by the extended protocol: the server answers as the test program does (%s)" % (len(history), sent, ", ".join("%s %d" % kv for kv in sorted(kinds.items()))), bad == 0 and sent > 50, "%d differ" % bad)
    c.close()
    srv.stop()
    # the server's page file, read by the test program
    tables = sorted(set(re.findall(r"create table (?:if not exists )?(\w+)", " ".join(history))))
    dump = ["select * from %s order by 1" % t for t in tables]
    mine = ec.run_engine(os.path.join(d, "harness.db"), dump)
    theirs = ec.run_engine(os.path.join(d, "server.db"), dump)
    answered = sum(1 for b in mine if b and b[0].startswith("ok "))
    check("the server's page file holds what the test program's does (%d tables read)" % answered, mine == theirs and answered >= 3)
    # and the log of that session, which the server recorded as it went
    verified(d, os.path.join(d, "server.db"), [str(x) for x in history], "a session of %d statements over a socket" % len(history))


def durability(d):
    path = os.path.join(d, "kill.db")
    srv = Server(path)
    c = Client(srv.port)
    c.query("create table dur (k integer primary key, v text)")
    for k in range(40):
        c.query("insert into dur values (%d, 'row %d')" % (k, k))
    c.query("begin")
    c.query("update dur set v = 'seen' where k < 10")
    got = c.query("commit")
    srv.stop(signal.SIGKILL)                      # the commit was acknowledged: it is on the disk
    c.close(False)
    srv = Server(path)
    c = Client(srv.port)
    rows = c.query("select count(*) from dur where v = 'seen'")[4]
    all_rows = c.query("select count(*) from dur")[4]
    check("killed after an acknowledged commit, restarted: the commit is there", got[5] == "COMMIT" and rows == [[b"10"]] and all_rows == [[b"40"]], (got, rows, all_rows))
    # a connection that ends inside a transaction
    c.query("begin")
    c.query("insert into dur values (100, 'half')")
    c.query("update dur set v = 'half' where k = 1")
    c.close(False)
    c = Client(srv.port)
    a = c.query("select count(*) from dur where v = 'half'")[4]
    b = c.query("insert into dur values (100, 'whole')")
    check("a connection closed inside a transaction: nothing of it stays, and its key is free", a == [[b"0"]] and b[5] == "INSERT 0 1" and c.status == "I", (a, b))
    # what the lost transaction drew from a counter stays drawn, as after any rollback
    c.query("create table drawn (id integer generated always as identity primary key, v text)")
    first = c.query("insert into drawn (v) values ('a') returning id")[4]
    c.query("begin")
    lost = c.query("insert into drawn (v) values ('lost') returning id")[4]
    c.close(False)
    c = Client(srv.port)
    nxt = c.query("insert into drawn (v) values ('b') returning id")[4]
    check("a value drawn in a transaction the connection took with it is not given again", (first, lost, nxt) == ([[b"1"]], [[b"2"]], [[b"3"]]) and c.status == "I", (first, lost, nxt))
    # the same with a Terminate, after which the server closes its side
    c.query("begin")
    c.query("delete from dur")
    c.s.sendall(message(b"X", b""))
    c.s.settimeout(5)
    try:
        closed = c.s.recv(100) == b""
    except OSError:
        closed = False
    c.s.close()
    c = Client(srv.port)
    check("a Terminate ends the connection, and inside a transaction rolls it back", closed and c.query("select count(*) from dur")[4] == [[b"41"]], closed)
    # a message that arrives in two pieces, the second being its last byte, after a longer one has been through the buffer
    c.query("select count(*) from dur where v = '%s'" % ("x" * 300))
    whole = message(b"Q", b"select count(*) from dur\0")
    c.s.sendall(whole[:-1])
    time.sleep(0.3)
    c.s.sendall(whole[-1:])
    check("a message in two pieces is read when it is whole", c.answer(c.until_ready())[4] == [[b"41"]])
    # an empty query, and a statement that ends with a semicolon
    c.s.sendall(message(b"Q", b"  ;  \0"))
    seen = b"".join(t for t, _ in c.until_ready())
    semi = c.query("select count(*) from dur ; ")
    two = c.query("select 1 from dur; select 2 from dur")
    check("an empty query is EmptyQueryResponse; one semicolon ends a statement; two statements are refused", seen == b"IZ" and semi[4] == [[b"41"]] and two[0] == "0A000", (seen, semi, two))
    # an answer larger than the server's buffer (1 MiB): every row arrives, in order
    c.query("create table big (k integer primary key, v text)")
    for i in range(0, 30000, 500):
        c.query("insert into big values " + ", ".join("(%d, '%s')" % (k, "%06d" % k * 10) for k in range(i, i + 500)))
    rows = c.query("select * from big order by k")[4]
    check("an answer of 30,000 rows and 2.4 MB arrives whole and in order", [r[0] for r in rows] == [b"%d" % k for k in range(30000)] and all(r[1] == b"%06d" % k * 10 for k, r in enumerate(rows)), len(rows))
    # an answer is not a write for each of its messages (each would wait for the client's acknowledgement of the one before: 40 ms a query, as first built)
    t0 = time.time()
    for k in range(500):
        c.query("insert into dur values (%d, 'speed')" % (1000 + k))
    t1 = time.time()
    for k in range(500):
        c.query("select v from dur where k = %d" % (1000 + k))
    t2 = time.time()
    c.query("delete from dur where k >= 1000")
    print("     500 inserts, each committed to the disk before its answer: %.2f s; 500 selects of a row: %.2f s" % (t1 - t0, t2 - t1))
    check("500 selects of one row take under 5 s", t2 - t1 < 5, t2 - t1)
    c.close()
    extended_protocol(srv)
    # an SSLRequest first
    c = Client(srv.port, ssl_first=True)
    check("an SSLRequest is answered N and the startup goes on", c.ssl_answer == b"N" and c.query("select count(*) from dur")[4] == [[b"41"]])
    c.close()
    # a client that is not on this machine's loopback is closed unread. The nearest thing a test has: this machine's other address
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        mine = probe.getsockname()[0]
    except OSError:
        mine = "127.0.0.1"
    probe.close()
    if mine.startswith("127."):
        print("skip a client from another address: this machine has only the loopback")
    else:
        try:
            far = socket.create_connection((mine, srv.port), timeout=10)
            body = struct.pack(">I", 196608) + b"user\0far\0\0"
            far.sendall(struct.pack(">I", len(body) + 4) + body)
            got = far.recv(100)
            far.close()
        except OSError:
            got = b""
        check("a client from another address (%s) is closed unread" % mine, got == b"", got)
    return srv


def extended_protocol(srv):
    """The extended protocol beyond what the differential sends: statements prepared by name, and what is refused (docs/m3-engine.md 6am)."""
    def M(t, body=b""):
        return message(t, body)
    parse = lambda name, sql: M(b"P", name + b"\0" + sql.encode() + b"\0" + struct.pack(">H", 0))
    execute = M(b"E", b"\0" + struct.pack(">I", 0))
    sync = M(b"S")
    c = Client(srv.port)
    c.query("create table ext (k integer primary key, v text, n integer)")
    a = c.prepare(b"ins", "insert into ext values ($1, $2, $3)")
    b = c.prepare(b"get", "select v, n from ext where k = $1")
    cc = c.prepare(b"upd", "update ext set n = n + $1 where k = $2 returning k, n")
    ok = [x[6] for x in (a, b, cc)] == [b"1Z"] * 3
    got = []
    for k in range(1, 6):
        got.append(c.run_named(b"ins", [str(k), None if k == 3 else "v%d" % k, str(k * 10)]))
    ok = ok and all(g[5] == "INSERT 0 1" and g[6] == b"2CZ" for g in got)
    r1 = c.run_named(b"get", ["3"])
    r2 = c.run_named(b"get", ["5"])
    r3 = c.run_named(b"upd", ["7", "5"])
    r4 = c.run_named(b"get", ["99"])
    dup = c.run_named(b"ins", ["1", "again", "0"])
    check("statements prepared by name and run by name: ParseComplete; then BindComplete, the rows with no description, the tag",
          ok and (r1[4], r1[6], r1[2]) == ([[None, b"30"]], b"2DCZ", None) and r2[4] == [[b"v5", b"50"]] and (r3[4], r3[5]) == ([[b"5", b"57"]], "UPDATE 1") and (r4[4], r4[5], r4[6]) == ([], "SELECT 0", b"2CZ")
          and (dup[0], dup[6]) == ("23505", b"2EZ"), (a, got[:1], r1, r2, r3, r4, dup))
    twice = c.prepare(b"get", "select 1 from ext")
    never = c.run_named(b"nope", [])
    closed = c.raw(M(b"C", b"Sget\0") + sync)
    gone = c.run_named(b"get", ["1"])
    again = c.prepare(b"get", "select n from ext where k = $1")
    back = c.run_named(b"get", ["2"])
    check("a name twice is 42P05, a name never prepared 26000; a statement closed is gone and its name free",
          (twice[0], twice[6]) == ("42P05", b"EZ") and (never[0], never[6]) == ("26000", b"EZ") and closed[6] == b"3Z" and gone[0] == "26000" and again[6] == b"1Z" and back[4] == [[b"20"]], (twice, never, closed, gone, again, back))
    # an error skips to the Sync; the next batch is answered
    skipped = c.raw(parse(b"", "select v from ext where k = $1") + Client.bind(b"nope", ["1"]) + M(b"D", b"P\0") + execute + parse(b"late", "select 1 from ext") + sync)
    after = c.run_named(b"late", [])
    fine = c.extended("select count(*) from ext", [])
    check("an error skips everything up to the Sync, and the next batch is answered", (skipped[0], skipped[6]) == ("26000", b"1EZ") and after[0] == "26000" and fine[4] == [[b"5"]] and fine[6] == b"12TDCZ", (skipped, after, fine))
    # what is refused, each with its tag
    refusals = [("describe-statement", parse(b"", "select 1 from ext") + M(b"D", b"S\0") + sync, b"1EZ"),
                ("parameter-types", M(b"P", b"\0select $1 from ext\0" + struct.pack(">HI", 1, 23)) + sync, b"EZ"),
                ("binary-format", parse(b"", "select v from ext where k = $1") + M(b"B", b"\0\0" + struct.pack(">HHHi", 1, 1, 1, 4) + struct.pack(">i", 1) + struct.pack(">H", 0)) + execute + sync, b"1EZ"),
                ("binary-format", parse(b"", "select v from ext") + M(b"B", b"\0\0" + struct.pack(">HHHH", 0, 0, 1, 1)) + execute + sync, b"1EZ"),
                ("named-portal", parse(b"", "select v from ext") + M(b"B", b"cur\0\0" + struct.pack(">HHH", 0, 0, 0)) + execute + sync, b"1EZ"),
                ("row-limit", parse(b"", "select v from ext") + Client.bind(b"", []) + M(b"E", b"\0" + struct.pack(">I", 2)) + sync, b"12EZ"),
                ("pipeline", parse(b"", "insert into ext values (50, 'p', 0)") + Client.bind(b"", []) + execute + Client.bind(b"", []) + execute + sync, b"12C2EZ"),
                ("describe-before-execute", parse(b"", "select v from ext") + Client.bind(b"", []) + M(b"D", b"P\0") + M(b"H") + execute + sync, b"12EZ"),
                ("function-call", M(b"F", struct.pack(">IHHH", 1, 0, 0, 0)) + sync, b"EZ"),
                ("too-many-values", parse(b"", "select v from ext") + Client.bind(b"", ["1"] * 65) + execute + sync, b"1EZ")]
    wrong = []
    for tag, data, order in refusals:
        r = c.raw(data)
        want_state = "54000" if tag == "too-many-values" else "0A000"
        if (r[0], r[1], r[6]) != (want_state, "cancho-db: refused " + tag, order):
            wrong.append((tag, r[0], r[1], r[6]))
    still = c.query("select count(*) from ext")
    check("refused with its tag, the connection going on: %s" % ", ".join(sorted(set(t for t, _, _ in refusals))), not wrong and still[4] == [[b"6"]], (wrong, still))
    # a portal is run once; with none bound an Execute is 34000; an empty statement is EmptyQueryResponse
    once = c.raw(parse(b"", "select count(*) from ext") + Client.bind(b"", []) + execute + sync + execute + sync)
    rest = c.answer(c.until_ready())
    empty = c.raw(parse(b"", " ; ") + Client.bind(b"", []) + M(b"D", b"P\0") + execute + sync)
    check("a portal is run once; an empty statement is NoData and EmptyQueryResponse", once[6] == b"12DCZ" and (rest[0], rest[6]) == ("34000", b"EZ") and empty[6] == b"12nIZ", (once, rest, empty))
    # a transaction opened by a simple query, written to by prepared statements; two Executes to a Sync are allowed inside it
    c.query("begin")
    t1 = c.raw(Client.bind(b"ins", ["60", "t", "1"]) + execute + Client.bind(b"ins", ["61", "t", "2"]) + execute + sync)
    t2 = c.run_named(b"ins", ["60", "t", "3"])
    t3 = c.run_named(b"ins", ["62", "t", "3"])
    c.query("rollback")
    t4 = c.query("select count(*) from ext")
    check("in a transaction: two Executes to a Sync; an error fails it and the next statement is 25P02; a rollback takes it all back",
          (t1[6], c.status) == (b"2C2CZ", "I") and t2[0] == "23505" and t3[0] == "25P02" and t4[4] == [[b"6"]], (t1, t2, t3, t4))
    # an error at an Execute skips what follows it too
    c.query("begin")
    t5 = c.raw(Client.bind(b"ins", ["1", "dup", "0"]) + execute + Client.bind(b"ins", ["63", "t", "0"]) + execute + sync)
    c.query("rollback")
    # Close of the unnamed statement, and of the portal
    k1 = c.raw(parse(b"", "select count(*) from ext") + M(b"C", b"S\0") + Client.bind(b"", []) + sync)
    k2 = c.raw(parse(b"", "select count(*) from ext") + Client.bind(b"", []) + M(b"C", b"P\0") + execute + sync)
    k3 = c.raw(parse(b"", "select count(*) from ext") + Client.bind(b"", []) + parse(b"", "select 1 from ext") + execute + sync)
    check("an error at an Execute skips to the Sync; the unnamed statement closed is gone, the portal closed is gone, and a portal does not outlive its statement",
          (t5[0], t5[6]) == ("23505", b"2EZ") and (k1[0], k1[6]) == ("26000", b"13EZ") and (k2[0], k2[6]) == ("34000", b"123EZ") and (k3[0], k3[6]) == ("34000", b"121EZ"), (t5, k1, k2, k3))
    # a simple query drops the unnamed statement
    c.raw(parse(b"", "select count(*) from ext") + sync)
    c.query("select 1 from ext")
    dropped = c.raw(Client.bind(b"", []) + execute + sync)
    # a statement longer than a prepared statement may be, and more named statements than a connection holds
    long = c.raw(parse(b"", "select '" + "x" * (1 << 20) + "' from ext") + sync)
    # three are prepared (ins, get, upd); a closed one's place is free again
    c.raw(M(b"C", b"Sget\0") + sync)
    c.prepare(b"get", "select n from ext where k = $1")
    many = [c.prepare(b"s%d" % i, "select %d from ext" % i) for i in range(70)]
    full = [m[1] for m in many if m[0]]
    for i in range(0, 40):
        c.raw(M(b"C", b"Ss%d\0" % i) + sync)
    churn = [c.prepare(b"r%d" % i, "select %d from ext" % i)[6] for i in range(40)]
    check("a simple query drops the unnamed statement; a statement over 1 MiB and a 65th name are refused, not cut; a closed statement's place is used again",
          dropped[0] == "26000" and (long[0], long[1]) == ("54000", "cancho-db: refused statement-too-long") and [m[6] for m in many].count(b"1Z") == 64 - 3 and full == ["cancho-db: refused too-many-statements"] * 9
          and many[-1][0] == "53200" and churn == [b"1Z"] * 40, (dropped, long[:2], [m[6] for m in many].count(b"1Z"), full[:2], churn.count(b"1Z")))
    c.close()
    # the statements of a connection end with it
    c = Client(srv.port)
    check("a new connection has none of the last one's statements", c.run_named(b"ins", ["70", "x", "1"])[0] == "26000")
    c.query("drop table ext")
    c.close()


def with_cancho_pg(d):
    """cancho-pg's own example client (examples/psql.cho, built from its repository beside this one) against the server and against PostgreSQL."""
    repo = os.environ.get("CANCHO_PG", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "cancho-pg"))
    cancho = os.environ.get("CANCHO", "cancho")
    port = int(os.environ.get("PG_E2E_PORT", "5532"))
    if not os.path.exists(os.path.join(repo, "examples", "psql.cho")) or shutil.which(cancho) is None or subprocess.run(["pg_isready", "-h", "127.0.0.1", "-p", str(port)], capture_output=True).returncode != 0:
        print("skip cancho-pg's client against the server: its repository is not beside this one (CANCHO_PG), or there is no compiler or no PostgreSQL")
        return
    exe = os.path.join(d, "cpsql")
    b = subprocess.run([cancho, "build", "--std", os.path.join(repo, "examples", "psql.cho"), os.path.join(repo, "src", "pg.cho"), "-o", exe], capture_output=True, text=True)
    if b.returncode != 0:
        check("cancho-pg's example client builds", False, b.stdout + b.stderr)
        return
    db = os.environ.get("E2E_DB", "cdb_e2e") + "_wire"
    subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-d", "postgres", "-q", "-c", "drop database if exists %s" % db, "-c", "create database %s" % db], capture_output=True)
    script = [["create table cp (k integer primary key, name text, n bigint, ok boolean)"],
              ["insert into cp values ($1, $2, $3, $4)", "1", "ana", "10", "true"],
              ["insert into cp values ($1, $2, $3, $4)", "2", "bo", "\\N", "f"],
              ["insert into cp values ($1, $2, $3, $4) returning k, name", "3", "c'y; drop table cp", "7", "\\N"],
              ["select k, name, n, ok from cp where k >= $1 order by k", "2"],
              ["update cp set n = n + $1 where k = $2", "5", "1"],
              ["select * from cp where name = $1", "ana"],
              ["select count(*) from cp where n > $1 or ok", "6"],
              ["delete from cp where k = $1 returning name", "2"],
              ["insert into cp values ($1, $2, $3, $4) on conflict do nothing", "1", "dup", "0", "t"],
              ["select k, name from cp order by k"],
              ["insert into cp values ($1, $2, $3, $4)", "1", "dup", "0", "t"],
              ["drop table cp"]]
    out = {}
    srv = Server(os.path.join(d, "cpg.db"))
    for name, p in (("server", srv.port), ("postgres", port)):
        lines = []
        for st in script:
            r = subprocess.run([exe, "127.0.0.1", str(p), "postgres", db, "-"] + st, capture_output=True, text=True)
            # an error's words are PostgreSQL's own; its SQLSTATE is what is compared
            lines += [l[:11] if l.startswith("ERROR ") else l for l in r.stdout.splitlines()] + ["status %d" % r.returncode]
        out[name] = lines
    srv.stop()
    check("cancho-pg's own client prints for the server what it prints for PostgreSQL (%d statements, %d lines)" % (len(script), len(out["postgres"])),
          out["server"] == out["postgres"] and len(out["postgres"]) > 25 and "ERROR 23505" in out["postgres"], "\n".join(difflib.unified_diff(out["server"], out["postgres"], "server", "postgres", lineterm="")))


def garbage(srv):
    rng = random.Random(SEED)
    startup = struct.pack(">I", 196608) + b"user\0g\0\0"
    startup = struct.pack(">I", len(startup) + 4) + startup
    cases = [("random bytes for a startup", bytes(rng.randrange(256) for _ in range(64))),
             ("a startup of no length", struct.pack(">I", 3)),
             ("a startup of another protocol", struct.pack(">II", 8, 131072)),
             ("a cancel request", struct.pack(">IIII", 16, 80877102, 1, 2)),
             ("nothing at all", b""),
             ("half a startup", startup[:7]),
             ("a message of a huge length", startup + b"Q" + struct.pack(">I", 1 << 30) + b"select"),
             ("a message of length 3", startup + b"Q" + struct.pack(">I", 3)),
             ("a message of no known type", startup + message(b"!", b"what")),
             ("half a query and a close", startup + message(b"Q", b"select count(*) from dur\0")[:12]),
             ("a query that is no string", startup + message(b"Q", b"select 1")),
             ("a query of bytes that are no text", startup + message(b"Q", bytes(rng.randrange(1, 256) for _ in range(300)) + b"\0")),
             ("many messages at once", startup + message(b"Q", b"select count(*) from dur\0") * 50),
             ("a COPY message", startup + message(b"d", b"data"))]
    for _ in range(40):
        cases.append(("random bytes after a startup", startup + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 200)))))
    bad = []
    # what the server says before it closes: a message it cannot read past is a protocol violation, said so; and every whole message before the end is answered
    says = {"a message of a huge length": b"SERROR\0VERROR\0C54000\0", "a message of length 3": b"SFATAL\0VFATAL\0C08P01\0", "a message of no known type": b"C08P01\0", "a query that is no string": b"C08P01\0",
            "a COPY message": b"C08P01\0", "many messages at once": b"Z\0\0\0\x05I" * 51}
    for name, data in cases:
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=20)
        reply = b""
        try:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            while True:
                got = s.recv(65536)
                if not got:
                    break
                reply += got
        except OSError:
            pass
        s.close()
        if name in says and (says[name] not in reply if name != "many messages at once" else reply.count(b"Z\0\0\0\x05I") != 51):
            bad.append(name + ": the reply")
        try:
            c = Client(srv.port)
            if c.query("select count(*) from dur")[4] != [[b"41"]] or not srv.alive():
                bad.append(name)
            c.close()
        except (OSError, EOFError):
            bad.append(name)
            break
    check("garbage (%d kinds of it): the server answers the next connection as before" % len(cases), not bad, bad)


def several(d):
    """More than one connection (docs/m3-engine.md 6aq)."""
    srv = Server(os.path.join(d, "several.db"), 1500, 1500)       # a transaction may idle 1.5 s while another waits; a client may take none of its answer for 1.5 s
    a, b = Client(srv.port), Client(srv.port)
    a.query("create table sv (k integer primary key, who text)")
    got = []
    for k in range(40):
        got.append((a if k % 2 == 0 else b).query("insert into sv values (%d, '%s')" % (k, "ab"[k % 2]))[5])
    ra, rb = a.query("select count(*) from sv where who = 'b'")[4], b.query("select count(*) from sv where who = 'a'")[4]
    check("two connections, their statements interleaved: each is answered, and each sees what the other wrote", got == ["INSERT 0 1"] * 40 and ra == [[b"20"]] and rb == [[b"20"]], (got[:3], ra, rb))
    # a transaction has the database to itself: what another connection sends waits for it to end
    a.query("begin")
    a.query("insert into sv values (100, 'txn')")
    b.ask("insert into sv values (101, 'waits')")
    early = b.answered(0.4)
    c = Client(srv.port)                                           # a third connects meanwhile, and is answered its startup
    c.ask("select count(*) from sv")
    early_c = c.answered(0.3)
    done = a.query("commit")
    late, late_c = b.answered(5), c.answered(5)
    order = a.query("select k from sv where k >= 100 order by k")[4]
    check("a statement of another connection waits for a transaction to commit, reads too, and is answered then; both writes are there",
          early is None and early_c is None and done[5] == "COMMIT" and late is not None and late[5] == "INSERT 0 1" and late_c is not None and late_c[4] == [[b"42"]] and order == [[b"100"], [b"101"]], (early, early_c, late, late_c, order))
    a.query("begin")
    a.query("insert into sv values (200, 'undone')")
    # the one that waits is sent by the extended protocol this time: its Parse and Bind are answered, its Execute waits
    b.s.sendall(message(b"P", b"\0insert into sv values ($1, $2)\0" + struct.pack(">H", 0)) + Client.bind(b"", ["200", "mine"]) + message(b"E", b"\0" + struct.pack(">I", 0)) + message(b"S", b""))
    early = b.answered(0.4)
    a.query("rollback")
    late = b.answered(5)
    who = c.query("select who from sv where k = 200")[4]
    check("the same with a rollback: the waiting insert of the same key succeeds", early is None and late is not None and late[5] == "INSERT 0 1" and who == [[b"mine"]], (early, late, who))
    a.query("begin")
    a.query("delete from sv")
    b.ask("select count(*) from sv")
    early = b.answered(0.4)
    a.close(False)                                                 # the one in the transaction goes away
    late = b.answered(5)
    check("the same when the connection in the transaction is closed: it is rolled back and the other is answered", early is None and late is not None and late[4] == [[b"43"]], (early, late))
    # a transaction that idles while another waits is ended; one that idles with nobody waiting is not
    a = Client(srv.port)
    a.query("begin")
    a.query("insert into sv values (300, 'idle')")
    time.sleep(2.2)
    still = a.query("insert into sv values (301, 'idle')")
    a.query("commit")
    a.query("begin")
    a.query("insert into sv values (302, 'ended')")
    t0 = time.time()
    b.ask("select count(*) from sv")
    late = b.answered(6)
    took = time.time() - t0
    a.s.settimeout(3)
    msgs = []
    try:
        while True:
            msgs.append(a.msg())
    except (EOFError, OSError):
        pass                                                       # the server closed it after the error
    fatal = a.answer(msgs) if msgs else None
    check("a transaction idle for the limit while another waits is ended with 25P03 and the other is answered; idle with nobody waiting, it is left alone",
          still[5] == "INSERT 0 1" and late is not None and late[4] == [[b"45"]] and 1.2 < took < 4 and fatal is not None and fatal[0] == "25P03", (still, late, took, fatal))
    b.close()
    c.close()
    # the 17th connection
    held = [Client(srv.port) for _ in range(16)]
    s17 = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    try:
        told = s17.recv(200)
        rest = s17.recv(200)
    except OSError:
        told, rest = b"", b"?"
    s17.close()
    alive = [h.query("select count(*) from sv")[4] for h in held]
    held[3].close()
    time.sleep(0.2)
    again = Client(srv.port)
    check("a 17th connection is told 53300 and closed; the 16 go on, and a place given back is taken",
          b"C53300\0" in told and rest == b"" and alive == [[[b"45"]]] * 16 and again.query("select count(*) from sv")[4] == [[b"45"]], (told, rest, alive[:2]))
    for h in held[:3] + held[4:]:
        h.close()
    # a message longer than a connection's buffer is refused and read past
    long = again.query("select '" + "x" * (3 << 19) + "' from sv")
    after = again.query("select count(*) from sv")
    check("a query over 1 MiB is refused (54000) and the connection goes on", (long[0], long[1], again.status) == ("54000", "cancho-db: refused statement-too-long", "I") and after[4] == [[b"45"]], (long[:2], after))
    # a client that asks for a large answer and never reads it is dropped after the limit, and the others are served
    again.query("create table wide (k integer primary key, v text)")
    for i in range(0, 20000, 50):
        again.query("insert into wide values " + ", ".join("(%d, '%s')" % (k, "%08d" % k * 60) for k in range(i, i + 50)))
    deaf = Client(srv.port, rcvbuf=4096)
    deaf.ask("select * from wide")
    time.sleep(0.2)
    t0 = time.time()
    other = again.query("select count(*) from wide")
    took = time.time() - t0
    deaf.s.settimeout(5)
    n = 0
    try:
        while True:
            got = deaf.s.recv(1 << 20)
            if not got:
                break
            n += len(got)
    except OSError:
        pass
    check("a client that does not read its answer is dropped after the limit, and another is served (it waited %.1f s; the first got %.1f of about 10 MB)" % (took, n / 1e6),
          other[4] == [[b"20000"]] and took < 4 and 0 < n < 9500000, (other[4], took, n))
    again.close()
    # many clients at once, each with a table of its own, against the test program's answers for the same statements
    import threading
    scripts, results = [], [None] * 8
    for i in range(8):
        rng = random.Random(SEED * 100 + i)
        sc = ["create table mc%d (k integer primary key, v integer, t text)" % i]
        for _ in range(150):
            r = rng.random()
            k = rng.randrange(30)
            if r < 0.4:
                sc.append("insert into mc%d values (%d, %d, 't%d')" % (i, k, rng.randrange(100), k))
            elif r < 0.6:
                sc.append("update mc%d set v = v + %d where k < %d" % (i, rng.randrange(5), k))
            elif r < 0.7:
                sc.append("delete from mc%d where k = %d" % (i, k))
            elif r < 0.75:
                sc += ["begin", "update mc%d set t = 'x' where k = %d" % (i, k), rng.choice(["commit", "rollback"])]
            else:
                sc.append("select k, v, t from mc%d where v >= %d order by k" % (i, rng.randrange(100)))
        scripts.append(sc)

    def one(i):
        cl = Client(srv.port)
        out = []
        for sql in scripts[i]:
            r = cl.query(sql)
            out.append((r[0], r[2], r[3], r[4], r[5], cl.status))
        cl.close()
        results[i] = out

    threads = [threading.Thread(target=one, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    wrong = []
    for i in range(8):
        blocks = ec.run_engine(os.path.join(d, "mc%d.db" % i), scripts[i])
        want = [(v[0], v[2], v[3], v[4], v[5], v[6]) for v in (harness_view(b) for b in blocks)]
        if results[i] != want:
            wrong.append(i)
    check("8 clients at once, %d statements each with transactions among them: each is answered as the test program answers its statements alone" % len(scripts[0]), not wrong and all(results), wrong)
    check("the server is still running", srv.alive())
    srv.stop()
    # what 8 clients at once, the transactions that waited, the one that was ended and the connections that were dropped left behind: one log, and it verifies
    verified(d, os.path.join(d, "several.db"), ["create table sv ", "create table wide "] + [sc[0] for sc in scripts], "many connections")
    # with no key file the server serves and records nothing, and says so; with one that is no key it does not start
    quiet = Server(os.path.join(d, "nokey.db"), key=False)
    said = quiet.p.stderr.readline()
    c = Client(quiet.port)
    c.query("create table nk (k integer primary key)")
    wrote = c.query("insert into nk values (1)")
    c.close()
    quiet.stop()
    r = subprocess.run([HARNESS, os.path.join(d, "nokey.db")], input="!records\nselect count(*) from nk\n", capture_output=True, text=True)
    with open(os.path.join(d, "bad.key"), "w") as f:
        f.write("not a key\n")
    bad = subprocess.run([SERVER, os.path.join(d, "bad.db"), str(free_port()), os.path.join(d, "bad.key")], capture_output=True, text=True, timeout=20)
    missing = subprocess.run([SERVER, os.path.join(d, "bad.db"), str(free_port()), os.path.join(d, "nosuch.key")], capture_output=True, text=True, timeout=20)
    check("with no key file the server serves, records nothing and says so; with a file that is no key, or none where one is named, it does not start",
          b"not recorded" in said and wrote[5] == "INSERT 0 1" and "records 0" in r.stdout and "R 31" in r.stdout and bad.returncode == 2 and missing.returncode == 2 and "listening" not in bad.stderr + missing.stderr,
          (said, wrote, r.stdout[:100], bad.returncode, missing.returncode))


def logins(d):
    """A login, what a token allows, and who and when in the log (docs/m3-engine.md 6at)."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import verify as l1  # noqa: E402  (to read a record's fields)
    import hashlib
    srv = Server(os.path.join(d, "login.db"), login=True)
    full = mint("password", "--effects", ALL)
    # who is not let in, each with the proxy's rule, and none of them served
    refused = [("no password, a query in its place", None, "main", "08P01", "cancho-db: a password was asked for"),
               ("a password that is no token", "nonsense", "main", "28P01", "cancho-db: refused login-bad-token"),
               ("a token another root signed", mint("password", "--effects", ALL, "--foreign"), "main", "28P01", "cancho-db: refused login-bad-signature"),
               ("a token without the seed of its last key", mint("password", "--effects", ALL, "--wrong-seed"), "main", "28P01", "cancho-db: refused login-bad-proof"),
               ("a token that has expired", mint("password", "--effects", ALL, "--expiry", "1000"), "main", "28P01", "cancho-db: refused login-expired"),
               ("a token for another branch", mint("password", "--effects", ALL, "--branch", "other"), "main", "3D000", "cancho-db: refused login-branch-denied"),
               ("a database that is not the branch", full, "postgres", "3D000", "cancho-db: refused login-branch-denied")]
    wrong = []
    for name, password, database, state, text in refused:
        if password is None:
            c = Client.__new__(Client)
            c.s = socket.create_connection(("127.0.0.1", srv.port), timeout=20)
            c.buf, c.status, c.names, c.params = b"", "?", [], {}
            body = struct.pack(">I", 196608) + b"user\0x\0database\0main\0\0"
            c.s.sendall(struct.pack(">I", len(body) + 4) + body)
            asked = c.msg()
            c.s.sendall(message(b"Q", b"select 1 from nothing\0"))
            got = c.answer(c.until_ready())
        else:
            c = Client(srv.port, password=password, database=database)
            asked, got = c.asked, c.answer(c.first)
        if asked != (b"R", struct.pack(">I", 3)) or (got[0], got[1], got[6], c.status) != (state, text, b"E", "closed"):
            wrong.append((name, asked, got[0], got[1], got[6], c.status))
        c.s.close()
    check("not let in, each told why and closed with nothing served: %s" % "; ".join(r[0] for r in refused), not wrong, wrong)
    # let in: asked for a password, then served as before
    t0 = int(time.time() * 1000)
    a = Client(srv.port, password=full, database="main")
    made = [a.query("create table lt (k integer primary key, v text)"), a.query("create table lu (k integer primary key, v text)"), a.query("insert into lt values (1, 'a'), (2, 'b')"),
            a.query("insert into lu values (1, 'x')")]
    check("a token of the root's is let in: AuthenticationCleartextPassword, then the startup's answer, and it is served",
          a.asked == (b"R", struct.pack(">I", 3)) and b"".join(t for t, _ in a.first) == b"RSSSSSSKZ" and [m[5] for m in made] == ["CREATE TABLE", "CREATE TABLE", "INSERT 0 2", "INSERT 0 1"], (a.asked, a.first[:1], made))
    # what a token allows: a statement with an effect it does not is not run
    ro = Client(srv.port, password=mint("password", "--effects", "r:*"), database="main")
    r1 = [ro.query("select k, v from lt order by k"), ro.query("insert into lt values (3, 'c')"), ro.query("update lt set v = 'z'"), ro.query("delete from lt"), ro.query("truncate lt"),
          ro.query("create table lz (k integer primary key)"), ro.query("drop table lu"), ro.query("alter table lt rename to lr"), ro.query("alter table lt add column w integer"), ro.query("create sequence ls"),
          ro.query("create index li on lt (v)")]
    check("a token that may only read: it reads, and every write and every definition is 42501 effect-denied",
          r1[0][4] == [[b"1", b"a"], [b"2", b"b"]] and all((x[0], x[1]) == ("42501", "cancho-db: refused effect-denied") for x in r1[1:]) and ro.status == "I", [(x[0], x[1], x[5]) for x in r1])
    one = Client(srv.port, password=mint("password", "--effects", "r:lt,r:lt.*,w:lt"), database="main")
    r2 = [one.query("insert into lt values (3, 'c')"), one.query("select v from lt where k = 3"), one.query("update lt set v = 'cc' where k = 3 returning k, v"), one.query("select v from lu"),
          one.query("insert into lu values (2, 'y')"), one.query("insert into lt values (4, 'd') returning k"), one.query("truncate lt")]
    check("a token for one table: it writes and reads that table, with RETURNING too, and no other",
          (r2[0][5], r2[1][4], r2[2][4], r2[5][4], r2[6][5]) == ("INSERT 0 1", [[b"c"]], [[b"3", b"cc"]], [[b"4"]], "TRUNCATE TABLE") and [x[0] for x in r2[3:5]] == ["42501", "42501"], [(x[0], x[4], x[5]) for x in r2])
    blind = Client(srv.port, password=mint("password", "--effects", "w:lt"), database="main")
    r3 = [blind.query("insert into lt values (5, 'e')"), blind.query("insert into lt values (6, 'f') returning v"), blind.query("update lt set v = 'g' where k = 5")]
    check("a token that may write a table and not read it: an insert, but not what it returns, nor an update that reads to find its rows",
          r3[0][5] == "INSERT 0 1" and [x[0] for x in r3[1:]] == ["42501", "42501"], [(x[0], x[5]) for x in r3])
    # in a transaction a statement that is not allowed fails it; by the extended protocol it is the same refusal
    one.query("begin")
    t1 = [one.query("insert into lt values (7, 'h')"), one.query("insert into lu values (7, 'h')"), one.query("select v from lt"), one.query("commit")]
    ext = one.extended("insert into lu values ($1, $2)", ["8", "i"])
    here = a.query("select k from lt order by k")[4]
    there = a.query("select k from lu order by k")[4]
    check("a statement not allowed fails its transaction, and nothing of it stays; by the extended protocol the same refusal",
          (t1[0][5], t1[1][0], t1[2][0], t1[3][5]) == ("INSERT 0 1", "42501", "25P02", "ROLLBACK") and (ext[0], ext[1], ext[6]) == ("42501", "cancho-db: refused effect-denied", b"12EZ")
          and here == [[b"5"]] and there == [[b"1"]], (t1, ext, here, there))
    for c in (a, ro, one, blind):
        c.close()
    t9 = int(time.time() * 1000)
    srv.stop()
    # who and when: every record names the token it was made under and the time, and the file kept each token
    r = subprocess.run([HARNESS, os.path.join(d, "login.db")], input="!records\n!tokens\n", capture_output=True, text=True).stdout.split("\n")
    recs = [bytes.fromhex(l.split()[1]) for l in r if l.startswith("L ")][1:]
    kept = [bytes.fromhex(l.split()[1]) for l in r if l.startswith("K ")]
    ids = set(hashlib.sha256(b"cancho-db/token/v1\0" + t).digest() for t in kept)
    infos = [l1.decode(rec[4:4 + int.from_bytes(rec[:4], "big")])[3] for rec in recs]
    times = [i[4] for i in infos]
    check("every record names its token and its time: %d commits under %d tokens (the read-only one made none), each time within the test's and none before the one before" % (len(recs), len(kept)),
          len(recs) >= 6 and len(kept) == 3 and all(i[2] in ids for i in infos) and len(set(i[2] for i in infos)) == 3 and all(t0 - 1000 <= t <= t9 + 1000 for t in times) and times == sorted(times)
          and all(i[1] == bytes(32) for i in infos), (len(recs), len(kept), times[:3], t0, t9))
    verified(d, os.path.join(d, "login.db"), ["create table lt ", "create table lu "], "a server with a login", login=True)
    # the whole of a random history under a login, against the test program's answers (which is asked nothing about who): a token that allows everything changes no answer
    srv = Server(os.path.join(d, "login2.db"), login=True)
    c = Client(srv.port, password=full, database="main")
    history = [st[0] for st in ec.generate(random.Random(SEED + 7), min(COUNT, 600))]
    blocks = ec.run_engine(os.path.join(d, "login2h.db"), ec.lines(history))
    bad = 0
    for i, sql in enumerate(history):
        params = getattr(sql, "params", None)
        got = c.query(str(sql)) if params is None else c.extended(str(sql), params)
        want = harness_view(blocks[i])
        if (got[0], got[1] if got[0] == "0A000" else None, got[2], got[3], got[4], got[5], c.status) != want:
            bad += 1
            if bad <= 3:
                print("FAIL %d: %s\n     server:       %s\n     test program: %s" % (i, str(sql)[:200], str(got)[:400], str(want)[:400]))
    check("%d random statements under a login with a token that allows everything: answered as the test program answers them" % len(history), bad == 0, bad)
    c.close()
    srv.stop()
    verified(d, os.path.join(d, "login2.db"), [str(x) for x in history], "a random history under a login", login=True)


def with_psql(d):
    port = int(os.environ.get("PG_E2E_PORT", "5532"))
    if shutil.which("psql") is None or subprocess.run(["pg_isready", "-h", "127.0.0.1", "-p", str(port)], capture_output=True).returncode != 0:
        print("skip psql against the server and against PostgreSQL: no psql, or no PostgreSQL on port %d" % port)
        return
    db = os.environ.get("E2E_DB", "cdb_e2e") + "_wire"
    subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-d", "postgres", "-q", "-c", "drop database if exists %s" % db, "-c", "create database %s" % db], capture_output=True)
    script = ["create table ps (k integer primary key, name text not null, n bigint, ok boolean)",
              "insert into ps values (1, 'ana', 10, true), (2, 'bo', null, false), (3, 'c''y', -5, null)",
              "select * from ps order by k",
              "select name, n + 1 as m from ps where ok or n < 0 order by name desc",
              "update ps set n = coalesce(n, 0) + k returning k, n",
              "begin", "delete from ps where k = 2", "select count(*), sum(k), min(k), max(k) from ps", "rollback",
              "select count(*) from ps",
              "insert into ps values (4, 'd', 1, true) on conflict do nothing",
              "select k, name from ps where name like '%a%' or k in (3, 4) order by k limit 3",
              "alter table ps add column extra text default 'x'",
              "select * from ps order by k desc",
              "drop table ps"]
    args = []
    for s in script:
        args += ["-c", s]
    srv = Server(os.path.join(d, "psql.db"))
    theirs = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(srv.port), "-U", "postgres", "-d", db, "-X"] + args, capture_output=True, text=True)
    srv.stop()
    pg = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-d", db, "-X"] + args, capture_output=True, text=True)
    check("psql prints for the server what it prints for PostgreSQL (%d statements, %d lines)" % (len(script), len(pg.stdout.splitlines())),
          theirs.returncode == 0 and pg.returncode == 0 and theirs.stdout == pg.stdout and theirs.stderr == pg.stderr and len(pg.stdout.splitlines()) > 30,
          "\n".join(difflib.unified_diff((theirs.stdout + theirs.stderr).splitlines(), (pg.stdout + pg.stderr).splitlines(), "server", "postgres", lineterm="")))


def beside(d):
    """The export tool (6av) run again and again beside a server that clients write to: each run is whole and verifies, or says it raced a commit; never something else."""
    import threading
    import time
    tool = os.environ.get("LOGEXPORT", os.path.join(ROOT, "build", "logexport"))
    path = os.path.join(d, "beside")
    srv = Server(path)
    c = Client(srv.port)
    for i in range(4):
        c.query("create table w%d (k integer primary key, v text)" % i)
    c.query("insert into w0 values (-1, 'the first commit: a table made changes no row and is no commit')")
    c.close()
    done = [0]

    def writer(i):
        cl = Client(srv.port)
        for k in range(120):
            cl.query("insert into w%d values (%d, 'row %d of writer %d')" % (i, k, k, i))
            time.sleep(0.004 * (1 + (k * 7 + i) % 5))
        cl.close()
        done[0] += 1
    ths = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in ths:
        t.start()

    def run(*what):
        r = subprocess.run([tool, path] + [str(x) for x in what], capture_output=True)
        return r.returncode, r.stdout, r.stderr.decode().strip()

    def judged(name, data, more=()):
        with open(os.path.join(d, name), "wb") as fh:
            fh.write(data)
        return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "verify.py" if not more else "l3a.py"), os.path.join(d, name)] + list(more), capture_output=True, text=True).stdout.strip()
    whole, raced, sets, odd, last = 0, 0, 0, [], 0
    while done[0] < 4:
        st, out, err = run("anchor")
        if st == 0:
            n = int(out.split()[1])
            if n < last:
                odd.append(("the log got shorter", n, last))
            last = n
            a, b = run("log", n), run("facts", n)
            for st2, data, err2 in (a, b):
                if st2 == 0:
                    whole += 1
                elif (st2, err2) == (1, "refused export-raced"):
                    raced += 1
                else:
                    odd.append((st2, err2))
            if a[0] == 0:
                v = judged("b.log", a[1])
                if not v.startswith("ok commits=%d " % n):
                    odd.append(("log", n, v))
            if a[0] == 0 and b[0] == 0 and n > 0:
                with open(os.path.join(d, "b.facts"), "wb") as fh:
                    fh.write(b[1])
                v = judged("b.log", a[1], ["--deltas", os.path.join(d, "b.facts")])
                sets += 1
                if not v.startswith("ok commits=%d " % n):
                    odd.append(("facts", n, v))
        elif (st, err) == (1, "refused export-raced"):
            raced += 1
        else:
            odd.append((st, err))
    for t in ths:
        t.join()
    check("the export tool beside a server 4 clients write to: %d runs whole, each log verifies and each log with its facts (%d sets) has every commit's changes; %d runs say they raced a commit; nothing else"
          % (whole, sets, raced), not odd and whole >= 3 and sets >= 1 and raced >= 1, odd[:3] or (whole, sets, raced))
    # the writers done: one anchor, and everything at it
    st, out, err = run("anchor")
    n = int(out.split()[1]) if st == 0 else -1
    files = {w: run(w, n) if w in ("log", "facts", "live") else run(w) for w in ("log", "facts", "tokens", "stmts", "live")}
    for w in files:
        with open(os.path.join(d, "e." + w), "wb") as fh:
            fh.write(files[w][1])
    good = n == 1 + 4 * 120 and all(files[w][0] == 0 for w in files)
    for cmd in VERIFIERS:
        v = subprocess.run(cmd.split() + [os.path.join(d, "e.log"), "--deltas", os.path.join(d, "e.facts"), "--live-dump", os.path.join(d, "e.live")], capture_output=True, text=True, cwd=ROOT)
        v = (v.stdout + v.stderr).strip()
        check("%s, on what the tool wrote beside the server once the writers are done (%d commits): ok, the rows compared" % (cmd, n), good and v.startswith("ok commits=%d " % n) and v.endswith(" final"), v)
    srv.stop()


def main():
    with tempfile.TemporaryDirectory() as d:
        differential(d)
        srv = durability(d)
        garbage(srv)
        check("the server is still running at the end", srv.alive())
        srv.stop()
        several(d)
        beside(d)
        logins(d)
        with_psql(d)
        with_cancho_pg(d)
    if FAILED:
        print("FAIL engine wire: %d failed" % len(FAILED))
        return 1
    print("PASS engine wire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
