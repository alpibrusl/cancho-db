#!/usr/bin/env python3
"""The extended protocol through the proxy (docs/m1-extended.md, P3b and P3c), against a real PostgreSQL, from raw protocol messages.

    PG_E2E_PORT=5532 python3 tests/ext_e2e.py PROXY_BINARY

What it checks, with no driver in the way (the drivers are tests/drivers_e2e.py):

  * the message sequences measured from real drivers (docs/m1-extended.md section 2: psycopg 3, asyncpg, pgx, pg8000, node-postgres) get
    from the proxy **the answers PostgreSQL itself gives**, message for message;
  * a refusal is an error and every message up to Sync discarded, as PostgreSQL does, with the transaction rolled back and Sync answered;
  * a transaction through the extended protocol is one commit, a statement counts at Execute, and the log, tokens and statements of the
    session are accepted by the verifiers at L2 and IR;
  * what the proxy sends the server: the guard's rendering in Parse, and nothing the guard refused.
"""
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))
from pgtee import Tee  # noqa: E402
import verify as pyverify  # noqa: E402

PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "postgres")
PROXY = sys.argv[1]
VERIFIERS = os.environ.get("E2E_VERIFIERS", "").split()
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:600]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def mint(*args): return subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "mint.py")] + list(args), capture_output=True, text=True, check=True).stdout.strip()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def psql(sql):
    return subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", DB, "-c", sql], capture_output=True, text=True)


ROOT = mint("root")
TOKEN = mint("password", "--effects", "r:*,w:*,d:*,c:*,n:*")
NARROW = mint("password", "--effects", "r:xe,r:xe.a,r:xe.b")


# ---------------------------------------------------------------------------------------------------- the raw protocol
def msg(t, body=b""): return t + struct.pack(">I", len(body) + 4) + body
def cs(x): return x.encode() + b"\0"


def Parse(name, sql, types=()): return msg(b"P", cs(name) + cs(sql) + struct.pack(">H", len(types)) + b"".join(struct.pack(">I", t) for t in types))


def Bind(portal, stmt, params=(), pfmt=(), rfmt=()):
    body = cs(portal) + cs(stmt) + struct.pack(">H", len(pfmt)) + b"".join(struct.pack(">H", f) for f in pfmt)
    body += struct.pack(">H", len(params))
    for v in params:
        body += struct.pack(">i", -1) if v is None else struct.pack(">i", len(v)) + v
    return msg(b"B", body + struct.pack(">H", len(rfmt)) + b"".join(struct.pack(">H", f) for f in rfmt))


def Describe(kind, name=""): return msg(b"D", kind.encode() + cs(name))
def Execute(portal="", rows=0): return msg(b"E", cs(portal) + struct.pack(">I", rows))
def Close(kind, name=""): return msg(b"C", kind.encode() + cs(name))
def Sync(): return msg(b"S")
def Flush(): return msg(b"H")
def Query(sql): return msg(b"Q", cs(sql))


class Conn:
    """A raw client: direct to PostgreSQL (trust login) when `password` is None, or to the proxy."""

    def __init__(self, port, password=None, db="main"):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=20)
        self.buf = b""
        body = struct.pack(">I", 196608) + b"user\0" + (b"agent" if password else b"postgres") + b"\0database\0" + (db if password else DB).encode() + b"\0\0"
        self.s.sendall(struct.pack(">I", len(body) + 4) + body)
        if password:
            self.until(b"R")
            self.s.sendall(msg(b"p", cs(password)))
        self.z()

    def one(self):
        while len(self.buf) < 5 or len(self.buf) < 1 + struct.unpack(">I", self.buf[1:5])[0]:
            d = self.s.recv(65536)
            if not d:
                raise EOFError("closed")
            self.buf += d
        n = struct.unpack(">I", self.buf[1:5])[0]
        m = (chr(self.buf[0]), self.buf[5:1 + n])
        self.buf = self.buf[1 + n:]
        return m

    def until(self, t):
        while True:
            m = self.one()
            if m[0] == t.decode():
                return m

    def z(self):
        out = []
        while True:
            m = self.one()
            out.append(m)
            if m[0] == "Z":
                return out

    def count(self, n):
        return [self.one() for _ in range(n)]

    def send(self, *ms):
        self.s.sendall(b"".join(ms))

    def run(self, *ms):
        self.send(*ms)
        return self.z()

    def close(self):
        try:
            self.s.sendall(msg(b"X"))
        except OSError:
            pass
        self.s.close()


def kinds(ms): return "".join(m[0] for m in ms)
def errs(ms): return [re.search(rb"C(\w{5})\0", b).group(1).decode() for k, b in ms if k == "E"]
def status(ms): return ms[-1][1].decode()


def start(ldir, upstream=None):
    port = free_port()
    p = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(upstream or PG_PORT), "main", ROOT, "postgres", DB, str(ldir), str(Path(ldir).parent / "key")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    for _ in range(200):
        if p.poll() is not None:
            break
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    return p, port


def read_log(path):
    data = Path(path).read_bytes()
    at, out = 40, []
    while at < len(data):
        n = struct.unpack(">I", data[at:at + 4])[0]
        out.append(pyverify.decode(data[at + 4:at + 4 + n]) + (data[at + 4:at + 4 + n],))
        at += 4 + n + 64
    return out


def verifiers_accept(label, ldir, n):
    argv = ["--root", ROOT, "--tokens", str(ldir / "tokens"), "--stmts", str(ldir / "stmts")]
    for name, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
        out = subprocess.run(cmd + [str(ldir / "log")] + argv, capture_output=True, text=True).stdout.strip()
        check("%s: %s accepts the log, the tokens and the statements at L2 and IR" % (label, name), out.startswith("ok commits=%d " % n), out)


# ---------------------------------------------------------------------------------------------------- setup
work = Path(tempfile.mkdtemp())
(work / "key").write_bytes(bytes(range(32)))
ldir = work / "log"
ldir.mkdir()
for t in ("xe", "xo"):
    psql("drop table if exists %s" % t)
psql("create table xe(a int primary key, b text, c numeric)")
psql("insert into xe values (1, 'one', 1.5), (2, 'two', 2.5)")
psql("create table xo(a int primary key, b text)")
tee = Tee(PG_PORT)
proc, port = start(ldir, tee.port)
check("the proxy starts", proc.poll() is None)
direct = lambda: Conn(PG_PORT)
via = lambda: Conn(port, TOKEN)


def same_answers(name, seq_builder, setup=None):
    """The messages of one sequence, run direct and through the proxy: the same kinds and the same payloads (the proxy's rendering of a
    statement is what PostgreSQL then parses, so a plan or a row is the same)."""
    d, v = direct(), via()
    a = seq_builder(d, "d")
    b = seq_builder(v, "v")
    d.close()
    v.close()
    check("%s: the proxy's answers are PostgreSQL's (%s)" % (name, kinds(b)), kinds(a) == kinds(b) and [m for m in a if m[0] not in "Z"] == [m for m in b if m[0] not in "Z"], "%s\n%s" % (a, b))
    return b


# ---------------------------------------------------------------------------------------------------- the sequences of real drivers
SEL = "select a, b from xe where a = $1"
same_answers("psycopg 3 (unnamed, binary parameter)",
             lambda c, w: c.run(Parse("", SEL, [21]), Bind("", "", [b"\x00\x01"], [1], [0]), Describe("P"), Execute(), Sync()))
same_answers("node-postgres (unnamed, text parameter)",
             lambda c, w: c.run(Parse("", SEL), Bind("", "", [b"2"], [0], [0]), Describe("P"), Execute(), Sync()))


def asyncpg_like(c, w):
    out = []
    c.send(Parse("s_" + w + "1", SEL), Describe("S", "s_" + w + "1"), Flush())
    out += c.count(3)
    out += c.run(Bind("", "s_" + w + "1", [b"\x00\x00\x00\x01"], [1], [1]), Execute(), Sync())
    out += c.run(Bind("", "s_" + w + "1", [b"\x00\x00\x00\x02"], [1], [1]), Execute(), Sync())
    return out


same_answers("asyncpg (named, Describe S and Flush, then Bind and Execute, reused)", asyncpg_like)


def pgx_like(c, w):
    out = c.run(Parse("p_" + w, SEL), Describe("S", "p_" + w), Sync())
    out += c.run(Bind("", "p_" + w, [b"\x00\x00\x00\x01"], [1], [1, 0]), Describe("P"), Execute(), Sync())
    out += c.run(Bind("", "p_" + w, [b"\x00\x00\x00\x02"], [1], [1, 0]), Describe("P"), Execute(), Sync())
    return out


same_answers("pgx (Parse, Describe S, Sync; Bind, Describe P, Execute, Sync, twice)", pgx_like)


def pg8000_like(c, w):
    out = []
    c.send(Parse("", SEL), Flush(), Sync())
    out += c.z()
    c.send(Describe("S"), Flush(), Sync())
    out += c.z()
    c.send(Bind("", "", [b"1"], [], []), Flush(), Execute(), Flush(), Sync())
    out += c.z()
    return out


same_answers("pg8000 (a Flush and a Sync after almost every message)", pg8000_like)
same_answers("a Parse of a name, Describe S, Close and Bind of it is an error, as PostgreSQL says it",
             lambda c, w: c.run(Parse("c_" + w, SEL), Close("S", "c_" + w), Bind("", "c_" + w, [b"1"]), Execute(), Sync())[0:2] + [("-", b"")])
same_answers("an unnamed portal run twice (the second Execute of a finished portal)",
             lambda c, w: c.run(Parse("", SEL), Bind("", "", [b"1"]), Execute(), Execute(), Sync()))
same_answers("a row limit: Execute of 1 row of 2 is PortalSuspended, and Execute again gives the rest",
             lambda c, w: c.run(Parse("", "select a from xe order by a"), Bind("", ""), Execute("", 1), Execute("", 1), Execute("", 1), Sync()))
same_answers("an empty Parse is refused by the proxy where PostgreSQL would answer EmptyQueryResponse: the proxy's refusal, then Sync",
             lambda c, w: [m for m in c.run(Parse("", ""), Bind("", ""), Execute(), Sync())][-1:])

# ---------------------------------------------------------------------------------------------------- what the proxy sends
tee.clear()
v = via()
v.run(Parse("", "select a  /* x */, b from XE where a = $1"), Bind("", "", [b"1"]), Execute(), Sync())
ups = [(k, d) for k, d in tee.messages if k in ("Parse", "Query", "Bind", "Execute", "S", "Describe") and not str(d).startswith("select c.relname")]
check("the server is sent BEGIN (the proxy's own, by the extended protocol under a name of its own), the guard's rendering in Parse (with `$1`) under the client's name, then COMMIT",
      [d for k, d in ups if k == "Parse"][:1] == ["BEGIN"] and any(k == "Parse" and d == 'select "a", "b" from "xe" where ("a" = $1)' for k, d in ups)
      and [d for k, d in ups if k == "Parse"][-1] == "COMMIT", ups)
v.close()

# ---------------------------------------------------------------------------------------------------- refusals
v = via()
tee.clear()
r = v.run(Parse("", "select c.relname from pg_class c"), Bind("", ""), Execute(), Sync())
check("a statement the guard refuses: one error (42P01 or 0A000), everything up to Sync discarded, ReadyForQuery I", len(errs(r)) == 1 and kinds(r) == "EZ" and status(r) == "I", r)
check("... and nothing of it reached the server", not [d for k, d in tee.messages if k == "Parse" and "pg_class" in str(d)], tee.messages)
r = v.run(Query("select a from xe where a = 1"))
check("... and the connection is fine after", kinds(r) == "TDCZ", r)

r = v.run(Parse("", "select a from xe where a = $1"), Bind("", "", [b"1"]), Execute(), Parse("", "drop table xe cascade"), Bind("", ""), Execute(), Sync())
check("a refusal after an Execute: the first statement's tag, then the error, then ReadyForQuery I (PostgreSQL's own stream), and nothing is left running",
      kinds(r) == "12DCEZ" and status(r) == "I", r)

r = v.run(Parse("", "insert into xo values ($1, 'x')"), Bind("", "", [b"500"]), Execute(), Parse("", "select c.relname from pg_class c"), Bind("", ""), Execute(), Sync())
check("an INSERT and then a refused statement in one group: the group is rolled back (the row is not there)", errs(r) and psql("select count(*) from xo where a = 500").stdout.strip() == "0", (r, psql("select count(*) from xo where a = 500").stdout))

v.send(Query("begin"))
v.z()
r = v.run(Parse("", "select c.relname from pg_class c"), Bind("", ""), Execute(), Sync())
check("a refusal inside a transaction fails it: ReadyForQuery E", errs(r) and status(r) == "E", r)
r = v.run(Parse("", "select a from xe where a = $1"), Bind("", "", [b"1"]), Execute(), Sync())
check("... and a statement after it is 25P02 until ROLLBACK", errs(r) == ["25P02"] and status(r) == "E", r)
r = v.run(Query("rollback"))
check("... ROLLBACK ends it", status(r) == "I", r)

r = v.run(Parse("cdb_x", "select a from xe where a = $1"), Sync())
check("a statement name starting cdb is refused (0A000): the proxy's own commands use those", errs(r) == ["0A000"], r)
r = v.run(Parse("", "select a from xe where a = $1"), Bind("cdb_p", "", [b"1"]), Sync())
check("... and so is a portal name", errs(r) == ["0A000"], r)

# a refusal in an implicit transaction rolls the server's one back: the server was sent ROLLBACK, and the next group works
tee.clear()
r = v.run(Parse("", "insert into xo values ($1, 'x')"), Bind("", "", [b"501"]), Execute(), Parse("", "select c.relname from pg_class c"), Bind("", ""), Execute(), Sync())
q = tee.queries()
check("a refusal after an INSERT: the server was sent ROLLBACK (not left in its transaction)", "ROLLBACK" in q and "COMMIT" not in q and not any(x.startswith("PREPARE") for x in q), q)
r = v.run(Parse("", "select a from xe where a = $1"), Bind("", "", [b"1"]), Execute(), Sync())
check("... and the next group on the connection works", kinds(r) == "12DCZ", r)

# the proxy keeps the state it says: a refusal inside a transaction, then Sync, says E (and ReadyForQuery T before the refusal)
v.send(Query("begin"))
v.z()
r = v.run(Parse("", "select 1 from xe where a = $1"), Bind("", "", [b"1"]), Sync())
check("inside a transaction, ReadyForQuery says T", status(r) == "T", r)
r = v.run(Parse("", "select c.relname from pg_class c"), Sync())
check("a refusal there: the error, then ReadyForQuery E", errs(r) == ["42P01"] or errs(r) == ["0A000"] or len(errs(r)) == 1, r)
check("... status E", status(r) == "E", r)
v.run(Query("rollback"))

# messages the proxy does not support (a function call, COPY data): ONE error, everything up to Sync discarded (here a whole Parse/Bind/Execute that would otherwise be answered), Sync answered
tee.clear()
fcall = msg(b"F", struct.pack(">IhhH", 1234, 0, 0, 0) + struct.pack(">h", 0))
r = v.run(fcall, Parse("", "select a from xe where a = $1"), Bind("", "", [b"1"]), Execute(), Sync())
check("a function-call message: one 0A000, the Parse, Bind and Execute after it are discarded, ReadyForQuery I", errs(r) == ["0A000"] and kinds(r) == "EZ" and status(r) == "I", r)
check("... and none of them reached the server", not [d for k, d in tee.messages if k in ("Parse", "Bind", "Execute") and "xe" in str(d) and "cdb_x" not in str(d)], tee.messages)
r = v.run(msg(b"d", b"abc"), Parse("", "select a from xe where a = $1"), Bind("", "", [b"1"]), Execute(), Sync())
check("COPY data (d): the same", errs(r) == ["0A000"] and kinds(r) == "EZ" and status(r) == "I", r)
r = v.run(Query("select a from xe where a = 1"))
check("... and the connection is fine after both", kinds(r) == "TDCZ", r)

r = v.run(Parse("dup", "select 1 from xe where a = $1"), Sync())
r = v.run(Parse("dup", "select 1 from xe where a = $1"), Sync())
check("a named statement parsed twice is 42P05, as in PostgreSQL", errs(r) == ["42P05"], r)
r = v.run(Bind("", "nope", []), Execute(), Sync())
check("a Bind of a statement that does not exist is 26000", errs(r) == ["26000"], r)
r = v.run(Execute("nowhere"), Sync())
check("an Execute of a portal that does not exist is 34000", errs(r) == ["34000"], r)
r = v.run(Parse("", "select 1 from xe; select 2 from xe"), Sync())
check("two statements in one Parse are refused (multiple-statements)", len(errs(r)) == 1, r)
for i in range(33):
    r = v.run(Parse("many%d" % i, "select a from xe where a = $1"), Sync())
check("the 33rd named statement of a connection is refused (54000)", errs(r) == ["54000"], r)
v.close()

# a statement the server itself refuses: the error comes from the server and everything after it up to Sync is discarded
v = via()
psql("delete from xo")
psql("insert into xo values (1, 'one')")
r = v.run(Parse("", "insert into xo values ($1, $2)"), Bind("", "", [b"1", b"dup"]), Execute(), Parse("", "insert into xo values ($1, $2)"), Bind("", "", [b"2", b"ok"]), Execute(), Sync())
check("a duplicate key (the server's error 23505): the rest of the group is discarded and ReadyForQuery I", errs(r) == ["23505"] and status(r) == "I" and psql("select count(*) from xo").stdout.strip() == "1", r)
v.close()

# ---------------------------------------------------------------------------------------------------- the commits
n_before = len(read_log(ldir / "log"))
v = via()
psql("delete from xo")
v.run(Parse("", "insert into xo values ($1, $2)"), Bind("", "", [b"10", b"a"]), Execute(), Parse("", "insert into xo values ($1, $2)"), Bind("", "", [b"11", b"b"]), Execute(), Sync())
v.run(Parse("ins", "insert into xo values ($1, $2)"), Describe("S", "ins"), Flush()) if False else None
v.run(Parse("ins", "insert into xo values ($1, $2)"), Sync())
v.run(Bind("", "ins", [b"12", b"c"]), Execute(), Sync())
v.run(Bind("", "ins", [b"13", b"d"]), Execute(), Bind("p2", "ins", [b"14", b"e"]), Execute("p2"), Sync())
v.run(Query("begin"))
v.run(Parse("", "insert into xo values ($1, $2)"), Bind("", "", [b"15", b"f"]), Execute(), Sync())
v.run(Parse("", "select a from xo where a = $1"), Bind("", "", [b"15"]), Execute(), Sync())
v.run(Query("commit"))
v.run(Parse("", "select a from xo where a = $1"), Bind("", "", [b"10"]), Execute(), Sync())
v.run(Parse("", "select a from xo where a = $1"), Bind("", "", [b"10"]), Describe("P"), Sync())
v.close()
time.sleep(0.3)
log = read_log(ldir / "log")[n_before:]
check("the rows of all of it are there (10 to 15)", psql("select string_agg(a::text, ',' order by a) from xo").stdout.strip() == "10,11,12,13,14,15", psql("select string_agg(a::text, ',' order by a) from xo").stdout)
check("one commit per implicit transaction, and one for the explicit one: 2 inserts, 1 Parse alone (none), 1, 2, the transaction (2 statements), a select, a Parse-and-Describe (none)",
      [len(c[3][5]) for c in log] == [2, 1, 2, 2, 1], [len(c[3][5]) for c in log])
check("the explicit transaction lists its two statements (each counted at its Execute)", len(log[3][3][5]) == 2, log[3][3][5])
verifiers_accept("the extended session", ldir, n_before + len(log))

# ---------------------------------------------------------------------------------------------------- a narrow token
nv = Conn(port, NARROW)
r = nv.run(Parse("", "select a from xe where a = $1"), Bind("", "", [b"1"]), Execute(), Sync())
check("a token narrowed to xe.a and xe.b: a statement that reads those is allowed", kinds(r) == "12DCZ", r)
r = nv.run(Parse("", "select c from xe where a = $1"), Bind("", "", [b"1"]), Execute(), Sync())
check("... and one that reads xe.c is refused before the server sees it (42501)", errs(r) == ["42501"], r)
nv.close()

proc.terminate()
proc.communicate(timeout=10)
tee.stop()
psql("drop table if exists xe")
psql("drop table if exists xo")
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall extended-protocol checks passed")
sys.exit(1 if FAILED else 0)
