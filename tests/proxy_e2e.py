#!/usr/bin/env python3
"""The P0 and P1d gates (docs/m1-proxy.md section 7, docs/m1-lowering.md section 5.2), against a real PostgreSQL and the stock psql.

    PG_E2E_PORT=5532 python3 tests/proxy_e2e.py PROXY_BINARY

PostgreSQL must be on 127.0.0.1:$PG_E2E_PORT with trust login for the role `postgres`. The test puts a wire tee
(tools/pgtee.py) between the proxy and PostgreSQL, which is how it counts the connections that reach the server: a refused
login must not be one of them, and a refused query must not be a Query the server sees. It creates and drops the tables `p0_e2e` and
`p0_big`, directly on the server. Exit status 1 if any check fails.
"""
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))
from pgtee import Tee, ensure_database  # noqa: E402

PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_e2e")        # the database the proxy is pointed at: a mutant run gives each worker its own
ensure_database(PG_PORT, DB)
PROXY = sys.argv[1]
MINT = [sys.executable, str(ROOT_DIR / "tools" / "mint.py")]
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def mint(*args): return subprocess.run(MINT + list(args), capture_output=True, text=True, check=True).stdout.strip()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


ROOT = mint("root")


def client_starts(tee):
    return [d for k, d in tee.messages if k == "Startup" and d.get("application_name") != "cancho-db-catalog"]


def client_queries(tee):
    """What PostgreSQL was sent by clients' connections: not the proxy's own catalog questions."""
    out = []
    for q in tee.queries():
        if q.startswith("select c.relname, a.attname"):
            continue
        if q.startswith("select case when length(f) > 200000"):
            q = "FACTS"           # the proxy asks for the transaction's net facts before it builds the commit (M2b-2b)
        elif q.startswith("update cdb.delta set commit_id") or q.startswith("with m as (insert into cdb.mark"):
            q = "DELTA ID"        # ... and gives them the commit's id
        out.append(re.sub(r"'cdb:[0-9a-f]{64}'", "'cdb:ID'", q))
    return out


def client_statements(tee):
    """What clients' statements became upstream: client_queries without the transaction commands the proxy adds itself."""
    return [q for q in client_queries(tee) if q not in ("BEGIN", "COMMIT", "ROLLBACK", "FACTS", "DELTA ID") and not q.startswith(("PREPARE TRANSACTION", "COMMIT PREPARED"))]


def direct(sql):
    return subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", DB, "-c", sql],
                          capture_output=True, text=True)


_scratch = tempfile.mkdtemp()
Path(_scratch, "key").write_bytes(bytes(range(32)))
_runs = [0]


def start_proxy(listen, upstream_port, branch="main"):
    """A proxy with a log directory of its own (the log is not optional, P2d-2): a new one for every start."""
    _runs[0] += 1
    logdir = Path(_scratch, "log%d" % _runs[0])
    logdir.mkdir()
    p = subprocess.Popen([PROXY, str(listen), "127.0.0.1", str(upstream_port), branch, ROOT, "postgres", DB, str(logdir), str(Path(_scratch, "key"))],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", listen), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.05)
    raise SystemExit("the proxy did not start listening")


def psql(port, password, sql, db="main", extra=(), input=None, ssl="prefer", timeout=30):
    env = dict(os.environ, PGPASSWORD=password, PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="agent", PGDATABASE=db,
               PGSSLMODE=ssl, PGCONNECT_TIMEOUT="25")
    args = ["psql", "-w", "-At", "-v", "ON_ERROR_STOP=0", *extra] + (["-c", sql] if sql else [])
    try:
        return subprocess.run(args, env=env, capture_output=True, text=True, input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        # a hung psql is a failed check, not a crashed test
        return subprocess.CompletedProcess(args, 124, "", "psql timed out after %d s" % timeout)


def raw(port, data, read=64, wait=1.0):
    """Send `data`, return what comes back (b"" if the server just closes)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=wait + 5)
    s.sendall(data)
    s.settimeout(wait)
    out = b""
    try:
        while len(out) < read:
            d = s.recv(4096)
            if not d:
                break
            out += d
    except socket.timeout:
        out = out or b"<timeout>"
    s.close()
    return out


tee = Tee(PG_PORT)
lp = free_port()
proxy = start_proxy(lp, tee.port)
ALLOW = "r:*,w:*,d:*,c:*,n:*"
good = mint("password", "--effects", ALLOW)
direct("drop table if exists p0_e2e, p0_big cascade")
direct("create table p0_e2e(a int primary key, b text); insert into p0_e2e values (1,'x'),(2,'y'),(3,'z')")
direct("create table p0_big(g int primary key, m text); insert into p0_big select g, md5(g::text) from generate_series(1,200000) g")
Q1 = "select a from p0_e2e order by a limit 1"

# ---------------------------------------------------------------- a valid login, and what the proxy lets through
r = psql(lp, good, "select a, b from p0_e2e order by a")
check("valid token: psql connects (default sslmode, so SSLRequest is answered N) and runs a query",
      r.returncode == 0 and r.stdout.strip() == "1|x\n2|y\n3|z", r.stdout + r.stderr)
check("... and the connection reached PostgreSQL once (the proxy's own catalog connection is another)",
      len(client_starts(tee)) == 1, str(tee.kinds()))
startup = client_starts(tee)[0]
check("... as the configured role and database, not the client's choice",
      startup.get("user") == "postgres" and startup.get("database") == DB, str(startup))
check("... with the client's application_name passed through", startup.get("application_name") == "psql", str(startup))

r = psql(lp, good, "", input="insert into p0_e2e values (4,'w'),(5,'v');\nselect count(*) from p0_e2e;\n")
check("DML round trip", r.returncode == 0 and "INSERT 0 2" in r.stdout and r.stdout.strip().endswith("5"), r.stdout + r.stderr)
r = psql(lp, good, "insert into p0_e2e values (1, 'dup')")
check("a PostgreSQL error the guard cannot see is relayed as it is", "duplicate key value" in r.stderr, r.stderr)
psql(lp, good, "delete from p0_e2e where a > 3")

direct_rows = direct("select g, m from p0_big").stdout
via = psql(lp, good, "select g, m from p0_big").stdout
check("200,000 rows come back byte for byte as direct (%d bytes)" % len(direct_rows),
      direct_rows == via and len(direct_rows) > 7_000_000, "%d vs %d bytes" % (len(direct_rows), len(via)))

procs = [subprocess.Popen(["psql", "-At", "-c", "select %d from p0_e2e limit 1" % i],
                          env=dict(os.environ, PGPASSWORD=good, PGHOST="127.0.0.1", PGPORT=str(lp), PGUSER="agent",
                                   PGDATABASE="main", PGSSLMODE="disable"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True) for i in range(24)]
outs = [p.communicate(timeout=60)[0].strip() for p in procs]
check("24 clients at once all get their own answer", sorted(outs) == sorted("%d" % i for i in range(24)), str(outs[:3]))

for n in (2, 3, 5):
    pw = mint("password", "--blocks", str(n), "--effects", ALLOW)
    r = psql(lp, pw, Q1)
    check("a token of %d blocks (a %d-character password) works" % (n, len(pw)), r.returncode == 0 and r.stdout.strip() == "1", r.stderr)

# ---------------------------------------------------------------- refused logins, and none of them reaches PostgreSQL
before = len(client_starts(tee))
cases = [
    ("a key that is not the token's last", ("password", "--wrong-seed"), "main", "login-bad-proof", "28P01"),
    ("a token signed by another root", ("password", "--foreign"), "main", "login-bad-signature", "28P01"),
    ("a token for another branch", ("password", "--branch", "agent/*"), "main", "login-branch-denied", "3D000"),
    ("an expired token", ("password", "--expiry", "1"), "main", "login-expired", "28P01"),
    ("a branch this server does not serve", ("password",), "other", "login-branch-denied", "3D000"),
]
for name, margs, db, tag, state in cases:
    r = psql(lp, mint(*margs), "select 1", db=db)
    verbose = psql(lp, mint(*margs), "select 1", db=db, extra=("-v", "VERBOSITY=sqlstate"))
    check("refused: %s (%s)" % (name, tag), r.returncode != 0 and tag in r.stderr and r.stdout == "", r.stderr)
r = psql(lp, "hunter2", "select 1")
check("refused: a password that is not a token (login-bad-token)", "login-bad-token" in r.stderr and r.returncode != 0, r.stderr)
check("... none of those %d refusals reached PostgreSQL" % (len(cases) + 1),
      len(client_starts(tee)) == before, "%d new connections" % (len(client_starts(tee)) - before))

# SQLSTATEs, read from the wire: an ErrorResponse's C field
def error_state(data):
    i = data.find(b"E")
    if i < 0:
        return None
    body = data[i + 5:]
    for field in body.split(b"\0"):
        if field[:1] == b"C":
            return field[1:].decode()
    return None


def startup_packet(db=b"main", ver=196608):
    body = struct.pack(">I", ver) + b"user\0agent\0database\0" + db + b"\0\0"
    return struct.pack(">I", len(body) + 4) + body


def password_packet(pw):
    body = pw.encode() + b"\0"
    return b"p" + struct.pack(">I", len(body) + 4) + body


for tag, margs, db, state in [("login-bad-proof", ("password", "--wrong-seed"), b"main", "28P01"),
                              ("login-branch-denied", ("password", "--branch", "agent/*"), b"main", "3D000")]:
    out = raw(lp, startup_packet(db), read=9)          # Authentication request
    got = raw(lp, startup_packet(db) + password_packet(mint(*margs)), read=400)
    check("%s is SQLSTATE %s on the wire" % (tag, state), error_state(got) == state, str(got[:80]))

# ---------------------------------------------------------------- the protocol before login
got = raw(lp, startup_packet() + password_packet(""), read=400)
check("an empty password is refused with 28P01", error_state(got[9:]) == "28P01" and b"login-bad-token" in got, str(got[:80]))
before = len(client_starts(tee))
check("SSLRequest is answered N", raw(lp, struct.pack(">II", 8, 80877103), read=1) == b"N")
check("GSSENCRequest is answered N", raw(lp, struct.pack(">II", 8, 80877104), read=1) == b"N")
check("a startup asks for a cleartext password (R, length 8, code 3)",
      raw(lp, startup_packet(), read=9) == b"R" + struct.pack(">II", 8, 3))
got = raw(lp, startup_packet(ver=131072), read=300)
check("protocol 2.0 is refused with 0A000", error_state(got) == "0A000", str(got[:60]))
got = raw(lp, struct.pack(">I", 12) + b"\x00\x03\x00\x00xx\x00\x00", read=300)
check("a malformed startup is refused with 08P01", error_state(got) == "08P01", str(got[:60]))
got = raw(lp, struct.pack(">I", 3) + b"x", read=300)
check("a startup length under 8 is refused with 08P01", error_state(got) == "08P01", str(got[:60]))
got = raw(lp, startup_packet() + b"X" + struct.pack(">I", 4), read=300)
check("a message other than a password is refused with 08P01", error_state(got[9:]) == "08P01", str(got[:60]))
got = raw(lp, struct.pack(">IIII", 16, 80877102, 7, 9), read=10, wait=0.5)
check("a CancelRequest is closed without an answer (P0 does not forward cancels)", got == b"", str(got))
got = raw(lp, startup_packet() + b"p" + struct.pack(">I", 70000) + b"A" * 100, read=400)
check("a password message longer than the login buffer is refused", error_state(got[9:]) in ("08P01",), str(got[:60]))

new_starts = client_starts(tee)[before:]
check("... and nothing in the protocol section reached PostgreSQL either", not new_starts,
      "%d new connections: %s" % (len(new_starts), new_starts))

# ---------------------------------------------------------------- only loopback
hosts = subprocess.run("hostname -I", shell=True, capture_output=True, text=True).stdout.split()
outside = [h for h in hosts if not h.startswith("127.") and ":" not in h]
if outside:
    s = socket.create_connection((outside[0], lp), timeout=3)   # the proxy listens on every address: this connects
    s.settimeout(3)
    try:
        s.sendall(struct.pack(">II", 8, 80877103))
        data = s.recv(10)
        verdict = "closed" if data == b"" else "answered %r" % data
    except ConnectionResetError:
        verdict = "closed"          # a reset on close means bytes were left unread: the proxy never read them
    except socket.timeout:
        verdict = "left open"
    s.close()
    check("a client on a non-loopback address (%s) is closed and gets no answer to its SSLRequest" % outside[0],
          verdict == "closed", verdict)
else:
    print("skip a non-loopback client: this host has no non-loopback IPv4 address")

# ---------------------------------------------------------------- slow and silent peers
t0 = time.time()
s = socket.create_connection(("127.0.0.1", lp))
s.settimeout(20)
try:
    closed = s.recv(10) == b""
except socket.timeout:
    closed = False
dt = time.time() - t0
check("a client that sends nothing is closed after about 10 s (%.1f s)" % dt, closed and 9 < dt < 14)
s.close()
check("... and the proxy still serves", psql(lp, good, Q1).stdout.strip() == "1")

# (the proxy settles prepared transactions before it listens, so it needs a live server to start: these upstreams are tees that go bad after that)
silent_tee = Tee(PG_PORT)
p2 = free_port()
proxy2 = start_proxy(p2, silent_tee.port)
silent_tee.blackhole = True
t0 = time.time()
r = psql(p2, good, "select 1", timeout=40)
dt = time.time() - t0
check("an upstream that never answers: refused with upstream-timeout after about 5 s (%.1f s)" % dt,
      "upstream-timeout" in r.stderr and 4 < dt < 12, r.stderr)
proxy2.terminate()
silent_tee.stop()
dead_tee = Tee(PG_PORT)
proxy3 = start_proxy(free_port(), dead_tee.port)
# the listener is open before recovery has run: a query that is answered shows the proxy is serving, and only then does the upstream go
psql(int(proxy3.args[1]), good, "select 1")
dead_tee.stop()
p3 = proxy3.args[1]
r = psql(int(p3), good, "select 1")
check("an upstream that is down: refused with upstream-unavailable", "upstream-unavailable" in r.stderr, r.stderr)
proxy3.terminate()

# ---------------------------------------------------------------- P1d: what the guard does to queries, seen at the server
narrow = mint("password", "--effects", "r:p0_e2e,r:p0_e2e.a,r:p0_e2e.b")
a_only = mint("password", "--effects", "r:p0_e2e,r:p0_e2e.a")
tee.clear()
r = psql(lp, narrow, "select a /* a comment */ from P0_E2E -- and a trailing one\n order by a")
check("an allowed query returns its rows", r.returncode == 0 and r.stdout.split() == ["1", "2", "3"], r.stdout + r.stderr)
check("... and PostgreSQL was sent the RENDERING, not what the client typed (inside the transaction the proxy opens)",
      client_queries(tee) == ["BEGIN", 'select "a" from "p0_e2e" order by "a"', "COMMIT"], str(client_queries(tee)))

tee.clear()
refused = [
    ("a column the token does not allow", "select a, b, a + 1 from p0_e2e where a > (b = 'x')::int", "effect-denied"),
    ("a column read only in ORDER BY", "select a from p0_e2e order by b", "effect-denied"),
    ("a column read only in WHERE", "select a from p0_e2e where b = 'x'", "effect-denied"),
    ("a write the token does not allow", "delete from p0_e2e", "effect-denied"),
    ("a table the token does not allow", "select g from p0_big", "effect-denied"),
    ("DDL the token does not allow", "drop table p0_e2e", "effect-denied"),
    ("a second statement that is not allowed", "select a from p0_e2e; delete from p0_e2e", "effect-denied"),
    ("a column that does not exist", "select a from p0_e2e order by random_col", "unknown-column"),
    ("a table that does not exist", "select x from no_such_table", "unknown-table"),
    ("a sub-select", "select a from p0_e2e where a in (select a from p0_e2e)", "subquery"),
    ("a statement outside the subset", "set search_path = public", "unsupported-statement"),
    ("a savepoint", "savepoint a", "unsupported-statement"),
    ("a nondeterministic call", "select random() from p0_e2e", "nondeterministic"),
    ("a statement hidden after a comment", "select a from p0_e2e /* ; delete from p0_e2e */; delete from p0_e2e", "effect-denied"),
]
for name, sql, tag in refused:
    r = psql(lp, a_only, sql)
    check("refused: %s (%s)" % (name, tag), r.returncode != 0 and tag in r.stderr and r.stdout == "", r.stdout + r.stderr)
check("... and NONE of those %d refused messages (nor any part of them) reached PostgreSQL" % len(refused),
      client_queries(tee) == [], str(client_queries(tee)))
check("... the table is untouched", direct("select count(*) from p0_e2e").stdout.strip() == "3")

r = psql(lp, narrow, "select a from p0_e2e where b = 'it''s'")
check("a string with a doubled quote is lowered and sent back doubled", r.returncode == 0 and client_statements(tee)[-1] == "select \"a\" from \"p0_e2e\" where (\"b\" = 'it''s')", str(client_queries(tee)))

# the SQLSTATE of a refusal, from the wire
def simple_query(port, password, sql):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(startup_packet() + password_packet(password))
    s.settimeout(5)
    buf = b""
    while b"Z" not in buf[-6:] or len(buf) < 20:
        d = s.recv(65536)
        if not d:
            break
        buf += d
    body = sql.encode() + b"\0"
    s.sendall(b"Q" + struct.pack(">I", len(body) + 4) + body)
    out = b""
    s.settimeout(5)
    try:
        while not out.endswith(b"Z\x00\x00\x00\x05I") and len(out) < 100000:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    s.close()
    return out


out = simple_query(lp, narrow, "select b, a from p0_e2e where a = 1; select g from p0_big")
check("a refusal is an ErrorResponse (42501 for a denied effect) then ReadyForQuery, and no row of the first statement",
      error_state(out) == "42501" and out.endswith(b"Z\x00\x00\x00\x05I") and b"D\x00" not in out, str(out[:80]))
out = simple_query(lp, narrow, "select zzz from p0_e2e")
check("an unknown column is 42703, as PostgreSQL itself says it", error_state(out) == "42703", str(out[:80]))

# the extended protocol and everything else a simple client never sends
def frames(*msgs): return b"".join(t + struct.pack(">I", len(b) + 4) + b for t, b in msgs)


s = socket.create_connection(("127.0.0.1", lp), timeout=10)
s.sendall(startup_packet() + password_packet(narrow))
s.settimeout(5)
buf = b""
while not buf.endswith(b"Z\x00\x00\x00\x05I"):
    buf += s.recv(65536)
tee.clear()
s.sendall(frames((b"P", b"\0select 1\0\0\0"), (b"B", b"\0\0\0\0\0\0\0"), (b"E", b"\0\0\0\0\0"), (b"S", b"")))
got = b""
try:
    while not got.endswith(b"Z\x00\x00\x00\x05I"):
        got += s.recv(65536)
except socket.timeout:
    pass
check("the extended protocol (Parse, Bind, Execute, Sync) gets ONE error, 0A000, then ReadyForQuery, as PostgreSQL's own error handling does",
      error_state(got) == "0A000" and got.count(b"E\x00") == 1 and got.endswith(b"Z\x00\x00\x00\x05I"), str(got[:100]))
body = b"select a from p0_e2e where a = 2\0"
s.sendall(b"Q" + struct.pack(">I", len(body) + 4) + body)
got = b""
try:
    while not got.endswith(b"Z\x00\x00\x00\x05I"):
        got += s.recv(65536)
except socket.timeout:
    pass
check("... and the same connection then serves a simple query", b"D" in got and got.endswith(b"Z\x00\x00\x00\x05I"), str(got[:100]))
check("... and none of the extended messages reached PostgreSQL", all(not q.startswith("select 1") for q in client_queries(tee)), str(client_queries(tee)))
s.sendall(frames((b"?", b"")))
s.settimeout(5)
try:
    got = s.recv(1000)
except socket.timeout:
    got = b"<timeout>"
check("a message type that is not in the protocol is a FATAL 08P01 and the connection is closed", error_state(got) == "08P01", str(got[:80]))
s.close()

before = len(client_queries(tee))
r = psql(lp, narrow, "select a from p0_e2e order by a")
check("a Terminate from psql is forwarded and the server session ends cleanly",
      r.returncode == 0 and direct("select count(*) from pg_stat_activity where application_name = 'psql'").stdout.strip() in ("0", "1"))

# the schema is read fresh for each query: what changes around the proxy is seen by the next statement, with no restart
direct("drop table if exists p0_fresh")
direct("create table p0_fresh(x int primary key)")
r = psql(lp, good, "select x from p0_fresh")
check("a table created behind the proxy's back is visible to the next query", r.returncode == 0, r.stderr)
direct("alter table p0_fresh add column y int")
r = psql(lp, good, "select y from p0_fresh")
check("... a column added behind its back too", r.returncode == 0, r.stderr)
direct("drop table p0_fresh")
r = psql(lp, good, "select x from p0_fresh")
check("... and a table dropped behind its back is unknown-table (42P01), not a stale accept", "unknown-table" in r.stderr, r.stderr)

# ---------------------------------------------------------------- P2a: transactions, tracked by the proxy
class Wire:
    """A raw client of the proxy: sends simple queries and returns every message up to ReadyForQuery."""

    def __init__(self, port, password, db=b"main"):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=15)
        self.s.sendall(startup_packet(db) + password_packet(password))
        self.buf = b""
        self.read_until_ready()

    def messages(self):
        out = []
        while len(self.buf) >= 5:
            ln = struct.unpack(">I", self.buf[1:5])[0]
            if len(self.buf) < 1 + ln:
                break
            out.append((chr(self.buf[0]), self.buf[5:1 + ln]))
            self.buf = self.buf[1 + ln:]
        return out

    def read_until_ready(self):
        got = []
        while not got or got[-1][0] != "Z":
            got += self.messages()
            if got and got[-1][0] == "Z":
                break
            d = self.s.recv(65536)
            if not d:
                raise EOFError("closed")
            self.buf += d
        return got

    def send(self, sql):
        body = sql.encode() + b"\0"
        self.s.sendall(b"Q" + struct.pack(">I", len(body) + 4) + body)

    def query(self, sql):
        self.send(sql)
        return self.read_until_ready()

    def close(self):
        self.s.close()


def status_of(msgs): return msgs[-1][1].decode()
def tags_of(msgs): return [m[1].rstrip(b"\0").decode() for m in msgs if m[0] == "C"]
def codes_of(msgs):
    out = []
    for t, body in msgs:
        if t == "E":
            for f in body.split(b"\0"):
                if f[:1] == b"C":
                    out.append(f[1:].decode())
    return out


direct("drop table if exists p2a; create table p2a(a int primary key, b text)")
w = Wire(lp, good)
tee.clear()
m = w.query("begin")
check("BEGIN is answered by the proxy: CommandComplete BEGIN, then ReadyForQuery T", tags_of(m) == ["BEGIN"] and status_of(m) == "T", str(m))
m = w.query("insert into p2a values (1, 'x')")
check("a statement in the transaction: its CommandComplete comes at once, status stays T", tags_of(m) == ["INSERT 0 1"] and status_of(m) == "T", str(m))
check("... and PostgreSQL has not got the row yet (another session sees nothing)", direct("select count(*) from p2a").stdout.strip() == "0")
m = w.query("commit")
check("COMMIT: CommandComplete COMMIT, ReadyForQuery I", tags_of(m) == ["COMMIT"] and status_of(m) == "I", str(m))
check("... and the row is there for everyone", direct("select count(*) from p2a").stdout.strip() == "1")
check("the server was sent BEGIN, the rendering, the facts question, the commit id for the delta rows, PREPARE, COMMIT PREPARED: exactly the proxy's own commands and the statement",
      client_queries(tee) == ["BEGIN", 'insert into "p2a" values (1, \'x\')', "FACTS", "DELTA ID", "PREPARE TRANSACTION 'cdb:ID'", "COMMIT PREPARED 'cdb:ID'"], str(client_queries(tee)))

m = w.query("begin")
w.query("insert into p2a values (2, 'y')")
m = w.query("rollback")
check("ROLLBACK: CommandComplete ROLLBACK, status I, and the row is gone", tags_of(m) == ["ROLLBACK"] and status_of(m) == "I" and
      direct("select count(*) from p2a").stdout.strip() == "1", str(m))

w.query("begin")
m = w.query("insert into p2a values (1, 'dup')")
check("an error from PostgreSQL inside a transaction: relayed (23505), status E", codes_of(m) == ["23505"] and status_of(m) == "E", str(m))
m = w.query("select a from p2a")
check("... and the next statement is refused by the proxy with 25P02 and nothing is sent upstream",
      codes_of(m) == ["25P02"] and status_of(m) == "E" and client_queries(tee)[-1] != 'select "a" from "p2a"', str(m))
m = w.query("commit")
check("COMMIT of a failed transaction is a ROLLBACK, as in PostgreSQL", tags_of(m) == ["ROLLBACK"] and status_of(m) == "I", str(m))

w.query("begin")
w.query("insert into p2a values (3, 'z')")
tee.clear()
m = w.query("select nope from p2a")
check("a statement the guard refuses inside a transaction: the error, status E", codes_of(m) == ["42703"] and status_of(m) == "E", str(m))
check("... the proxy rolled the upstream transaction back at once (the server was sent ROLLBACK, and nothing else)",
      client_queries(tee) == ["ROLLBACK"], str(client_queries(tee)))
m = w.query("select a from p2a")
check("... and the next statement is 25P02: the upstream transaction is gone, so running it would not be inside one",
      codes_of(m) == ["25P02"] and status_of(m) == "E", str(m))
m = w.query("rollback")
check("... the client's ROLLBACK is answered, and the insert never happened", tags_of(m) == ["ROLLBACK"] and status_of(m) == "I" and
      direct("select count(*) from p2a").stdout.strip() == "1", str(m))

m = w.query("begin; select a from p2a")
check("transaction control mixed with a statement is refused (0A000) and nothing is sent upstream",
      codes_of(m) == ["0A000"] and status_of(m) == "I", str(m))
m = w.query("begin isolation level serializable")
check("an option on BEGIN is refused (0A000)", codes_of(m) == ["0A000"] and status_of(m) == "I", str(m))
m = w.query("begin")
m = w.query("begin")
check("BEGIN inside a transaction is an error here (25001), the transaction stays open", codes_of(m) == ["25001"] and status_of(m) == "T", str(m))
w.query("rollback")
check("COMMIT and ROLLBACK with no transaction are answered, status I",
      tags_of(w.query("commit")) == ["COMMIT"] and tags_of(w.query("rollback")) == ["ROLLBACK"])

# autocommit: the proxy wraps a statement in a transaction of its own, and the client sees only what it would have seen
tee.clear()
m = w.query("insert into p2a values (10, 'a'); insert into p2a values (11, 'b')")
check("an autocommit message of two statements: both CommandCompletes, then ReadyForQuery I",
      tags_of(m) == ["INSERT 0 1", "INSERT 0 1"] and status_of(m) == "I", str(m))
check("... and the server was sent BEGIN, both statements as ONE message, COMMIT",
      client_queries(tee) == ["BEGIN", 'insert into "p2a" values (10, \'a\'); insert into "p2a" values (11, \'b\')', "FACTS", "DELTA ID", "PREPARE TRANSACTION 'cdb:ID'", "COMMIT PREPARED 'cdb:ID'"],
      str(client_queries(tee)))

# the order of a message of several statements: every statement's messages in the server's order, the last tag held for the commit (found in P3: the
# proxy held ALL the tags and streamed the rows after them, so `T D C T D C Z` reached the client as `T D T D C C Z`)
m = w.query("select a from p2a where a = 10; select b from p2a where a = 11")
check("a message of two selects: T D C T D C Z, in the server's order", "".join(k for k, _ in m) == "TDCTDCZ", "".join(k for k, _ in m))
m = w.query("insert into p2a values (40, 'k'); select a from p2a where a = 40; select b from p2a where a = 40")
check("an insert and two selects: C T D C T D C Z", "".join(k for k, _ in m) == "CTDCTDCZ", "".join(k for k, _ in m))
m = w.query("select a from p2a where a = 40")
check("one statement is as before: T D C Z", "".join(k for k, _ in m) == "TDCZ", "".join(k for k, _ in m))
tee.clear()
m = w.query("insert into p2a values (12, 'c'); insert into p2a values (10, 'dup')")
check("an autocommit message whose second statement fails: the first statement's tag, then the error (23505), status I: the stream PostgreSQL sends",
      codes_of(m) == ["23505"] and tags_of(m) == ["INSERT 0 1"] and [k for k, _ in m] == ["C", "E", "Z"] and status_of(m) == "I", str(m))
check("... the server was sent BEGIN, the two statements and ROLLBACK, and nothing else (no facts question, no PREPARE: a failed statement is not a commit), and the first statement's row is not there",
      client_queries(tee) == ["BEGIN", 'insert into "p2a" values (12, \'c\'); insert into "p2a" values (10, \'dup\')', "ROLLBACK"] and
      direct("select count(*) from p2a where a = 12").stdout.strip() == "0", str(client_queries(tee)))
m = w.query("select a from p2a order by a")
check("a select in autocommit streams its rows: DataRow messages, SELECT n, I", [x for x in m if x[0] == "D"] and tags_of(m)[0].startswith("SELECT") and status_of(m) == "I", str(m[:3]))

# two queries sent at once are answered in order, one after the other
tee.clear()
w.send("select pg_sleep(0.3) from p2a limit 1")
w.send("select a from p2a where a = 10")
a1 = w.read_until_ready()
a2 = w.read_until_ready()
check("two queries pipelined are each answered, in order", tags_of(a1) == ["SELECT 1"] and tags_of(a2) == ["SELECT 1"], str((a1, a2)))
check("... and the second is not served while the first is in flight: the server sees one transaction after the other",
      client_queries(tee) == ["BEGIN", 'select pg_sleep(0.3) from "p2a" limit 1', "FACTS", "DELTA ID", "PREPARE TRANSACTION 'cdb:ID'", "COMMIT PREPARED 'cdb:ID'", "BEGIN", 'select "a" from "p2a" where ("a" = 10)', "COMMIT"],
      str(client_queries(tee)))
w.close()

# a client that goes away inside a transaction takes its work with it
w2 = Wire(lp, good)
w2.query("begin")
w2.query("insert into p2a values (20, 'gone')")
w2.close()
time.sleep(0.5)
check("a client that disconnects inside a transaction: the transaction is rolled back", direct("select count(*) from p2a where a = 20").stdout.strip() == "0")

# the same through psql: a script with a transaction, an error, and a rollback
r = psql(lp, good, "", input="begin;\ninsert into p2a values (30, 'p');\nselect a from p2a where a = 30;\ncommit;\nselect count(*) from p2a where a = 30;\n")
check("psql runs a transaction through the proxy", r.returncode == 0 and "COMMIT" in r.stdout and r.stdout.strip().endswith("1"), r.stdout + r.stderr)
direct("drop table if exists p2a")


# ---- P2c: the log directory at startup (docs/m1-commit-path.md section 5.4)
import hashlib
import random
import shutil
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_rng = random.Random(5)
_seed = bytes(_rng.randrange(256) for _ in range(32))
_sk = Ed25519PrivateKey.from_private_bytes(_seed)
_pk = _sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _log_with(n, branch=b"main"):
    out, parent = b"CHODBLG1" + _pk, None
    for seq in range(n):
        l32 = lambda items: struct.pack(">I", len(items)) + b"".join(items)
        enc = b"".join([struct.pack(">H", 1), l32([parent] if parent else []), struct.pack(">H", len(branch)) + branch, struct.pack(">Q", seq),
                        bytes(32), l32([bytes(32)]), l32([]), bytes(32), bytes(32), l32([]), l32([]), bytes(32), bytes(32), l32([]), struct.pack(">Q", seq)])
        cid = hashlib.sha256(b"cancho-db/commit/v1\x00" + enc).digest()
        out += struct.pack(">I", len(enc)) + enc + _sk.sign(cid)
        parent = cid
    return out


def start_logged(ldir, keyfile, branch="main", wait=True, upstream=None, preexec=None):
    port = free_port()
    p = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(upstream or PG_PORT), branch, ROOT, "postgres", DB, str(ldir), str(keyfile)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, preexec_fn=preexec)
    if not wait:
        return p, port
    for _ in range(100):
        if p.poll() is not None:
            return p, port
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p, port
        except OSError:
            time.sleep(0.05)
    return p, port


_work = Path(tempfile.mkdtemp())
(_work / "key").write_bytes(_seed)
_dir = _work / "logs"
_dir.mkdir()
lp1, lport1 = start_logged(_dir, _work / "key")
check("P2c: a proxy with a fresh log directory listens", lp1.poll() is None and (_dir / "log").read_bytes() == b"CHODBLG1" + _pk)
lp2, _ = start_logged(_dir, _work / "key")
try:
    err2 = lp2.communicate(timeout=10)[1]
except subprocess.TimeoutExpired:
    lp2.kill()
    err2 = "timed out"
check("P2c: a second proxy on the same directory is refused", lp2.returncode == 3 and "locked" in err2, "%s %s" % (lp2.returncode, err2))
lp1.kill()
lp1.wait()
(_dir / "log").write_bytes(_log_with(3) + _log_with(4)[len(_log_with(3)):][:6])  # the first 6 bytes of a fourth record
lp3, lport3 = start_logged(_dir, _work / "key")
check("P2c: a restart reads the log back and cuts the torn tail", lp3.poll() is None and (_dir / "log").read_bytes() == _log_with(3))
lp3.terminate()
err3 = lp3.communicate(timeout=10)[1]
check("P2c: and says so", "log has 3 commits, next seq 3, cut 6 bytes of torn tail" in err3, err3)
bad = bytearray(_log_with(3))
bad[60] ^= 1
(_dir / "log").write_bytes(bytes(bad))
lp4, lport4 = start_logged(_dir, _work / "key")
try:
    err4 = lp4.communicate(timeout=10)[1]
except subprocess.TimeoutExpired:
    lp4.kill()
    err4 = "timed out"
refused = False
try:
    socket.create_connection(("127.0.0.1", lport4), timeout=0.3).close()
except OSError:
    refused = True
check("P2c: a log that does not verify is refused at startup, and the listener never opens", lp4.returncode == 3 and "log-corrupt" in err4 and refused and (_dir / "log").read_bytes() == bytes(bad), "%s %s" % (lp4.returncode, err4))
(_dir / "log").write_bytes(b"CHODBLG1" + bytes(32) + _log_with(2)[40:])
lp5, _ = start_logged(_dir, _work / "key")
try:
    err5 = lp5.communicate(timeout=10)[1]
except subprocess.TimeoutExpired:
    lp5.kill()
    err5 = "timed out"
check("P2c: a log of another key is refused", lp5.returncode == 3 and "foreign-key" in err5, err5)
lp6, _ = start_logged(_work / "nothere", _work / "key")
err6 = lp6.communicate(timeout=10)[1]
check("P2c: a missing log directory is refused", lp6.returncode == 3, err6)
(_work / "fresh").mkdir()
lp7, _ = start_logged(_work / "fresh", _work / "nokey")
try:
    err7 = lp7.communicate(timeout=10)[1]
except subprocess.TimeoutExpired:
    lp7.kill()
    err7 = "it kept running"
check("P2c: a missing key file is refused, and nothing is created for it", lp7.returncode == 3 and "key file" in err7 and not (_work / "fresh" / "log").exists(), "%s %s" % (lp7.returncode, err7))
shutil.rmtree(_work, ignore_errors=True)

# ---- P2d-3: what the proxy writes in the log (docs/m1-commit-path.md section 5.6)
import verify as pyverify

VERIFIERS = os.environ.get("E2E_VERIFIERS", "").split()      # extra verifier binaries (the gate passes the cancho one and the Go one)


def read_log(path):
    data = Path(path).read_bytes()
    at, out = 40, []
    while at < len(data):
        n = struct.unpack(">I", data[at:at + 4])[0]
        out.append(pyverify.decode(data[at + 4:at + 4 + n]) + (data[at + 4:at + 4 + n],))
        at += 4 + n + 64
    return out


direct("drop table if exists p2d; create table p2d(a int primary key, b text)")
_d = Path(_scratch, "p2d")
_d.mkdir()
cp, cport = start_logged(_d, Path(_scratch, "key"))
t_before = int(time.time() * 1000)
cw = Wire(cport, good)
cw.query("insert into p2d values (1, 'a')")
cw.query("begin")
cw.query("insert into p2d values (2, 'b')")
cw.query("insert into p2d values (3, 'c')")
cw.query("select a from p2d where a = 2")
r_commit = cw.query("commit")
cw.query("begin")
cw.query("insert into p2d values (4, 'd')")
cw.query("rollback")
r_read = cw.query("select a from p2d where a = 1")
r_dup = cw.query("insert into p2d values (1, 'dup')")
r_post = cw.query("insert into p2d values (5, 'e')")
check("P2d: the commits answered", tags_of(r_commit) == ["COMMIT"] and tags_of(r_read) == ["SELECT 1"] and tags_of(r_post) == ["INSERT 0 1"], str((r_commit, r_read, r_post)))
check("P2d: a failing statement is an error, and commits nothing", any(m[0] == "E" for m in r_dup), str(r_dup))
cw.close()
time.sleep(0.3)
rows = direct("select string_agg(a::text, ',' order by a) from p2d").stdout.strip()
check("P2d: PostgreSQL has exactly the rows of the commits (1, 2, 3 and 5; 4 was rolled back, the duplicate failed)", rows == "1,2,3,5", rows)
cp.terminate()
cp.communicate(timeout=10)
commits = read_log(_d / "log")
check("P2d: the log has one commit per transaction: 4 (two autocommit writes, one transaction, one read)", len(commits) == 4, len(commits))
if len(commits) == 4:
    check("P2d: in the order they ran, on the branch served, chained by seq", [c[1] for c in commits] == [0, 1, 2, 3] and all(c[0] == b"main" for c in commits), [(c[0], c[1]) for c in commits])
    check("P2d: with their statements counted (1, 3, 1, 1)", [len(c[3][5]) for c in commits] == [1, 3, 1, 1], [len(c[3][5]) for c in commits])
    check("P2d: the third is a read: its effects are reads only; the others write", all(k == 0 for k, _ in commits[2][3][3]) and all(any(k == 1 for k, _ in c[3][3]) for c in (commits[0], commits[1], commits[3])),
          [c[3][3] for c in commits])
    # the schema the transaction began with: SHA-256 of the snapshot text, rebuilt here from the catalog by queries of this file's own
    def schema_of(enc):
        at = 2
        at += 4 + 32 * struct.unpack(">I", enc[at:at + 4])[0]
        at += 2 + struct.unpack(">H", enc[at:at + 2])[0] + 8
        return enc[at:at + 32]

    cols = direct("select c.relname || ' ' || a.attname from pg_class c join pg_namespace n on n.oid = c.relnamespace join pg_attribute a on a.attrelid = c.oid "
                  "where n.nspname = 'public' and c.relkind in ('r', 'p') and a.attnum > 0 and not a.attisdropped order by c.relname, a.attnum").stdout.split("\n")
    idxs = direct("select indexname || ' ' || tablename from pg_indexes where schemaname = 'public' order by indexname").stdout.split("\n")
    text, last = "", None
    for line in [l for l in cols if l]:
        table, col = line.split(" ")
        if table != last:
            text += ("\n" if last is not None else "") + table + ":"
            last = table
        text += " " + col
    text += "\n" if last is not None else ""
    text += "".join("index %s on %s\n" % tuple(l.split(" ")) for l in idxs if l)
    check("P2d: every commit records the SHA-256 of the schema snapshot the transaction began with", all(schema_of(c[4]) == hashlib.sha256(text.encode()).digest() for c in commits),
          str((text[:80], [schema_of(c[4]).hex()[:8] for c in commits], hashlib.sha256(text.encode()).hexdigest()[:8])))
    check("P2d: times are the clock's at the commit", all(t_before - 1000 <= c[3][4] <= int(time.time() * 1000) + 1000 for c in commits), [c[3][4] for c in commits])
    # the whole directory, as an auditor would take it: L2 and IR, with every verifier there is
    root_hex = ROOT
    argv = ["--root", root_hex, "--tokens", str(_d / "tokens"), "--stmts", str(_d / "stmts")]
    for name, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
        out = subprocess.run(cmd + [str(_d / "log")] + argv, capture_output=True, text=True).stdout.strip()
        check("P2d: %s accepts the log, the tokens and the statements at L2 and IR" % name, out.startswith("ok commits=4 branches=1"), out)
    # restart: the chain goes on from the tip
    cp2, cport2 = start_logged(_d, Path(_scratch, "key"))
    cw2 = Wire(cport2, good)
    cw2.query("insert into p2d values (6, 'f')")
    cw2.close()
    time.sleep(0.3)
    cp2.terminate()
    err2 = cp2.communicate(timeout=10)[1]
    commits2 = read_log(_d / "log")
    check("P2d: a restart reads the tip back and the chain goes on (next seq 4, parent the old tip)", "next seq 4" in err2 and len(commits2) == 5 and commits2[4][1] == 4 and commits2[4][2] == [pyverify.hashlib.sha256(b"cancho-db/commit/v1\x00" + commits2[3][4]).digest()], err2)
    out = subprocess.run(["python3", str(ROOT_DIR / "tools" / "verify.py"), str(_d / "log")] + argv, capture_output=True, text=True).stdout.strip()
    check("P2d: and the longer log verifies", out.startswith("ok commits=5 branches=1"), out)
    # M2c-1 (docs/m2-branches.md D20, D21): a log can hold several branches, each with its own chain, and the proxy serves every branch of its log
    cid_of = lambda c: pyverify.hashlib.sha256(b"cancho-db/commit/v1\x00" + c[4]).digest()
    cp3, cport3 = start_logged(_d, Path(_scratch, "key"), "dev")
    cw3 = Wire(cport3, good, b"dev")
    cw3.query("insert into p2d values (7, 'g')")
    cw3.close()
    time.sleep(0.3)
    cp3.terminate()
    cp3.communicate(timeout=10)
    commits3 = read_log(_d / "log")
    check("M2c-1: a server configured with a new branch starts it: first commit, seq 0, no parent", len(commits3) == 6 and commits3[5][0] == b"dev" and commits3[5][1] == 0 and commits3[5][2] == [], str([(c[0], c[1]) for c in commits3]))
    # a branch other than the first has a schema of its own, `cdb_b_<name>` (M2c-2, D22): this one is made by hand, there being no fork in this part of the test
    direct("drop schema if exists cdb_b_dev cascade; create schema cdb_b_dev; create table cdb_b_dev.p2d(a int primary key, b text)")
    cp4, cport4 = start_logged(_d, Path(_scratch, "key"), "main")
    cw4 = Wire(cport4, good, b"dev")
    cw4.query("insert into p2d values (8, 'h')")
    cw4.close()
    cw5 = Wire(cport4, good, b"main")
    cw5.query("insert into p2d values (9, 'i')")
    cw5.close()
    refused = raw(cport4, startup_packet(b"nosuch") + password_packet(good))
    time.sleep(0.3)
    cp4.terminate()
    err4 = cp4.communicate(timeout=10)[1]
    commits4 = read_log(_d / "log")
    check("M2c-1: a server configured with main serves dev too, since its log has it: dev goes on from its own tip", len(commits4) == 8 and commits4[6][0] == b"dev" and commits4[6][1] == 1 and commits4[6][2] == [cid_of(commits3[5])], str([(c[0], c[1]) for c in commits4]))
    check("M2c-1: and main goes on from main's tip, not from dev's", commits4[7][0] == b"main" and commits4[7][1] == 5 and commits4[7][2] == [cid_of(commits3[4])], str([(c[0], c[1], len(c[2])) for c in commits4[6:]]))
    check("M2c-1: a database that is not a branch of the log is refused as a branch the token does not allow", error_state(refused) == "3D000", str(refused[:60]))
    out = subprocess.run(["python3", str(ROOT_DIR / "tools" / "verify.py"), str(_d / "log")] + argv, capture_output=True, text=True).stdout.strip()
    direct("drop schema if exists cdb_b_dev cascade")
    check("M2c-1: the log of two branches verifies", out.startswith("ok commits=8 branches=2"), out)
direct("drop table if exists p2d")

# ---- P2d-4: the failure windows of docs/m1-commit-path.md section 4, reached from outside (a tee kills the proxy at a chosen message)
import resource
import signal

direct("drop table if exists p2f; create table p2f(a int primary key, b text)")


def prepared_xacts():
    return int(direct("select count(*) from pg_prepared_xacts where gid like 'cdb:%' and database = current_database()").stdout.strip() or -1)


def rows_of():
    return direct("select coalesce(string_agg(a::text, ',' order by a), '') from p2f").stdout.strip()


def commits_in(ldir):
    return len(read_log(Path(ldir, "log")))


def run_window(name, prefix, when, key, expect):
    """Kill the proxy at one window, look at what PostgreSQL and the log hold, restart it (which recovers) and look again. `expect` is
    (prepared before, rows before, commits before, summary on restart, rows after, commits after)."""
    direct("delete from p2f")
    direct("delete from cdb.delta where tbl = 'p2f'")       # (the cleanup above was a direct write: its facts have no commit)
    ldir = Path(_scratch, "w_" + name)
    ldir.mkdir()
    ft = Tee(PG_PORT)
    fp, fport = start_logged(ldir, Path(_scratch, "key"), upstream=ft.port)
    ft.fault(prefix, when, fp.kill)
    died = None
    try:
        fw = Wire(fport, good)
        died = fw.query("insert into p2f values (%d, 'v')" % key)
    except (EOFError, ConnectionError, OSError):
        died = "closed"
    fp.wait(timeout=10)
    ft.stop()
    before = (prepared_xacts(), rows_of(), commits_in(ldir))
    rp, rport = start_logged(ldir, Path(_scratch, "key"))
    time.sleep(0.5)
    ok_started = rp.poll() is None
    rp.terminate()
    err = rp.communicate(timeout=10)[1]
    after = (prepared_xacts(), rows_of(), commits_in(ldir))
    want_before, want_after, summary = expect
    check("P2d-4 %s: the proxy was killed, and PostgreSQL, the log hold what the window says (prepared, rows, commits) %s" % (name, want_before),
          fp.returncode is not None and before == want_before, "%s %s" % (before, died))
    check("P2d-4 %s: the restart settles it: %s" % (name, want_after), ok_started and after == want_after and summary in err, "%s %s" % (after, err))
    # equality: the rows PostgreSQL holds are the rows the commits in the log name, one for one
    check("P2d-4 %s: and the rows are exactly the commits (count and identity)" % name,
          len([r for r in after[1].split(",") if r]) == after[2] and (after[2] == 0 or after[1] == str(key)), after)
    # M2b-2b: the row's delta rows are in the prepared transaction, so after recovery they exist exactly when the row does, each with the commit's id
    stamped = direct("select count(*) filter (where commit_id is not null) || '|' || count(*) from cdb.delta where tbl = 'p2f'").stdout.strip()
    check("P2d-4 %s: and the delta rows live or die with the data: %d commit(s), %d stamped delta row(s) of %d" % (name, after[2], after[2], after[2]), stamped == "%d|%d" % (after[2], after[2]), stamped)
    if after[2]:
        argv = ["--root", ROOT, "--tokens", str(ldir / "tokens"), "--stmts", str(ldir / "stmts")]
        for vname, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
            out = subprocess.run(cmd + [str(ldir / "log")] + argv, capture_output=True, text=True).stdout.strip()
            check("P2d-4 %s: %s accepts the files after recovery" % (name, vname), out.startswith("ok commits=%d" % after[2]), out)


# a prepared transaction of another database (the view is cluster-wide) is not this proxy's to settle and must not stop it starting
direct("drop database if exists p2d_other")
direct("create database p2d_other")
subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", "p2d_other", "-c", "begin; create table t(a int); prepare transaction 'cdb:%s'" % ("0" * 64)], capture_output=True, text=True)
sd = Path(_scratch, "w_other")
sd.mkdir()
so, _ = start_logged(sd, Path(_scratch, "key"))
time.sleep(0.5)
check("P2d-4: a prepared transaction of another database does not stop the proxy from starting", so.poll() is None)
so.terminate()
so.communicate(timeout=10)
subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", "p2d_other", "-c", "rollback prepared 'cdb:%s'" % ("0" * 64)], capture_output=True, text=True)
direct("drop database if exists p2d_other")

run_window("before_prepare", "PREPARE TRANSACTION", "before", 1, ((0, "", 0), (0, "", 0), "log has 0 commits"))
run_window("prepared_no_log", "PREPARE TRANSACTION", "reply", 2, ((1, "", 0), (0, "", 0), "recovery: committed 0, rolled back 1"))
run_window("logged_not_committed", "COMMIT PREPARED", "before", 3, ((1, "", 1), (0, "3", 1), "recovery: committed 1, rolled back 0"))
run_window("committed_not_acked", "COMMIT PREPARED", "reply", 4, ((0, "4", 1), (0, "4", 1), "log has 1 commits"))

# the log cannot be written: the file-size limit is set just under the size of one commit's log, so the append fails part-way (a torn record)
direct("delete from p2f")
size_dir = Path(_scratch, "w_size")
size_dir.mkdir()
sp_, sport = start_logged(size_dir, Path(_scratch, "key"))
sw = Wire(sport, good)
sw.query("insert into p2f values (91, 'v')")
sw.close()
time.sleep(0.3)
sp_.terminate()
sp_.communicate(timeout=10)
log_size, tok_size, stmt_size = (Path(size_dir, n).stat().st_size for n in ("log", "tokens", "stmts"))
limit = log_size - 1
direct("delete from p2f")
fdir = Path(_scratch, "w_full")
fdir.mkdir()


def limited():
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)


fp2, fport2 = start_logged(fdir, Path(_scratch, "key"), preexec=limited)
fw2 = Wire(fport2, good)
r_full = fw2.query("insert into p2f values (92, 'v')")
check("P2d-4: when the log cannot be written the client gets 58000 and PostgreSQL has nothing (limit %d, one commit needs %d, tokens %d, stmts %d)" % (limit, log_size, tok_size, stmt_size),
      tok_size < log_size and stmt_size < log_size and any(m[0] == "E" and b"58000" in m[1] for m in r_full) and rows_of() == "" and prepared_xacts() == 0, str(r_full))
r_two = fw2.query("insert into p2f values (93, 'a'); insert into p2f values (94, 'b')")
check("... in a message of two statements the first statement's tag is released in its place and only the last is held, so a failed commit gives C then E (as PostgreSQL's own stream would)",
      [k for k, _ in r_two] == ["C", "E", "Z"] and b"58000" in r_two[1][1] and tags_of(r_two) == ["INSERT 0 1"], str(r_two))
r_next = fw2.query("select a from p2f where a = 92")
check("... and the proxy goes on answering (a read is a commit too, so it is refused the same way while the log cannot be written)",
      fp2.poll() is None and any(m[0] == "E" and b"58000" in m[1] for m in r_next) and r_next[-1][0] == "Z", str(r_next))
fw2.close()
fp2.terminate()
fp2.communicate(timeout=10)
torn = Path(fdir, "log").stat().st_size
fp3, _ = start_logged(fdir, Path(_scratch, "key"))
time.sleep(0.5)
fp3.terminate()
err_full = fp3.communicate(timeout=10)[1]
check("... its torn record (%d bytes past the header) is cut at the next start" % (torn - 40), (torn == 40 or "torn tail" in err_full) and Path(fdir, "log").stat().st_size == 40, err_full)

# the upstream connection is lost after the log has the commit and before PostgreSQL does: the RUNNING proxy settles it, without a restart
direct("delete from p2f")
ldir = Path(_scratch, "w_live")
ldir.mkdir()
lt = Tee(PG_PORT)
lp_, lport_ = start_logged(ldir, Path(_scratch, "key"), upstream=lt.port)
lt.fault("COMMIT PREPARED", "drop", None)
try:
    lw = Wire(lport_, good)
    lw.query("insert into p2f values (77, 'v')")
    live_closed = False
except (EOFError, ConnectionError, OSError):
    live_closed = True
settled = False
for _ in range(60):
    if prepared_xacts() == 0:
        settled = True
        break
    time.sleep(0.25)
check("P2d-4 live: the client's connection was closed, and the running proxy settled the prepared transaction itself by committing it (the log has it)",
      live_closed and settled and rows_of() == "77" and commits_in(ldir) == 1 and lp_.poll() is None, "%s %s %s %s" % (live_closed, settled, rows_of(), commits_in(ldir)))
lw2 = Wire(lport_, good)
lw2.query("insert into p2f values (78, 'w')")
lw2.close()
time.sleep(0.3)
lp_.terminate()
lp_.communicate(timeout=10)
check("P2d-4 live: and it goes on, the chain unbroken (two commits, the second after the first)", commits_in(ldir) == 2 and rows_of() == "77,78", "%s %s" % (commits_in(ldir), rows_of()))
lt.stop()
argv = ["--root", ROOT, "--tokens", str(ldir / "tokens"), "--stmts", str(ldir / "stmts")]
out = subprocess.run(["python3", str(ROOT_DIR / "tools" / "verify.py"), str(ldir / "log")] + argv, capture_output=True, text=True).stdout.strip()
check("P2d-4 live: and the files verify at L2 and IR", out.startswith("ok commits=2"), out)

# a transaction larger than a commit can name is refused (54000) and aborts the transaction, as any refused statement does
direct("drop table if exists p2l; create table p2l(a int primary key)")
ld = Path(_scratch, "p2l")
ld.mkdir()
lgp, lgport = start_logged(ld, Path(_scratch, "key"))
lgw = Wire(lgport, good)
lgw.query("begin")
answers = [lgw.query("select a from p2l where a = 1") for _ in range(65)]
refused_at = [i for i, m in enumerate(answers) if any(x[0] == "E" and b"54000" in x[1] for x in m)]
r_after = lgw.query("select a from p2l where a = 1")
r_end = lgw.query("rollback")
check("P2d: the 65th statement of a transaction is refused 54000 (the 64 before it ran), the transaction is then failed (25P02) until ROLLBACK",
      refused_at == [64] and any(x[0] == "E" and b"25P02" in x[1] for x in r_after) and tags_of(r_end) == ["ROLLBACK"], str((refused_at, r_after, r_end)))
lgw.close()
lgp.terminate()
lgp.communicate(timeout=10)
check("P2d: ... and nothing of it is in the log", commits_in(ld) == 0, commits_in(ld))
direct("drop table if exists p2l")
direct("drop table if exists p2f")

# ---- P2d-5: now() is read inside the transaction and recorded in the commit (P2-D9)
import datetime

direct("drop table if exists p2n; create table p2n(a int primary key)")
direct("insert into p2n values (1)")
nd_dir = Path(_scratch, "p2n")
nd_dir.mkdir()
np_, nport = start_logged(nd_dir, Path(_scratch, "key"))
nw = Wire(nport, good)


def effects_start(enc):
    """Where a commit's effects begin: after the version, parents, branch, seq, schema and statements."""
    at = 2
    at += 4 + 32 * struct.unpack(">I", enc[at:at + 4])[0]
    at += 2 + struct.unpack(">H", enc[at:at + 2])[0] + 8 + 32
    at += 4 + 32 * struct.unpack(">I", enc[at:at + 4])[0]
    return at


def nondet_start(enc):
    """Where a commit's nondet list begins: after the effects, the token and principal, and the code hashes."""
    at = effects_start(enc)
    n = struct.unpack(">I", enc[at:at + 4])[0]
    at += 4
    for _ in range(n):
        at += 1 + 2 + struct.unpack(">H", enc[at + 1:at + 3])[0]
    at += 32 + 32
    at += 4 + 32 * struct.unpack(">I", enc[at:at + 4])[0]
    return at


def values_of(enc):
    pos = nondet_start(enc)
    n = struct.unpack(">I", enc[pos:pos + 4])[0]
    pos += 4
    vals = []
    for _ in range(n):
        tag = enc[pos]
        if tag == 1:
            vals.append(struct.unpack(">q", enc[pos + 1:pos + 9])[0])
            pos += 9
        elif tag == 0:
            vals.append(None)
            pos += 1
        else:
            ln = struct.unpack(">I", enc[pos + 1:pos + 5])[0]
            vals.append(enc[pos + 5:pos + 5 + ln])
            pos += 5 + ln
    return vals


def micros(text):
    """A timestamptz as PostgreSQL prints it (`2026-11-17 19:52:01.123456+00`) in microseconds since the epoch."""
    if len(text) > 3 and text[-3] in "+-" and ":" not in text[-3:]:
        text += ":00"
    dt = datetime.datetime.fromisoformat(text)
    return (dt - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(microseconds=1)


def first_column(msgs):
    for k, body in msgs:
        if k == "D":
            ln = struct.unpack(">I", body[2:6])[0]
            return body[6:6 + ln].decode()
    return None


nw.query("begin")
t1 = first_column(nw.query("select now() from p2n where a = 1"))
time.sleep(0.05)
t2 = first_column(nw.query("select now() from p2n where a = 1"))
nw.query("commit")
t3 = first_column(nw.query("select now() from p2n where a = 1"))
nw.query("insert into p2n values (2)")
nw.close()
time.sleep(0.3)
np_.terminate()
np_.communicate(timeout=10)
ncommits = read_log(nd_dir / "log")
check("P2d-5: a statement with now() runs (it was refused before), and in a transaction now() is one value", t1 is not None and t1 == t2 and t3 is not None and t3 != t1, str((t1, t2, t3)))
check("P2d-5: three commits (the transaction, the autocommit select, the insert)", len(ncommits) == 3, len(ncommits))
if len(ncommits) == 3:
    v0, v1, v2 = (values_of(c[4]) for c in ncommits)
    check("P2d-5: the transaction's commit records now() as ONE int value: exactly the one the client was shown, in microseconds", v0 == [micros(t1)], str((v0, t1, micros(t1))))
    check("P2d-5: the autocommit select records its own now()", v1 == [micros(t3)] and v1 != v0, str((v1, t3)))
    check("P2d-5: a commit that read no clock records no nondet value", v2 == [], str(v2))
    check("P2d-5: the effects of the first two name the nondeterminism (kind 4, `now`)", all((4, b"now") in c[3][3] for c in ncommits[:2]) and (4, b"now") not in ncommits[2][3][3], [c[3][3] for c in ncommits])
    argv = ["--root", ROOT, "--tokens", str(nd_dir / "tokens"), "--stmts", str(nd_dir / "stmts")]
    for vname, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
        out = subprocess.run(cmd + [str(nd_dir / "log")] + argv, capture_output=True, text=True).stdout.strip()
        check("P2d-5: %s accepts the log with its nondet values at L2 and IR" % vname, out.startswith("ok commits=3"), out)
direct("drop table if exists p2n")

# ---------------------------------------------------------------- M2b-2a: the row-delta capture, installed by the proxy (docs/m2-branches.md D14, D15)
import hashlib
check("M2b-2a: the proxy installed the capture: the delta table is there and the table made after the proxy started is tracked (three triggers)",
      direct("select count(*) from pg_trigger where tgrelid = 'p0_e2e'::regclass and tgname like 'cdb_%'").stdout.strip() == "3" and direct("select count(*) from pg_class where oid = 'cdb.delta'::regclass").stdout.strip() == "1",
      direct("select count(*) from pg_trigger where tgrelid = 'p0_e2e'::regclass and tgname like 'cdb_%'").stderr)
direct("delete from cdb.delta where tbl = 'p0_e2e'")
for sql in ("insert into p0_e2e values (40, 'w')", "update p0_e2e set b = 'v' where a = 40", "delete from p0_e2e where a = 40"):
    psql(lp, good, sql)
rows = direct("select op, encode(new_hash, 'hex'), new_row::text from (select case when old_hash is null then 'I' when new_hash is null then 'D' else 'U' end as op, new_hash, new_row, seq from cdb.delta where tbl = 'p0_e2e') d order by seq").stdout.strip().splitlines()
check("M2b-2a: an insert, an update and a delete made through the proxy are captured, in order (I, U, D)", [r.split("|")[0] for r in rows] == ["I", "U", "D"], rows)
ins = rows[0].split("|")
check("M2b-2a: the new-row hash is SHA-256 of 'cancho-db/row/v1', a NUL and the jsonb text of the row (recomputed here)",
      len(ins) == 3 and hashlib.sha256(b"cancho-db/row/v1\x00" + ins[2].encode()).hexdigest() == ins[1], ins)
r = psql(lp, good, "create table p0_nokey (x int)")
check("M2b-2a: a table without a primary key cannot be created through the proxy, and is not created", r.returncode != 0 and "no primary key" in r.stderr and direct("select count(*) from pg_class where relname = 'p0_nokey'").stdout.strip() == "0", r.stderr)
direct("delete from cdb.delta where tbl = 'p0_keyed'")      # the delta table outlives a run in the same database
r = psql(lp, good, "create table p0_keyed (id int primary key, v text)")
check("M2b-2a: a table with a primary key can", r.returncode == 0, r.stderr)
psql(lp, good, "insert into p0_keyed values (1, 'a')")
check("M2b-2a: ... and its first write is captured", direct("select count(*) from cdb.delta where tbl = 'p0_keyed'").stdout.strip() == "1")
direct("drop table p0_keyed")
# a keyless or partitioned table that is already there: the proxy refuses to start, and names it
direct("alter event trigger cdb_ddl disable")
direct("create table p0_keyless (x int)")
direct("create table p0_part (id int primary key) partition by range (id)")
_kd = Path(tempfile.mkdtemp())
kp, _ = start_logged(_kd, _scratch + "/key", wait=False)
try:
    kerr = kp.communicate(timeout=15)[1]
except subprocess.TimeoutExpired:
    kp.kill()
    kerr = "timed out"
check("M2b-2a: with a keyless table and a partitioned table in public the proxy refuses to start (exit 7) and names both",
      kp.returncode == 7 and "p0_keyless (no primary key)" in kerr and "p0_part (partitioned)" in kerr, "%s %s" % (kp.returncode, kerr))
check("M2b-2a: a start puts the event trigger back on (it was disabled by hand before the refused start)", direct("select evtenabled from pg_event_trigger where evtname = 'cdb_ddl'").stdout.strip() == "O")
direct("drop table p0_keyless, p0_part")
direct("alter event trigger cdb_ddl disable")
direct("create table p0_pre (id int primary key)")        # made while the event trigger is off: only the proxy's start can track it
check("M2b-2a: (a table made while the event trigger was off has no triggers yet)", direct("select count(*) from pg_trigger where tgrelid = 'p0_pre'::regclass and tgname like 'cdb_%'").stdout.strip() == "0")
kp2, _ = start_logged(Path(tempfile.mkdtemp()), _scratch + "/key", wait=True)
check("M2b-2a: and starts again once they are gone", kp2.poll() is None, kp2.poll())
check("M2b-2a: ... and its start tracked the table that was already there (three triggers)", direct("select count(*) from pg_trigger where tgrelid = 'p0_pre'::regclass and tgname like 'cdb_%'").stdout.strip() == "3")
kp2.terminate()
direct("drop table p0_pre")

check("the proxy is still alive after all of it", proxy.poll() is None)
direct("drop table if exists p0_e2e, p0_big cascade")
proxy.terminate()
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall P0, P1d, P2a, P2c, P2d, P2d-4 and M2b-2a checks passed")
sys.exit(1 if FAILED else 0)
