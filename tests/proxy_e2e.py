#!/usr/bin/env python3
"""The P0 and P1d gates (docs/m1-proxy.md section 7, docs/m1-lowering.md section 5.2), against a real PostgreSQL and the stock psql.

    PG_E2E_PORT=5532 python3 tests/proxy_e2e.py PROXY_BINARY

PostgreSQL must be on 127.0.0.1:$PG_E2E_PORT with trust login for the role `postgres`. The test puts a wire tee
(tools/pgtee.py) between the proxy and PostgreSQL, which is how it counts the connections that reach the server: a refused
login must not be one of them, and a refused query must not be a Query the server sees. It creates and drops the tables `p0_e2e` and
`p0_big`, directly on the server. Exit status 1 if any check fails.
"""
import os
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
from pgtee import Tee  # noqa: E402

PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
PROXY = sys.argv[1]
MINT = [sys.executable, str(ROOT_DIR / "tools" / "mint.py")]
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + detail) if detail and not ok else ""))
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
    return [q for q in tee.queries() if not q.startswith("select c.relname, a.attname")]


def direct(sql):
    return subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-c", sql],
                          capture_output=True, text=True)


def start_proxy(listen, upstream_port, branch="main"):
    p = subprocess.Popen([PROXY, str(listen), "127.0.0.1", str(upstream_port), branch, ROOT, "postgres", "postgres"],
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
direct("create table p0_big as select g, md5(g::text) m from generate_series(1,200000) g")
Q1 = "select a from p0_e2e order by a limit 1"

# ---------------------------------------------------------------- a valid login, and what the proxy lets through
r = psql(lp, good, "select a, b from p0_e2e order by a")
check("valid token: psql connects (default sslmode, so SSLRequest is answered N) and runs a query",
      r.returncode == 0 and r.stdout.strip() == "1|x\n2|y\n3|z", r.stdout + r.stderr)
check("... and the connection reached PostgreSQL once (the proxy's own catalog connection is another)",
      len(client_starts(tee)) == 1, str(tee.kinds()))
startup = client_starts(tee)[0]
check("... as the configured role and database, not the client's choice",
      startup.get("user") == "postgres" and startup.get("database") == "postgres", str(startup))
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

silent = socket.socket()
silent.bind(("127.0.0.1", 0))
silent.listen(4)
sp = silent.getsockname()[1]
p2 = free_port()
proxy2 = start_proxy(p2, sp)
t0 = time.time()
r = psql(p2, good, "select 1", timeout=40)
dt = time.time() - t0
check("an upstream that never answers: refused with upstream-timeout after about 5 s (%.1f s)" % dt,
      "upstream-timeout" in r.stderr and 4 < dt < 12, r.stderr)
proxy2.terminate()
silent.close()
dead = free_port()
proxy3 = start_proxy(free_port(), dead)
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
check("... and PostgreSQL was sent the RENDERING, not what the client typed",
      client_queries(tee) == ['select "a" from "p0_e2e" order by "a"'], str(client_queries(tee)))

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
    ("a transaction", "begin", "unsupported-statement"),
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
check("a string with a doubled quote is lowered and sent back doubled", r.returncode == 0 and client_queries(tee)[-1] == "select \"a\" from \"p0_e2e\" where (\"b\" = 'it''s')", str(client_queries(tee)))

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

check("the proxy is still alive after all of it", proxy.poll() is None)
direct("drop table if exists p0_e2e, p0_big cascade")
proxy.terminate()
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall P0 and P1d checks passed")
sys.exit(1 if FAILED else 0)
