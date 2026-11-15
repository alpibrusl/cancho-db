#!/usr/bin/env python3
"""The P0 gate of docs/m1-proxy.md section 7, against a real PostgreSQL and the stock psql.

    PG_E2E_PORT=5532 python3 tests/proxy_e2e.py PROXY_BINARY

PostgreSQL must be on 127.0.0.1:$PG_E2E_PORT with trust login for the role `postgres`. The test puts a wire tee
(tools/pgtee.py) between the proxy and PostgreSQL, which is how it counts the connections that reach the server: a refused
login must not be one of them. It creates and drops the table `p0_e2e`. Exit status 1 if any check fails.
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
good = mint("password")

# ---------------------------------------------------------------- a valid login, and everything forwarded untouched
r = psql(lp, good, "select 1, current_database()")
check("valid token: psql connects (default sslmode, so SSLRequest is answered N) and runs a query",
      r.returncode == 0 and r.stdout.strip() == "1|postgres", r.stdout + r.stderr)
check("... and the connection reached PostgreSQL once", tee.kinds().count("Startup") == 1, str(tee.kinds()))
startup = [d for k, d in tee.messages if k == "Startup"][0]
check("... as the configured role and database, not the client's choice",
      startup.get("user") == "postgres" and startup.get("database") == "postgres", str(startup))
check("... with the client's application_name passed through", startup.get("application_name") == "psql", str(startup))

psql(lp, good, "drop table if exists p0_e2e; create table p0_e2e(a int primary key, b text)")
r = psql(lp, good, "", input="insert into p0_e2e values (1,'x'),(2,'y');\nselect count(*) from p0_e2e;\n")
check("DML round trip", r.returncode == 0 and "INSERT 0 2" in r.stdout and r.stdout.strip().endswith("2"), r.stdout + r.stderr)
r = psql(lp, good, "select * from no_such_table")
check("a PostgreSQL error is relayed as it is", "relation \"no_such_table\" does not exist" in r.stderr, r.stderr)
r = psql(lp, good, "", input="begin;\ninsert into p0_e2e values (3,'z');\nrollback;\nselect count(*) from p0_e2e;\n")
check("a transaction rolls back", r.stdout.strip().endswith("2"), r.stdout + r.stderr)

direct = subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-c",
                         "select g, md5(g::text) from generate_series(1,200000) g"], capture_output=True, text=True).stdout
via = psql(lp, good, "select g, md5(g::text) from generate_series(1,200000) g").stdout
check("200,000 rows come back byte for byte as direct (%d bytes)" % len(direct), direct == via and len(direct) > 5_000_000,
      "%d vs %d bytes" % (len(direct), len(via)))

procs = [subprocess.Popen(["psql", "-At", "-c", "select pg_sleep(0.2), %d" % i],
                          env=dict(os.environ, PGPASSWORD=good, PGHOST="127.0.0.1", PGPORT=str(lp), PGUSER="agent",
                                   PGDATABASE="main", PGSSLMODE="disable"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True) for i in range(24)]
outs = [p.communicate(timeout=60)[0].strip() for p in procs]
check("24 clients at once all get their own answer", sorted(outs) == sorted("|%d" % i for i in range(24)), str(outs[:3]))

for n in (2, 3, 5):
    pw = mint("password", "--blocks", str(n))
    r = psql(lp, pw, "select 1")
    check("a token of %d blocks (a %d-character password) works" % (n, len(pw)), r.returncode == 0 and r.stdout.strip() == "1", r.stderr)

# ---------------------------------------------------------------- refused logins, and none of them reaches PostgreSQL
before = tee.kinds().count("Startup")
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
      tee.kinds().count("Startup") == before, "%d new connections" % (tee.kinds().count("Startup") - before))

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
before = tee.kinds().count("Startup")
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

new_starts = [d for k, d in tee.messages if k == "Startup"][before:]
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
check("... and the proxy still serves", psql(lp, good, "select 1").stdout.strip() == "1")

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

check("the proxy is still alive after all of it", proxy.poll() is None)
psql(lp, good, "drop table if exists p0_e2e")
proxy.terminate()
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall P0 checks passed")
sys.exit(1 if FAILED else 0)
