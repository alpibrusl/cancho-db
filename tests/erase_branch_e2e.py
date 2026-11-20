#!/usr/bin/env python3
"""`cancho_erase` on a branch other than the first, and the extended protocol's refusal (docs/m2g-erasure.md 6d), against a real PostgreSQL.

    PG_E2E_PORT=5532 E2E_VERIFIERS="build/verify build/verify-go" python3 tests/erase_branch_e2e.py PROXY_BINARY

A subject is on `main` and, by a fork, on `side`. Checked: an erase on `side` deletes her there, answers that she is still held in `public` (the other branch), and leaves `main`'s row; an erase on `main` then finds
nothing held elsewhere; after both, no byte of the log directory holds her e-mail, name or phone while another subject's are there; every verifier accepts the log (two branches) at L2 with statements; a
`cancho_erase` sent with the extended protocol (Parse, Bind, Execute, Sync) is refused 0A000 `erase-extended-protocol`, the connection then serves a simple query, and nothing is erased.
"""
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))
sys.path.insert(0, str(ROOT_DIR / "tests"))
from pgtee import ensure_database  # noqa: E402

PROXY = sys.argv[1]
PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_erase_branch")
VERIFIERS = os.environ.get("E2E_VERIFIERS", "build/verify").split()
ROOT = subprocess.run([sys.executable, str(ROOT_DIR / "tools/mint.py"), "root"], capture_output=True, text=True).stdout.strip()
def password(effects): return subprocess.run([sys.executable, str(ROOT_DIR / "tools/mint.py"), "password", "--effects", effects], capture_output=True, text=True).stdout.strip()
FULL = password("r:*,w:*,d:*,c:*,n:*")
NO_CALL = password("r:*,w:*,d:*,n:*")
NO_WRITE = password("r:*,w:notes,c:cancho_erase,n:*")
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:500]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def psql(port, sql, pw=None, user="agent", db="main"):
    return subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", user, "-d", db, "-At", "-q", "-v", "VERBOSITY=verbose", "-c", sql], capture_output=True, text=True,
                          env=dict(os.environ, PGPASSWORD=pw or FULL))


def direct(sql):
    return subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", DB, "-At", "-q", "-c", sql], capture_output=True, text=True)


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def scan(directory, needle):
    return sum(Path(directory, f).read_bytes().count(needle.encode()) for f in os.listdir(directory) if Path(directory, f).is_file())


def verify(logdir, stmts):
    outs = []
    for v in VERIFIERS:
        r = subprocess.run(v.split() + [str(logdir / "log"), "--root", ROOT, "--tokens", str(logdir / "tokens"), "--stmts", str(stmts)], capture_output=True, text=True)
        outs.append(r.stdout.strip())
    return outs


ensure_database(PG_PORT, DB)
direct("drop schema public cascade; create schema public; drop schema if exists cdb cascade")
for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
    direct('drop schema "%s" cascade' % sc)
work = Path(tempfile.mkdtemp())
logdir = work / "log"
logdir.mkdir()
key = work / "key"
key.write_bytes(bytes(range(32)))
direct("create table people (email text primary key, name text, phone text)")
port = free_port()
proc = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(PG_PORT), "main", ROOT, "postgres", DB, str(logdir), str(key)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
for _ in range(100):
    if proc.poll() is not None:
        break
    try:
        import socket
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        break
    except OSError:
        time.sleep(0.05)
check("the proxy starts", proc.poll() is None, proc.poll())
for sql in ("insert into people values ('eva@example.org', 'Eva Roca', '600555666')",
            "insert into people values ('luis@example.org', 'Luis Vega', '600333444')",
            "select cancho_fork('side')"):
    r = psql(port, sql)
    check("on main: %s" % sql[:50], r.returncode == 0, r.stderr)
r = psql(port, "select count(*) from people where email = 'eva@example.org'", db="side")
check("the fork holds her too", r.stdout.strip() == "1", r.stdout + r.stderr)
E = "select cancho_erase('people', '[\"eva@example.org\"]')"
r = psql(port, E, db="side")
check("an erase on side deletes her there and says she is still held in public", r.returncode == 0 and "erased: 1 row(s) deleted" in r.stdout and "still held in public" in r.stdout, r.stdout + r.stderr)
time.sleep(0.3)
check("... her row is gone from side and is on main", direct("select count(*) from cdb_b_side.people where email = 'eva@example.org'").stdout.strip() == "0" and direct("select count(*) from public.people where email = 'eva@example.org'").stdout.strip() == "1")
r = psql(port, E)
check("an erase on main then finds nothing held elsewhere", r.returncode == 0 and "erased: 1 row(s) deleted" in r.stdout and "still held" not in r.stdout, r.stdout + r.stderr)
time.sleep(0.3)
check("... her row is gone from main too, his is there", direct("select string_agg(email, ',') from public.people").stdout.strip() == "luis@example.org")
tables = direct("select format('%I.%I', schemaname, tablename) from pg_tables where schemaname in ('public', 'cdb', 'cdb_b_side') order by 1").stdout.split()
dump = "".join(direct("select t::text from %s t" % t).stdout for t in tables)
check("no upstream table holds her e-mail, name or phone", all(v not in dump for v in ("eva@example.org", "Roca", "600555666")) and "luis@example.org" in dump, [v for v in ("eva@example.org", "Roca", "600555666") if v in dump])

# the extended protocol: Parse, Bind, Execute, Sync, with the erase as text and no parameters
def startup(db=b"main"):
    body = struct.pack(">I", 196608) + b"user\0agent\0database\0" + db + b"\0\0"
    return struct.pack(">I", len(body) + 4) + body


def message(kind, body):
    return kind + struct.pack(">I", len(body) + 4) + body


def read_until(s, last):
    buf = b""
    while True:
        d = s.recv(65536)
        if not d:
            return buf
        buf += d
        at, kinds = 0, []
        while at + 5 <= len(buf):
            ln = struct.unpack(">I", buf[at + 1:at + 5])[0]
            if at + 1 + ln > len(buf):
                break
            kinds.append(chr(buf[at]))
            at += 1 + ln
        if kinds and kinds[-1] == last:
            return buf


import socket as _socket
import struct
c = _socket.create_connection(("127.0.0.1", port), timeout=15)
c.sendall(startup() + message(b"p", FULL.encode() + b"\0"))
read_until(c, "Z")
c.sendall(message(b"P", b"\0" + E.encode() + b"\0" + struct.pack(">H", 0)) + message(b"B", b"\0\0" + struct.pack(">HHH", 0, 0, 0)) + message(b"E", b"\0" + struct.pack(">I", 0)) + message(b"S", b""))
got = read_until(c, "Z")
check("the extended protocol's erase is refused 0A000 erase-extended-protocol", b"0A000" in got and b"erase-extended-protocol" in got, got[:200])
c.sendall(message(b"Q", b"select email from people\0"))
got = read_until(c, "Z")
check("... and the same connection then serves a simple query", b"luis@example.org" in got and b"SELECT" in got, got[:160])
c.close()
time.sleep(0.3)
proc.terminate()
proc.communicate(timeout=10)

stmts = logdir / "stmts"
check("no byte of the log directory is hers (e-mail, name, phone) and his are there",
      all(scan(logdir, v) == 0 for v in ("eva@example.org", "Roca", "600555666")) and scan(logdir, "luis@example.org") >= 1,
      {v: scan(logdir, v) for v in ("eva@example.org", "Roca", "600555666", "luis@example.org")})
outs = verify(logdir, stmts)
check("every verifier accepts the log of two branches at L2 with statements", all(re.fullmatch(r"ok commits=\d+ branches=2 level=2\+ir", o) for o in outs), outs)
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall erase branch checks passed")
sys.exit(1 if FAILED else 0)
