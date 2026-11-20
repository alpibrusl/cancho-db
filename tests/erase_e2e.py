#!/usr/bin/env python3
"""`cancho_erase` through the proxy (docs/m2g-erasure.md 6d, slice E4a), against a real PostgreSQL.

    PG_E2E_PORT=5532 E2E_VERIFIERS="build/verify build/verify-go" python3 tests/erase_e2e.py PROXY_BINARY

Checked: a token that has `write` but not `call cancho_erase` is refused 42501; a token that may call it but not write the table is refused 42501 (erase-write-denied); malformed statements, a bad table name and a bad key
are refused with their tags; inside a transaction block it is refused; with a token that may do both, `select cancho_erase('people', '["ana@example.org"]')` deletes the row, scrubs the capture's delta rows (no image, salt or
key of hers in any upstream table) and the rest of the table is as it was; the erase statement's own record in the statement store holds no constant (its payload is erased); the earlier statements that name her are still
in the store until `tools/erase_stmts.py --containing` runs (stated: E4b, the proxy's own rewrite, is later), and after it no byte of the log directory is hers while another subject's are; every verifier accepts the log at L2
with statements both before and after.
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
DB = os.environ.get("E2E_DB", "cdb_erase_e2e")
VERIFIERS = os.environ.get("E2E_VERIFIERS", "build/verify").split()
ROOT = subprocess.run([sys.executable, str(ROOT_DIR / "tools/mint.py"), "root"], capture_output=True, text=True).stdout.strip()
def password(effects): return subprocess.run([sys.executable, str(ROOT_DIR / "tools/mint.py"), "password", "--effects", effects], capture_output=True, text=True).stdout.strip()
FULL = password("r:*,w:*,d:*,c:cancho_erase,n:*")
NO_CALL = password("r:*,w:*,d:*,n:*")
NO_WRITE = password("r:*,w:notes,c:cancho_erase,n:*")
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:500]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def psql(port, sql, pw=None, user="agent"):
    return subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", user, "-d", "main", "-At", "-q", "-v", "VERBOSITY=verbose", "-c", sql], capture_output=True, text=True,
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
    return sum(Path(directory, f).read_bytes().count(needle.encode()) for f in os.listdir(directory))


def verify(logdir, stmts):
    outs = []
    for v in VERIFIERS:
        r = subprocess.run(v.split() + [str(logdir / "log"), "--root", ROOT, "--tokens", str(logdir / "tokens"), "--stmts", str(stmts)], capture_output=True, text=True)
        outs.append(r.stdout.strip())
    return outs


ensure_database(PG_PORT, DB)
direct("drop schema public cascade; create schema public; drop schema if exists cdb cascade")
work = Path(tempfile.mkdtemp())
logdir = work / "log"
logdir.mkdir()
key = work / "key"
key.write_bytes(bytes(range(32)))
direct("create table people (email text primary key, name text, phone text); create table notes (id int primary key, owner text)")
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
for sql in ("insert into people values ('ana@example.org', 'Ana Quintero', '600111222')",
            "insert into people values ('luis@example.org', 'Luis Vega', '600333444')",
            "select name from people where email = 'ana@example.org'"):
    r = psql(port, sql)
    check("runs: %s" % sql[:60], r.returncode == 0, r.stderr)
time.sleep(0.3)
E = "select cancho_erase('people', '[\"ana@example.org\"]')"
r = psql(port, E, NO_CALL)
check("a token with write and no call cancho_erase is refused 42501", r.returncode != 0 and "42501" in r.stderr, r.stderr)
r = psql(port, E, NO_WRITE)
check("a token that may call it but not write the table is refused (erase-write-denied)", r.returncode != 0 and "42501" in r.stderr and "write" in r.stderr, r.stderr)
for what, sql, state in (("malformed (one argument)", "select cancho_erase('people')", "0A000"),
                         ("a bad table name", "select cancho_erase('Peo ple', '[\"a\"]')", "22023"),
                         ("a key that is not a JSON array", "select cancho_erase('people', 'ana')", "22023"),
                         ("a backslash in the key", "select cancho_erase('people', '[\"a\\\\b\"]')", "22023"),
                         ("a table name that starts with a digit", "select cancho_erase('1people', '[\"a\"]')", "22023"),
                         ("a key with no opening bracket", "select cancho_erase('people', '\"a\"]')", "22023"),
                         ("a key with no closing bracket", "select cancho_erase('people', '[\"a\"')", "22023"),
                         ("a quote in the key (no escape is read, so it is not the shape)", "select cancho_erase('people', '[\"a''b\"]')", "0A000"),
                         ("inside a transaction block", None, "25001")):
    if sql is None:
        r = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "agent", "-d", "main", "-At", "-q", "-v", "VERBOSITY=verbose"], input="begin;\n" + E + ";\ncommit;\n", capture_output=True, text=True,
                           env=dict(os.environ, PGPASSWORD=FULL))
        r.returncode = 1 if "ERROR" in r.stderr else 0
    else:
        r = psql(port, sql)
    check("refused (%s): %s" % (what, state), r.returncode != 0 and state in r.stderr, r.stderr)
check("nothing of that has erased her", direct("select count(*) from people where email = 'ana@example.org'").stdout.strip() == "1")
r = psql(port, E)
check("with a token that may do both the erase runs", r.returncode == 0 and "erased: 1 row(s) deleted" in r.stdout, r.stdout + r.stderr)
time.sleep(0.3)
check("her row is gone and his is there", direct("select string_agg(email, ',') from people").stdout.strip() == "luis@example.org")
tables = direct("select format('%I.%I', schemaname, tablename) from pg_tables where schemaname in ('public', 'cdb') order by 1").stdout.split()
dump = "".join(direct("select t::text from %s t" % t).stdout for t in tables)
check("no upstream table the capture keeps holds her e-mail, name or phone", all(v not in dump for v in ("ana@example.org", "Quintero", "600111222")) and "luis@example.org" in dump,
      [v for v in ("ana@example.org", "Quintero", "600111222") if v in dump])
proc.terminate()
proc.communicate(timeout=10)

stmts = logdir / "stmts"
data = stmts.read_bytes()
check("the statement store is version 3", data[:8] == b"CHODBST3")
import struct
sys.path.insert(0, str(ROOT_DIR / "tools"))
import verify as vv  # noqa: E402
recs, at = [], 8
while at < len(data):
    (n,) = struct.unpack(">I", data[at:at + 4])
    recs.append(data[at + 4:at + 4 + n])
    at += 4 + n
erase_recs = [r for r in recs if b"cancho_erase" in r]
check("the erase statement has one record, and its payload is erased (tag 0, nothing after)", len(erase_recs) == 1 and erase_recs[0][-1:] == b"\x00" and b"ana@example" not in erase_recs[0] and b"people" not in erase_recs[0][-1:], len(erase_recs))
outs = verify(logdir, stmts)
check("every verifier accepts the log with the statement store (L2 with statements)", all(re.fullmatch(r"ok commits=\d+ branches=1 level=2\+ir", o) for o in outs), outs)
check("the earlier statements that name her are still in the store (E4b is the proxy's own rewrite)", scan(logdir, "ana@example.org") >= 1)
erased = work / "stmts.erased"
r = subprocess.run([sys.executable, str(ROOT_DIR / "tools/erase_stmts.py"), str(stmts), str(erased), "--containing", "ana@example.org"], capture_output=True, text=True)
check("tools/erase_stmts.py erases them", r.returncode == 0 and r.stdout.startswith("erased "), r.stdout + r.stderr)
after = work / "after"
after.mkdir()
for f in ("log", "tokens"):
    (after / f).write_bytes((logdir / f).read_bytes())
(after / "stmts").write_bytes(erased.read_bytes())
r = subprocess.run([sys.executable, str(ROOT_DIR / "tools/erase_stmts.py"), str(after / "stmts"), str(after / "stmts2"), "--containing", "Quintero"], capture_output=True, text=True)
(after / "stmts").write_bytes((after / "stmts2").read_bytes())
(after / "stmts2").unlink()
check("then no byte of the log directory is hers (e-mail, name, phone) and his are still there", all(scan(after, v) == 0 for v in ("ana@example.org", "Quintero", "600111222")) and scan(after, "luis@example.org") >= 1,
      {v: scan(after, v) for v in ("ana@example.org", "Quintero", "600111222", "luis@example.org")})
outs = verify(logdir, after / "stmts")
check("every verifier still accepts the same log with the erased store", all(re.fullmatch(r"ok commits=\d+ branches=1 level=2\+ir", o) for o in outs), outs)
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall erase checks passed")
sys.exit(1 if FAILED else 0)
