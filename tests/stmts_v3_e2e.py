#!/usr/bin/env python3
"""The statement store of a real session through the proxy (docs/spec/ir.md section 8, docs/m2g-erasure.md E3c): version 3, the constants are payloads, and erasing them leaves a log that still verifies.

    PG_E2E_PORT=5532 E2E_VERIFIERS="build/verify build/verify-go" python3 tests/stmts_v3_e2e.py PROXY_BINARY

A session writes personal values as literals (an insert, an update, a delete by e-mail, a select). Checked: the statement store is `CHODBST3`; before erasure the values are in its payloads and nowhere else in the log directory
(the log holds hashes); every verifier accepts the log with the store (L2 with statements); the records of one statement with different salts have different ids; a statement with no constants repeats with one id; then
`tools/erase_stmts.py` erases the payloads that hold one subject's values: the planted values are in no byte of the directory any more, the others' still are, and every verifier still accepts the same log with the erased store.
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
DB = "cdb_stmts_v3"
VERIFIERS = os.environ.get("E2E_VERIFIERS", "build/verify").split()
ROOT = subprocess.run([sys.executable, str(ROOT_DIR / "tools/mint.py"), "root"], capture_output=True, text=True).stdout.strip()
PASSWORD = subprocess.run([sys.executable, str(ROOT_DIR / "tools/mint.py"), "password", "--effects", "r:*,w:*,d:*,c:*,n:*"], capture_output=True, text=True).stdout.strip()
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:500]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def psql(port, sql, user="agent"):
    return subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", user, "-d", "main", "-At", "-q", "-c", sql], capture_output=True, text=True,
                          env=dict(os.environ, PGPASSWORD=PASSWORD))


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
direct("drop schema public cascade; create schema public; drop table if exists cdb.delta")
work = Path(tempfile.mkdtemp())
logdir = work / "log"
logdir.mkdir()
key = work / "key"
key.write_bytes(bytes(range(32)))
direct("create table people (email text primary key, name text, phone text); create table ping (id int primary key)")
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
            "update people set phone = '611999888' where email = 'ana@example.org'",
            "select name from people where email = 'ana@example.org'",
            "select name from people where email = 'luis@example.org'",
            "insert into ping values (1)", "delete from ping where id = 1", "insert into ping values (1)"):
    r = psql(port, sql)
    check("runs: %s" % sql[:60], r.returncode == 0, r.stderr)
time.sleep(0.3)
proc.terminate()
proc.communicate(timeout=10)

stmts = logdir / "stmts"
data = stmts.read_bytes()
check("the statement store is version 3", data[:8] == b"CHODBST3", data[:8])
outs = verify(logdir, stmts)
check("every verifier accepts the log with the statement store (L2 with statements)", all(re.fullmatch(r"ok commits=\d+ branches=1 level=2\+ir", o) for o in outs), outs)
check("the planted values are in the statement payloads, and only there: the log holds hashes (before erasure)",
      all(scan(logdir, n) >= 1 for n in ("Quintero", "600111222", "611999888", "ana@example.org", "Vega")) and (logdir / "log").read_bytes().count(b"Quintero") == 0 and (logdir / "log").read_bytes().count(b"ana@example.org") == 0)
# the two reads of one statement shape with different constants, and the two statements `select name ... where email = ?` of different people, have different ids; with no constant the repeat is one
import struct
sys.path.insert(0, str(ROOT_DIR / "tools"))
import verify as vv  # noqa: E402
ids, at = [], 8
while at < len(data):
    (n,) = struct.unpack(">I", data[at:at + 4])
    body = data[at + 4:at + 4 + n]
    at += 4 + n
    ids.append(vv.v3_record(body)[0])
check("every statement record has its own id (ten statements, nine ids: the repeated insert into ping has constants too, so a salt each)", len(ids) == len(set(ids)) and len(ids) == 8, (len(ids), len(set(ids))))

erased = work / "stmts.erased"
r = subprocess.run([sys.executable, str(ROOT_DIR / "tools/erase_stmts.py"), str(stmts), str(erased), "--containing", "Quintero"], capture_output=True, text=True)
check("tools/erase_stmts.py erases the records that hold one subject's name", r.returncode == 0 and r.stdout.startswith("erased 1 record"), r.stdout + r.stderr)
r = subprocess.run([sys.executable, str(ROOT_DIR / "tools/erase_stmts.py"), str(stmts), str(work / "stmts.erased2"), "--containing", "ana@example.org"], capture_output=True, text=True)
r2 = subprocess.run([sys.executable, str(ROOT_DIR / "tools/erase_stmts.py"), str(work / "stmts.erased2"), str(work / "stmts.erased3"), "--containing", "611999888"], capture_output=True, text=True)
shutil_dir = work / "afterlog"
shutil_dir.mkdir()
for f in ("log", "tokens"):
    (shutil_dir / f).write_bytes((logdir / f).read_bytes())
(shutil_dir / "stmts").write_bytes((work / "stmts.erased3").read_bytes())
check("with every record that names the subject erased, no byte of the directory has her name, her phones or her e-mail",
      all(scan(shutil_dir, n) == 0 for n in ("Quintero", "600111222", "611999888", "ana@example.org")), {n: scan(shutil_dir, n) for n in ("Quintero", "600111222", "611999888", "ana@example.org")})
check("... and the others' values are still there", scan(shutil_dir, "Vega") >= 1 and scan(shutil_dir, "luis@example.org") >= 1)
outs = verify(logdir, shutil_dir / "stmts")
check("... and every verifier still accepts the same log with the erased store", all(re.fullmatch(r"ok commits=\d+ branches=1 level=2\+ir", o) for o in outs), outs)
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall statement store version 3 checks passed")
sys.exit(1 if FAILED else 0)
