#!/usr/bin/env python3
"""L3a over a real session in which a subject is erased through the proxy (docs/m2g-erasure.md E5, docs/spec/l3a.md section 9).

    PG_E2E_PORT=5532 python3 tests/erase_l3a_e2e.py PROXY_BINARY [VERIFIER ...]

A session inserts two subjects, updates one, and erases her with `cancho_erase`; then the delta store is exported (tools/export_deltas.py) and the live tables dumped (tools/export_live.py). Checked: the store
(and the dump) hold none of her e-mail, name or phone; every verifier says `ok ... erased=N final` with N above zero (the replay, `changes`, `state` and the tables all hold over the erased rows); the other
subject's rows are not erased; a hash of an erased row changed afterwards is refused (`changes-mismatch`); a row of hers put back behind the proxy's back is refused (`store-malformed`: the
dump of a row the capture never saw has empty salts; before `export_live` used a left join such a row was left out of the dump and the comparison passed).
"""
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))
from pgtee import ensure_database  # noqa: E402

PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_erase_l3a")
PROXY = sys.argv[1]
VERIFIERS = sys.argv[2:] or ["python3 tools/l3a.py"]
FAILED = []
ensure_database(PG_PORT, DB)
PSQL = ["-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", DB]


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:500]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def mint(*args): return subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "mint.py")] + list(args), capture_output=True, text=True, check=True).stdout.strip()


ROOT = mint("root")
TOKEN = mint("password", "--effects", "r:*,w:*,d:*,c:cancho_erase,n:*")


def direct(sql):
    return subprocess.run(["psql", "-At", "-v", "ON_ERROR_STOP=1"] + PSQL + ["-c", sql], capture_output=True, text=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def psql(port, sql):
    env = dict(os.environ, PGPASSWORD=TOKEN, PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="agent", PGDATABASE="main", PGSSLMODE="prefer", PGCONNECT_TIMEOUT="25")
    return subprocess.run(["psql", "-w", "-At"], env=env, input=sql + "\n", capture_output=True, text=True, timeout=120)


def run_all(log, deltas, live=None):
    outs = []
    for v in VERIFIERS:
        cmd = v.split() + [str(log), "--deltas", str(deltas)]
        if live:
            cmd += ["--live-dump", str(live)]
        outs.append(subprocess.run(cmd, capture_output=True, text=True).stdout.strip())
    return outs


work = Path(tempfile.mkdtemp())
(work / "key").write_bytes(bytes(range(32)))
direct("drop schema public cascade; create schema public")
if direct("select to_regclass('cdb.delta')").stdout.strip():
    direct("delete from cdb.delta; delete from cdb.mark; delete from cdb.cur")
direct("create table people (email text primary key, name text, phone text)")
ldir = work / "log"
ldir.mkdir()
port = free_port()
proc = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(PG_PORT), "main", ROOT, "postgres", DB, str(ldir), str(work / "key")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
for _ in range(200):
    if proc.poll() is not None:
        break
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        break
    except OSError:
        time.sleep(0.05)
check("the proxy starts", proc.poll() is None)
psql(port, "insert into people values ('ana@example.org', 'Ana Quintero', '600111222')")
psql(port, "insert into people values ('luis@example.org', 'Luis Vega', '600333444')")
psql(port, "update people set phone = '611999888' where email = 'ana@example.org'")
r = psql(port, "select cancho_erase('people', '[\"ana@example.org\"]')")
check("the erase runs through the proxy", r.returncode == 0 and "erased: 1 row(s) deleted" in r.stdout, r.stdout + r.stderr)
psql(port, "insert into people values ('eva@example.org', 'Eva Roca', '600555666')")
time.sleep(0.3)
proc.terminate()
proc.communicate(timeout=10)

deltas, live = work / "deltas.tsv", work / "live.tsv"
r = subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "export_deltas.py"), str(deltas)] + PSQL, capture_output=True, text=True)
check("the delta store is exported", r.returncode == 0 and deltas.read_text().startswith("CHODBDL2\n"), r.stderr)
subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "export_live.py"), str(live), "public", "--"] + PSQL, check=True)
text = deltas.read_text() + live.read_text()
hexes = {v: v.encode().hex() for v in ("ana@example.org", "Ana Quintero", "600111222", "611999888")}
check("neither the delta store nor the live dump holds her e-mail, name or phones, as text or as hex", all(v not in text and h not in text for v, h in hexes.items()),
      [v for v, h in hexes.items() if v in text or h in text])
check("... and the others' rows are there", "luis@example.org".encode().hex() in text and "eva@example.org".encode().hex() in text)
outs = run_all(ldir / "log", deltas, live)
check("every verifier: ok over the erased rows, with the live tables compared (%s)" % outs[0], all(re.fullmatch(r"ok commits=\d+ facts=\d+ branches=1 erased=[1-9]\d* final", o) for o in outs), outs)
outs = run_all(ldir / "log", deltas)
check("without the live tables: ok", all(re.fullmatch(r"ok commits=\d+ facts=\d+ branches=1 erased=[1-9]\d*", o) for o in outs), outs)

lines = deltas.read_text().split("\n")
rows = [l for l in lines[1:] if l]
erased_rows = [i for i, l in enumerate(rows) if l.split("\t")[8:10] == ["", ""] or not l.split("\t")[8]]
check("some rows of the store are erased (no image), not all", 0 < len(erased_rows) < len(rows), (len(erased_rows), len(rows)))
if erased_rows:
    i = erased_rows[0]
    f = rows[i].split("\t")
    f[6] = "00" * 32 if f[6] else f[6]
    f[7] = "00" * 32 if f[7] and not f[6].startswith("00" * 32) else f[7]
    p = work / "v_hash.tsv"
    p.write_text("\n".join([lines[0]] + rows[:i] + ["\t".join(f)] + rows[i + 1:]) + "\n")
    outs = run_all(ldir / "log", p)
    check("a hash of an erased row changed afterwards: changes-mismatch", all(o.startswith("reject rule=changes-mismatch") for o in outs), outs)
direct("set session_replication_role = replica; insert into people values ('ana@example.org', 'Ana Quintero', '600111222')")
outs = run_all(ldir / "log", deltas, live)
subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "export_live.py"), str(live), "public", "--"] + PSQL, check=True)
outs = run_all(ldir / "log", deltas, live)
check("her row put back behind the proxy's back (no salts: the capture never saw it) is refused, not passed over (store-malformed: a live row with empty salts)", all(o == "reject rule=store-malformed record=-1" for o in outs), outs)
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall erase L3a checks passed")
sys.exit(1 if FAILED else 0)
