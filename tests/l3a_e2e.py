#!/usr/bin/env python3
"""L3a over the log and the database of a real session through the proxy (docs/spec/l3a.md).

    PG_E2E_PORT=5532 python3 tests/l3a_e2e.py PROXY_BINARY [VERIFIER ...]

A session with writes, a fork, writes on both branches, a merge, DDL, a read and an `AS OF` read; then the delta store is exported from the database (tools/export_deltas.py) and every verifier (default
`python3 tools/l3a.py`) must say `ok ... final` with the live tables compared. Then the ways to cheat are tried and each must be refused with its tag:

  * a row of a table changed directly in the database (not through the proxy): replay-final;
  * a line of the store removed, an image changed, a hash changed, a line added: changes-mismatch / facts-image;
  * a commit's rows moved to another commit: changes-mismatch;
  * data that was in the tables before the proxy first ran: without a base, replay-precondition; with a base made from the tables then, ok.
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
DB = os.environ.get("E2E_DB", "cdb_e2e")
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


def direct(sql):
    return subprocess.run(["psql", "-At"] + PSQL + ["-c", sql], capture_output=True, text=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


ROOT = mint("root")
TOKEN = mint("password", "--effects", "r:*,w:*,d:*,c:*,n:*")
work = Path(tempfile.mkdtemp())
(work / "key").write_bytes(bytes(range(32)))


def start(ldir):
    port = free_port()
    p = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(PG_PORT), "main", ROOT, "postgres", DB, str(ldir), str(work / "key")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    for _ in range(200):
        if p.poll() is not None:
            break
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    return p, port


def psql(port, sql, db="main"):
    env = dict(os.environ, PGPASSWORD=TOKEN, PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="agent", PGDATABASE=db, PGSSLMODE="prefer", PGCONNECT_TIMEOUT="25")
    return subprocess.run(["psql", "-w", "-At", "-v", "ON_ERROR_STOP=0"], env=env, input=sql.replace("; ", ";\n") + "\n", capture_output=True, text=True, timeout=120)


def reset():
    direct("drop schema public cascade; create schema public")
    for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
        direct('drop schema "%s" cascade' % sc)
    if direct("select to_regclass('cdb.delta')").stdout.strip():
        direct("delete from cdb.delta; delete from cdb.mark")


def run_all(log, deltas, base=None, live=False):
    outs = []
    for v in VERIFIERS:
        cmd = v.split() + [str(log), "--deltas", str(deltas)]
        if base:
            cmd += ["--base", str(base)]
        if live:
            cmd += ["--live", " ".join(PSQL)]
        outs.append(subprocess.run(cmd, capture_output=True, text=True).stdout.strip())
    return outs


def export(path):
    return subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "export_deltas.py"), str(path)] + PSQL, capture_output=True, text=True)


# ------------------------------------------------------------------------------------------------ a session
reset()
direct("create table m_par (id int primary key, name text); create table m_kid (id int primary key, par int references m_par(id), v text)")
ldir = Path(tempfile.mkdtemp(dir=work))
proc, port = start(ldir)
check("the proxy starts", proc.poll() is None)
psql(port, "insert into m_par values (1, 'a'), (2, 'b'), (3, 'c')")
psql(port, "insert into m_kid values (1, 1, 'x'), (2, 2, 'y')")
psql(port, "update m_par set name = 'a2' where id = 1")
psql(port, "select cancho_fork('side')")
psql(port, "update m_par set name = 's' where id = 2", db="side")
psql(port, "insert into m_par values (9, 'side-new'); insert into m_kid values (9, 9, 'z')", db="side")
psql(port, "delete from m_kid where id = 1")
psql(port, "insert into m_par values (4, 'd')")
r = psql(port, "select cancho_merge('side')")
check("the merge is made", r.returncode == 0 and "ERROR" not in r.stderr, r.stderr)
psql(port, "create table m_new (id int primary key, w int)")
psql(port, "insert into m_new values (1, 10), (2, 20)")
psql(port, "update m_new set w = w + 1")
psql(port, "select id from m_par order by id")
log_commit_for_asof = None
psql(port, "delete from m_new where id = 2")
time.sleep(0.3)
proc.terminate()
proc.communicate(timeout=10)
deltas = work / "deltas.tsv"
r = export(deltas)
check("the delta store is exported", r.returncode == 0 and deltas.read_text().startswith("CHODBDL1\n"), r.stderr)
outs = run_all(ldir / "log", deltas, live=True)
check("every verifier: ok, with the live tables compared (%s)" % outs[0], all(re.fullmatch(r"ok commits=\d+ facts=\d+ branches=2 final", o) for o in outs), outs)
outs = run_all(ldir / "log", deltas)
check("without the live tables: ok", all(re.fullmatch(r"ok commits=\d+ facts=\d+ branches=2", o) for o in outs), outs)

# ------------------------------------------------------------------------------------------------ cheating
direct("alter table m_par disable trigger user")
direct("update m_par set name = 'evil' where id = 3")
direct("alter table m_par enable trigger user")
outs = run_all(ldir / "log", deltas, live=True)
check("a row changed in the database behind the proxy's back: replay-final", all(o == "reject rule=replay-final record=-1" for o in outs), outs)
direct("update m_par set name = 'c' where id = 3")
outs = run_all(ldir / "log", deltas, live=True)
check("... and put back: ok again", all(o.endswith("final") and o.startswith("ok") for o in outs), outs)
direct("delete from m_kid where id = 2")
outs = run_all(ldir / "log", deltas, live=True)
check("a row deleted behind its back (the trigger records it, unstamped): replay-final", all(o == "reject rule=replay-final record=-1" for o in outs), outs)
direct("insert into m_kid values (2, 2, 'y')")

lines = deltas.read_text().split("\n")
rows = [l for l in lines[1:] if l]


def variant(name, new_lines, expect_prefix):
    p = work / ("v_%s.tsv" % name)
    p.write_text("\n".join(new_lines) + "\n")
    outs = run_all(ldir / "log", p)
    check("%s: %s" % (name, expect_prefix), all(o.startswith("reject rule=" + expect_prefix) for o in outs), outs)


variant("a line of the store removed", [lines[0]] + rows[1:], "changes-mismatch")
f = rows[0].split("\t")
f2 = list(f)
f2[8] = ("7b7d").lower() if f2[8] else f2[8]
variant("an image changed (its hash kept)", [lines[0]] + ["\t".join(f2)] + rows[1:], "facts-image")
f3 = list(f)
f3[6] = "00" * 32 if f3[6] else f3[6]
variant("a hash changed (its image kept)", [lines[0]] + ["\t".join(f3)] + rows[1:], "facts-image")
extra = rows[0].split("\t")
extra[0] = str(max(int(r.split("\t")[0]) for r in rows) + 1)
extra[4] = extra[4] + "00"       # (a copy of a line with the same key and images nets to the same facts: not a change; another key is a fact the log never committed to)
variant("a line for another key added to a commit", [lines[0]] + rows + ["\t".join(extra)], "changes-mismatch")
g = rows[0].split("\t")
other = [r.split("\t")[1] for r in rows if r.split("\t")[1] != g[1]][0]
g[1] = other
variant("a row moved to another commit", [lines[0]] + ["\t".join(g)] + rows[1:], "changes-mismatch")
variant("the store emptied", [lines[0]], "changes-mismatch")

# ------------------------------------------------------------------------------------------------ data from before the proxy
reset()
direct("create table m_par (id int primary key, name text)")
direct("insert into m_par values (1, 'pre'), (2, 'pre2')")
ldir2 = Path(tempfile.mkdtemp(dir=work))
proc, port = start(ldir2)
psql(port, "update m_par set name = 'changed' where id = 1")
psql(port, "insert into m_par values (3, 'new')")
time.sleep(0.3)
proc.terminate()
proc.communicate(timeout=10)
d2 = work / "deltas2.tsv"
export(d2)
outs = run_all(ldir2 / "log", d2)
check("rows that were there before the proxy, no base: replay-precondition", all(o.startswith("reject rule=replay-precondition") for o in outs), outs)
base_rows = direct("select encode(convert_to('m_par', 'UTF8'), 'hex') || E'\\t' || encode(convert_to(jsonb_build_array(id)::text, 'UTF8'), 'hex') || E'\\t' || encode(convert_to(jsonb_build_object('id', id, 'name', name)::text, 'UTF8'), 'hex') from (values (1, 'pre'), (2, 'pre2')) v(id, name)").stdout
base = work / "base.tsv"
base.write_text("CHODBBS1\n" + base_rows)
outs = run_all(ldir2 / "log", d2, base=base, live=True)
check("... with the base (the rows then): ok, final", all(re.fullmatch(r"ok commits=\d+ facts=\d+ branches=1 final", o) for o in outs), outs)

reset()
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall L3a checks passed")
sys.exit(1 if FAILED else 0)
