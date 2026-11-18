#!/usr/bin/env python3
"""M2b-2b: `changes` and `state` in the commits the proxy makes (docs/spec/state.md, docs/m2-branches.md D16 to D19), against a real PostgreSQL.

    PG_E2E_PORT=5532 E2E_VERIFIERS="build/verify" python3 tests/changes_e2e.py PROXY_BINARY

Writes, reads, DDL, a change that changes nothing, a composite key and a big transaction go through the proxy; then, for every commit in the log:

  * `changes` and `state` are read from the commit's bytes by a parser written here from docs/spec/commit.md section 2;
  * the delta rows that carry the commit's id are read back from the database, the NET facts are worked out again here (first image before, last image after, per key, in
    the spec's order) and `tools/state.py` gives the `changes` they make: it must be the log's;
  * `state` is recomputed from the parents' states and `changes`;
  * a read, a DDL statement and a write that changes nothing have the empty `changes` and no delta row carries their id;
  * the verifiers (L1, L2 and IR) accept the log;
  * a restart takes the tip's `state` back from the log, so the next commit chains from it;
  * a transaction with more facts than one commit may carry (the answer would not fit) is refused 54000, rolled back, and leaves nothing in the log.
"""
import hashlib
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
from pgtee import ensure_database  # noqa: E402
import state as ref  # noqa: E402

PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_e2e")
PROXY = sys.argv[1]
VERIFIERS = os.environ.get("E2E_VERIFIERS", "").split()
FAILED = []
ensure_database(PG_PORT, DB)


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


def direct(sql):
    return subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", DB, "-c", sql], capture_output=True, text=True)


ROOT = mint("root")
TOKEN = mint("password", "--effects", "r:*,w:*,d:*,c:*,n:*")
work = Path(tempfile.mkdtemp())
(work / "key").write_bytes(bytes(range(32)))
ldir = work / "log"
ldir.mkdir()
LONG = "ch_" + "t" * 60                                  # a long table name makes each fact long, so a thousand rows are past the bound


def start():
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


def psql(port, sql):
    env = dict(os.environ, PGPASSWORD=TOKEN, PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="agent", PGDATABASE="main", PGSSLMODE="prefer", PGCONNECT_TIMEOUT="25")
    # through standard input, so that each statement is its own message (the proxy refuses transaction control mixed with a statement in one)
    return subprocess.run(["psql", "-w", "-At", "-v", "ON_ERROR_STOP=0"], env=env, input=sql.replace("; ", ";\n") + "\n", capture_output=True, text=True, timeout=120)


def commits():
    """(id, changes, state, parents) of every commit of the log, from the bytes (docs/spec/commit.md sections 2 to 4)."""
    data = (ldir / "log").read_bytes()
    at, out = 40, []
    while at < len(data):
        n = struct.unpack(">I", data[at:at + 4])[0]
        enc = data[at + 4:at + 4 + n]
        at += 4 + n + 64
        o = 2
        np_ = struct.unpack(">I", enc[o:o + 4])[0]; o += 4
        parents = [enc[o + 32 * i:o + 32 * i + 32] for i in range(np_)]; o += 32 * np_
        o += 2 + struct.unpack(">H", enc[o:o + 2])[0]          # branch
        o += 8 + 32                                            # seq, schema
        o += 4 + 32 * struct.unpack(">I", enc[o:o + 4])[0]     # statements
        ne = struct.unpack(">I", enc[o:o + 4])[0]; o += 4
        for _ in range(ne):
            o += 1 + 2 + struct.unpack(">H", enc[o + 1:o + 3])[0]
        o += 32 + 32                                           # token, principal
        o += 4 + 32 * struct.unpack(">I", enc[o:o + 4])[0]     # code
        nn = struct.unpack(">I", enc[o:o + 4])[0]; o += 4
        for _ in range(nn):
            tag = enc[o]; o += 1
            o += {0: 0, 1: 8}.get(tag, 0)
            if tag == 2:
                o += 4 + struct.unpack(">I", enc[o:o + 4])[0]
        changes, state = enc[o:o + 32], enc[o + 32:o + 64]
        ident = hashlib.sha256(b"cancho-db/commit/v1\x00" + enc).digest()
        out.append((ident, changes, state, parents))
    return out


def net_facts(rows):
    """rows: [(tbl, pk_hex, seq, old_hex|None, new_hex|None)] of ONE commit -> the facts text (first image before, last image after, per key; sorted as the spec sorts)."""
    per = {}
    for tbl, pk, seq, o, n in sorted(rows, key=lambda r: r[2]):
        k = (tbl.encode(), bytes.fromhex(pk))
        if k not in per:
            per[k] = [o, n]
        else:
            per[k][1] = n
    facts = []
    for (tb, pk), (o, n) in sorted(per.items()):
        if o is None and n is None or o == n:
            continue
        kind = 0 if o is None else 2 if n is None else 1
        facts.append("%d:%s:%s:%s:%s" % (kind, tb.hex(), pk.hex(), o or "-", n or "-"))
    return " ".join(facts)


# ---------------------------------------------------------------------------------------------------- setup
for t in ("ch1", "ch2", "ch3", LONG):
    direct('drop table if exists "%s" cascade' % t)
direct("delete from cdb.delta where tbl in ('ch1', 'ch2', 'ch3', '%s')" % LONG) if direct("select to_regclass('cdb.delta')").stdout.strip() else None
proc, port = start()
check("the proxy starts", proc.poll() is None)
r = [direct("create table ch1 (id int primary key, v text)"), direct("create table ch2 (a int, b text, w int, primary key (a, b))"), direct('create table "%s" (id int primary key, v text)' % LONG)]
check("the tables are made behind the proxy (they are tracked by the event trigger)", all(x.returncode == 0 for x in r), [x.stderr for x in r])
direct("delete from cdb.delta where tbl in ('ch1', 'ch2', '%s')" % LONG)

steps = [
    ("an autocommit insert", "insert into ch1 values (1, 'a')"),
    ("a transaction: insert, update of it, another insert, a delete of the first row", "begin; insert into ch1 values (2, 'b'); update ch1 set v = 'bb' where id = 2; insert into ch1 values (3, 'c'); delete from ch1 where id = 1; commit"),
    ("a read", "select id from ch1 order by id"),
    ("a write that changes nothing", "update ch1 set v = 'c' where id = 3"),
    ("DDL", "create table ch3 (id int primary key)"),
    ("a composite key: two inserts and an update", "begin; insert into ch2 values (1, 'x', 10), (1, 'y', 20); update ch2 set w = 11 where a = 1 and b = 'x'; commit"),
    ("a bigger insert (300 rows)", "insert into ch1 values " + ", ".join("(%d, 'r')" % i for i in range(100, 400))),
]
for name, sql in steps:
    r = psql(port, sql)
    check("%s: runs through the proxy" % name, r.returncode == 0 and "ERROR" not in r.stderr, r.stderr)
time.sleep(0.3)

cs = commits()
check("the log has one commit per step that made one (a read is a commit too): %d" % len(steps), len(cs) == len(steps), len(cs))
EMPTY = bytes.fromhex(ref.run("C")[3:])
rows_by_commit = {}
for line in direct("select encode(commit_id, 'hex') || '|' || tbl || '|' || encode(pk, 'hex') || '|' || seq || '|' || coalesce(encode(old_hash, 'hex'), '') || '|' || coalesce(encode(new_hash, 'hex'), '') from cdb.delta where commit_id is not null and tbl in ('ch1', 'ch2', 'ch3', '%s') order by seq" % LONG).stdout.splitlines():
    cid, tbl, pk, seq, o, n = line.split("|")
    rows_by_commit.setdefault(cid, []).append((tbl, pk, int(seq), o or None, n or None))

ok_changes, bad = True, []
prev_state, ok_state = None, True
for i, (ident, changes, state, parents) in enumerate(cs):
    mine = rows_by_commit.get(ident.hex(), [])
    want = ref.run("C " + net_facts(mine))
    if want != "ok " + changes.hex():
        ok_changes = False
        bad.append((i, want[:30], changes.hex()[:30]))
    exp_state = ref.state([prev_state] if prev_state else [], changes)
    if exp_state != state:
        ok_state = False
    if (len(parents) == 1) != (prev_state is not None):
        ok_state = False
    prev_state = state
check("every commit's `changes` is the one tools/state.py gives the net facts of its delta rows (recomputed here from the database)", ok_changes, bad)
check("every commit's `state` is the chain over the parent's state and its changes", ok_state)
kinds = [("empty" if c[1] == EMPTY else "facts") for c in cs]
check("a read, a write that changes nothing and DDL have the empty `changes`; the others do not: %s" % " ".join(kinds), kinds == ["facts", "facts", "empty", "empty", "empty", "facts", "facts"], kinds)
check("no delta row carries the id of the read or of the DDL; the write that changed nothing has its delta row (stamped, with equal images) and no net fact",
      all(cs[i][0].hex() not in rows_by_commit for i in (2, 4)) and len(rows_by_commit.get(cs[3][0].hex(), [])) == 1 and net_facts(rows_by_commit[cs[3][0].hex()]) == "", list(rows_by_commit))
check("every delta row of the run is stamped: none is left without a commit", direct("select count(*) from cdb.delta where commit_id is null and tbl in ('ch1', 'ch2', '%s')" % LONG).stdout.strip() == "0")
net1 = net_facts(rows_by_commit[cs[1][0].hex()])
check("the transaction's net facts are a delete of row 1, an insert of row 2 (its last image) and an insert of row 3", [f.split(":")[0] for f in net1.split()] == ["2", "0", "0"] or sorted(f.split(":")[0] for f in net1.split()) == ["0", "0", "2"], net1)

argv = ["--root", ROOT, "--tokens", str(ldir / "tokens"), "--stmts", str(ldir / "stmts")]
for vname, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
    out = subprocess.run(cmd + [str(ldir / "log")] + argv, capture_output=True, text=True).stdout.strip()
    check("%s accepts the log, the tokens and the statements at L1, L2 and IR" % vname, out.startswith("ok commits=%d " % len(cs)), out)

# ---------------------------------------------------------------------------------------------------- the bound
# (a statement that changes many rows with little text: the per-transaction limit on statement size is met first by big INSERTs)
direct('insert into "%s" select g, \'x\' from generate_series(0, 999) g' % LONG)
direct("delete from cdb.delta where tbl = '%s'" % LONG)
n_before = len(commits())
r600 = psql(port, 'update "%s" set v = \'y\' where id < 600' % LONG)
nfacts = int(direct("select count(*) from cdb.delta d where tbl = '%s' and commit_id = (select commit_id from cdb.delta where tbl = '%s' order by seq desc limit 1)" % (LONG, LONG)).stdout.strip() or -1)
check("an UPDATE of 600 rows of a table with a long name (%d facts of about 270 bytes: 160 KB of facts text) is within the bound" % nfacts, r600.returncode == 0 and "ERROR" not in r600.stderr and nfacts == 600 and len(commits()) == n_before + 1, r600.stderr)
r900 = psql(port, 'update "%s" set v = \'z\' where id < 900' % LONG)
check("an UPDATE of 900 rows (about 245 KB of facts text) is past it: refused 54000 transaction-too-large", "transaction-too-large" in r900.stderr, r900.stderr + r900.stdout)
check("... rolled back (the rows are as the first update left them) and nothing of it is in the log",
      direct('select count(*) from "%s" where v = \'z\'' % LONG).stdout.strip() == "0" and direct('select count(*) from "%s" where v = \'y\'' % LONG).stdout.strip() == "600" and len(commits()) == n_before + 1, len(commits()) - n_before)
check("... with no delta row left without a commit (the rolled-back transaction took its facts with it)", direct("select count(*) from cdb.delta where commit_id is null and tbl = '%s'" % LONG).stdout.strip() == "0")
check("... and the same connection goes on working", psql(port, "select id from ch1 order by id limit 1").returncode == 0)

# ---------------------------------------------------------------------------------------------------- a restart
tip = commits()[-1]
proc.terminate()
proc.communicate(timeout=10)
proc, port = start()
check("the proxy restarts on the same log", proc.poll() is None)
psql(port, "insert into ch1 values (9000, 'after the restart')")
time.sleep(0.3)
after = commits()
check("a restart takes the tip's state back from the log: the next commit's state chains from it", len(after) == len(cs) + 3 and after[-1][3] == [tip[0]] and after[-1][2] == ref.state([tip[2]], after[-1][1]),
      (len(after), len(cs) + 3, after[-1][3] == [tip[0]], after[-1][2] == ref.state([tip[2]], after[-1][1])))
for vname, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
    out = subprocess.run(cmd + [str(ldir / "log")] + argv, capture_output=True, text=True).stdout.strip()
    check("%s accepts the longer log" % vname, out.startswith("ok commits=%d " % len(after)), out)

proc.terminate()
for t in ("ch1", "ch2", "ch3", LONG):
    direct('drop table if exists "%s" cascade' % t)
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall M2b-2b checks passed")
sys.exit(1 if FAILED else 0)
