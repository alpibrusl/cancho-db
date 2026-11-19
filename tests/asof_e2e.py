#!/usr/bin/env python3
"""M2d-3: `AS OF` through the proxy (docs/m2-branches.md D27 to D33), against a real PostgreSQL.

    PG_E2E_PORT=5532 E2E_VERIFIERS="build/verify" python3 tests/asof_e2e.py PROXY_BINARY

The oracle is the data (D9): after every commit of a random session of inserts, updates and deletes the test makes a copy of the table with `create table ... as` (the test is the only writer, so
the copy is the table as that commit left it), and then asks the proxy for the table `as of` each commit and compares it, row for row, with the copy. Over an integer key, a composite key and a text key,
on the first branch and on a fork of it. Then: a commit that does not exist, a commit of another branch, the clause in a write, a token of the current rows, the log verified, a restart.
"""
import hashlib
import os
import random
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

PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_e2e")
PROXY = sys.argv[1]
VERIFIERS = os.environ.get("E2E_VERIFIERS", "").split()
FAILED = []
ensure_database(PG_PORT, DB)


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:700]) if detail and not ok else ""))
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
ALLOW = "r:*,w:*,d:*,c:*,n:*"
TOKEN = mint("password", "--effects", ALLOW)
work = Path(tempfile.mkdtemp())
(work / "key").write_bytes(bytes(range(32)))
ldir = work / "log"
ldir.mkdir()


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


def psql(port, sql, db="main", token=None):
    env = dict(os.environ, PGPASSWORD=token or TOKEN, PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="agent", PGDATABASE=db, PGSSLMODE="prefer", PGCONNECT_TIMEOUT="25")
    return subprocess.run(["psql", "-w", "-At", "-v", "ON_ERROR_STOP=0"], env=env, input=sql.replace("; ", ";\n") + "\n", capture_output=True, text=True, timeout=120)


def commit_ids():
    """The id of every commit of the log, in order, with its branch."""
    data = (ldir / "log").read_bytes()
    at, out = 40, []
    while at < len(data):
        n = struct.unpack(">I", data[at:at + 4])[0]
        enc = data[at + 4:at + 4 + n]
        at += 4 + n + 64
        o = 2
        np_ = struct.unpack(">I", enc[o:o + 4])[0]; o += 4 + 32 * np_
        bl = struct.unpack(">H", enc[o:o + 2])[0]; o += 2
        out.append((hashlib.sha256(b"cancho-db/commit/v1\x00" + enc).digest().hex(), enc[o:o + bl].decode()))
    return out


# ---------------------------------------------------------------------------------------------------- setup
direct("drop schema public cascade; create schema public; drop schema if exists oracle cascade; create schema oracle")
for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
    direct('drop schema "%s" cascade' % sc)
direct("delete from cdb.delta") if direct("select to_regclass('cdb.delta')").stdout.strip() else None
direct("delete from cdb.mark") if direct("select to_regclass('cdb.mark')").stdout.strip() else None
proc, port = start()
check("the proxy starts", proc.poll() is None)
TABLES = [("ao_i", "id int primary key, a text, b int", "id", lambda r: "%d" % r.randrange(1, 40), "(%s, 'v%d', %d)"),
          ("ao_c", "x int, y text, v int, primary key (x, y)", "x, y", lambda r: "%d, 'k%d'" % (r.randrange(1, 6), r.randrange(1, 6)), None),
          ("ao_t", "k text primary key, v int", "k", lambda r: "'t%d'" % r.randrange(1, 40), None)]
for name, cols, _, _, _ in TABLES:
    r = direct("create table %s (%s)" % (name, cols))
    check("table %s is made" % name, r.returncode == 0, r.stderr)


def session(db, rounds, rnd):
    """Random writes, one commit each; after each, a copy of every table as it is. Returns [(commit index in the log, {table: copy name})]."""
    out = []
    for step in range(rounds):
        t = rnd.choice(TABLES)
        name, cols, key, gen, _ = t
        kind = rnd.randrange(4)
        k = gen(rnd)
        if name == "ao_i":
            sql = {0: "insert into ao_i values (%s, 'v%d', %d)" % (k, step, step), 1: "update ao_i set a = 'u%d', b = b + 1 where id = %s" % (step, k),
                   2: "delete from ao_i where id = %s" % k, 3: "update ao_i set b = b + %d where id <= %s" % (step, k)}[kind]
        elif name == "ao_c":
            xk, yk = k.split(", ")
            sql = {0: "insert into ao_c values (%s, %s, %d)" % (xk, yk, step), 1: "update ao_c set v = v + 1 where x = %s and y = %s" % (xk, yk),
                   2: "delete from ao_c where x = %s and y = %s" % (xk, yk), 3: "update ao_c set v = %d where x = %s" % (step, xk)}[kind]
        else:
            sql = {0: "insert into ao_t values (%s, %d)" % (k, step), 1: "update ao_t set v = v + 1 where k = %s" % k,
                   2: "delete from ao_t where k = %s" % k, 3: "update ao_t set v = %d where k <= %s" % (step, k)}[kind]
        n0 = len(commit_ids())
        psql(port, sql, db=db)
        ids = commit_ids()
        if len(ids) == n0:
            continue                      # the statement failed (a duplicate key): no commit
        copies = {}
        for tname, *_ in TABLES:
            sch = "public" if db == "main" else "cdb_b_" + db
            cp = "cp_%s_%s_%d" % (db, tname, len(ids) - 1)
            direct('create table oracle.%s as table "%s".%s' % (cp, sch, tname))
            copies[tname] = cp
        out.append((len(ids) - 1, copies))
    return out


def rows(port, sql, db):
    r = psql(port, sql, db=db)
    return r.returncode, r.stdout.strip().split("\n") if r.stdout.strip() else [], r.stderr


rnd = random.Random(7)
history = session("main", 70, rnd)
check("a random session of %d commits was made, with a copy of every table after each" % len(history), len(history) > 40, len(history))
ids = commit_ids()
bad = []
for idx, copies in history:
    for tname, cp in copies.items():
        order = {"ao_i": "id", "ao_c": "x, y", "ao_t": "k"}[tname]
        rc, got, err = rows(port, "select * from %s as of '%s' order by %s" % (tname, ids[idx][0], order), "main")
        want = direct("select * from oracle.%s order by %s" % (cp, order)).stdout.strip().split("\n")
        want = [w for w in want if w]
        if rc != 0 or "ERROR" in err or got != want:
            bad.append((idx, tname, err.strip()[:120], got[:3], want[:3]))
check("%d reads AS OF a commit equal the copy made at that commit, row for row (three tables, every commit)" % (3 * len(history)), not bad, bad[:2])
rc, got, err = rows(port, "select count(*) from ao_i as of '%s'" % ids[history[-1][0]][0], "main")
check("AS OF the last commit is the table as it is now", got == [direct("select count(*) from ao_i").stdout.strip()], (got, err))
rc, got, err = rows(port, "select o.id, c.k from ao_i as of '%s' o join ao_t as of '%s' c on c.v = o.b order by 1, 2" % (ids[history[10][0]][0], ids[history[10][0]][0]), "main")
check("two tables AS OF the same commit can be joined", rc == 0 and "ERROR" not in err, err)

# ---------------------------------------------------------------------------------------------------- refusals and the branch
r = psql(port, "select * from ao_i as of '%s'" % ("00" * 32))
check("a commit that is not in the log: 22023 as-of-unknown-commit", "as-of-unknown-commit" in r.stderr, r.stderr)
r = psql(port, "select * from ao_i as of 'xyz'")
check("an id that is not 64 hex digits: as-of-bad-commit", "as-of-bad-commit" in r.stderr, r.stderr)
r = psql(port, "update ao_i as of '%s' set b = 0" % ids[history[0][0]][0])
check("the clause in an UPDATE: as-of-write", "as-of-write" in r.stderr, r.stderr)
r = psql(port, "select * from ao_i as of '%s'" % ids[history[3][0]][0], token=mint("password", "--effects", "r:ao_i,r:ao_i.*"))
check("a token of the current rows may not read the past: effect-denied", "effect-denied" in r.stderr, r.stderr)
r = psql(port, "select * from ao_i as of '%s'" % ids[history[3][0]][0], token=mint("password", "--effects", "r:ao_i@*"))
check("a token that names the past may", r.returncode == 0 and "ERROR" not in r.stderr, r.stderr)
cs = commit_ids()
check("the statement store holds the reads with the commit in the table's name (what the log's statements hash)", ("ao_i@" + ids[history[3][0]][0]).encode() in (ldir / "stmts").read_bytes())
r = psql(port, "select cancho_fork('side')")
check("a fork is made", r.returncode == 0 and "ERROR" not in r.stderr, r.stderr)
fork_idx = len(commit_ids()) - 1
r = psql(port, "select * from ao_i as of '%s'" % ids[history[5][0]][0], db="side")
check("a commit of another branch cannot be named from the fork: as-of-unknown-commit", "as-of-unknown-commit" in r.stderr, r.stderr)
side_hist = session("side", 25, random.Random(11))
ids = commit_ids()
bad = []
for idx, copies in side_hist:
    for tname, cp in copies.items():
        order = {"ao_i": "id", "ao_c": "x, y", "ao_t": "k"}[tname]
        rc, got, err = rows(port, "select * from %s as of '%s' order by %s" % (tname, ids[idx][0], order), "side")
        want = [w for w in direct("select * from oracle.%s order by %s" % (cp, order)).stdout.strip().split("\n") if w]
        if rc != 0 or got != want:
            bad.append((idx, tname, err.strip()[:120], got[:3], want[:3]))
check("%d reads AS OF a commit on the fork equal the copies made on the fork" % (3 * len(side_hist)), not bad, bad[:2])
rc, got, err = rows(port, "select count(*) from ao_i as of '%s'" % ids[fork_idx][0], "side")
check("AS OF the fork commit is the copy as it was made", rc == 0 and got == [direct("select count(*) from oracle.cp_main_ao_i_%d" % history[-1][0]).stdout.strip()], (got, err))
check("the main branch cannot name a commit of the fork", "as-of-unknown-commit" in psql(port, "select * from ao_i as of '%s'" % ids[side_hist[0][0]][0]).stderr)

# ---------------------------------------------------------------------------------------------------- the log, a restart
time.sleep(0.3)
argv = ["--root", ROOT, "--tokens", str(ldir / "tokens"), "--stmts", str(ldir / "stmts")]
n = len(commit_ids())
for vname, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
    out = subprocess.run(cmd + [str(ldir / "log")] + argv, capture_output=True, text=True).stdout.strip()
    check("%s accepts the log of the session, the reads that name history included, at L1, L2 and IR" % vname, out.startswith("ok commits=%d " % n), out)
proc.terminate()
proc.communicate(timeout=10)
proc, port = start()
rc, got, err = rows(port, "select count(*) from ao_i as of '%s'" % commit_ids()[history[20][0]][0], "main")
want = direct("select count(*) from oracle.%s" % history[20][1]["ao_i"]).stdout.strip()
check("after a restart the past is still there", rc == 0 and got == [want], (got, want, err))
proc.terminate()
proc.communicate(timeout=10)
for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
    direct('drop schema "%s" cascade' % sc)
direct("drop schema public cascade; create schema public; drop schema oracle cascade")
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall AS OF checks passed")
sys.exit(1 if FAILED else 0)
