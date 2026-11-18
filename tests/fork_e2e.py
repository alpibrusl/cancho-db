#!/usr/bin/env python3
"""M2c-2: `select cancho_fork('<name>')` through the proxy (docs/m2-branches.md D20 to D26), against a real PostgreSQL.

    PG_E2E_PORT=5532 E2E_VERIFIERS="build/verify build/verify-go" python3 tests/fork_e2e.py PROXY_BINARY

  * a fork makes the schema `cdb_b_<name>` as a copy of the connection's branch, and ONE commit in the log: branch the new name, seq 0, one parent (the source's tip), the one
    statement `call cancho_fork`, the empty `changes` and the `state` over the parent's state and it (recomputed here from the bytes, with tools/state.py);
  * a connection to the new branch (the database name) sees the copy; a write there is not in the source and the source's is not there; each branch's chain goes on from its own tip;
  * a fork of a fork; a restart that serves both; a fork refused (token, name, shape, transaction, name taken) leaves no schema and nothing in the log;
  * a token whose `branch` pattern does not cover the new name cannot fork;
  * the three verifiers accept the log of three branches at L1, L2 and IR;
  * a crash before PREPARE, after PREPARE, before COMMIT PREPARED, after COMMIT PREPARED: the schema exists exactly when the commit does.
"""
import hashlib
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))
from pgtee import Tee, ensure_database  # noqa: E402
import state as ref  # noqa: E402

PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_e2e")
PROXY = sys.argv[1]
VERIFIERS = os.environ.get("E2E_VERIFIERS", "").split()
FAILED = []
ensure_database(PG_PORT, DB)
EMPTY = bytes.fromhex(ref.run("C")[3:])


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


def new_log():
    d = Path(tempfile.mkdtemp(dir=work))
    return d


def start(ldir, upstream=None):
    port = free_port()
    p = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(upstream or PG_PORT), "main", ROOT, "postgres", DB, str(ldir), str(work / "key")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    for _ in range(200):
        if p.poll() is not None:
            break
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    return p, port


def stop(p):
    p.terminate()
    return p.communicate(timeout=10)[1]


def psql(port, sql, db="main", token=None):
    env = dict(os.environ, PGPASSWORD=token or TOKEN, PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="agent", PGDATABASE=db, PGSSLMODE="prefer", PGCONNECT_TIMEOUT="25")
    return subprocess.run(["psql", "-w", "-At", "-v", "ON_ERROR_STOP=0"], env=env, input=sql.replace("; ", ";\n") + "\n", capture_output=True, text=True, timeout=120)


def commits(ldir):
    """(id, branch, seq, parents, statements, effects, changes, state) of every commit, from the bytes (docs/spec/commit.md section 2)."""
    data = (ldir / "log").read_bytes()
    at, out = 40, []
    while at < len(data):
        n = struct.unpack(">I", data[at:at + 4])[0]
        enc = data[at + 4:at + 4 + n]
        at += 4 + n + 64
        o = 2
        np_ = struct.unpack(">I", enc[o:o + 4])[0]; o += 4
        parents = [enc[o + 32 * i:o + 32 * i + 32] for i in range(np_)]; o += 32 * np_
        bl = struct.unpack(">H", enc[o:o + 2])[0]; o += 2
        branch = enc[o:o + bl].decode(); o += bl
        seq = struct.unpack(">Q", enc[o:o + 8])[0]; o += 8 + 32
        ns = struct.unpack(">I", enc[o:o + 4])[0]; o += 4 + 32 * ns
        ne = struct.unpack(">I", enc[o:o + 4])[0]; o += 4
        effects = []
        for _ in range(ne):
            kind = enc[o]
            ln = struct.unpack(">H", enc[o + 1:o + 3])[0]
            effects.append((kind, enc[o + 3:o + 3 + ln].decode()))
            o += 3 + ln
        o += 32 + 32
        o += 4 + 32 * struct.unpack(">I", enc[o:o + 4])[0]
        nn = struct.unpack(">I", enc[o:o + 4])[0]; o += 4
        for _ in range(nn):
            tag = enc[o]; o += 1
            o += {0: 0, 1: 8}.get(tag, 0)
            if tag == 2:
                o += 4 + struct.unpack(">I", enc[o:o + 4])[0]
        changes, state = enc[o:o + 32], enc[o + 32:o + 64]
        out.append((hashlib.sha256(b"cancho-db/commit/v1\x00" + enc).digest(), branch, seq, parents, ns, effects, changes, state))
    return out


def schemas():
    return direct("select coalesce(string_agg(nspname, ',' order by nspname), '') from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.strip()


def verify(ldir, label):
    argv = ["--root", ROOT, "--tokens", str(ldir / "tokens"), "--stmts", str(ldir / "stmts")]
    n = len(commits(ldir))
    for vname, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
        out = subprocess.run(cmd + [str(ldir / "log")] + argv, capture_output=True, text=True).stdout.strip()
        check("%s: %s accepts the log, the tokens and the statements at L1, L2 and IR" % (label, vname), out.startswith("ok commits=%d " % n), out)


# ---------------------------------------------------------------------------------------------------- setup
for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
    direct('drop schema "%s" cascade' % sc)
direct("drop schema public cascade; create schema public")
direct("delete from cdb.delta") if direct("select to_regclass('cdb.delta')").stdout.strip() else None
ldir = new_log()
proc, port = start(ldir)
check("the proxy starts", proc.poll() is None)
r = [direct("create table fk_par (id int primary key, name text)"), direct("create table fk_kid (id int generated always as identity primary key, par int references fk_par(id), v text)")]
check("the tables are made", all(x.returncode == 0 for x in r), [x.stderr for x in r])
for sql in ("insert into fk_par values (1, 'one'), (2, 'two')", "insert into fk_kid(par, v) values (1, 'a'), (2, 'b')"):
    r = psql(port, sql)
    check("main: %s" % sql[:40], r.returncode == 0 and "ERROR" not in r.stderr, r.stderr)

# ---------------------------------------------------------------------------------------------------- the fork
before = commits(ldir)
r = psql(port, "select cancho_fork('feat')")
check("the fork runs through the proxy and says how many tables it copied", r.returncode == 0 and "ERROR" not in r.stderr and r.stdout.strip() == "2", (r.stdout, r.stderr))
cs = commits(ldir)
check("one commit more, on the new branch", len(cs) == len(before) + 1 and cs[-1][1] == "feat" and cs[-1][2] == 0, [(c[1], c[2]) for c in cs])
fc = cs[-1]
check("its parent is main's tip, and only that", fc[3] == [before[-1][0]], (fc[3], before[-1][0]))
check("its statement is the one call, and its effect `call cancho_fork`", fc[4] == 1 and fc[5] == [(3, "cancho_fork")], (fc[4], fc[5]))
check("its `changes` is the empty one (the copy is a base, not a change)", fc[6] == EMPTY, fc[6].hex())
check("its `state` is the chain over the source tip's state and that", fc[7] == ref.state([before[-1][7]], EMPTY), fc[7].hex())
check("the schema exists, and holds the rows", schemas() == "cdb_b_feat" and direct("select count(*) from cdb_b_feat.fk_kid").stdout.strip() == "2")
check("no delta row of the fork's copy exists in the branch's schema", direct("select count(*) from cdb.delta where sch = 'cdb_b_feat'").stdout.strip() == "0")

# ---------------------------------------------------------------------------------------------------- two branches, two sets of data
r = psql(port, "select id, v from fk_kid order by id", db="feat")
check("a connection to `feat` sees the copy", r.stdout.split() == ["1|a", "2|b"], (r.stdout, r.stderr))
r = psql(port, "insert into fk_kid(par, v) values (1, 'feat-only')", db="feat")
check("... can write there: the identity went on past the copied rows", r.returncode == 0 and "ERROR" not in r.stderr, r.stderr)
check("... and the write is not in main", psql(port, "select count(*) from fk_kid where v = 'feat-only'", db="main").stdout.strip() == "0")
psql(port, "insert into fk_kid(par, v) values (2, 'main-only')", db="main")
check("... and main's is not in feat", psql(port, "select count(*) from fk_kid where v = 'main-only'", db="feat").stdout.strip() == "0")
r = psql(port, "insert into fk_kid(par, v) values (99, 'x')", db="feat")
check("the foreign key holds in the branch", "violates foreign key" in r.stderr, r.stderr)
cs = commits(ldir)
feat = [c for c in cs if c[1] == "feat"]
main = [c for c in cs if c[1] == "main"]
check("each branch's chain goes on from its own tip: feat 0, 1, 2 (read of the failed insert is not a commit), main continues", [c[2] for c in feat][:2] == [0, 1] and feat[1][3] == [feat[0][0]] and main[-1][3] == [main[-2][0]] and main[-1][2] == main[-2][2] + 1, [(c[1], c[2]) for c in cs])
wr = [c for c in feat if c[6] != EMPTY]
check("the branch's own write has facts (its `changes` is not empty) and its state chains from its parent's", len(wr) == 1 and wr[0][7] == ref.state([feat[feat.index(wr[0]) - 1][7]], wr[0][6]))

# a table made in the branch is in the branch's schema, and the guard checks statements against that schema's snapshot (D22)
r = psql(port, "create table feat_only (id int primary key, w text)", db="feat")
check("DDL on `feat` makes the table in the branch's schema only", r.returncode == 0 and "ERROR" not in r.stderr and direct("select string_agg(table_schema, ',') from information_schema.tables where table_name = 'feat_only'").stdout.strip() == "cdb_b_feat", (r.stderr, direct("select string_agg(table_schema, ',') from information_schema.tables where table_name = 'feat_only'").stdout))
r = psql(port, "insert into feat_only values (1, 'x'); select w from feat_only", db="feat")
check("... the guard knows it there (the branch's snapshot), and the connection reads and writes it", r.returncode == 0 and "ERROR" not in r.stderr and r.stdout.split()[-1] == "x", (r.stdout, r.stderr))
r = psql(port, "select w from feat_only", db="main")
check("... and main's guard does not: unknown-table", "unknown-table" in r.stderr, r.stderr)

# ---------------------------------------------------------------------------------------------------- refusals leave nothing
n0, s0 = len(commits(ldir)), schemas()
cases = [
    ("a name that is taken", "select cancho_fork('feat')", "fork-branch-exists", "main"),
    ("a name with a capital", "select cancho_fork('Feat2')", "fork-bad-name", "main"),
    ("a name with a dash", "select cancho_fork('a-b')", "fork-bad-name", "main"),
    ("a name of 41 characters", "select cancho_fork('%s')" % ("a" * 41), "fork-bad-name", "main"),
    ("an empty name", "select cancho_fork('')", "fork-bad-name", "main"),
    ("two arguments", "select cancho_fork('x', 'main')", "fork-malformed", "main"),
    ("a computed argument", "select cancho_fork('x' || 'y')", "fork-malformed", "main"),
    ("a bare word", "select cancho_fork(feat)", "cannot-lower|unknown|not-supported|column", "main"),
    ("a transaction block", "begin; select cancho_fork('inblock'); commit", "fork-in-transaction", "main"),
]
for name, sql, tag, db in cases:
    r = psql(port, sql, db=db)
    check("refused: %s" % name, any(t in r.stderr for t in tag.split("|")) and "ERROR" in r.stderr, r.stderr + r.stdout)
check("... and none of them made a schema or a commit", schemas() == s0 and len(commits(ldir)) == n0 + (1 if False else 0), (schemas(), len(commits(ldir)) - n0))
r = psql(port, "select cancho_fork('feat2')", db="main", token=mint("password", "--effects", "r:*,w:*,d:*,c:read_only"))
check("a token that may not call cancho_fork is refused by the guard", "effect-denied" in r.stderr, r.stderr)
TOKEN_M = mint("password", "--branch", "m*", "--effects", ALLOW)
r = psql(port, "select cancho_fork('feat2')", db="main", token=TOKEN_M)
check("a token whose branch pattern (m*) does not cover the new name cannot fork: fork-branch-denied", "fork-branch-denied" in r.stderr and schemas() == s0, r.stderr)
r = psql(port, "select cancho_fork('mine')", db="main", token=TOKEN_M)
check("... and one that does cover it can", r.returncode == 0 and "ERROR" not in r.stderr and "cdb_b_mine" in schemas(), r.stderr)
r = psql(port, "select 1", db="feat", token=TOKEN_M)
check("... but cannot connect to a branch the pattern does not cover", "login-branch-denied" in r.stderr, r.stderr)

# ---------------------------------------------------------------------------------------------------- a fork of a fork
r = psql(port, "select cancho_fork('deep')", db="feat")
cs = commits(ldir)
feat = [c for c in cs if c[1] == "feat"]
deep = [c for c in cs if c[1] == "deep"]
check("a connection to `feat` forks it: the commit is on `deep`, seq 0, parent feat's tip", r.returncode == 0 and len(deep) == 1 and deep[0][2] == 0 and deep[0][3] == [feat[-1][0]], (r.stderr, [(c[1], c[2]) for c in cs]))
check("... and the copy has feat's own rows", psql(port, "select count(*) from fk_kid where v = 'feat-only'", db="deep").stdout.strip() == "1")
check("... its state chains from feat's", deep[0][7] == ref.state([feat[-1][7]], EMPTY))

# ---------------------------------------------------------------------------------------------------- the verifiers, and a restart
time.sleep(0.3)
if os.environ.get("FORK_DEBUG"):
    print([(i, c[1], c[2]) for i, c in enumerate(commits(ldir))], (ldir / "tokens").stat().st_size)
verify(ldir, "four branches")
err = stop(proc)
proc, port = start(ldir)
time.sleep(0.3)
check("a restart finds every branch in the log: its start says so", proc.poll() is None)
r = psql(port, "select count(*) from fk_kid", db="deep")
check("... and serves the fork made before it", r.stdout.strip() == "3", (r.stdout, r.stderr))
r = psql(port, "insert into fk_kid(par, v) values (1, 'after-restart')", db="feat")
cs = commits(ldir)
feat = [c for c in cs if c[1] == "feat"]
check("... the next commit of feat chains from feat's last (not another branch's)", r.returncode == 0 and feat[-1][3] == [feat[-2][0]] and feat[-1][2] == feat[-2][2] + 1, (r.stderr, [(c[1], c[2]) for c in cs]))
r = psql(port, "select cancho_fork('feat')", db="main")
check("... and a name taken before the restart is still taken", "fork-branch-exists" in r.stderr, r.stderr)
stop(proc)


# ---------------------------------------------------------------------------------------------------- a race: the source moves while the copy is made
def race():
    rdir = new_log()
    tee = Tee(PG_PORT)
    p, prt = start(rdir, upstream=tee.port)
    psql(prt, "insert into fk_par values (700, 'r')")
    tee.fault("select cdb.fork(", "hold", lambda: psql(prt, "insert into fk_par values (701, 'r2')"))
    n0 = len(commits(rdir))
    r = psql(prt, "select cancho_fork('race')")
    cs2 = commits(rdir)
    check("a commit on the source between the copy and the fork's commit: the fork is refused 40001 fork-raced", "fork-raced" in r.stderr, (r.stdout, r.stderr))
    check("... rolled back: no schema, and the other commit is in the log and the fork's is not", "cdb_b_race" not in schemas() and len(cs2) == n0 + 1 and all(c[1] == "main" for c in cs2), (schemas(), [(c[1], c[2]) for c in cs2]))
    r = psql(prt, "select cancho_fork('race')")
    check("... and the same fork, tried again, succeeds and copies both rows", r.returncode == 0 and "ERROR" not in r.stderr and psql(prt, "select count(*) from fk_par where id >= 700", db="race").stdout.strip() == "2", (r.stdout, r.stderr))
    tee.stop()
    stop(p)


race()

# ---------------------------------------------------------------------------------------------------- the extended protocol does not fork
def extended_refused():
    rdir = new_log()
    p, prt = start(rdir)
    sk = socket.create_connection(("127.0.0.1", prt), timeout=15)
    body = b"user\0agent\0database\0main\0\0"
    sk.sendall(struct.pack(">II", len(body) + 8, 196608) + body)
    time.sleep(0.2)
    sk.recv(4096)
    pw = TOKEN.encode() + b"\0"
    sk.sendall(b"p" + struct.pack(">I", len(pw) + 4) + pw)
    time.sleep(0.3)
    sk.recv(65536)
    parse = b"\0" + b"select cancho_fork('ext')\0" + struct.pack(">H", 0)
    sk.sendall(b"P" + struct.pack(">I", len(parse) + 4) + parse + b"S" + struct.pack(">I", 4))
    time.sleep(0.3)
    data = sk.recv(65536)
    sk.close()
    check("a Parse of the fork statement is refused: 0A000 fork-extended-protocol", b"0A000" in data and b"fork-extended-protocol" in data, data)
    check("... and made nothing", "cdb_b_ext" not in schemas())
    stop(p)


extended_refused()

# ---------------------------------------------------------------------------------------------------- the windows of a crash
def window(name, prefix, when, want_schema, want_commits):
    wdir = new_log()
    for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
        direct('drop schema "%s" cascade' % sc)
    tee = Tee(PG_PORT)
    p, prt = start(wdir, upstream=tee.port)
    psql(prt, "insert into fk_par values (%d, 'w')" % (500 + len(name)))
    direct("select 1")
    tee.fault(prefix, when, p.kill)
    psql(prt, "select cancho_fork('win')")
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
    tee.stop()
    prepared = direct("select count(*) from pg_prepared_xacts where gid like 'cdb:%' and database = current_database()").stdout.strip()
    p2, prt2 = start(wdir)
    time.sleep(0.5)
    alive = p2.poll() is None
    err2 = stop(p2)
    sch = schemas()
    n = len([c for c in commits(wdir) if c[1] == "win"])
    check("crash %s: the schema exists exactly when the fork's commit does (schema '%s', %d fork commit)" % (name, sch, n), alive and sch == want_schema and n == want_commits, (alive, sch, n, prepared, err2[-200:]))
    if want_commits:
        p3, prt3 = start(wdir)
        r = psql(prt3, "select count(*) from fk_par", db="win")
        check("crash %s: after recovery the branch can be connected to and holds the data" % name, r.returncode == 0 and r.stdout.strip().isdigit(), (r.stdout, r.stderr))
        stop(p3)
        verify(wdir, "crash " + name)
    return


window("before PREPARE", "PREPARE TRANSACTION", "before", "", 0)
window("after PREPARE, answer lost", "PREPARE TRANSACTION", "reply", "", 0)
window("logged, before COMMIT PREPARED", "COMMIT PREPARED", "before", "cdb_b_win", 1)
window("committed, answer lost", "COMMIT PREPARED", "reply", "cdb_b_win", 1)

for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
    direct('drop schema "%s" cascade' % sc)
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall fork checks passed")
sys.exit(1 if FAILED else 0)
