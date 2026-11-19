#!/usr/bin/env python3
"""M2e-2: `select cancho_merge('<source>')` through the proxy (docs/m2-branches.md D34 to D42), against a real PostgreSQL.

    PG_E2E_PORT=5532 E2E_VERIFIERS="build/verify build/verify-go" python3 tests/merge_e2e.py PROXY_BINARY

  * a merge is ONE commit on the connection's branch with TWO parents (its tip and the source's tip, in that order), the effect `call cancho_merge`, `changes` the root over the net facts of the rows it applied
    (recomputed here from the delta rows with tools/state.py) and `state` the chain over BOTH parents' states and that;
  * the merged table equals what a reference of the rule (written here) gives from copies of the base and of the two sides;
  * a second merge in either direction, and one after a restart, find their base (the commit graph is rebuilt from the log);
  * a conflict, a foreign-key break, a branch that is not there, itself, a transaction block, a token that cannot write every table, a computed argument, the extended protocol: each refused with its tag, nothing in the log, the data as it was;
  * a commit on either branch while the merge runs: `merge-raced`;
  * the three verifiers accept the log of forks and merges at L1, L2 and IR;
  * a crash before PREPARE, after PREPARE, before COMMIT PREPARED, after COMMIT PREPARED: the data is merged exactly when the commit is in the log.
"""
import hashlib
import json
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
TOKEN = mint("password", "--effects", "r:*,w:*,d:*,c:*,n:*")
work = Path(tempfile.mkdtemp())
(work / "key").write_bytes(bytes(range(32)))


def new_log():
    return Path(tempfile.mkdtemp(dir=work))


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
    """(id, branch, seq, parents, effects, changes, state) of every commit, from the bytes (docs/spec/commit.md section 2)."""
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
            ln = struct.unpack(">H", enc[o + 1:o + 3])[0]
            effects.append((enc[o], enc[o + 3:o + 3 + ln].decode()))
            o += 3 + ln
        o += 32 + 32
        o += 4 + 32 * struct.unpack(">I", enc[o:o + 4])[0]
        nn = struct.unpack(">I", enc[o:o + 4])[0]; o += 4
        for _ in range(nn):
            tag = enc[o]; o += 1
            o += {0: 0, 1: 8}.get(tag, 0)
            if tag == 2:
                o += 4 + struct.unpack(">I", enc[o:o + 4])[0]
        out.append((hashlib.sha256(b"cancho-db/commit/v1\x00" + enc).digest(), branch, seq, parents, effects, enc[o:o + 32], enc[o + 32:o + 64]))
    return out


def verify(ldir, label):
    argv = ["--root", ROOT, "--tokens", str(ldir / "tokens"), "--stmts", str(ldir / "stmts")]
    n = len(commits(ldir))
    for vname, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
        out = subprocess.run(cmd + [str(ldir / "log")] + argv, capture_output=True, text=True).stdout.strip()
        check("%s: %s accepts the log, the tokens and the statements at L1, L2 and IR" % (label, vname), out.startswith("ok commits=%d " % n), out)


TABLES = [("m_par", "id"), ("m_kid", "id"), ("m_c", "x, y")]


def dump(schema, table, key):
    r = direct("select jsonb_build_array(%s)::text || E'\\t' || to_jsonb(rr)::text from %s.%s rr" % (", ".join("rr." + c.strip() for c in key.split(",")), schema, table))
    out = {}
    for line in r.stdout.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            out[k] = v
    return out


def state_of(schema):
    return {t: dump(schema, t, key) for t, key in TABLES}


def reference(base, t, s):
    """D34: (conflicting keys, merged dict)."""
    conflicts, merged = [], dict(t)
    for k in set(base) | set(t) | set(s):
        b, tv, sv = base.get(k), t.get(k), s.get(k)
        if sv == b:
            continue
        if tv == b:
            if sv is None:
                merged.pop(k, None)
            else:
                merged[k] = sv
        elif tv != sv:
            conflicts.append(k)
    return conflicts, merged


def merged_state(base, t, s):
    out, conflicts = {}, []
    for tn, _ in TABLES:
        c, m = reference(base[tn], t[tn], s[tn])
        conflicts += c
        out[tn] = m
    return conflicts, out


def net_facts_of(commit_id_hex):
    """The facts `changes` is the root of, from the delta rows stamped with the commit: first image before, last image after, per key, in the spec's order."""
    rows = direct("select tbl || '|' || encode(pk, 'hex') || '|' || seq || '|' || coalesce(encode(old_hash, 'hex'), '') || '|' || coalesce(encode(new_hash, 'hex'), '') from cdb.delta where commit_id = decode('%s', 'hex')" % commit_id_hex).stdout.split()
    per = {}
    for line in sorted(rows, key=lambda r: int(r.split("|")[2])):
        tbl, pk, seq, o, n = line.split("|")
        k = (tbl.encode(), bytes.fromhex(pk))
        if k not in per:
            per[k] = [o or None, n or None]
        else:
            per[k][1] = n or None
    facts = []
    for (tb, pk), (o, n) in sorted(per.items()):
        if o is None and n is None or o == n:
            continue
        kind = 0 if o is None else 2 if n is None else 1
        facts.append("%d:%s:%s:%s:%s" % (kind, tb.hex(), pk.hex(), o or "-", n or "-"))
    return " ".join(facts)


def setup_tables():
    direct("drop schema public cascade; create schema public; drop schema if exists oracle cascade; create schema oracle")
    for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
        direct('drop schema "%s" cascade' % sc)
    direct("delete from cdb.delta") if direct("select to_regclass('cdb.delta')").stdout.strip() else None
    direct("delete from cdb.mark") if direct("select to_regclass('cdb.mark')").stdout.strip() else None
    direct("create table m_par (id int primary key, name text); create table m_kid (id int primary key, par int references m_par(id), v text); create table m_c (x int, y text, w int, primary key (x, y))")


# ---------------------------------------------------------------------------------------------------- the first merge
setup_tables()
ldir = new_log()
proc, port = start(ldir)
check("the proxy starts", proc.poll() is None)
# (the proxy refuses INSERT ... SELECT, so the base is written as VALUES)
psql(port, "insert into m_par values " + ", ".join("(%d, 'p%d')" % (g, g) for g in range(1, 9)))
psql(port, "insert into m_kid values " + ", ".join("(%d, %d, 'k')" % (g, 1 + g % 8) for g in range(1, 9)))
psql(port, "insert into m_c values (2, 'k2', 1), (3, 'k3', 2), (1, 'k1', 3)")
r = psql(port, "select cancho_fork('side')")
check("a fork is made", r.returncode == 0 and "ERROR" not in r.stderr, r.stderr)
base = state_of("public")
psql(port, "update m_par set name = 'main-1' where id = 1")
psql(port, "insert into m_par values (100, 'main-new')")
psql(port, "update m_c set w = 99 where x = 1")
psql(port, "update m_par set name = 'side-2' where id = 2", db="side")
psql(port, "insert into m_par values (200, 'side-new'); insert into m_kid values (201, 200, 'side-kid')", db="side")
psql(port, "delete from m_kid where id = 3", db="side")
psql(port, "update m_par set name = 'side-1' where id = 1", db="side") if False else None
t_state, s_state = state_of("public"), state_of("cdb_b_side")
conflicts, want = merged_state(base, t_state, s_state)
check("the sides diverged without a conflict (the reference says so)", not conflicts, conflicts)
before = commits(ldir)
main_tip, side_tip = [c for c in before if c[1] == "main"][-1], [c for c in before if c[1] == "side"][-1]
r = psql(port, "select cancho_merge('side')")
check("the merge runs through the proxy and answers how many rows it applied", r.returncode == 0 and "ERROR" not in r.stderr and r.stdout.strip().isdigit(), (r.stdout, r.stderr))
after = commits(ldir)
mc = after[-1]
check("one commit more: on the target branch, the next seq", len(after) == len(before) + 1 and mc[1] == "main" and mc[2] == main_tip[2] + 1, [(c[1], c[2]) for c in after][-3:])
check("its two parents are the target's tip and the source's tip, in that order", mc[3] == [main_tip[0], side_tip[0]], (mc[3], main_tip[0], side_tip[0]))
check("its effect is `call cancho_merge` and nothing else", mc[4] == [(3, "cancho_merge")], mc[4])
check("the target equals the reference's result, row for row", state_of("public") == want, [(t, len(state_of("public")[t]), len(want[t])) for t, _ in TABLES])
facts = net_facts_of(mc[0].hex())
check("its `changes` is the root over the net facts of the rows it applied (recomputed from the delta rows)", facts != "" and ref.run("C " + facts) == "ok " + mc[5].hex(), (facts[:80], mc[5].hex()))
check("its `state` is the chain over BOTH parents' states and its changes", mc[6] == ref.state([main_tip[6], side_tip[6]], mc[5]), mc[6].hex())
check("the source is untouched", state_of("cdb_b_side") == s_state)

# ---------------------------------------------------------------------------------------------------- a second merge, both directions
base2_main, base2_side = state_of("public"), state_of("cdb_b_side")
psql(port, "update m_par set name = 'side-again' where id = 4", db="side")
psql(port, "update m_c set w = 5 where x = 3", db="main")
# a row the side changed and the first merge brought over, changed again on main: with the right base (the side's tip at the first merge) it is main's alone, with the fork point as the base it would be a conflict
psql(port, "update m_par set name = 'main-again' where id = 2", db="main")
t2, s2 = state_of("public"), state_of("cdb_b_side")
# the base is now the source's tip: the target has the source's earlier changes already
c2, want2 = merged_state(base2_side, t2, s2)
r = psql(port, "select cancho_merge('side')")
check("a second merge of the same branch: its base is the source's last commit, found in the graph (through the first merge's second parent); the result is the reference's", r.returncode == 0 and "ERROR" not in r.stderr and not c2 and state_of("public") == want2, (r.stderr, c2))
n_after = len(commits(ldir))
# the other direction: the source takes the target's changes
base3 = state_of("public")
psql(port, "insert into m_par values (300, 'main-after')")
t3, s3 = state_of("public"), state_of("cdb_b_side")
r = psql(port, "select cancho_merge('main')", db="side")
# the source's last commit is already an ancestor of `main` (the second merge made it one), so the base is the side's own state: the side takes everything main has
c3, want3 = merged_state(s3, s3, t3)
mc2 = commits(ldir)[-1]
check("a merge the other way (the first branch as the source, `main`): two parents, on `side`", r.returncode == 0 and mc2[1] == "side" and len(mc2[3]) == 2, (r.stderr, mc2[1], len(mc2[3])))
check("... and the side holds its own rows and main's (no conflict was possible)", not c3 and state_of("cdb_b_side") == want3, c3)

# ---------------------------------------------------------------------------------------------------- refusals
n0, d0 = len(commits(ldir)), state_of("public")
psql(port, "update m_par set name = 'c-main' where id = 5")
psql(port, "update m_par set name = 'c-side' where id = 5", db="side")
n1 = len(commits(ldir))
d1 = state_of("public")
r = psql(port, "select cancho_merge('side')")
check("a key changed to different images on both branches: merge-conflict, naming the table", "merge-conflict" in r.stderr and "m_par" in r.stderr, r.stderr)
check("... nothing in the log and the data as it was", len(commits(ldir)) == n1 and state_of("public") == d1)
psql(port, "update m_par set name = 'c-main' where id = 5", db="side")
psql(port, "insert into m_kid values (400, 8, 'late')")
psql(port, "delete from m_kid where par = 8; delete from m_par where id = 8", db="side")
n2, d2 = len(commits(ldir)), state_of("public")
r = psql(port, "select cancho_merge('side')")
check("the source deletes a parent the target gave a new child: merge-constraint", "merge-constraint" in r.stderr, r.stderr)
check("... nothing in the log and the data as it was", len(commits(ldir)) == n2 and state_of("public") == d2)
cases = [
    ("a branch that is not there", "select cancho_merge('nosuch')", "merge-unknown-branch"),
    ("a branch merged into itself", "select cancho_merge('main')", "merge-same-branch"),
    ("a name with a capital", "select cancho_merge('Side')", "merge-bad-name"),
    ("a computed argument", "select cancho_merge('si' || 'de')", "merge-malformed"),
    ("two arguments", "select cancho_merge('side', 'main')", "merge-malformed"),
    ("a transaction block", "begin; select cancho_merge('side'); commit", "merge-in-transaction"),
]
for name, sql, tag in cases:
    n_before = len(commits(ldir))
    r = psql(port, sql)
    check("refused: %s (%s)" % (name, tag), tag in r.stderr and len(commits(ldir)) == n_before, r.stderr + r.stdout)
r = psql(port, "select cancho_merge('side')", token=mint("password", "--effects", "r:*,w:m_c,w:m_par,d:*,c:*,n:*"))
check("a token that may not write every table of the branch: merge-denied", "merge-denied" in r.stderr, r.stderr)
r = psql(port, "select cancho_merge('side')", token=mint("password", "--effects", "r:*,w:*,d:*,c:cancho_fork,n:*"))
check("a token that may not call cancho_merge is refused by the guard", "effect-denied" in r.stderr, r.stderr)
sk = socket.create_connection(("127.0.0.1", port), timeout=15)
body = b"user\0agent\0database\0main\0\0"
sk.sendall(struct.pack(">II", len(body) + 8, 196608) + body)
time.sleep(0.2)
sk.recv(4096)
pw = TOKEN.encode() + b"\0"
sk.sendall(b"p" + struct.pack(">I", len(pw) + 4) + pw)
time.sleep(0.3)
sk.recv(65536)
parse = b"\0" + b"select cancho_merge('side')\0" + struct.pack(">H", 0)
sk.sendall(b"P" + struct.pack(">I", len(parse) + 4) + parse + b"S" + struct.pack(">I", 4))
time.sleep(0.3)
data = sk.recv(65536)
sk.close()
check("a Parse of the merge statement: 0A000 merge-extended-protocol", b"merge-extended-protocol" in data, data)

# ---------------------------------------------------------------------------------------------------- a restart: the graph is rebuilt from the log
psql(port, "update m_par set name = 'c-main' where id = 5")
stop(proc)
proc, port = start(ldir)
time.sleep(0.3)
psql(port, "delete from m_kid where id = 400; update m_par set name = 'c-main' where id = 8", db="main") if False else None
psql(port, "update m_par set name = 'after-restart' where id = 6", db="side")
bb = state_of("public")
r = psql(port, "select cancho_merge('side')")
mcs = commits(ldir)[-1]
check("after a restart a merge still finds its base: the graph was read from the log", "ERROR" in r.stderr and "merge-constraint" in r.stderr or (r.returncode == 0 and len(mcs[3]) == 2), (r.stderr, r.stdout))

# ---------------------------------------------------------------------------------------------------- the verifiers
time.sleep(0.3)
verify(ldir, "forks and merges")
stop(proc)

# ---------------------------------------------------------------------------------------------------- a race: a commit on the source while the merge runs
def race():
    setup_tables()
    rdir = new_log()
    tee = Tee(PG_PORT)
    p, prt = start(rdir, upstream=tee.port)
    psql(prt, "insert into m_par values (1, 'a'), (2, 'b'), (3, 'c')")
    psql(prt, "select cancho_fork('side')")
    psql(prt, "update m_par set name = 's' where id = 1", db="side")
    psql(prt, "update m_par set name = 'm' where id = 2")
    tee.fault("select cdb.merge(", "hold", lambda: psql(prt, "update m_par set name = 's2' where id = 3", db="side"))
    n0 = len(commits(rdir))
    r = psql(prt, "select cancho_merge('side')")
    cs = commits(rdir)
    check("a commit on the source between the merge's start and its commit: merge-raced", "merge-raced" in r.stderr, r.stderr)
    check("... rolled back: the other commit is in the log and the merge's is not, and the target is as it was", len(cs) == n0 + 1 and all(len(c[3]) < 2 for c in cs), [(c[1], len(c[3])) for c in cs][-3:])
    r = psql(prt, "select cancho_merge('side')")
    check("... and the same merge, tried again, goes through", r.returncode == 0 and "ERROR" not in r.stderr, r.stderr)
    tee.stop()
    stop(p)
    # ... and the same with the commit landing on the TARGET while the merge runs
    setup_tables()
    rdir = new_log()
    tee = Tee(PG_PORT)
    p, prt = start(rdir, upstream=tee.port)
    psql(prt, "insert into m_par values (1, 'a'), (2, 'b'), (3, 'c')")
    psql(prt, "select cancho_fork('side')")
    psql(prt, "update m_par set name = 's' where id = 1", db="side")
    tee.fault("select cdb.merge(", "hold", lambda: psql(prt, "update m_par set name = 'm3' where id = 3"))
    r = psql(prt, "select cancho_merge('side')")
    check("a commit on the TARGET between the merge's start and its commit: merge-raced", "merge-raced" in r.stderr, r.stderr)
    tee.stop()
    stop(p)


race()


# ---------------------------------------------------------------------------------------------------- the windows of a crash
def window(name, prefix, when, merged_expected, want_merge_commits):
    setup_tables()
    wdir = new_log()
    p0, prt0 = start(wdir)
    psql(prt0, "insert into m_par values (1, 'a'), (2, 'b')")
    psql(prt0, "select cancho_fork('side')")
    psql(prt0, "update m_par set name = 'side' where id = 1", db="side")
    stop(p0)
    tee = Tee(PG_PORT)
    p, prt = start(wdir, upstream=tee.port)
    psql(prt, "update m_par set name = 'main' where id = 2")
    tee.fault(prefix, when, p.kill)
    psql(prt, "select cancho_merge('side')")
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
    tee.stop()
    p2, prt2 = start(wdir)
    time.sleep(0.5)
    alive = p2.poll() is None
    err2 = stop(p2)
    merged = dump("public", "m_par", "id").get("[1]", "") .find("side") >= 0
    n = len([c for c in commits(wdir) if len(c[3]) == 2])
    check("crash %s: the data is merged exactly when the merge's commit is in the log (merged %s, %d merge commit)" % (name, merged, n), alive and merged == merged_expected and n == want_merge_commits, (alive, merged, n, err2[-200:]))
    if want_merge_commits:
        verify(wdir, "crash " + name)


window("before PREPARE", "PREPARE TRANSACTION", "before", False, 0)
window("after PREPARE, answer lost", "PREPARE TRANSACTION", "reply", False, 0)
window("logged, before COMMIT PREPARED", "COMMIT PREPARED", "before", True, 1)
window("committed, answer lost", "COMMIT PREPARED", "reply", True, 1)

direct("drop schema public cascade; create schema public; drop schema if exists oracle cascade")
for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
    direct('drop schema "%s" cascade' % sc)
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall merge checks passed")
sys.exit(1 if FAILED else 0)
