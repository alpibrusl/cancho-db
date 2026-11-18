#!/usr/bin/env python3
"""sql/capture.sql against a snapshot diff (docs/m2-branches.md D5, D6).

    PG_E2E_PORT=5532 python3 tests/capture_check.py

For each transaction, the facts `cdb.facts(txid_current())` says it made are compared with the facts a diff of the table before and after gives, built here from the jsonb text
of every row alone (the row hash, the key, the order, the kind), so the triggers, the net-effect rule and the SQL ordering are each checked by an oracle that does not read them. Then:

  * rolled-back work leaves no delta row; a table without a primary key is refused by cdb.track;
  * the same facts give the same `changes` in tools/state.py (the format of cdb.facts is the one the Python reference reads);
  * 300 random transactions (inserts, updates, key changes, deletes, in any order, on tables with an integer, a composite and a text key) all match.
"""
import hashlib
import os
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import state as ref  # noqa: E402

PORT = os.environ.get("PG_E2E_PORT", "5532")
DB = os.environ.get("CAPTURE_DB", "capture_check")
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:600]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def psql(sql, db=DB, file=None):
    args = ["psql", "-h", "127.0.0.1", "-p", PORT, "-U", "postgres", "-d", db, "-At", "-q", "-v", "ON_ERROR_STOP=1"]
    args += ["-f", file] if file else ["-c", sql]
    return subprocess.run(args, capture_output=True, text=True, timeout=300)


def sh(b): return hashlib.sha256(b).digest()


def snapshot(lines):
    out = {}
    for line in lines:
        if "\t" not in line:
            continue
        pk, row = line.split("\t", 1)
        out[pk] = row
    return out


def expected_facts(table, before, after):
    facts = []
    for pk in set(before) | set(after):
        o, n = before.get(pk), after.get(pk)
        if o == n:
            continue
        oh = sh(b"cancho-db/row/v1\x00" + o.encode()) if o is not None else None
        nh = sh(b"cancho-db/row/v1\x00" + n.encode()) if n is not None else None
        kind = 0 if o is None else 2 if n is None else 1
        facts.append((table.encode(), pk.encode(), kind, oh, nh))
    facts.sort(key=lambda f: (f[0], f[1]))
    return " ".join("%d:%s:%s:%s:%s" % (k, t.hex(), p.hex(), "-" if o is None else o.hex(), "-" if n is None else n.hex()) for t, p, k, o, n in facts)


def run_tx(table, pkexpr, tx_sql, commit=True):
    """Run tx_sql in one transaction on `table`; returns (facts text from the SQL, expected from the diff)."""
    snap = "select (%s)::text || E'\\t' || to_jsonb(t)::text from %s t order by 1;" % (pkexpr, table)
    script = "\\echo @@BEFORE\n%s\nbegin;\n%s\n\\echo @@FACTS\nselect cdb.facts(txid_current());\n%s\n\\echo @@AFTER\n%s\n" % (snap, tx_sql, "commit;" if commit else "rollback;", snap)
    path = Path("/tmp/capture_check_%d.sql" % os.getpid())
    path.write_text(script)
    r = psql(None, file=str(path))
    if r.returncode != 0:
        return None, r.stderr
    parts = r.stdout.split("@@FACTS\n")
    before = parts[0].split("@@BEFORE\n")[1].splitlines()
    facts, after = parts[1].split("@@AFTER\n")
    return facts.strip(), expected_facts(table, snapshot(before), snapshot(after.splitlines()))


psql("drop database if exists %s" % DB, db="postgres")
psql("create database %s" % DB, db="postgres")
r = psql(None, file=str(ROOT / "sql/capture.sql"))
check("sql/capture.sql installs", r.returncode == 0, r.stderr)

setup = """
create table acc(id int primary key, owner text, bal numeric, note jsonb);
create table lin(a int, b text, v int, primary key (a, b));
create table txt(k text primary key, v int);
alter event trigger cdb_ddl disable;
create table nopk(x int);
alter event trigger cdb_ddl enable;
insert into acc select g, 'o' || g, g * 1.5, jsonb_build_object('n', g) from generate_series(1, 20) g;
insert into lin select g % 4, 'b' || g, g from generate_series(1, 12) g;
insert into txt values ('alpha', 1), ('Beta', 2), ('é', 3), ('', 4);
"""
r = psql(setup)
check("the test tables are made", r.returncode == 0, r.stderr)
r = psql("select cdb.track('nopk')")
check("cdb.track refuses a table without a primary key", r.returncode != 0 and "has no primary key" in r.stderr, r.stderr)
r = psql("select cdb.track('acc'), cdb.track('lin'), cdb.track('txt')")
check("the three tables are tracked", r.returncode == 0, r.stderr)

PK = {"acc": "jsonb_build_array(t.id)", "lin": "jsonb_build_array(t.a, t.b)", "txt": "jsonb_build_array(t.k)"}
scen = [
    ("an insert", "acc", "insert into acc values (100, 'new', 1, '{}');"),
    ("an update", "acc", "update acc set bal = bal + 1 where id = 3;"),
    ("a delete", "acc", "delete from acc where id = 4;"),
    ("an insert then an update of it: one insert of the last image", "acc", "insert into acc values (101, 'x', 1, '{}'); update acc set owner = 'y' where id = 101;"),
    ("an insert then a delete: no fact", "acc", "insert into acc values (102, 'x', 1, '{}'); delete from acc where id = 102;"),
    ("an update then its undoing: no fact", "acc", "update acc set bal = bal + 5 where id = 5; update acc set bal = bal - 5 where id = 5;"),
    ("an update then a delete: a delete of the first image", "acc", "update acc set owner = 'zz' where id = 6; delete from acc where id = 6;"),
    ("a delete then an insert of the same key: an update", "acc", "delete from acc where id = 7; insert into acc values (7, 'back', 0, '{}');"),
    ("a key change: a delete and an insert", "acc", "update acc set id = 200 where id = 8;"),
    ("a swap of two keys (through a third): two updates", "acc", "update acc set id = 900 where id = 9; update acc set id = 9 where id = 10; update acc set id = 10 where id = 900;"),
    ("an update that changes nothing: no fact", "acc", "update acc set owner = owner where id = 11;"),
    ("a bulk update", "acc", "update acc set bal = bal * 2 where id > 12;"),
    ("mixed statements in one transaction", "acc", "insert into acc values (300,'m',1,'{}'); update acc set owner='m2' where id=300; delete from acc where id = 13; update acc set bal=0 where id=14;"),
    ("a composite key: update, insert, delete", "lin", "update lin set v = v + 100 where a = 1; insert into lin values (9, 'z', 1); delete from lin where a = 2 and b = 'b2';"),
    ("a composite key change", "lin", "update lin set b = 'moved' where a = 3 and b = 'b3';"),
    ("a text key with a non-ASCII value and the empty string", "txt", "update txt set v = v + 1; insert into txt values ('ü', 9);"),
    ("nothing at all", "acc", "select 1;"),
]
for name, table, tx in scen:
    facts, want = run_tx(table, PK[table], tx)
    check("%s: the facts are those of the snapshot diff" % name, facts is not None and facts == want, (facts, want))
    if facts:
        ok = ref.run("C " + facts).startswith("ok ")
        check("... and tools/state.py takes them (the format is the reference's)", ok, ref.run("C " + facts))

# the event trigger: a table made in `public` is tracked in the same transaction; a keyless or partitioned one is refused; untrackable() names what is there
r = psql("create table ev_nokey (x int)")
check("the event trigger refuses a table without a primary key", r.returncode != 0 and "has no primary key" in r.stderr and psql("select count(*) from pg_class where relname = 'ev_nokey'").stdout.strip() == "0", r.stderr)
r = psql("create table ev_ctas as select 1 as a")
check("... also a CREATE TABLE AS", r.returncode != 0 and "has no primary key" in r.stderr, r.stderr)
r = psql("begin; create table ev_ok (id int primary key, v text); insert into ev_ok values (1, 'a'), (2, 'b'); update ev_ok set v = 'c' where id = 1; select cdb.facts(txid_current()); commit;")
facts = [l for l in r.stdout.splitlines() if l.startswith("0:")]
check("a table made in the transaction is tracked in the transaction: two net facts, both inserts (the update folded into the first)", r.returncode == 0 and len(facts) == 1 and len(facts[0].split()) == 2 and all(f.startswith("0:") for f in facts[0].split()), r.stdout + r.stderr)
r = psql("alter table ev_ok drop constraint ev_ok_pkey")
check("dropping the primary key of a tracked table is refused", r.returncode != 0 and "has no primary key" in r.stderr, r.stderr)
r = psql("alter table ev_ok add column w int")
check("an ALTER that keeps the key is fine", r.returncode == 0, r.stderr)
psql("alter event trigger cdb_ddl disable; create table ev_k (x int); create table ev_p (id int primary key) partition by range (id); alter event trigger cdb_ddl enable;")
u = psql("select cdb.untrackable()").stdout.strip()
check("cdb.untrackable() names the keyless and the partitioned tables, and only those (nopk is the test's own)", u == "ev_k (no primary key), ev_p (partitioned), nopk (no primary key)", u)
r = psql("create table ev_p1 partition of ev_p for values from (0) to (10)")
check("a partition cannot be made while the trigger is on (0A000)", r.returncode != 0 and "partitioned tables are not supported" in r.stderr, r.stderr)
psql("drop table ev_k, ev_p, ev_ok, nopk")
check("... and untrackable() is empty again", psql("select cdb.untrackable()").stdout.strip() == "")

# rollback leaves nothing
before_n = int(psql("select count(*) from cdb.delta").stdout)
facts, want = run_tx("acc", PK["acc"], "insert into acc values (900, 'r', 1, '{}'); update acc set bal = 0 where id = 1;", commit=False)
after_n = int(psql("select count(*) from cdb.delta").stdout)
check("a rolled-back transaction leaves no delta row (the SQL saw %d facts inside it)" % len(facts.split()), after_n == before_n and want == "", (before_n, after_n, want))

# random transactions
rnd = random.Random(11)
def rtx():
    ops = []
    for _ in range(rnd.randrange(1, 6)):
        t = rnd.choice(["acc", "lin", "txt"])
        k = rnd.randrange(3)
        if t == "acc":
            i = rnd.randrange(1, 40)
            ops.append((t, ["insert into acc values (%d, 'r', %d, '{}') on conflict do nothing;" % (i, rnd.randrange(5)),
                            "update acc set bal = %d, owner = 'u%d' where id = %d;" % (rnd.randrange(5), rnd.randrange(3), i),
                            "delete from acc where id = %d;" % i][k]))
            if rnd.random() < 0.1:
                ops.append((t, "update acc set id = id + 50 where id = %d and not exists (select 1 from acc where id = %d);" % (i, i + 50)))
        elif t == "lin":
            a, b = rnd.randrange(5), "b%d" % rnd.randrange(8)
            ops.append((t, ["insert into lin values (%d, '%s', %d) on conflict do nothing;" % (a, b, rnd.randrange(5)),
                            "update lin set v = %d where a = %d and b = '%s';" % (rnd.randrange(5), a, b),
                            "delete from lin where a = %d and b = '%s';" % (a, b)][k]))
        else:
            kk = rnd.choice(["alpha", "Beta", "é", "", "k1", "k2"])
            ops.append((t, ["insert into txt values ('%s', %d) on conflict do nothing;" % (kk, rnd.randrange(5)),
                            "update txt set v = %d where k = '%s';" % (rnd.randrange(5), kk),
                            "delete from txt where k = '%s';" % kk][k]))
    return ops

bad = []
for n in range(300):
    ops = rtx()
    # the oracle diffs one table; a transaction over several tables is checked table by table with the same transaction
    tables = sorted({t for t, _ in ops})
    snaps = "".join("\\echo @@BEFORE %s\nselect (%s)::text || E'\\t' || to_jsonb(t)::text from %s t order by 1;\n" % (t, PK[t], t) for t in tables)
    after = "".join("\\echo @@AFTER %s\nselect (%s)::text || E'\\t' || to_jsonb(t)::text from %s t order by 1;\n" % (t, PK[t], t) for t in tables)
    script = snaps + "begin;\n" + "\n".join(s for _, s in ops) + "\n\\echo @@FACTS\nselect cdb.facts(txid_current());\ncommit;\n" + after
    p = Path("/tmp/capture_check_r_%d.sql" % os.getpid())
    p.write_text(script)
    r = psql(None, file=str(p))
    if r.returncode != 0:
        bad.append((n, r.stderr[:200]))
        continue
    text = r.stdout
    got = text.split("@@FACTS\n")[1].split("\n", 1)[0].strip()
    def section(tag, t):
        seg = text.split("@@%s %s\n" % (tag, t))[1]
        seg = seg.split("@@")[0]
        return snapshot([l for l in seg.splitlines() if "\t" in l])
    want_parts = []
    for t in tables:
        w = expected_facts(t, section("BEFORE", t), section("AFTER", t))
        if w:
            want_parts.append(w)
    # all tables together, in (table, key) order
    allf = sorted(" ".join(want_parts).split(), key=lambda f: (bytes.fromhex(f.split(":")[1]), bytes.fromhex(f.split(":")[2])))
    if got.split() != allf:
        bad.append((n, got[:120], " ".join(allf)[:120], ops))
check("300 random transactions over three tables: the SQL's facts are the snapshot diff's, every time", not bad, bad[:2])

# ---- cdb.fork (docs/m2-branches.md D2, D24, D26): a copy that is a base and not a change
FDB = DB + "_fork"
psql("drop database if exists %s" % FDB, db="postgres")
psql("create database %s" % FDB, db="postgres")
r = psql(None, db=FDB, file=str(ROOT / "sql/capture.sql"))
check("fork: sql/capture.sql installs in a fresh database", r.returncode == 0, r.stderr)
fixture = """
create table par(id int primary key, name text);
create table kid(id int generated always as identity primary key, par_id int references par(id) on delete cascade, v text default 'd');
create table ser(id serial primary key, w int);
create table gen(a int primary key, b int generated always as (a * 2) stored);
create index kid_v on kid (v);
insert into par select g, 'p' || g from generate_series(1, 5) g;
insert into kid(par_id, v) select 1 + g % 5, 'v' || g from generate_series(1, 12) g;
insert into ser(w) values (1), (2);
insert into gen(a) values (1), (2), (3);
"""
r = psql(fixture, db=FDB)
check("fork: the fixture is made", r.returncode == 0, r.stderr)
r = psql("begin; select cdb.fork('public', 'cdb_b_x'); select 'FACTS[' || cdb.facts(txid_current()) || ']'; commit;", db=FDB)
check("fork: copies four tables and the transaction records no facts", r.returncode == 0 and r.stdout.split() == ["4", "FACTS[]"], (r.stdout, r.stderr))
check("fork: the copy has no delta rows at all", psql("select count(*) from cdb.delta where sch <> 'public'", db=FDB).stdout.strip() == "0")


def dump(schema):
    parts = []
    for t, order in [("par", "id"), ("kid", "id"), ("ser", "id"), ("gen", "a")]:
        parts.append(psql("select coalesce(string_agg(to_jsonb(x)::text, ' ' order by %s), '') from %s.%s x" % (order, schema, t), db=FDB).stdout.strip())
    return parts


check("fork: every table of the copy holds the rows of the source, generated column included", dump("cdb_b_x") == dump("public") and all(dump("public")), dump("cdb_b_x"))
r = psql("select count(*) from pg_constraint c join pg_class t on t.oid = c.conrelid join pg_class f on f.oid = c.confrelid join pg_namespace n on n.oid = t.relnamespace join pg_namespace m on m.oid = f.relnamespace "
         "where c.contype = 'f' and n.nspname = 'cdb_b_x' and m.nspname = 'cdb_b_x'", db=FDB)
check("fork: the foreign key is in the copy and points at the copy", r.stdout.strip() == "1", r.stdout + r.stderr)
r = psql("insert into cdb_b_x.kid(par_id) values (99)", db=FDB)
check("fork: ... and is enforced there", r.returncode != 0 and "violates foreign key" in r.stderr, r.stderr)
r = psql("begin; insert into cdb_b_x.kid(par_id) values (2) returning id; select cdb.facts(txid_current()); commit;", db=FDB)
check("fork: an identity column goes on past the copied rows (13, the failed insert above took one: 14), the write is a fact", r.returncode == 0 and r.stdout.split("\n")[0] == "14" and r.stdout.count(":") == 4 and len(r.stdout.split("\n")[1].split()) == 1, r.stdout + r.stderr)
check("fork: its delta row says which schema it was in", psql("select string_agg(sch || '.' || tbl, ',') from cdb.delta where sch <> 'public'", db=FDB).stdout.strip() == "cdb_b_x.kid", psql("select string_agg(sch || '.' || tbl, ',') from cdb.delta where sch <> 'public'", db=FDB).stdout)
check("fork: a write in the branch is not in the source, and one in the source is not in the branch",
      psql("select count(*) from public.kid", db=FDB).stdout.strip() == "12" and psql("insert into public.kid(par_id) values (3); select count(*) from cdb_b_x.kid", db=FDB).stdout.split()[-1] == "13")
r = psql("create table cdb_b_x.later(a int, b int)", db=FDB)
check("fork: a keyless table made in the branch is refused, as in the first", r.returncode != 0 and "has no primary key" in r.stderr, r.stderr)
r = psql("begin; create table cdb_b_x.later(a int primary key); insert into cdb_b_x.later values (1); select cdb.facts(txid_current()); commit;", db=FDB)
check("fork: a table made in the branch is tracked at once", r.returncode == 0 and r.stdout.count(":") == 4, r.stdout + r.stderr)
r = psql("begin; select cdb.fork('cdb_b_x', 'cdb_b_y'); select cdb.facts(txid_current()); commit;", db=FDB)
check("fork: a branch forks too, and the copy has the branch's own rows", r.returncode == 0 and psql("select count(*) from cdb_b_y.kid", db=FDB).stdout.strip() == "13" and r.stdout.split()[0] == "5", (r.stdout, r.stderr))
r = psql("begin; select cdb.fork('public', 'cdb_b_z'); rollback; select count(*) from pg_namespace where nspname = 'cdb_b_z'", db=FDB)
check("fork: a rolled-back fork leaves no schema", r.returncode == 0 and r.stdout.split()[-1] == "0", r.stdout + r.stderr)
r = psql("select cdb.fork('public', 'cdb_b_x')", db=FDB)
check("fork: a name that is taken is refused", r.returncode != 0 and "already exists" in r.stderr, r.stderr)
r = psql("alter event trigger cdb_ddl disable; create table cdb_b_x.nopk2(x int); alter event trigger cdb_ddl enable; select cdb.untrackable()", db=FDB)
check("fork: untrackable() names a keyless table of a branch, with its schema", r.stdout.strip().endswith("cdb_b_x.nopk2 (no primary key)"), r.stdout + r.stderr)
psql("drop table cdb_b_x.nopk2", db=FDB)
check("fork: untrackable() and track_all() see the branches' tables", psql("select cdb.untrackable()", db=FDB).stdout.strip() == "" and psql("select cdb.track_all()", db=FDB).stdout.strip() == "14", psql("select cdb.track_all()", db=FDB).stdout)
psql("drop database if exists %s" % FDB, db="postgres")

psql("drop database if exists %s" % DB, db="postgres")
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall capture checks passed")
sys.exit(1 if FAILED else 0)
