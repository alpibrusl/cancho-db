#!/usr/bin/env python3
"""cdb.merge (docs/m2-branches.md D34 to D36, D41) against a Python reference of the same rule, in a real PostgreSQL.

    PG_E2E_PORT=5532 python3 tests/merge_check.py

Each trial makes three small tables (a parent, a child that references it, a composite-key table), loads a base, forks it (`cdb.fork`), lets the two branches change independently by random statements (a statement
PostgreSQL refuses is skipped), and stamps each side's commits as the proxy does (a mark and the place in the log). The reference is written here from D34: per key, source unchanged from the base keeps the target's row, target
unchanged and source changed takes the source's, equal images do nothing, anything else is a conflict; then the foreign key from child to parent is checked on the result. The database must agree:

  * a conflict: the error names `merge-conflict`, the target is exactly as it was and the transaction left no delta row;
  * a merge that would break the foreign key: `merge-constraint`, the same;
  * otherwise the target equals the reference's result, row for row, and the facts of the merging transaction are those of a diff of the target before and after (so the capture sees a merge as it sees any writes).

Then the refusals that are not about data: tables that differ, a table made after the base, a merge into itself (no change).
"""
import json
import os
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import hashlib  # noqa: E402

PORT = os.environ.get("PG_E2E_PORT", "5532")
DB = os.environ.get("MERGE_DB", "merge_check")
FAILED = []
TABLES = [("m_par", "id"), ("m_kid", "id"), ("m_c", "x, y")]


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok", name, "") if ok else "FAIL %s   %s" % (name, str(detail)[:700]))
    if not ok:
        FAILED.append(name)


def psql(sql, db=DB, file=None, stop=True):
    args = ["psql", "-h", "127.0.0.1", "-p", PORT, "-U", "postgres", "-d", db, "-At", "-q"] + (["-v", "ON_ERROR_STOP=1"] if stop else [])
    args += ["-f", file] if file else ["-c", sql]
    return subprocess.run(args, capture_output=True, text=True, timeout=300)


def sh(b): return hashlib.sha256(b).digest()


def dump(schema, table, key):
    """{key text: row jsonb text} of one table: the images the capture hashes."""
    # the row alias is `rr`, not `x`: a bare `x` is the COLUMN x in a table that has one (m_c does), and the images compared would be that column's
    r = psql("select jsonb_build_array(%s)::text || E'\\t' || to_jsonb(rr)::text from %s.%s rr" % (", ".join("rr." + c.strip() for c in key.split(",")), schema, table))
    out = {}
    for line in r.stdout.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            out[k] = v
    return out


def reference(base, t, s):
    """D34 over three dicts: (conflicting keys, merged dict)."""
    conflicts, merged = [], dict(t)
    for k in set(base) | set(t) | set(s):
        b, tv, sv = base.get(k), t.get(k), s.get(k)
        if sv == b:
            continue                      # the source left it: the target's row stays
        if tv == b:
            if sv is None:
                merged.pop(k, None)
            else:
                merged[k] = sv
        elif tv != sv:
            conflicts.append(k)
    return conflicts, merged


def fk_ok(par, kid):
    ids = {json.loads(v)["id"] for v in par.values()}
    return all(json.loads(v)["par"] in ids for v in kid.values())


def setup(base_ord_rows=14):
    psql("drop schema if exists public cascade; create schema public; drop schema if exists cdb_b_s cascade; drop schema if exists oracle cascade; create schema oracle; delete from cdb.delta; delete from cdb.mark; delete from cdb.cur")
    psql("create table m_par (id int primary key, name text); create table m_kid (id int primary key, par int references m_par(id), v text); create table m_c (x int, y text, w int, primary key (x, y))")


def stamp(sch, ord_):
    h = "%064x" % ord_
    psql("with m as (insert into cdb.mark(commit_id, sch, ord) values (decode('%s', 'hex'), '%s', %d)) update cdb.delta set commit_id = decode('%s', 'hex'), ord = %d where ord is null and commit_id is null and sch = '%s'" % (h, sch, ord_, h, ord_, sch))


def ops(rnd, side, n):
    """Random statements for one side: its own new ids are in its own range, and some ids are shared so that both sides touch the same rows."""
    base_id = 100 if side == "t" else 200
    out = []
    for i in range(n):
        k = rnd.randrange(8)
        pid = rnd.choice([1, 2, 3, 4, 5, 6, 7, 8])
        shared = rnd.choice([50, 51, 52])
        if k == 0:
            out.append("update m_par set name = 'n%s%d' where id = %d" % (side, rnd.randrange(3), pid))
        elif k == 1:
            out.append("insert into m_par values (%d, 'p%s%d')" % (rnd.choice([base_id + rnd.randrange(5), shared]), side, rnd.randrange(3)))
        elif k == 2:
            out.append("delete from m_par where id = %d" % pid)
        elif k == 3:
            out.append("insert into m_kid select %d, id, 'k%s' from m_par where id = %d" % (rnd.choice([base_id + rnd.randrange(5), shared]), side, pid))
        elif k == 4:
            out.append("update m_kid set v = 'v%s%d' where id = %d" % (side, rnd.randrange(3), rnd.randrange(1, 9)))
        elif k == 5:
            out.append("delete from m_kid where id = %d" % rnd.randrange(1, 9))
        elif k == 6:
            out.append("insert into m_c values (%d, 'k%d', %d) on conflict (x, y) do update set w = excluded.w" % (rnd.randrange(1, 4), rnd.randrange(1, 4), rnd.randrange(3)))
        else:
            out.append("%s from m_c where x = %d" % (rnd.choice(["delete", "delete", "update m_c set w = w + 1 where x = %d" % rnd.randrange(1, 4) + " --"]), rnd.randrange(1, 4)) if False else "delete from m_c where x = %d and y = 'k%d'" % (rnd.randrange(1, 4), rnd.randrange(1, 4)))
    return out


def run_side(statements, schema_search):
    # one script, a statement the database refuses is skipped (each is its own transaction)
    sql = "set search_path = %s;\n" % schema_search + ";\n".join(statements) + ";\n"
    psql(None, file=_write(sql), stop=False)


_n = [0]


def _write(text):
    _n[0] += 1
    p = Path("/tmp") / ("merge_check_%d_%d.sql" % (os.getpid(), _n[0]))
    p.write_text(text)
    return str(p)


def dump_full(schema, table, key):
    """{commitment: (row jsonb text, row salt)}: the rows with the salts the capture gave them (cdb.cur); the hash and the commitment are worked out here (docs/spec/l3a.md section 9)."""
    kx = "jsonb_build_array(%s)" % ", ".join("rr." + c.strip() for c in key.split(","))
    r = psql("select (%s)::text || E'\\t' || to_jsonb(rr)::text || E'\\t' || encode(c.salt, 'hex') || E'\\t' || encode(c.key_salt, 'hex') from %s.%s rr join cdb.cur c on c.sch = '%s' and c.tbl = '%s' and c.pk = convert_to((%s)::text, 'UTF8')"
             % (kx, schema, table, schema, table, kx))
    out = {}
    for line in r.stdout.splitlines():
        if "\t" in line:
            k, v, sa, ks = line.split("\t")
            out[sh(b"cancho-db/key/v1\x00" + bytes.fromhex(ks) + k.encode())] = (v, bytes.fromhex(sa))
    return out


def full_of(schema):
    return {t: dump_full(schema, t, key) for t, key in TABLES}


def facts_of_diff(before, after):
    """The facts of the merge from the rows and salts before and after it (a salt is the capture's, a hash is worked out here)."""
    out = []
    for tname, key in TABLES:
        for kc in set(before[tname]) | set(after[tname]):
            o, n = before[tname].get(kc), after[tname].get(kc)
            oh = sh(b"cancho-db/row/v2\x00" + o[1] + o[0].encode()) if o is not None else None
            nh = sh(b"cancho-db/row/v2\x00" + n[1] + n[0].encode()) if n is not None else None
            if oh == nh:
                continue
            kind = 0 if o is None else 2 if n is None else 1
            out.append("%d:%s:%s:%s:%s" % (kind, tname.encode().hex(), kc.hex(), oh.hex() if oh else "-", nh.hex() if nh else "-"))
    return sorted(out, key=lambda f: (bytes.fromhex(f.split(":")[1]), bytes.fromhex(f.split(":")[2])))


def state_of(schema):
    return {t: dump(schema, t, key) for t, key in TABLES}


psql("drop database if exists %s" % DB, db="postgres")
psql("create database %s" % DB, db="postgres")
r = psql(None, file=str(ROOT / "sql/capture.sql"))
check("sql/capture.sql installs", r.returncode == 0, r.stderr)

rnd = random.Random(5)
stats = {"conflict": 0, "constraint": 0, "merged": 0, "empty": 0}
bad = []
TRIALS = int(os.environ.get("MERGE_TRIALS", "60"))


def trial(n, t_ops, s_ops, expect=None):
    """One trial: a fresh base, a fork, the two sides' statements, the merge, and the reference's verdict against the database's. `expect` pins the outcome a scenario is for."""
    setup()
    psql("insert into m_par select g, 'p' || g from generate_series(1, 8) g; insert into m_kid select g, 1 + g % 8, 'k' from generate_series(1, 8) g; insert into m_c select g % 3 + 1, 'k' || (g % 3 + 1), g from generate_series(1, 9) g on conflict do nothing")
    stamp("public", 0)
    r = psql("select cdb.fork('public', 'cdb_b_s')")
    if r.returncode != 0:
        bad.append((n, "fork", r.stderr))
        return
    base = state_of("public")
    run_side(t_ops, "public")
    stamp("public", 2)
    run_side(s_ops, "cdb_b_s")
    stamp("cdb_b_s", 3)
    t_state, s_state = state_of("public"), state_of("cdb_b_s")
    t_full = full_of("public")
    conflicts, merged = [], {}
    for tname, _ in TABLES:
        c, m = reference(base[tname], t_state[tname], s_state[tname])
        conflicts += [(tname, k) for k in c]
        merged[tname] = m
    fk = fk_ok(merged["m_par"], merged["m_kid"])
    before_delta = psql("select count(*) from cdb.delta").stdout.strip()
    r = psql("begin; select cdb.merge('public', 'cdb_b_s', 'public', 0); select 'FACTS[' || cdb.facts(txid_current()) || ']'; commit")
    after = state_of("public")
    after_full = full_of("public")
    if conflicts:
        outcome = "conflict"
        ok = r.returncode != 0 and "merge-conflict" in r.stderr and after == t_state and psql("select count(*) from cdb.delta").stdout.strip() == before_delta and conflicts[0][0] + " " in r.stderr
    elif not fk:
        outcome = "constraint"
        ok = r.returncode != 0 and "merge-constraint" in r.stderr and after == t_state and psql("select count(*) from cdb.delta").stdout.strip() == before_delta
    else:
        outcome = "merged"
        want_facts = facts_of_diff(t_full, after_full)
        got_facts = []
        for line in r.stdout.splitlines():
            if line.startswith("FACTS["):
                got_facts = line[len("FACTS["):-1].split()
        ok = r.returncode == 0 and after == merged and got_facts == want_facts
        if not want_facts:
            stats["empty"] += 1
    stats[outcome] += 1
    if expect and outcome != expect:
        ok = False
    if not ok:
        bad.append((n, "%s conflicts=%s fk=%s" % (outcome, conflicts[:3], fk), r.stderr.strip()[:200], [(t, len(after[t]), len(merged[t])) for t, _ in TABLES]))


for n in range(TRIALS):
    trial(n, ops(rnd, "t", rnd.randrange(0, 9)), ops(rnd, "s", rnd.randrange(0, 9)))
# scenarios that pin an outcome: the source deletes a parent (and its child), the target meanwhile adds a child of it: the result would break the key
for n, p_id in enumerate((3, 5, 8)):
    trial("fk-%d" % n, ["insert into m_kid values (150, %d, 'late')" % p_id], ["delete from m_kid where par = %d" % p_id, "delete from m_par where id = %d" % p_id], expect="constraint")
# ... and one that needs the order: the source adds a parent and its child, and removes another parent with its child; the target changes other rows
trial("order", ["update m_par set name = 'tt' where id = 1", "update m_c set w = 99 where x = 1"],
      ["insert into m_par values (120, 'new')", "insert into m_kid values (121, 120, 'newkid')", "delete from m_kid where par = 4", "delete from m_par where id = 4"], expect="merged")
# both sides change the same rows to the same images (and delete the same row): nothing to apply for those, and no conflict
trial("same", ["update m_c set w = 77 where x = 1", "delete from m_kid where id = 2", "update m_par set name = 'both' where id = 6"],
      ["update m_c set w = 77 where x = 1", "delete from m_kid where id = 2", "update m_par set name = 'both' where id = 6", "update m_par set name = 'only-s' where id = 7"], expect="merged")
check("%d trials and 5 scenarios: %d conflicts refused, %d foreign-key breaks refused, %d merges applied (%d of them changing nothing); each as the reference says, the target untouched when refused, the facts those of a diff" %
      (TRIALS, stats["conflict"], stats["constraint"], stats["merged"], stats["empty"]), not bad, bad[:2])
check("the trials cover all three outcomes", stats["conflict"] > 5 and stats["constraint"] >= 3 and stats["merged"] - stats["empty"] > 10, stats)

# ---- schemas that do not match
setup()
psql("insert into m_par values (1, 'a')")
stamp("public", 0)
psql("select cdb.fork('public', 'cdb_b_s')")
psql("alter table cdb_b_s.m_c add column extra int")
r = psql("select cdb.merge('public', 'cdb_b_s', 'public', 0)")
check("a table with other columns on the two sides: merge-schema-differs", r.returncode != 0 and "merge-schema-differs" in r.stderr, r.stderr)
psql("alter table cdb_b_s.m_c drop column extra; create table cdb_b_s.m_new (a int primary key)")
r = psql("select cdb.merge('public', 'cdb_b_s', 'public', 0)")
check("a table only the source has: merge-schema-differs", r.returncode != 0 and "merge-schema-differs" in r.stderr, r.stderr)
psql("drop table cdb_b_s.m_new")
r = psql("select cdb.merge('public', 'cdb_b_s', 'public', 0)")
check("the same tables and nothing changed: a merge that applies nothing", r.returncode == 0 and r.stdout.strip() == "0", r.stdout + r.stderr)
r = psql("select cdb.merge('public', 'public', 'public', 0)")
check("a merge of a branch into itself applies nothing", r.returncode == 0 and r.stdout.strip() == "0", r.stdout + r.stderr)

psql("drop database if exists %s" % DB, db="postgres")
for p in Path("/tmp").glob("merge_check_%d_*.sql" % os.getpid()):
    p.unlink()
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall merge checks passed")
sys.exit(1 if FAILED else 0)
