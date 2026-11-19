#!/usr/bin/env python3
"""cdb.erase (docs/m2g-erasure.md D-E3, D-E6) against a database: a subject's rows are gone from the tables, from every delta row and from cdb.cur, in the schema it is run in; the facts
of the erasing transaction are still there and the others' rows are untouched; a branch made before holds its own copy and is named.

    PG_E2E_PORT=5532 python3 tests/erase_check.py

The scan is the one that matters: a planted value (a name, a phone number, an e-mail) is searched for in the text of every row of every table the capture keeps, with the table's own `::text`, before and after.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = os.environ.get("PG_E2E_PORT", "5532")
DB = os.environ.get("ERASE_DB", "erase_check")
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:500]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def psql(sql, db=DB, file=None):
    args = ["psql", "-h", "127.0.0.1", "-p", PORT, "-U", "postgres", "-d", db, "-At", "-q", "-v", "ON_ERROR_STOP=1"]
    args += ["-f", file] if file else ["-c", sql]
    return subprocess.run(args, capture_output=True, text=True, timeout=300)


def holders(needle, where=None):
    """How many rows of the capture's own tables mention `needle` anywhere in their text (cdb.delta, cdb.cur, the tracked tables). `where` restricts it to the table `people` of one schema: its rows, its delta rows and its cur rows."""
    n = 0
    tables = ("cdb.delta", "cdb.cur", "public.people", "cdb_b_side.people", "public.notes") if where is None else ("cdb.delta", "cdb.cur", where + ".people")
    for tbl in tables:
        cond = "t::text like '%%%s%%'" % needle
        if where is not None and tbl.startswith("cdb."):
            cond += " and t.sch = '%s' and t.tbl = 'people'" % where
        n += int(psql("select count(*) from %s t where %s" % (tbl, cond)).stdout.strip() or 0)
    return n


psql("drop database if exists %s" % DB, db="postgres")
psql("create database %s" % DB, db="postgres")
r = psql(None, file=str(ROOT / "sql/capture.sql"))
check("sql/capture.sql installs", r.returncode == 0, r.stderr)
r = psql("""
create table people (email text primary key, name text, phone text);
create table notes (id int primary key, owner text, body text);
insert into people values ('ana@example.org', 'Ana Quintero', '600111222'), ('luis@example.org', 'Luis Vega', '600333444'), ('eva@example.org', 'Eva Soto', '600555666');
insert into notes values (1, 'ana@example.org', 'a note'), (2, 'luis@example.org', 'another');
update people set phone = '611999888' where email = 'ana@example.org';
update people set name = 'Ana Quintero Ruiz' where email = 'ana@example.org';
""")
check("the fixture is made, through the capture", r.returncode == 0, r.stderr)
before = {n: holders(n) for n in ("Quintero", "611999888", "600111222", "ana@example.org", "Luis Vega")}
check("before: the subject's name, both phone numbers and e-mail are all over the capture's tables", all(before[n] > 0 for n in ("Quintero", "611999888", "600111222", "ana@example.org")), before)
r = psql("select cdb.fork('public', 'cdb_b_side')")
check("a branch is forked before the erasure", r.returncode == 0, r.stderr)

r = psql("begin; select cdb.erase('public', 'people', '[\"ana@example.org\"]'); select 'FACTS[' || cdb.facts(txid_current()) || ']'; commit;")
lines = r.stdout.strip().splitlines()
check("the erasure runs and says what it did, and that the branch still holds the key",
      r.returncode == 0 and lines and lines[0].startswith("erased: 1 row(s) deleted, ") and "still held in cdb_b_side" in lines[0], r.stdout + r.stderr)
facts = [l for l in lines if l.startswith("FACTS[")]
check("the erasing transaction has one net fact, a delete, with both hashes kept", facts and len(facts[0][6:-1].split()) == 1 and facts[0][6:-1].startswith("2:"), facts)
check("the subject's row is gone from the table", psql("select count(*) from public.people where email = 'ana@example.org'").stdout.strip() == "0")
check("the others' rows are still there", psql("select count(*) from public.people").stdout.strip() == "2")
gone = {n: holders(n, "public") for n in ("Quintero", "611999888", "600111222", "ana@example.org")}
check("after: nothing the capture keeps for the table `people` in `public` holds the subject's name, any of the phone numbers or the e-mail", all(v == 0 for v in gone.values()), gone)
branch = {n: holders(n, "cdb_b_side") for n in ("Quintero", "611999888", "600111222", "ana@example.org")}
check("... the branch made before holds its copy (the current name, phone and e-mail, not the old phone: the fork copied the rows, not the history)", branch == {"Quintero": 1, "611999888": 1, "600111222": 0, "ana@example.org": 1}, branch)
check("... the others' data in `public` is untouched", holders("Luis Vega", "public") == 2 and holders("600333444", "public") == 2, (holders("Luis Vega", "public"), holders("600333444", "public")))
check("erasure is by key: another table's column that names the subject (notes.owner) is the caller's to erase, and is still there", psql("select count(*) from public.notes where owner = 'ana@example.org'").stdout.strip() == "1")
r = psql("select count(*) from cdb.delta d where d.sch = 'public' and d.tbl = 'people' and d.kc is not null and d.pk is null and d.old_row is null and d.new_row is null and d.old_salt is null and d.new_salt is null and d.key_salt is null")
check("the subject's delta rows keep their key commitment and hashes and lose everything else", r.stdout.strip() == "4", r.stdout + r.stderr)
check("... the hashes are still there", psql("select count(*) from cdb.delta d where d.sch = 'public' and d.tbl = 'people' and d.pk is null and (d.old_hash is not null or d.new_hash is not null)").stdout.strip() == "4")
check("cdb.cur has no entry for the subject in public, and the others' are there", psql("select count(*) from cdb.cur where sch = 'public' and tbl = 'people'").stdout.strip() == "2")

# the branch erases its own copy
r = psql("begin; select cdb.erase('cdb_b_side', 'people', '[\"ana@example.org\"]'); commit;")
check("the same erasure in the branch removes its copy, and nothing is held elsewhere any more", r.returncode == 0 and "still held" not in r.stdout, r.stdout + r.stderr)
final = {n: holders(n) for n in ("Quintero", "611999888", "600111222")}
check("then the subject's name and phone numbers are held by nothing the capture keeps", all(v == 0 for v in final.values()), final)
r = psql("select cdb.erase('public', 'notes', '[1]')")
check("... and, with the notes row erased too, so is the e-mail", r.returncode == 0 and holders("ana@example.org") == 0, (r.stdout, holders("ana@example.org")))

# erasing a key that is not there, a table without a key, composite keys
r = psql("select cdb.erase('public', 'people', '[\"nobody@example.org\"]')")
check("a key that is not there: nothing deleted, nothing scrubbed", r.returncode == 0 and r.stdout.strip().startswith("erased: 0 row(s) deleted, 0 delta row(s) scrubbed"), r.stdout + r.stderr)
r = psql("select cdb.erase('public', 'nosuch', '[1]')")
check("an unknown table is refused", r.returncode != 0, r.stdout)
r = psql("select cdb.erase('public', 'people', 'not json')")
check("a key that is not json is refused", r.returncode != 0 and "json" in r.stderr, r.stderr)
psql("create table pairs (a int, b text, v text, primary key (a, b)); insert into pairs values (1, 'x', 'secret-one'), (1, 'y', 'keep'), (2, 'x', 'secret-two'); update pairs set v = 'secret-uno' where a = 1 and b = 'x'")
r = psql("select cdb.erase('public', 'pairs', '[1, \"x\"]')")
check("a composite key", r.returncode == 0 and r.stdout.startswith("erased: 1 row(s) deleted, 3 delta row(s) scrubbed"), r.stdout + r.stderr)
check("... its values are gone from the delta rows and the others' are not",
      psql("select count(*) from cdb.delta d where d::text like '%secret-one%' or d::text like '%secret-uno%'").stdout.strip() == "0" and psql("select count(*) from cdb.delta d where d::text like '%secret-two%'").stdout.strip() != "0")
r = psql("begin; select cdb.erase('public', 'people', '[\"luis@example.org\"]'); rollback;")
check("an erasure that is rolled back leaves everything as it was", psql("select count(*) from public.people where email = 'luis@example.org'").stdout.strip() == "1" and psql("select count(*) from cdb.delta where tbl = 'people' and pk is not null").stdout.strip() != "0")
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall erase checks passed")
sys.exit(1 if FAILED else 0)
