#!/usr/bin/env python3
"""The DDL parser against PostgreSQL itself: does the rendering do what the original does?
(docs/m1-lowering.md section 6, gate 2, for DDL)

    PG_E2E_PORT=5532 python3 tests/ddl_diff.py STMTCHECK_BINARY [CASES] [SEED]

DDL has no plan to compare, so both texts are RUN, each in a transaction that is rolled back, after the same small prelude,
and what they leave in the catalog is compared: the columns of the table (name, type with modifiers, NOT NULL, default
expression), its constraints (`pg_get_constraintdef`), and its indexes (`pg_indexes.indexdef`), plus whether the table and the
index still exist. Equal snapshots, or equal SQLSTATEs, for the original and for the rendering. As in the plan comparisons, an
accepted statement that PostgreSQL refuses as a syntax error is a failure.
"""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pgdiff  # noqa: E402

PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
CHECK = sys.argv[1]
CASES = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1
pgdiff.PORT = PORT

PRELUDE = "create table t (a int, b text); create index i0 on t (a)"
SNAPSHOT = """select
  coalesce((select string_agg(a.attname || ' ' || format_type(a.atttypid, a.atttypmod) || ' ' || a.attnotnull::text || ' ' ||
            coalesce(pg_get_expr(d.adbin, d.adrelid), '-'), '; ' order by a.attnum)
            from pg_attribute a left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
            where a.attrelid = to_regclass('t') and a.attnum > 0 and not a.attisdropped), 'no table') || ' | ' ||
  coalesce((select string_agg(conname || ' ' || contype::text || ' ' || pg_get_constraintdef(oid), '; ' order by conname)
            from pg_constraint where conrelid = to_regclass('t')), '-') || ' | ' ||
  coalesce((select string_agg(indexname || ' ' || indexdef, '; ' order by indexname)
            from pg_indexes where tablename = 't'), '-')"""

TYPES = ["int", "integer", "bigint", "smallint", "text", "boolean", "bool", "numeric", "numeric(10,2)", "numeric(5)", "decimal",
         "varchar", "varchar(20)", "date", "timestamp", "timestamptz", "real", "INT", "Text"]
DEFAULTS = ["1", "-5", "0", "'x'", "''", "'it''s'", "true", "false", "null", "1.5", ".5", "2.", "100000", "2147483648"]


def check(src):
    r = subprocess.run([CHECK], input=src.encode(), capture_output=True, timeout=30)
    out = r.stdout.decode().rstrip("\n")
    if r.returncode != 0 or not out:
        return ("crash", r.stderr.decode()[:100])
    if out.startswith("ok "):
        return ("ok", out[3:])
    return ("refused", out.split(" ", 1)[1])


def run_in_txn(pg, stmt):
    """-> ("snapshot", text) or ("error", sqlstate, is_syntax)"""
    pg.run("begin")
    try:
        _, err = pg.run(PRELUDE)
        if err:
            return ("error", "prelude " + err[0], False)
        _, err = pg.run(stmt)
        if err:
            return ("error", err[0], err[1].startswith("syntax error"))
        rows, err = pg.run(SNAPSHOT)
        if err:
            return ("error", "snapshot " + err[0], False)
        return ("snapshot", rows[0][0])
    finally:
        pg.run("rollback")


class DGen:
    def __init__(self, rng):
        self.r = rng

    def name(self):
        return self.r.choice(["a", "b", "c", "d", "x", "Y", '"Z"', "col_1", "t", "key", "name", "value", "i0", "i1"])

    def coldef(self):
        r = self.r
        parts = [self.name(), r.choice(TYPES)]
        cons = []
        if r.random() < 0.3:
            cons.append("not null")
        if r.random() < 0.15:
            cons.append("primary key")
        if r.random() < 0.15:
            cons.append("unique")
        if r.random() < 0.3:
            cons.append("default " + r.choice(DEFAULTS))
        r.shuffle(cons)
        return " ".join(parts + cons)

    def statement(self):
        r = self.r
        k = r.random()
        if k < 0.35:
            cols = ", ".join(self.coldef() for _ in range(r.randint(1, 4)))
            return r.choice(["create table ", "CREATE TABLE ", "create table "]) + r.choice(["t", "u", "T"]) + r.choice([" (", "(", " ( "]) + cols + ")"
        if k < 0.55:
            return "alter table t add " + r.choice(["column ", "", "COLUMN "]) + self.coldef()
        if k < 0.8:
            cols = ", ".join(r.sample(["a", "b", "c"], r.randint(1, 2)))
            return "create " + r.choice(["", "unique "]) + "index " + r.choice(["i1", "i0", "ix", '"Ix"']) + " on t (" + cols + ")"
        if k < 0.9:
            return "drop table " + r.choice(["t", "u", "T"])
        return "drop index " + r.choice(["i0", "i1", "I0"])


WORDS = ["create", "table", "index", "unique", "alter", "drop", "add", "column", "on", "t", "u", "i0", "a", "b", "(", ")", ",", "int",
         "text", "not null", "null", "primary key", "unique", "default", "1", "'x'", "references t", "check (a > 1)", "if not exists",
         "if exists", "cascade", "using btree", "concurrently", "only", "constraint c", "generated always as identity", "collate x"]


def fuzz(rng):
    start = rng.choice(["create table t (", "create table t (a int ", "alter table t add ", "create index i1 on t (", "drop table ", "create "])
    return start + " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 8))) + rng.choice(["", ")", ")"])


def main():
    rng = random.Random(SEED)
    pg = pgdiff.PG()
    g = DGen(rng)
    stats = {"cases": 0, "refused": 0, "refused_valid": 0, "same_snapshot": 0, "same_error": 0}
    bad = []
    for n in range(CASES):
        src = g.statement() if n % 3 else fuzz(rng)
        got = check(src)
        stats["cases"] += 1
        if got[0] == "crash":
            bad.append(("crash", src, got))
            continue
        orig = run_in_txn(pg, src)
        if got[0] == "refused":
            stats["refused"] += 1
            if orig[0] == "snapshot":
                stats["refused_valid"] += 1
            continue
        rend = run_in_txn(pg, got[1])
        if orig[0] == "error" and orig[2]:
            bad.append(("accepted what PostgreSQL refuses as a syntax error", src, got[1]))
        elif orig[:2] == rend[:2]:
            stats["same_snapshot" if orig[0] == "snapshot" else "same_error"] += 1
        else:
            bad.append(("different", src, got[1], orig, rend))
    print(stats)
    for b in bad[:10]:
        print("DISAGREEMENT", b)
    print(f"{len(bad)} disagreements in {stats['cases']} cases")
    return 1 if bad else 0


sys.exit(main())
