#!/usr/bin/env python3
"""The SELECT parser against PostgreSQL itself: does the rendering mean what the original means?
(docs/m1-lowering.md section 6, gate 2, for statements)

    PG_E2E_PORT=5532 python3 tests/stmt_diff.py STMTCHECK_BINARY [CASES] [SEED]

As tests/parse_diff.py, for whole SELECT statements: `EXPLAIN (VERBOSE, COSTS OFF) <statement>` for the original and for the
rendering must be identical (or both errors with one SQLSTATE), and nothing the parser accepts may be a syntax error (42601)
to PostgreSQL. The statements come from a grammar (items with and without aliases, one to three tables with the joins the
parser reads, and each clause present or not, with the expression generator of tests/pgdiff.py inside) and from a fuzzer over
a vocabulary of clause words and punctuation, where PostgreSQL is the oracle.
"""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pgdiff  # noqa: E402
from pgdiff import Gen  # noqa: E402

PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
CHECK = sys.argv[1]
CASES = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1
pgdiff.PORT = PORT

SCHEMA = [
    "create temp table t(a int, b int, c text, d bool)",
    "create temp table u(a int, x int, y text)",
    "create temp table v(b int, z int)",
]


def check(src):
    r = subprocess.run([CHECK], input=src.encode(), capture_output=True, timeout=30)
    out = r.stdout.decode().rstrip("\n")
    if r.returncode != 0 or not out:
        return ("crash", r.stderr.decode()[:100])
    if out.startswith("ok "):
        return ("ok", out[3:])
    return ("refused", out.split(" ", 1)[1])


class SGen:
    def __init__(self, rng):
        self.r = rng
        self.g = Gen(rng)

    def alias(self):
        return self.r.choice(["x", "y1", "Alias", '"Q"', "total"])

    def item(self, joined):
        r = self.r.random()
        if r < 0.1:
            return "*"
        if r < 0.15:
            return "t.*"
        e = self.g.any().replace("-- c\n", "").strip()
        if r < 0.5:
            return e
        return e + self.r.choice([" as ", " AS ", " "]) + self.alias()

    def source(self, name, alias_p=0.3):
        if self.r.random() < alias_p:
            return name + self.r.choice([" as ", " "]) + {"t": "tt", "u": "uu", "v": "vv"}[name]
        return name

    def statement(self):
        r = self.r
        g = self.g
        # a plain table most of the time, and the joins the parser reads now and then
        shape = r.random()
        if shape < 0.55:
            frm = " from " + self.source("t")
            joined = False
        elif shape < 0.75:
            frm = " from t" + r.choice([" join ", " inner join ", " left join ", " left outer join "]) + "u on t.a = u.a"
            joined = True
        elif shape < 0.85:
            frm = " from t, u"
            joined = True
        elif shape < 0.9:
            frm = " from t join u on t.a = u.a left join v on t.b = v.b"
            joined = True
        elif shape < 0.95:
            frm = ""
            joined = False
        else:
            frm = " from t left join u on t.a = u.a and u.x > 1"
            joined = True
        g.prefix = "t." if joined else ""
        items = ", ".join(self.item(joined) for _ in range(r.randint(1, 3)))
        s = "select " + ("distinct " if r.random() < 0.15 else "") + items + frm
        if r.random() < 0.5:
            s += " where " + g.b(r.randint(1, 3))
        if r.random() < 0.2:
            s += " group by " + ", ".join(g.i(1) for _ in range(r.randint(1, 2)))
            if r.random() < 0.4:
                s += " having " + g.b(1)
        if r.random() < 0.3:
            s += " order by " + ", ".join(g.i(1) + r.choice(["", "", " asc", " desc", " DESC"]) for _ in range(r.randint(1, 2)))
        if r.random() < 0.25:
            s += " limit " + r.choice(["1", "5", "10", "1+1"])
            if r.random() < 0.4:
                s += " offset " + r.choice(["0", "2", "1+1"])
        elif r.random() < 0.05:
            s += " offset 3"
        g.prefix = ""
        return s


WORDS = ["select", "distinct", "from", "where", "group by", "having", "order by", "limit", "offset", "join", "inner join",
         "left join", "left outer join", "on", "as", "asc", "desc", ",", "*", "t.*", "a", "b", "t", "u", "t.a", "u.a", "1", "2",
         "(", ")", "=", "and", "or", "not", "null", "count(*)", "union", "all", "right join", "cross join", "using", "nulls first",
         "for update", "with", "by", "x", "'s'", "like", "in", "is null", "case when a then 1 end"]


def fuzz(rng):
    return ("select " if rng.random() < 0.6 else "") + " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 12)))


def main():
    rng = random.Random(SEED)
    pg = pgdiff.PG()
    for ddl in SCHEMA:
        err = pg.run(ddl)[1]
        if err:
            print("cannot create the schema:", err)
            return 1
    g = SGen(rng)
    stats = {"cases": 0, "refused": 0, "refused_valid": 0, "same_plan": 0, "same_error": 0}
    bad = []
    for n in range(CASES):
        src = g.statement() if n % 3 else fuzz(rng)
        got = check(src)
        stats["cases"] += 1
        if got[0] == "crash":
            bad.append(("crash", src, got))
            continue
        orig = pg.explain(src)
        if got[0] == "refused":
            stats["refused"] += 1
            if orig[0] == "plan":
                stats["refused_valid"] += 1
                stats.setdefault("refused_valid_tags", {}).setdefault(got[1], 0)
                stats["refused_valid_tags"][got[1]] += 1
            continue
        rend = pg.explain(got[1])
        if orig[0] == "error" and orig[2]:
            bad.append(("accepted what PostgreSQL refuses as a syntax error", src, got[1]))
        elif orig[:2] == rend[:2]:
            stats["same_plan" if orig[0] == "plan" else "same_error"] += 1
        else:
            bad.append(("different", src, got[1], orig, rend))
    print(stats)
    for b in bad[:10]:
        print("DISAGREEMENT", b)
    print(f"{len(bad)} disagreements in {stats['cases']} cases")
    return 1 if bad else 0


sys.exit(main())
