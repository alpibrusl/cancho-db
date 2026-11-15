#!/usr/bin/env python3
"""Writes tests/stmt_cases.cho: the cases for src/stmt.cho (SELECT; docs/m1-lowering.md sections 2 and 7), as cancho source.

Every expected answer is written by hand below, from PostgreSQL's documented operator precedence and grammar, not computed by
anything in src/. A case is an expression, and either the rendering it must have (every operator parenthesised, names always
quoted and folded, keywords lower case) or the tag of the refusal it must get. Inputs and renderings are hex in the generated
file. The limits (stack depths, arena sizes, output size) are per case, so that the refusals for exceeding them are tested too.

    python3 tools/gen_stmt.py            # rewrites tests/stmt_cases.cho
    python3 tools/gen_stmt.py --check    # fails if the file on disk differs (the gate runs this)
"""
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "stmt_cases.cho"
CASES = []  # (input, ("ok", rendering) | ("refuse", tag), limits dict)
DEFAULTS = dict(oscap=64, vcap=64, ncap=200, kcap=200, ocap=2048, rcap=128, tmpcap=64)


def ok(src, rendering, **lim):
    CASES.append((src.encode("latin-1"), ("ok", rendering.encode("latin-1")), dict(DEFAULTS, **lim)))


def refuse(src, tag, **lim):
    CASES.append((src.encode("latin-1"), ("refuse", tag), dict(DEFAULTS, **lim)))


def q(name):
    return '"%s"' % name


def q(name):
    return '"%s"' % name


# ---- the items
ok("select 1", "select 1")
ok("SELECT a", 'select "a"')
ok("select a, b", 'select "a", "b"')
ok("select *", "select *")
ok("select t.*", 'select "t".*')
ok("select T.*, a", 'select "t".*, "a"')
ok('select "T".*', 'select "T".*')
ok("select a as x", 'select "a" as "x"')
ok("select a x", 'select "a" as "x"')
ok('select a "X y"', 'select "a" as "X y"')
ok("select a+1 as n, b", 'select ("a" + 1) as "n", "b"')
ok("select distinct a", 'select distinct "a"')
ok("select distinct *", "select distinct *")
ok("select a as day", 'select "a" as "day"')
ok("select count(*) c", 'select count(*) as "c"')
ok("select 1 -- c", "select 1")
ok("select /* c */ 1", "select 1")
for w in ["day", "filter", "hour", "minute", "month", "over", "second", "varying", "within", "without", "year"]:
    refuse("select a " + w, "syntax")                  # PostgreSQL's non-bare-label words
    ok("select a as " + w, 'select "a" as "%s"' % w)
refuse("select a as select", "reserved-word")
refuse("select a as from", "reserved-word")
refuse("select a b c", "syntax")
refuse("select", "syntax")
refuse("select ,", "syntax")
refuse("select a,", "syntax")
refuse("select , a", "syntax")
refuse("select from t", "reserved-word")
refuse("select a, from t", "reserved-word")
refuse("select nulls first", "unknown-construct")
ok("select a.*", 'select "a".*')
refuse("select *, 1 from", "syntax")
refuse("select all a", "reserved-word")
refuse("select distinct on (a) a", "reserved-word")
refuse("select (select 1)", "subquery")
refuse("insert into t values (1)", "unsupported-statement")
refuse("update t set a = 1", "unsupported-statement")
refuse("", "unsupported-statement")
refuse("delete from t", "unsupported-statement")
refuse("with x as (select 1) select * from x", "unsupported-statement")
refuse("values (1)", "unsupported-statement")

# ---- FROM
ok("select a from t", 'select "a" from "t"')
ok("select a from T", 'select "a" from "t"')
ok("select a from t u", 'select "a" from "t" as "u"')
ok("select a from t as u", 'select "a" from "t" as "u"')
ok('select a from "Mixed" m', 'select "a" from "Mixed" as "m"')
ok("select a from t, u", 'select "a" from "t", "u"')
ok("select a from t x, u y, v", 'select "a" from "t" as "x", "u" as "y", "v"')
ok("select a from t join u on t.a = u.a", 'select "a" from "t" inner join "u" on ("t"."a" = "u"."a")')
ok("select a from t inner join u on true", 'select "a" from "t" inner join "u" on true')
ok("select a from t left join u on t.a = u.a", 'select "a" from "t" left join "u" on ("t"."a" = "u"."a")')
ok("select a from t left outer join u on true", 'select "a" from "t" left join "u" on true')
ok("select a from t join u on true join v on false",
   'select "a" from "t" inner join "u" on true inner join "v" on false')
ok("select a from t left join u on true join v on false",
   'select "a" from "t" left join "u" on true inner join "v" on false')
ok("select a from t join u on true, v", 'select "a" from "t" inner join "u" on true, "v"')
ok("select a from v, t join u on true", 'select "a" from "v", "t" inner join "u" on true')
ok("select a from t x join u y on x.a = y.a and y.b > 1",
   'select "a" from "t" as "x" inner join "u" as "y" on (("x"."a" = "y"."a") and ("y"."b" > 1))')
refuse("select a from", "syntax")
refuse("select a from t,", "syntax")
refuse("select a from s.t", "unknown-construct")
refuse("select a from t.u.v", "unknown-construct")
refuse("select a from f(1)", "unknown-construct")
refuse("select a from (select 1) x", "subquery")
refuse("select a from (t)", "unknown-construct")
refuse("select a from (t join u on true)", "unknown-construct")
refuse("select a from t join u", "syntax")
refuse("select a from t join u using (a)", "unsupported-join")
refuse("select a from t right join u on true", "unsupported-join")
refuse("select a from t full join u on true", "unsupported-join")
refuse("select a from t cross join u", "unsupported-join")
refuse("select a from t natural join u", "unsupported-join")
refuse("select a from t left u on true", "unsupported-join")
refuse("select a from t left outer u on true", "unsupported-join")
refuse("select a from t join u on", "syntax")
refuse("select a from t as", "syntax")
refuse("select a from t as select", "reserved-word")
refuse("select a from select", "reserved-word")
refuse("select a from t tablesample bernoulli (1)", "syntax")

# ---- WHERE, GROUP BY, HAVING
ok("select a from t where a > 1", 'select "a" from "t" where ("a" > 1)')
ok("select a from t where a > 1 and b < 2 or c", 'select "a" from "t" where ((("a" > 1) and ("b" < 2)) or "c")')
ok("select 1 where true", "select 1 where true")
ok("select a from t group by a", 'select "a" from "t" group by "a"')
ok("select a from t group by a, b+1", 'select "a" from "t" group by "a", ("b" + 1)')
ok("select a from t group by a having count(*) > 1", 'select "a" from "t" group by "a" having (count(*) > 1)')
ok("select a from t where b group by a having c", 'select "a" from "t" where "b" group by "a" having "c"')
refuse("select a from t where", "syntax")
refuse("select a from t group a", "syntax")
refuse("select a from t group by", "syntax")
refuse("select a from t group by a,", "syntax")
refuse("select a from t having", "syntax")
refuse("select a from t where a in (select 1)", "subquery")
refuse("select a from t group by all", "reserved-word")
refuse("select a from t group by rollup (a)", "unknown-construct")
refuse("select a from t group by a, cube (b)", "unknown-construct")
refuse("select a from t where a b", "syntax")

# ---- ORDER BY, LIMIT, OFFSET
ok("select a from t order by a", 'select "a" from "t" order by "a"')
ok("select a from t order by a asc", 'select "a" from "t" order by "a" asc')
ok("select a from t order by a desc, b", 'select "a" from "t" order by "a" desc, "b"')
ok("select a from t order by 1 DESC", 'select "a" from "t" order by 1 desc')
ok("select a from t order by a+b desc", 'select "a" from "t" order by ("a" + "b") desc')
ok("select a from t limit 5", 'select "a" from "t" limit 5')
ok("select a from t limit 5 offset 2", 'select "a" from "t" limit 5 offset 2')
ok("select a from t offset 2", 'select "a" from "t" offset 2')
ok("select a from t limit 1+1", 'select "a" from "t" limit (1 + 1)')
ok("select a from t where b group by a having c order by a limit 1 offset 2",
   'select "a" from "t" where "b" group by "a" having "c" order by "a" limit 1 offset 2')
refuse("select a from t order a", "syntax")
refuse("select a from t order by", "syntax")
refuse("select a from t order by a nulls first", "unknown-construct")
refuse("select a from t order by a nulls last", "unknown-construct")
refuse("select a from t order by a using <", "unknown-construct")
refuse("select a from t order by a collate x", "syntax")
refuse("select a from t limit", "syntax")
refuse("select a from t limit all", "reserved-word")
refuse("select a from t offset 1 limit 2", "syntax")
refuse("select a from t limit 1 limit 2", "syntax")
refuse("select a from t fetch first 1 rows only", "syntax")
refuse("select a from t for update", "syntax")
refuse("select a from t window w as ()", "syntax")

# ---- set operations and the rest are refused with their tags
refuse("select a from t union select b from u", "set-operation")
refuse("select a from t union all select b from u", "set-operation")
refuse("select a from t intersect select b from u", "set-operation")
refuse("select a from t except select b from u", "set-operation")
refuse("select a from t where a in (1) union select 1", "set-operation")
refuse("select a from t;", "syntax")

# ---- limits
refuse("select a, b, c, d", "too-big", tmpcap=3)
ok("select a, b, c", 'select "a", "b", "c"', tmpcap=3)
refuse("select 1, 2, 3", "too-big", ncap=6)


def hx(b): return b.hex()


def emit():
    o = ["module cdb.stmt_cases;", "",
         "// GENERATED by tools/gen_stmt.py: do not edit. The cases for src/stmt.cho; every answer was written by hand in the",
         "// generator. Inputs and renderings are hex.", "",
         "pub fn n_stmt() -> [] int {\n    return %d;\n}\n" % len(CASES)]

    def table(fname, typ, f, default):
        lines = ["pub fn stmt_%s(i: int) -> [] %s {" % (fname, typ)]
        for i, case in enumerate(CASES):
            lines.append("    if i == %d {\n        return %s;\n    }" % (i, f(case)))
        lines.append("    return %s;\n}\n" % default)
        o.append("\n".join(lines))

    table("input", "&static [byte]", lambda c: '"%s"' % hx(c[0]), '""')
    table("ok", "int", lambda c: "1" if c[1][0] == "ok" else "0", "0")
    table("want", "&static [byte]", lambda c: '"%s"' % (hx(c[1][1]) if c[1][0] == "ok" else ""), '""')
    table("tag", "&static [byte]", lambda c: '"%s"' % (c[1][1] if c[1][0] == "refuse" else ""), '""')
    for k in ("oscap", "vcap", "ncap", "kcap", "ocap", "rcap", "tmpcap"):
        table(k, "int", lambda c, k=k: str(c[2][k]), "0")
    return "\n".join(o)


if __name__ == "__main__":
    text = emit()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("tests/stmt_cases.cho is not what tools/gen_stmt.py writes", file=sys.stderr)
            sys.exit(1)
        print("statement cases reproducible: %d cases" % len(CASES))
    else:
        OUT.write_text(text)
        print("wrote %s: %d cases (%d refusals)" % (OUT.name, len(CASES), sum(1 for c in CASES if c[1][0] == "refuse")))
