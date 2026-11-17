#!/usr/bin/env python3
"""Writes tests/parse_cases.cho: the cases for src/parse.cho (docs/m1-lowering.md sections 1, 2, 7), as cancho source.

Every expected answer is written by hand below, from PostgreSQL's documented operator precedence and grammar, not computed by
anything in src/. A case is an expression, and either the rendering it must have (every operator parenthesised, names always
quoted and folded, keywords lower case) or the tag of the refusal it must get. Inputs and renderings are hex in the generated
file. The limits (stack depths, arena sizes, output size) are per case, so that the refusals for exceeding them are tested too.

    python3 tools/gen_parse.py            # rewrites tests/parse_cases.cho
    python3 tools/gen_parse.py --check    # fails if the file on disk differs (the gate runs this)
"""
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "parse_cases.cho"
CASES = []  # (input, ("ok", rendering) | ("refuse", tag), limits dict)
DEFAULTS = dict(oscap=64, vcap=64, ncap=100, kcap=100, ocap=1024, rcap=64)


def ok(src, rendering, **lim):
    CASES.append((src.encode("latin-1"), ("ok", rendering.encode("latin-1")), dict(DEFAULTS, **lim)))


def refuse(src, tag, **lim):
    CASES.append((src.encode("latin-1"), ("refuse", tag), dict(DEFAULTS, **lim)))


def q(name):
    return '"%s"' % name


# ---- leaves and names
ok("1", "1")
# ---- parameters: `$n`, a leaf, written back as it was (docs/m1-extended.md P3-D1)
ok("$1", "$1")
ok("  $12  ", "$12")
ok("$65535", "$65535")
ok("$1 + $2 * $3", "($1 + ($2 * $3))")
ok("a = $1", '(' + q("a") + ' = $1)')
ok("a in ($1, $2, 3)", '(' + q("a") + ' in ($1, $2, 3))')
ok("a between $1 and $2", '(' + q("a") + ' between $1 and $2)')
ok("-$1", "(- $1)")
ok("not $1", "(not $1)")
ok("$1 is null", "($1 is null)")
ok("$1::int", "cast($1 as integer)")
ok("f($1, $2)", "f($1, $2)")
ok("case when $1 then $2 else $3 end", "(case when $1 then $2 else $3 end)")
refuse("$1 $2", "syntax")
# (a number that is not a parameter, `$0` or `$65536`, is the lexer's refusal: tools/gen_lex.py and tests/guard_check.py)
ok("  1  ", "1")
ok("12.50", "12.50")
ok(".5", ".5")
ok("1e2", "1e2")
ok("'it''s'", "'it''s'")
ok("''", "''")
ok("null", "null")
ok("NULL", "null")
ok("True", "true")
ok("FALSE", "false")
ok("a", q("a"))
ok("A", q("a"))
ok("MixedCase", q("mixedcase"))
ok('"A"', q("A"))
ok('"a""b"', '"a""b"')
ok("t.c", q("t") + "." + q("c"))
ok('T."C"', q("t") + "." + q("C"))
ok('"T".c', q("T") + "." + q("c"))
ok("a--b", q("a"))                                  # a comment is not an operator
ok("/* x */ a /* y */", q("a"))
ok("name", q("name"))                               # not a keyword that matters
refuse("select", "reserved-word")
refuse("user", "reserved-word")
refuse("table", "reserved-word")
refuse("t.select", "reserved-word")
refuse("a.b.c", "unknown-construct")
refuse("t.*", "unknown-construct")
refuse("a b", "syntax")
refuse("1 2", "syntax")
refuse("'a' 'b'", "syntax")
refuse("", "syntax")
refuse(",", "syntax")
refuse(")", "syntax")

# ---- precedence and associativity (PostgreSQL: OR < AND < NOT < IS < comparisons < BETWEEN IN LIKE < || < + - < * / % < unary -)
ok("1+2*3", "(1 + (2 * 3))")
ok("1*2+3", "((1 * 2) + 3)")
ok("1-2-3", "((1 - 2) - 3)")
ok("8/4/2", "((8 / 4) / 2)")
ok("7%4*2", "((7 % 4) * 2)")
ok("1+2<3", "((1 + 2) < 3)")
ok("a or b and c", "(%s or (%s and %s))" % (q("a"), q("b"), q("c")))
ok("a and b or c", "((%s and %s) or %s)" % (q("a"), q("b"), q("c")))
ok("a or b or c", "((%s or %s) or %s)" % (q("a"), q("b"), q("c")))
ok("not a and b", "((not %s) and %s)" % (q("a"), q("b")))
ok("not a = b", "(not (%s = %s))" % (q("a"), q("b")))
ok("not not a", "(not (not %s))" % q("a"))
ok("a = not b", "(%s = (not %s))" % (q("a"), q("b")))
ok("-a", "(- %s)" % q("a"))
ok("- -a", "(- (- %s))" % q("a"))
ok("-a*b", "((- %s) * %s)" % (q("a"), q("b")))
ok("a - -b", "(%s - (- %s))" % (q("a"), q("b")))
ok("a-b", "(%s - %s)" % (q("a"), q("b")))
ok("-a::int", "(- cast(%s as integer))" % q("a"))
ok("a||b+c", "(%s || (%s + %s))" % (q("a"), q("b"), q("c")))
ok("a+b||c", "((%s + %s) || %s)" % (q("a"), q("b"), q("c")))
ok("a||b like c", "((%s || %s) like %s)" % (q("a"), q("b"), q("c")))
ok("a=b and c<>d", "((%s = %s) and (%s <> %s))" % (q("a"), q("b"), q("c"), q("d")))
ok("a!=b", "(%s <> %s)" % (q("a"), q("b")))
ok("a<=b", "(%s <= %s)" % (q("a"), q("b")))
ok("a>=b", "(%s >= %s)" % (q("a"), q("b")))
ok("a<b", "(%s < %s)" % (q("a"), q("b")))
ok("a>b", "(%s > %s)" % (q("a"), q("b")))
refuse("a<b<c", "syntax")
refuse("a=b=c", "syntax")
refuse("a<b=c", "syntax")
ok("(a<b)<c", "((%s < %s) < %s)" % (q("a"), q("b"), q("c")))
ok("a<b and b<c", "((%s < %s) and (%s < %s))" % (q("a"), q("b"), q("b"), q("c")))
ok("(a)", q("a"))
ok("((1))", "1")
ok("(a+b)*c", "((%s + %s) * %s)" % (q("a"), q("b"), q("c")))
ok("a*(b+c)", "(%s * (%s + %s))" % (q("a"), q("b"), q("c")))
refuse("(a, b)", "unknown-construct")
refuse("()", "syntax")
refuse("(a", "syntax")
refuse("a)", "syntax")
refuse("(select 1)", "subquery")
refuse("(with x as (select 1) select 1)", "subquery")
refuse("(values (1))", "subquery")

# ---- operators that are not in the subset
refuse("a ^ b", "unsupported-operator")
refuse("a @> b", "unsupported-operator")
refuse("a ~ b", "unsupported-operator")
refuse("a ! b", "unsupported-operator")
refuse("a <-> b", "unsupported-operator")
refuse("a -> b", "unsupported-operator")
refuse("a ->> 'x'", "unsupported-operator")
refuse("a || b ||| c", "unsupported-operator")
refuse("+a", "unknown-construct")
refuse("a + + b", "unknown-construct")
refuse("* a", "unsupported-operator")
refuse("a +", "syntax")
refuse("a and", "syntax")
refuse("not", "syntax")

# ---- every operator against every other that matters
ok("1-2*3", "(1 - (2 * 3))")
ok("2*3-1", "((2 * 3) - 1)")
ok("6/2-1", "((6 / 2) - 1)")
ok("1-6%4", "(1 - (6 % 4))")
ok("a = b like c", "(%s = (%s like %s))" % (q("a"), q("b"), q("c")))
ok("a like b = c", "((%s like %s) = %s)" % (q("a"), q("b"), q("c")))
ok("a = b between 1 and 2", "(%s = (%s between 1 and 2))" % (q("a"), q("b")))
ok("a between 1 and 2 = c", "((%s between 1 and 2) = %s)" % (q("a"), q("c")))
ok("a < b in (1)", "(%s < (%s in (1)))" % (q("a"), q("b")))
ok("a in (1) < b", "((%s in (1)) < %s)" % (q("a"), q("b")))
refuse("x and a between 1", "syntax")
refuse("SELECT", "reserved-word")
refuse("User", "reserved-word")
refuse("T.Select", "reserved-word")
refuse("xmltable", "reserved-word")
refuse("case when a end", "syntax")
refuse("case a when 1 end", "syntax")

# ---- IS [NOT] NULL
ok("a is null", "(%s is null)" % q("a"))
ok("a is not null", "(%s is not null)" % q("a"))
ok("a=b is null", "((%s = %s) is null)" % (q("a"), q("b")))
ok("a+b is null", "((%s + %s) is null)" % (q("a"), q("b")))
ok("a is null and b", "((%s is null) and %s)" % (q("a"), q("b")))
ok("a is null is null", "((%s is null) is null)" % q("a"))
ok("not a is null", "(not (%s is null))" % q("a"))
ok("a and b is null", "(%s and (%s is null))" % (q("a"), q("b")))
refuse("a is true", "unknown-construct")
refuse("a is not true", "unknown-construct")
refuse("a is distinct from b", "unknown-construct")
refuse("a is", "unknown-construct")
refuse("a isnull", "syntax")

# ---- BETWEEN
ok("a between 1 and 2", "(%s between 1 and 2)" % q("a"))
ok("a not between 1 and 2", "(%s not between 1 and 2)" % q("a"))
ok("a between 1+1 and 2*2", "(%s between (1 + 1) and (2 * 2))" % q("a"))
ok("a between 1 and 2 and b", "((%s between 1 and 2) and %s)" % (q("a"), q("b")))
ok("a between 1 and 2 or b", "((%s between 1 and 2) or %s)" % (q("a"), q("b")))
ok("x and a between 1 and 2", "(%s and (%s between 1 and 2))" % (q("x"), q("a")))
ok("a between b and c and d between e and f", "((%s between %s and %s) and (%s between %s and %s))" % tuple(q(c) for c in "abcdef"))
ok("a between (b and c) and d", "(%s between (%s and %s) and %s)" % (q("a"), q("b"), q("c"), q("d")))
ok("a between 1 and 2 is null", "((%s between 1 and 2) is null)" % q("a"))
ok("not a between 1 and 2", "(not (%s between 1 and 2))" % q("a"))
refuse("a between 1", "syntax")
refuse("a between 1 and", "syntax")
refuse("a between and 2", "reserved-word")
refuse("a between 1 = 1 and 2", "syntax")          # PostgreSQL reads this; the subset does not, so the refusal is the safe side
refuse("a between 1 and 2 between 3 and 4", "syntax")
refuse("f(x, a between 1)", "syntax")                   # an open BETWEEN must not take the argument beside it
refuse("a between symmetric 1 and 2", "reserved-word")

# ---- IN
ok("a in (1,2,3)", "(%s in (1, 2, 3))" % q("a"))
ok("a not in (1)", "(%s not in (1))" % q("a"))
ok("a+1 in (b*2, c)", "((%s + 1) in ((%s * 2), %s))" % (q("a"), q("b"), q("c")))
ok("a in (1) - b", "((%s in (1)) - %s)" % (q("a"), q("b")))        # an IN list is closed: found by the differential
ok("a in (1) in (2)", "((%s in (1)) in (2))" % q("a"))
ok("a in (1) and b in (2)", "((%s in (1)) and (%s in (2)))" % (q("a"), q("b")))
ok("a in ((1), (2))", "(%s in (1, 2))" % q("a"))
ok("f(a in (1), 2)", "f((%s in (1)), 2)" % q("a"))
ok("a in (b in (1))", "(%s in ((%s in (1))))" % (q("a"), q("b")))
refuse("a in ()", "syntax")
refuse("a in (1,)", "syntax")
refuse("a in (select 1)", "subquery")
refuse("a in b", "syntax")
refuse("a in (1", "syntax")
refuse("a not in", "syntax")
refuse("a not b", "syntax")

# ---- LIKE and ILIKE
ok("a like 'x%'", "(%s like 'x%%')" % q("a"))
ok("a not like b", "(%s not like %s)" % (q("a"), q("b")))
ok("a ilike b", "(%s ilike %s)" % (q("a"), q("b")))
ok("a not ilike b||c", "(%s not ilike (%s || %s))" % (q("a"), q("b"), q("c")))
ok("a like b and c", "((%s like %s) and %s)" % (q("a"), q("b"), q("c")))
refuse("a like b like c", "syntax")
refuse("a like b escape 'x'", "syntax")
refuse("a similar to b", "syntax")
refuse("a like", "syntax")

# ---- CASE
ok("case when a then 1 end", "(case when %s then 1 end)" % q("a"))
ok("case when a then 1 else 2 end", "(case when %s then 1 else 2 end)" % q("a"))
ok("CASE a WHEN 1 THEN 2 WHEN 3 THEN 4 ELSE 5 END", "(case %s when 1 then 2 when 3 then 4 else 5 end)" % q("a"))
ok("case when a then 1 when b then 2 end", "(case when %s then 1 when %s then 2 end)" % (q("a"), q("b")))
ok("case when a then case when b then 1 end end", "(case when %s then (case when %s then 1 end) end)" % (q("a"), q("b")))
ok("case a+1 when b then c end", "(case (%s + 1) when %s then %s end)" % (q("a"), q("b"), q("c")))
ok("case when a and b then c or d else e end", "(case when (%s and %s) then (%s or %s) else %s end)" % tuple(q(c) for c in "abcde"))
ok("1 + case when a then 1 end * 2", "(1 + ((case when %s then 1 end) * 2))" % q("a"))
ok("case when a then f(1, 2) end", "(case when %s then f(1, 2) end)" % q("a"))
refuse("case end", "reserved-word")
refuse("case", "syntax")
refuse("case a end", "syntax")
refuse("case when a then 1", "syntax")
refuse("case when a then 1 else 2", "syntax")
refuse("case when a 1 end", "syntax")
refuse("case when a then 1 else 2 else 3 end", "syntax")
refuse("case when then 1 end", "reserved-word")
refuse("case when a then end", "reserved-word")
refuse("case a b when 1 then 2 end", "syntax")
refuse("case when a then 1 then 2 end", "syntax")
refuse("case when a, b then 1 end", "syntax")
refuse("when", "reserved-word")
refuse("a then b", "syntax")
refuse("a else b", "syntax")
refuse("a end", "syntax")

# ---- CAST and ::
ok("a::int", "cast(%s as integer)" % q("a"))
ok("a::INT::text", "cast(cast(%s as integer) as text)" % q("a"))
ok("cast(a as bigint)", "cast(%s as bigint)" % q("a"))
ok("CAST(a AS Smallint)", "cast(%s as smallint)" % q("a"))
ok("cast(a+1 as numeric(10, 2))", "cast((%s + 1) as numeric(10, 2))" % q("a"))
ok("a::varchar(20)", "cast(%s as varchar(20))" % q("a"))
ok("a::numeric(5)", "cast(%s as numeric(5))" % q("a"))
ok("a::numeric", "cast(%s as numeric)" % q("a"))
ok("a::decimal", "cast(%s as numeric)" % q("a"))
ok("1::bool", "cast(1 as boolean)")
ok("a::boolean", "cast(%s as boolean)" % q("a"))
ok("a::integer", "cast(%s as integer)" % q("a"))
ok("a::text", "cast(%s as text)" % q("a"))
ok("a::date", "cast(%s as date)" % q("a"))
ok("a::timestamp", "cast(%s as timestamp)" % q("a"))
ok("a::timestamptz", "cast(%s as timestamptz)" % q("a"))
ok("a::real", "cast(%s as real)" % q("a"))
ok("a::bigint", "cast(%s as bigint)" % q("a"))
ok("(a+b)::int", "cast((%s + %s) as integer)" % (q("a"), q("b")))
ok("a+b::int", "(%s + cast(%s as integer))" % (q("a"), q("b")))
ok("f(a)::int", "cast(f(%s) as integer)" % q("a"))
ok("cast(a as int)::text", "cast(cast(%s as integer) as text)" % q("a"))
refuse("a::text(5)", "unknown-construct")
refuse("a::money", "unknown-type")
refuse("a::\"int\"", "unknown-type")
refuse("a::mytype", "unknown-type")
refuse("a::int[]", "syntax")
refuse("a::numeric(1,2,3)", "syntax")
refuse("a::numeric(x)", "syntax")
refuse("a::varchar(1,2)", "syntax")
refuse("a::", "syntax")
refuse("a:: 1", "syntax")
refuse("cast(a)", "syntax")
refuse("cast(a as int", "syntax")
refuse("cast(a as int, b)", "syntax")
refuse("cast(a as)", "syntax")
refuse("cast(a, b as int)", "syntax")
refuse("cast(a as int as int)", "syntax")
refuse("a as int", "syntax")

# ---- calls
ok("f()", "f()")
ok("F(a, b+1)", "f(%s, (%s + 1))" % (q("a"), q("b")))
ok("count(*)", "count(*)")
ok("COUNT( * )", "count(*)")
ok("now()", "now()")
ok("lower(a) || upper(b)", "(lower(%s) || upper(%s))" % (q("a"), q("b")))
ok("f(g(h(1)))", "f(g(h(1)))")
ok("f(a)+g(b)", "(f(%s) + g(%s))" % (q("a"), q("b")))
ok("f((a))", "f(%s)" % q("a"))
ok("f(a, b, c)", "f(%s, %s, %s)" % (q("a"), q("b"), q("c")))
refuse("sum(*)", "unsupported-operator")
refuse("count(* )+", "syntax")
refuse("f(a", "syntax")
refuse("f(a,)", "syntax")
refuse("f(,a)", "syntax")
refuse("f(distinct a)", "reserved-word")
refuse("f(all a)", "reserved-word")
refuse("f(select 1)", "subquery")
refuse('"f"(a)', "unknown-construct")
refuse("a.b(c)", "syntax")
refuse("f(a) over (partition by b)", "syntax")
refuse("f(a) filter (where b)", "syntax")
refuse("left(a, 1)", "reserved-word")
refuse("coalesce(a, 1)", "reserved-word")
refuse("current_timestamp", "reserved-word")
refuse("extract(year from a)", "reserved-word")

# ---- limits: every one is a refusal, never a trap
refuse("((((((((1))))))))", "nested-too-deep", oscap=4)
refuse("- - - - - - - 1", "nested-too-deep", oscap=4)
refuse("f(1, 2, 3, 4, 5, 6)", "nested-too-deep", vcap=4)
refuse("1+2+3+4", "too-big", ncap=4)
refuse("f(1, 2, 3, 4, 5, 6)", "too-big", kcap=3)
refuse("1 + 2", "too-big", ocap=3)
refuse("f(1, 2, 3, 4)", "too-big", kcap=3)
ok("f(1, 2, 3)", "f(1, 2, 3)", kcap=3)                 # exactly at the limit
refuse("-(-(-1))", "nested-too-deep", rcap=2)
ok("((((1))))", "1", oscap=4)                         # one under the limit
ok("1+2+3", "((1 + 2) + 3)", ncap=6)


def hx(b): return b.hex()


def emit():
    o = ["module cdb.parse_cases;", "",
         "// GENERATED by tools/gen_parse.py: do not edit. The cases for src/parse.cho; every answer was written by hand in the",
         "// generator. Inputs and renderings are hex.", "",
         "pub fn n_parse() -> [] int {\n    return %d;\n}\n" % len(CASES)]

    def table(fname, typ, f, default):
        lines = ["pub fn parse_%s(i: int) -> [] %s {" % (fname, typ)]
        for i, case in enumerate(CASES):
            lines.append("    if i == %d {\n        return %s;\n    }" % (i, f(case)))
        lines.append("    return %s;\n}\n" % default)
        o.append("\n".join(lines))

    table("input", "&static [byte]", lambda c: '"%s"' % hx(c[0]), '""')
    table("ok", "int", lambda c: "1" if c[1][0] == "ok" else "0", "0")
    table("want", "&static [byte]", lambda c: '"%s"' % (hx(c[1][1]) if c[1][0] == "ok" else ""), '""')
    table("tag", "&static [byte]", lambda c: '"%s"' % (c[1][1] if c[1][0] == "refuse" else ""), '""')
    for k in ("oscap", "vcap", "ncap", "kcap", "ocap", "rcap"):
        table(k, "int", lambda c, k=k: str(c[2][k]), "0")
    return "\n".join(o)


if __name__ == "__main__":
    text = emit()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("tests/parse_cases.cho is not what tools/gen_parse.py writes", file=sys.stderr)
            sys.exit(1)
        print("parser cases reproducible: %d cases" % len(CASES))
    else:
        OUT.write_text(text)
        print("wrote %s: %d cases (%d refusals)" % (OUT.name, len(CASES), sum(1 for c in CASES if c[1][0] == "refuse")))
