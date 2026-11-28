#!/usr/bin/env python3
"""The pattern operators and the lengths of a text, against PostgreSQL (docs/m3-engine.md 6by).

    PG_E2E_PORT=5532 python3 tests/regex_check.py build/enginecheck PATTERNS SEED

A table of texts (ASCII of every kind, letters beyond ASCII, the empty text, a null). For each of PATTERNS random patterns of the subset the engine reads, and a fixed
list of them: the rows `s ~ pattern` and `s !~ pattern` choose must be the rows PostgreSQL chooses. For patterns outside the subset, or that are no pattern: the
engine refuses, whatever PostgreSQL does with them (it answers some and has an error for others; which is written beside each). And `length`, `char_length`,
`octet_length` of every text. The database's collation is C, as the engine's is, so `[:alpha:]` and its kin are ASCII's on both sides.
"""
import os
import random
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
N, SEED = int(sys.argv[2]), int(sys.argv[3])
sys.argv = [sys.argv[0], sys.argv[1], "10", str(SEED)]
import engine_check as ec  # noqa: E402

TEXTS = ["", "bell\x07", "del\x7f", "nel\u0085", "nbsp\u00a0", "unit\x1f", "say \"so\"", "a", "abc", "ABC", "abc-12", "a b", "a  b", "x[y]", "a.b", "a+b", "a*b", "trip_01", "A-Z", "0123456789", "f" * 64, "0" * 40, "9a" * 20, "hello world", "tab\there", "ñandú", "naïve café", "日本語", "a]b", "a^b", "a$b",
         "{1,2}", "back\\slash", "-", "_", "a-", "-a", "aaa", "aaaa", "aaaaa", "ab" * 6, "zz top", "Mixed Case 9", "user@example.com", "1 2 3 use", "2 14 77 7 2 x", "é", "q?", "(paren)", "pipe|d", "comma,sep", "UPPER_lower-1.2"]
FIXED = ["f" * 64, "[[:cntrl:]]", "^[^[:cntrl:]]*$", "[[:blank:]]", "[\"\\\\[:cntrl:]]", "^[^\"\\\\[:cntrl:]]+$", "^[a-z0-9_-]{1,40}$", "^[0-9a-f]{64}$", "^[a-z]+", "[[:space:]]", "\\[y", "b", "a.c", "^.{5}$", "^$", "", "^", "$", "a*", "^a*$", "^a+$", "a{2}", "^a{2,3}$", "a{4,}", "[^a-z]", "^[^a-z]*$", "[]a]", "[^]a]", "[a-]",
         "[-a]", "[[:alpha:]][[:digit:]]", "^[[:upper:]]+$", "[[:punct:]]", "^[[:alnum:]_]+$", "[[:xdigit:]]{10}", "[[:lower:]] [[:lower:]]", "ñ", "[ñú]", "^[a-zñ]+$", "日", "\\.", "\\+", "\\*", "\\$", "\\^", "\\\\", "\\{1",
         "x?y", "^[0-9]+ [0-9]+ use$", "^1 [0-9]+ 7 2 ", "a\\-", "[a\\-z]", "[\\]]", "^.?$", ".{3}", "^[A-Z][a-z]+ [A-Z]"]
# outside the subset, or no pattern at all: (the pattern, PostgreSQL's SQLSTATE or None if it answers)
REFUSED = [("f" * 65, None), ("[[:print:]]", None), ("[[:graph:]]", None), ("(a|b)", None), ("a|b", None), ("(abc)", None), ("\\d+", None), ("\\w", None), ("\\s", None), ("\\mfoo", None), ("a+?", None), ("a**", "2201B"), ("a{2}{3}", "2201B"), ("^a^", None), ("a$b", None), ("x^", None),
           ("*a", "2201B"), ("+", "2201B"), ("[a", "2201B"), ("[z-a]", "2201B"), ("a{3,2}", "2201B"), ("a{256}", "2201B"), ("[[:nope:]]", "2201B"), ("[[.a.]]", None), ("[[=a=]]", None), ("a{", None), ("a}", None), ("\\", "2201B"),
           ("[\\d]", None), ("a{1", "2201B"), ("(?i)a", None)]


def pattern(rng):
    """A random pattern of the subset."""
    out = "^" if rng.random() < 0.5 else ""
    for _ in range(rng.randrange(1, 5)):
        r = rng.random()
        if r < 0.35:
            atom = rng.choice(list("abcxyz019_- ") + ["\\.", "\\+", "\\[", "ñ"])
        elif r < 0.45:
            atom = "."
        else:
            neg = "^" if rng.random() < 0.2 else ""
            body = "".join(rng.choice(["a-z", "A-Z", "0-9", "a-f", "_", "-", " ", "[:alpha:]", "[:digit:]", "[:space:]", "[:upper:]", "[:punct:]", "[:cntrl:]", "[:blank:]", "ñ", "x", "."]) for _ in range(rng.randrange(1, 4)))
            # a `-` in the middle would make a range of what is around it
            body = "".join(sorted(set(body.replace("--", "-").split("-")), key=len)) + ("-" if "-" in body else "")
            atom = "[" + neg + (body or "a") + "]"
        q = rng.random()
        if q < 0.15:
            atom += "*"
        elif q < 0.30:
            atom += "+"
        elif q < 0.40:
            atom += "?"
        elif q < 0.55:
            m = rng.randrange(0, 4)
            atom += rng.choice(["{%d}" % m, "{%d,}" % m, "{%d,%d}" % (m, m + rng.randrange(0, 40))])
        out += atom
    return out + ("$" if rng.random() < 0.5 else "")


def lit(s):
    return "'" + s.replace("'", "''") + "'"


def main():
    rng = random.Random(SEED * 7907 + 3)
    ec.admin("drop database if exists %s" % ec.DB)
    r = ec.admin("create database %s encoding 'UTF8' lc_collate 'C' lc_ctype 'C' template template0" % ec.DB)
    if r.returncode != 0:
        raise SystemExit("regex_check: " + r.stderr)
    pg = ec.Pg(ec.DB)
    setup = ["create table rp (k integer primary key, s text)", "insert into rp values " + ", ".join("(%d, %s)" % (i + 1, lit(p)) for i, p in enumerate(FIXED)),
             "create table rx (k integer primary key, s text)", "insert into rx values " + ", ".join("(%d, %s)" % (i + 1, lit(t)) for i, t in enumerate(TEXTS)) + ", (%d, null)" % (len(TEXTS) + 1)]
    pats = FIXED + [pattern(rng) for _ in range(N)]
    asks = []
    for p in pats:
        asks.append("select k from rx where s ~ %s order by k" % lit(p))
        asks.append("select k from rx where s !~ %s order by k" % lit(p))
    asks.append("select k, length(s), char_length(s), octet_length(s) from rx order by k")
    asks.append("select k from rx where length(s) > 5 and s ~ '^[a-z]' order by k")
    asks.append("select k, s ~ '^a' from rx order by k")
    # a pattern that is null: null, for every text
    asks.append("select k, 'abc' ~ s, 'abc' !~ s, s ~ s from rx where s is null")
    refs = ["select k from rx where s ~ %s order by k" % lit(p) for p, _ in REFUSED]
    # the pattern from a column: each row's own. Some of the texts are patterns outside the subset (a group, an alternation), so the statement is refused; over
    # texts that are all in it, it is answered
    refs.append("select k from rx where 'abc' ~ s order by k")
    asks.append("select k from rp where 'abc-12' ~ s order by k")
    with tempfile.TemporaryDirectory() as d:
        eng = ec.run_engine(os.path.join(d, "rx.db"), setup + asks + refs)
    for s in setup:
        pg.query(s)
    bad, chosen, refused = [], 0, 0
    for sql, ans in zip(asks, eng[len(setup):len(setup) + len(asks)]):
        err, _, rows, _ = pg.query(sql)
        mine = [[ec.unhex(v) if v != "-" else None for v in l.split()[1:]] for l in ans if l.startswith("R ")]
        if ans[0].startswith("refused"):
            # a pattern the generator made that is outside the subset would be a fault of the generator: none is allowed here
            bad.append((sql, "the engine refuses", ans[0]))
        elif err is not None or mine != [list(r) for r in rows]:
            bad.append((sql, "PostgreSQL: %s %s" % (err, rows[:6]), "the engine: %s" % mine[:6]))
        elif " ~ " in sql:
            chosen += len(mine)
    for (p, want), sql, ans in zip(REFUSED + [("(a column's)", "2201B")], refs, eng[len(setup) + len(asks):]):
        err = pg.query(sql)[0]
        if ans[0] != "refused engine-unsupported":
            bad.append((sql, "the engine says %s, and this is one it does not read" % ans[0], ""))
        elif err != want and ec.PGMAJOR[0] in (0, 16):
            bad.append((sql, "PostgreSQL says %s, expected %s" % (err, want), ""))
        else:
            refused += 1
    pg.query("drop table rx")
    pg.query("drop table rp")
    for b in bad[:8]:
        print("FAIL", *b)
    if bad:
        print("regex_check: %d disagreements" % len(bad))
        return 1
    print("regex_check: %d patterns, each with ~ and !~ over %d texts: the rows are PostgreSQL's (%d rows chosen by ~); %d patterns outside the subset refused; ok" % (len(pats), len(TEXTS) + 1, chosen, refused))
    return 0


if __name__ == "__main__":
    sys.exit(main())
