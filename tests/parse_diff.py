#!/usr/bin/env python3
"""The expression parser against PostgreSQL itself: does the rendering mean what the original means?
(docs/m1-lowering.md section 6, gate 2)

    PG_E2E_PORT=5532 python3 tests/parse_diff.py EXPRCHECK_BINARY [CASES] [SEED]

For each generated expression it asks:

  * `exprcheck` (src/parse.cho): `ok <rendering>`, or `refused <tag>`;
  * PostgreSQL, over the wire: `EXPLAIN (VERBOSE, COSTS OFF) SELECT <expr> FROM t` for the original and for the rendering.

The rendering is what the proxy will run, so what must hold when the parser accepts is:

  * the two plans are IDENTICAL: PostgreSQL parenthesises what it parsed in its `Output:` line, so a precedence or
    associativity mistake in the parser shows as a different line;
  * if one errors the other errors with the same SQLSTATE;
  * PostgreSQL does not refuse the original as a SYNTAX error (42601): that would be the parser accepting what PostgreSQL
    rejects, and running a statement nobody wrote.

A refusal by the parser is not compared (the safe direction); how many valid expressions it refused is reported, not hidden.
The strings come from two generators: a grammar of typed expressions written with and without redundant parentheses, spaced and
cased at random, where most are valid; and a fuzzer over a vocabulary of tokens, where most are not and PostgreSQL is the oracle.
"""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pgdiff  # noqa: E402
from pgdiff import Gen, fuzz, chain  # noqa: E402

PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
EXPR = sys.argv[1]
CASES = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1


def check(src):
    r = subprocess.run([EXPR], input=src.encode(), capture_output=True, timeout=30)
    out = r.stdout.decode().rstrip("\n")
    if r.returncode != 0 or not out:
        return ("crash", r.stderr.decode()[:100])
    if out.startswith("ok "):
        return ("ok", out[3:])
    return ("refused", out.split(" ", 1)[1])


pgdiff.PORT = PORT


def main():
    rng = random.Random(SEED)
    pg = pgdiff.PG()
    err = pg.run("create temp table t(a int, b int, c text, d bool)")[1]
    if err:
        print("cannot create the table:", err)
        return 1
    g = Gen(rng)
    stats = {"cases": 0, "refused": 0, "refused_valid": 0, "same_plan": 0, "same_error": 0}
    bad = []
    for n in range(CASES):
        src = g.any() if n % 4 < 2 else (chain(rng) if n % 4 == 2 else fuzz(rng))
        got = check(src)
        stats["cases"] += 1
        if got[0] == "crash":
            bad.append(("crash", src, got))
            continue
        orig = pg.plan(src)
        if got[0] == "refused":
            stats["refused"] += 1
            if orig[0] == "plan":
                stats["refused_valid"] += 1
            continue
        render = got[1]
        rend = pg.plan(render)
        if orig[0] == "error" and orig[2]:
            bad.append(("accepted what PostgreSQL refuses as a syntax error", src, render))
        elif orig[:2] == rend[:2]:
            stats["same_plan" if orig[0] == "plan" else "same_error"] += 1
        else:
            bad.append(("different", src, render, orig, rend))
    print(stats)
    for b in bad[:10]:
        print("DISAGREEMENT", b)
    print(f"{len(bad)} disagreements in {stats['cases']} cases")
    return 1 if bad else 0


sys.exit(main())
