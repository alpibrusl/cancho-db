#!/usr/bin/env python3
"""Name resolution in the lowering against PostgreSQL's own (docs/m1-lowering.md section 4.1, section 6).

    PG_E2E_PORT=5532 python3 tests/lower_diff.py LOWERCHECK_BINARY [CASES] [SEED]

The lowering resolves names against a schema snapshot. PostgreSQL resolves the same names against the real catalog, and says
what it found as an SQLSTATE: 42P01 an unknown table, 42703 an unknown column, 42702 an ambiguous one. For statements from the
generator of tests/stmt_diff.py (over the tables t, u and v), with the snapshot written to match:

  * when the lowering REFUSES with `unknown-table`, `unknown-column` or `ambiguous-column`, PostgreSQL must not ACCEPT the
    statement, nor refuse it for a different name problem: refusing what PostgreSQL accepts would be a lowering that cannot run
    valid SQL (PostgreSQL may report an earlier unrelated error first, which is not held against the lowering);
  * when the lowering ACCEPTS, PostgreSQL must NOT refuse it for a name: accepting a name PostgreSQL cannot resolve would mean
    the IR names something other than what runs.

A different SQLSTATE from PostgreSQL (a type error, say) is not compared: the lowering does not type-check.
"""
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pgdiff  # noqa: E402
import stmt_diff  # noqa: E402

LOWER = sys.argv[1]
CASES = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1
pgdiff.PORT = int(os.environ.get("PG_E2E_PORT", "5532"))

SNAPSHOT = "t: a b c d\nu: a x y\nv: b z\n"
TAG_TO_STATE = {"unknown-table": "42P01", "unknown-column": "42703", "ambiguous-column": "42702"}
NAME_STATES = set(TAG_TO_STATE.values())


def lower(sql):
    r = subprocess.run([LOWER], input=(SNAPSHOT + "---\n" + sql).encode(), capture_output=True, timeout=30)
    out = r.stdout.decode().strip()
    if r.returncode != 0 or not out:
        return ("crash", r.stderr.decode()[:100])
    kind, _, rest = out.partition(" ")
    return (kind, rest)


def main():
    rng = random.Random(SEED)
    pg = pgdiff.PG()
    for ddl in stmt_diff.SCHEMA:
        err = pg.run(ddl)[1]
        if err:
            print("cannot create the schema:", err)
            return 1
    g = stmt_diff.SGen(rng)
    stats = {"cases": 0, "lowered": 0, "name_refusals": 0, "other_refusals": 0}
    bad = []
    for _ in range(CASES):
        src = g.statement()
        got = lower(src)
        stats["cases"] += 1
        if got[0] == "crash":
            bad.append(("crash", src, got))
            continue
        orig = pg.explain(src)
        pg_state = orig[1] if orig[0] == "error" else None
        if got[0] == "ok":
            stats["lowered"] += 1
            if pg_state in NAME_STATES:
                bad.append(("lowered a statement PostgreSQL refuses for a name", src, pg_state))
        elif got[1] in TAG_TO_STATE:
            stats["name_refusals"] += 1
            # PostgreSQL may report an earlier, unrelated error first (an ORDER BY position, a type), so only a statement it
            # accepts, or one it refuses for a DIFFERENT name problem, counts against the lowering
            if orig[0] == "plan" or pg_state in NAME_STATES and pg_state != TAG_TO_STATE[got[1]]:
                bad.append(("refused for a name PostgreSQL resolves", src, got[1], pg_state))
        else:
            stats["other_refusals"] += 1
    print(stats)
    for b in bad[:10]:
        print("DISAGREEMENT", b)
    print("%d disagreements in %d cases" % (len(bad), stats["cases"]))
    return 1 if bad else 0


sys.exit(main())
