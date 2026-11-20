#!/usr/bin/env python3
"""Write the counts of the landing page (docs/index.html) from the repository, or check that they are current.

    python3 scripts/site.py           # rewrite the numbers in docs/index.html
    python3 scripts/site.py --check   # exit 1 if they are stale (scripts/check.sh runs this)

A number on the page is `<span data-n="NAME">VALUE</span>`. The names: `vectors` (the golden vectors in vectors/, one `.expect` each), `mutants` (the deliberate faults of tests/mutants.py: every entry of
every list of (label, file, original, replacement) in it), `claims` (the rows of docs/claims.md). The page is hand-written otherwise; the replayed session in it is a recording, not generated.
"""
import importlib.util
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "index.html"


def figures():
    vectors = len(list((ROOT / "vectors").glob("*.expect")))
    claims = len(re.findall(r"^\| C\d+ \|", (ROOT / "docs" / "claims.md").read_text(), re.M))
    cwd = os.getcwd()
    os.chdir(ROOT)
    argv = sys.argv
    sys.argv = ["mutants.py", "none"]
    try:
        spec = importlib.util.spec_from_file_location("mutants_table", ROOT / "tests" / "mutants.py")
        m = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(m)
        except SystemExit:
            pass
    finally:
        sys.argv = argv
        os.chdir(cwd)
    mutants = sum(len(v) for v in vars(m).values()
                  if isinstance(v, list) and v and isinstance(v[0], tuple) and len(v[0]) == 4 and all(isinstance(x, str) for x in v[0]))
    return {"vectors": vectors, "claims": claims, "mutants": mutants}


def main(check):
    text = PAGE.read_text()
    figs = figures()
    stale = []

    def fill(m):
        name = m.group(1)
        if name not in figs:
            stale.append("unknown figure %s" % name)
            return m.group(0)
        want = "{:,}".format(figs[name])
        if m.group(2) != want:
            stale.append("%s: the page says %s, the repository has %s" % (name, m.group(2), want))
        return '<span data-n="%s">%s</span>' % (name, want)

    new = re.sub(r'<span data-n="(\w+)">([^<]*)</span>', fill, text)
    if check:
        for s in stale:
            print("site.py: stale: " + s, file=sys.stderr)
        return 1 if stale else 0
    if new != text:
        PAGE.write_text(new)
        print("site.py: updated " + ", ".join(stale))
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv))
