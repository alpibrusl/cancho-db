#!/usr/bin/env python3
"""The L3a verifier over the golden cases of tests/l3a/ (docs/spec/l3a.md section 7).

    python3 tests/l3a_check.py VERIFIER...        each argument is a command (for example `python3 tools/l3a.py`)

A case is NAME.log, NAME.deltas, optionally NAME.base, NAME.expect (the line to write) and NAME.args (extra arguments: `--base` means "the file NAME.base"). Every verifier must write the expected line on every case.
"""
import shlex
import subprocess
import sys
from pathlib import Path

CASES = Path(__file__).resolve().parent / "l3a"
failed = 0
cases = sorted(p.stem for p in CASES.glob("*.expect"))
for cmd in sys.argv[1:]:
    bad = []
    for name in cases:
        args = (CASES / (name + ".args")).read_text().split()
        argv = shlex.split(cmd) + [str(CASES / (name + ".log")), "--deltas", str(CASES / (name + ".deltas"))]
        i = 0
        while i < len(args):
            if args[i] == "--base":
                argv += ["--base", str(CASES / (name + ".base"))]
                i += 1
            elif args[i] == "--live-dump":
                argv += ["--live-dump", str(CASES / (name + ".live"))]
                i += 1
            elif args[i] == "--first-branch":
                argv += ["--first-branch", args[i + 1]]
                i += 2
            else:
                raise SystemExit("unknown argument in %s.args: %s" % (name, args[i]))
        r = subprocess.run(argv, capture_output=True, text=True)
        want = (CASES / (name + ".expect")).read_text().strip()
        if r.stdout.strip() != want:
            bad.append((name, want, r.stdout.strip() or r.stderr.strip()[:120]))
    for name, want, got in bad:
        print("FAIL %s: want %r, got %r" % (name, want, got))
    print("%s: %d cases, %d failed" % (cmd, len(cases), len(bad)))
    failed += len(bad)
sys.exit(1 if failed else 0)
