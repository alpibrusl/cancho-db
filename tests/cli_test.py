#!/usr/bin/env python3
"""The command line of both verifiers (docs/spec/commit.md section 6): exit 2 and no verdict on a usage error or an
unreadable file, exit 0 and 1 for a verdict, and a verdict is exactly one line on stdout.

    cli_test.py VECTORS_DIR CHO_VERIFIER
"""
import subprocess
import sys
from pathlib import Path

vdir, cho = Path(sys.argv[1]), sys.argv[2]
py = [sys.executable, str(Path(__file__).resolve().parent.parent / "tools/verify.py")]
good, bad = str(vdir / "ok_chain3.log"), str(vdir / "bad_magic.log")
tip = (vdir / "ok_expect_tip.args").read_text().split()[1]
cases = [
    ([], 2, ""),
    (["a", "b"], 2, ""),
    (["nope-does-not-exist.log"], 2, ""),
    ([good, "--expect"], 2, ""),
    ([good, "--expect", "zz"], 2, ""),
    ([good, "--expect", tip[:-1]], 2, ""),
    ([good, "--expect", tip + "0"], 2, ""),
    ([good, "--expect", tip.upper()], 0, "ok commits=3 branches=1\n"),
    ([good, "--bogus"], 2, ""),
    ([good, "-x"], 2, ""),
    (["--expect", tip, good], 0, "ok commits=3 branches=1\n"),
    ([good], 0, "ok commits=3 branches=1\n"),
    ([bad], 1, "reject rule=bad-magic record=-1\n"),
    ([str(vdir)], 2, ""),  # a directory is not a log
]
# L2 (docs/spec/token.md section 6)
root = (vdir / "l2_ok_basic.args").read_text().split()[1]
tok = str(vdir / "l2_ok_basic.tokens")
l2log = str(vdir / "l2_ok_basic.log")
rev = str(vdir / "l2_ok_revoked_later.revoked")
l2ok = "ok commits=3 branches=1 level=2\n"
cases += [
    ([l2log, "--root", root, "--tokens", tok], 0, l2ok),
    (["--tokens", tok, l2log, "--root", root], 0, l2ok),
    ([l2log, "--root", root.upper(), "--tokens", tok], 0, l2ok),
    ([l2log, "--root", root, "--tokens", tok, "--revoked", rev], 0, l2ok),
    ([l2log, "--tokens", tok], 2, ""),                                  # tokens without a root
    ([l2log, "--revoked", rev], 2, ""),                                 # revoked without a root
    ([l2log, "--root", root], 2, ""),                                   # a root without tokens
    ([l2log, "--root", root[:-1], "--tokens", tok], 2, ""),
    ([l2log, "--root", "zz" * 32, "--tokens", tok], 2, ""),
    ([l2log, "--root", root, "--root", root, "--tokens", tok], 2, ""),  # repeated
    ([l2log, "--root", root, "--tokens", tok, "--tokens", tok], 2, ""),
    ([l2log, "--root", root, "--tokens", "nope-no-such-file"], 2, ""),
    ([l2log, "--root", root, "--tokens", tok, "--revoked", "nope-no-such-file"], 2, ""),
    ([l2log, "--root", root, "--tokens", str(vdir)], 2, ""),            # a directory is not a token store
    ([l2log, "--root", root, "--tokens", tok, "--expect", "00" * 32], 1, "reject rule=expected-missing record=-1\n"),
    ([bad, "--root", root, "--tokens", tok], 1, "reject rule=bad-magic record=-1\n"),  # L1 first
]
failed = 0
for name, cmd in (("cancho", [cho]), ("python", py)):
    for args, status, out in cases:
        p = subprocess.run(cmd + args, capture_output=True, text=True)
        # the python one lowercases nothing: accept either upper or lower hex as the spec's "64 hex digits"
        if p.returncode != status or p.stdout != out:
            failed += 1
            print("FAIL %s %r: exit %d stdout %r, want exit %d stdout %r" % (name, args, p.returncode, p.stdout, status, out))
print("%d checks, %d failed" % (2 * len(cases), failed))
sys.exit(1 if failed else 0)
