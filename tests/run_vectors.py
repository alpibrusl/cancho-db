#!/usr/bin/env python3
"""Runs a verifier over every vector and compares its one line and exit status with NAME.expect.

    run_vectors.py [--jobs N] VECTORS_DIR -- COMMAND [ARG...]

COMMAND is run as `COMMAND NAME.log [the words of NAME.args, with {dir} replaced by the vectors directory]`. A vector passes when stdout is exactly the expected line and the
exit status is 0 for `ok ...` and 1 for `reject ...`. Exit status of this script: 0 all pass, 1 any failed.
"""
import concurrent.futures
import subprocess
import sys
from pathlib import Path


def run_one(log, cmd):
    expect = log.with_suffix(".expect").read_text()
    args_file = log.with_suffix(".args")
    extra = args_file.read_text().replace("{dir}", str(log.parent)).split() if args_file.exists() else []
    p = subprocess.run(cmd + [str(log)] + extra, capture_output=True, timeout=60)
    want_status = 0 if expect.startswith("ok") else 1
    out = p.stdout.decode(errors="replace")
    if out == expect and p.returncode == want_status and not p.stderr:
        return log.stem, None
    return log.stem, "want %r (exit %d), got %r (exit %d) stderr=%r" % (
        expect, want_status, out, p.returncode, p.stderr[:200])


def main(argv):
    jobs = 8
    if argv[1] == "--jobs":
        jobs, argv = int(argv[2]), argv[2:]
    split = argv.index("--")
    vdir, cmd = Path(argv[1]), argv[split + 1:]
    logs = sorted(vdir.glob("*.log"))
    if not logs:
        print("no vectors in", vdir)
        return 1
    with concurrent.futures.ThreadPoolExecutor(jobs) as ex:
        results = list(ex.map(lambda l: run_one(l, cmd), logs))
    bad = [(n, why) for n, why in results if why]
    for n, why in bad:
        print("FAIL", n, why)
    print("%d vectors, %d failed" % (len(results), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
