#!/usr/bin/env python3
"""Differential fuzz of two L3a verifiers (docs/spec/l3a.md): the golden cases of tests/l3a with random damage to the delta store, the base, the live dump and the log; both must write the same line,
and neither may crash.

    python3 tests/l3a_fuzz.py "VERIFIER A" "VERIFIER B" [ROUNDS] [SEED]
"""
import random
import subprocess
import sys
import tempfile
from pathlib import Path

CASES = Path(__file__).resolve().parent / "l3a"


def run(verifier, log, deltas, base, live, first):
    argv = verifier.split() + [str(log), "--deltas", str(deltas)]
    if base:
        argv += ["--base", str(base)]
    if live:
        argv += ["--live-dump", str(live)]
    if first:
        argv += ["--first-branch", first]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout.strip()


def damage(data, rng):
    b = bytearray(data)
    for _ in range(rng.choice([1, 1, 2, 3])):
        op = rng.randrange(6)
        if not b:
            b = bytearray(b"x")
        i = rng.randrange(len(b))
        if op == 0:
            b[i] = rng.randrange(256)
        elif op == 1:
            del b[i:i + rng.randrange(1, 40)]
        elif op == 2:
            b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 6)))
        elif op == 3:
            b[i] = ord(rng.choice("0123456789abcdef\t\n"))
        elif op == 4:
            b = b[:i]
        else:
            j = rng.randrange(len(b))
            b[i:i] = b[j:j + rng.randrange(1, 60)]
    return bytes(b)


def main():
    va, vb = sys.argv[1], sys.argv[2]
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    rng = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
    names = sorted(p.stem for p in CASES.glob("*.expect"))
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for n in range(rounds):
            name = rng.choice(names)
            args = (CASES / (name + ".args")).read_text().split() if (CASES / (name + ".args")).exists() else []
            first = args[args.index("--first-branch") + 1] if "--first-branch" in args else None
            files = {}
            for ext in ("log", "deltas", "base", "live"):
                f = CASES / (name + "." + ext)
                if f.exists():
                    data = f.read_bytes()
                    if rng.random() < (0.5 if ext == "log" else 0.7) / (1 if ext != "log" else 2):
                        data = damage(data, rng)
                    (tmp / ("x." + ext)).write_bytes(data)
                    files[ext] = tmp / ("x." + ext)
            if "log" not in files:
                continue
            got = []
            for v in (va, vb):
                try:
                    got.append(run(v, files["log"], files["deltas"], files.get("base"), files.get("live"), first))
                except subprocess.TimeoutExpired:
                    got.append((-9, "timeout"))
            for (rc, out), v in zip(got, (va, vb)):
                if rc not in (0, 1, 2):
                    failed += 1
                    print("CRASH %s on %s round %d: rc=%d" % (v, name, n, rc))
                    for ext, f in files.items():
                        Path("/tmp/l3a_fuzz_fail_%d.%s" % (n, ext)).write_bytes(f.read_bytes())
            # a damaged log is L1's to refuse: both must not crash, and what they say about it may differ
            damaged_log = (tmp / "x.log").read_bytes() != (CASES / (name + ".log")).read_bytes()
            if damaged_log and any("log-malformed" in g[1] for g in got):
                continue
            if got[0] != got[1] and 2 not in (got[0][0], got[1][0]):
                failed += 1
                print("DIFF %s round %d: %r vs %r" % (name, n, got[0], got[1]))
                for ext, f in files.items():
                    Path("/tmp/l3a_fuzz_fail_%d.%s" % (n, ext)).write_bytes(f.read_bytes())
    print("%d rounds, %d failed" % (rounds, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
