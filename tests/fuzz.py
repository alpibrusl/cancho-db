#!/usr/bin/env python3
"""Differential fuzzing of the two verifiers, and the no-panic rule: no input may reach a crash.

    fuzz.py VECTORS_DIR CHO_VERIFIER [CASES] [SEED]

Each case is a vector with random damage (flipped bits, cut or grown tails, inserted or deleted bytes, records swapped
or spliced from another vector). Both verifiers must print the same single line, and the cancho one must exit 0 or 1
with nothing on stderr: a trap, a signal or a stray message is a failure. The seed is printed and fixed by default, so
a failure reproduces; the failing input is written next to the report.
"""
import importlib.util
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("verify_py", ROOT / "tools/verify.py")
pyv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pyv)


def py_verdict(data):
    try:
        return pyv.verify(data, None)
    except pyv.Reject as e:
        return "reject rule=%s record=%d" % (e.rule, e.record)


def mutate(rng, data, pool):
    d = bytearray(data)
    for _ in range(rng.choice([1, 1, 1, 2, 3, 8])):
        k = rng.randrange(8)
        if k == 0 and d:
            d[rng.randrange(len(d))] ^= 1 << rng.randrange(8)
        elif k == 1 and d:
            d[rng.randrange(len(d))] = rng.randrange(256)
        elif k == 2 and d:
            del d[rng.randrange(len(d)):]
        elif k == 3:
            d += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 70)))
        elif k == 4 and d:
            i = rng.randrange(len(d))
            del d[i:i + rng.randrange(1, 40)]
        elif k == 5:
            i = rng.randrange(len(d) + 1)
            d[i:i] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
        elif k == 6 and len(d) > 48:
            # a field that is a count or a length: put an extreme value there
            i = rng.randrange(40, len(d) - 4)
            d[i:i + 4] = rng.choice([b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", b"\x7f\xff\xff\xff", b"\x00\x00\x00\x01",
                                     b"\x00\x00\x00\x40"])
        elif k == 7:
            other = rng.choice(pool)
            if len(other) > 40 and len(d) > 40:
                a, b = rng.randrange(40, len(d)), rng.randrange(40, len(other))
                d = d[:a] + bytearray(other[b:])
    return bytes(d)


def main(argv):
    vdir, exe = Path(argv[1]), argv[2]
    cases = int(argv[3]) if len(argv) > 3 else 1500
    seed = int(argv[4]) if len(argv) > 4 else 1
    rng = random.Random(seed)
    pool = [p.read_bytes() for p in sorted(vdir.glob("*.log"))]
    print("fuzz: %d cases, seed %d, %d seeds" % (cases, seed, len(pool)))
    verdicts, bad = {}, 0
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "case.log"
        for n in range(cases):
            data = mutate(rng, rng.choice(pool), pool)
            f.write_bytes(data)
            p = subprocess.run([exe, str(f)], capture_output=True, timeout=30)
            got = p.stdout.decode(errors="replace").strip()
            want = py_verdict(data)
            rule = want.split()[1][5:] if want.startswith("reject") else "ok"
            verdicts[rule] = verdicts.get(rule, 0) + 1
            if got != want or p.returncode not in (0, 1) or p.stderr:
                bad += 1
                keep = ROOT / ("fuzz-failure-%d-%d.log" % (seed, n))
                keep.write_bytes(data)
                print("FAIL case %d: cancho=%r exit=%d stderr=%r python=%r (input kept: %s)" % (
                    n, got, p.returncode, p.stderr[:100], want, keep.name))
    print("verdicts reached:", ", ".join("%s=%d" % kv for kv in sorted(verdicts.items())))
    print("%d cases, %d failed" % (cases, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
