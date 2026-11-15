#!/usr/bin/env python3
"""Differential fuzzing of the two verifiers, and the no-panic rule: no input may reach a crash.

    [FUZZ_EXTRA="exe exe..."] fuzz.py VECTORS_DIR CHO_VERIFIER [CASES] [SEED]

FUZZ_EXTRA names more verifiers (the Go one) that must print the same line as the other two.

Each case is a vector with random damage (flipped bits, cut or grown tails, inserted or deleted bytes, records swapped
or spliced from another vector). Both verifiers must print the same single line, and the cancho one must exit 0 or 1
with nothing on stderr: a trap, a signal or a stray message is a failure. The seed is printed and fixed by default, so
a failure reproduces; the failing input is written next to the report.
"""
import importlib.util
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("verify_py", ROOT / "tools/verify.py")
pyv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pyv)


def py_verdict(data, l2=None):
    """The Python verifier's line for a log, and with l2=(root, tokens, revoked-or-None) for L2 as well."""
    try:
        commits, branches, infos = pyv.verify(data, None)
        if l2 is not None:
            pyv.verify_l2(infos, *l2)
        level = "" if not l2 else (" level=2+ir" if l2[3] is not None else " level=2")
        return "ok commits=%d branches=%d%s" % (commits, branches, level)
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
    extra = os.environ.get("FUZZ_EXTRA", "").split()

    def others(cmd):
        """The lines the extra verifiers print for the same command line (compared to the cancho one)."""
        return [subprocess.run([e] + cmd[1:], capture_output=True, timeout=30) for e in extra]

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
            more = [(q.stdout.decode(errors="replace").strip(), q.returncode, q.stderr) for q in others([exe, str(f)])]
            if got != want or p.returncode not in (0, 1) or p.stderr or any(
                    m[0] != want or m[1] not in (0, 1) or m[2] for m in more):
                bad += 1
                keep = ROOT / ("fuzz-failure-%d-%d.log" % (seed, n))
                keep.write_bytes(data)
                print("FAIL case %d: cancho=%r exit=%d stderr=%r python=%r others=%r (input kept: %s)" % (
                    n, got, p.returncode, p.stderr[:100], want, more, keep.name))
        # L2 and the IR: damage the log, the token store, the revocation list or the statement store of a vector
        def parse(args_file):
            words = args_file.read_text().replace("{dir}", str(vdir)).split()
            opts = {words[k]: words[k + 1] for k in range(0, len(words), 2)}
            return opts

        l2_cases = [(a.with_suffix(".log"), parse(a)) for a in sorted(vdir.glob("*.args")) if "--root" in a.read_text()]
        pools = {"--tokens": [], "--revoked": [], "--stmts": []}
        for _, o in l2_cases:
            for k in pools:
                if k in o:
                    pools[k].append(Path(o[k]).read_bytes())
        l2_verdicts = {}
        for n in range(cases // 2):
            log_p, opts = rng.choice(l2_cases)
            blobs = {"log": log_p.read_bytes()}
            for k in pools:
                if k in opts:
                    blobs[k] = Path(opts[k]).read_bytes()
            target = rng.choice(["log"] + [k for k in pools if k in opts] * 3)
            blobs[target] = mutate(rng, blobs[target], pool if target == "log" else pools[target])
            f.write_bytes(blobs["log"])
            cmd = [exe, str(f), "--root", opts["--root"]]
            for k in pools:
                if k in blobs:
                    path = Path(tmp) / ("case" + k.replace("--", "."))
                    path.write_bytes(blobs[k])
                    cmd += [k, str(path)]
            p = subprocess.run(cmd, capture_output=True, timeout=30)
            got = p.stdout.decode(errors="replace").strip()
            want = py_verdict(blobs["log"], (bytes.fromhex(opts["--root"]), blobs["--tokens"], blobs.get("--revoked"),
                                             blobs.get("--stmts")))
            rule = want.split()[1][5:] if want.startswith("reject") else "ok"
            l2_verdicts[rule] = l2_verdicts.get(rule, 0) + 1
            more = [(q.stdout.decode(errors="replace").strip(), q.returncode, q.stderr) for q in others(cmd)]
            if got != want or p.returncode not in (0, 1) or p.stderr or any(
                    m[0] != want or m[1] not in (0, 1) or m[2] for m in more):
                bad += 1
                keep = ROOT / ("fuzz-failure-l2-%d-%d" % (seed, n))
                for k, blob in blobs.items():
                    keep.with_name(keep.name + "." + k.replace("--", "")).write_bytes(blob)
                print("FAIL L2 case %d: cancho=%r exit=%d stderr=%r python=%r others=%r (input kept: %s.*)" % (
                    n, got, p.returncode, p.stderr[:100], want, more, keep.name))
    print("verdicts reached:", ", ".join("%s=%d" % kv for kv in sorted(verdicts.items())))
    print("L2 verdicts reached:", ", ".join("%s=%d" % kv for kv in sorted(l2_verdicts.items())))
    print("%d cases, %d failed" % (cases + cases // 2, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
