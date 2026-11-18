#!/usr/bin/env python3
"""docs/spec/state.md: the cancho implementation (src/state.cho, through proxy/statecheck.cho) against tools/state.py and the golden cases.

    python3 tests/state_check.py build/statecheck

  1. the golden cases (vectors/state/cases.txt) are what tools/state.py writes now, and are never edited by hand;
  2. two values are computed here by straight-line code that shares nothing with tools/state.py, and `openssl dgst` agrees on the first: the empty `changes`, and the
     `changes` of three facts (so the tree shape, the odd carry and the three prefixes are pinned by a second reading of the spec);
  3. statecheck answers every golden case as written;
  4. 4,000 random commands, valid and damaged (a flipped field, a wrong order, a bad hex digit, a truncated line), give the same answer from both.
"""
import hashlib
import random
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import state as ref  # noqa: E402

TOOL = sys.argv[1]
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:500]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def run_tool(lines):
    out = subprocess.run([TOOL], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=300)
    return out.stdout.splitlines()


# 1. the cases are reproducible
golden = (ROOT / "vectors/state/cases.txt").read_text().splitlines()
made = [line + " => " + ref.run(line) for line in ref.cases()]
check("the golden cases are what tools/state.py writes (%d)" % len(golden), made == golden)

# 2. values computed by hand, and openssl
sha = lambda b: hashlib.sha256(b).digest()
empty = sha(b"cancho-db/changes/v1\x00" + b"\x00\x00\x00\x00" + bytes(32))
ossl = subprocess.run(["openssl", "dgst", "-sha256", "-r"], input=b"cancho-db/changes/v1\x00" + bytes(4) + bytes(32), capture_output=True).stdout.split()[0].decode()
check("the empty changes is %s, and openssl says the same" % empty.hex()[:16], ref.run("C") == "ok " + empty.hex() == "ok " + ossl, (ref.run("C"), ossl))


def enc(kind, table, pk, old, new):
    return struct.pack(">H", len(table)) + table + struct.pack(">I", len(pk)) + pk + bytes([kind]) + (old or bytes(32)) + (new or bytes(32))


i1, i2, i3 = sha(b"image 1"), sha(b"image 2"), sha(b"image 3")
facts = [(0, b"t", b"\x01", None, i1), (1, b"t", b"\x02", i1, i2), (2, b"u", b"\x01", i3, None)]
l = [sha(b"cancho-db/fact/v1\x00" + enc(*f)) for f in facts]
root = sha(b"cancho-db/node/v1\x00" + sha(b"cancho-db/node/v1\x00" + l[0] + l[1]) + l[2])   # (l0 l1) paired, l2 carried up and paired with it
by_hand = sha(b"cancho-db/changes/v1\x00" + struct.pack(">I", 3) + root)
line = "C " + " ".join(ref.fact_text(*f) for f in facts)
check("three facts: the changes by hand is what tools/state.py says", ref.run(line) == "ok " + by_hand.hex(), (ref.run(line), by_hand.hex()))
st = sha(b"cancho-db/state/v1\x00" + b"\x02" + sha(b"p0") + sha(b"p1") + by_hand)
check("a merge's state by hand is what tools/state.py says", ref.run("S 2 %s %s %s" % (sha(b"p0").hex(), sha(b"p1").hex(), by_hand.hex())) == "ok " + st.hex())

# 3. the golden cases through the cancho implementation
cmds = [g.split(" => ")[0] for g in golden]
want = [g.split(" => ")[1] for g in golden]
got = run_tool(cmds)
bad = [(c[:70], w[:40], g[:40]) for c, w, g in zip(cmds, want, got) if w != g]
check("statecheck answers all %d golden cases as written" % len(cmds), len(got) == len(want) and not bad, bad[:3])

# 4. random commands, valid and damaged
rnd = random.Random(7)
hh = lambda: bytes(rnd.randrange(256) for _ in range(32))
cases = []
for _ in range(4000):
    n = rnd.randrange(0, 12)
    keys = sorted({(bytes(rnd.randrange(97, 101) for _ in range(rnd.randrange(1, 4))), bytes(rnd.randrange(4) for _ in range(rnd.randrange(1, 4)))) for _ in range(n)})
    fs = []
    for tb, pk in keys:
        kind = rnd.randrange(3)
        fs.append([kind, tb, pk, None if kind == 0 else hh(), None if kind == 2 else hh()])
    r = rnd.random()
    if r < 0.15 and fs:          # a field of one fact changed: kind, table, pk or an image
        f = rnd.choice(fs)
        w = rnd.randrange(5)
        if w == 0: f[0] = rnd.randrange(5)
        elif w == 1: f[1] = bytes(rnd.randrange(97, 101) for _ in range(rnd.choice([0, 1, 256])))
        elif w == 2: f[2] = b"" if rnd.random() < 0.5 else bytes(rnd.randrange(4) for _ in range(rnd.randrange(1, 4)))
        elif w == 3: f[3] = None if f[3] else hh()
        else: f[4] = bytes(32) if rnd.random() < 0.5 else (None if f[4] else hh())
    elif r < 0.25 and len(fs) > 1:  # two facts swapped, or one repeated
        a, b = rnd.sample(range(len(fs)), 2)
        if rnd.random() < 0.5: fs[a], fs[b] = fs[b], fs[a]
        else: fs.insert(a, list(fs[b]))
    text = "C " + " ".join(ref.fact_text(*f) for f in fs) if fs else "C"
    r2 = rnd.random()
    if r2 < 0.06 and len(text) > 3:
        k = rnd.randrange(2, len(text))
        text = text[:k] + rnd.choice(["g", "Z", ":", " ", "-", "0"]) + text[k + 1:]
    elif r2 < 0.1 and len(text) > 3:
        text = text[:rnd.randrange(2, len(text))]
    cases.append(text)
for _ in range(500):
    p = rnd.randrange(0, 4)
    cases.append("S %d %s" % (p, " ".join(hh().hex() for _ in range(p + 1))))
a, b = [ref.run(c) for c in cases], run_tool(cases)
diff = [(c[:90], x, y) for c, x, y in zip(cases, a, b) if x != y]
kinds = {}
for x in a:
    kinds[x.split()[0] + (" " + x.split()[1] if x.startswith("error") else "")] = kinds.get(x.split()[0] + (" " + x.split()[1] if x.startswith("error") else ""), 0) + 1
check("%d random commands: statecheck and tools/state.py agree %s" % (len(cases), kinds), len(b) == len(a) and not diff, diff[:3])

print("\n%d checks failed" % len(FAILED) if FAILED else "\nall state checks passed")
sys.exit(1 if FAILED else 0)
