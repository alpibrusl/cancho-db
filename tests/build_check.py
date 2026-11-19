#!/usr/bin/env python3
"""Checks src/build.cho (P2b) against an encoder written here from docs/spec/commit.md alone, and against the three verifiers.

    python3 tests/build_check.py build/buildcheck build/verify build/verify-go

For many random commits: `buildcheck` (cancho) must produce the same encoding, id, signature and public key as this file's own
encoder and `cryptography`'s Ed25519 (deterministic, so equal bytes). Then a chain of such commits is written as a log and the
cancho, Python and Go verifiers must each say `ok`; and one flipped byte in a record must be rejected by each. Refusals:
a field of the wrong size, a bad effect and a branch that is empty or too long answer `error`.
"""
import hashlib
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BUILD, *VERIFIERS = sys.argv[1:]
ROOT = Path(__file__).resolve().parent.parent
PY = ["python3", str(ROOT / "tools" / "verify.py")]
failures = 0


def check(name, ok, detail=""):
    global failures
    if not ok:
        failures += 1
        print("FAIL", name, detail)


def u16(n): return struct.pack(">H", n)
def u32(n): return struct.pack(">I", n)
def u64(n): return struct.pack(">Q", n)
def lst(items): return u32(len(items)) + b"".join(items)


def effect(kind, target): return bytes([kind]) + u16(len(target)) + target


def encode(c):
    effs = sorted({(k, t) for k, t in c["effects"]})
    return b"".join([
        u16(1), lst(c["parents"]), u16(len(c["branch"])) + c["branch"], u64(c["seq"]), c["schema"], lst(c["statements"]),
        lst([effect(k, t) for k, t in effs]), c["token"], c["principal"], lst(c["code"]), u32(len(c["nondet"])) + b"".join(c["nondet"]),
        c["changes"], c["state"], u32(len(c["checks"])) + b"".join(c["checks"]), u64(c["time"]),
    ])


def run(c, seed):
    lines = [
        seed.hex(), b"".join(c["parents"]).hex(), c["branch"].hex(), str(c["seq"]), c["schema"].hex(), b"".join(c["statements"]).hex(),
        b"".join(effect(k, t) for k, t in c["effects_raw"]).hex(), c["token"].hex(), c["principal"].hex(), b"".join(c["code"]).hex(),
        str(len(c["nondet"])), b"".join(c["nondet"]).hex(), c["changes"].hex(), c["state"].hex(), str(len(c["checks"])),
        b"".join(c["checks"]).hex(), str(c["time"]),
    ]
    out = subprocess.run([BUILD], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60).stdout.split("\n")
    return out


rng = random.Random(7)


def rb(n): return bytes(rng.randrange(256) for _ in range(n))


def random_commit(seq, parents):
    effects = []
    for _ in range(rng.randrange(0, 9)):
        kind = rng.randrange(5)
        target = bytes(rng.choice(b"abc.*:_/") for _ in range(rng.randrange(0, 6)))
        effects.append((kind, target))
    raw = effects + ([rng.choice(effects)] if effects and rng.random() < 0.5 else [])
    rng.shuffle(raw)
    nondet = [rng.choice([b"\x00", b"\x01" + struct.pack(">q", rng.randrange(-2**40, 2**40)), b"\x02" + u32(3) + rb(3)])
              for _ in range(rng.randrange(0, 3))]
    return {
        "parents": parents, "branch": bytes(rng.choice(b"main/dev-x") for _ in range(rng.randrange(1, 12))), "seq": seq,
        "schema": rb(32), "statements": [rb(32) for _ in range(rng.randrange(0, 4))], "effects": effects, "effects_raw": raw,
        "token": rb(32), "principal": rb(32), "code": [rb(32) for _ in range(rng.randrange(0, 2))], "nondet": nondet,
        "changes": rb(32), "state": rb(32), "checks": [u16(2) + b"ok" + bytes([rng.randrange(2)]) for _ in range(rng.randrange(0, 3))],
        "time": rng.randrange(0, 2**40),
    }


seed = rb(32)
sk = Ed25519PrivateKey.from_private_bytes(seed)
pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
DOMAIN = b"cancho-db/commit/v1\x00"

records = []
parents = []
branch = b"main"
for i in range(120):
    c = random_commit(i, parents)
    c["branch"] = branch
    out = run(c, seed)
    enc = encode(c)
    cid = hashlib.sha256(DOMAIN + enc).digest()
    check("case %d: encoding" % i, out[0] == enc.hex(), "%s\n%s" % (out[0], enc.hex()))
    check("case %d: id" % i, out[1] == cid.hex())
    check("case %d: signature" % i, out[2] == sk.sign(cid).hex())
    check("case %d: public key" % i, out[3] == pk.hex())
    check("case %d: log" % i, out[4] == (b"CHODBLG1" + pk + u32(len(enc)) + enc + sk.sign(cid)).hex())
    check("case %d: token store" % i, out[5] == (b"CHODBTK1" + u32(32) + c["token"]).hex())
    check("case %d: statement store" % i, out[6] == (b"CHODBST3" + u32(32 * len(c["statements"])) + b"".join(c["statements"])).hex())
    if out[0] == enc.hex() and out[2] == sk.sign(cid).hex():
        records.append(u32(len(enc)) + enc + bytes.fromhex(out[2]))
        parents = [cid]

# a chain written as a log: every verifier says ok, and one flipped byte in a record is rejected by every verifier
header = b"CHODBLG1" + pk
good = header + b"".join(records)
bad = bytearray(good)
bad[40 + 10] ^= 1
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "good.log").write_bytes(good)
    (Path(d) / "bad.log").write_bytes(bytes(bad))
    for name, argv in [("python", PY)] + [("verifier %s" % v, [v]) for v in VERIFIERS]:
        r = subprocess.run(argv + [str(Path(d) / "good.log")], capture_output=True, text=True).stdout.strip()
        check("%s accepts the chain" % name, r == "ok commits=%d branches=1" % len(records), r)
        r = subprocess.run(argv + [str(Path(d) / "bad.log")], capture_output=True, text=True).stdout.strip()
        check("%s rejects a flipped byte" % name, r.startswith("reject"), r)

# a sequence number and a time that do not fit in 32 bits
for i, (sq, tm) in enumerate([(2**32 + 5, 2**41 + 7), (2**40 + 1, 2**33)]):
    c = random_commit(sq, [])
    c["time"] = tm
    out = run(c, seed)
    check("wide seq/time %d: encoding" % i, out[0] == encode(c).hex())

# refusals
base = random_commit(0, [])
for name, edit in [
    ("empty branch", lambda c: c.update(branch=b"")),
    ("branch of 256 bytes", lambda c: c.update(branch=b"x" * 256)),
    ("schema of 31 bytes", lambda c: c.update(schema=rb(31))),
    ("three parents' worth of bytes is allowed, but not 3 parents of 31", lambda c: c.update(parents=[rb(31), rb(32)])),
    ("effect kind 5", lambda c: c.update(effects_raw=[(5, b"x")])),
]:
    c = dict(base)
    edit(c)
    out = run(c, seed)
    check("refused: " + name, out[0] == "error", out[0][:60])

print("build_check: %d failures" % failures)
sys.exit(1 if failures else 0)
