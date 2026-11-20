#!/usr/bin/env python3
"""`ir.lift` (docs/spec/ir.md section 8) against the Python verifier: every statement of every version 2 store under vectors/ goes through `liftcheck`; a statement it lifts must, put into a version 3 record
with a fixed salt, be accepted by tools/verify.py `v3_record` with the effects the version 2 record infers; a statement it refuses must be one the verifier refuses too.

    python3 tests/lift_check.py build/liftcheck
"""
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import verify as v  # noqa: E402

SALT = bytes(range(16))
records = []
for f in sorted((ROOT / "vectors").glob("*.stmts")):
    data = f.read_bytes()
    if data[:8] != b"CHODBST2":
        continue
    at = 8
    while len(data) - at >= 4:
        (n,) = struct.unpack(">I", data[at:at + 4])
        if len(data) - at - 4 < n:
            break
        records.append((f.name, data[at + 4:at + 4 + n]))
        at += 4 + n
out = subprocess.run([sys.argv[1]], input="".join(r.hex() + "\n" for _, r in records), capture_output=True, text=True).stdout.split("\n")
failed, lifted = 0, 0
for (name, rec), line in zip(records, out):
    try:
        want = v.infer_effects(rec, True)
        wf = want[0] if isinstance(want, tuple) else want
    except v.Reject:
        wf = None
    parts = line.split(" ")
    if parts and parts[0] == "ok":
        lifted += 1
        shape, vals, n = bytes.fromhex(parts[1]), bytes.fromhex(parts[2]), int(parts[3])
        chash = hashlib.sha256(v.CONSTS_DOMAIN + SALT + struct.pack(">I", n) + vals).digest()
        body = shape + chash + b"\x01" + SALT + struct.pack(">I", n) + vals
        try:
            _, eff = v.v3_record(body)
        except v.Reject as e:
            print("FAIL %s: lifted record refused: %s" % (name, e.rule))
            failed += 1
            continue
        if wf is None or eff != wf:
            print("FAIL %s: effects differ: %r vs %r" % (name, eff, wf))
            failed += 1
    elif wf is not None:
        print("FAIL %s: refused by lift but the verifier accepts it" % name)
        failed += 1
print("lift_check: %d statements, %d lifted, %d failures" % (len(records), lifted, failed))
sys.exit(1 if failed else 0)
