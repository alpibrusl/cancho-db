#!/usr/bin/env python3
"""The statement store rewrite (docs/m2g-erasure.md 6d, E4b): `store.rewrite_stmts` in cancho against `tools/erase_stmts.py`, and the crash points.

    python3 tests/erase_store_check.py build/erasecheck

For each version 3 store of `vectors/` that the Python verifier loads, and each text found in its payloads as a needle: the store the cancho rewrite leaves is byte for byte the one `tools/erase_stmts.py --containing`
makes, `tools/verify.py` still loads it with the same ids, and the number of records erased is the Python tool's. Then the crash points of one store: stopped after `stmts.new` is written, the store is
as it was and `store.open_store` removes the copy; stopped after the rename, the store is the new one; a store with a torn last record is `failed 2` (the open that follows cuts the tail, as at start); a missing store is `failed 1`.
"""
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import verify as v  # noqa: E402
import erase_stmts  # noqa: E402

EXE = sys.argv[1]
FAILED = []


def check(name, ok, detail=""):
    if not ok:
        print("FAIL %s   %s" % (name, str(detail)[:300]))
        FAILED.append(name)


def needles_hex(needles):
    return b"".join(struct.pack(">H", len(n)) + n for n in needles).hex()


def run(directory, needles, stop):
    r = subprocess.run([EXE, str(directory), str(stop)], input=needles_hex(needles) + "\n", capture_output=True, text=True)
    return r.stdout.split("\n")


def payload_texts(data):
    out, at = set(), 8
    while at < len(data):
        (n,) = struct.unpack(">I", data[at:at + 4])
        body = data[at + 4:at + 4 + n]
        at += 4 + n
        _, end, _ = v.infer_effects(body, v3=True)
        if body[end + 32] == 1:
            out.update(m.group(0) for m in re.finditer(rb"[A-Za-z@._ ]{4,}", body[end + 33:]))
    return out


cases = stores = 0
for f in sorted((ROOT / "vectors").glob("ir3_*.stmts")):
    data = f.read_bytes()
    try:
        before = v.load_stmts(data)
        texts = payload_texts(data)
    except Exception:
        continue
    stores += 1
    for needle in sorted(texts) or [b"zzzz-not-there"]:
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "stmts").write_bytes(data)
            out = run(d, [needle], 0)
            want, n = erase_stmts.erase(data, needle)
            got = (Path(d) / "stmts").read_bytes()
            cases += 1
            check("%s %r: the same store as erase_stmts.py" % (f.name, needle), got == want, out)
            check("%s %r: erased %d" % (f.name, needle, n), out[0] == "erased %d" % n and out[1] == "open ok", out)
            try:
                check("%s %r: the same ids" % (f.name, needle), v.load_stmts(got).keys() == before.keys())
            except Exception as e:
                check("%s %r: loads" % (f.name, needle), False, e)
            check("%s %r: no stale copy" % (f.name, needle), not (Path(d) / "stmts.new").exists())

# crash points, on the store with the most to erase
best = max((f for f in (ROOT / "vectors").glob("ir3_*.stmts") if f.read_bytes()[:8] == b"CHODBST3"), key=lambda f: len(payload_texts(f.read_bytes())) if f.name.startswith("ir3_ok") else -1)
data = best.read_bytes()
needle = sorted(payload_texts(data))[0]
want, n = erase_stmts.erase(data, needle)
check("the crash-point store has something to erase", n > 0 and want != data, best.name)
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "stmts").write_bytes(data)
    out = run(d, [needle], 1)
    check("stopped after stmts.new: the store is as it was", (Path(d) / "stmts").read_bytes() == data, out)
    check("... and open_store removed the copy", out[1] == "open ok" and not (Path(d) / "stmts.new").exists(), out)
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "stmts").write_bytes(data)
    (Path(d) / "stmts.new").write_bytes(b"half a store")
    out = run(d, [needle], 2)
    check("stopped after the rename: the store is the new one, and a stale copy did not matter", (Path(d) / "stmts").read_bytes() == want and not (Path(d) / "stmts.new").exists(), out)
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "stmts").write_bytes(b"CHODBST2" + data[8:])
    out = run(d, [needle], 0)
    check("a store with another magic is not rewritten by the version 3 walk (failed 2 or an unchanged store)", out[0].startswith("failed") or (Path(d) / "stmts").read_bytes()[:8] == b"CHODBST2", out)
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "stmts").write_bytes(data[:-3])
    out = run(d, [needle], 0)
    after = (Path(d) / "stmts").read_bytes()
    check("a store with a torn last record is failed 2, and nothing is erased (the open that follows cuts the torn tail, as at start)", out[0] == "failed 2" and data.startswith(after) and len(after) < len(data), out)
with tempfile.TemporaryDirectory() as d:
    out = run(d, [needle], 0)
    check("a directory with no store: failed 1", out[0] == "failed 1", out)
print("erase_store_check: %d stores, %d cases, %d failures" % (stores, cases, len(FAILED)))
sys.exit(1 if FAILED else 0)
