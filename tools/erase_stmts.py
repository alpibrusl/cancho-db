#!/usr/bin/env python3
"""Erase the constants of statement records in a version 3 statement store (docs/spec/ir.md section 8, docs/m2g-erasure.md D-E7).

    python3 tools/erase_stmts.py STORE OUTPUT [--containing TEXT]

Every record of STORE (magic `CHODBST3`) whose payload holds TEXT (as bytes), or every record without `--containing`, is written to OUTPUT with its payload erased: the shape and the hash of the constants stay, the salt and the
constants go. The ids do not change, so the log's `stmts` hashes and L2 over the new store are as before. Offline: STORE must not be open for append by a running proxy (the proxy's own erasure, E4, is a later slice).
Prints how many records were erased.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify as v  # noqa: E402


def erase(data, needle=None):
    if data[:8] != b"CHODBST3":
        raise SystemExit("erase_stmts: not a version 3 statement store")
    out, at, erased = [data[:8]], 8, 0
    while at < len(data):
        (n,) = struct.unpack(">I", data[at:at + 4])
        body = data[at + 4:at + 4 + n]
        at += 4 + n
        _, end, _ = v.infer_effects(body, v3=True)
        payload = body[end + 33:]
        if body[end + 32] == 1 and (needle is None or needle in payload):
            body = body[:end + 32] + b"\x00"
            erased += 1
        out.append(struct.pack(">I", len(body)) + body)
    return b"".join(out), erased


def main(argv):
    if len(argv) < 3 or (len(argv) > 3 and (argv[3] != "--containing" or len(argv) != 5)):
        print(__doc__, file=sys.stderr)
        return 2
    needle = argv[4].encode() if len(argv) == 5 else None
    data, n = erase(Path(argv[1]).read_bytes(), needle)
    Path(argv[2]).write_bytes(data)
    print("erased %d record(s)" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
