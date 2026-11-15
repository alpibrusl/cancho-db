#!/usr/bin/env python3
"""Second verifier: L1 of docs/spec/commit.md, written from that page alone (nothing here is taken from
tools/gen_vectors.py or src/verify.cho).

    verify.py LOG [--expect <64 hex digits>]

Prints exactly one line, `ok commits=N branches=B` or `reject rule=TAG record=I`. Exit 0 ok, 1 reject, 2 usage or an
unreadable file.
"""
import hashlib
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAGIC = b"CHODBLG1"
DOMAIN = b"cancho-db/commit/v1\x00"
MAX_RECORD = 16 * 1024 * 1024


class Reject(Exception):
    def __init__(self, rule, record=-1):
        self.rule, self.record = rule, record


class Reader:
    def __init__(self, data):
        self.d, self.at = data, 0

    def take(self, n):
        if n < 0 or self.at + n > len(self.d):
            raise Reject("bad-encoding")
        b = self.d[self.at:self.at + n]
        self.at += n
        return b

    def u8(self): return self.take(1)[0]
    def u16(self): return struct.unpack(">H", self.take(2))[0]
    def u32(self): return struct.unpack(">I", self.take(4))[0]
    def u64(self): return struct.unpack(">Q", self.take(8))[0]
    def b16(self): return self.take(self.u16())

    def count(self):
        n = self.u32()
        if n > len(self.d) - self.at:  # every element is at least one byte
            raise Reject("bad-encoding")
        return n


def decode(enc):
    """-> (branch, seq, parents). Raises Reject for anything §2 forbids."""
    r = Reader(enc)
    if r.u16() != 1:
        raise Reject("bad-version")
    parents = [r.take(32) for _ in range(r.count())]
    if len(parents) > 2:
        raise Reject("parent-count")
    branch = r.b16()
    if len(branch) == 0:
        raise Reject("branch-empty")
    if len(branch) > 255:
        raise Reject("bad-encoding")
    seq = r.u64()
    r.take(32)                                    # schema
    for _ in range(r.count()): r.take(32)         # statements
    last = None
    for _ in range(r.count()):                    # effects
        kind = r.u8()
        if kind > 4:
            raise Reject("bad-encoding")
        key = (kind, r.b16())
        if last is not None and not key > last:
            raise Reject("effects-unordered")
        last = key
    r.take(32); r.take(32)                        # token, principal
    for _ in range(r.count()): r.take(32)         # code
    for _ in range(r.count()):                    # nondet
        tag = r.u8()
        if tag == 0:
            pass
        elif tag == 1:
            r.take(8)
        elif tag == 2:
            r.take(r.u32())
        else:
            raise Reject("bad-encoding")
    r.take(32); r.take(32)                        # changes, state
    for _ in range(r.count()):                    # checks
        r.b16()
        if r.u8() > 1:
            raise Reject("bad-encoding")
    r.u64()                                       # time
    if r.at != len(enc):
        raise Reject("bad-encoding")
    return branch, seq, parents


def verify(data, expect):
    if len(data) < 8:
        raise Reject("truncated")
    if data[:8] != MAGIC:
        raise Reject("bad-magic")
    if len(data) < 40:
        raise Reject("truncated")
    server = Ed25519PublicKey.from_public_bytes(data[8:40])
    at, index = 40, 0
    seen, count, tip = set(), {}, {}
    while at < len(data):
        if len(data) - at < 4:
            raise Reject("truncated", index)
        (length,) = struct.unpack(">I", data[at:at + 4])
        if length > MAX_RECORD:
            raise Reject("record-too-large", index)
        if len(data) - at - 4 < length + 64:
            raise Reject("truncated", index)
        enc = data[at + 4:at + 4 + length]
        sig = data[at + 4 + length:at + 4 + length + 64]
        at += 4 + length + 64
        try:
            branch, seq, parents = decode(enc)
            ident = hashlib.sha256(DOMAIN + enc).digest()
            if ident in seen:
                raise Reject("duplicate-commit")
            try:
                server.verify(sig, ident)
            except InvalidSignature:
                raise Reject("bad-signature")
            if seq != count.get(branch, 0):
                raise Reject("seq-gap")
            if seq == 0:
                if len(parents) == 2:
                    raise Reject("parent-count")
                if parents and parents[0] not in seen:
                    raise Reject("parent-unknown")
            else:
                if len(parents) == 0:
                    raise Reject("parent-count")
                if parents[0] != tip[branch]:
                    raise Reject("parent-mismatch")
                if len(parents) == 2:
                    if parents[1] == parents[0]:
                        raise Reject("parent-count")
                    if parents[1] not in seen:
                        raise Reject("parent-unknown")
        except Reject as e:
            raise Reject(e.rule, index)
        seen.add(ident)
        count[branch] = seq + 1
        tip[branch] = ident
        index += 1
    if expect is not None and expect not in seen:
        raise Reject("expected-missing")
    return "ok commits=%d branches=%d" % (index, len(count))


def main(argv):
    usage = "usage: verify.py LOG [--expect <64 hex digits>]"
    path, expect, i = None, None, 1
    while i < len(argv):
        a = argv[i]
        if a == "--expect" and expect is None and i + 1 < len(argv):
            text = argv[i + 1]
            ok = len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text)
            if not ok:
                print(usage, file=sys.stderr)
                return 2
            expect = bytes.fromhex(text)
            i += 2
        elif not a.startswith("-") and path is None:
            path = a
            i += 1
        else:
            print(usage, file=sys.stderr)
            return 2
    if path is None:
        print(usage, file=sys.stderr)
        return 2
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print("verify.py: cannot read %s: %s" % (path, e.strerror), file=sys.stderr)
        return 2
    try:
        print(verify(data, expect))
        return 0
    except Reject as e:
        print("reject rule=%s record=%d" % (e.rule, e.record))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
