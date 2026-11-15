#!/usr/bin/env python3
"""Second verifier: L1 of docs/spec/commit.md, written from that page alone (nothing here is taken from
tools/gen_vectors.py or src/verify.cho).

    verify.py LOG [--expect <64 hex digits>] [--root <64 hex> --tokens FILE [--revoked FILE]]

L1 of docs/spec/commit.md, and with --root also L2 of docs/spec/token.md. Prints exactly one line, `ok commits=N
branches=B` (`... level=2` with --root) or `reject rule=TAG record=I`. Exit 0 ok, 1 reject, 2 usage or an unreadable
file.
"""
import hashlib
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAGIC = b"CHODBLG1"
DOMAIN = b"cancho-db/commit/v1\x00"
MAX_RECORD = 16 * 1024 * 1024
NO_EXPIRY = 2**64 - 1


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
    """-> (branch, seq, parents, info). Raises Reject for anything §2 forbids; info is what L2 needs."""
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
    effects = []
    for _ in range(r.count()):                    # effects
        kind = r.u8()
        if kind > 4:
            raise Reject("bad-encoding")
        key = (kind, r.b16())
        if last is not None and not key > last:
            raise Reject("effects-unordered")
        last = key
        effects.append(key)
    token = r.take(32)
    principal = r.take(32)
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
    time = r.u64()
    if r.at != len(enc):
        raise Reject("bad-encoding")
    return branch, seq, parents, (branch, principal, token, effects, time)


def verify(data, expect):
    """L1. -> (commits, branches, infos) or raises Reject."""
    if len(data) < 8:
        raise Reject("truncated")
    if data[:8] != MAGIC:
        raise Reject("bad-magic")
    if len(data) < 40:
        raise Reject("truncated")
    server_key = data[8:40]
    at, index = 40, 0
    seen, count, tip, infos = set(), {}, {}, []
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
            branch, seq, parents, info = decode(enc)
            ident = hashlib.sha256(DOMAIN + enc).digest()
            if ident in seen:
                raise Reject("duplicate-commit")
            if not sig_ok(server_key, sig, ident):
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
        infos.append(info)
        count[branch] = seq + 1
        tip[branch] = ident
        index += 1
    if expect is not None and expect not in seen:
        raise Reject("expected-missing")
    return index, len(count), infos


# ---------------------------------------------------------------- L2 (docs/spec/token.md)
TOKEN_DOMAIN = b"cancho-db/token/v1\x00"
BLOCK_DOMAIN = b"cancho-db/token-block/v1\x00"
REVOKE_DOMAIN = b"cancho-db/revoke/v1\x00"
ZERO32 = bytes(32)


def decode_token(enc):
    """-> list of blocks (principal, branch, effects, expiry, next_key, signature, payload bytes, whole block bytes)."""
    r = Reader(enc)
    blocks = []
    try:
        n = r.count()
        if n == 0:
            raise Reject("bad-encoding")
        for _ in range(n):
            start = r.at
            principal = r.take(32)
            branch = r.b16()
            effects, last = [], None
            for _ in range(r.count()):
                kind = r.u8()
                if kind > 4:
                    raise Reject("bad-encoding")
                key = (kind, r.b16())
                if last is not None and not key > last:
                    raise Reject("bad-encoding")
                last = key
                effects.append(key)
            expiry = r.u64()
            payload_end = r.at
            next_key = r.take(32)
            sig = r.take(64)
            blocks.append((principal, branch, effects, expiry, next_key, sig, enc[start:payload_end],
                           enc[start:r.at]))
        if r.at != len(enc):
            raise Reject("bad-encoding")
    except Reject:
        raise Reject("token-bad-encoding")
    return blocks


def prefix_id(blocks, k):
    return hashlib.sha256(TOKEN_DOMAIN + struct.pack(">I", k) + b"".join(b[7] for b in blocks[:k])).digest()


def pattern_matches(pattern, value):
    if pattern[-1:] == b"*":
        return value.startswith(pattern[:-1])
    return pattern == value


def sig_ok(pk, sig, message):
    """Ed25519 verification that answers False, never raises, for a key that is not a point."""
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def chain_valid(blocks, root):
    key = root
    for b in blocks:
        if not sig_ok(key, b[5], BLOCK_DOMAIN + b[6] + b[4]):
            return False
        key = b[4]
    return True


def block_permits_effect(block, effect):
    return any(k == effect[0] and pattern_matches(t, effect[1]) for k, t in block[2])


def l2_denial(blocks, root, info, revoked):
    """The first L2 rule the commit `info` breaks under the token `blocks`, or None. (§4, commit checks 2 to 7)"""
    branch, principal, _token, effects, time = info
    if not chain_valid(blocks, root):
        return "token-bad-signature"
    for k in range(1, len(blocks) + 1):
        since = revoked.get(prefix_id(blocks, k))
        if since is not None and since <= time:
            return "token-revoked"
    if any(b[3] != NO_EXPIRY and time > b[3] for b in blocks):
        return "token-expired"
    if any(b[0] != ZERO32 and b[0] != principal for b in blocks):
        return "principal-denied"
    if any(not pattern_matches(b[1], branch) for b in blocks):
        return "branch-denied"
    if any(not block_permits_effect(b, e) for b in blocks for e in effects):
        return "effect-denied"
    return None


def load_tokens(data):
    if len(data) < 8:
        raise Reject("tokens-truncated")
    if data[:8] != b"CHODBTK1":
        raise Reject("tokens-bad-magic")
    at, index, store = 8, 0, {}
    while at < len(data):
        if len(data) - at < 4:
            raise Reject("tokens-truncated", index)
        (length,) = struct.unpack(">I", data[at:at + 4])
        if len(data) - at - 4 < length:
            raise Reject("tokens-truncated", index)
        enc = data[at + 4:at + 4 + length]
        at += 4 + length
        try:
            blocks = decode_token(enc)
        except Reject as e:
            raise Reject(e.rule, index)
        store[prefix_id(blocks, len(blocks))] = blocks
        index += 1
    return store


def load_revoked(data, root):
    if len(data) < 8:
        raise Reject("revocations-truncated")
    if data[:8] != b"CHODBRV1":
        raise Reject("revocations-bad-magic")
    revoked, index = {}, 0
    for at in range(8, len(data), 104):
        if len(data) - at < 104:
            raise Reject("revocations-truncated", index)
        ident, since_b, sig = data[at:at + 32], data[at + 32:at + 40], data[at + 40:at + 104]
        if not sig_ok(root, sig, REVOKE_DOMAIN + ident + since_b):
            raise Reject("revocation-bad-signature", index)
        (since,) = struct.unpack(">Q", since_b)
        revoked[ident] = min(since, revoked.get(ident, since))
        index += 1
    return revoked


def verify_l2(infos, root, tokens_data, revoked_data):
    store = load_tokens(tokens_data)
    revoked = load_revoked(revoked_data, root) if revoked_data is not None else {}
    for index, info in enumerate(infos):
        blocks = store.get(info[2])
        why = "token-missing" if blocks is None else l2_denial(blocks, root, info, revoked)
        if why:
            raise Reject(why, index)


def main(argv):
    usage = "usage: verify.py LOG [--expect <64 hex digits>] [--root <64 hex digits> --tokens FILE [--revoked FILE]]"
    path, expect, root, tokens, revoked, i = None, None, None, None, None, 1

    def hex32(text):
        ok = len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text)
        return bytes.fromhex(text) if ok else None

    while i < len(argv):
        a = argv[i]
        if a in ("--expect", "--root") and i + 1 < len(argv) and (expect if a == "--expect" else root) is None:
            v = hex32(argv[i + 1])
            if v is None:
                print(usage, file=sys.stderr)
                return 2
            if a == "--expect":
                expect = v
            else:
                root = v
            i += 2
        elif a in ("--tokens", "--revoked") and i + 1 < len(argv) and (tokens if a == "--tokens" else revoked) is None:
            if a == "--tokens":
                tokens = argv[i + 1]
            else:
                revoked = argv[i + 1]
            i += 2
        elif not a.startswith("-") and path is None:
            path = a
            i += 1
        else:
            print(usage, file=sys.stderr)
            return 2
    if path is None or (root is None and (tokens is not None or revoked is not None)) or (
            root is not None and tokens is None):
        print(usage, file=sys.stderr)
        return 2
    try:
        with open(path, "rb") as f:
            data = f.read()
        tokens_data = open(tokens, "rb").read() if tokens else None
        revoked_data = open(revoked, "rb").read() if revoked else None
    except OSError as e:
        print("verify.py: cannot read %s: %s" % (e.filename, e.strerror), file=sys.stderr)
        return 2
    try:
        commits, branches, infos = verify(data, expect)
        if root is not None:
            verify_l2(infos, root, tokens_data, revoked_data)
        print("ok commits=%d branches=%d%s" % (commits, branches, " level=2" if root is not None else ""))
        return 0
    except Reject as e:
        print("reject rule=%s record=%d" % (e.rule, e.record))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
