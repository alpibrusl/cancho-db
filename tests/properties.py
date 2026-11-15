#!/usr/bin/env python3
"""Property test for docs/spec/token.md section 5: appending a block never widens a token.

    properties.py [CASES] [SEED]

Random chains of random blocks (patterns, principals, expiries) and random commits, built with real signatures and
judged by the Python verifier's own L2 rules (tools/verify.py). For every token and every commit:

  * if the whole token allows the commit, so does every prefix of it (attenuation cannot widen);
  * a prefix of a token that decoded and verified still decodes and verifies (the property holds for what is stored);
  * a token revoked at some prefix is revoked.

A property that never fires proves nothing, so the run also counts the cases where the full token allowed the commit
and where a prefix allowed it and the full token did not, and fails if either is rare.
"""
import importlib.util
import random
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("verify_py", ROOT / "tools/verify.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

NONE = 2**64 - 1


def newkey(rng):
    sk = Ed25519PrivateKey.from_private_bytes(bytes(rng.randrange(256) for _ in range(32)))
    return sk, sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b16(b): return struct.pack(">H", len(b)) + b


# a small alphabet so that patterns collide often: matches and misses both happen
BRANCHES = [b"main", b"main2", b"agent/a", b"agent/b", b"agent/", b""]
BRANCH_PATTERNS = [b"*", b"main", b"main*", b"agent/*", b"agent/a", b"agent/b", b"", b"zzz"]
TARGETS = [b"orders", b"orders.id", b"orders.total", b"users", b"", b"fn.refund"]
TARGET_PATTERNS = [b"*", b"orders", b"orders.*", b"users", b"", b"fn.*", b"o*"]
TIMES = [0, 5, 10, 2**32 - 1, 2**32, 2**63, NONE - 1, NONE]


def random_block_spec(rng, principals):
    """Mostly permissive blocks, sometimes a narrow one, so a long token still allows a commit often enough."""
    permissive = rng.random() < 0.65
    return dict(
        principal=bytes(32) if permissive or rng.random() < 0.5 else rng.choice(principals),
        branch=rng.choice([b"*", b"*", b"main*", b"agent/*"]) if permissive else rng.choice(BRANCH_PATTERNS),
        effects=sorted(set((k, t) for k in range(5) for t in [b"*"])) if permissive and rng.random() < 0.5
        else sorted(set((rng.randrange(5), rng.choice(TARGET_PATTERNS)) for _ in range(rng.randrange(0, 6)))),
        expiry=NONE if permissive or rng.random() < 0.5 else rng.choice(TIMES),
    )


def encode_block(spec, next_pk, signer):
    payload = (spec["principal"] + b16(spec["branch"])
               + struct.pack(">I", len(spec["effects"]))
               + b"".join(bytes([k]) + b16(t) for k, t in spec["effects"])
               + struct.pack(">Q", spec["expiry"]))
    return payload + next_pk + signer.sign(v.BLOCK_DOMAIN + payload + next_pk)


def main(argv):
    cases = int(argv[1]) if len(argv) > 1 else 3000
    seed = int(argv[2]) if len(argv) > 2 else 1
    rng = random.Random(seed)
    root_sk, root_pk = newkey(rng)
    principals = [newkey(rng)[1] for _ in range(3)]
    stats = dict(full_allowed=0, prefix_allowed_full_denied=0, checked=0, revoked=0)
    for n in range(cases):
        signer, blocks = root_sk, []
        for _ in range(rng.randrange(1, 6)):
            nsk, npk = newkey(rng)
            blocks.append(encode_block(random_block_spec(rng, principals), npk, signer))
            signer = nsk
        encoding = struct.pack(">I", len(blocks)) + b"".join(blocks)
        decoded = v.decode_token(encoding)
        assert len(decoded) == len(blocks)
        info = (rng.choice(BRANCHES), rng.choice(principals + [bytes(32)]), None,
                sorted(set((rng.randrange(5), rng.choice(TARGETS)) for _ in range(rng.randrange(0, 4)))),
                rng.choice(TIMES))
        revoked = {}
        if rng.random() < 0.3:
            k = rng.randrange(1, len(blocks) + 1)
            revoked[v.prefix_id(decoded, k)] = rng.choice(TIMES)
        denials = [v.l2_denial(decoded[:k], root_pk, info, revoked) for k in range(1, len(decoded) + 1)]
        # every prefix is itself a token that decodes and verifies
        for k in range(1, len(decoded) + 1):
            again = v.decode_token(struct.pack(">I", k) + b"".join(blocks[:k]))
            assert v.chain_valid(again, root_pk), "case %d: prefix %d does not verify" % (n, k)
        stats["checked"] += 1
        # attenuation cannot widen: allowed with k+1 blocks implies allowed with k blocks (a revocation is not a grant,
        # so it is judged separately below)
        for k in range(1, len(denials)):
            if denials[k] is None and denials[k - 1] is not None:
                print("FAIL case %d: allowed with %d blocks, denied (%s) with %d; blocks=%r info=%r revoked=%r" % (
                    n, k + 1, denials[k - 1], k, [d[:4] for d in decoded], info, revoked))
                return 1
        if denials[-1] is None:
            stats["full_allowed"] += 1
        if any(d is None for d in denials[:-1]) and denials[-1] is not None:
            stats["prefix_allowed_full_denied"] += 1
        # revoked at a prefix means revoked for every longer token, and for the token itself
        if revoked:
            stats["revoked"] += 1
            (ident, since), = revoked.items()
            for k in range(1, len(decoded) + 1):
                if v.prefix_id(decoded, k) == ident:
                    for j in range(k, len(decoded) + 1):
                        d = v.l2_denial(decoded[:j], root_pk, info, revoked)
                        if info[4] >= since and d != "token-revoked":
                            print("FAIL case %d: revoked at prefix %d but %d blocks gave %r" % (n, k, j, d))
                            return 1
    print("properties: %d cases, seed %d: %s" % (cases, seed, ", ".join("%s=%d" % kv for kv in stats.items())))
    if stats["full_allowed"] < cases // 50 or stats["prefix_allowed_full_denied"] < cases // 50:
        print("FAIL: the property was rarely exercised; the alphabet no longer produces both outcomes")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
