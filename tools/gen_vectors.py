#!/usr/bin/env python3
"""Writes vectors/: the golden test vectors of docs/spec/commit.md.

Every vector is NAME.log (input), NAME.expect (the exact line a verifier must print) and, when the case needs
arguments, NAME.args. The expected verdict of each case is written *here, by hand, from the spec's rules*; it is never
copied from a verifier's output, or the vectors would test nothing but the verifier's agreement with itself.

Ed25519 is deterministic (RFC 8032), and the keys are derived from fixed strings, so the output is byte-for-byte
reproducible: CI regenerates into a scratch directory and diffs it against the committed one.

    python3 tools/gen_vectors.py [OUT_DIR]        # default: vectors/

The encoder below is this generator's own and is *not* the verifier's decoder. It is allowed to produce non-canonical
bytes on purpose (see `raw` and the `bad_*` cases), which a conforming encoder never would.
"""
import hashlib
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAGIC = b"CHODBLG1"
DOMAIN = b"cancho-db/commit/v1\x00"


def key(name):
    seed = hashlib.sha256(b"cancho-db test key: " + name.encode()).digest()
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, pk


SERVER, SERVER_PK = key("server")
OTHER, OTHER_PK = key("other")


def h(label):
    """A made-up 32-byte hash that is nobody's output, named so a vector reads."""
    return hashlib.sha256(b"cancho-db test value: " + label.encode()).digest()


def u16(n): return struct.pack(">H", n)
def u32(n): return struct.pack(">I", n)
def u64(n): return struct.pack(">Q", n)


def b16(b): return u16(len(b)) + b
def b32(b): return u32(len(b)) + b


def lst(items): return u32(len(items)) + b"".join(items)


def effect(kind, target): return bytes([kind]) + b16(target)


def value_null(): return b"\x00"
def value_int(n): return b"\x01" + struct.pack(">q", n)
def value_bytes(b): return b"\x02" + b32(b)


def check(name, ok): return b16(name) + bytes([ok])


def commit(branch=b"main", seq=0, parents=(), version=1, schema=None, statements=(), effects=(), token=None,
           principal=None, code=(), nondet=(), changes=None, state=None, checks=(), time=1_700_000_000_000):
    """The canonical encoding of a commit. Arguments that are already encoded bytes go in as bytes."""
    return b"".join([
        u16(version),
        lst(parents),
        b16(branch),
        u64(seq),
        schema or h("schema"),
        lst(statements),
        lst(effects),
        token or h("token"),
        principal or h("principal"),
        lst(code),
        lst(nondet),
        changes or h("changes:%s:%d" % (branch.decode(), seq)),
        state or h("state:%s:%d" % (branch.decode(), seq)),
        lst(checks),
        u64(time),
    ])


def cid(enc): return hashlib.sha256(DOMAIN + enc).digest()


def record(enc, sk=SERVER, length=None, sig=None):
    """One log record. `length` and `sig` can be forced to make a malformed one."""
    if sig is None:
        sig = sk.sign(cid(enc))
    return u32(len(enc) if length is None else length) + enc + sig


def log(*records, pk=SERVER_PK, magic=MAGIC):
    return magic + pk + b"".join(records)


class Chain:
    """Builds valid commits and remembers ids, so a vector can name a parent."""

    def __init__(self):
        self.tip = {}
        self.n = {}
        self.encs = []

    def add(self, branch, parents=None, **kw):
        b = branch.encode()
        seq = self.n.get(b, 0)
        if parents is None:
            parents = [self.tip[b]] if b in self.tip else []
        enc = commit(branch=b, seq=seq, parents=parents, **kw)
        self.encs.append(enc)
        self.tip[b] = cid(enc)
        self.n[b] = seq + 1
        return enc


def main_chain(n):
    c = Chain()
    for _ in range(n):
        c.add("main")
    return c


def rejects(rule, at): return "reject rule=%s record=%d" % (rule, at)


V = {}  # name -> (log bytes, expect line, args, {suffix: bytes})


def vec(name, data, expect, args="", files=None):
    assert name not in V, name
    V[name] = (data, expect, args, files or {})


# ------------------------------------------------------------------ valid
vec("ok_empty", log(), "ok commits=0 branches=0")

c = main_chain(1)
vec("ok_root", log(*[record(e) for e in c.encs]), "ok commits=1 branches=1")

c = main_chain(3)
chain3 = c
vec("ok_chain3", log(*[record(e) for e in c.encs]), "ok commits=3 branches=1")

# A fork: `feature` starts from main's second commit.
c = Chain()
c.add("main"); c.add("main")
c.add("feature", parents=[c.tip[b"main"]]); c.add("feature")
vec("ok_fork", log(*[record(e) for e in c.encs]), "ok commits=4 branches=2")

# A merge: main takes feature's tip as a second parent.
c = Chain()
c.add("main"); c.add("main")
c.add("feature", parents=[c.tip[b"main"]])
c.add("main", parents=[c.tip[b"main"], c.tip[b"feature"]])
vec("ok_merge", log(*[record(e) for e in c.encs]), "ok commits=4 branches=2")

# Two roots: two branches that share no history.
c = Chain()
c.add("a"); c.add("b"); c.add("a")
vec("ok_two_roots", log(*[record(e) for e in c.encs]), "ok commits=3 branches=2")

# Every field populated, every effect kind, every value tag, a check of each outcome, a long branch name.
c = Chain()
c.add("agent-7/" + "x" * 240,
      statements=[h("stmt1"), h("stmt2")],
      effects=[effect(k, t) for k, t in sorted([(0, b"orders.id"), (0, b"orders.total"), (1, b"orders"),
                                                (2, b"orders"), (3, b"refund"), (4, b""), (0, b"orders")])],
      code=[h("fn:refund")],
      nondet=[value_null(), value_int(-1), value_int(2**63 - 1), value_bytes(b""), value_bytes(b"\x00\xff abc")],
      checks=[check(b"orders_total_positive", 1), check(b"fk_customer", 0), check(b"", 1)])
vec("ok_all_fields", log(*[record(e) for e in c.encs]), "ok commits=1 branches=1")

# Effects order is by (kind, target) as unsigned bytes, a prefix first. The order is stated here as tuples, not by
# sorting the encodings (a length prefix would change it), and asserted against Python's own bytes ordering.
ordered = [(0, b"a"), (0, b"a\x00"), (0, b"ab"), (0, b"\xff"), (1, b""), (4, b"z")]
assert ordered == sorted(ordered)
c = Chain()
c.add("main", effects=[effect(k, t) for k, t in ordered])
vec("ok_effects_order", log(*[record(e) for e in c.encs]), "ok commits=1 branches=1")

# Tail pinning, `--expect`.
tip3 = chain3.tip[b"main"].hex()
vec("ok_expect_tip", log(*[record(e) for e in chain3.encs]), "ok commits=3 branches=1", "--expect " + tip3)
vec("ok_expect_early", log(*[record(e) for e in chain3.encs]), "ok commits=3 branches=1",
    "--expect " + cid(chain3.encs[0]).hex())
vec("expected_missing", log(*[record(e) for e in chain3.encs]), rejects("expected-missing", -1), "--expect " + "00" * 32)
# The end of a log removed: the prefix verifies on its own, and fails against the id the reader held.
vec("truncated_tail_ok_alone", log(*[record(e) for e in chain3.encs[:2]]), "ok commits=2 branches=1")
vec("truncated_tail_pinned", log(*[record(e) for e in chain3.encs[:2]]), rejects("expected-missing", -1),
    "--expect " + tip3)
# The expected id is only judged after every record has passed.
c = Chain(); c.add("main"); c.add("main")
bad = log(record(c.encs[0]), record(c.encs[1], sig=bytes(64)))
vec("expected_after_records", bad, rejects("bad-signature", 1), "--expect " + "00" * 32)

# ---------------------------------------------------------------- framing
good = log(*[record(e) for e in chain3.encs])
vec("bad_magic", b"CHODBLG2" + good[8:], rejects("bad-magic", -1))
vec("empty_file", b"", rejects("truncated", -1))
vec("short_file_prefix_of_magic", MAGIC[:5], rejects("truncated", -1))
vec("truncated_header", good[:20], rejects("truncated", -1))
vec("truncated_header_no_records", (MAGIC + SERVER_PK)[:39], rejects("truncated", -1))
r0 = record(chain3.encs[0])
vec("truncated_length_field", log(r0)[:40 + len(r0)] + b"\x00\x00", rejects("truncated", 1))
vec("truncated_body", good[:-70], rejects("truncated", 2))
vec("truncated_signature", good[:-1], rejects("truncated", 2))
vec("record_too_large", log(r0, u32(16 * 1024 * 1024 + 1)), rejects("record-too-large", 1))
vec("record_too_large_wins_over_truncated", log(u32(0xFFFFFFFF)), rejects("record-too-large", 0))
vec("max_record_is_truncated_not_too_large", log(u32(16 * 1024 * 1024) + b"\x00" * 10), rejects("truncated", 0))
vec("bad_magic_before_anything", b"XXXXXXXX" + b"\x00" * 3, rejects("bad-magic", -1))

# --------------------------------------------------------------- decoding
e = chain3.encs[0]
vec("bad_version_2", log(record(commit(version=2))), rejects("bad-version", 0))
vec("bad_version_0", log(record(commit(version=0))), rejects("bad-version", 0))
vec("bad_version_unsigned", log(record(commit(version=2), sig=bytes(64))), rejects("bad-version", 0))
vec("trailing_byte", log(record(e + b"\x00")), rejects("bad-encoding", 0))
vec("length_short_by_one", log(u32(len(e) - 1) + e[:-1] + SERVER.sign(cid(e[:-1]))), rejects("bad-encoding", 0))
vec("empty_record", log(record(b"")), rejects("bad-encoding", 0))
vec("one_byte_record", log(record(b"\x00")), rejects("bad-encoding", 0))
vec("version_only", log(record(u16(1))), rejects("bad-encoding", 0))

# A count that claims more than the record holds (and one that would overflow a 32-bit multiplication).
for name, count in [("count_overrun", 1000), ("count_huge", 0xFFFFFFFF), ("count_overflow", 0x20000001)]:
    enc = (u16(1) + u32(count))  # parents: claims `count` hashes, holds none
    vec("parents_" + name, log(record(enc)), rejects("bad-encoding", 0))
nd = (u16(1) + lst([]) + b16(b"main") + u64(0) + h("s") + lst([]) + lst([]) + h("t") + h("p") + lst([]) + u32(0xFFFFFFFF))
vec("nondet_count_huge", log(record(nd)), rejects("bad-encoding", 0))

vec("parents_three", log(record(commit(parents=[h("1"), h("2"), h("3")]))), rejects("parent-count", 0))
# the count is checked against the bytes left before it is checked against 2
vec("parents_three_but_short", log(record(u16(1) + u32(3) + h("1") + h("2"))), rejects("bad-encoding", 0))
# a record is judged when it is reached: an early decode failure beats a later truncation
vec("decode_error_before_later_truncation", log(record(commit(version=9)), r0, r0)[:-5], rejects("bad-version", 0))
vec("effects_unordered_before_later_malformed",
    log(record(commit(effects=[effect(1, b"t"), effect(0, b"t")]) + b"\x00")), rejects("effects-unordered", 0))
vec("branch_empty", log(record(commit(branch=b""))), rejects("branch-empty", 0))
vec("branch_256", log(record(commit(branch=b"x" * 256))), rejects("bad-encoding", 0))
vec("branch_255_ok", log(record(commit(branch=b"x" * 255))), "ok commits=1 branches=1")
vec("branch_len_overrun", log(record(u16(1) + lst([]) + u16(60000) + b"main")), rejects("bad-encoding", 0))
vec("effect_kind_5", log(record(commit(effects=[effect(5, b"t")]))), rejects("bad-encoding", 0))
vec("effect_kind_255", log(record(commit(effects=[effect(255, b"t")]))), rejects("bad-encoding", 0))
vec("value_tag_3", log(record(commit(nondet=[b"\x03"]))), rejects("bad-encoding", 0))
vec("value_int_short", log(record(commit(nondet=[b"\x01\x00\x00"]))), rejects("bad-encoding", 0))
vec("value_bytes_overrun", log(record(commit(nondet=[b"\x02" + u32(99) + b"ab"]))), rejects("bad-encoding", 0))
vec("check_ok_2", log(record(commit(checks=[check(b"c", 2)]))), rejects("bad-encoding", 0))
vec("check_ok_255", log(record(commit(checks=[check(b"c", 255)]))), rejects("bad-encoding", 0))
vec("effects_swapped", log(record(commit(effects=[effect(1, b"t"), effect(0, b"t")]))),
    rejects("effects-unordered", 0))
vec("effects_target_swapped", log(record(commit(effects=[effect(0, b"b"), effect(0, b"a")]))),
    rejects("effects-unordered", 0))
vec("effects_duplicate", log(record(commit(effects=[effect(0, b"a"), effect(0, b"a")]))),
    rejects("effects-unordered", 0))
vec("effects_prefix_after", log(record(commit(effects=[effect(0, b"ab"), effect(0, b"a")]))),
    rejects("effects-unordered", 0))
# A decode failure on a later record is reported at that record.
vec("decode_error_second", log(record(chain3.encs[0]), record(commit(version=9))), rejects("bad-version", 1))
# Decoding precedes the signature check: an invalid commit with a good signature and one with none say the same.
vec("decode_before_signature", log(record(commit(effects=[effect(5, b"t")]), sig=bytes(64))),
    rejects("bad-encoding", 0))

# ----------------------------------------------------------- duplicate/sig
vec("duplicate_commit", log(r0, r0), rejects("duplicate-commit", 1))
vec("duplicate_not_adjacent", log(*[record(e) for e in chain3.encs], r0), rejects("duplicate-commit", 3))

recs = [record(e) for e in chain3.encs]


def flip(rec, at):
    b = bytearray(rec)
    b[at] ^= 1
    return bytes(b)


vec("sig_flipped_bit", log(recs[0], flip(recs[1], len(recs[1]) - 1), recs[2]), rejects("bad-signature", 1))
vec("sig_zero", log(recs[0], record(chain3.encs[1], sig=bytes(64))), rejects("bad-signature", 1))
vec("body_flipped_state", log(recs[0], flip(recs[1], 4 + len(chain3.encs[1]) - 20), recs[2]),
    rejects("bad-signature", 1))
vec("body_flipped_time", log(recs[0], recs[1], flip(recs[2], 4 + len(chain3.encs[2]) - 1)),
    rejects("bad-signature", 2))
vec("body_flipped_schema", log(flip(recs[0], 4 + 25)), rejects("bad-signature", 0))  # root: schema is at 20..52
vec("signed_by_other_key", log(recs[0], record(chain3.encs[1], sk=OTHER)), rejects("bad-signature", 1))
vec("log_key_is_other", log(*recs, pk=OTHER_PK), rejects("bad-signature", 0))
vec("signature_over_encoding_not_id", log(record(chain3.encs[0], sig=SERVER.sign(chain3.encs[0]))),
    rejects("bad-signature", 0))
vec("signature_without_domain", log(record(chain3.encs[0],
                                           sig=SERVER.sign(hashlib.sha256(chain3.encs[0]).digest()))),
    rejects("bad-signature", 0))
# A record signed by another key *and* otherwise broken fails on the signature, before the chain rules.
vec("signature_before_seq", log(record(commit(seq=5), sk=OTHER)), rejects("bad-signature", 0))

# -------------------------------------------------------------- sequence
vec("seq_starts_at_1", log(record(commit(seq=1))), rejects("seq-gap", 0))
c = Chain(); c.add("main")
vec("seq_skips", log(record(c.encs[0]), record(commit(seq=2, parents=[c.tip[b"main"]]))), rejects("seq-gap", 1))
vec("seq_repeats", log(record(c.encs[0]), record(commit(seq=0, parents=[], state=h("other")))),
    rejects("seq-gap", 1))
vec("seq_goes_back", log(record(chain3.encs[0]), record(chain3.encs[1]), record(commit(seq=0, state=h("x")))),
    rejects("seq-gap", 2))
vec("records_reordered", log(recs[1], recs[0], recs[2]), rejects("seq-gap", 0))
vec("record_dropped", log(recs[0], recs[2]), rejects("seq-gap", 1))
# `seq` is per branch: another branch's count does not satisfy it.
c = Chain(); c.add("main"); c.add("main")
vec("seq_is_per_branch", log(record(c.encs[0]), record(c.encs[1]), record(commit(branch=b"other", seq=2))),
    rejects("seq-gap", 2))
vec("seq_max_u64", log(record(commit(seq=2**64 - 1))), rejects("seq-gap", 0))
# A u64: a verifier that kept only the low 32 bits would take these for seq 0 and seq 1.
vec("seq_2_pow_32", log(record(commit(seq=2**32))), rejects("seq-gap", 0))
vec("seq_2_pow_32_plus_next", log(record(chain3.encs[0]), record(commit(seq=2**32 + 1, parents=[cid(chain3.encs[0])]))),
    rejects("seq-gap", 1))

# --------------------------------------------------------------- parents
c = Chain(); c.add("main"); c.add("main")
vec("parent_mismatch", log(record(c.encs[0]), record(commit(seq=1, parents=[h("not the tip")]))),
    rejects("parent-mismatch", 1))
# parents[0] is a real commit, but not the branch's previous one.
c = Chain(); c.add("main"); c.add("main")
wrong = c.encs[0]
vec("parent_is_older_commit", log(*[record(e) for e in c.encs],
                                  record(commit(seq=2, parents=[cid(wrong)]))), rejects("parent-mismatch", 2))
c = Chain(); c.add("main"); c.add("other")
vec("parent_is_other_branch_tip", log(*[record(e) for e in c.encs],
                                      record(commit(seq=1, parents=[c.tip[b"other"]]))),
    rejects("parent-mismatch", 2))
vec("seq1_no_parents", log(record(chain3.encs[0]), record(commit(seq=1, parents=[]))), rejects("parent-count", 1))
vec("fork_unknown_parent", log(record(commit(branch=b"f", seq=0, parents=[h("nowhere")]))),
    rejects("parent-unknown", 0))
vec("fork_from_later_commit", log(record(commit(branch=b"f", seq=0, parents=[cid(chain3.encs[1])])),
                                  *[record(e) for e in chain3.encs]), rejects("parent-unknown", 0))
vec("root_two_parents", log(record(chain3.encs[0]), record(commit(branch=b"f", seq=0, parents=[cid(chain3.encs[0]),
                                                                                               h("z")]))),
    rejects("parent-count", 1))
c = Chain(); c.add("main")
vec("merge_unknown_second_parent", log(record(c.encs[0]),
                                       record(commit(seq=1, parents=[c.tip[b"main"], h("nowhere")]))),
    rejects("parent-unknown", 1))
vec("merge_same_parent_twice", log(record(c.encs[0]), record(commit(seq=1, parents=[c.tip[b"main"]] * 2))),
    rejects("parent-count", 1))
vec("merge_mismatched_first", log(record(c.encs[0]), record(commit(branch=b"o", seq=0)),
                                  record(commit(seq=1, parents=[cid(commit(branch=b"o", seq=0)), c.tip[b"main"]]))),
    rejects("parent-mismatch", 2))

# A fork may point at any earlier commit of any branch, including the very previous record.
c = Chain(); c.add("main")
c.add("f", parents=[c.tip[b"main"]])
vec("ok_fork_from_previous_record", log(*[record(e) for e in c.encs]), "ok commits=2 branches=2")

# The first failure is the verdict: two faults, the earlier record wins; one record with two faults, the earlier rule.
vec("first_failure_wins", log(recs[0], record(commit(seq=7), sk=OTHER), record(commit(version=3))),
    rejects("bad-signature", 1))


def write(out):
    out.mkdir(parents=True, exist_ok=True)
    for old in out.iterdir():
        if old.suffix in (".log", ".expect", ".args", ".tokens", ".revoked"):
            old.unlink()
    for name, (data, expect, args, files) in sorted(V.items()):
        (out / (name + ".log")).write_bytes(data)
        (out / (name + ".expect")).write_text(expect + "\n")
        if args:
            (out / (name + ".args")).write_text(args + "\n")
        for suffix, blob in files.items():
            (out / (name + suffix)).write_bytes(blob)
    return len(V)


if __name__ == "__main__":
    import gen_l2
    gen_l2.add(sys.modules[__name__])
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "vectors"
    print("wrote %d vectors to %s" % (write(target), target))
