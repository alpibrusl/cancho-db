#!/usr/bin/env python3
"""Reference for docs/spec/state.md: the leaf of a fact, `changes` over a commit's facts, and `state` over parents' states.

    python3 tools/state.py            reads commands from standard input, one per line, writes one result line each
    python3 tools/state.py --vectors  writes the golden cases (tests/state_cases.txt) to standard output

Commands:   C FACT ...   FACT = kind:table:pk:old:new, hex fields, `-` for an absent hash   ->  ok HEX | error RULE
            S P PARENT... CHANGES   (all hex)                                              ->  ok HEX

Written from the spec only. The same author wrote src/state.cho, so agreement between them shows the two do the same thing on the cases,
not that the spec was read independently (docs/m2-branches.md, D13: the second reader is still to come).
"""
import hashlib
import random
import struct
import sys

ZERO = bytes(32)


def sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def fact_encoding(kind, table, pk, old, new):
    """The bytes of a fact (spec section 2), or the rule it breaks."""
    if kind not in (0, 1, 2):
        return "fact-kind"
    if not 1 <= len(table) <= 255:
        return "fact-table"
    if not 1 <= len(pk) <= 65535:
        return "fact-pk"
    present = {0: (False, True), 1: (True, True), 2: (True, False)}[kind]
    if (old is not None) != present[0] or (new is not None) != present[1]:
        return "fact-image"
    if old == ZERO or new == ZERO:
        return "fact-image"
    if (old is not None and len(old) != 32) or (new is not None and len(new) != 32):
        return "fact-image"
    return struct.pack(">H", len(table)) + table + struct.pack(">I", len(pk)) + pk + bytes([kind]) + (old or ZERO) + (new or ZERO)


def leaf(enc):
    return sha(b"cancho-db/fact/v1\x00", enc)


def changes(facts):
    """`facts`: list of (kind, table, pk, old, new). Returns ('ok', hash) or ('error', rule)."""
    leaves, last = [], None
    for kind, table, pk, old, new in facts:
        enc = fact_encoding(kind, table, pk, old, new)
        if isinstance(enc, str):
            return "error", enc
        if last is not None and not (last < (table, pk)):
            return "error", "facts-unordered"
        last = (table, pk)
        leaves.append(leaf(enc))
    level = leaves
    while len(level) > 1:
        nxt = [sha(b"cancho-db/node/v1\x00", level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    root = level[0] if level else ZERO
    return "ok", sha(b"cancho-db/changes/v1\x00", struct.pack(">I", len(leaves)), root)


def state(parent_states, chg):
    return sha(b"cancho-db/state/v1\x00", bytes([len(parent_states)]), *parent_states, chg)


def parse_fact(text):
    k, t, p, o, n = text.split(":")
    return int(k), bytes.fromhex(t), bytes.fromhex(p), None if o == "-" else bytes.fromhex(o), None if n == "-" else bytes.fromhex(n)


def run(line):
    f = line.split()
    if not f:
        return "error empty"
    if f[0] == "C":
        try:
            kind, val = changes([parse_fact(x) for x in f[1:]])
        except (ValueError, IndexError):
            return "error command"
        return "ok " + val.hex() if kind == "ok" else "error " + val
    if f[0] == "S":
        try:
            p = int(f[1])
            ps = [bytes.fromhex(x) for x in f[2:2 + p]]
            chg = bytes.fromhex(f[2 + p])
            if p > 2 or len(f) != 3 + p or any(len(x) != 32 for x in ps) or len(chg) != 32:
                return "error command"
        except (ValueError, IndexError):
            return "error command"
        return "ok " + state(ps, chg).hex()
    return "error command"


def fact_text(kind, table, pk, old, new):
    return "%d:%s:%s:%s:%s" % (kind, table.hex(), pk.hex(), "-" if old is None else old.hex(), "-" if new is None else new.hex())


def cases(seed=1):
    """The golden cases: named shapes first, then seeded random ones. Returns command lines."""
    rnd = random.Random(seed)
    h = lambda: bytes(rnd.randrange(256) for _ in range(32))
    out = ["C"]
    t, p = b"accounts", b"\x00\x00\x00\x01"
    out.append("C " + fact_text(0, t, p, None, h()))
    out.append("C " + fact_text(1, t, p, h(), h()))
    out.append("C " + fact_text(2, t, p, h(), None))
    # trees of 2 .. 9 leaves (odd counts carry the last hash up)
    for n in range(2, 10):
        out.append("C " + " ".join(fact_text(0, t, struct.pack(">I", i), None, h()) for i in range(n)))
    # ordering: table first, then pk; a prefix sorts first
    out.append("C " + fact_text(0, b"a", b"\x02", None, h()) + " " + fact_text(0, b"ab", b"\x01", None, h()) + " " + fact_text(0, b"b", b"\x00", None, h()))
    out.append("C " + fact_text(0, b"a", b"\x01", None, h()) + " " + fact_text(0, b"a", b"\x01\x00", None, h()))
    # refusals, each rule
    out.append("C " + fact_text(3, t, p, None, h()))
    out.append("C " + fact_text(0, b"", p, None, h()))
    out.append("C " + fact_text(0, b"x" * 256, p, None, h()))
    out.append("C " + fact_text(0, t, b"", None, h()))
    out.append("C " + fact_text(0, t, p, h(), h()))
    out.append("C " + fact_text(1, t, p, None, h()))
    out.append("C " + fact_text(2, t, p, h(), h()))
    out.append("C " + fact_text(0, t, p, None, ZERO))
    out.append("C " + fact_text(0, t, p, None, h()[:31]))
    out.append("C " + fact_text(1, t, p, h() + b"\x00", h()))
    out.append("C " + fact_text(0, t, p, None, h()) + " " + fact_text(0, t, p, None, h()))
    out.append("C " + fact_text(0, b"b", p, None, h()) + " " + fact_text(0, b"a", p, None, h()))
    # state: a root, a normal commit, a fork point, a merge, a read (empty changes)
    c0 = changes([])[1].hex()
    s0 = state([], bytes.fromhex(c0)).hex()
    ca = h().hex()
    out.append("S 0 " + c0)
    out.append("S 1 " + s0 + " " + ca)
    out.append("S 2 " + s0 + " " + ca + " " + c0)
    out.append("S 2 " + ca + " " + s0 + " " + c0)
    out.append("S 3 " + s0 + " " + s0 + " " + s0 + " " + c0)
    out.append("S 1 " + s0)
    # seeded random lists: sorted, unique, mixed kinds
    for _ in range(40):
        n = rnd.randrange(0, 40)
        keys = sorted({(bytes(rnd.randrange(97, 100) for _ in range(rnd.randrange(1, 3))), bytes(rnd.randrange(3) for _ in range(rnd.randrange(1, 3)))) for _ in range(n)})
        fs = []
        for tb, pk in keys:
            kind = rnd.randrange(3)
            fs.append(fact_text(kind, tb, pk, None if kind == 0 else h(), None if kind == 2 else h()))
        out.append("C " + " ".join(fs))
    return out


def main():
    if "--vectors" in sys.argv:
        for line in cases():
            print(line + " => " + run(line))
        return
    for line in sys.stdin:
        print(run(line.rstrip("\n")))


if __name__ == "__main__":
    main()
