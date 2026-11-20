#!/usr/bin/env python3
"""Do the vectors have teeth? Breaks each verifier one rule at a time and requires the vectors to notice.

    mutants.py py                       # mutate tools/verify.py
    mutants.py cho [PATH_TO_CANCHO]     # mutate src/*.cho, rebuild with the compiler, run

A mutant is a one-line change that makes the verifier accept something the spec refuses (or refuse something it
accepts). It is *killed* when at least one vector fails against it. A mutant that survives means a rule no vector
exercises: either add the vector or, if the change is behaviourally identical, say why in `EQUIVALENT` below. The
mutated source must contain the original text exactly once, so a mutant cannot rot silently when the source moves.
Exit status 0 only if every mutant is killed.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (label, file, original, replacement)
PY = [
    ("accept version 2", "tools/verify.py", "if r.u16() != 1:", "if r.u16() > 2:"),
    ("allow 3 parents", "tools/verify.py", "if len(parents) > 2:", "if len(parents) > 3:"),
    ("branch up to 256", "tools/verify.py", "if len(branch) > 255:", "if len(branch) > 256:"),
    ("accept empty branch", "tools/verify.py", "if len(branch) == 0:", "if False:"),
    ("effect kind 5 allowed", "tools/verify.py", "\n        if kind > 4:", "\n        if kind > 5:"),
    ("effects: allow duplicates", "tools/verify.py", "not key > last:\n            raise Reject(\"effects-unordered\")", "key < last:\n            raise Reject(\"effects-unordered\")"),
    ("effects: unordered allowed", "tools/verify.py", "not key > last:\n            raise Reject(\"effects-unordered\")", "False:\n            raise Reject(\"effects-unordered\")"),
    ("effects: kind ignored", "tools/verify.py", "\n        key = (kind, r.b16())", "\n        key = (0, r.b16())"),
    ("check ok up to 2", "tools/verify.py", "r.b16()\n        if r.u8() > 1:", "r.b16()\n        if r.u8() > 2:"),
    ("nondet tag 3 allowed", "tools/verify.py", "        else:\n            raise Reject(\"bad-encoding\")\n    r.take(32); r.take(32)",
     "        else:\n            r.take(0)\n    r.take(32); r.take(32)"),
    ("trailing bytes allowed", "tools/verify.py", "\n    if r.at != len(enc):", "\n    if False:"),
    ("record limit off by one", "tools/verify.py", "if length > MAX_RECORD:", "if length >= MAX_RECORD:"),
    ("signature length off", "tools/verify.py", "< length + 64:", "< length + 63:"),
    ("duplicates allowed", "tools/verify.py", "if ident in seen:", "if False:"),
    ("signature unchecked", "tools/verify.py", "if not sig_ok(server_key, sig, ident):", "if False:"),
    ("sig over wrong domain", "tools/verify.py", "if not sig_ok(server_key, sig, ident):", "if not sig_ok(server_key, sig, hashlib.sha256(enc).digest()):"),
    ("seq may skip ahead", "tools/verify.py", "if seq != count.get(branch, 0):", "if seq < count.get(branch, 0):"),
    ("seq may repeat", "tools/verify.py", "if seq != count.get(branch, 0):", "if seq > count.get(branch, 0):"),
    ("seq global not per branch", "tools/verify.py", "if seq != count.get(branch, 0):", "if seq != index:"),
    ("root may have 2 parents", "tools/verify.py", "if len(parents) == 2:\n                    raise Reject(\"parent-count\")\n                if parents and",
     "if parents and"),
    ("fork parent unchecked", "tools/verify.py", "if parents and parents[0] not in seen:", "if False:"),
    ("seq>0 needs no parent", "tools/verify.py", "if len(parents) == 0:\n                    raise Reject(\"parent-count\")\n                if parents[0] != tip[branch]",
     "if len(parents) == 0:\n                    pass\n                elif parents[0] != tip[branch]"),
    ("first parent unchecked", "tools/verify.py", "if parents[0] != tip[branch]:", "if False:"),
    ("merge parents may be equal", "tools/verify.py", "if parents[1] == parents[0]:", "if False:"),
    ("merge parent may be unknown", "tools/verify.py", "if parents[1] not in seen:", "if False:"),
    ("expected id unchecked", "tools/verify.py", "if expect is not None and expect not in seen:", "if False:"),
    ("expected id checked before records", "tools/verify.py", "infos = set(), {}, {}, []\n    while at < len(data):",
     "infos = set(), {}, {}, []\n    if expect is not None and expect not in seen:\n        raise Reject(\"expected-missing\")\n    while at < len(data):"),
    ("magic unchecked", "tools/verify.py", "if data[:8] != MAGIC:", "if False:"),
    ("short header accepted", "tools/verify.py", "if len(data) < 40:", "if len(data) < 8:"),
    ("record index off by one", "tools/verify.py", "raise Reject(e.rule, index)\n        seen.add(ident)", "raise Reject(e.rule, index + 1)\n        seen.add(ident)"),
    ("signature after chain rules", "tools/verify.py", "            if not sig_ok(server_key, sig, ident):\n                raise Reject(\"bad-signature\")\n            if seq != count.get(branch, 0):\n                raise Reject(\"seq-gap\")",
     "            if seq != count.get(branch, 0):\n                raise Reject(\"seq-gap\")\n            if not sig_ok(server_key, sig, ident):\n                raise Reject(\"bad-signature\")"),
    ("decode after signature", "tools/verify.py", "            branch, seq, parents, info = decode(enc)\n            ident = hashlib.sha256(DOMAIN + enc).digest()\n            if ident in seen:",
     "            ident = hashlib.sha256(DOMAIN + enc).digest()\n            if not sig_ok(server_key, sig, ident):\n                raise Reject(\"bad-signature\")\n            branch, seq, parents, info = decode(enc)\n            if ident in seen:"),
    # ---- L2
    ("L2: chain unchecked", "tools/verify.py", "if not chain_valid(blocks, root):", "if False:"),
    ("L2: only the first block's signature is checked", "tools/verify.py", "    for b in blocks:\n        if not sig_ok(key, b[5]", "    for b in blocks[:1]:\n        if not sig_ok(key, b[5]"),
    ("L2: block signature ignores next_key", "tools/verify.py", "BLOCK_DOMAIN + b[6] + b[4])", "BLOCK_DOMAIN + b[6])"),
    ("L2: revocation of a prefix ignored", "tools/verify.py", "for k in range(1, len(blocks) + 1):", "for k in range(len(blocks), len(blocks) + 1):"),
    ("L2: revoked only after since", "tools/verify.py", "since <= time:", "since < time:"),
    ("L2: revoked before since", "tools/verify.py", "since <= time:", "since >= time:"),
    ("L2: only the first block's expiry", "tools/verify.py", "b[3] != NO_EXPIRY and time > b[3] for b in blocks)", "b[3] != NO_EXPIRY and time > b[3] for b in blocks[:1])"),
    ("L2: expiry inclusive", "tools/verify.py", "time > b[3] for b in blocks)", "time >= b[3] for b in blocks)"),
    ("L2: zero principal is not a wildcard", "tools/verify.py", "b[0] != ZERO32 and b[0] != principal", "b[0] != principal"),
    ("L2: only the first block's principal", "tools/verify.py", "b[0] != ZERO32 and b[0] != principal for b in blocks)", "b[0] != ZERO32 and b[0] != principal for b in blocks[:1])"),
    ("L2: principal never denied", "tools/verify.py", "b[0] != ZERO32 and b[0] != principal for b in blocks)", "False)"),
    ("L2: only the first block's branch", "tools/verify.py", "not pattern_matches(b[1], branch) for b in blocks)", "not pattern_matches(b[1], branch) for b in blocks[:1])"),
    ("L2: branch never denied", "tools/verify.py", "not pattern_matches(b[1], branch) for b in blocks)", "False)"),
    ("L2: only the first block's effects", "tools/verify.py", "not block_permits_effect(b, e) for b in blocks for e in effects)", "not block_permits_effect(b, e) for b in blocks[:1] for e in effects)"),
    ("L2: only the first effect", "tools/verify.py", "not block_permits_effect(b, e) for b in blocks for e in effects)", "not block_permits_effect(b, e) for b in blocks for e in effects[:1])"),
    ("L2: effect kind ignored", "tools/verify.py", "k == effect[0] and pattern_matches", "pattern_matches"),
    ("L2: effect never denied", "tools/verify.py", "not block_permits_effect(b, e) for b in blocks for e in effects)", "False)"),
    ("L2: wildcard is not a prefix", "tools/verify.py", "return value.startswith(pattern[:-1])", "return value.startswith(pattern)"),
    ("L2: wildcard needs a longer value", "tools/verify.py", "return value.startswith(pattern[:-1])", "return value.startswith(pattern[:-1]) and len(value) > len(pattern)"),
    ("L2: no wildcard", "tools/verify.py", 'if pattern[-1:] == b"*":', 'if False:'),
    ("L2: empty pattern matches all", "tools/verify.py", "return pattern == value", "return pattern == value or pattern == b''"),
    ("L2: token id ignores block count", "tools/verify.py", 'struct.pack(">I", k) + b"".join', 'struct.pack(">I", 1) + b"".join'),
    ("L2: token id ignores domain", "tools/verify.py", "hashlib.sha256(TOKEN_DOMAIN + struct", "hashlib.sha256(struct"),
    ("L2: token trailing bytes allowed", "tools/verify.py", "        if r.at != len(enc):\n            raise Reject(\"bad-encoding\")\n    except Reject:", "        pass\n    except Reject:"),
    ("L2: token with no blocks allowed", "tools/verify.py", "        if n == 0:\n            raise Reject(\"bad-encoding\")\n        for _ in range(n):", "        for _ in range(n):"),
    ("L2: token effects unordered allowed", "tools/verify.py", "                if last is not None and not key > last:\n                    raise Reject(\"bad-encoding\")\n                last = key\n                effects.append(key)\n            expiry", "                last = key\n                effects.append(key)\n            expiry"),
    ("L2: token effect kind 5 allowed", "tools/verify.py", "                if kind > 4:\n                    raise Reject(\"bad-encoding\")\n                key = (kind, r.b16())\n                if last is not None and not key > last:\n                    raise Reject(\"bad-encoding\")", "                key = (kind, r.b16())\n                if last is not None and not key > last:\n                    raise Reject(\"bad-encoding\")"),
    ("L2: tokens magic unchecked", "tools/verify.py", 'if data[:8] != b"CHODBTK1":', "if False:"),
    ("L2: tokens short header accepted", "tools/verify.py", '    if len(data) < 8:\n        raise Reject("tokens-truncated")', '    if len(data) < 0:\n        raise Reject("tokens-truncated")'),
    ("L2: tokens truncated entry accepted", "tools/verify.py", "if len(data) - at - 4 < length:\n            raise Reject(\"tokens-truncated\", index)", "if False:\n            raise Reject(\"tokens-truncated\", index)"),
    ("L2: revoked magic unchecked", "tools/verify.py", 'if data[:8] != b"CHODBRV1":', "if False:"),
    ("L2: revoked truncated entry accepted", "tools/verify.py", "if len(data) - at < 104:", "if False:"),
    ("L2: revocation signature unchecked", "tools/verify.py", "if not sig_ok(root, sig, REVOKE_DOMAIN + ident + since_b):", "if False:"),
    ("L2: revocation signature without domain", "tools/verify.py", "REVOKE_DOMAIN + ident + since_b)", "ident + since_b)"),
    ("L2: revocation latest wins", "tools/verify.py", "revoked[ident] = min(since, revoked.get(ident, since))", "revoked[ident] = since"),
    ("L2: token not found is allowed", "tools/verify.py", 'why = "token-missing" if blocks is None else l2_denial', 'why = None if blocks is None else l2_denial'),
    ("L2: commits stop at the first", "tools/verify.py", "    for index, info in enumerate(infos):", "    for index, info in list(enumerate(infos))[:1]:"),
    ("L2: record is off by one", "tools/verify.py", "raise Reject(why, index)", "raise Reject(why, index + 1)"),
    ("L2: expired checked before revoked", "tools/verify.py", '    for k in range(1, len(blocks) + 1):\n        since = revoked.get(prefix_id(blocks, k))\n        if since is not None and since <= time:\n            return "token-revoked"\n    if any(b[3] != NO_EXPIRY and time > b[3] for b in blocks):\n        return "token-expired"',
     '    if any(b[3] != NO_EXPIRY and time > b[3] for b in blocks):\n        return "token-expired"\n    for k in range(1, len(blocks) + 1):\n        since = revoked.get(prefix_id(blocks, k))\n        if since is not None and since <= time:\n            return "token-revoked"'),
    ("L2: effects checked before branch", "tools/verify.py", '    if any(not pattern_matches(b[1], branch) for b in blocks):\n        return "branch-denied"\n    if ir is not None:',
     '    if any(not block_permits_effect(b, e) for b in blocks for e in effects):\n        return "effect-denied"\n    if any(not pattern_matches(b[1], branch) for b in blocks):\n        return "branch-denied"\n    if ir is not None:'),
    ("L2: branch checked before principal", "tools/verify.py", '    if any(b[0] != ZERO32 and b[0] != principal for b in blocks):\n        return "principal-denied"\n    if any(not pattern_matches(b[1], branch) for b in blocks):\n        return "branch-denied"',
     '    if any(not pattern_matches(b[1], branch) for b in blocks):\n        return "branch-denied"\n    if any(b[0] != ZERO32 and b[0] != principal for b in blocks):\n        return "principal-denied"'),
    ("L2: principal checked before expiry", "tools/verify.py", '    if any(b[3] != NO_EXPIRY and time > b[3] for b in blocks):\n        return "token-expired"\n    if any(b[0] != ZERO32',
     '    if any(b[0] != ZERO32 and b[0] != principal for b in blocks):\n        return "principal-denied"\n    if any(b[3] != NO_EXPIRY and time > b[3] for b in blocks):\n        return "token-expired"\n    if any(b[0] != ZERO32'),
    ("L2: signature checked after revocation", "tools/verify.py", '    if not chain_valid(blocks, root):\n        return "token-bad-signature"\n    for k in range(1, len(blocks) + 1):\n        since = revoked.get(prefix_id(blocks, k))\n        if since is not None and since <= time:\n            return "token-revoked"',
     '    for k in range(1, len(blocks) + 1):\n        since = revoked.get(prefix_id(blocks, k))\n        if since is not None and since <= time:\n            return "token-revoked"\n    if not chain_valid(blocks, root):\n        return "token-bad-signature"'),
    # ---- IR v2 (ir.md section 6)
    ("v2: Select2 accepted in a v1 store", "tools/verify.py", "        elif tag == 6 and v2:\n            if r.u8() > 1:                             # distinct", "        elif tag == 6:\n            if r.u8() > 1:                             # distinct"),
    ("v2: Star accepted in a v1 store", "tools/verify.py", "            elif tag == 6 and v2:\n                pass", "            elif tag == 6:\n                pass"),
    ("v2: Unary accepted in a v1 store", "tools/verify.py", "elif tag == 7 and v2:                      # Unary", "elif tag == 7:                      # Unary"),
    ("v2: In accepted in a v1 store", "tools/verify.py", "elif tag == 8 and v2:                      # In", "elif tag == 8:                      # In"),
    ("v2: Case accepted in a v1 store", "tools/verify.py", "elif tag == 9 and v2:                      # Case", "elif tag == 9:                      # Case"),
    ("v2: Cast accepted in a v1 store", "tools/verify.py", "elif tag == 10 and v2:                     # Cast", "elif tag == 10:                     # Cast"),
    ("v2: v2 operators accepted in a v1 store", "tools/verify.py", "if r.u8() > (17 if v2 else 11):", "if r.u8() > 17:"),
    ("v2: operator 18 accepted", "tools/verify.py", "if r.u8() > (17 if v2 else 11):", "if r.u8() > (18 if v2 else 11):"),
    ("v2: unary operator 4 accepted", "tools/verify.py", "                if r.u8() > 3:\n                    bad()\n                pending += 1", "                if r.u8() > 4:\n                    bad()\n                pending += 1"),
    ("v2: In with no members accepted", "tools/verify.py", "                if n < 1:\n                    bad()\n                pending += 1 + n", "                pending += 1 + n"),
    ("v2: In negated 2 accepted", "tools/verify.py", "                if r.u8() > 1:\n                    bad()\n                n = r.u32()", "                if r.u8() > 2:\n                    bad()\n                n = r.u32()"),
    ("v2: Case with no pairs accepted", "tools/verify.py", "if n < 1 or has_else > 1:", "if has_else > 1:"),
    ("v2: Case else flag 2 accepted", "tools/verify.py", "if n < 1 or has_else > 1:", "if n < 1 or has_else > 2:"),
    ("v2: a Case else is not owed", "tools/verify.py", "pending += 2 * n + has_else", "pending += 2 * n"),
    ("v2: a Case pair owes one", "tools/verify.py", "pending += 2 * n + has_else", "pending += n + has_else"),
    ("v2: an In owes no members", "tools/verify.py", "pending += 1 + n", "pending += 1"),
    ("v2: a Cast type name may be empty and dotted-free", "tools/verify.py", "                name(False)\n                pending += 1\n            else:", "                r.b16()\n                pending += 1\n            else:"),
    ("v2: a Cast is a call", "tools/verify.py", "                name(False)\n                pending += 1\n            else:", "                out.add((3, name(False)))\n                pending += 1\n            else:"),
    ("v2: distinct 2 accepted", "tools/verify.py", "if r.u8() > 1:                             # distinct", "if r.u8() > 2:                             # distinct"),
    ("v2: a Select2 without from accepted", "tools/verify.py", "            if nf == 0:\n                bad()\n            for i in range(nf):", "            for i in range(nf):"),
    ("v2: the first from may be a join", "tools/verify.py", "if kind > 2 or (i == 0 and kind != 0):", "if kind > 2:"),
    ("v2: join kind 3 accepted", "tools/verify.py", "if kind > 2 or (i == 0 and kind != 0):", "if kind > 3 or (i == 0 and kind != 0):"),
    ("v2: a join needs no on", "tools/verify.py", "if flag > 1 or (flag == 1) != (kind in (1, 2)):", "if flag > 1:"),
    ("v2: a comma may have an on", "tools/verify.py", "if flag > 1 or (flag == 1) != (kind in (1, 2)):", "if flag > 1 or (kind in (1, 2) and flag != 1):"),
    ("v2: order direction 2 accepted", "tools/verify.py", "if r.u8() > 1 or r.u8() > 2:", "if r.u8() > 2 or r.u8() > 2:"),
    ("v2: order nulls 3 accepted", "tools/verify.py", "if r.u8() > 1 or r.u8() > 2:", "if r.u8() > 1 or r.u8() > 3:"),
    ("v2: the from table is not a read", "tools/verify.py", "            for i in range(nf):\n                out.add((0, name(True)))", "            for i in range(nf):\n                name(True)"),
    ("v2: a join condition reads nothing", "tools/verify.py", "                if flag == 1:\n                    expr(True)", "                if flag == 1:\n                    keep = set(out)\n                    expr(True)\n                    out.intersection_update(keep)"),
    ("v2: where reads nothing", "tools/verify.py", "            opt()                                      # where", "            keep = set(out)\n            opt()\n            out.intersection_update(keep)"),
    ("v2: group by reads nothing", "tools/verify.py", "            for _ in range(cnt()):                     # group by\n                expr(True)", "            keep = set(out)\n            for _ in range(cnt()):\n                expr(True)\n            out.intersection_update(keep)"),
    ("v2: having reads nothing", "tools/verify.py", "            opt()                                      # having", "            keep = set(out)\n            opt()\n            out.intersection_update(keep)"),
    ("v2: order by reads nothing", "tools/verify.py", "            for _ in range(cnt()):                     # order by\n                expr(True)", "            keep = set(out)\n            for _ in range(cnt()):\n                expr(True)\n            out.intersection_update(keep)"),
    ("v2: limit reads nothing", "tools/verify.py", "            opt()                                      # limit", "            keep = set(out)\n            opt()\n            out.intersection_update(keep)"),
    ("v2: offset reads nothing", "tools/verify.py", "            opt()                                      # offset", "            keep = set(out)\n            opt()\n            out.intersection_update(keep)"),
    ("v2: a Select2 with trailing bytes accepted", "tools/verify.py", "        if r.at != len(enc):\n            bad()\n    except Reject as e:", "        pass\n    except Reject as e:"),
    # ---- statement IR (ir.md)
    ("IR: select forgets the table read", "tools/verify.py", "            for _ in range(tables):\n                out.add((0, name(True)))", "            for _ in range(tables):\n                name(True)"),
    ("IR: column read forgets the column", "tools/verify.py", 'out.add((0, t + b"." + c))', "out.add((0, t))"),
    ("IR: column read forgets the table", "tools/verify.py", 'out.add((0, t + b"." + c))', "out.add((0, c))"),
    ("IR: columns are not reads", "tools/verify.py", 'out.add((0, t + b"." + c))', "pass"),
    ("IR: insert forgets the write", "tools/verify.py", "            t = name(True)\n            out.add((1, t))", "            t = name(True)"),
    ("IR: update forgets the write", "tools/verify.py", "            out.add((1, name(True)))\n            nsets = cnt()", "            name(True)\n            nsets = cnt()"),
    ("IR: delete forgets the write", "tools/verify.py", "        elif tag == 3:\n            out.add((1, name(True)))", "        elif tag == 3:\n            name(True)"),
    ("IR: ddl is a write", "tools/verify.py", "out.add((2, name(True)))", "out.add((1, name(True)))"),
    ("IR: call statement forgets the call", "tools/verify.py", "            out.add((3, name(False)))", "            name(False)"),
    ("IR: call expression forgets the call", "tools/verify.py", "                out.add((3, f))", "                pass"),
    ("IR: nondet forgets the source", "tools/verify.py", "out.add((4, name(False)))", "name(False)"),
    ("IR: select where ignored", "tools/verify.py", "                out.add((0, name(True)))\n            opt()\n        elif tag == 1:", "                out.add((0, name(True)))\n        elif tag == 1:"),
    ("IR: update where ignored", "tools/verify.py", "                expr(True)\n            opt()\n        elif tag == 3:", "                expr(True)\n        elif tag == 3:"),
    ("IR: delete where ignored", "tools/verify.py", "            out.add((1, name(True)))\n            opt()\n        elif tag == 4:", "            out.add((1, name(True)))\n        elif tag == 4:"),
    ("IR: dots allowed in table and column names", "tools/verify.py", 'if len(n) == 0 or (ident and b"." in n):', "if len(n) == 0:"),
    ("IR: empty names allowed", "tools/verify.py", 'if len(n) == 0 or (ident and b"." in n):', 'if ident and b"." in n:'),
    ("IR: column reference allowed in VALUES", "tools/verify.py", "                if not allow_col:\n                    bad()\n", ""),
    ("IR: insert row length unchecked", "tools/verify.py", "                if cnt() != ncols:\n                    bad()", "                cnt()"),
    ("IR: select without from allowed", "tools/verify.py", "            if tables == 0:\n                bad()", "            if False:\n                bad()"),
    ("IR: update without sets allowed", "tools/verify.py", "            if nsets == 0:\n                bad()", "            if False:\n                bad()"),
    ("IR: ddl kind 5 allowed", "tools/verify.py", "            if r.u8() > 4:\n                bad()", "            if r.u8() > 5:\n                bad()"),
    ("IR: operator 12 allowed in a v1 store", "tools/verify.py", "if r.u8() > (17 if v2 else 11):", "if r.u8() > (17 if v2 else 12):"),
    ("IR: value tag 3 allowed", "tools/verify.py", "                elif vt != 0:\n                    bad()", "                elif vt != 0:\n                    pass"),
    ("IR: optional flag 2 allowed", "tools/verify.py", "        elif flag != 0:\n            bad()", "        elif flag != 0:\n            pass"),
    ("IR: unknown expression tag allowed", "tools/verify.py", "            else:\n                bad()\n            if pending >", "            else:\n                pass\n            if pending >"),
    ("IR: an operator owes one operand", "tools/verify.py", "if r.u8() > (17 if v2 else 11):\n                    bad()\n                pending += 2", "if r.u8() > (17 if v2 else 11):\n                    bad()\n                pending += 1"),
    ("IR: a call owes no operands", "tools/verify.py", "                pending += argc", "                pass"),
    ("IR: trailing bytes allowed", "tools/verify.py", "        if r.at != len(enc):\n            bad()\n    except Reject as e:", "        pass\n    except Reject as e:"),
    ("IR: statement id without domain", "tools/verify.py", "hashlib.sha256(STMT_DOMAIN + enc).digest()", "hashlib.sha256(enc).digest()"),
    ("IR: recorded may be larger", "tools/verify.py", "if inferred != set(effects):", "if not inferred <= set(effects):"),
    ("IR: recorded may be smaller", "tools/verify.py", "if inferred != set(effects):", "if not inferred >= set(effects):"),
    ("IR: missing statement ignored", "tools/verify.py", '            if sid not in ir:\n                return "stmt-missing"\n            inferred |= ir[sid]', "            if sid not in ir:\n                continue\n            inferred |= ir[sid]"),
    ("IR: only the first statement counts", "tools/verify.py", "        for sid in statements:\n            if sid not in ir:", "        for sid in statements[:1]:\n            if sid not in ir:"),
    ("IR: effects judged before the statements", "tools/verify.py", '    if ir is not None:\n        inferred = set()', '    if any(not block_permits_effect(b, e) for b in blocks for e in effects):\n        return "effect-denied"\n    if ir is not None:\n        inferred = set()'),
    ("IR: mismatch before missing", "tools/verify.py", '            if sid not in ir:\n                return "stmt-missing"\n            inferred |= ir[sid]\n        if inferred != set(effects):\n            return "effects-mismatch"', '            if sid in ir:\n                inferred |= ir[sid]\n        if inferred != set(effects):\n            return "effects-mismatch"\n        if any(sid not in ir for sid in statements):\n            return "stmt-missing"'),
    ("IR: stmts magic unchecked", "tools/verify.py", 'if data[:8] not in (b"CHODBST1", b"CHODBST2", b"CHODBST3"):', "if False:"),
    ("IR: stmts short header accepted", "tools/verify.py", '    if len(data) < 8:\n        raise Reject("stmts-truncated")', '    if len(data) < 0:\n        raise Reject("stmts-truncated")'),
    ("IR: stmts truncated entry accepted", "tools/verify.py", 'if len(data) - at - 4 < length:\n            raise Reject("stmts-truncated", index)', 'if False:\n            raise Reject("stmts-truncated", index)'),
    ("IR: stmts record index off by one", "tools/verify.py", 'raise Reject(e.rule, index)\n        store[ident] = effects', 'raise Reject(e.rule, index + 1)\n        store[ident] = effects'),
    ("IR: statements are read before the revocations", "tools/verify.py", "    revoked = load_revoked(revoked_data, root) if revoked_data is not None else {}\n    ir = load_stmts(stmts_data) if stmts_data is not None else None", "    ir = load_stmts(stmts_data) if stmts_data is not None else None\n    revoked = load_revoked(revoked_data, root) if revoked_data is not None else {}"),
    ("v3: a Const is allowed in a v3 shape", "tools/verify.py", "                if v3:\n                    bad()                              # a v3 shape holds no constant", "                if False:\n                    bad()                              # a v3 shape holds no constant"),
    ("v3: a hole may have type 3", "tools/verify.py", "                if vt > 2:\n                    bad()\n                holes.append(vt)", "                if vt > 3:\n                    bad()\n                holes.append(vt)"),
    ("v3: a hole is allowed in a v2 shape", "tools/verify.py", "            elif tag == 11 and v3:", "            elif tag == 11 and v2:"),
    ("v3: a payload tag of 2 is accepted", "tools/verify.py", "    else:\n        raise Reject(\"stmt-bad-encoding\")\n    return hashlib.sha256(STMT3_DOMAIN", "    else:\n        pass\n    return hashlib.sha256(STMT3_DOMAIN"),
    ("v3: an erased payload may be followed by bytes", "tools/verify.py", "    if tag == 0:\n        if payload:\n            raise Reject(\"stmt-bad-encoding\")", "    if tag == 0:\n        if False:\n            raise Reject(\"stmt-bad-encoding\")"),
    ("v3: bytes may follow the constants", "tools/verify.py", "            if r.at != len(payload) - 20:\n                raise Reject(\"stmt-bad-encoding\")", "            if False:\n                raise Reject(\"stmt-bad-encoding\")"),
    ("v3: the constants need not have the holes' types", "tools/verify.py", "if types != holes or hashlib.sha256(", "if hashlib.sha256("),
    ("v3: the hash of the constants is not checked", "tools/verify.py", " + payload[20:]).digest() != chash:", " + payload[20:]).digest() != chash and False:"),
    ("v3: the salt is not in the hash of the constants", "tools/verify.py", "CONSTS_DOMAIN + salt + struct.pack", "CONSTS_DOMAIN + struct.pack"),
    ("v3: the id leaves out the hash of the constants", "tools/verify.py", "STMT3_DOMAIN + shape + chash", "STMT3_DOMAIN + shape"),
    ("v3: a mismatch is a bad encoding", "tools/verify.py", "            raise Reject(\"stmt-consts-mismatch\")", "            raise Reject(\"stmt-bad-encoding\")"),
    ("v3: a version 3 store has a bad magic", "tools/verify.py", "(b\"CHODBST1\", b\"CHODBST2\", b\"CHODBST3\")", "(b\"CHODBST1\", b\"CHODBST2\")"),
]

CHO = [
    ("accept version 2", "src/commit.cho", "if be(data, 0, 2) != 1 {", "if be(data, 0, 2) > 2 {"),
    ("allow 3 parents", "src/commit.cho", "if np > 2 {", "if np > 3 {"),
    ("branch up to 256", "src/commit.cho", "if bl > 255 ||", "if bl > 256 ||"),
    ("accept empty branch", "src/commit.cho", "if bl == 0 {", "if bl == 7 {"),
    ("effect kind 5 allowed", "src/commit.cho", "if kind > 4 {", "if kind > 5 {"),
    ("effects: allow duplicates", "src/commit.cho", "if c <= 0 {", "if c < 0 {"),
    ("effects: kind ignored", "src/commit.cho", "var c = kind - last_kind;", "var c = 0;"),
    ("effects: target ignored", "src/commit.cho", "c = compare_at(data, cur[0], tl, last_at, last_len);", "c = 1;"),
    ("check ok up to 2", "src/commit.cho", "if int_of(data[cur[0]]) > 1 {", "if int_of(data[cur[0]]) > 2 {"),
    ("nondet tag 3 allowed", "src/commit.cho", "} else if tag != 0 {", "} else if tag > 3 {"),
    ("trailing bytes allowed", "src/commit.cho", "|| cur[0] != len(data) {", "|| false {"),
    ("record limit off by one", "src/l1.cho", "if length > 16777216 {", "if length >= 16777216 {"),
    ("signature length off", "src/l1.cho", "< length + 64 {", "< length + 63 {"),
    ("duplicates allowed", "src/l1.cho", "if is_dup {", "if false {"),
    ("signature unchecked", "src/l1.cho", "} else if crypto_ok(data[8..40], ident, sig) == 0 {", "} else if false {"),
    ("sig over wrong domain", "src/l1.cho", "crypto.sha256_update(sha, nul);\n", ""),
    ("seq may skip ahead", "src/l1.cho", "out[commit.f_seq_lo()] != count_here {", "out[commit.f_seq_lo()] < count_here {"),
    ("seq may repeat", "src/l1.cho", "out[commit.f_seq_lo()] != count_here {", "out[commit.f_seq_lo()] > count_here {"),
    ("seq high half ignored", "src/l1.cho", "if out[commit.f_seq_hi()] != 0 ||", "if false ||"),
    ("root may have 2 parents", "src/l1.cho", "if np == 2 {\n                                rule = commit.parent_count();\n                            } else if np == 1 {", "if np == 1 {"),
    ("fork parent unchecked", "src/l1.cho", "if !known {\n                                    rule = commit.parent_unknown();\n                                }\n                            }\n                        } else if np == 0 {", "if false {\n                                    rule = commit.parent_unknown();\n                                }\n                            }\n                        } else if np == 0 {"),
    ("seq>0 needs no parent", "src/l1.cho", "} else if np == 0 {\n                            rule = commit.parent_count();\n                        } else {", "} else if np == 0 {\n                            rule = 0;\n                        } else {"),
    ("first parent unchecked", "src/l1.cho", "rule = commit.parent_mismatch();", "rule = 0;"),
    ("merge parents may be equal", "src/l1.cho", "if same(enc[pat..pat + 32], enc[pat + 32..pat + 64]) {", "if false {"),
    ("merge parent may be unknown", "src/l1.cho", "                                    if !known {\n                                        rule = commit.parent_unknown();\n                                    }\n                                }\n                            }\n                        }\n\n",
     "                                }\n                            }\n                        }\n\n"),
    ("expected id unchecked", "src/l1.cho", "if rule == 0 && len(expect) == 32 {", "if false {"),
    ("magic unchecked", "src/l1.cho", "} else if !same(data[0..8], \"CHODBLG1\") {", "} else if false {"),
    ("short header accepted", "src/l1.cho", "} else if len(data) < 40 {", "} else if len(data) < 8 {"),
    ("record index off by one", "src/l1.cho", "bad_at = index;", "bad_at = index + 1;"),
    ("commit not counted per branch", "src/l1.cho", "counts = map.put(heap, counts, branch, count_here + 1);", "counts = map.put(heap, counts, branch, commits + 1);"),
    ("tip not updated", "src/l1.cho", "tips = map.put(heap, tips, branch, commits);", "tips = tips;"),
    ("v3: a Const is allowed in a v3 shape", "src/ir.cho", "} else if tag == 1 && mv != 3 {", "} else if tag == 1 {"),
    ("v3: a hole may have type 3", "src/ir.cho", "|| int_of(data[cur[0]]) > 2 {", "|| int_of(data[cur[0]]) > 3 {"),
    ("v3: a hole is allowed in a v2 shape", "src/ir.cho", "} else if tag == 11 && mv == 3 {", "} else if tag == 11 {"),
    ("v3: a payload tag of 2 is accepted", "src/ir.cho", "    if tag != 1 || rest < 33 + 20 {", "    if rest < 33 + 20 {"),
    ("v3: an erased payload may be followed by bytes", "src/ir.cho", "        return rest == 33;", "        return true;"),
    ("v3: bytes may follow the constants", "src/ir.cho", "    if !good || p != len(data) {", "    if !good {"),
    ("v3: the constants need not have the holes' types", "src/ir.cho", "if good && i < nm[2] && nm[3 + i] != vt {", "if false {"),
    ("v3: the constants need not be as many as the holes", "src/ir.cho", "    var same = n == nm[2];", "    var same = true;"),
    ("v3: the hash of the constants is not checked", "src/ir.cho", "    if !same || !matches {", "    if !same {"),
    ("v3: the salt is not in the hash of the constants", "src/ir.cho", "        crypto.sha256_update(sha, data[pat..pat + 16]);", "        crypto.sha256_update(sha, data[pat..pat]);"),
    ("v3: the count is not in the hash of the constants", "src/ir.cho", "        crypto.sha256_update(sha, cnt);", "        crypto.sha256_update(sha, nul);"),
    ("v3: the id leaves out the hash of the constants", "src/ir.cho", "        crypto.sha256_update(sha, data[0..end + 32]);", "        crypto.sha256_update(sha, data[0..end]);"),
    ("v3: a mismatch is a bad encoding", "src/l2.cho", "                            rule = commit.stmt_consts_mismatch();", "                            rule = commit.stmt_bad_encoding();"),
    ("v3: a version 3 store has a bad magic", "src/l2.cho", " && !bytes.equal(stmts[0..8], \"CHODBST3\") {", " {"),
]

CHO += [
    # ---- L2
    ("L2: chain unchecked", "src/l2.cho", "if !token.chain_ok(tk, root) {", "if false {"),
    ("L2: only the first block's signature", "src/token.cho", "while i < n && good {", "while i < 1 && good {"),
    ("L2: block signature ignores next_key", "src/token.cho", "m = put(msg, m, tk[at..pe + 32]);", "m = put(msg, m, tk[at..pe]);"),
    ("L2: revocation of a prefix ignored", "src/l2.cho", "var k = 1;", "var k = token.blocks(tk);"),
    ("L2: revoked only after since", "src/l2.cho", "th, tl) <= 0 {", "th, tl) < 0 {"),
    ("L2: revoked before since", "src/l2.cho", "th, tl) <= 0 {", "th, tl) >= 0 {"),
    ("L2: only the first block's expiry", "src/token.cho", "if !(eh == 4294967295 && el == 4294967295) &&", "if i == 0 && !(eh == 4294967295 && el == 4294967295) &&"),
    ("L2: expiry inclusive", "src/token.cho", "cmp64(th, tl, eh, el) > 0 {", "cmp64(th, tl, eh, el) >= 0 {"),
    ("L2: u64 compare looks at the low half only", "src/token.cho", "    if ah != bh {", "    if false {"),
    ("L2: u64 compare looks at the high half only", "src/token.cho", "    if al < bl {\n        return 0 - 1;\n    }\n    if al > bl {\n        return 1;\n    }\n    return 0;", "    return 0;"),
    ("L2: zero principal is not a wildcard", "src/token.cho", "if !zero && !bytes.equal(", "if !bytes.equal("),
    ("L2: only the first block's principal", "src/token.cho", "if !zero && !bytes.equal(", "if i == 0 && !zero && !bytes.equal("),
    ("L2: principal never denied", "src/token.cho", "if !zero && !bytes.equal(", "if false && !bytes.equal("),
    ("L2: only the first block's branch", "src/token.cho", "if !matches(tk[at + 34..at + 34 + bl], branch) {", "if i == 0 && !matches(tk[at + 34..at + 34 + bl], branch) {"),
    ("L2: branch never denied", "src/token.cho", "if !matches(tk[at + 34..at + 34 + bl], branch) {", "if false {"),
    ("L2: only the first block's effects", "src/token.cho", "while i < n && !hit {", "while i < 1 && !hit {"),
    ("L2: only the first effect", "src/token.cho", "while j < en && !hit {", "while j < 1 && !hit {"),
    ("L2: effect kind ignored", "src/token.cho", "if k == kind && matches(", "if matches("),
    ("L2: effect never denied", "src/token.cho", "if !block_permits(tk, ecount_at + 4, ne, kind, enc[q + 3..q + 3 + tl]) {", "if false {"),
    ("L2: wildcard is not a prefix", "src/token.cho", "return bytes.starts_with(value, pattern[0..n - 1]);", "return bytes.starts_with(value, pattern);"),
    ("L2: wildcard needs a longer value", "src/token.cho", "return bytes.starts_with(value, pattern[0..n - 1]);", "return bytes.starts_with(value, pattern[0..n - 1]) && len(value) > n;"),
    ("L2: no wildcard", "src/token.cho", "if n > 0 && int_of(pattern[n - 1]) == '*' {", "if false {"),
    ("L2: empty pattern matches all", "src/token.cho", "return bytes.equal(pattern, value);", "return bytes.equal(pattern, value) || n == 0;"),
    ("L2: token id ignores block count", "src/token.cho", "head[4] = byte_of(k % 256);", "head[4] = byte_of(1);"),
    ("L2: token id ignores domain", "src/token.cho", '        crypto.sha256_update(sha, "cancho-db/token/v1");\n', ""),
    ("L2: token trailing bytes allowed", "src/token.cho", "return at == len(tk);", "return at <= len(tk);"),
    ("L2: token with no blocks allowed", "src/token.cho", "if n == 0 || n > len(tk) {", "if n > len(tk) {"),
    ("L2: token effects duplicate allowed", "src/token.cho", "            if c <= 0 {", "            if c < 0 {"),
    ("L2: token effects unordered allowed", "src/token.cho", "            if c <= 0 {", "            if false {"),
    ("L2: token effect kind 5 allowed", "src/token.cho", "if kind > 4 {", "if kind > 5 {"),
    ("L2: tokens magic unchecked", "src/l2.cho", '} else if !bytes.equal(tokens[0..8], "CHODBTK1") {', "} else if false {"),
    ("L2: tokens truncated entry accepted", "src/l2.cho", "if len(tokens) - at - 4 < length {", "if false {"),
    ("L2: revoked magic unchecked", "src/l2.cho", '} else if !bytes.equal(revoked[0..8], "CHODBRV1") {', "} else if false {"),
    ("L2: revoked truncated entry accepted", "src/l2.cho", "if len(revoked) - ra < 104 {", "if false {"),
    ("L2: revocation signature unchecked", "src/l2.cho", "if ed25519.verify(root, msg, revoked[ra + 40..ra + 104]) != 1 {", "if false {"),
    ("L2: revocation domain differs", "src/l2.cho", 'let tag = "cancho-db/revoke/v1";', 'let tag = "cancho-db/revoke/v2";'),
    ("L2: revocation latest wins", "src/l2.cho", "if earlier {", "if true {"),
    ("L2: revocation earliest compare reversed", "src/l2.cho", "commit.be(revoked, oa + 36, 4)) < 0;", "commit.be(revoked, oa + 36, 4)) > 0;"),
    ("L2: token not found is allowed", "src/l2.cho", "if !found {\n                rule = commit.token_missing();", "if false {\n                rule = commit.token_missing();"),
    ("L2: record is off by one", "src/l2.cho", "bad_at = index;\n            }\n            index = index + 1;", "bad_at = index + 1;\n            }\n            index = index + 1;"),
    ("L2: expired checked before revoked", "src/l2.cho", "if is_revoked {\n                        rule = commit.token_revoked();\n                    } else if token.expired(tk, th, tl) {\n                        rule = commit.token_expired();",
     "if token.expired(tk, th, tl) {\n                        rule = commit.token_expired();\n                    } else if is_revoked {\n                        rule = commit.token_revoked();"),
    ("L2: principal checked before expiry", "src/l2.cho", "} else if token.expired(tk, th, tl) {\n                        rule = commit.token_expired();\n                    } else if token.principal_denied(tk, enc[pat..pat + 32]) {\n                        rule = commit.principal_denied();",
     "} else if token.principal_denied(tk, enc[pat..pat + 32]) {\n                        rule = commit.principal_denied();\n                    } else if token.expired(tk, th, tl) {\n                        rule = commit.token_expired();"),
    ("L2: branch checked before principal", "src/l2.cho", "} else if token.principal_denied(tk, enc[pat..pat + 32]) {\n                        rule = commit.principal_denied();\n                    } else if token.branch_denied(tk, enc[bat..bat + out[commit.f_branch_len()]]) {\n                        rule = commit.branch_denied();",
     "} else if token.branch_denied(tk, enc[bat..bat + out[commit.f_branch_len()]]) {\n                        rule = commit.branch_denied();\n                    } else if token.principal_denied(tk, enc[pat..pat + 32]) {\n                        rule = commit.principal_denied();"),
    ("L2: effects checked before branch", "src/l2.cho", "} else if token.branch_denied(tk, enc[bat..bat + out[commit.f_branch_len()]]) {",
     "} else if token.effect_denied(tk, enc, out[commit.f_effects_at()], out[commit.f_effects_n()]) {\n                        rule = commit.effect_denied();\n                    } else if token.branch_denied(tk, enc[bat..bat + out[commit.f_branch_len()]]) {"),
]


CHO += [
    # ---- IR v2 (ir.md section 6)
    ("v2: Select2 accepted in a v1 store", "src/ir.cho", "} else if tag == 6 && mv >= 2 {\n                // Select2", "} else if tag == 6 {\n                // Select2"),
    ("v2: Star accepted in a v1 store", "src/ir.cho", "} else if tag == 6 && mv >= 2 {\n                // Star", "} else if tag == 6 {\n                // Star"),
    ("v2: Unary accepted in a v1 store", "src/ir.cho", "} else if tag == 7 && mv >= 2 {", "} else if tag == 7 {"),
    ("v2: In accepted in a v1 store", "src/ir.cho", "} else if tag == 8 && mv >= 2 {", "} else if tag == 8 {"),
    ("v2: Case accepted in a v1 store", "src/ir.cho", "} else if tag == 9 && mv >= 2 {", "} else if tag == 9 {"),
    ("v2: Cast accepted in a v1 store", "src/ir.cho", "} else if tag == 10 && mv >= 2 {", "} else if tag == 10 {"),
    ("v2: v2 operators accepted in a v1 store", "src/ir.cho", "    if mv >= 2 {\n        return 17;\n    }\n    return 11;", "    return 17;"),
    ("v2: operator 18 accepted", "src/ir.cho", "        return 17;", "        return 18;"),
    ("v2: unary operator 4 accepted", "src/ir.cho", "if int_of(data[cur[0]]) > 3 {", "if int_of(data[cur[0]]) > 4 {"),
    ("v2: In with no members accepted", "src/ir.cho", "if int_of(data[cur[0]]) > 1 || n < 1 {", "if int_of(data[cur[0]]) > 1 {"),
    ("v2: In negated 2 accepted", "src/ir.cho", "if int_of(data[cur[0]]) > 1 || n < 1 {", "if int_of(data[cur[0]]) > 2 || n < 1 {"),
    ("v2: Case with no pairs accepted", "src/ir.cho", "if n < 1 || has_else > 1 {", "if has_else > 1 {"),
    ("v2: Case else flag 2 accepted", "src/ir.cho", "if n < 1 || has_else > 1 {", "if n < 1 || has_else > 2 {"),
    ("v2: a Case else is not owed", "src/ir.cho", "pending = pending + 2 * n + has_else;", "pending = pending + 2 * n;"),
    ("v2: a Case pair owes one", "src/ir.cho", "pending = pending + 2 * n + has_else;", "pending = pending + n + has_else;"),
    ("v2: an In owes no members", "src/ir.cho", "pending = pending + 1 + n;", "pending = pending + 1;"),
    ("v2: a Cast operand is not owed", "src/ir.cho", "} else {\n                    pending = pending + 1;\n                }\n            } else {", "} else {\n                    pending = pending + 0;\n                }\n            } else {"),
    ("v2: distinct 2 accepted", "src/ir.cho", "if int_of(data[cur[0]]) > 1 {\n                        good = false;\n                    }\n                    cur[0] = cur[0] + 1;\n                }\n                if good {\n                    let ni", "if int_of(data[cur[0]]) > 2 {\n                        good = false;\n                    }\n                    cur[0] = cur[0] + 1;\n                }\n                if good {\n                    let ni"),
    ("v2: a Select2 without from accepted", "src/ir.cho", "                    if nf < 1 {\n                        good = false;\n                    }", "                    if nf < 0 {\n                        good = false;\n                    }"),
    ("v2: the first from may be a join", "src/ir.cho", "if kind > 2 || fi == 0 && kind != 0 || flag > 1 || flag != joined {", "if kind > 2 || flag > 1 || flag != joined {"),
    ("v2: join kind 3 accepted", "src/ir.cho", "if kind > 2 || fi == 0 && kind != 0 || flag > 1 || flag != joined {", "if kind > 3 || fi == 0 && kind != 0 || flag > 1 || flag != joined {"),
    ("v2: a join needs no on", "src/ir.cho", "if kind > 2 || fi == 0 && kind != 0 || flag > 1 || flag != joined {", "if kind > 2 || fi == 0 && kind != 0 || flag > 1 {"),
    ("v2: a comma may have an on", "src/ir.cho", "|| flag > 1 || flag != joined {", "|| flag > 1 || (joined == 1 && flag != 1) {"),
    ("v2: order direction 2 accepted", "src/ir.cho", "if int_of(data[cur[0]]) > 1 || int_of(data[cur[0] + 1]) > 2 {", "if int_of(data[cur[0]]) > 2 || int_of(data[cur[0] + 1]) > 2 {"),
    ("v2: order nulls 3 accepted", "src/ir.cho", "if int_of(data[cur[0]]) > 1 || int_of(data[cur[0] + 1]) > 2 {", "if int_of(data[cur[0]]) > 1 || int_of(data[cur[0] + 1]) > 3 {"),
    ("v2: the from table is not a read", "src/ir.cho", "                        } else {\n                            m = add(heap, m, 0, data, nm[0], nm[1], false, 0, 0);\n                            if !commit.have(data, cur, 2) {", "                        } else {\n                            if !commit.have(data, cur, 2) {"),
    ("v2: a join condition is not parsed", "src/ir.cho", "                                } else if flag == 1 {\n                                    let (grown, ok) = expr(heap, m, data, cur, nm, true, mv);\n                                    m = grown;\n                                    good = ok;\n                                }", "                                } else if flag == 1 {\n                                    good = false;\n                                }"),
    # ---- statement IR (ir.md)
    ("IR: select forgets the table read", "src/ir.cho", "                        } else {\n                            m = add(heap, m, 0, data, nm[0], nm[1], false, 0, 0);\n                        }\n                        i = i + 1;", "                        } else {\n                            m = m;\n                        }\n                        i = i + 1;"),
    ("IR: column read forgets the column", "src/ir.cho", "m = add(heap, m, 0, data, t_at, t_len, true, nm[0], nm[1]);", "m = add(heap, m, 0, data, t_at, t_len, false, 0, 0);"),
    ("IR: column read forgets the table", "src/ir.cho", "data, t_at, t_len, true, nm[0], nm[1]);", "data, nm[0], nm[1], false, 0, 0);"),
    ("IR: columns are not reads", "src/ir.cho", "m = add(heap, m, 0, data, t_at, t_len, true, nm[0], nm[1]);", "m = m;"),
    ("IR: insert forgets the write", "src/ir.cho", "m = add(heap, m, 1, data, nm[0], nm[1], false, 0, 0);\n                    let ncols", "let ncols"),
    ("IR: update forgets the write", "src/ir.cho", "m = add(heap, m, 1, data, nm[0], nm[1], false, 0, 0);\n                    let nsets", "let nsets"),
    ("IR: delete forgets the write", "src/ir.cho", "m = add(heap, m, 1, data, nm[0], nm[1], false, 0, 0);\n                    let (grown, ok) = opt", "let (grown, ok) = opt"),
    ("IR: ddl is a write", "src/ir.cho", "m = add(heap, m, 2, data, nm[0], nm[1], false, 0, 0);", "m = add(heap, m, 1, data, nm[0], nm[1], false, 0, 0);"),
    ("IR: call statement forgets the call", "src/ir.cho", "m = add(heap, m, 3, data, nm[0], nm[1], false, 0, 0);\n                    let na", "let na"),
    ("IR: call expression forgets the call", "src/ir.cho", "m = add(heap, m, 3, data, nm[0], nm[1], false, 0, 0);\n                    if !commit.have(data, cur, 4)", "if !commit.have(data, cur, 4)"),
    ("IR: nondet forgets the source", "src/ir.cho", "m = add(heap, m, 4, data, nm[0], nm[1], false, 0, 0);", "m = m;"),
    ("IR: dots allowed in names", "src/ir.cho", "if int_of(data[cur[0] + i]) == '.' {", "if false {"),
    ("IR: empty names allowed", "src/ir.cho", "if l == 0 || !commit.have(data, cur, l) {", "if !commit.have(data, cur, l) {"),
    ("IR: column reference allowed in VALUES", "src/ir.cho", "if !allow_col || !name(data, cur, nm, true) {", "if !name(data, cur, nm, true) {"),
    ("IR: insert row length unchecked", "src/ir.cho", "if rc != ncols {", "if false {"),
    ("IR: select without from allowed", "src/ir.cho", "if nt < 1 {", "if nt < 0 {"),
    ("IR: update without sets allowed", "src/ir.cho", "if nsets < 1 {", "if nsets < 0 {"),
    ("IR: ddl kind 5 allowed", "src/ir.cho", "if int_of(data[cur[0]]) > 4 {", "if int_of(data[cur[0]]) > 5 {"),
    ("IR: operator 12 allowed in a v1 store", "src/ir.cho", "        return 17;\n    }\n    return 11;", "        return 17;\n    }\n    return 12;"),
    ("IR: value tag 3 allowed", "src/ir.cho", "} else if vt != 0 {\n                        good = false;", "} else if vt != 0 {\n                        good = good;"),
    ("IR: optional flag 2 allowed", "src/ir.cho", "return (set, flag == 0);", "return (set, true);"),
    ("IR: unknown expression tag allowed", "src/ir.cho", "            } else {\n                good = false;\n            }\n            // every node", "            } else {\n                good = good;\n            }\n            // every node"),
    ("IR: an operator owes one operand", "src/ir.cho", "pending = pending + 2;", "pending = pending + 1;"),
    ("IR: a call owes no operands", "src/ir.cho", "pending = pending + commit.be(data, cur[0], 4);", "pending = pending + 0;"),
    ("IR: trailing bytes allowed", "src/ir.cho", "if good && cur[0] != len(data) {", "if false {"),
    ("IR: statement id without domain", "src/ir.cho", '        crypto.sha256_update(sha, "cancho-db/stmt/v1");\n', ""),
    ("IR: recorded may be smaller", "src/ir.cho", "var same = size == ne;", "var same = size >= ne;"),
    ("IR: inferred elements not compared", "src/ir.cho", "if !found {\n                    same = false;\n                }", "if false {\n                    same = false;\n                }"),
    ("IR: missing statement ignored", "src/ir.cho", "if off < 0 {\n            verdict = 1;", "if off < 0 {\n            verdict = 0;"),
    ("IR: only the first statement counts", "src/ir.cho", "while i < n && verdict == 0 {", "while i < 1 && verdict == 0 {"),
    ("IR: effects judged before the statements", "src/l2.cho", "if ircode == 1 {\n                            rule = commit.stmt_missing();\n                        } else if ircode == 2 {\n                            rule = commit.effects_mismatch();\n                        } else if token.effect_denied(tk, enc, out[commit.f_effects_at()], out[commit.f_effects_n()]) {\n                            rule = commit.effect_denied();\n                        }",
     "if token.effect_denied(tk, enc, out[commit.f_effects_at()], out[commit.f_effects_n()]) {\n                            rule = commit.effect_denied();\n                        } else if ircode == 1 {\n                            rule = commit.stmt_missing();\n                        } else if ircode == 2 {\n                            rule = commit.effects_mismatch();\n                        }"),
    ("IR: mismatch reported as missing", "src/l2.cho", "rule = commit.effects_mismatch();", "rule = commit.stmt_missing();"),
    ("IR: stmts magic unchecked", "src/l2.cho", '} else if !bytes.equal(stmts[0..8], "CHODBST1") && !bytes.equal(stmts[0..8], "CHODBST2") && !bytes.equal(stmts[0..8], "CHODBST3") {', "} else if false {"),
    ("IR: stmts truncated entry accepted", "src/l2.cho", "if len(stmts) - sat - 4 < length {", "if false {"),
    ("IR: stmts malformed entry accepted", "src/l2.cho", "if !well_formed {", "if false {"),
    ("IR: stmts record index off by one", "src/l2.cho", "bad_at = sidx;", "bad_at = sidx + 1;"),
    ("IR: statements not checked without a token match", "src/l2.cho", "if has_stmts {\n                            borrow sstore", "if false {\n                            borrow sstore"),
]

LOGIN = [
    # ---- the proxy's front door (src/login.cho, tests/login_test.cho)
    ("login: startup length below 8 accepted", "src/login.cho", "if n < 8 || n > 10000 {", "if n < 7 || n > 10000 {"),
    ("login: startup length above 10000 accepted", "src/login.cho", "if n < 8 || n > 10000 {", "if n < 8 {"),
    ("login: startup length limit off by one", "src/login.cho", "if n < 8 || n > 10000 {", "if n < 8 || n > 10001 {"),
    ("login: cancel request of any length", "src/login.cho", "if len(msg) == 12 {", "if len(msg) >= 8 {"),
    ("login: ssl request with a tail", "src/login.cho", "if len(msg) == 4 {\n            return kind_ssl();", "if len(msg) >= 4 {\n            return kind_ssl();"),
    ("login: any protocol 3.x accepted", "src/login.cho", "if code != 196608 {", "if code / 65536 != 3 {"),
    ("login: bytes after the terminator accepted", "src/login.cho", "if p != len(msg) - 1 {", "if false {"),
    ("login: duplicate parameters accepted", "src/login.cho", "if out[slot] >= 0 {", "if false {"),
    ("login: empty user accepted", "src/login.cho", "if out[0] < 0 || out[1] == 0 {", "if out[0] < 0 {"),
    ("login: empty database is not the user", "src/login.cho", "if out[2] < 0 || out[3] == 0 {", "if out[2] < 0 {"),
    ("login: base64 of 1 mod 4 accepted", "src/login.cho", "if n % 4 == 1 {", "if false {"),
    ("login: base64 leftover bits ignored", "src/login.cho", "if acc != 0 {\n        return 0 - 1;", "if false {\n        return 0 - 1;"),
    ("login: base64 padding accepted", "src/login.cho", "if c == '_' {\n        return 63;\n    }\n    return 0 - 1;", "if c == '_' {\n        return 63;\n    }\n    if c == '=' {\n        return 0;\n    }\n    return 0 - 1;"),
    ("login: base64 plus and slash accepted", "src/login.cho", "if c == '-' {\n        return 62;", "if c == '+' {\n        return 62;\n    }\n    if c == '-' {\n        return 62;"),
    ("login: signature unchecked", "src/login.cho", "if !token.chain_ok(tk, root) {", "if false {"),
    ("login: possession unchecked", "src/login.cho", "if !proved {", "if false {"),
    ("login: possession of the first key will do", "src/token.cho", "let n = blocks(tk);\n    var at = 4;\n    var i = 0;\n    while i < n - 1 {", "let n = blocks(tk);\n    var at = 4;\n    var i = 0;\n    while i < 0 {"),
    ("login: expiry unchecked", "src/login.cho", "if token.expired(tk, now_hi, now_lo) {", "if false {"),
    ("login: branch equality unchecked", "src/login.cho", "if !bytes.equal(database, branch) || token.branch_denied(tk, database) {", "if token.branch_denied(tk, database) {"),
    ("login: token pattern unchecked", "src/login.cho", "if !bytes.equal(database, branch) || token.branch_denied(tk, database) {", "if !bytes.equal(database, branch) {"),
    ("login: principal conflict unchecked", "src/login.cho", "if conflict != 0 {", "if false {"),
    ("login: principal conflict never found", "src/token.cho", "if have && !bytes.equal(tk[at..at + 32], out) {", "if false {"),
    ("login: expiry before possession", "src/login.cho", "    var proved = false;", "    if token.expired(tk, now_hi, now_lo) {\n        return login_expired();\n    }\n    var proved = false;"),
    ("login: branch before expiry", "src/login.cho", "    if token.expired(tk, now_hi, now_lo) {\n        return login_expired();\n    }\n    if !bytes.equal(database, branch)", "    if !bytes.equal(database, branch) || token.branch_denied(tk, database) {\n        return login_branch_denied();\n    }\n    if token.expired(tk, now_hi, now_lo) {\n        return login_expired();\n    }\n    if !bytes.equal(database, branch)"),
    ("login: authentication request code", "src/login.cho", "put32(buf, 5, 3);", "put32(buf, 5, 5);"),
    ("login: ready for query length", "src/login.cho", "put32(buf, 1, 5);", "put32(buf, 1, 6);"),
    ("login: error length counts the type byte", "src/login.cho", "put32(buf, 1, total - 1);", "put32(buf, 1, total);"),
    ("login: error has no V field", "src/login.cho", "buf[at] = byte_of('V');", "buf[at] = byte_of('v');"),
    ("login: error message not cut", "src/login.cho", "if mlen > room {", "if false {"),
    ("login: error written into a buffer too small", "src/login.cho", "if len(buf) < fixed {", "if len(buf) < 0 {"),
    ("login: 127.x is not all loopback", "src/login.cho", "return addr.word(who, 3) / 16777216 == 127;", "return addr.word(who, 3) == 2130706433;"),
    ("login: 126.x is loopback", "src/login.cho", "return addr.word(who, 3) / 16777216 == 127;", "return addr.word(who, 3) / 16777216 >= 126 && addr.word(who, 3) / 16777216 <= 127;"),
    ("login: 128.x is loopback", "src/login.cho", "return addr.word(who, 3) / 16777216 == 127;", "return addr.word(who, 3) / 16777216 >= 127 && addr.word(who, 3) / 16777216 <= 128;"),
    ("login: every IPv4 is loopback", "src/login.cho", "return addr.word(who, 3) / 16777216 == 127;", "return true;"),
    ("login: ::1 is not loopback", "src/login.cho", "&& addr.word(who, 3) == 1;", "&& addr.word(who, 3) == 2;"),
    ("login: any ::x is loopback", "src/login.cho", "&& addr.word(who, 3) == 1;", "&& addr.word(who, 3) >= 1;"),
    ("login: the first IPv6 word ignored", "src/login.cho", "return addr.word(who, 0) == 0 && addr.word(who, 1) == 0", "return addr.word(who, 1) == 0"),
    ("login: the third IPv6 word ignored", "src/login.cho", "&& addr.word(who, 2) == 0 && addr.word(who, 3) == 1;", "&& addr.word(who, 3) == 1;"),
    ("login: refusal tag changed", "src/login.cho", 'return "login-bad-proof";', 'return "login-bad-proofs";'),
    ("login: branch denied is not 3D000", "src/login.cho", 'return "3D000";', 'return "28P01";'),
]

PROXY = [
    # ---- the event loop (proxy/proxy.cho), judged by tests/proxy_e2e.py against a real PostgreSQL
    ("proxy: the signing key is not required", "proxy/proxy.cho", "    if !keyed {\n", "    if false {\n"),
    ("proxy: a write is not prepared first", "src/commitpath.cho", "            if step == 0 && wrote {\n                step = upstream_exec(", "            if false {\n                step = upstream_exec("),
    ("proxy: a read is prepared too", "src/commitpath.cho", "if kind >= 1 && kind <= 3 {", "if kind >= 0 && kind <= 3 {"),
    ("proxy: every connection commits on the first branch", "src/commitpath.cho", "        let bx = st[p + 23];", "        let bx = 0;"),
    ("proxy: login does not remember the connection's branch", "proxy/proxy.cho", "                                    st[p + 23] = which;", "                                    st[p + 23] = 0;"),
    ("proxy: a database that is no branch of the log is let in", "proxy/proxy.cho", "                                    rule = login.login_branch_denied();\n                                }", "                                    rule = login.login_ok();\n                                }"),
    # ---- the fork (M2c-2), judged by tests/fork_e2e.py
    ("fork: the new branch's first commit has the source's seq", "src/commitpath.cho", "            seqno = 0;", "            seqno = seqno;"),
    ("fork: the commit is on the source branch", "src/commitpath.cho", "            branch = fk[34..34 + int_of(fk[33])];", "            branch = branch;"),
    ("fork: a source that moved is not noticed", "src/commitpath.cho", "            if moved {\n                fcode = 4;", "            if false {\n                fcode = 4;"),
    ("fork: the new branch is not entered in the table", "src/commitpath.cho", "                        chain[0] = chain[0] + 1;", "                        chain[0] = chain[0] + 0;"),
    ("fork: the new branch's tip is the source's", "src/commitpath.cho", "let ntip = contents(core.store.tip)[64 * nb..64 * nb + 64];", "let ntip = contents(core.store.tip)[64 * bx..64 * bx + 64];"),
    ("fork: the token's branch pattern is not checked", "src/forkpath.cho", "    if token.branch_denied(", "    if false && token.branch_denied("),
    ("fork: a fork inside a transaction is let through", "src/forkpath.cho", "    if ts != 0 {\n        return refuse(tab, core, k, ts, \"25001\", \"fork-in-transaction\"", "    if false {\n        return refuse(tab, core, k, ts, \"25001\", \"fork-in-transaction\""),
    ("fork: a taken name is let through", "src/forkpath.cho", "    if tk == 1 {", "    if tk == 9 {"),
    ("fork: the name is not validated", "src/fork.cho", "    if !upstream.branch_name_ok(sql[start..start + nl]) {", "    if false {"),
    ("fork: a branch is always forked from the first", "src/fork.cho", "    if src_is_first {", "    if true {"),
    ("fork: a fork is not recognised", "src/forkpath.cho", "    if nstmts != 1 ||", "    if nstmts != 7 ||"),
    ("fork: the extended protocol runs a fork", "src/extended.cho", "} else if vd[6] == 0 && forkpath.is_fork(vd[7], effs[0..vd[9]]) {", "} else if false {"),
    ("fork: a new client's token is taken for stored", "proxy/proxy.cho", "                                contents(core.acci)[8 * k + 4] = 0;", "                                contents(core.acci)[8 * k + 4] = contents(core.acci)[8 * k + 4];"),
    ("fork: the branch's snapshot is the first's", "src/catalog.cho", "                if bx == 0 {\n                    var qi = 0;", "                if true {\n                    var qi = 0;"),
    ("fork: the upstream connection has no search_path", "proxy/proxy.cho", "                    if st[p + 23] > 0 {\n                        // a branch other than the first lives", "                    if false {\n                        // a branch other than the first lives"),
    # ---- AS OF (M2d-3), judged by tests/asof_e2e.py
    ("asof: the delta rows are stamped without their place in the log", "src/commitpath.cho", "\"'::bytea, ord = \");", "\"'::bytea, ord = 0 * \");"),
    ("asof: the mark has the wrong place in the log", "src/commitpath.cho", "at = build.put_bytes(q, at, \"', \");\n                at = dec_sql(q, at, chain[2]);", "at = build.put_bytes(q, at, \"', \");\n                at = dec_sql(q, at, chain[2] + 1);"),
    ("asof: a fork's mark is in the first branch's schema", "src/commitpath.cho", "                if forking || bx > 0 {\n                    at = build.put_bytes(q, at, \"cdb_b_\");", "                if false {\n                    at = build.put_bytes(q, at, \"cdb_b_\");"),
    ("merge: the second parent is the target's own tip", 'src/commitpath.cho', 'mp[32 + q4] = contents(core.store.tip)[64 * src + q4];', 'mp[32 + q4] = contents(core.store.tip)[64 * bx + q4];'),
    ('merge: the state ignores the second parent', 'src/commitpath.cho', '            state.state(2, ms[0..64], chg, stt);', '            state.state(1, ms[0..32], chg, stt);'),
    ('merge: a source that moved is not noticed', 'src/commitpath.cho', 'if mp[q5] != fk[q5] || mp[32 + q5] != fk[80 + q5] {', 'if mp[q5] != fk[q5] {'),
    ('merge: a target that moved is not noticed', 'src/commitpath.cho', 'if mp[q5] != fk[q5] || mp[32 + q5] != fk[80 + q5] {', 'if mp[32 + q5] != fk[80 + q5] {'),
    ("merge: the base is the target's tip", 'src/forkpath.cho', '    let base = merge_base(core, tx[bx], tx[src]);', '    let base = tx[bx];'),
    ('merge: the walk stops at the first commit', 'src/forkpath.cho', '        if v == 3 {\n            return i;', '        if v == 3 {\n            return 0;'),
    ('merge: any token may merge', 'src/forkpath.cho', '    if !may_write_all(snap,', '    if false && !may_write_all(snap,'),
    ('merge: a branch may be merged into itself', 'src/forkpath.cho', '    if src == bx {', '    if false {'),
    ('merge: the extended protocol runs a merge', 'src/extended.cho', '} else if vd[6] == 0 && forkpath.is_merge(vd[7], effs[0..vd[9]]) {', '} else if false {'),
    ('merge: a merge is not recognised', 'src/forkpath.cho', '    return is_call(nstmts, effs, "cancho_merge");', '    return is_call(nstmts, effs, "cancho_merg");'),
    ("merge: a merge commit's second parent is not in the graph", 'src/commitpath.cho', 'contents(core.store.cg)[2 * gi + 1] = gp1;', 'contents(core.store.cg)[2 * gi + 1] = 0 - 1;'),
    ("merge: a commit's branch is not in the graph", 'src/commitpath.cho', 'contents(core.store.cbr)[gi] = byte_of(nb);', 'contents(core.store.cbr)[gi] = byte_of(0);'),
    ("merge: a branch's last commit is not in the graph", 'src/commitpath.cho', '                    txs[nb] = gi;', '                    txs[nb] = txs[nb];'),
    ("merge: the source's schema is the first branch's", 'src/forkpath.cho', 'contents(core.rend), tn, bx == 0, sn, src == 0, bn, bb == 0, base);', 'contents(core.rend), tn, bx == 0, sn, true, bn, bb == 0, base);'),
    ("proxy: the chain does not advance", "src/commitpath.cho", "chain[4 + 3 * nb + 1] = chain[4 + 3 * nb + 1] + 1;", "chain[4 + 3 * nb + 1] = chain[4 + 3 * nb + 1];"),
    ("proxy: the tip is not remembered", "src/commitpath.cho", "                        ntip[j] = ident[j];", "                        ntip[j] = ntip[j];"),
    ("proxy: the token is never stored", "src/commitpath.cho", "            if ai[8 * k + 4] == 0 {\n                tl = build.store_record(tr, 0, tk);", "            if false {\n                tl = build.store_record(tr, 0, tk);"),
    ("proxy: the statements are not recorded", "src/commitpath.cho", "irat = np;\n                                build.put_bytes(acc[base..base + 2048]", "irat = irat + 0;\n                                build.put_bytes(acc[base..base + 2048]"),
    ("proxy: the effects are not recorded", "src/commitpath.cho", "build.put_bytes(acc[base + shared.acc_effs_at()..base + shared.acc_snap_at()], ai[8 * k + 2], effs);", "ai[8 * k + 2] = ai[8 * k + 2] + 0;"),
    ("proxy: the schema is not the transaction's own", "src/commitpath.cho", "crypto.sha256(snapshot, acc[k * shared.acc_stride() + shared.acc_snap_at()..k * shared.acc_stride() + shared.acc_snap_at() + 32]);", "crypto.sha256(\"\", acc[k * shared.acc_stride() + shared.acc_snap_at()..k * shared.acc_stride() + shared.acc_snap_at() + 32]);"),
    ("proxy: recovery rolls back what the log has", "src/catalog.cho", "                    if held == 1 {\n                        at = build.put_bytes(sql, 0, \"COMMIT PREPARED '\");", "                    if held == 0 {\n                        at = build.put_bytes(sql, 0, \"COMMIT PREPARED '\");"),
    ("proxy: recovery tries other databases' transactions", "src/catalog.cho", " and database = current_database() order by prepared", " order by prepared"),
    ("proxy: recovery commits what the log lacks", "src/catalog.cho", "    if want < 0 {\n        return 0 - 1;\n    }\n    return found;", "    if want < 0 {\n        return 0 - 1;\n    }\n    return 1;"),
    ("proxy: recovery settles nothing", "src/catalog.cho", "    if status == 0 {\n        region g {", "    if false {\n        region g {"),
    ("proxy: a log failure leaves the transaction prepared", "src/commitpath.cho", "                        upstream_exec(tab, core, b, q[0..gid_sql(q, \"ROLLBACK PREPARED '\", ident)]);", "                        step = 0;"),
    ("proxy: a commit's id is not in the recovery table", "src/commitpath.cho", "                    chain[2] = chain[2] + 1;", "                    chain[2] = chain[2] + 0;"),
    ("proxy: now() is not recorded", "src/commitpath.cho", "            nd[0] = byte_of(1);\n            build.put_be(nd, 1, nowv, 8);\n            nds = 1;", "            nds = 0;"),
    ("proxy: now() is the proxy's clock, not the transaction's", "src/commitpath.cho", "            build.put_be(nd, 1, nowv, 8);", "            build.put_be(nd, 1, contents(core.aux)[1] * 1000, 8);"),
    ("proxy: a transaction without now() records one", "src/commitpath.cho", "    if ai[8 * k + 6] == 1 {\n        let nr", "    if true {\n        let nr"),
    ("proxy: now() is not noted when added", "src/commitpath.cho", "        ai[8 * k + 6] = 1;\n    }\n    return 0;", "        ai[8 * k + 6] = 0;\n    }\n    return 0;"),
    ("proxy: the statements of a transaction are not limited", "src/commitpath.cho", "    if ai[8 * k] + n > shared.acc_stmts() ||", "    if false ||"),
    ("proxy: rows stream past a held tag", "proxy/proxy.cho", "                    if st[q + 21] == 1 && st[cp + 18] > 0 {\n                        // anything that follows", "                    if false {\n                        // anything that follows"),
    ("proxy: an older held tag is kept, not released", "proxy/proxy.cho", "                            if st[cp + 18] > 0 {\n                                if !shared.send(", "                            if false {\n                                if !shared.send("),
    ("proxy: non-loopback clients are served", "proxy/proxy.cho", "if !is_loopback(ct, a) {", "if false {"),
    ("proxy: the token is not checked", "proxy/proxy.cho", "if rule != login.login_ok() {", "if false {"),
    ("proxy: a silent client is never closed", "proxy/proxy.cho", "now - st[p + 11] > shared.hello_ms()", "false"),
    ("proxy: a silent upstream is waited for a minute", "src/shared.cho", "fn login_ms() -> [] int {\n    return 5000;", "fn login_ms() -> [] int {\n    return 60000;"),
    ("proxy: the upstream's bytes lose the last one", "proxy/proxy.cho", "            if !shared.send(tab, core, client, rb[pos..pos + n]) {", "            if !shared.send(tab, core, client, rb[pos..pos + n - 1]) {"),
    ("proxy: the signing key's public half is not derived", "src/shared.cho", "ed25519.public_key_from_seed(seed, contents(sw)[32..64]);", "contents(sw)[32] = byte_of(0);"),
    # ---- the row-delta capture (M2b-2a), judged by tests/proxy_e2e.py
    ("proxy: the capture is not installed", "src/catalog.cho", "    while i < capture_sql.count() {", "    while i < 0 {"),
    ("proxy: a keyless table does not stop the start", "src/catalog.cho", "    if commitpath.first_text_at(contents(core.snapin)) >= 0 {\n        return 1;", "    if false {\n        return 1;"),
    ("proxy: the tables already there are not tracked", "src/catalog.cho", '"select cdb.track_all()"', '"select 1"'),
    # ---- changes and state in the commit (M2b-2b), judged by tests/changes_e2e.py
    ("chg: the facts are not asked for", "src/commitpath.cho", '"select case when length(f) > 200000 then \'!\' else f end from (select cdb.facts(txid_current()) as f) s"', '"select \'\'"'),
    ("chg: state ignores the parent's state", "src/commitpath.cho", "state.state(np, tip[32..32 + 32 * np], chg, stt);", "state.state(0, tip[32..32], chg, stt);"),
    ("chg: the tip does not keep the state", "src/commitpath.cho", "tip[32 + j] = stt[j];", "tip[32 + j] = byte_of(0);"),
    ("chg: the delta rows are not stamped with the commit", "src/commitpath.cho", "step = upstream_exec(tab, core, b, q[0..dn]);", "step = 0;"),
    ("chg: the bound on facts is not asked", "src/commitpath.cho", "length(f) > 200000 then", "length(f) > 20000000 then"),
    ("chg: a restart does not read the tip's state", "src/store.cho", "tip[64 * found + 32 + j] = enc[out[commit.f_state_at()] + j];", "tip[64 * found + 32 + j] = byte_of(0);"),
    ("proxy: SSLRequest is not answered N", "proxy/proxy.cho", "let no = alloc_slice[r](1, byte_of('N'));", "let no = alloc_slice[r](1, byte_of('S'));"),
    ("proxy: the client's application_name is dropped", "proxy/proxy.cho", "if st[p + 8] >= 0 && at + st[p + 9] + 4 < 1000 {", "if false {"),
    ("proxy: the upstream role is the client's", "src/upstream.cho", "\n    at = put_cstr(msg, at, cfg[32 + ci[2]..32 + ci[2] + ci[3]]);", "\n    at = put_cstr(msg, at, cfg[32 + ci[4]..32 + ci[4] + ci[5]]);"),
    ("proxy: a refused login still opens the upstream", "proxy/proxy.cho", "shared.refuse(tab, core, k, \"FATAL\", login.sqlstate(rule), login.rule_name(rule), \"the capability token was refused\");", "st[p] = 5;"),
    ("proxy: protocol versions are not checked", "proxy/proxy.cho", "} else if kind == login.err_version() {", "} else if false {"),
    # ---- the query path (P1d-2)
    ("proxy: the rendering is not what is sent", "proxy/proxy.cho", "run_query(tw, core, k, rl);", "run_query(tw, core, k, 0);"),
    ("proxy: a refused query is sent upstream anyway", "proxy/proxy.cho", "                if verdict != 0 {\n                    refused_query(tw, core, k, vd);", "                if false {\n                    refused_query(tw, core, k, vd);"),
    ("proxy: a Parse message is a protocol violation", "proxy/proxy.cho", "} else if ty == 'P' || ty == 'B' ||", "} else if ty == 'B' ||"),
    ("ext: messages after an unsupported message are answered too", "proxy/proxy.cho", "                        st[p + 15] = 1;\n                    }\n                    shared.consume(core, k, ln + 1);", "                        st[p + 15] = 0;\n                    }\n                    shared.consume(core, k, ln + 1);"),
    ("proxy: Sync after a refusal is not answered", "src/extended.cho", "            let n = login.ready_for_query(z, status);\n            shared.send(tab, core, k, z[0..n]);", "            let n = login.ready_for_query(z, status);"),
    # ---- transactions (P2a)
    ("proxy: an autocommit statement is not wrapped in a transaction", "proxy/proxy.cho", "    if ts == 0 {\n        let r = commitpath.upstream_exec(tab, core, b, \"BEGIN\");\n        if r != 0 {\n            shared.answer_error(tab, core, k, 73, \"08006\", \"upstream-unavailable\", \"the database could not begin a transaction\");\n            return 0;\n        }\n        st[shared.stride() * b + 21] = 1;", "    if false {\n        let r = commitpath.upstream_exec(tab, core, b, \"BEGIN\");\n        if r != 0 {\n            shared.answer_error(tab, core, k, 73, \"08006\", \"upstream-unavailable\", \"the database could not begin a transaction\");\n            return 0;\n        }\n        st[shared.stride() * b + 21] = 1;"),
    ("proxy: CommandComplete is not held in autocommit", "proxy/proxy.cho", "                        if ty == 'C' && st[q + 21] == 1 {", "                        if false {"),
    ("proxy: a failed autocommit statement is committed", "proxy/proxy.cho", "    if failed {\n        r = commitpath.upstream_exec(tab, core, k, \"ROLLBACK\");", "    if false {\n        r = commitpath.upstream_exec(tab, core, k, \"ROLLBACK\");"),
    ("proxy: the server's E status does not fail the client's transaction", "proxy/proxy.cho", "                                } else {\n                                    st[cp + 16] = 2;\n                                }", "                                } else {\n                                    st[cp + 16] = 1;\n                                }"),
    ("proxy: a refused statement leaves the transaction open", "proxy/proxy.cho", "        commitpath.upstream_exec(tab, core, st[p + 1], \"ROLLBACK\");\n        commitpath.reset(core, k);\n        st[p + 16] = 2;", "        commitpath.upstream_exec(tab, core, st[p + 1], \"ROLLBACK\");\n        commitpath.reset(core, k);\n        st[p + 16] = 1;"),
    ("proxy: COMMIT does not commit", "proxy/proxy.cho", "    let committing = kind == 2 && ts == 1;", "    let committing = false;"),
    ("proxy: a statement runs in a failed transaction", "proxy/proxy.cho", "    if ts == 2 {\n        shared.answer_error(tab, core, k, 'E', \"25P02\"", "    if false {\n        shared.answer_error(tab, core, k, 'E', \"25P02\""),
    ("proxy: queries are served while a statement is in flight", "proxy/proxy.cho", " && st[shared.stride() * k + 17] == 0 {", " {"),
    ("proxy: BEGIN inside a transaction is forgiven", "proxy/proxy.cho", "        } else if ts == 1 {\n            shared.answer_error(tab, core, k, 'T', \"25001\"", "        } else if ts == 3 {\n            shared.answer_error(tab, core, k, 'T', \"25001\""),
    ("proxy: a refusal does not say ReadyForQuery", "src/shared.cho", "        n = n + login.ready_for_query(buf[n..640], status);", "        n = n + 0;"),
    # ---- cancho_erase (E4a), judged by tests/erase_e2e.py
    ("erase: the table the token may write is not checked", "src/forkpath.cho", "            if token.effect_denied(contents(core.tokb)[k * shared.token_max()..k * shared.token_max() + st[p + 12]], enc, 0, 1) {", "            if false {"),
    ("erase: the statement record keeps the key", "proxy/proxy.cho", "effs[0..vd[9]], forkpath.is_erase(vd[7], effs[0..vd[9]]));", "effs[0..vd[9]], false);"),
    ("erase: allowed inside a transaction block", "src/forkpath.cho", "    if ts != 0 {\n        return refuse(tab, core, k, ts, \"25001\", \"erase-in-transaction\"", "    if false {\n        return refuse(tab, core, k, ts, \"25001\", \"erase-in-transaction\""),
    ("erase: a backslash is allowed in the key", "src/erase.cho", "if c == '\\'' || c == '\\\\' || c < 32 {", "if c == '\\'' || c < 32 {"),
    ("erase: a table may start with a digit", "src/erase.cho", "digit && i > 0", "digit"),
    ("erase: the key need not start with a bracket", "src/erase.cho", " || int_of(key[0]) != '[' || ", " || "),
    ("erase: the key need not end with a bracket", "src/erase.cho", " || int_of(key[len(key) - 1]) != ']' {", " {"),
    ("erase: the call is run outside the erase path (the guard's rendering is sent)", "proxy/proxy.cho", "                    } else if forkpath.is_erase(vd[7], effs[0..vd[9]]) {\n                        rl = forkpath.start_erase(tw, core, k, ts, sql);\n", "                    } else if false {\n                        rl = forkpath.start_erase(tw, core, k, ts, sql);\n"),
    # ---- the extended protocol (P3b/P3c), judged by tests/ext_e2e.py
    ("ext: names starting cdb are not reserved", "src/extended.cho", "int_of(name[0]) == 'c' && int_of(name[1]) == 'd' && int_of(name[2]) == 'b';", "int_of(name[0]) == 'c' && int_of(name[1]) == 'd' && int_of(name[2]) == 'z';"),
    ("ext: a statement is not counted at Execute", "src/extended.cho", "            if added != 0 {\n                fail(tw, core, k, \"54000\"", "            if added != 0 || true {\n                fail(tw, core, k, \"54000\""),
    ("ext: a refusal does not roll back the implicit transaction", "src/extended.cho", "    if st[q + 21] == 1 {\n        commitpath.upstream_exec(tab, core, up, \"ROLLBACK\");\n        st[q + 21] = 0;", "    if st[q + 21] == 9 {\n        commitpath.upstream_exec(tab, core, up, \"ROLLBACK\");\n        st[q + 21] = 0;"),
    ("ext: messages after an error are not discarded", "src/extended.cho", "    if contents(core.state)[shared.stride() * k + 15] != 0 && ty != 'S' {", "    if false && ty != 'S' {"),
]

def run_proxy(cancho):
    """Each mutant is built and judged by the whole end-to-end test. They are slow (about three minutes each), so several run at
    once, each in a database of its own on the same server (E2E_DB) and with its own wire tee and ports."""
    import concurrent.futures
    import queue
    skip = int(os.environ.get("MUTANT_FROM", "0"))
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in PROXY[skip:] if not only or only in m[0]]
    workers = int(os.environ.get("MUTANT_JOBS", "4"))
    port = os.environ.get("PG_E2E_PORT", "5532")
    dbs = queue.Queue()
    for w in range(workers):
        name = "mutant_db_%d" % w
        for sql in ("drop database if exists %s" % name, "create database %s" % name):
            subprocess.run(["psql", "-h", "127.0.0.1", "-p", port, "-U", "postgres", "-d", "postgres", "-c", sql],
                           capture_output=True)
        dbs.put(name)

    def one(item):
        label, rel, old, new = item
        db = dbs.get()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                for d in ("src", "proxy", "tools", "tests"):
                    shutil.copytree(ROOT / d, work / d, ignore=shutil.ignore_patterns("__pycache__"))
                f = work / rel
                text = f.read_text()
                if text.count(old) != 1:
                    return label, "STALE  %-52s original text occurs %d times" % (label, text.count(old)), False
                f.write_text(text.replace(old, new))
                exe = work / "proxy_mutant"
                b = subprocess.run([cancho, "build", "--std", str(work / "proxy/proxy.cho"), str(work / "src/commit.cho"),
                                    str(work / "src/token.cho"), str(work / "src/login.cho")]
                                   + [str(work / "src" / n) for n in ("lex.cho", "parse.cho", "stmt.cho", "lower.cho", "ir.cho", "guard.cho", "snapshot.cho", "build.cho", "store.cho", "l1.cho", "upstream.cho", "shared.cho", "commitpath.cho", "catalog.cho", "extended.cho", "capture_sql.cho", "state.cho", "fork.cho", "forkpath.cho", "erase.cho", "asof.cho")]
                                   + ["-o", str(exe)], capture_output=True, text=True)
                if b.returncode != 0:
                    return label, "BROKEN %-52s does not build: %s" % (label, b.stderr.strip()[:160]), False
                try:
                    judge = "ext_e2e.py" if label.startswith("ext:") else "changes_e2e.py" if label.startswith("chg:") else "fork_e2e.py" if label.startswith("fork:") else "asof_e2e.py" if label.startswith("asof:") else "merge_e2e.py" if label.startswith("merge:") else "erase_e2e.py" if label.startswith("erase:") else "proxy_e2e.py"
                    r = subprocess.run([sys.executable, str(work / "tests" / judge), str(exe)], capture_output=True,
                                       text=True, timeout=600, env=dict(os.environ, E2E_DB=db))
                    out, code = r.stdout + r.stderr, r.returncode
                except subprocess.TimeoutExpired:
                    out, code = "timed out", 1
                if code == 0:
                    return label, "SURVIVED %-50s every end-to-end check passes" % label, False
                failed = [l[5:].strip() for l in out.splitlines() if l.startswith("FAIL")]
                return label, "killed   %-50s by: %s" % (label, (failed[0] if failed else out.strip().splitlines()[-1])[:90]), True
        finally:
            dbs.put(db)

    with concurrent.futures.ThreadPoolExecutor(workers) as ex:
        results = list(ex.map(one, table))
    survivors = []
    for label, line, killed in results:
        print(line)
        if not killed:
            survivors.append(label)
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


LEX = [
    ("lex: $0 is a parameter", "src/lex.cho", "if int_of(sql[i + 1]) == '0' || v > 65535 ||", "if v > 65535 ||"),
    ("lex: a parameter may be over 65535", "src/lex.cho", "if int_of(sql[i + 1]) == '0' || v > 65535 ||", "if int_of(sql[i + 1]) == '0' ||"),
    ("lex: a parameter may be followed by identifier characters", "src/lex.cho", "j < n_in && (is_digit(int_of(sql[j])) || is_ident_char(int_of(sql[j])))", "false"),
    ("lex: a parameter's text is cut short", "src/lex.cho", "n = put(toks, n, t_param(), i, j - i, 0);", "n = put(toks, n, t_param(), i, j - i - 1, 0);"),
    # ---- the SQL lexer (src/lex.cho, tests/lex_test.cho)
    ("lex: block comments do not nest", "src/lex.cho", "                    depth = depth + 1;\n                    i = i + 2;", "                    i = i + 2;"),
    ("lex: a line comment runs past the newline", "src/lex.cho", "while i < n_in && int_of(sql[i]) != '\\n' {", "while i < n_in && int_of(sql[i]) != '\\r' {"),
    ("lex: a doubled quote ends a string", "src/lex.cho", "                        doubled = 1;\n                        j = j + 2;\n                    } else {\n                        closed = true;\n                    }\n                } else {\n                    j = j + 1;\n                }\n            }\n            n = put(toks, n, t_string()", "                        closed = true;\n                    } else {\n                        closed = true;\n                    }\n                } else {\n                    j = j + 1;\n                }\n            }\n            n = put(toks, n, t_string()"),
    ("lex: an empty quoted identifier is allowed", "src/lex.cho", "if width == 0 {", "if false {"),
    ("lex: a 64-byte identifier is allowed", "src/lex.cho", "fn max_ident() -> [] int {\n    return 63;", "fn max_ident() -> [] int {\n    return 64;"),
    ("lex: an identifier of 62 is refused", "src/lex.cho", "fn max_ident() -> [] int {\n    return 63;", "fn max_ident() -> [] int {\n    return 62;"),
    ("lex: non-ASCII bytes are allowed", "src/lex.cho", "        if c >= 128 {\n            return 0 - e_non_ascii();", "        if false {\n            return 0 - e_non_ascii();"),
    ("lex: a NUL byte is allowed", "src/lex.cho", "        if c == 0 {\n            return 0 - e_nul_byte();", "        if false {\n            return 0 - e_nul_byte();"),
    ("lex: dollar quoting is allowed to fall through", "src/lex.cho", "} else if c == '$' {", "} else if c == '#' {"),
    ("lex: a parameter is read as a dollar quote", "src/lex.cho", "// `$1` is a parameter; anything else is a dollar quote, which is not in the grammar\n            if i + 1 < n_in && is_digit(int_of(sql[i + 1])) {", "// `$1` is a parameter; anything else is a dollar quote, which is not in the grammar\n            if false {"),
    ("lex: lower-case e is not an escape string", "src/lex.cho", "if p == 'e' || p == 'E' {", "if p == 'E' {"),
    ("lex: n is not a prefix", "src/lex.cho", "|| p == 'n' || p == 'N' {", "{"),
    ("lex: x is not a prefix", "src/lex.cho", "|| p == 'x' || p == 'X' || p == 'n'", "|| p == 'n'"),
    ("lex: a two-letter prefix is one too", "src/lex.cho", "if j - i == 1 && j < n_in && int_of(sql[j]) == '\\'' {", "if j - i <= 2 && j < n_in && int_of(sql[j]) == '\\'' {"),
    ("lex: U&' is an ordinary string", "src/lex.cho", "if j - i == 1 && (c == 'u' || c == 'U') &&", "if false && (c == 'u' || c == 'U') &&"),
    ("lex: U&\" is an ordinary identifier", "src/lex.cho", "&& (int_of(sql[j + 1]) == '\\'' || int_of(sql[j + 1]) == '\"')", "&& (int_of(sql[j + 1]) == '\\'')"),
    ("lex: a number may be followed by letters", "src/lex.cho", "if j < n_in && is_ident_char(int_of(sql[j])) {\n                return 0 - e_number_junk();", "if false {\n                return 0 - e_number_junk();"),
    ("lex: an exponent is not read", "src/lex.cho", "if j < n_in && (int_of(sql[j]) == 'e' || int_of(sql[j]) == 'E') {", "if false {"),
    ("lex: a fraction is not read", "src/lex.cho", "if j < n_in && int_of(sql[j]) == '.' {\n                j = j + 1;", "if false {\n                j = j + 1;"),
    ("lex: .5 is not a number", "src/lex.cho", "} else if is_digit(c) || c == '.' && i + 1 < n_in && is_digit(int_of(sql[i + 1])) {", "} else if is_digit(c) {"),
    ("lex: $ may not be inside an identifier", "src/lex.cho", "return is_ident_start(c) || is_digit(c) || c == '$';", "return is_ident_start(c) || is_digit(c);"),
    ("lex: an operator runs into a line comment", "src/lex.cho", "if d == '-' && j + 1 < n_in && int_of(sql[j + 1]) == '-' {\n                    stop = true;", "if false {\n                    stop = true;"),
    ("lex: an operator runs into a block comment", "src/lex.cho", "} else if d == '/' && j + 1 < n_in && int_of(sql[j + 1]) == '*' {\n                    stop = true;", "} else if false {\n                    stop = true;"),
    ("lex: an operator may always end in + or -", "src/lex.cho", "            if !special {", "            if false {"),
    ("lex: an operator may never end in + or -", "src/lex.cho", "            if !special {", "            if true {"),
    ("lex: ~ is not special", "src/lex.cho", "return c == '~' || c == '!' || c == '@'", "return c == '!' || c == '@'"),
    ("lex: @ is not special", "src/lex.cho", "|| c == '@' || c == '#' || c == '%' || c == '^' || c == '&' || c == '|' || c == '`' || c == '?';\n}\n\nfn put", "|| c == '#' || c == '%' || c == '^' || c == '&' || c == '|' || c == '`' || c == '?';\n}\n\nfn put"),
    ("lex: a form feed is whitespace", "src/lex.cho", "if c == ' ' || c == '\\t' || c == '\\n' || c == '\\r' {", "if c == ' ' || c == '\\t' || c == '\\n' || c == '\\r' || c == 12 {"),
    ("lex: a carriage return is not whitespace", "src/lex.cho", "if c == ' ' || c == '\\t' || c == '\\n' || c == '\\r' {", "if c == ' ' || c == '\\t' || c == '\\n' {"),
    ("lex: :: is two colons", "src/lex.cho", "} else if c == ':' && i + 1 < n_in && int_of(sql[i + 1]) == ':' {", "} else if false {"),
    ("lex: ; is ordinary punctuation", "src/lex.cho", "n = put(toks, n, t_semicolon(), i, 1, 0);", "n = put(toks, n, t_punct(), i, 1, 0);"),
    ("lex: empty statements are kept", "src/lex.cho", "            if i > from {", "            if i >= from {"),
    ("lex: the last statement is dropped", "src/lex.cho", "var cut = i == n;", "var cut = false;"),
    ("lex: the token cap is off by one", "src/lex.cho", "if n >= cap - 1 {", "if n >= cap {"),
    ("lex: a string with a prefix letter after a digit", "src/lex.cho", "fn is_ident_start(c: int) -> [] bool {\n    return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_';", "fn is_ident_start(c: int) -> [] bool {\n    return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z';"),
]

# ---- the commit builder (src/build.cho, tests/build_check.py against an independent encoder and the verifiers)
BUILD = [
    ("build: the signature is made with a key that is not the seed's", "src/build.cho", "return ed25519.sign_with_public(seed, pk, ident, out);", "return ed25519.sign_with_public(seed, seed, ident, out);"),
    ("build: bytes are written mod 255", "src/build.cho", "out[at + i] = byte_of(rest % 256);", "out[at + i] = byte_of(rest % 255);"),
    ("build: effect kinds up to 5", "src/build.cho", "int_of(effs[p]) > 4", "int_of(effs[p]) > 5"),
    ("build: effects are ordered by target only", "src/build.cho", "    if ka != kb {\n        return ka - kb;", "    if false {\n        return ka - kb;"),
    ("build: repeated effects are written twice", "src/build.cho", "effect_cmp(effs, q, last) > 0", "effect_cmp(effs, q, last) >= 0"),
    ("build: effects come out largest first", "src/build.cho", "effect_cmp(effs, q, best) < 0", "effect_cmp(effs, q, best) > 0"),
    ("build: the effect count is the input's", "src/build.cho", "put_be(out, at, written, 4);", "put_be(out, at, n, 4);"),
    ("build: the effects ignore an earlier failure", "src/build.cho", "    if at < 0 {\n        return 0 - 1;\n    }\n    // first pass", "    if false {\n        return 0 - 1;\n    }\n    // first pass"),
    ("build: a hash list may be ragged", "src/build.cho", "if len(hashes) % 32 != 0 {", "if false {"),
    ("build: the sequence's low half is mod 2^32 - 1", "src/build.cho", "at = put_be(out, at, seq % 4294967296, 4);", "at = put_be(out, at, seq % 4294967295, 4);"),
    ("build: the time's high half is lost", "src/build.cho", "at = put_be(out, at, time / 4294967296, 4);", "at = put_be(out, at, 0, 4);"),
    ("build: an empty branch is allowed", "src/build.cho", "len(branch) == 0 ||", "false ||"),
    ("build: a branch of 256 bytes is allowed", "src/build.cho", "len(branch) > 255", "len(branch) > 256"),
    ("build: a short schema hash is allowed", "src/build.cho", "len(schema) != 32 ||", "false ||"),
    ("build: the version is 2", "src/build.cho", "var at = put_be(out, 0, 1, 2);", "var at = put_be(out, 0, 2, 2);"),
    ("build: the id's domain is v2", "src/build.cho", "\"cancho-db/commit/v1\"", "\"cancho-db/commit/v2\""),
    ("build: the id leaves out the separator", "src/build.cho", "crypto.sha256_update(sha, \"cancho-db/commit/v1\");\n        crypto.sha256_update(sha, nul);", "crypto.sha256_update(sha, \"cancho-db/commit/v1\");\n        crypto.sha256_update(sha, enc[0..0]);"),
    ("build: the log's magic is wrong", "src/build.cho", "\"CHODBLG1\"", "\"CHODBLG2\""),
    ("build: the token store's magic is wrong", "src/build.cho", "\"CHODBTK1\"", "\"CHODBTK2\""),
    ("build: the statement store is v1", "src/build.cho", "\"CHODBST3\"", "\"CHODBST1\""),
    ("build: a log record's length is one over", "src/build.cho", "put_be(out, at, len(enc), 4)", "put_be(out, at, len(enc) + 1, 4)"),
    ("build: a store entry's length is one over", "src/build.cho", "put_be(out, at, len(body), 4)", "put_be(out, at, len(body) + 1, 4)"),
]



# ---- the log directory (src/store.cho, tests/store_check.py: the scan, the repair, the lock and the order of durable writes)
STORE = [
    ("store: the branches share one tip", "src/store.cho", "                                        tip[64 * found + j] = ident[j];", "                                        tip[j] = ident[j];"),
    ("store: a branch's next seq is the log's last", "src/store.cho", "bi[3 * found + 1] = out[commit.f_seq_lo()] + 1;", "bi[1] = out[commit.f_seq_lo()] + 1;"),
    ("store: the configured branch is not first", "src/store.cho", "    bi[0] = len(branch);\n    info[6] = 1;", "    bi[0] = len(branch);\n    info[6] = 0;"),
    ("store: a 65th branch is taken", "src/store.cho", "if info[6] >= branches_max() || len(bname) > branch_name_max() {", "if len(bname) > branch_name_max() {"),
    ("store: a commit's branch is not recorded", "src/store.cho", "cbr[index - 1] = byte_of(found);", "cbr[index - 1] = byte_of(0);"),
    ("store: a branch's last commit is not remembered", "src/store.cho", "                                        tx[found] = index - 1;", "                                        tx[found] = tx[found];"),
    ("store: a parent that is no tip is not looked for", "src/store.cho", "while q2 >= 0 && cg[2 * (index - 1) + pj] < 0 {", "while false && q2 >= 0 && cg[2 * (index - 1) + pj] < 0 {"),
    ("store: the log's lock is not taken", "src/store.cho", "if !locked {", "if false {"),
    ("store: a torn tail is not cut", "src/store.cho", "if code == 0 && (rewrite || good < len(all)) {", "if code == 0 && rewrite {"),
    ("store: the log is not verified", "src/store.cho", "if code == 0 && !rewrite {", "if false {"),
    ("store: another key's log is accepted", "src/store.cho", "} else if !is_prefix(head, all) {", "} else if false {"),
    ("store: the log's magic is not checked", "src/store.cho", "} else if !is_prefix(all[0..8], \"CHODBLG1\") {", "} else if false {"),
    ("store: a record's length is not limited", "src/store.cho", "whole_end(all, 40, 64, 16777216)", "whole_end(all, 40, 64, 4294967296)"),
    ("store: a record's signature is not counted in its frame", "src/store.cho", "whole_end(all, 40, 64, 16777216)", "whole_end(all, 40, 63, 16777216)"),
    ("store: the next seq is the tip's own", "src/store.cho", "bi[3 * found + 1] = out[commit.f_seq_lo()] + 1;", "bi[3 * found + 1] = out[commit.f_seq_lo()];"),
    ("store: every branch's commit is the tip", "src/store.cho", "if l1.same(names[bx * branch_name_max()..bx * branch_name_max() + bi[3 * bx]], bname) {", "if true {"),
    ("store: a torn header is cut and not rewritten", "src/store.cho", "ok = write_all(w, head);", "ok = true;"),
    ("store: a torn store tail is not cut", "src/store.cho", "ptruncate = end < len(all);", "ptruncate = false;"),
    ("store: a store's magic is not checked", "src/store.cho", "} else if !is_prefix(magic, all) {", "} else if false {"),
    ("store: the new file is not synced", "src/store.cho", "ok = write_all(w, head) && synced(w);", "ok = write_all(w, head);"),
    ("store: the log's repair is not synced", "src/store.cho", "ok = ok && synced(w);\n                        }\n                        if !ok {\n                            code = r_io();", "ok = ok;\n                        }\n                        if !ok {\n                            code = r_io();"),
    ("store: a store's repair is not synced", "src/store.cho", "ok = ok && synced(w);\n                }\n            }\n            if !ok {\n                file_close(a);", "ok = ok;\n                }\n            }\n            if !ok {\n                file_close(a);"),
    ("store: the token store is not synced", "src/store.cho", "if !write_all(tokens, token_rec) || !synced(tokens) {", "if !write_all(tokens, token_rec) {"),
    ("store: the statement store is not synced", "src/store.cho", "if !write_all(stmts, stmt_recs) || !synced(stmts) {", "if !write_all(stmts, stmt_recs) {"),
    ("store: the log is not synced", "src/store.cho", "if !write_all(log, log_rec) || !synced(log) {", "if !write_all(log, log_rec) {"),
    ("store: the commit ids are not handed over", "src/store.cho", "build.put_bytes(ids, 32 * index, ident);", "index = index + 0;"),
    ("store: the id table's size is not checked", "src/store.cho", "if 32 * (index + 1) > len(ids) {", "if false {"),
    ("store: the log is written before the stores", "src/store.cho", "    if len(token_rec) > 0 {\n        if !write_all(tokens", "    if !write_all(log, log_rec) || !synced(log) {\n        return r_io();\n    }\n    if len(token_rec) > 0 {\n        if !write_all(tokens"),
    ("erase-store: every record is erased, whatever the needle", "src/store.cho", "if contains(hay, list[at + 2..at + 2 + n]) {", "if true {"),
    ("erase-store: the erased record keeps the payload tag of a whole one", "src/store.cho", "out = buffer.append(heap, out, body[0..end + 32]);\n                            out = buffer.push(heap, out, byte_of(0));", "out = buffer.append(heap, out, body[0..end + 32]);\n                            out = buffer.push(heap, out, byte_of(1));"),
    ("erase-store: the erased record's length is one over", "src/store.cho", "out = push_be4(heap, out, end + 33);", "out = push_be4(heap, out, end + 34);"),
    ("erase-store: a whole copy is not applied at start", "src/store.cho", "        if valid {\n            match dir_open_append(dir, \"stmts\") {", "        if false {\n            match dir_open_append(dir, \"stmts\") {"),
    ("erase-store: the copy's hash is not checked", "src/store.cho", "if sum[i] != all[content_len + i] {", "if false {"),
    ("erase-store: the copy's magic is not checked", "src/store.cho", "if is_prefix(all[0..8], \"CHODBST3\") {", "if true {"),
    ("erase-store: the store is not emptied before it is rewritten", "src/store.cho", "match file_truncate(stmts, 0) {", "match file_truncate(stmts, 8) {"),
    ("erase-store: a stale copy is not removed at open", "src/store.cho", "if is_prefix(name, \"stmts\") && len(name) == 5 {", "if false {"),
    ("erase-store: a record running past the end is read", "src/store.cho", "if pos + 4 + n > len(all) {\n                        verdict = 0 - 2;", "if false {\n                        verdict = 0 - 2;"),
    ("erase-store: the store's magic is not copied", "src/store.cho", "out = buffer.append(heap, out, all[0..8]);", "out = buffer.append(heap, out, \"CHODBST1\");"),
    ("erase-store: a record is kept whole when the needle is the last bytes of its payload", "src/store.cho", "holds_any(body[end + 33..n], needles)", "holds_any(body[end + 33..n - 1], needles)"),
]


def run_unit(table, test_files, src_names, cancho):
    only = os.environ.get("MUTANT_ONLY")
    if only:
        table = [m for m in table if only in m[0]]
    survivors = []
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            shutil.copytree(ROOT / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            files = [str(work / t) for t in test_files] + [str(work / "src" / n) for n in src_names]
            r = subprocess.run([cancho, "test"] + files + ["--std"], capture_output=True, text=True)
            if r.returncode == 0:
                print("SURVIVED %-46s every unit test passes" % label)
                survivors.append(label)
            elif "running" not in r.stdout:
                print("BROKEN %-48s does not build: %s" % (label, (r.stdout + r.stderr).strip()[:160]))
                survivors.append(label)
            else:
                failed = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("test ") and "FAILED" in l]
                print("killed   %-46s by %s" % (label, ", ".join(failed) or "a trap"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0

# ---- the SQL expression parser (src/parse.cho, tests/parse_test.cho)
PARSE = [
    ("parse: a parameter is not an atom", "src/parse.cho", "} else if kind == lex.t_param() {", "} else if false {"),
    ("parse: a parameter is written back without its $", "src/parse.cho", "if kind == n_num() || kind == n_param() {\n        return put_text(out, p, sql, tstart(toks, data), tlen(toks, data), false);", "if kind == n_num() || kind == n_param() {\n        return put_text(out, p, sql, tstart(toks, data) + 1, tlen(toks, data) - 1, false);"),
    ("parse: AND binds like OR", "src/parse.cho", "if code == o_and() {\n        return 2;", "if code == o_and() {\n        return 1;"),
    ("parse: NOT binds tighter than comparison", "src/parse.cho", "if code == o_not() {\n        return 3;", "if code == o_not() {\n        return 6;"),
    ("parse: || binds like +", "src/parse.cho", "if code == o_concat() {\n        return 7;", "if code == o_concat() {\n        return 8;"),
    ("parse: || binds tighter than *", "src/parse.cho", "if code == o_concat() {\n        return 7;", "if code == o_concat() {\n        return 10;"),
    ("parse: + binds like *", "src/parse.cho", "if code == o_add() || code == o_sub() {\n        return 8;", "if code == o_add() || code == o_sub() {\n        return 9;"),
    ("parse: - is looser than +", "src/parse.cho", "if code == o_add() || code == o_sub() {", "if code == o_add() {"),
    ("parse: unary minus is loose", "src/parse.cho", "    return 11;\n}\n\nfn nonassoc", "    return 7;\n}\n\nfn nonassoc"),
    ("parse: comparisons associate", "src/parse.cho", "return prec == 5 || prec == 6;", "return prec == 6;"),
    ("parse: LIKE associates", "src/parse.cho", "return prec == 5 || prec == 6;", "return prec == 5;"),
    ("parse: comparisons bind like LIKE", "src/parse.cho", "if code >= o_eq() && code <= o_ge() {\n        return 5;", "if code >= o_eq() && code <= o_ge() {\n        return 6;"),
    ("parse: IN is looser than comparison", "src/parse.cho", "if code >= o_like() && code <= o_nin() || code == o_between() || code == o_nbetween() {\n        return 6;", "if code >= o_like() && code <= o_nin() || code == o_between() || code == o_nbetween() {\n        return 4;"),
    ("parse: IN waits for its operand", "src/parse.cho", "            r = reduce_one(nodes, kids, vs, os, st);\n        }\n    } else if code == f_paren() {", "        }\n    } else if code == f_paren() {"),
    ("parse: the first operator is reduced too late", "src/parse.cho", "let r = reduce_while(nodes, kids, vs, os, st, prec, na);", "let r = reduce_while(nodes, kids, vs, os, st, prec + 1, na);"),
    ("parse: IS does not reduce first", "src/parse.cho", "r = reduce_while(nodes, kids, vs, os, st, 4, 0 - 2);", "r = reduce_while(nodes, kids, vs, os, st, 99, 0 - 2);"),
    ("parse: IS reduces too much", "src/parse.cho", "r = reduce_while(nodes, kids, vs, os, st, 4, 0 - 2);", "r = reduce_while(nodes, kids, vs, os, st, 1, 0 - 2);"),
    ("parse: BETWEEN's AND is a logical AND", "src/parse.cho", "&& (os[top] == o_between() || os[top] == o_nbetween()) && os[top + 3] == 0 {", "&& false {"),
    ("parse: BETWEEN may be left open", "src/parse.cho", "        if b != 1 {\n            return 0 - e_syntax();\n        }\n        var neg = 0;", "        var neg = 0;"),
    ("parse: NOT BETWEEN is BETWEEN", "src/parse.cho", "var code = o_between();\n                        if neg {\n                            code = o_nbetween();", "var code = o_between();\n                        if false {\n                            code = o_nbetween();"),
    ("parse: NOT IN is IN", "src/parse.cho", "var code = o_in();\n                        if neg {\n                            code = o_nin();", "var code = o_in();\n                        if false {\n                            code = o_nin();"),
    ("parse: NOT LIKE is LIKE", "src/parse.cho", "var code = o_like();\n                        if neg {\n                            code = o_nlike();", "var code = o_like();\n                        if false {\n                            code = o_nlike();"),
    ("parse: NOT ILIKE is ILIKE", "src/parse.cho", "var code = o_ilike();\n                        if neg {\n                            code = o_nilike();", "var code = o_ilike();\n                        if false {\n                            code = o_nilike();"),
    ("parse: IS TRUE is IS NULL", "src/parse.cho", "if !kw(sql, toks, q, end, \"null\") {\n                            return fail(st, q, e_unknown_construct());\n                        }", "if false {\n                            return fail(st, q, e_unknown_construct());\n                        }"),
    ("parse: IS NOT NULL is IS NULL", "src/parse.cho", "build(nodes, kids, vs, st, n_isnull(), isneg, 1, 0 - 1, 0 - 1)", "build(nodes, kids, vs, st, n_isnull(), 0, 1, 0 - 1, 0 - 1)"),
    ("parse: != is not <>", "src/parse.cho", 'if word_is(sql, a, n, "<>") || word_is(sql, a, n, "!=") {', 'if word_is(sql, a, n, "<>") {'),
    ("parse: a reserved word is a name", "src/parse.cho", "} else if is_reserved(sql, a, l) {", "} else if false {"),
    ("parse: a reserved word after a dot is a name", "src/parse.cho", "if is_reserved(sql, tstart(toks, pos + 2), tlen(toks, pos + 2)) {", "if false {"),
    ("parse: the keyword match is case sensitive", "src/parse.cho", "if lower(int_of(sql[start + i])) != int_of(lit[i]) {", "if int_of(sql[start + i]) != int_of(lit[i]) {"),
    ("parse: the reserved list is case sensitive", "src/parse.cho", "if lower(int_of(sql[start + i])) != int_of(words[at + i]) {", "if int_of(sql[start + i]) != int_of(words[at + i]) {"),
    ("parse: the reserved list's last word is lost", "src/parse.cho", "while i <= len(words) {", "while i < len(words) {"),
    ("parse: a name is not folded", "src/parse.cho", "p = put_text(out, p, sql, tstart(toks, tok), tlen(toks, tok), tkind(toks, tok) == lex.t_ident());", "p = put_text(out, p, sql, tstart(toks, tok), tlen(toks, tok), false);"),
    ("parse: a quoted name is folded", "src/parse.cho", "p = put_text(out, p, sql, tstart(toks, tok), tlen(toks, tok), tkind(toks, tok) == lex.t_ident());", "p = put_text(out, p, sql, tstart(toks, tok), tlen(toks, tok), true);"),
    ("parse: a sub-select is not refused in parentheses", "src/parse.cho", "if starts_query(sql, toks, pos + 1, end) {", "if false {"),
    ("parse: a sub-select is not refused in IN", "src/parse.cho", "if starts_query(sql, toks, at + 2, end) {", "if false {"),
    ("parse: a sub-select is not refused in a call", "src/parse.cho", "if starts_query(sql, toks, pos + 2, end) {", "if false {"),
    ("parse: an unknown type is accepted", "src/parse.cho", "    if !known {\n        return fail(st, pos, e_unknown_type());\n    }", "    if false {\n        return fail(st, pos, e_unknown_type());\n    }"),
    ("parse: a quoted type name is accepted", "src/parse.cho", "    if tkind(toks, pos) == lex.t_quoted() {\n        return fail(st, pos, e_unknown_type());\n    }", "    if false {\n        return fail(st, pos, e_unknown_type());\n    }"),
    ("parse: decimal is not numeric", "src/parse.cho", 'if word_is(sql, start, length, "numeric") || word_is(sql, start, length, "decimal") {', 'if word_is(sql, start, length, "numeric") {'),
    ("parse: a modifier on text is accepted", "src/parse.cho", "        } else {\n            return fail(st, p, e_unknown_construct());\n        }\n        if p + 1 >= end", "        } else {\n            mods = 1;\n        }\n        if p + 1 >= end"),
    ("parse: a numeric has one modifier", "src/parse.cho", "            mods = 2;\n        } else if code == 7 {", "            mods = 1;\n        } else if code == 7 {"),
    ("parse: CASE needs no ELSE flag", "src/parse.cho", "build(nodes, kids, vs, st, n_case(), 0, st[4] - base, operand, has_else)", "build(nodes, kids, vs, st, n_case(), 0, st[4] - base, operand, 0)"),
    ("parse: CASE forgets its operand", "src/parse.cho", "build(nodes, kids, vs, st, n_case(), 0, st[4] - base, operand, has_else)", "build(nodes, kids, vs, st, n_case(), 0, st[4] - base, 0, has_else)"),
    ("parse: CASE may END after WHEN", "src/parse.cho", "if state != 3 && state != 4 {", "if state != 3 && state != 4 && state != 2 {"),
    ("parse: CASE may have two ELSEs", "src/parse.cho", "        if state != 3 {\n            return fail(st, pos, e_syntax());\n        }\n        os[at + 3] = 4 + 8 * operand;", "        os[at + 3] = 4 + 8 * operand;"),
    ("parse: THEN may follow anything", "src/parse.cho", "        if state != 2 {\n            return fail(st, pos, e_syntax());\n        }\n        os[at + 3] = 3 + 8 * operand;", "        os[at + 3] = 3 + 8 * operand;"),
    ("parse: count(*) is any function", "src/parse.cho", '&& punct(sql, toks, pos + 3, end, \')\') && word_is(sql, a, l, "count") {', "&& punct(sql, toks, pos + 3, end, ')') {"),
    ("parse: a call renders without its name folded", "src/parse.cho", "p = put_text(out, p, sql, tstart(toks, data), tlen(toks, data), true);\n        p = put_byte(out, p, '(');", "p = put_text(out, p, sql, tstart(toks, data), tlen(toks, data), false);\n        p = put_byte(out, p, '(');"),
    ("parse: unary plus is accepted", "src/parse.cho", '} else if word_is(sql, a, l, "+") {\n                    return fail(st, pos, e_unknown_construct());', '} else if word_is(sql, a, l, "+") {\n                    pos = pos + 1;'),
    ("parse: a third name part is accepted", "src/parse.cho", "        if punct(sql, toks, next, end, '.') {\n            return fail(st, next, e_unknown_construct());\n        }", "        if false {\n            return fail(st, next, e_unknown_construct());\n        }"),
    ("parse: a leftover token is not an error at the top", "src/parse.cho", "if r >= 0 && (st[5] != 0 || st[4] != 1) {", "if r >= 0 && st[4] != 1 {"),
    ("parse: the operand stack has no limit", "src/parse.cho", "    if st[4] >= len(vs) {\n        return 0 - e_nested_too_deep();\n    }\n", "    if false {\n        return 0 - e_nested_too_deep();\n    }\n"),
    ("parse: the operator stack limit is off by one", "src/parse.cho", "if 4 * st[5] + 4 > len(os) {", "if 4 * st[5] + 4 > len(os) + 4 {"),
    ("parse: the node arena limit is off by one", "src/parse.cho", "if 6 * id + 6 > len(nodes) {", "if 6 * id + 6 > len(nodes) + 6 {"),
    ("parse: the kids limit is off by one", "src/parse.cho", "    if st[1] + count > len(kids) {\n        return 0 - e_too_big();\n    }\n    let first = st[1];\n    var i = 0;\n    while i < count {\n        kids[first + i] = vs[", "    if st[1] + count > len(kids) + 1 {\n        return 0 - e_too_big();\n    }\n    let first = st[1];\n    var i = 0;\n    while i < count {\n        kids[first + i] = vs["),
    ("parse: the traversal stack limit is off by one", "src/parse.cho", "if 2 * sp + 2 > len(rs) {", "if 2 * sp + 2 > len(rs) + 2 {"),
    ("parse: the output limit is off by one", "src/parse.cho", "if at < 0 || at >= len(out) {", "if at < 0 || at > len(out) {"),
    ("parse: an overrun of the output goes unnoticed", "src/parse.cho", "    if p < 0 {\n        return 0 - e_too_big();\n    }\n    return p;", "    return p;"),
]

# ---- the SELECT parser (src/stmt.cho, and the statement half of the renderer in src/parse.cho; tests/stmt_test.cho)
STMT = [
    ("stmt: AS OF takes any string", "src/stmt.cho", "        if !is_commit_id(sql, toks, pos + 3) {", "        if false {"),
    ("stmt: a commit id may be of another length", "src/stmt.cho", "    if parse.tlen(toks, i) != 64 {", "    if parse.tlen(toks, i) != 65 {"),
    ("stmt: a commit id may use any lower-case letter", "src/stmt.cho", "c >= 'a' && c <= 'f')", "c >= 'a' && c <= 'z')"),
    ("stmt: a commit id may be in capitals", "src/stmt.cho", "c >= 'a' && c <= 'f')", "c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')"),
    ("stmt: AS OF needs no word `of`", "src/stmt.cho", 'parse.kw(sql, toks, pos + 2, end, "of") && pos + 3 < end', "pos + 3 < end"),
    ("stmt: the table node forgets its commit", "src/stmt.cho", "parse.n_table(), pos, tmp, 0, st[9], asof);", "parse.n_table(), pos, tmp, 0, st[9], 0 - 1);"),
    ("stmt: a rendering drops the AS OF", "src/parse.cho", "        if nodes[6 * node + 5] >= 0 {\n            // `AS OF", "        if false {\n            // `AS OF"),
    ("stmt: DISTINCT is ignored", "src/stmt.cho", "        distinct = 1;\n", "        distinct = 0;\n"),
    ("stmt: a left join is an inner join", "src/stmt.cho", "                    kind = 1;\n                } else if", "                    kind = 0;\n                } else if"),
    ("stmt: a right join is accepted", "src/stmt.cho", '} else if parse.kw(sql, toks, pos, end, "right") ||', "} else if false ||"),
    ("stmt: USING is a syntax error", "src/stmt.cho", '                        if parse.kw(sql, toks, pos, end, "using") {', "        if false {"),
    ("stmt: a schema-qualified table is accepted", "src/stmt.cho", "if parse.punct(sql, toks, pos + 1, end, '.') || !allow_paren && parse.punct(sql, toks, pos + 1, end, '(') {", "if !allow_paren && parse.punct(sql, toks, pos + 1, end, '(') {"),
    ("stmt: a set operation is a syntax error", "src/stmt.cho", '        if parse.kw(sql, toks, pos, end, "union") ||', "        if false ||"),
    ("stmt: ASC is DESC", "src/stmt.cho", "                dir = 1;\n                q = q + 1;", "                dir = 2;\n                q = q + 1;"),
    ("stmt: NULLS FIRST is accepted", "src/stmt.cho", '            if parse.kw(sql, toks, q, end, "nulls") ||', "            if false ||"),
    ("stmt: a reserved word may follow AS", "src/stmt.cho", "if parse.tkind(toks, p) == lex.t_ident() && parse.is_reserved(sql, parse.tstart(toks, p), parse.tlen(toks, p)) {", "if false {"),
    ("stmt: any word is a bare label", "src/stmt.cho", "(mode != 1 || bare_label_ok(sql, toks, p))", "true"),
    ("stmt: filter is a bare label", "src/stmt.cho", 'parse.word_is(sql, a, n, "filter") || ', ""),
    ("stmt: year is a bare label", "src/stmt.cho", ' || parse.word_is(sql, a, n, "year")', ""),
    ("stmt: ROLLUP is a call", "src/stmt.cho", '            if (parse.kw(sql, toks, pos, end, "rollup") || parse.kw(sql, toks, pos, end, "cube")) &&', "            if false &&"),
    ("stmt: CUBE is a call", "src/stmt.cho", ' || parse.kw(sql, toks, pos, end, "cube")) &&', ") &&"),
    ("stmt: t.* loses its table", "src/stmt.cho", "parse.n_star(), pos, tmp, 0", "parse.n_star(), 0 - 1, tmp, 0"),
    ("stmt: the staging limit is off by one", "src/stmt.cho", "if st[10] >= len(tmp) {", "if st[10] > len(tmp) {"),
    ("stmt: HAVING is a WHERE", "src/stmt.cho", "parse.n_having(), 0, 0);", "parse.n_where(), 0, 0);"),
    ("stmt: LIMIT is an OFFSET", "src/stmt.cho", "parse.n_limit(), 0, 0);", "parse.n_offset(), 0, 0);"),
    ("stmt: a join's condition is not required", "src/stmt.cho", '                    if !parse.kw(sql, toks, pos, end, "on") {', '                    if false {'),
    ("stmt: a table alias is dropped", "src/stmt.cho", "parse.n_table(), pos, tmp, 0, st[9], asof);", "parse.n_table(), pos, tmp, 0, 0 - 1, asof);"),
    ("stmt: a select alias is dropped", "src/stmt.cho", "parse.n_item(), st[9], tmp[mark..mark + 1]", "parse.n_item(), 0 - 1, tmp[mark..mark + 1]"),
    ("stmt: FROM may be empty", "src/stmt.cho", '        pos = pos + 1;\n        more = true;\n        while more {\n            var q = table_ref(', '        pos = pos + 1;\n        more = false;\n        while more {\n            var q = table_ref('),
    ("stmt: a trailing token is ignored", "src/stmt.cho", "    if pos < end {\n        if parse.kw(sql, toks, pos, end, \"union\")", "    if false {\n        if parse.kw(sql, toks, pos, end, \"union\")"),
    ("stmt: a left join renders as inner", "src/parse.cho", 'return put_lit(out, p, " left join ");', 'return put_lit(out, p, " inner join ");'),
    ("stmt: DESC renders as ASC", "src/parse.cho", 'if data == 2 {\n            return put_lit(out, p, " desc");', 'if data == 2 {\n            return put_lit(out, p, " asc");'),
    ("stmt: DISTINCT is not rendered", "src/parse.cho", '        if data == 1 {\n            p = put_lit(out, p, "distinct ");', '        if false {\n            p = put_lit(out, p, "distinct ");'),
    ("stmt: WHERE renders as HAVING", "src/parse.cho", 'return put_lit(out, p, "where ");', 'return put_lit(out, p, "having ");'),
    ("stmt: ORDER BY renders as GROUP BY", "src/parse.cho", 'return put_lit(out, p, "order by ");', 'return put_lit(out, p, "group by ");'),
    ("stmt: OFFSET renders as LIMIT", "src/parse.cho", 'return put_lit(out, p, "offset ");', 'return put_lit(out, p, "limit ");'),
    ("stmt: a table alias is not rendered", "src/parse.cho", "        if nodes[6 * node + 4] >= 0 {\n            p = put_lit(out, p, \" as \");\n            p = put_name(out, p, sql, toks, nodes[6 * node + 4]);\n        }\n        return p;\n    }\n    if kind == n_from()", "        return p;\n    }\n    if kind == n_from()"),
    ("stmt: a select alias is not rendered", "src/parse.cho", "        if data >= 0 {\n            p = put_lit(out, p, \" as \");\n            return put_name(out, p, sql, toks, data);\n        }\n        return p;\n    }\n    if kind == n_order()", "        return p;\n    }\n    if kind == n_order()"),
    ("stmt: t.* renders without its table", "src/parse.cho", "        p = put_name(out, p, sql, toks, data);\n        return put_lit(out, p, \".*\");", "        return put_lit(out, p, \"*\");"),
    ("stmt: clauses are not separated", "src/parse.cho", "    if kind == n_select() || kind == n_insert() || kind == n_update() || kind == n_delete() {\n        return put_byte(out, p, ' ');\n    }", "    if kind == n_insert() || kind == n_update() || kind == n_delete() {\n        return put_byte(out, p, ' ');\n    }"),
    # ---- INSERT, UPDATE, DELETE
    ("dml: INSERT without INTO", "src/stmt.cho", '    if !parse.kw(sql, toks, pos, end, "into") {', "    if false {"),
    ("dml: an INSERT alias without AS", "src/stmt.cho", "    if allow_paren {\n        amode = 2;\n    }", "    if false {\n        amode = 2;\n    }"),
    ("dml: INSERT ... SELECT is a syntax error", "src/stmt.cho", '    if parse.kw(sql, toks, pos, end, "select") || parse.kw(sql, toks, pos, end, "with") {\n        return parse.fail(st, pos, parse.e_insert_select());', '    if false {\n        return parse.fail(st, pos, parse.e_insert_select());'),
    ("dml: INSERT without VALUES", "src/stmt.cho", '    if !parse.kw(sql, toks, pos, end, "values") {\n        return parse.fail(st, pos, parse.e_syntax());', '    if false {\n        return parse.fail(st, pos, parse.e_syntax());'),
    ("dml: an INSERT row without parentheses", "src/stmt.cho", "        if !parse.punct(sql, toks, pos, end, '(') {\n            return parse.fail(st, pos, parse.e_syntax());\n        }\n        if parse.kw(sql, toks, pos + 1, end, \"select\")", "        if false {\n            return parse.fail(st, pos, parse.e_syntax());\n        }\n        if parse.kw(sql, toks, pos + 1, end, \"select\")"),
    ("dml: only the first INSERT row", "src/stmt.cho", "        if parse.punct(sql, toks, pos, end, ',') {\n            pos = pos + 1;\n        } else {\n            rows = false;\n        }", "        rows = false;"),
    ("dml: RETURNING is a syntax error", "src/stmt.cho", '    if parse.kw(sql, toks, pos, end, "returning") {\n        return parse.fail(st, pos, parse.e_returning());', '    if false {\n        return parse.fail(st, pos, parse.e_returning());'),
    ("dml: ON CONFLICT is a syntax error", "src/stmt.cho", '    if parse.kw(sql, toks, pos, end, "on") {\n        return parse.fail(st, pos, parse.e_on_conflict());', '    if false {\n        return parse.fail(st, pos, parse.e_on_conflict());'),
    ("dml: UPDATE without SET", "src/stmt.cho", '    if !parse.kw(sql, toks, pos, end, "set") {\n        return parse.fail(st, pos, parse.e_syntax());', '    if false {\n        return parse.fail(st, pos, parse.e_syntax());'),
    ("dml: SET may be an alias", "src/stmt.cho", '    if mode != 1 && parse.kw(sql, toks, p, end, "set") {', "    if false {"),
    ("dml: an assignment needs no =", "src/stmt.cho", '        if !parse.opr(sql, toks, q, end, "=") {', "        if false {"),
    ("dml: an assignment loses its column", "src/stmt.cho", "parse.n_assign(), col_tok, tmp[mark..mark + 1]", "parse.n_assign(), 0 - 1, tmp[mark..mark + 1]"),
    ("dml: only the first assignment", "src/stmt.cho", "        pos = q;\n        if parse.punct(sql, toks, pos, end, ',') {\n            pos = pos + 1;\n        } else {\n            more = false;\n        }\n    }\n    let assigns", "        pos = q;\n        more = false;\n    }\n    let assigns"),
    ("dml: DELETE without FROM", "src/stmt.cho", '    if !parse.kw(sql, toks, pos, end, "from") {\n        return parse.fail(st, pos, parse.e_syntax());', '    if false {\n        return parse.fail(st, pos, parse.e_syntax());'),
    ("dml: DELETE ... USING is a syntax error", "src/stmt.cho", '        if parse.kw(sql, toks, pos, end, "using") {\n            return parse.fail(st, pos, parse.e_unknown_construct());', '        if false {\n            return parse.fail(st, pos, parse.e_unknown_construct());'),
    ("dml: UPDATE or DELETE without a trailing check", "src/stmt.cho", "    let n = st[11];\n    if pos < end {\n        return leftover(sql, toks, pos, end, st);\n    }\n    let root = parse.mk(nodes, kids, st, parse.n_update()", "    let n = st[11];\n    if false {\n        return leftover(sql, toks, pos, end, st);\n    }\n    let root = parse.mk(nodes, kids, st, parse.n_update()"),
    ("dml: a WHERE is dropped from UPDATE", "src/stmt.cho", "clauses[count] = id;\n    st[11] = count + 1;", "st[11] = count;"),
    ("dml: a statement that is not DML is accepted as SELECT", "src/stmt.cho", '    if parse.kw(sql, toks, from, end, "update") {', '    if parse.kw(sql, toks, from, end, "update") || parse.kw(sql, toks, from, end, "drop") {'),
    ("dml: INSERT renders as UPDATE", "src/parse.cho", 'return put_lit(out, p, "insert into ");', 'return put_lit(out, p, "update ");'),
    ("dml: VALUES is not rendered", "src/parse.cho", 'return put_lit(out, p, "values ");', "return p;"),
    ("dml: the column list is not closed", "src/parse.cho", "    if kind == n_cols() || kind == n_row() || kind == n_create_table() || kind == n_create_index() {\n        return put_byte(out, p, ')');\n    }", "    if kind == n_row() || kind == n_create_table() || kind == n_create_index() {\n        return put_byte(out, p, ')');\n    }"),
    ("dml: a row is not closed", "src/parse.cho", "    if kind == n_cols() || kind == n_row() || kind == n_create_table() || kind == n_create_index() {\n        return put_byte(out, p, ')');\n    }", "    if kind == n_cols() || kind == n_create_table() || kind == n_create_index() {\n        return put_byte(out, p, ')');\n    }"),
    ("dml: SET is not rendered", "src/parse.cho", 'return put_lit(out, p, "set ");', "return p;"),
    ("dml: an assignment renders without its column", "src/parse.cho", "    if kind == n_assign() {\n        p = put_name(out, p, sql, toks, data);\n        return put_lit(out, p, \" = \");\n    }", "    if kind == n_assign() {\n        return put_lit(out, p, \" = \");\n    }"),
    ("dml: DELETE renders as SELECT FROM", "src/parse.cho", 'return put_lit(out, p, "delete from ");', 'return put_lit(out, p, "select from ");'),
    ("dml: statement parts are not separated", "src/parse.cho", "    if kind == n_select() || kind == n_insert() || kind == n_update() || kind == n_delete() {", "    if kind == n_select() {"),

    # ---- the closed DDL
    ("ddl: NOT NULL sets the wrong bit", "src/stmt.cho", "            bit = 1;\n            p = p + 2;", "            bit = 4;\n            p = p + 2;"),
    ("ddl: PRIMARY KEY is UNIQUE", "src/stmt.cho", "            bit = 2;\n            p = p + 2;", "            bit = 4;\n            p = p + 2;"),
    ("ddl: UNIQUE is NOT NULL", "src/stmt.cho", "            bit = 4;\n            p = p + 1;", "            bit = 1;\n            p = p + 1;"),
    ("ddl: a constraint may repeat", "src/stmt.cho", "        } else if flags / bit % 2 == 1 {\n            return parse.fail(st, p, parse.e_syntax());", "        } else if false {\n            return parse.fail(st, p, parse.e_syntax());"),
    ("ddl: any expression is a default", "src/stmt.cho", "            } else if kind != parse.n_num() && kind != parse.n_str() && kind != parse.n_null() && kind != parse.n_true() && kind != parse.n_false() {", "            } else if false {"),
    ("ddl: a negated string is a default", "src/stmt.cho", "                if kind != parse.n_num() {\n                    return parse.fail(st, p + 1, parse.e_unknown_construct());", "                if false {\n                    return parse.fail(st, p + 1, parse.e_unknown_construct());"),
    ("ddl: a default is lost", "src/stmt.cho", "            flags = flags + 8;\n            p = q;", "            flags = flags + 8;\n            st[10] = st[10] - 1;\n            p = q;"),
    ("ddl: the default sets no flag", "src/stmt.cho", "parse.n_coldef(), col, tmp[mark..st[10]], st[10] - mark, flags % 8,", "parse.n_coldef(), col, tmp[mark..st[10]], st[10] - mark, 0,"),
    ("ddl: a column loses its name", "src/stmt.cho", "parse.n_coldef(), col,", "parse.n_coldef(), 0 - 1,"),
    ("ddl: a table name may have a schema", "src/stmt.cho", "    if parse.punct(sql, toks, pos + 1, end, '.') {\n        return parse.fail(st, pos + 1, parse.e_unknown_construct());\n    }\n    st[9] = pos;", "    st[9] = pos;"),
    ("ddl: CREATE TABLE may end early", "src/stmt.cho", "    pos = pos + 1;\n    if pos < end {\n        return parse.fail(st, pos, parse.e_syntax());\n    }\n    let root = close_list(nodes, kids, tmp, st, parse.n_create_table(), 0, table);", "    pos = pos + 1;\n    let root = close_list(nodes, kids, tmp, st, parse.n_create_table(), 0, table);"),
    ("ddl: ALTER TABLE does more than ADD", "src/stmt.cho", '    if !parse.kw(sql, toks, pos, end, "add") {\n        return parse.fail(st, pos, parse.e_unsupported_statement());\n    }', '    if false {\n        return parse.fail(st, pos, parse.e_unsupported_statement());\n    }'),
    ("ddl: ADD COLUMN requires COLUMN", "src/stmt.cho", '    if parse.kw(sql, toks, pos, end, "column") {\n        pos = pos + 1;\n    }', '    if false {\n        pos = pos + 1;\n    }'),
    ("ddl: UNIQUE INDEX is a plain index", "src/stmt.cho", "        unique = 1;\n        pos = pos + 1;", "        unique = 0;\n        pos = pos + 1;"),
    ("ddl: an index may have no ON", "src/stmt.cho", '    if !parse.kw(sql, toks, pos, end, "on") {\n        return parse.fail(st, pos, parse.e_syntax());\n    }', '    if false {\n        return parse.fail(st, pos, parse.e_syntax());\n    }'),
    ("ddl: an index loses its table", "src/stmt.cho", "parse.n_create_index(), name, tmp[0..st[10]], st[10], unique, table);", "parse.n_create_index(), name, tmp[0..st[10]], st[10], unique, name);"),
    ("ddl: DROP INDEX drops a table", "src/stmt.cho", '    if parse.kw(sql, toks, from + 1, end, "index") {\n        kind = parse.n_drop_index();', '    if false {\n        kind = parse.n_drop_index();'),
    ("ddl: DROP TABLE takes a list", "src/stmt.cho", "    if pos < end {\n        return parse.fail(st, pos, parse.e_syntax());\n    }\n    let root = parse.mk(nodes, kids, st, kind,", "    let root = parse.mk(nodes, kids, st, kind,"),
    ("ddl: a type's modifiers are not rendered", "src/parse.cho", "    var p = put_lit(out, at, type_name(code));\n    if m1 >= 0 {", "    var p = put_lit(out, at, type_name(code));\n    if false {"),
    ("ddl: NOT NULL is not rendered", "src/parse.cho", '        p = put_lit(out, p, " not null");', "        p = put_lit(out, p, \"\");"),
    ("ddl: UNIQUE is not rendered", "src/parse.cho", '        p = put_lit(out, p, " unique");', "        p = put_lit(out, p, \"\");"),
    ("ddl: a unique index renders plain", "src/parse.cho", '        if nodes[6 * node + 4] == 1 {\n            p = put_lit(out, p, "unique ");', '        if false {\n            p = put_lit(out, p, "unique ");'),
    ("ddl: ALTER renders without COLUMN", "src/parse.cho", 'return put_lit(out, p, " add column ");', 'return put_lit(out, p, " add ");'),
    ("ddl: a default renders without its flags", "src/parse.cho", "        p = put_flags(out, p, nodes[6 * node + 4]);\n        return put_lit(out, p, \" default \");", "        return put_lit(out, p, \" default \");"),
    ("ddl: a column without a default renders without its flags", "src/parse.cho", "        if nodes[6 * node + 3] == 1 {\n            return put_flags(out, p, nodes[6 * node + 4]);\n        }\n        return p;", "        return p;"),]

# ---- the lowering (src/lower.cho, tests/lower_check.py: IR bytes, effects through the verifier, refusals)
LOWER = [
    ("lower: a table read as of a commit is named without it", "src/lower.cho", "    let tok = sc[120 + e];\n    if tok < 0 {", "    let tok = sc[120 + e];\n    if true {"),
    ("lower: the scope forgets the commit", "src/lower.cho", "    sc[120 + sc[2]] = nodes[6 * node + 5];", "    sc[120 + sc[2]] = 0 - 1;"),
    ("lower: the commit's digits are one short", "src/lower.cho", "    while i < 64 && r >= 0 {\n        r = w8(out, sc, int_of(sql[parse.tstart(toks, tok) + i]));", "    while i < 63 && r >= 0 {\n        r = w8(out, sc, int_of(sql[parse.tstart(toks, tok) + i]));"),
    ("lower: an UPDATE of a table as of a commit is let through", "src/lower.cho", "    let update = nodes[6 * root] == parse.n_update();\n    if nodes[6 * target + 5] >= 0 {", "    let update = nodes[6 * root] == parse.n_update();\n    if false {"),
    ("lower: an INSERT into a table as of a commit is let through", "src/lower.cho", "    let table = nodes[6 * target + 1];\n    if nodes[6 * target + 5] >= 0 {", "    let table = nodes[6 * target + 1];\n    if false {"),
    ("lower: a parameter's index is zero-based", "src/lower.cho", "r = wn(out, sc, idx, 4);", "r = wn(out, sc, idx - 1, 4);"),
    ("lower: a parameter is written as a constant", "src/lower.cho", "        r = w8(out, sc, 2);\n        if r >= 0 {\n            r = wn(out, sc, idx, 4);", "        r = w8(out, sc, 1);\n        if r >= 0 {\n            r = wn(out, sc, idx, 4);"),
    ("lower: only the last digit of a parameter counts", "src/lower.cho", "idx = idx * 10 + int_of(sql[q]) - '0';", "idx = int_of(sql[q]) - '0';"),
    ("lower: = maps to <>", "src/lower.cho", "    if code == 3 {\n        return 0;", "    if code == 3 {\n        return 1;"),
    ("lower: or maps to and", "src/lower.cho", "    if code == 1 {\n        return 7;", "    if code == 1 {\n        return 6;"),
    ("lower: NOT IN is IN", "src/lower.cho", "                    if data == 20 {\n                        neg = 1;", "                    if false {\n                        neg = 1;"),
    ("lower: NOT BETWEEN is BETWEEN", "src/lower.cho", "            sc[4] = 0;\n            if data == 1 {\n                r = w8(out, sc, 7);", "            sc[4] = 0;\n            if false {\n                r = w8(out, sc, 7);"),
    ("lower: BETWEEN's low bound is > not >=", "src/lower.cho", "            if r >= 0 {\n                r = w8(out, sc, 5);\n            }\n            if r >= 0 {\n                r = w8(out, sc, 5);\n            }\n            if r < 0 {\n                return r;\n            }\n            return kids[first];", "            if r >= 0 {\n                r = w8(out, sc, 5);\n            }\n            if r >= 0 {\n                r = w8(out, sc, 4);\n            }\n            if r < 0 {\n                return r;\n            }\n            return kids[first];"),
    ("lower: count(*) loses its star", "src/lower.cho", "            if r >= 0 && nodes[6 * node + 4] == 1 {\n                r = w8(out, sc, 6);\n            }", "            if false {\n                r = w8(out, sc, 6);\n            }"),
    ("lower: now() is a call", "src/lower.cho", '            if parse.word_is(sql, a, l, "now") && count == 0 {', "            if false {"),
    ("lower: random() is allowed", "src/lower.cho", 'parse.word_is(sql, a, n, "random") || ', ""),
    ("lower: nextval() is allowed", "src/lower.cho", ' || parse.word_is(sql, a, n, "nextval")', ""),
    ("lower: an unknown qualified column is accepted", "src/lower.cho", "        if !has_column(sql, toks, col, schema, sc[16 + 3 * entry + 2], sc) {", "        if false {"),
    ("lower: an ambiguous column is accepted", "src/lower.cho", "        if found > 1 {", "        if false {"),
    ("lower: an alias does not hide the table", "src/lower.cho", "        if sc[at] >= 0 {\n            by = sc[at];\n        }", "        if false {\n            by = sc[at];\n        }"),
    ("lower: a left join is inner", "src/lower.cho", "            if nodes[6 * j + 1] == 1 {\n                kind = 2;", "            if nodes[6 * j + 1] == 1 {\n                kind = 1;"),
    ("lower: a join's condition is the wrong child", "src/lower.cho", "            sc[48 + 3 * sc[3] + 2] = kids[nodes[6 * j + 2] + 2];", "            sc[48 + 3 * sc[3] + 2] = kids[nodes[6 * j + 2] + 1];"),
    ("lower: DESC is ASC", "src/lower.cho", "            if nodes[6 * ord + 1] == 2 {\n                dir = 1;", "            if nodes[6 * ord + 1] == 2 {\n                dir = 0;"),
    ("lower: ORDER BY ignores an alias", "src/lower.cho", "                if nodes[6 * it] == parse.n_item() && nodes[6 * it + 1] >= 0 && same_name(", "                if false && nodes[6 * it] == parse.n_item() && nodes[6 * it + 1] >= 0 && same_name("),
    ("lower: an ambiguous ORDER BY name is accepted", "src/lower.cho", "nodes[6 * expr + 1], schema, sc) > 1 {", "nodes[6 * expr + 1], schema, sc) > 5 {"),
    ("lower: an INSERT row of the wrong width is accepted", "src/lower.cho", "        if nodes[6 * rn + 3] != width {", "        if false {"),
    ("lower: an UPDATE of an unknown column is accepted", "src/lower.cho", "            if !has_column(sql, toks, col, schema, line, sc) {\n                return fail(sc, col, e_unknown_column());\n            }\n            r0 = wname_tok(sql, toks, col, out, sc);", "            if false {\n                return fail(sc, col, e_unknown_column());\n            }\n            r0 = wname_tok(sql, toks, col, out, sc);"),
    ("lower: an ALTER is a CREATE", "src/lower.cho", "        code = 1;\n        must_exist = true;", "        code = 0;\n        must_exist = true;"),
    ("lower: a DROP TABLE is an ALTER", "src/lower.cho", "        code = 2;\n        must_exist = true;", "        code = 1;\n        must_exist = true;"),
    ("lower: a DROP INDEX is a DROP TABLE", "src/lower.cho", "        code = 4;\n    }", "        code = 2;\n    }"),
    ("lower: an index's DDL names the index", "src/lower.cho", "        table = nodes[6 * root + 5];", "        table = data;"),
    ("lower: a name is not folded", "src/lower.cho", "        if !quoted {\n            ch = low(ch);\n        }\n        r = w8(out, sc, ch);\n        if r < 0 {\n            return r;\n        }\n        written = written + 1;", "        r = w8(out, sc, ch);\n        if r < 0 {\n            return r;\n        }\n        written = written + 1;"),
    ("lower: every number is bytes", "src/lower.cho", "        if v >= 0 {\n            r = w8(out, sc, 1);", "        if false {\n            r = w8(out, sc, 1);"),
    ("lower: a doubled quote stays doubled", "src/lower.cho", "        if string && ch == '\\'' && i + 1 < n {", "        if false {"),
    ("lower: CASE x WHEN compares with <>", "src/lower.cho", "            if at == 0 {\n                r = w8(out, sc, 5);\n                if r >= 0 {\n                    r = w8(out, sc, 0);", "            if at == 0 {\n                r = w8(out, sc, 5);\n                if r >= 0 {\n                    r = w8(out, sc, 1);"),
]

# ---- the query guard (src/guard.cho, tests/guard_check.py)
GUARD = [
    ("guard: AS OF is not rewritten", "src/guard.cho", "        sent = asof.rewrite(heap, out, written);", "        sent = written;"),
    ("guard: a string constant is scanned for the clause", "src/asof.cho", "            } else if c == '\\'' {\n                mode = 1;", "            } else if false {\n                mode = 1;"),
    ("guard: the table's name is not the alias when none is given", "src/asof.cho", "                    if !is_at(out[0..n], i, \" as \\\"\") {", "                    if false {"),
    ("guard: a given alias is followed by another", "src/asof.cho", "                    if !is_at(out[0..n], i, \" as \\\"\") {", "                    if true {"),
    ("guard: the commit id is cut short", "src/asof.cho", "out[i + 8..i + 8 + 64]);", "out[i + 8..i + 8 + 63]);"),
    ("guard: a statement's id is not recorded", "src/guard.cho", "ir.id(contents(iw)[0..w], ids[32 * nst..32 * nst + 32]);", "nst = nst + 0;"),
    ("guard: a statement's IR is not recorded", "src/guard.cho", "irat = build.store_record(irs, irat, contents(iw)[0..w]);", "irat = irat + 0;"),
    ("guard: a statement's effects are not recorded", "src/guard.cho", "effat = emit_effects(sr, effs, effat);", "effat = effat + 0;"),
    ("guard: a message of too many statements is cut", "src/guard.cho", "} else if 32 * (nst + 1) > len(ids) {", "} else if false {"),
    ("guard: an effect's target is dropped", "src/guard.cho", "w = build.put_bytes(effs, w, key[1..len(key)]);", "w = build.put_bytes(effs, w, key[1..1]);"),
    ("guard: denied effects are not checked", "src/guard.cho", "                                                                        if dk >= 0 {", "                                                                        if false {"),
    ("guard: only the first effect is checked", "src/guard.cho", "    while e < map.entries(set) {\n        if map.is_live(set, e) {", "    while e < 1 {\n        if map.is_live(set, e) {"),
    ("guard: a denied effect is allowed to pass", "src/guard.cho", "                denied = token.effect_denied(tk, enc, 0, 1);", "                denied = false;"),
    ("guard: the effect's length is off", "src/guard.cho", "                enc[2] = byte_of((len(key) - 1) % 256);", "                enc[2] = byte_of((len(key) - 2) % 256);"),
    ("guard: statements are not separated", "src/guard.cho", "                                                                if i > 0 {", "                                                                if i > 1 {"),
    ("guard: the effects are inferred as v1", "src/guard.cho", "ir.infer(heap, set, contents(iw)[0..w], 2, vd[14..16])", "ir.infer(heap, set, contents(iw)[0..w], 1, vd[14..16])"),
    ("guard: a lexer refusal is a parser refusal", "src/guard.cho", "mark(vd, 1, 0 - n, 0 - 1, 0);", "mark(vd, 2, 0 - n, 0 - 1, 0);"),
    ("guard: the refused statement is not counted", "src/guard.cho", "mark(vd, 2, 0 - pq, contents(sw)[3], i);", "mark(vd, 2, 0 - pq, contents(sw)[3], 0);"),
    ("guard: a denied effect is 0A000", "src/guard.cho", "    if vd[0] == 3 {\n        return \"42501\";", "    if vd[0] == 3 {\n        return \"0A000\";"),
    ("guard: an unknown column is 0A000", "src/guard.cho", "        if c == 21 {\n            return \"42703\";", "        if c == 21 {\n            return \"0A000\";"),
    ("guard: an unknown table is 42703", "src/guard.cho", "        if c == 20 {\n            return \"42P01\";", "        if c == 20 {\n            return \"42703\";"),
    ("guard: a lowering refusal is lost", "src/guard.cho", "                                                                if w < 0 {\n                                                                    mark(vd, 2, 0 - w, contents(scw)[1], i);", "                                                                if false {\n                                                                    mark(vd, 2, 0 - w, contents(scw)[1], i);"),
    ("guard: the rendering is not appended", "src/guard.cho", "                                                                        written = written + rl;", "                                                                        written = written + 0;"),
]


# Mutants that cannot be killed because they change nothing observable, with the reason. Empty: every mutant above
# changes behaviour, and the ones that looked equivalent (the count guard against the bytes left) are not listed
# because they are not mutants here: removing the guard leaves every field read bounds-checked, so the verdict is the
# same and only the allocation is not bounded (spec §1), which a verdict cannot show.
EQUIVALENT = []


def run_login(cancho):
    survivors = []
    for label, rel, old, new in LOGIN:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            shutil.copytree(ROOT / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            files = [str(work / "tests/login_test.cho"), str(work / "tests/login_cases.cho")] + sorted(
                str(p) for p in (work / "src").glob("*.cho") if p.name in ("commit.cho", "token.cho", "login.cho"))
            r = subprocess.run([cancho, "test"] + files + ["--std"], capture_output=True, text=True)
            if r.returncode == 0:
                print("SURVIVED %-46s every login test passes" % label)
                survivors.append(label)
            elif "error" in (r.stdout + r.stderr).lower() and "running" not in r.stdout:
                print("BROKEN %-48s does not build: %s" % (label, (r.stdout + r.stderr).strip()[:160]))
                survivors.append(label)
            else:
                failed = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("test ") and "FAILED" in l]
                print("killed   %-46s by %s" % (label, ", ".join(failed) or "a trap"))
    print("%d mutants, %d not killed" % (len(LOGIN), len(survivors)))
    return 1 if survivors else 0


def run_lower(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in LOWER if not only or only in m[0]]
    survivors = []
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            exe = work / "lowercheck"
            srcs = [str(work / "src" / n) for n in ("lex.cho", "parse.cho", "stmt.cho", "lower.cho")]
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/lowercheck.cho")] + srcs + ["-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            r = subprocess.run([sys.executable, str(ROOT / "tests/lower_check.py"), str(exe), str(ROOT / "build/verify")],
                               capture_output=True, text=True)
            if r.returncode == 0:
                print("SURVIVED %-46s every lowering case passes" % label)
                survivors.append(label)
            else:
                first = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d case(s), e.g. %s" % (label, len(first), first[0][5:60] if first else "a crash"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


def run_guard(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in GUARD if not only or only in m[0]]
    survivors = []
    names = ("commit.cho", "token.cho", "lex.cho", "parse.cho", "stmt.cho", "lower.cho", "ir.cho", "guard.cho", "build.cho", "asof.cho")
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            exe = work / "guardcheck"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/guardcheck.cho")] + [str(work / "src" / n) for n in names] + ["-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            r = subprocess.run([sys.executable, str(ROOT / "tests/guard_check.py"), str(exe)], capture_output=True, text=True)
            if r.returncode == 0:
                print("SURVIVED %-46s every guard case passes" % label)
                survivors.append(label)
            else:
                first = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d case(s), e.g. %s" % (label, len(first), first[0][5:60] if first else "a crash"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


def run_build(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in BUILD if not only or only in m[0]]
    survivors = []
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            exe = work / "buildcheck"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/buildcheck.cho"), str(work / "src/build.cho"), str(work / "src/commit.cho"), "-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            r = subprocess.run([sys.executable, str(ROOT / "tests/build_check.py"), str(exe)], capture_output=True, text=True, timeout=600)
            if r.returncode == 0:
                print("SURVIVED %-46s every build check passes" % label)
                survivors.append(label)
            else:
                first = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d check(s), e.g. %s" % (label, len(first), first[0][5:60] if first else "a crash"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


STATE = [
    # ---- src/state.cho (docs/spec/state.md), judged by tests/state_check.py
    ("state: a leaf has another domain prefix", "src/state.cho", '"cancho-db/fact/v1"', '"cancho-db/fact/v2"'),
    ("state: a node has another domain prefix", "src/state.cho", '"cancho-db/node/v1"', '"cancho-db/node/v2"'),
    ("state: an unpaired last hash is dropped", "src/state.cho", "if m % 2 == 1 {", "if m % 2 == 2 {"),
    ("state: a node pairs a hash with itself", "src/state.cho", "both[32 + j] = lv[64 * k + 32 + j];", "both[32 + j] = lv[64 * k + j];"),
    ("state: changes counts one fact too many", "src/state.cho", "build.put_be(cnt, 0, n, 4);", "build.put_be(cnt, 0, n + 1, 4);"),
    ("state: the parent count is not in state", "src/state.cho", "build.put_bytes(head, build.put_be(head, 0, np, 1), parents);", "build.put_bytes(head, build.put_be(head, 0, 0, 1), parents);"),
    ("state: a zero image is accepted", "src/state.cho", "if len(old) == 32 && is_zero(old) || len(new) == 32 && is_zero(new) {", "if false {"),
    ("state: kind 3 is accepted", "src/state.cho", "if kind < 0 || kind > 2 {", "if kind < 0 || kind > 3 {"),
    ("state: a table of 256 bytes is accepted", "src/state.cho", "len(table) > 255", "len(table) > 256"),
    ("state: a delete has a new image", "src/state.cho", "    if kind == 2 {\n        want_new = 0;", "    if kind == 1 {\n        want_new = 0;"),
    ("state: the table sorts after the key", "src/state.cho", "    if c != 0 {\n        return c < 0;", "    if c != 0 {\n        return c > 0;"),
    ("state: a repeated key is in order", "src/state.cho", "return cmp(p1, p2) < 0;", "return cmp(p1, p2) <= 0;"),
    ("state: a prefix sorts after its extension", "src/state.cho", "    return len(x) - len(y);", "    return len(y) - len(x);"),
    ("state: the kind is not in the encoding", "src/state.cho", "n = build.put_be(out, n, kind, 1);", "n = build.put_be(out, n, 0, 1);"),
    # ---- tools/state.py
    ("state.py: the empty root is not zero", "tools/state.py", "root = level[0] if level else ZERO", "root = level[0] if level else sha(b'')"),
    ("state.py: an unpaired hash is dropped", "tools/state.py", "        if len(level) % 2:\n            nxt.append(level[-1])", "        if False:\n            nxt.append(level[-1])"),
    ("state.py: a repeated key is in order", "tools/state.py", "not (last < (table, pk))", "not (last <= (table, pk))"),
    ("state.py: a short image is accepted", "tools/state.py", "len(old) != 32) or (new is not None and len(new) != 32)", "len(old) > 32) or (new is not None and len(new) > 32)"),
    ("state.py: state leaves out the parent count", "tools/state.py", "bytes([len(parent_states)]), *parent_states", "b'', *parent_states"),
    ("state.py: parents' states are reversed", "tools/state.py", "bytes([len(parent_states)]), *parent_states", "bytes([len(parent_states)]), *reversed(parent_states)"),
]


def run_state(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in STATE if not only or only in m[0]]
    survivors = []
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for d in ("src", "tools", "proxy"):
                shutil.copytree(ROOT / d, work / d, ignore=shutil.ignore_patterns("__pycache__"))
            (work / "tests").mkdir()
            shutil.copy(ROOT / "tests/state_check.py", work / "tests/state_check.py")
            shutil.copy(ROOT / "tests/state_cases.txt", work / "tests/state_cases.txt")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            exe = work / "statecheck"
            b = subprocess.run([cancho, "build", "--std", str(work / "proxy/statecheck.cho"), str(work / "src/state.cho"), str(work / "src/build.cho"), str(work / "src/commit.cho"), "-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            r = subprocess.run([sys.executable, str(work / "tests/state_check.py"), str(exe)], capture_output=True, text=True, timeout=600)
            if r.returncode == 0:
                print("SURVIVED %-46s every state check passes" % label)
                survivors.append(label)
            else:
                first = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d check(s), e.g. %s" % (label, len(first), first[0][5:70] if first else "a crash"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


def run_store(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in STORE if not only or only in m[0]]
    survivors = []
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            exe = work / "storecheck"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/storecheck.cho")] + [str(work / "src" / n) for n in ("store.cho", "build.cho", "commit.cho", "l1.cho", "ir.cho")] + ["-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode == 0 and label.startswith("erase-store:"):
                exe = work / "erasecheck"
                b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/erasecheck.cho")] + [str(work / "src" / n) for n in ("store.cho", "build.cho", "commit.cho", "l1.cho", "ir.cho")] + ["-o", str(exe)],
                                   capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            try:
                judge = "erase_store_check.py" if label.startswith("erase-store:") else "store_check.py"
                r = subprocess.run([sys.executable, str(ROOT / "tests" / judge), str(exe)], capture_output=True, text=True, timeout=300)
                rc, out = r.returncode, r.stdout
            except subprocess.TimeoutExpired:
                rc, out = 1, "FAIL timed out"
            if rc == 0:
                print("SURVIVED %-46s every store check passes" % label)
                survivors.append(label)
            else:
                first = [l for l in out.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d check(s), e.g. %s" % (label, len(first), first[0][5:60] if first else "a crash"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


# ---- sql/capture.sql, judged by tests/capture_check.py (the capture, the event trigger and cdb.fork)
SQL = [
    ("sql: the delta rows do not say their schema", "sql/capture.sql", "sc text := TG_TABLE_SCHEMA;", "sc text := 'public';"),
    ("sql: a table made in a branch schema is not tracked", "sql/capture.sql", "ns not like 'cdb\\_b\\_%')", "ns not like 'zzz')"),
    ("sql: track_all skips the branches", "sql/capture.sql", "where (s.nspname = 'public' or s.nspname like 'cdb\\_b\\_%') and c.relkind = 'r' loop", "where s.nspname = 'public' and c.relkind = 'r' loop"),
    ("sql: untrackable skips the branches", "sql/capture.sql", "     where (n.nspname = 'public' or n.nspname like 'cdb\\_b\\_%') and c.relkind in ('r', 'p')\n       and (c.relkind", "     where n.nspname = 'public' and c.relkind in ('r', 'p')\n       and (c.relkind"),
    ("sql fork: the copy is tracked while it is filled (it records facts)", "sql/capture.sql", "        continue when current_setting('cdb.forking', true) = 'on';", "        continue when false;"),
    ("sql fork: the copy is not tracked afterwards", "sql/capture.sql", "        perform cdb.track(r.t);\n    end loop;\n    perform set_config('cdb.forking', 'off', true);", "        null;\n    end loop;\n    perform set_config('cdb.forking', 'off', true);"),
    ("sql fork: the foreign keys are not copied", "sql/capture.sql", "        execute stmt;", "        null;"),
    ("sql fork: an identity counter skips a number", "sql/capture.sql", "0) + 1, false)', pg_get_serial_sequence", "0) + 1, true)', pg_get_serial_sequence"),
    ("sql fork: a generated column is inserted", "sql/capture.sql", "where a.attrelid = format('%I.%I', src, r.relname)::regclass and a.attnum > 0 and not a.attisdropped and a.attgenerated = '';", "where a.attrelid = format('%I.%I', src, r.relname)::regclass and a.attnum > 0 and not a.attisdropped;"),
    ("sql fork: the rows are not copied", "sql/capture.sql", "select %s from %I.%I', dst, r.relname, cols, cols, src, r.relname);", "select %s from %I.%I where false', dst, r.relname, cols, cols, src, r.relname);"),
    ("sql asof: the later deltas do not exclude the current rows", "sql/capture.sql", "where d.sch = %2$L and d.tbl = %3$L and (d.ord > %4$s or d.ord is null and d.xid = txid_current()) and d.pk", "where d.sch = %2$L and d.tbl = %3$L and (d.ord > %4$s + 1000000000 or d.ord is null and d.xid = txid_current()) and d.pk"),
    ("sql asof: the latest later delta is used, not the earliest", "sql/capture.sql", "order by d.pk, coalesce(d.ord, 9223372036854775807), d.seq) e", "order by d.pk, coalesce(d.ord, 9223372036854775807) desc, d.seq desc) e"),
    ("sql asof: a later insert has an old image", "sql/capture.sql", "         where e.old_row is not null", "         where true"),
    ("sql asof: the writes of the transaction asking are in the past", "sql/capture.sql", "(d.ord > %4$s or d.ord is null and d.xid = txid_current()) order by d.pk", "d.ord > %4$s order by d.pk"),
    ("sql ord: a commit of any branch is found", "sql/capture.sql", "where m.commit_id = decode(h, 'hex') and m.sch = sc;", "where m.commit_id = decode(h, 'hex');"),
    ("sql ord: history before ord is let through", "sql/capture.sql", "    if exists (select 1 from cdb.delta d where d.sch = sc and d.commit_id is not null and d.ord is null) then", "    if false and exists (select 1 from cdb.delta d where d.sch = sc and d.commit_id is not null and d.ord is null) then"),
    ("sql ord: an unknown commit is not refused", "sql/capture.sql", "    if o is null then\n        raise exception 'as-of-unknown-commit", "    if false then\n        raise exception 'as-of-unknown-commit"),
    ('sql merge: a conflict is not counted', "sql/capture.sql", '(select count(*) from m where tj is distinct from bj and sj is distinct from bj and tj is distinct from sj),', '(select count(*) from m where tj is distinct from bj and sj is distinct from bj and tj is distinct from sj and false),'),
    ('sql merge: two equal changes are a conflict', "sql/capture.sql", '(select count(*) from m where tj is distinct from bj and sj is distinct from bj and tj is distinct from sj),', '(select count(*) from m where tj is distinct from bj and sj is distinct from bj),'),
    ("sql merge: the source's inserts are not applied", "sql/capture.sql", "(select coalesce(jsonb_agg(sj), '[]') from m where tj is not distinct from bj and sj is distinct from bj and sj is not null and tj is null)", "(select '[]'::jsonb)"),
    ("sql merge: the source's updates are not applied", "sql/capture.sql", "(select coalesce(jsonb_agg(sj), '[]') from m where tj is not distinct from bj and sj is distinct from bj and sj is not null and tj is not null),", "(select '[]'::jsonb),"),
    ("sql merge: the source's deletes are not applied", "sql/capture.sql", "(select coalesce(jsonb_agg(k), '[]') from m where tj is not distinct from bj and sj is distinct from bj and sj is null),", "(select '[]'::jsonb),"),
    ('sql merge: deletes are applied parents first', "sql/capture.sql", '        for i in reverse n .. 1 loop', '        for i in 1 .. n loop'),
    ('sql merge: updates and inserts are applied children first', "sql/capture.sql", '        -- updates and inserts, parents first\n        for i in 1 .. n loop', '        -- updates and inserts, parents first\n        for i in reverse n .. 1 loop'),
    ('sql merge: a constraint violation is not reported as one', "sql/capture.sql", '    exception when integrity_constraint_violation then', '    exception when no_data_found then'),
    ('sql merge: tables with other columns are merged', "sql/capture.sql", '    foreach t in array tabs loop\n        if (select array_agg(a.attname', '    foreach t in array tabs loop\n        if false and (select array_agg(a.attname'),
    ('sql merge: a table only one side has is merged', "sql/capture.sql", '    if tabs is distinct from (select', '    if false and tabs is distinct from (select'),
    ("sql merge: the base is the target's state", "sql/capture.sql", 'from (select jsonb_build_array(%1$s) as k, to_jsonb(%7$I) as j from cdb.asof(null::%2$I.%3$I, %4$s) %7$I) b', 'from (select jsonb_build_array(%1$s) as k, to_jsonb(%7$I) as j from %5$I.%3$I %7$I) b'),
    ("sql alias: a row alias may be a column's name", "sql/capture.sql", '    while exists (select 1 from pg_attribute where attrelid = rel and attname = a', '    while false and exists (select 1 from pg_attribute where attrelid = rel and attname = a'),
    ("sql alias: the capture's aliases are fixed", "sql/capture.sql", "    ao := cdb.free_alias(tbl, 'cdb_o');", "    ao := 'cdb_o';"),
    ("sql fork: the source's own schema is copied from, whatever was asked", "sql/capture.sql", "where s.nspname = src and c.relkind = 'r' order by c.relname loop", "where s.nspname = 'public' and c.relkind = 'r' order by c.relname loop"),
]


def run_sql(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in SQL if not only or only in m[0]]
    survivors = []
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for d in ("sql", "tools"):
                shutil.copytree(ROOT / d, work / d, ignore=shutil.ignore_patterns("__pycache__"))
            (work / "tests").mkdir()
            shutil.copy(ROOT / "tests" / "capture_check.py", work / "tests" / "capture_check.py")
            shutil.copy(ROOT / "tests" / "merge_check.py", work / "tests" / "merge_check.py")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            try:
                judge = "merge_check.py" if label.startswith("sql merge:") else "capture_check.py"
                r = subprocess.run([sys.executable, str(work / "tests" / judge)], capture_output=True, text=True, timeout=900, env=dict(os.environ, MERGE_TRIALS="40"))
                rc, out = r.returncode, r.stdout + r.stderr
            except subprocess.TimeoutExpired:
                rc, out = 1, "FAIL timed out"
            if rc == 0:
                print("SURVIVED %-46s every capture check passes" % label)
                survivors.append(label)
            else:
                first = [l for l in out.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d check(s), e.g. %s" % (label, len(first), first[0][5:70] if first else "a crash: " + out.strip().splitlines()[-1][:60]))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


# ---- the L3a verifier (tools/l3a.py), judged by the golden cases of tests/l3a and, for the live comparison, tests/l3a_e2e.py
L3A = [
    ("l3a: the store's magic is not checked", 'if not lines or lines[0] not in ("CHODBDL1", "CHODBDL2"):', 'if False:'),
    ('l3a: a line may have any number of fields', '        if len(f) != (9 if version == 1 else 13):', '        if False:'),
    ('l3a: a seq may repeat', ' or int(f[0]) in seen:', ':'),
    ('l3a: a seq may have a leading zero', '(len(f[0]) > 1 and f[0][0] == "0") or ', ''),
    ('l3a: hex may be in capitals', 'any(c not in "0123456789abcdef" for c in text)', 'any(c not in "0123456789abcdefABCDEF" for c in text)'),
    ('l3a: a hash may be any length', 'if nbytes is not None and len(b) != nbytes:', 'if False:'),
    ('l3a: a row may have no hash at all', 'if row["old_hash"] is None and row["new_hash"] is None:', 'if False:'),
    ("l3a: the base's magic is not checked", 'if not lines or lines[0] != "CHODBBS%d" % version:', 'if False:'),
    ('l3a: a row of no commit of the log is let through', 'if r["commit"] not in ids:', 'if False:'),
    ("l3a: a row in another branch's schema is let through", 'if any(r["schema"] != schema_of(branch, first) for r in mine):', 'if False:'),
    ('l3a: rows on a commit that only read are let through', 'if mine and not any(k in (1, 2, 3) for k in kinds):', 'if False:'),
    ('l3a: an image need not be its hash', 'or (h is not None and hash_image(im) != h):', ':'),
    ('l3a: an image may lack its hash or a hash its image', 'if (h is None) != (im is None) or (h is not None', 'if (h is not None'),
    ('l3a: changes are not compared', 'if verdict != "ok " + changes.hex():', 'if False:'),
    ('l3a: netting takes the first new image', '            per[k][1] = r["new_hash"]', '            pass'),
    ('l3a: netting does not order by seq', 'for r in sorted(rows, key=lambda r: r["seq"]):', 'for r in list(rows):'),
    ('l3a: every fact is an update', '0 if o is None else 2 if n is None else 1', '1'),
    ('l3a: facts that net to nothing are facts', '        if o == n:\n            continue\n', ''),
    ('l3a: state is not compared', 'or ref.state([state_of[p] for p in parents], changes) != state:', 'or False:'),
    ("l3a: a merge's parents are taken in the other order", 'ref.state([state_of[p] for p in parents], changes)', 'ref.state([state_of[p] for p in reversed(parents)], changes)'),
    ('l3a: an insert of a key that is there is let through', '                if cur is not None:\n                    raise Reject("replay-precondition", i)', '                if False:\n                    raise Reject("replay-precondition", i)'),
    ('l3a: an update from another image is let through', 'elif cur is None or cur != o:', 'elif cur is None:'),
    ('l3a: a fork starts empty', 'maps[branch] = dict(maps[src])', 'maps[branch] = {}'),
    ("l3a: a fork shares the source's rows", 'maps[branch] = dict(maps[src])', 'maps[branch] = maps[src]'),
    ('l3a: a fork from an older commit is accepted', 'if last.get(src) != parents[0]:', 'if False:'),
    ("l3a: the base is not the first branch's", 'maps[branch] = dict(base) if branch == first else {}', 'maps[branch] = {}'),
    ('l3a: every branch is in the first schema', 'return "public" if branch == first else "cdb_b_" + branch', 'return "public"'),
    ('l3a: the last line may lack its newline', '    if data and not data.endswith("\\n"):', '    if False:'),
    ('l3a: a key may be twice in the base', '        if k in base:', '        if False:'),
    ('l3a v2: a salt need not make the hash', '                elif (im is None) != (sa is None) or (im is not None and hash_image(im, sa) != h):', '                elif (im is None) != (sa is None):'),
    ('l3a v2: a salt may lack its hash', '                    if im is not None or sa is not None:', '                    if im is not None:'),
    ('l3a v2: an image may lack its salt', '                elif (im is None) != (sa is None) or (im is not None and hash_image(im, sa) != h):', '                elif (im is not None and hash_image(im, sa) != h):'),
    ('l3a v2: the commitment need not be the key', '(r["key_plain"] is not None and key_commit(r["key_plain"], r["key_salt"]) != r["key"])', 'False'),
    ('l3a v2: a plain key may lack its salt', 'if (r["key_plain"] is None) != (r["key_salt"] is None) or (r["key_plain"] is not None and', 'if (r["key_plain"] is not None and r["key_salt"] is not None and'),
    ('l3a v2: erased keys are not counted', ' or r["key_plain"] is None)', ')'),
    ('l3a v2: erased images are not counted', '(r["old_hash"] is not None and r["old_image"] is None) or (r["new_hash"] is not None and r["new_image"] is None) or ', ''),
    ('l3a v2: the commitment may be any length', 'key=hexb(f[4], "key", 32 if version == 2 else None),', 'key=hexb(f[4], "key"),'),
    ('l3a v2: an old salt may be any length', 'old_salt=hexb(f[9], "salt", 16, True)', 'old_salt=hexb(f[9], "salt", None, True)'),
    ('l3a v2: a new salt may be any length', 'new_salt=hexb(f[10], "salt", 16, True)', 'new_salt=hexb(f[10], "salt", None, True)'),
    ('l3a v2: a key salt may be any length', 'key_salt=hexb(f[12], "salt", 16, True)', 'key_salt=hexb(f[12], "salt", None, True)'),
    ('l3a v2: the live row hash ignores the salt', 'hash_image(hexb(f[4], "image"), hexb(f[5], "salt", 16))', 'hash_image(hexb(f[4], "image"))'),
    ('l3a v2: the live key ignores its salt', 'key_commit(hexb(f[2], "key"), hexb(f[3], "salt", 16))', 'key_commit(hexb(f[2], "key"), bytes(16))'),
    ('l3a v2: the base row hash ignores the salt', 'h = hash_image(hexb(f[3], "image"), hexb(f[4], "salt", 16))', 'h = hash_image(hexb(f[3], "image"), bytes(16))'),
    ('l3a v2: the base key ignores its salt', 'k = (hexb(f[0], "table"), key_commit(hexb(f[1], "key"), hexb(f[2], "salt", 16)))', 'k = (hexb(f[0], "table"), key_commit(hexb(f[1], "key"), bytes(16)))'),
    ('l3a v2: the keys are not checked', '        if version == 2:\n            for r in mine:\n                if (r["key_plain"]', '        if version == 2 and False:\n            for r in mine:\n                if (r["key_plain"]'),
    ('l3a: the live tables are not compared', '        if seen[b] != m:', '        if False:'),
]


def run_l3a(cancho):
    only = os.environ.get("MUTANT_ONLY")
    survivors, count = [], 0
    for label, old, new in L3A:
        if only and only not in label:
            continue
        count += 1
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "tools", work / "tools", ignore=shutil.ignore_patterns("__pycache__"))
            (work / "tests").mkdir()
            shutil.copytree(ROOT / "tests" / "l3a", work / "tests" / "l3a")
            shutil.copy(ROOT / "tests" / "l3a_check.py", work / "tests" / "l3a_check.py")
            f = work / "tools" / "l3a.py"
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            verifier = "%s %s" % (sys.executable, f)
            if label.startswith("l3a live:"):
                cmd = [sys.executable, str(ROOT / "tests" / "l3a_e2e.py"), str(ROOT / "build" / "proxy"), verifier]
            else:
                cmd = [sys.executable, str(work / "tests" / "l3a_check.py"), verifier]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                rc, out = r.returncode, r.stdout
            except subprocess.TimeoutExpired:
                rc, out = 1, "FAIL timed out"
            if rc == 0:
                print("SURVIVED %-46s every L3a check passes" % label)
                survivors.append(label)
            else:
                first = [l for l in out.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d case(s), e.g. %s" % (label, len(first), first[0][5:70] if first else "a crash"))
    print("%d mutants, %d not killed" % (count, len(survivors)))
    return 1 if survivors else 0

# ---- the L3a verifier in cancho (src/l3a.cho), judged by the golden cases of tests/l3a
L3A_CHO = [
    ("l3a-cho: the store's magic is not checked", "    if !bytes.starts_with(text, magic) {", "    if false {"),
    ("l3a-cho: the first line may go on", "    if first != len(magic) || int_of(text[len(text) - 1]) != 10 {", "    if int_of(text[len(text) - 1]) != 10 {"),
    ("l3a-cho: a line may have more fields than it should", "    return count == n;", "    return count <= n;"),
    ("l3a-cho: a seq may not be digits", "                if int_of(text[k]) < '0' || int_of(text[k]) > '9' {", "                if false {"),
    ("l3a-cho: a seq may have a leading zero", "            if se - sa > 1 && int_of(text[sa]) == '0' {", "            if false {"),
    ("l3a-cho: a seq may repeat", "            if seen {\n                good = false;", "            if false {\n                good = false;"),
    ("l3a-cho: the last line may lack its newline", "    if first != len(magic) || int_of(text[len(text) - 1]) != 10 {", "    if first != len(magic) {"),
    ("l3a-cho: a key may be twice in the base", "            if twice {\n                rule = store_malformed();", "            if false {\n                rule = store_malformed();"),
    ("l3a-cho v2: a version 2 store is read as version 1", '    if bytes.starts_with(text, "CHODBDL2") {', '    if false {'),
    ("l3a-cho v2: the commitment may be any length", "            if meta[b + 9] - meta[b + 8] != 64 {", "            if false {"),
    ("l3a-cho v2: an old or new salt may be any length", "                if se != sa && (se - sa != 32 || !hex_text(text, sa, se)) {", "                if se != sa && !hex_text(text, sa, se) {"),
    ("l3a-cho v2: a plain key need not be hex", "            if good && meta[b + 23] != meta[b + 22] && !hex_text(text, meta[b + 22], meta[b + 23]) {", "            if false {"),
    ("l3a-cho v2: a key salt may be any length", "            if good && meta[b + 25] != meta[b + 24] && (meta[b + 25] - meta[b + 24] != 32 || !hex_text(text, meta[b + 24], meta[b + 25])) {", "            if good && meta[b + 25] != meta[b + 24] && !hex_text(text, meta[b + 24], meta[b + 25]) {"),
    ("l3a-cho v2: a base or dump salt may be any length", "(f == salt_a || f == salt_b) && fe - fa != 32", "false"),
    ("l3a-cho v2: a salt may lack its hash", "                            if ie > ia || se > sa {", "                            if ie > ia {"),
    ("l3a-cho v2: an image may lack its salt", "                        } else if ie > ia != se > sa {", "                        } else if false {"),
    ("l3a-cho v2: a salt need not make the hash", "                            state.row_hash2(salt16, big[0..n], tmp32);\n                            if !same32(tmp32, 0, hs, 32 * (2 * row + side)) {", "                            state.row_hash2(salt16, big[0..n], tmp32);\n                            if false {"),
    ("l3a-cho v2: a plain key may lack its salt", "                if pe > pa != ke > ka {", "                if false {"),
    ("l3a-cho v2: the commitment need not be the key", "                    state.hexdec(dtext, dmeta[m + 8], dmeta[m + 9], kb32, 0);\n                    if !same32(tmp32, 0, kb32, 0) {", "                    state.hexdec(dtext, dmeta[m + 8], dmeta[m + 9], kb32, 0);\n                    if false {"),
    ("l3a-cho v2: the base row hash ignores the salt", "                state.row_hash2(salt16, big[0..n2], tmp32);", "                state.row_hash(big[0..n2], tmp32);"),
    ("l3a-cho v2: the base key ignores its salt", "                state.key_commit(salt16, big[0..n], tmp32);\n                hex_put(lh, 64 * k, tmp32);", "                state.key_commit(kb32, big[0..n], tmp32);\n                hex_put(lh, 64 * k, tmp32);"),
    ("l3a-cho v2: the live row hash ignores the salt", "                        state.row_hash2(salt16, big[0..n], tmp32);\n                    } else {", "                        state.row_hash(big[0..n], tmp32);\n                    } else {"),
    ("l3a-cho v2: the live key ignores its salt", "                        state.key_commit(salt16, big[0..pn], tmp32);", "                        state.key_commit(kb32, big[0..pn], tmp32);"),
    ("l3a-cho v2: erased keys are not counted", "                if old_erased || new_erased || dmeta[m + 23] <= dmeta[m + 22] {", "                if old_erased || new_erased {"),
    ("l3a-cho v2: erased images are not counted", "                if old_erased || new_erased || dmeta[m + 23] <= dmeta[m + 22] {", "                if dmeta[m + 23] <= dmeta[m + 22] {"),
    ("l3a-cho v2: an erased row is counted twice", "                if old_erased || new_erased || dmeta[m + 23] <= dmeta[m + 22] {\n                    erased = erased + 1;", "                if old_erased || new_erased || dmeta[m + 23] <= dmeta[m + 22] {\n                    erased = erased + 1;\n                    if old_erased && new_erased {\n                        erased = erased + 1;\n                    }"),
    ("l3a-cho: hex may be in capitals", "c >= 'a' && c <= 'f';", "c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';"),
    ("l3a-cho: hex may be of an odd length", "    if b <= a || (b - a) % 2 != 0 {", "    if b <= a {"),
    ("l3a-cho: a commit id may be of any length", "meta[b + 3] - meta[b + 2] != 64 || ", ""),
    ("l3a-cho: a hash may be of any length", "if he != ha && (he - ha != 64 || !hex_text(text, ha, he)) {", "if he != ha && !hex_text(text, ha, he) {"),
    ("l3a-cho: a row may have no hash", "        if good && meta[b + 11] == meta[b + 10] && meta[b + 13] == meta[b + 12] {", "        if false {"),
    ("l3a-cho: a schema may be empty", "        if good && meta[b + 5] <= meta[b + 4] {", "        if false {"),
    ("l3a-cho: a table need not be hex", "        if good && !hex_text(text, meta[b + 6], meta[b + 7]) {", "        if false {"),
    ("l3a-cho: a key need not be hex", "        if good && !hex_text(text, meta[b + 8], meta[b + 9]) {", "        if false {"),
    ("l3a-cho: an image need not be hex", "            if ie != ia && !hex_text(text, ia, ie) {", "            if false {"),
    ("l3a-cho: a row of no commit is let through", "            if ci < 0 {\n                rule = store_foreign_row();", "            if false {\n                rule = store_foreign_row();"),
    ("l3a-cho: a row in another schema is let through", "                if !schema_is(dtext[dmeta[m + 4]..dmeta[m + 5]], name, bi == first_bi) {", "                if false {"),
    ("l3a-cho: rows on a commit that only read are let through", "            if rule == 0 && hi > lo && ci[8 * i + 3] == 0 {", "            if false {"),
    ("l3a-cho: a call is not a write", "                    if kind == 1 || kind == 2 || kind == 3 {", "                    if kind == 1 || kind == 2 {"),
    ("l3a-cho: a hash may lack its image", "                    } else if he > ha != ie > ia {", "                    } else if false {"),
    ("l3a-cho: an image need not be its hash", "                        state.row_hash(big[0..n], tmp32);\n                        if !same32(tmp32, 0, hs, 32 * (2 * row + side)) {", "                        state.row_hash(big[0..n], tmp32);\n                        if false {"),
    ("l3a-cho: changes are not compared", "                if code != 0 || !same32(digest, 0, enc, cat) {", "                if false {"),
    ("l3a-cho: changes are the log's own without the facts", "                if code != 0 || !same32(digest, 0, enc, cat) {", "                if code != 0 {"),
    ("l3a-cho: a fact that nets to nothing is a fact", "                    } else if oldp && newp && same32(hs, 32 * (2 * gi[g]), hs, 32 * (2 * gi[1 * g1 + g] + 1)) {", "                    } else if false {"),
    ("l3a-cho: a row of the same key is a new fact", "                        same = bytes.equal(dtext[dmeta[pm + 6]..dmeta[pm + 7]], dtext[dmeta[m + 6]..dmeta[m + 7]]) && bytes.equal(dtext[dmeta[pm + 8]..dmeta[pm + 9]], dtext[dmeta[m + 8]..dmeta[m + 9]]);", "                        same = false;"),
    ("l3a-cho: the netting ignores the table", "                        same = bytes.equal(dtext[dmeta[pm + 6]..dmeta[pm + 7]], dtext[dmeta[m + 6]..dmeta[m + 7]]) && ", "                        same = "),
    ("l3a-cho: the netting takes the first new image", "                    gi[1 * g1 + ng - 1] = ord[k];", "                    if !same {\n                        gi[1 * g1 + ng - 1] = ord[k];\n                    }"),
    ("l3a-cho: seq does not order the changes of a key", "    return bytes.compare(text[meta[a]..meta[a + 1]], text[meta[b]..meta[b + 1]]) < 0;", "    return false;"),
    ("l3a-cho: seq is compared as text only", "    if la != lb {\n        return la < lb;\n    }\n", ""),
    ("l3a-cho: an unknown parent is let through", "                    if pi < 0 {\n                        rule = state_mismatch();", "                    if pi < 0 {\n                        rule = 0;"),
    ("l3a-cho: state is not compared", "                    if !same32(want, 0, enc, ci[8 * i + 4]) {", "                    if false {"),
    ("l3a-cho: a fork is not checked against its parent's tip", "                        if ci[o_bl + src] != p0 {", "                        if false {"),
    ("l3a-cho: a fork starts empty", "== src {\n                                        gi[3 * g1 + j] = pos;", "== src && false {\n                                        gi[3 * g1 + j] = pos;"),
    ("l3a-cho: a fork copies into the wrong branch", "                            ck[gi[3 * g1 + j] + 1] = byte_of(bi % 256);", "                            ck[gi[3 * g1 + j] + 1] = byte_of(src % 256);"),
    ("l3a-cho: the base is not the first branch's", "        if rule == 0 && first_bi >= 0 && has_base {", "        if false {"),
    ("l3a-cho: an insert of a key that is there is let through", "                            if cur >= 0 {\n                                rule = replay_precondition();", "                            if false {\n                                rule = replay_precondition();"),
    ("l3a-cho: an update of an absent key is let through", "                        } else if cur < 0 || !same32(hs, 32 * cur, hs, 32 * (2 * gi[g])) {", "                        } else if !same32(hs, 32 * cur, hs, 32 * (2 * gi[g])) {"),
    ("l3a-cho: an update from another image is let through", "                        } else if cur < 0 || !same32(hs, 32 * cur, hs, 32 * (2 * gi[g])) {", "                        } else if cur < 0 {"),
    ("l3a-cho: a delete does not remove", "                            if gi[2 * g1 + g] == 2 {", "                            if false {"),
    ("l3a-cho: an update keeps the old image", "                                maps = map.put(heap, maps, keybuf[0..kn], 2 * gi[1 * g1 + g] + 1);", "                                maps = map.put(heap, maps, keybuf[0..kn], 2 * gi[g]);"),
    ("l3a-cho: facts are not counted", "                            nfacts = nfacts + 1;", "                            nfacts = nfacts;"),
    ("l3a-cho: a live row of no branch's schema is let through", "                if bi < 0 {\n                    rule = replay_final();", "                if bi < 0 {\n                    rule = 0;"),
    ("l3a-cho: a live key may be twice", "                    if twice || cur < 0 || !same32(tmp32, 0, hs, 32 * cur) {", "                    if cur < 0 || !same32(tmp32, 0, hs, 32 * cur) {"),
    ("l3a-cho: a live row may be unknown", "                    if twice || cur < 0 || !same32(tmp32, 0, hs, 32 * cur) {", "                    if twice || !same32(tmp32, 0, hs, 32 * cur) {"),
    ("l3a-cho: a live row may differ", "                    if twice || cur < 0 || !same32(tmp32, 0, hs, 32 * cur) {", "                    if twice || cur < 0 {"),
    ("l3a-cho: a row the dump lacks is let through", "                if held != dumped {", "                if false {"),
    ("l3a-cho: the first branch's schema is cdb_b_", "        return bytes.equal(schema, \"public\");", "        return bytes.starts_with(schema, \"cdb_b_\");"),
]


def run_l3a_cho(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in L3A_CHO if not only or only in m[0]]
    survivors = []
    for label, old, new in table:
        old, new = old.replace("\\n", "\n"), new.replace("\\n", "\n")
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            f = work / "src" / "l3a.cho"
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            exe = work / "l3averify"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/l3averify.cho")] + [str(work / "src" / n) for n in ("l3a.cho", "commit.cho", "build.cho", "state.cho")] + ["-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            try:
                r = subprocess.run([sys.executable, str(ROOT / "tests/l3a_check.py"), str(exe)], capture_output=True, text=True, timeout=300)
                rc, out = r.returncode, r.stdout
            except subprocess.TimeoutExpired:
                rc, out = 1, "FAIL timed out"
            if rc == 0:
                print("SURVIVED %-46s every L3a case passes" % label)
                survivors.append(label)
            else:
                first = [l for l in out.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d case(s), e.g. %s" % (label, len(first), first[0][5:70] if first else "a crash"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0



def run(kind, cancho):
    if kind == "guard":
        return run_guard(cancho)
    if kind == "build":
        return run_build(cancho)
    if kind == "store":
        return run_store(cancho)
    if kind == "sql":
        return run_sql(cancho)
    if kind == "l3a":
        return run_l3a(cancho)
    if kind == "l3a-cho":
        return run_l3a_cho(cancho)
    if kind == "state":
        return run_state(cancho)
    if kind == "lower":
        return run_lower(cancho)
    if kind == "login":
        return run_login(cancho)
    if kind == "lex":
        return run_unit(LEX, ["tests/lex_test.cho", "tests/lex_cases.cho"], ["lex.cho"], cancho)
    if kind == "parse":
        return run_unit(PARSE, ["tests/parse_test.cho", "tests/parse_cases.cho"], ["lex.cho", "parse.cho"], cancho)
    if kind == "stmt":
        return run_unit(STMT, ["tests/stmt_test.cho", "tests/stmt_cases.cho"], ["lex.cho", "parse.cho", "stmt.cho"], cancho)
    if kind == "proxy":
        return run_proxy(cancho)
    table = PY if kind == "py" else CHO
    only = os.environ.get("MUTANT_ONLY")
    if only:
        table = [m for m in table if only in m[0]]
    survivors = []
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            shutil.copytree(ROOT / "tools", work / "tools")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                print("STALE  %-40s original text occurs %d times" % (label, text.count(old)))
                survivors.append(label)
                continue
            f.write_text(text.replace(old, new))
            if kind == "py":
                cmd = [sys.executable, str(work / "tools/verify.py")]
            else:
                exe = work / "verify"
                sources = sorted(str(p) for p in (work / "src").glob("*.cho"))
                b = subprocess.run([cancho, "build", "--std"] + sources + ["-o", str(exe)],
                                   capture_output=True, text=True)
                if b.returncode != 0:
                    print("BROKEN %-40s does not build: %s" % (label, b.stderr.strip()[:200]))
                    survivors.append(label)
                    continue
                cmd = [str(exe)]
            r = subprocess.run([sys.executable, str(ROOT / "tests/run_vectors.py"), str(ROOT / "vectors"), "--"] + cmd,
                               capture_output=True, text=True)
            if r.returncode == 0:
                print("SURVIVED %-38s no vector fails" % label)
                survivors.append(label)
            else:
                failed = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
                print("killed   %-38s by %d vector(s), e.g. %s" % (label, len(failed), failed[0].split()[1]))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


if __name__ == "__main__":
    kind = sys.argv[1]
    sys.exit(run(kind, sys.argv[2] if len(sys.argv) > 2 else "cancho"))
