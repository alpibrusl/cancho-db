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
    ("erase: the statement store is not rewritten", "proxy/proxy.cho", "    let r = shared.store_erase(heap, core.store, contents(core.ern)[0..ei[0]]);", "    let r = shared.store_erase(heap, core.store, contents(core.ern)[0..0]);"),
    ("erase: an erase that did not commit still rewrites the store", "proxy/proxy.cho", "erase_ok = !failed && r == 0 && contents(core.store.chain)[2] > contents(core.erni)[1];", "erase_ok = r == 0;"),
    ("erase: the needles keep the opening quote", "src/erase.cho", "out[w + 2 + j] = key[i + 1 + j];", "out[w + 2 + j] = key[i + j];"),
    ("erase: the needles leave out the text values", "src/erase.cho", "if e < len(key) && e > i + 1 && w + 2 + (e - i - 1) <= len(out) {", "if false {"),
    ("erase-branch: an erase on a branch runs in the first branch's schema", "src/erase.cho", "    var at = put(out, 0, \"select cdb.erase('\");\n    if first {", "    var at = put(out, 0, \"select cdb.erase('\");\n    if true {"),
    ("erase-branch: the extended protocol runs the erase", "src/extended.cho", "} else if vd[6] == 0 && forkpath.is_erase(vd[7], effs[0..vd[9]]) {", "} else if false {"),
    ("install: a deadlock is not retried", "src/catalog.cho", "attempt < 5 && retriable(core)", "attempt < 0 && retriable(core)"),
    ("install: the retries are not bounded by five", "src/catalog.cho", "attempt < 5 && retriable(core)", "attempt < 50 && retriable(core)"),
    ("install: every error is retried", "src/catalog.cho", "attempt < 5 && retriable(core)", "attempt < 5"),
    ("install: a serialization failure is not retried", "src/catalog.cho", "(int_of(eb[2]) == 'P' || int_of(eb[2]) == '0')", "int_of(eb[2]) == 'P'"),
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
                    judge = "ext_e2e.py" if label.startswith("ext:") else "changes_e2e.py" if label.startswith("chg:") else "fork_e2e.py" if label.startswith("fork:") else "asof_e2e.py" if label.startswith("asof:") else "merge_e2e.py" if label.startswith("merge:") else "erase_e2e.py" if label.startswith("erase:") else "erase_branch_e2e.py" if label.startswith("erase-branch:") else "install_retry_e2e.py" if label.startswith("install:") else "proxy_e2e.py"
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
    ("parse: a reserved word is a name", "src/parse.cho", "} else if is_reserved(sql, a, l) && !(punct(sql, toks, pos + 1, end, '(') &&", "} else if false && !(punct(sql, toks, pos + 1, end, '(') &&"),
    ("parse: any reserved word before a parenthesis is a call", "src/parse.cho", "(word_is(sql, a, l, \"coalesce\") || word_is(sql, a, l, \"greatest\") || word_is(sql, a, l, \"least\"))) {", "true) {"),
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
    ("ddl: CREATE SEQUENCE is a statement of the proxy", "src/stmt.cho", "    st[10] = 0;\n    engine_form(st, parse.e_unsupported_statement());\n    let ine = if_not_exists(sql, toks, from + 2, end, st);", "    st[10] = 0;\n    let ine = 0;"),
    ("dml: INSERT ... SELECT with no table is a statement of the proxy", "src/stmt.cho", "        engine_form(st, parse.e_insert_select());\n        let at = pos;", "        let at = pos;"),
    ("dml: INSERT ... SELECT ... FROM is read as far as the FROM", "src/stmt.cho", '        if pos < end && !parse.kw(sql, toks, pos, end, "on") && !parse.kw(sql, toks, pos, end, "returning") {\n            return parse.fail(st, at, parse.e_insert_select());\n        }', ''),
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
    ("dml: INSERT ... SELECT is a syntax error", "src/stmt.cho", '        if parse.kw(sql, toks, pos, end, "with") {\n            return parse.fail(st, pos, parse.e_insert_select());', '        if false {\n            return parse.fail(st, pos, parse.e_insert_select());'),
    ("dml: INSERT without VALUES", "src/stmt.cho", '        if !parse.kw(sql, toks, pos, end, "values") {\n            return parse.fail(st, pos, parse.e_syntax());', '        if false {\n            return parse.fail(st, pos, parse.e_syntax());'),
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
    ("dml: UPDATE or DELETE without a trailing check", "src/stmt.cho", "    if pos < end {\n        return leftover(sql, toks, pos, end, st);\n    }\n    let root = parse.mk(nodes, kids, st, parse.n_update()", "    if false {\n        return leftover(sql, toks, pos, end, st);\n    }\n    let root = parse.mk(nodes, kids, st, parse.n_update()"),
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
    ("ddl: the default sets no flag", "src/stmt.cho", "parse.n_coldef(), col, tmp[mark..st[10]], st[10] - mark, flags % 8 + flags / 16 * 16,", "parse.n_coldef(), col, tmp[mark..st[10]], st[10] - mark, flags / 16 * 16,"),
    ("ddl: a column loses its name", "src/stmt.cho", "parse.n_coldef(), col, tmp[mark..st[10]]", "parse.n_coldef(), 0 - 1, tmp[mark..st[10]]"),
    ("ddl: a table name may have a schema", "src/stmt.cho", "    if parse.punct(sql, toks, pos + 1, end, '.') {\n        return parse.fail(st, pos + 1, parse.e_unknown_construct());\n    }\n    st[9] = pos;", "    st[9] = pos;"),
    ("ddl: CREATE TABLE may end early", "src/stmt.cho", "    pos = pos + 1;\n    if pos < end {\n        return parse.fail(st, pos, parse.e_syntax());\n    }\n    let root = close_list(nodes, kids, tmp, st, parse.n_create_table(), 0, table);", "    pos = pos + 1;\n    let root = close_list(nodes, kids, tmp, st, parse.n_create_table(), 0, table);"),
    ("ddl: ALTER TABLE does more than ADD", "src/stmt.cho", '        if !parse.kw(sql, toks, pos, end, "add") {\n            return parse.fail(st, pos, parse.e_unsupported_statement());\n        }', '        if false {\n            return parse.fail(st, pos, parse.e_unsupported_statement());\n        }'),
    ("ddl: ADD COLUMN requires COLUMN", "src/stmt.cho", '        pos = pos + 1;\n        if parse.kw(sql, toks, pos, end, "column") {\n            pos = pos + 1;\n        }\n        how = if_not_exists', '        pos = pos + 1;\n        if false {\n            pos = pos + 1;\n        }\n        how = if_not_exists'),
    ("ddl: UNIQUE INDEX is a plain index", "src/stmt.cho", "        unique = 1;\n        pos = pos + 1;", "        unique = 0;\n        pos = pos + 1;"),
    ("ddl: an index may have no ON", "src/stmt.cho", '    if !parse.kw(sql, toks, pos, end, "on") {\n        return parse.fail(st, pos, parse.e_syntax());\n    }', '    if false {\n        return parse.fail(st, pos, parse.e_syntax());\n    }'),
    ("ddl: an index loses its table", "src/stmt.cho", "parse.n_create_index(), name, tmp[0..st[10]], st[10], unique + 2 * ine + 4 * cond, table);", "parse.n_create_index(), name, tmp[0..st[10]], st[10], unique + 2 * ine + 4 * cond, name);"),
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
    ("lower: an ON sees a table joined after it", "src/lower.cho", "                    sc[5] = first;\n                    sc[2] = f + 1;", "                    sc[5] = first;"),
    ("lower: an ON sees a table before the comma", "src/lower.cho", "                    sc[5] = first;\n                    sc[2] = f + 1;", "                    sc[2] = f + 1;"),
    ("lower: an unqualified column in an ON is looked for in every table", "src/lower.cho", "        var found = 0;\n        var i = sc[5];", "        var found = 0;\n        var i = 0;"),
    ("lower: an output column is named by a CASE's first condition", "src/lower.cho", "                x = kids[nodes[6 * x + 2] + nodes[6 * x + 3] - 1];", "                x = kids[nodes[6 * x + 2]];"),
    ("lower: the innermost cast or CASE names the column", "src/lower.cho", "            if weak == 0 {\n                weak = 2;\n            }", "            weak = 2;"),
    ("lower: a cast has no name of its own", "src/lower.cho", "        return put_text(out, at, cast_name(code));", "        return put_text(out, at, \"?column?\");"),
    ("lower: a CASE has no name of its own", "src/lower.cho", "        return put_text(out, at, \"case\");", "        return put_text(out, at, \"?column?\");"),
    ("lower: ORDER BY does not see the name of a column without an alias", "src/lower.cho", "                        named = names_output(sql, toks, nodes, kids, kids[nodes[6 * it + 2]], ord_name);", "                        named = false;"),
    ("lower: integer is named integer", "src/lower.cho", "    if code == 2 {\n        return \"int4\";", "    if code == 2 {\n        return \"integer\";"),
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
    ("lower: ORDER BY ignores an alias", "src/lower.cho", "                        named = same_name(sql, toks, ord_name, nodes[6 * it + 1]);", "                        named = false;"),
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
    ("engine-forms: RETURNING goes to PostgreSQL", "src/stmt.cho",
     '    engine_form(st, parse.e_returning());\n    st[10] = 0;', '    st[10] = 0;'),
    ("engine-forms: the second form's refusal is the one given", "src/stmt.cho",
     '    if st[12] == 0 {\n        st[12] = code;\n    }', '    st[12] = code;'),
    ("engine-forms: ON CONFLICT DO NOTHING goes to PostgreSQL", "src/stmt.cho",
     '        oc = 1;\n        engine_form(st, parse.e_on_conflict());', '        oc = 1;'),
    ("engine-forms: IF NOT EXISTS goes to PostgreSQL", "src/stmt.cho",
     'parse.kw(sql, toks, pos + 2, end, "exists") {\n        engine_form(st, parse.e_unsupported_statement());', 'parse.kw(sql, toks, pos + 2, end, "exists") {'),
    ("engine-forms: a CHECK goes to PostgreSQL", "src/stmt.cho",
     '            flags = flags + 16;\n            engine_form(st, parse.e_unsupported_statement());', '            flags = flags + 16;'),
    ("engine-forms: an identity column goes to PostgreSQL", "src/stmt.cho",
     '            if bit == 32 {\n                engine_form(st, parse.e_unsupported_statement());\n            }', ''),
    ("engine-forms: a table key goes to PostgreSQL", "src/stmt.cho",
     '            keyed = true;\n            engine_form(st, parse.e_unsupported_statement());', '            keyed = true;'),
    ("engine-forms: a change of type goes to PostgreSQL", "src/stmt.cho",
     '        how = 2;\n        engine_form(st, parse.e_unsupported_statement());', '        how = 2;'),
    ("engine-forms: an index with a condition goes to PostgreSQL", "src/stmt.cho",
     '        cond = 1;\n        engine_form(st, parse.e_unsupported_statement());', '        cond = 1;'),
    ("engine-forms: the guard does not look at the mark", "src/guard.cho",
     'if pq >= 0 && contents(sw)[12] != 0 {', 'if pq >= 0 && contents(sw)[12] < 0 {'),
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



# ---- the copy-on-write B+tree and its pages (src/btree.cho, src/pager.cho), judged by tests/btree_check.py; the superblocks and the commit (src/pstore.cho), judged by tests/pstore_check.py
BTREE = [
    ("pager: a page changed under the cache is still served", "src/pager.cho", "    var rc = 0;\n    forget(p, id);", "    var rc = 0;"),
    ("btree: a page above one written anew is left as it was", "src/btree.cho", "        if !split && cid == was(sc, level + 1) {", "        if !split {"),
    ("btree: after a removal a page above a new page is left as it was", "src/btree.cho", "        if !removed && cid == was(sc, level + 1) {", "        if !removed {"),
    ("btree: keys compare backwards", "src/btree.cho", "        if c < d {\n            return 0 - 1;\n        }\n        if c > d {\n            return 1;\n        }", "        if c > d {\n            return 0 - 1;\n        }\n        if c < d {\n            return 1;\n        }"),
    ("btree: a key equal to a separator goes to the child on its left", "src/btree.cho", "if cmp(key, pg[at + 1..at + 1 + kl]) >= 0 {", "if cmp(key, pg[at + 1..at + 1 + kl]) > 0 {"),
    ("btree: a put of an existing key adds an entry", "src/btree.cho", "            if c == 0 {\n                added = 0;\n            } else {\n                wpos = mv(sc, wpos, at, elen);\n            }", "            wpos = mv(sc, wpos, at, elen);"),
    ("btree: the first child is not replaced in the parent", "src/btree.cho", "        if ix == 0 {\n            c0 = cid;\n        }\n        build.put_be(sc, wpos, c0, 4);", "        build.put_be(sc, wpos, c0, 4);"),
    ("btree: the wrong child is replaced in the parent", "src/btree.cho", "            if e == ix {\n                chn = cid;\n            }\n            build.put_be(sc, wpos, chn, 4);\n            wpos = wpos + 4;\n            if split && e == ix {", "            if e == ix + 1 {\n                chn = cid;\n            }\n            build.put_be(sc, wpos, chn, 4);\n            wpos = wpos + 4;\n            if split && e == ix {"),
    ("btree: the right half of a split goes in the wrong place", "src/btree.cho", "            if split && e == ix {\n                wpos = put_int_entry(sc, wpos, w3(), seplen, rid);", "            if split && e == ix + 1 {\n                wpos = put_int_entry(sc, wpos, w3(), seplen, rid);"),
    ("btree: a leaf split promotes the wrong key", "src/btree.cho", "mv(sc, w3(), w1() + b + 3, sl);", "mv(sc, w3(), w1() + b + 2, sl);"),
    ("btree: an internal split promotes the wrong key", "src/btree.cho", "mv(sc, w3(), w1() + b + 1, kl);", "mv(sc, w3(), w1() + b, kl);"),
    ("btree: a leaf may be made fuller than a page", "src/btree.cho", "    if 7 + total <= 4096 {\n        emit_at(sc, w2(), 1, ncount, w1(), total);", "    if 7 + total <= 4200 {\n        emit_at(sc, w2(), 1, ncount, w1(), total);"),
    ("btree: the last entry of a leaf is not dropped from its parent", "src/btree.cho", "var removed = count == 1;", "var removed = count == 0;"),
    ("btree: a page with one child that is deleted stays", "src/btree.cho", "if removed && pcount == 0 {", "if false {"),
    # (`e = 1` there is an equivalent mutant: it copies one more entry, of zeros, past the count the page states, and the count is what is read)
    ("btree: deleting the first child also drops the next entry", "src/btree.cho", "                    pat = pat + 5 + kl0;\n                    e = 2;", "                    pat = pat + 5 + kl0;\n                    e = 3;"),
    ("btree: a value's length is one byte", "src/btree.cho", "    build.put_be(sc, at + 1, len(vbytes), 2);", "    build.put_be(sc, at + 1, len(vbytes), 1);"),
    ("btree: a value of 801 bytes is taken", "src/btree.cho", "len(vbytes) > max_value()", "len(vbytes) > 900"),
    ("btree: a key of 201 bytes is taken", "src/btree.cho", "len(key) > max_key()", "len(key) > 300"),
    ("btree: the first entry after a key may be the key", "src/btree.cho", "take = c > 0 || inclusive && c == 0;", "take = c >= 0;"),
    ("btree: an inclusive scan skips the key", "src/btree.cho", "take = c > 0 || inclusive && c == 0;", "take = c > 0;"),
    ("btree: a scan takes the nearest right sibling it saw first", "src/btree.cho", "                if al != 0 {\n                    alt = al;\n                }", "                if al != 0 && alt == 0 {\n                    alt = al;\n                }"),
    ("pstore: a commit writes its superblock to the wrong page", "src/pstore.cho", "pager.write_page(p, 1 + seq % 2, sc[off..off + 4096]);", "pager.write_page(p, 2 - seq % 2, sc[off..off + 4096]);"),
    ("pstore: the catalog is not synced before the superblock is written", "src/pstore.cho", "    var rc = pager.sync(p);\n    if rc < 0 {\n        return code(rc);\n    }\n    rc = write_super(p, sc, seq + 1, cat);", "    var rc = 0;\n    rc = write_super(p, sc, seq + 1, cat);"),
    ("pstore: the superblock is not synced", "src/pstore.cho", "    rc = pager.sync(p);\n    if rc < 0 {\n        return code(rc);\n    }\n    return seq + 1;", "    return seq + 1;"),
    ("pstore: a new database's catalog is not synced before its superblock", "src/pstore.cho", "            zero = pager.sync(p);\n            if zero == 0 {\n                zero = write_super(p, sc, 0, cat);", "            zero = 0;\n            if zero == 0 {\n                zero = write_super(p, sc, 0, cat);"),
    ("pstore: the first valid superblock wins, not the newest", "src/pstore.cho", "            if seq > best && seq % 2 == slot - 1 {", "            if best < 0 && seq % 2 == slot - 1 {"),
    ("pstore: a file with no valid superblock is an empty database", "src/pstore.cho", "    if best < 0 {\n        return btree.err_bad();\n    }", "    if best < 0 {\n        return no_database();\n    }"),
    ("pstore: the roots are read from the wrong place", "src/pstore.cho", "        roots[i] = commit.be(sc, 7 + 4 * i, 4);", "        roots[i] = commit.be(sc, 8 + 4 * i, 4);"),
    ("pager: a superblock page is handed out as a page of a tree", "src/pager.cho", "    if next < 3 {\n        next = 3;\n    }", "    if next < 1 {\n        next = 1;\n    }"),
    ("pstore: a sweep does not keep what is not committed yet", "src/pstore.cho", "                if roots[i] != 0 {\n                    st[top] = roots[i];", "                if false {\n                    st[top] = roots[i];"),
    ("pstore: a sweep keeps only the pages of the first superblock", "src/pstore.cho", "            while slot <= 2 && err == 0 {\n                let rc = pager.read_page(p, slot, sc[0..4096]);\n                if rc == 0 - 1 {\n                    err = btree.err_io();\n                } else if", "            while slot <= 1 && err == 0 {\n                let rc = pager.read_page(p, slot, sc[0..4096]);\n                if rc == 0 - 1 {\n                    err = btree.err_io();\n                } else if"),
    ("pstore: a sweep does not keep the catalog pages", "src/pstore.cho", "                        mk[cat] = byte_of(1);", "                        mk[cat] = byte_of(0);"),
    ("pstore: a sweep does not zero the pages it frees", "src/pstore.cho", "                        let rc = pager.zero_page(p, id);", "                        let rc = 0;"),
    ("pstore: a sweep is not synced", "src/pstore.cho", "    let rc = pager.sync(p);\n    if rc < 0 {\n        return code(rc);\n    }\n    return count;", "    return count;"),
    ("pstore: a sweep keeps only the first child of a page", "src/pstore.cho", "                                st[top] = commit.be(sc, at + 1 + kl, 4);\n                                top = top + 1;", "                                st[top] = commit.be(sc, at + 1 + kl, 4);"),
    ("pstore: a sweep does not keep the first child of a page", "src/pstore.cho", "                            st[top] = commit.be(sc, 7, 4);\n                            top = top + 1;", "                            st[top] = commit.be(sc, 7, 4);"),
    ("pstore: a free page is handed out twice", "src/pager.cho", "        p.nfree = p.nfree - 1;\n        id = contents(p.free)[p.nfree];", "        id = contents(p.free)[p.nfree - 1];"),
    ("pstore: zeroing a page stops at its first half", "src/pager.cho", "                var upto = 4096;\n                if p.crash > 0 && p.steps == p.crash {\n                    p.dead = true;\n                    upto = p.torn;\n                }", "                var upto = 2048;\n                if p.crash > 0 && p.steps == p.crash {\n                    p.dead = true;\n                    upto = p.torn;\n                }"),
    ("pager: the CRC of a page is not checked", "src/pager.cho", "    if crc.crc32_of(out[7..4096]) != commit.be(out, 3, 4) {\n        return 0 - 2;\n    }", ""),
    ("pager: the CRC is checked over less than the page", "src/pager.cho", "    if crc.crc32_of(out[7..4096]) != commit.be(out, 3, 4) {", "    if crc.crc32_of(out[7..4000]) != commit.be(out, 3, 4) {"),
]


def run_btree(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in BTREE if not only or only in m[0]]
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
            exe = work / "btcheck"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/btcheck.cho")] + [str(work / "src" / n) for n in ("btree.cho", "pager.cho", "pstore.cho", "commit.cho", "build.cho")] + ["-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            try:
                judge = [str(ROOT / "tests/pstore_check.py"), str(exe)] if label.startswith("pstore:") or label.startswith("pager: a superblock") else [str(ROOT / "tests/btree_check.py"), str(exe), "3"]
                r = subprocess.run([sys.executable] + judge, capture_output=True, text=True, timeout=900)
                rc, out = r.returncode, r.stdout
            except subprocess.TimeoutExpired:
                rc, out = 1, "FAIL timed out"
            if rc == 0:
                print("SURVIVED %-46s every tree check passes" % label)
                survivors.append(label)
            else:
                first = [l for l in out.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d check(s), e.g. %s" % (label, len(first), first[0][5:70] if first else "a crash"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


# ---- the engine's rows (src/row.cho), judged by tests/row_check.py against PostgreSQL
ROW = [
    ("row: the image's keys are in byte order, not jsonb's", "src/row.cho", "    if len(x) != len(y) {\n        return len(x) < len(y);\n    }\n", ""),
    ("row: the image separates columns with a comma alone", "src/row.cho", "            w = puts(out, w, \", \");\n        }\n        w = json_string(out, w, col_name(def, best));", "            w = puts(out, w, \",\");\n        }\n        w = json_string(out, w, col_name(def, best));"),
    ("row: hex digits are upper case", "src/row.cho", "    return 'a' + v - 10;", "    return 'A' + v - 10;"),
    ("row: the byte 0x1f is not escaped", "src/row.cho", "        } else if c < 32 {", "        } else if c < 31 {"),
    ("row: a quote is not escaped", "src/row.cho", "        if c == '\"' || c == '\\\\' {", "        if c == '\\\\' {"),
    ("row: a negative integer is one too large", "src/row.cho", "    if neg {\n        v = v - 1;\n    }\n", ""),
    ("row: bytea's backslash is not doubled", "src/row.cho", 'var w = puts(out, at, "\\"\\\\\\\\x");', 'var w = puts(out, at, "\\"\\\\x");'),
    ("row: a stored integer key keeps its sign bit", "src/row.cho", "                    b = (b + 128) % 256;", "                    b = b;"),
    ("row: a stored text key has no terminator", "src/row.cho", "            w = put1(out, w, 0);\n            w = put1(out, w, 0);", "            w = w;"),
    ("row: a null key column is taken", "src/row.cho", "            if col_pk(def, i) > 0 {\n                return false;\n            }", "            if false {\n                return false;\n            }"),
    ("row: a boolean of 2 is taken", "src/row.cho", "} else if tag == 2 && int_of(row[at + 1]) > 1 {", "} else if tag == 2 && int_of(row[at + 1]) > 2 {"),
    ("row: bytes after a row are taken", "src/row.cho", "    return at == len(row);", "    return at <= len(row);"),
    ("row: the plain key separates with a comma alone", "src/row.cho", "        if k > 1 {\n            w = puts(out, w, \", \");", "        if k > 1 {\n            w = puts(out, w, \",\");"),
    ("row: true and false are swapped", "src/row.cho", "        if int_of(row[vat + 1]) == 1 {\n            return puts(out, at, \"true\");", "        if int_of(row[vat + 1]) == 0 {\n            return puts(out, at, \"true\");"),
    ("row: bytes after a definition are taken", "src/row.cho", "    if at != len(def) || seen != keys * (keys + 1) / 2 {", "    if seen != keys * (keys + 1) / 2 {"),
    ("row: key places need not be 1 to k", "src/row.cho", "    if at != len(def) || seen != keys * (keys + 1) / 2 {", "    if at != len(def) {"),
    ("row: a value of another type than its column is taken", "src/row.cho", "        } else if tag != storage_tag(col_type(def, i)) {\n            return false;", "        } else if false {\n            return false;"),
    ("row: a smallint column takes any integer", "src/row.cho", "        return v >= 0 - 32768 && v <= 32767;", "        return true;"),
    ("row: an integer column takes any integer", "src/row.cho", "        return v >= 0 - 2147483648 && v <= 2147483647;", "        return true;"),
]


def run_row(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in ROW if not only or only in m[0]]
    survivors = []
    for n, (label, rel, old, new) in enumerate(table):
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
            exe = work / "rowcheck"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/rowcheck.cho")] + [str(work / "src" / x) for x in ("row.cho", "state.cho", "commit.cho", "build.cho")] + ["-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            r = subprocess.run([sys.executable, str(ROOT / "tests/row_check.py"), str(exe)], capture_output=True, text=True, timeout=900, env=dict(os.environ, E2E_DB="cdb_rowmut"))
            if r.returncode == 0:
                print("SURVIVED %-46s every row check passes" % label)
                survivors.append(label)
            else:
                first = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d check(s), e.g. %s" % (label, len(first), first[0][5:70] if first else (r.stderr.strip()[:60] or "a crash")))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


# ---- the engine's expression evaluator (src/eval.cho), judged by tests/eval_check.py against PostgreSQL
EVAL = [
    ("eval: less than is less or equal", "src/eval.cho", "op == 2 && c < 0", "op == 2 && c <= 0"),
    ("eval: OR stops on false", "src/eval.cho", "            if op == 7 {\n                stop = 1;", "            if op == 7 {\n                stop = 0;"),
    ("eval: division is the remainder", "src/eval.cho", "            r = x / y;", "            r = x % y;"),
    ("eval: division by zero is out of range", "src/eval.cho", "        if y == 0 {\n            return (2, 0);", "        if y == 0 {\n            return (3, 0);"),
    ("eval: a result need not fit its type", "src/eval.cho", "    if !row.int_fits(ty, r) {\n        return (3, 0);\n    }\n    return (0, r);", "    return (0, r);"),
    ("eval: the narrower integer type wins", "src/eval.cho", "    if width(a) >= width(b) {", "    if width(a) <= width(b) {"),
    ("eval: an underscore matches one byte", "src/eval.cho", "                s = s + char_len(int_of(ar[sa + s]));\n                p = p + 1;", "                s = s + 1;\n                p = p + 1;"),
    ("eval: NOT ILIKE is case sensitive", "src/eval.cho", "op == 13 || op == 15", "op == 13"),
    ("eval: NOT LIKE is LIKE", "src/eval.cho", "                } else if op >= 14 {\n                    bool3(ws, out, 0, 1 - m, all_const);", "                } else if op >= 14 {\n                    bool3(ws, out, 0, m, all_const);"),
    ("eval: 'yes' is not a boolean", "src/eval.cho", 'name_is(ar, at, n, "yes")', 'name_is(ar, at, n, "yess")'),
    ("eval: an integer literal is always an integer", "src/eval.cho", "            var ty = 5;\n            if !row.int_fits(5, v) {\n                ty = 1;", "            var ty = 5;\n            if !row.int_fits(5, v) {\n                ty = 5;"),
    ("eval: a constant null is not folded", "src/eval.cho", "    return ws[x + 1] == 1 && ws[x + 4] == 1 || ws[y + 1] == 1 && ws[y + 4] == 1;", "    return false;"),
    ("eval: the rightmost type error is the one reported", "src/eval.cho", "                if r < 0 {\n                    wrong = r;", "                if r < 0 && wrong == 0 {\n                    wrong = r;"),
    ("eval: IN ignores NOT", "src/eval.cho", "            bool3(ws, out, 0, 1 - negated, all_const);", "            bool3(ws, out, 0, 1, all_const);"),
    ("eval: IN with a null and no match is false", "src/eval.cho", "        } else if seen_null {\n            bool3(ws, out, 1, 0, all_const);", "        } else if seen_null {\n            bool3(ws, out, 0, negated, all_const);"),
    ("eval: CASE takes the first condition that is false", "src/eval.cho", "            } else if ws[cv + 1] == 0 && ws[cv + 2] == 1 {\n                chosen = top - 6 * (2 * b + 1);", "            } else if ws[cv + 1] == 0 && ws[cv + 2] == 0 {\n                chosen = top - 6 * (2 * b + 1);"),
    ("eval: IS NULL is IS NOT NULL", "src/eval.cho", "                if ws[x + 1] == 1 == (op == 2) {", "                if ws[x + 1] == 1 == (op == 3) {"),
    ("eval: || writes the second text over the first", "src/eval.cho", "                    ar[start + xn + k] = ar[ya + k];", "                    ar[start + k] = ar[ya + k];"),
    ("eval: only a positive integer is true", "src/eval.cho", "        if a != 0 {\n            t = 1;", "        if a > 0 {\n            t = 1;"),
    ("eval: text after a number is ignored", "src/eval.cho", "    if i != end || digits == 0 {", "    if digits == 0 {"),
    ("eval: a minus before a literal makes a bigint", "src/eval.cho", "            var t = 5;\n            if !row.int_fits(5, v) {\n                t = 1;\n            }\n            set(ws, out, t, 0, v, 0, 1);", "            var t = 1;\n            set(ws, out, t, 0, v, 0, 1);"),
    ("eval: a condition's type is checked after the operand that follows it", "src/eval.cho", "                    } else if m % stride == 0 && m / stride < conds && ws[v] != 2 && ws[v] != 0 {\n                        wrong = mismatch();", "                    } else if false {\n                        wrong = mismatch();"),
    ("eval: AND with a constant false still looks at the other side", "src/eval.cho", "            if ws[y + 4] == 1 && ys == 0 && yv == stop {", "            if false {"),
    ("eval: subtraction adds", "src/eval.cho", "            yy = 0 - y;", "            yy = y;"),
]


def run_eval(cancho):
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in EVAL if not only or only in m[0]]
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
            exe = work / "evalcheck"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/evalcheck.cho")] + [str(work / "src" / x) for x in ("lex.cho", "parse.cho", "stmt.cho", "lower.cho", "state.cho", "commit.cho", "build.cho", "row.cho", "eval.cho")] + ["-o", str(exe)],
                               capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]))
                survivors.append(label)
                continue
            # the two runs of scripts/check.sh: a mutant is killed by either
            rc, out = 0, ""
            for seed in ("1", "2"):
                try:
                    r = subprocess.run([sys.executable, str(ROOT / "tests/eval_check.py"), str(exe), "4000", seed], capture_output=True, text=True, timeout=900, env=dict(os.environ, E2E_DB="cdb_evalmut"))
                    rc, out = r.returncode, r.stdout
                except subprocess.TimeoutExpired:
                    rc, out = 1, "FAIL timed out"
                if rc != 0:
                    break
            if rc == 0:
                print("SURVIVED %-46s every expression agrees" % label)
                survivors.append(label)
            else:
                first = [l for l in out.splitlines() if l.startswith("FAIL")]
                print("killed   %-46s by %d expression(s), e.g. %s" % (label, len(first), first[0][5:70] if first else "a crash"))
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


# The engine's statements (src/exec.cho, src/execw.cho, src/tables.cho, and the assignment of src/eval.cho), judged by tests/engine_check.py: the random history against PostgreSQL, the fixed statements that
# must be answered, and the page file after a delete and a drop.
ENGINE = [
    ('answer: a bigint is announced as an integer', 'src/answer.cho',
     '    if ty == row.t_int() {\n        return 20;',
     '    if ty == row.t_int() {\n        return 23;'),
    ('answer: true is sent as f', 'src/answer.cho',
     "            out[oat] = byte_of('t');",
     "            out[oat] = byte_of('f');"),
    ('answer: a negative number is sent without its sign', 'src/answer.cho',
     "        if v < 0 {\n            out[oat] = byte_of('-');\n            n = 1;\n        }",
     ''),
    ('answer: a number is sent as its last digit', 'src/answer.cho',
     "            out[oat + n] = byte_of('0' - w / div % 10);\n            n = n + 1;\n            div = div / 10;",
     "            out[oat + n] = byte_of('0' - w / div % 10);\n            n = n + 1;\n            div = 0;"),
    ('answer: the value after a text is read from inside it', 'src/answer.cho',
     '    return at + 3 + commit.be(rows, at + 1, 2);',
     '    return at + 3;'),
    ("answer: INSERT's tag has no zero", 'src/answer.cho',
     'at = word(out, 0, "INSERT 0 ");',
     'at = word(out, 0, "INSERT ");'),
    ('answer: a tag counts only its last digit', 'src/answer.cho',
     "            out[at] = byte_of('0' + n / div % 10);\n            at = at + 1;\n            div = div / 10;",
     "            out[at] = byte_of('0' + n / div % 10);\n            at = at + 1;\n            div = 0;"),
    ("answer: DROP TABLE's tag is CREATE TABLE's", 'src/answer.cho',
     'at = word(out, 0, "DROP TABLE");',
     'at = word(out, 0, "CREATE TABLE");'),
    ('history: a key written twice in a transaction keeps its second-to-last value', 'src/exec.cho',
     '    if g >= 0 {\n        return root;\n    }\n    if g != btree.not_found() {\n        return tree_err(g);\n    }\n    let o = btree.get(',
     '    if false {\n        return root;\n    }\n    if g != btree.not_found() && g < 0 {\n        return tree_err(g);\n    }\n    let o = btree.get('),
    ('history: in a transaction of several statements what is known is still not looked up', 'src/exec.cho',
     '    if !w.once {\n        return remember(p, w, root, k, kn);\n    }',
     ''),
    ('in place: the last byte of the entries after is not moved', 'src/btree.cho',
     '    if newlen > oldlen {\n        var m = end - 1;',
     '    if newlen > oldlen {\n        var m = end - 2;'),
    ('in place: a new entry is not counted', 'src/btree.cho',
     '    if !found {\n        build.put_be(pg, o + 1, count + 1, 2);',
     '    if false {\n        build.put_be(pg, o + 1, count + 1, 2);'),
    ('in place: an entry that does not fit is written past the page', 'src/btree.cho',
     '    if end - oldlen + newlen > o + 4096 {',
     '    if end - oldlen + newlen > o + 8192 {'),
    ('in place: a removed entry is still counted', 'src/btree.cho',
     '    build.put_be(pg, o + 1, count - 1, 2);',
     '    build.put_be(pg, o + 1, count, 2);'),
    ('in place: a shorter value leaves the entries after where they were', 'src/btree.cho',
     '    } else if newlen < oldlen {\n        var m = at + oldlen;\n        while m < end {',
     '    } else if newlen < oldlen {\n        var m = end;\n        while m < end {'),
    ('history: a known old value is recorded as nothing', 'src/exec.cho',
     '    if has_old {\n        contents(w.uval)[0] = byte_of(1);\n        n = copy(old, 0, len(old), contents(w.uval), 1);\n    }',
     ''),
    ('history: an inserted row is recorded as having been there', 'src/execw.cho',
     'contents(w.cur)[0..rl], contents(w.cur)[0..0], 0);',
     'contents(w.cur)[0..rl], contents(w.cur)[0..0], 1);'),
    ('cache: a commit does not write what is only in memory', 'src/pager.cho',
     '    let fr = flush(p);\n    if fr < 0 {\n        return fr;\n    }',
     '    let fr = 0;\n    if fr < 0 {\n        return fr;\n    }'),
    ('scan: a leaf is read one entry past its end', 'src/btree.cho',
     '    if st[0] == 1 && st[3] == root && st[2] < st[4] {',
     '    if st[0] == 1 && st[3] == root && st[2] <= st[4] {'),
    ('scan: the leaf kept is not moved along', 'src/btree.cho',
     '        st[1] = at + 3 + kl + vl;\n        st[2] = st[2] + 1;\n        return kl * 1024 + vl;',
     '        st[2] = st[2] + 1;\n        return kl * 1024 + vl;'),
    ('tree: the path walked in memory is not noted', 'src/btree.cho',
     '            setp(sc, d, id, ix0);\n',
     ''),
    ("names: an expression's column is named after nothing", 'src/lower.cho',
     '    return put_text(out, at, "?column?");',
     '    return put_text(out, at, "column");'),
    ('names: a CASE is named after its first branch', 'src/lower.cho',
     '            if nodes[6 * x + 5] == 1 && nodes[6 * x + 3] > 0 {\n                x = kids[nodes[6 * x + 2] + nodes[6 * x + 3] - 1];\n            } else {\n                going = false;\n            }\n        } else {\n            going = false;\n        }\n    }\n    if weak == 1 {\n        return put_text(out, at, cast_name(code));',
     '            if nodes[6 * x + 5] == 1 && nodes[6 * x + 3] > 0 {\n                x = kids[nodes[6 * x + 2]];\n            } else {\n                going = false;\n            }\n        } else {\n            going = false;\n        }\n    }\n    if weak == 1 {\n        return put_text(out, at, cast_name(code));'),
    ('names: a cast is named case', 'src/lower.cho',
     '    if weak == 1 {\n        return put_text(out, at, cast_name(code));',
     '    if weak == 3 {\n        return put_text(out, at, cast_name(code));'),
    ('names: an alias is ignored', 'src/lower.cho',
     '            if nodes[6 * it + 1] >= 0 {\n                let n = name_text(sql, toks, nodes[6 * it + 1], out, at + 2);',
     '            if false {\n                let n = name_text(sql, toks, nodes[6 * it + 1], out, at + 2);'),
    ('names: a qualified column is named after its table', 'src/lower.cho',
     '            if kind == parse.n_col() && nodes[6 * x + 4] >= 0 {\n                tok = nodes[6 * x + 4];\n            }\n            let n = name_text(sql, toks, tok, out, at);',
     '            let n = name_text(sql, toks, tok, out, at);'),
    ('names: a star names only its first column', 'src/lower.cho',
     '                    c = c + 1;\n                    ca = nth_column(schema, line, c, sc);\n                }\n                e = e + 1;\n            }\n        } else {\n            if at + 2 > len(out) {',
     '                    c = c + 1;\n                    ca = 0 - 1;\n                }\n                e = e + 1;\n            }\n        } else {\n            if at + 2 > len(out) {'),
    ('alter: the rows there do not get the default', 'src/execw.cho',
     '            if has_default {\n                if ra + dlen2 > exec.max_stored_row() {',
     '            if false {\n                if ra + dlen2 > exec.max_stored_row() {'),
    ('alter: a column that takes no null is added to rows with none to give', 'src/execw.cho',
     '        } else if nulls && marks % 2 == 1 {\n            exec.note(w, exec.e_not_null());\n            more = false;',
     '        } else if false {\n            exec.note(w, exec.e_not_null());\n            more = false;'),
    ('alter: a default of null satisfies not null', 'src/execw.cho',
     '        if int_of(contents(w.tmp)[xl + 1]) == 0 {\n            nulls = true;\n        }',
     ''),
    ('alter: the definition is not changed', 'src/execw.cho',
     '    let ekl = tables.entry_key(e[4..4 + nl], contents(w.key));\n    let nw = exec.put_key(p, w, nroot, contents(w.key), ekl, contents(w.ent)[0..total]);\n    if nw < 0 {\n        return nw;\n    }\n    w.root = nw;',
     '    w.root = nroot;'),
    ('alter: a second key is taken', 'src/execw.cho',
     '    let da = column_defs(w, sql, toks, nodes, kids, stmt, n0, n0 + 1, 6 + dl, xl, 1, 0 - 1);',
     '    let da = column_defs(w, sql, toks, nodes, kids, stmt, n0, n0 + 1, 6 + dl, xl, 0, 0 - 1);'),
    ("alter: the new column's name is not compared with the old ones", 'src/execw.cho',
     '        while k < c {\n            let ol = commit.be(contents(w.ent), oa + 2, 2);',
     '        while k < c - c0 {\n            let ol = commit.be(contents(w.ent), oa + 2, 2);'),
    ('index: a name that is taken is taken again', 'src/execw.cho',
     '    let g = btree.get(p, contents(w.sc), root, contents(w.key2)[0..kl], contents(w.cur));\n    if g >= 0 {\n        there = true;',
     '    let g = btree.get(p, contents(w.sc), root, contents(w.key2)[0..kl], contents(w.cur));\n    if false {\n        there = true;'),
    ("index: a table's name is free for an index", 'src/execw.cho',
     '    if gt >= 0 {\n        there = true;',
     '    if false {\n        there = true;'),
    ("index: an index's name is free for a table", 'src/execw.cho',
     '    if gi >= 0 {\n        exec.note(w, exec.e_table_exists());',
     '    if false {\n        exec.note(w, exec.e_table_exists());'),
    ('index: a column that is not there is indexed', 'src/execw.cho',
     '        if !found {\n            exec.note(w, exec.e_no_column());',
     '        if false {\n            exec.note(w, exec.e_no_column());'),
    ('index: a unique one is taken as any other', 'src/execw.cho',
     '    if iflags % 2 == 1 {\n        return exec.unsupported();\n    }\n',
     ''),
    ("index: a dropped table's indexes stay", 'src/execw.cho',
     '                if exec.same(contents(w.cur), 0, nv, e, 4, nl) {\n                    let nw = exec.del_key(p, w, nroot, contents(w.key2), nk);',
     '                if false {\n                    let nw = exec.del_key(p, w, nroot, contents(w.key2), nk);'),
    ('index: a dropped table takes every index with it', 'src/execw.cho',
     '                if exec.same(contents(w.cur), 0, nv, e, 4, nl) {\n                    let nw = exec.del_key(p, w, nroot, contents(w.key2), nk);',
     '                if true {\n                    let nw = exec.del_key(p, w, nroot, contents(w.key2), nk);'),
    ('index: the lowering is not told of it', 'src/tables.cho',
     '            } else if int_of(key2[4]) == 1 {\n                // an index (`index_key`): a line `index NAME on TABLE`\n                if at + 6 + (nk - 5) + 4 + nv + 1 > len(out) {\n                    return btree.err_big();\n                }\n                at = lit(out, at, "index ");',
     '            } else if int_of(key2[4]) == 1 {\n                // an index (`index_key`): a line `index NAME on TABLE`\n                if at + 6 + (nk - 5) + 4 + nv + 1 > len(out) {\n                    return btree.err_big();\n                }\n                at = lit(out, at, "indez ");'),
    ('pages: a page a root names is written in place', 'src/btree.cho',
     '    if old < 1 || !pager.is_fresh(p, old) {\n        id = pager.alloc(p);\n    }',
     '    if old < 1 {\n        id = pager.alloc(p);\n    }'),
    ('pages: a page handed out before the statement is still its own', 'src/pager.cho',
     '        contents(p.fresh)[contents(p.flist)[i]] = byte_of(0);',
     '        contents(p.fresh)[contents(p.flist)[i]] = byte_of(1);'),
    ('pages: a page above the leaf is written where the leaf was', 'src/btree.cho',
     '            emit_at(sc, w2(), 2, ncount, w1(), total);\n            let id = new_page(p, sc, w2(), was(sc, level));',
     '            emit_at(sc, w2(), 2, ncount, w1(), total);\n            let id = new_page(p, sc, w2(), was(sc, d));'),
    ('pages: the right half of a split leaf is written where the leaf was', 'src/btree.cho',
     '    let rid = new_page(p, sc, w4(), 0);',
     '    let rid = new_page(p, sc, w4(), was(sc, d));'),
    ('history: the value before is not kept', 'src/exec.cho',
     '        contents(w.uval)[0] = byte_of(1);\n        n = 1 + o;',
     '        contents(w.uval)[0] = byte_of(1);\n        n = 1;'),
    ('history: a key that was not there is recorded as there', 'src/exec.cho',
     '    } else if o == btree.not_found() {\n        contents(w.uval)[0] = byte_of(0);',
     '    } else if o == btree.not_found() {\n        contents(w.uval)[0] = byte_of(1);'),
    ('history: AS OF t undoes t as well', 'src/exec.cho',
     '            if 9223372036854775807 - commit.be(contents(w.key2), 4, 8) <= t {',
     '            if 9223372036854775807 - commit.be(contents(w.key2), 4, 8) < t {'),
    ('history: AS OF puts back the entry, not the value', 'src/exec.cho',
     '                    nw = btree.put(p, contents(w.sc), out, contents(w.key2)[12..nk], contents(w.cur)[1..nv]);',
     '                    nw = btree.put(p, contents(w.sc), out, contents(w.key2)[12..nk], contents(w.cur)[0..nv]);'),
    ('history: AS OF removes nothing that was not there', 'src/exec.cho',
     '                if int_of(contents(w.cur)[0]) == 0 {\n                    nw = btree.del(p, contents(w.sc), out, contents(w.key2)[12..nk]);\n                    if nw == btree.not_found() {\n                        nw = out;\n                    }',
     '                if int_of(contents(w.cur)[0]) == 0 {\n                    nw = out;\n                    if nw == btree.not_found() {\n                        nw = out;\n                    }'),
    ('history: entries are kept oldest first', 'src/exec.cho',
     '    build.put_be(out, 4, 9223372036854775807 - txn, 8);',
     '    build.put_be(out, 4, txn, 8);'),
    ("history: a transaction's number is given twice", 'src/exec.cho',
     '    build.put_be(contents(w.uval), 0, t, 8);',
     '    build.put_be(contents(w.uval), 0, t - 1, 8);'),
    ('history: a value set leaves no entry', 'src/exec.cho',
     '    let r = remember(p, w, root, k, kn);\n    if r < 0 {\n        return r;\n    }\n    let nw = btree.put(',
     '    let r = root;\n    if r < 0 {\n        return r;\n    }\n    let nw = btree.put('),
    ('history: a key removed leaves no entry', 'src/exec.cho',
     '    let r = remember(p, w, root, k, kn);\n    if r < 0 {\n        return r;\n    }\n    let nw = btree.del(',
     '    let r = root;\n    if r < 0 {\n        return r;\n    }\n    let nw = btree.del('),
    ("history: a dropped table's entry is not kept", 'src/execw.cho',
     '    let rm = exec.remember(p, w, nroot, contents(w.key), ekl);',
     '    let rm = nroot;'),
    ("history: a new table's entry is not kept", 'src/execw.cho',
     '    let r2 = exec.remember(p, w, r1, contents(w.key), ekl);',
     '    let r2 = r1;'),
    ('erase: the row stays', 'src/execw.cho',
     '    if d >= 0 {\n        nroot = d;\n        w.count = 1;',
     '    if d >= 0 {\n        w.count = 1;'),
    ('erase: the past stays', 'src/execw.cho',
     '            if exec.same(contents(w.key2), 12, nk - 12, contents(w.tmp), 65536, 4 + kn) {',
     '            if false {'),
    ("erase: every key's past goes", 'src/execw.cho',
     '            if exec.same(contents(w.key2), 12, nk - 12, contents(w.tmp), 65536, 4 + kn) {',
     '            if true {'),
    ('erase: a condition beside the key is ignored', 'src/execw.cho',
     '    if w.nconj != 1 || kn < 0 || w.hin != kn ||',
     '    if kn < 0 || w.hin != kn ||'),
    ('order by: two minus signs before a constant are an expression', 'src/execs.cho',
     '    return n > 0 && int_of(e[p]) == 1;',
     '    return n == 1 && int_of(e[p]) == 1;'),
    ('order by: a constant under a minus is ordered by', 'src/execs.cho',
     '        } else if minus_constant(e, at) {\n',
     '        } else if false {\n'),
    ('grouped: a constant under a minus is grouped by', 'src/execs.cho',
     '        } else if minus_constant(e, ga) {\n',
     '        } else if false {\n'),
    ('join: arithmetic counted as unable to raise', 'src/execs.cho',
     '        let ok = tag == 0 || tag == 1 || tag == 8 || tag == 5 && int_of(e[at + 1]) <= 7 || tag == 7 && int_of(e[at + 1]) != 1;\n        let n = eval.node_size(e, at);',
     '        let ok = tag == 0 || tag == 1 || tag == 8 || tag == 5 || tag == 7 && int_of(e[at + 1]) != 1;\n        let n = eval.node_size(e, at);'),
    ('join: a WHERE that can raise is taken', 'src/execs.cho',
     '        if !quiet(e, wpos, end) {\n            return exec.unsupported();\n        }',
     '        if false {\n            return exec.unsupported();\n        }'),
    ('join: an ON that can raise is taken', 'src/execs.cho',
     '            if !quiet(e, onpos, end) {\n                return exec.unsupported();\n            }',
     '            if false {\n                return exec.unsupported();\n            }'),
    ('join: a left join with no match gives no row', 'src/execs.cho',
     '            } else if contents(w.pos)[t + 4] == 2 && contents(w.pos)[t + 6] == 0 {',
     '            } else if false {'),
    ('join: an inner join with no match gives a row of nulls', 'src/execs.cho',
     '            } else if contents(w.pos)[t + 4] == 2 && contents(w.pos)[t + 6] == 0 {',
     '            } else if contents(w.pos)[t + 6] == 0 {'),
    ('join: a left join gives a row of nulls beside its matches', 'src/execs.cho',
     '                if bound {\n                    contents(w.pos)[t + 6] = 1;\n                }',
     ''),
    ('join: the ON is not asked', 'src/execs.cho',
     '                    bound = contents(w.ws)[b + 1] == 0 && contents(w.ws)[b + 2] == 1;',
     '                    bound = true;'),
    ('join: an ON that is null joins', 'src/execs.cho',
     '                    bound = contents(w.ws)[b + 1] == 0 && contents(w.ws)[b + 2] == 1;',
     '                    bound = contents(w.ws)[b + 1] != 0 || contents(w.ws)[b + 2] == 1;'),
    ('join: a table is read once, not once for each row before it', 'src/execs.cho',
     '                level = level + 1;\n                contents(w.pos)[exec.p_tab() + 8 * level + 3] = 0;',
     '                level = level + 1;'),
    ("join: every table's rows are the second table's", 'src/execs.cho',
     '        contents(w.pos)[t + 1] = n;\n        commit_key(w, tid);',
     '        contents(w.pos)[t + 1] = 0;\n        commit_key(w, tid);'),
    ('join: grouping by a column frees no column', 'src/execs.cho',
     '        if int_of(e[inner]) == 0 && (inner != ga || w.ntab > 1) {',
     '        if int_of(e[inner]) == 0 && inner != ga {'),
    ('join: a table joined to itself is taken', 'src/exec.cho',
     '    if tid == w.tid {\n        return unsupported();\n    }',
     '    if false {\n        return unsupported();\n    }'),
    ("join: the key's bounds are taken from any table's column", 'src/exec.cho',
     "    if w.ntab != 1 {\n        // under a join a column of that name may be another table's\n        return 0;\n    }",
     ''),
    ('grouped: the min of text by its first bytes', 'src/execs.cho',
     '        let d = int_of(x[xa + 3 + i]) - int_of(y[ya + 3 + i]);\n        if d != 0 {\n            return d;\n        }\n        i = i + 1;\n    }\n    return xn - yn;',
     '        let d = int_of(x[xa + 3 + i]) - int_of(y[ya + 3 + i]);\n        if d != 0 {\n            return d;\n        }\n        i = i + 1;\n    }\n    return 0;'),
    ("grouped: a literal item's type is unknown", 'src/execs.cho',
     '        } else if i < ni {\n            var ty = contents(w.ws)[b];\n            if ty == 0 {\n                ty = 3;\n            }',
     '        } else if i < ni {\n            var ty = contents(w.ws)[b];'),
    ('grouped: sum is min', 'src/execs.cho',
     '    if exec.same(e, at + 3, nl, "sum", 0, 3) {\n        return 2;',
     '    if exec.same(e, at + 3, nl, "sum", 0, 3) {\n        return 3;'),
    ('grouped: min and max the other way', 'src/execs.cho',
     '            take = kind == 3 && c < 0 || kind == 4 && c > 0;',
     '            take = kind == 3 && c > 0 || kind == 4 && c < 0;'),
    ('grouped: nulls are counted', 'src/execs.cho',
     '    if int_of(contents(w.chg)[off]) == 0 {\n        return 0;\n    }\n    let kind = contents(w.pos)[ab + 2];',
     '    let kind = contents(w.pos)[ab + 2];'),
    ('grouped: what is below zero is not summed', 'src/execs.cho',
     '        } else if v < 0 {\n            if contents(w.pos)[ab + 7]',
     '        } else if false {\n            if contents(w.pos)[ab + 7]'),
    ('grouped: the sum of no rows is 0', 'src/execs.cho',
     '            } else if real && kind == 2 && cnt > 0 {',
     '            } else if real && kind == 2 {'),
    ('grouped: the min of no rows is what was left there', 'src/execs.cho',
     '            } else if real && cnt > 0 {',
     '            } else if real {'),
    ('grouped: a sum is an integer', 'src/execs.cho',
     '                if kind == 2 && (ty == 5 || ty == 6) {\n                    contents(w.pos)[ab + 4] = 1;',
     '                if kind == 2 && (ty == 5 || ty == 6) {\n                    contents(w.pos)[ab + 4] = 5;'),
    ('grouped: min has the type of a count', 'src/execs.cho',
     '                    contents(w.pos)[ab + 4] = ty;',
     '                    contents(w.pos)[ab + 4] = 1;'),
    ('grouped: a sum of bigint is answered', 'src/execs.cho',
     '                if ty == 0 || kind == 2 && ty == 1 {',
     '                if ty == 0 {'),
    ('grouped: no aggregate for the type is 42804', 'src/execs.cho',
     '                    // no such aggregate for this type\n                    exec.note(w, 5);',
     '                    // no such aggregate for this type\n                    exec.note(w, 6);'),
    ('grouped: a column that is not grouped is read', 'src/execs.cho',
     '        exec.note(w, exec.e_grouping());',
     '        exec.note(w, 0);'),
    ('grouped: grouping by the key frees no column', 'src/execs.cho',
     '        if keyed {\n            return exec.unsupported();\n        }',
     '        if false {\n            return exec.unsupported();\n        }'),
    ('grouped: a cast in GROUP BY is not seen through', 'src/execs.cho',
     '        if int_of(e[inner]) == 0 && (inner != ga || w.ntab > 1) {',
     '        if int_of(e[inner]) == 0 && w.ntab > 1 {'),
    ('grouped: an error is certain beside a HAVING without aggregates', 'src/execs.cho',
     '        if bounded || hfree {',
     '        if bounded {'),
    ('grouped: an error is certain under DISTINCT', 'src/execs.cho',
     '    // as in `select`: a DISTINCT may be answered from the first row\n    var bounded = distinct || int_of(e[at]) == 1;',
     '    // as in `select`: a DISTINCT may be answered from the first row\n    var bounded = int_of(e[at]) == 1;'),
    ('select: an error is certain under DISTINCT', 'src/execs.cho',
     '    // a DISTINCT over items that cannot differ is a LIMIT 1 to PostgreSQL: it stops at the first row\n    var bounded = distinct || int_of(e[at]) == 1;',
     '    // a DISTINCT over items that cannot differ is a LIMIT 1 to PostgreSQL: it stops at the first row\n    var bounded = int_of(e[at]) == 1;'),
    ('grouped: GROUP BY 2 is GROUP BY 1', 'src/execs.cho',
     '            ga = contents(w.pos)[exec.p_item() + place - 1];\n            ge = contents(w.pos)[exec.p_iend() + place - 1];',
     '            ga = contents(w.pos)[exec.p_item()];\n            ge = contents(w.pos)[exec.p_iend()];'),
    ('grouped: HAVING lets every group through', 'src/execs.cho',
     '        if contents(w.ws)[b + 1] != 0 || contents(w.ws)[b + 2] != 1 {\n            return n;\n        }\n    }\n    if n >= exec.max_rows() {',
     '    }\n    if n >= exec.max_rows() {'),
    ('grouped: an error in HAVING is a group left out', 'src/execs.cho',
     '        if contents(w.ws)[b + 1] == 2 {\n            exec.note(w, contents(w.ws)[b + 2] - 1);\n            return n;\n        }',
     '        if contents(w.ws)[b + 1] == 2 {\n            return n;\n        }'),
    ('grouped: a HAVING that is no boolean is 42883', 'src/execs.cho',
     '        } else if contents(w.ws)[b] != 2 {\n            exec.note(w, 6);\n        } else if folded_away(w, e, hpos) {',
     '        } else if contents(w.ws)[b] != 2 {\n            exec.note(w, 5);\n        } else if folded_away(w, e, hpos) {'),
    ('grouped: every row is a group', 'src/execs.cho',
     '            while j < m && (j == i || order(contents(w.chg), contents(w.pos), first, contents(w.idx2)[j], 1, ng, 0) == 0) {',
     '            while j < m && j == i {'),
    ('grouped: the rows are not sorted by group', 'src/execs.cho',
     '        sort_groups(w, m, ng);\n',
     ''),
    ("grouped: the aggregates read the group's values", 'src/execs.cho',
     '                var off = nth(contents(w.chg), contents(w.idx2)[j], ng);',
     '                var off = nth(contents(w.chg), contents(w.idx2)[j], 0);'),
    ("grouped: every GROUP BY expression has the first one's value", 'src/execs.cho',
     '                let off = nth(contents(w.chg), rec, which);',
     '                let off = nth(contents(w.chg), rec, 0);'),
    ('grouped: count(*) counts nothing', 'src/execs.cho',
     '                        contents(w.chg)[fill] = byte_of(2);\n                        contents(w.chg)[fill + 1] = byte_of(1);',
     '                        contents(w.chg)[fill] = byte_of(0);\n                        contents(w.chg)[fill + 1] = byte_of(1);'),
    ('grouped: the slots stay on while the rows are read', 'src/execs.cho',
     '    contents(w.cx)[eval.slots_at()] = 0;\n    var at = lat;',
     '    var at = lat;'),
    ('grouped: an error in an item is a group left out', 'src/execs.cho',
     '        if contents(w.ws)[b + 1] == 2 {\n            exec.note(w, contents(w.ws)[b + 2] - 1);\n            bad = true;\n        } else if !bad {\n            fill = exec.enc(contents(w.rows), fill, contents(w.ws), b, contents(w.ar));',
     '        if contents(w.ws)[b + 1] == 2 {\n            bad = true;\n        } else if !bad {\n            fill = exec.enc(contents(w.rows), fill, contents(w.ws), b, contents(w.ar));'),
    ("grouped: an error in a row's argument is a row left out", 'src/execs.cho',
     '                        if contents(w.ws)[b + 1] == 2 {\n                            exec.note(w, contents(w.ws)[b + 2] - 1);\n                            bad = true;\n                        } else if !bad {\n                            fill = exec.enc(contents(w.chg), fill,',
     '                        if contents(w.ws)[b + 1] == 2 {\n                            bad = true;\n                        } else if !bad {\n                            fill = exec.enc(contents(w.chg), fill,'),
    ('grouped: a query with only a HAVING is not grouped', 'src/execs.cho',
     '    if ng > 0 || hpos != 0 || calls {',
     '    if ng > 0 || calls {'),
    ('slots: what is inside a given expression is computed', 'src/eval.cho',
     '        if p > cx[s] && p < cx[s + 1] {\n            return 0 - 2;',
     '        if p > cx[s] && p < cx[s + 1] {\n            return 0 - 1;'),
    ('slots: a given value is not used', 'src/eval.cho',
     '        if cx[s] == p {\n            return j;\n        }',
     '        if cx[s] == p {\n            return 0 - 1;\n        }'),
    ('slots: a given value is a constant', 'src/eval.cho',
     '            set(ws, base + 6 * sp, cx[s + 2], cx[s + 3], cx[s + 4], cx[s + 5], 0);',
     '            set(ws, base + 6 * sp, cx[s + 2], cx[s + 3], cx[s + 4], cx[s + 5], 1);'),
    ('bounds: rows skipped although a condition can raise', 'src/exec.cho',
     '            if !quiet {\n                return 0;\n            }',
     '            if false {\n                return 0;\n            }'),
    ('bounds: arithmetic counted as unable to raise', 'src/exec.cho',
     'tag == 5 && int_of(e[p + 1]) <= 7 ||',
     'tag == 5 ||'),
    ('bounds: the first key is left out', 'src/exec.cho',
     '        w.klen = 4 + n;\n        w.fresh = true;',
     '        w.klen = 4 + n;\n        w.fresh = false;'),
    ('bounds: the last key is left out', 'src/exec.cho',
     '    return kn > hn;\n}',
     '    return kn >= hn;\n}'),
    ('bounds: constant < key read as key < constant', 'src/exec.cho',
     '                if op == 2 || op == 3 {\n                    op = op + 2;',
     '                if op == 2 || op == 3 {\n                    op = op + 0;'),
    ('bounds: constant > key read as key > constant', 'src/exec.cho',
     '                } else if op == 4 || op == 5 {\n                    op = op - 2;',
     '                } else if op == 4 || op == 5 {\n                    op = op - 0;'),
    ('bounds: > sets the upper bound', 'src/exec.cho',
     '            if n >= 0 && (op == 0 || op == 2 || op == 3) {',
     '            if n >= 0 && (op == 0 || op == 4 || op == 5) {'),
    ('bounds: < sets the lower bound', 'src/exec.cho',
     '            if n >= 0 && (op == 0 || op == 4 || op == 5) {',
     '            if n >= 0 && (op == 0 || op == 2 || op == 3) {'),
    ('bounds: an integer key without its sign flipped', 'src/exec.cho',
     '                    contents(w.nrow)[0] = byte_of((int_of(contents(w.nrow)[0]) + 128) % 256);',
     '                    contents(w.nrow)[0] = byte_of((int_of(contents(w.nrow)[0]) + 0) % 256);'),
    ('bounds: a text key without its end', 'src/exec.cho',
     '                    contents(w.nrow)[n + 1] = byte_of(0);\n                    n = n + 2;',
     '                    contents(w.nrow)[n + 1] = byte_of(0);\n                    n = n + 0;'),
    ('bounds: any column is the key', 'src/exec.cho',
     '    return same(nm, 0, len(nm), e, at + 5 + tn, cn);',
     '    return true;'),
    ('note: a second code is not seen', 'src/exec.cho',
     '    } else if w.code != code {\n        w.multi = true;',
     '    } else if w.code == code {\n        w.multi = true;'),
    ('verdict: several codes answered as one', 'src/exec.cho',
     '    if w.multi {\n        return ambiguous();',
     '    if false {\n        return ambiguous();'),
    ('where: a false condition passes', 'src/exec.cho',
     '    if st == 0 && a == 1 {\n        return 1;\n    }\n    if w.nconj <= 1 {',
     '    if st == 0 {\n        return 1;\n    }\n    if w.nconj <= 1 {'),
    ('where: an error of the one condition is no error', 'src/exec.cho',
     '        if st == 2 {\n            note(w, a - 1);\n            return 2;\n        }\n        return 0;',
     '        return 0;'),
    ('where: an error beside a false condition is certain', 'src/exec.cho',
     '    if others > 0 {\n        w.orderdep = true;\n        return 0;\n    }',
     '    if false {\n        w.orderdep = true;\n        return 0;\n    }'),
    ('where: a false condition is not another condition', 'src/exec.cho',
     '        } else if sj != 0 || contents(w.ws)[b + 2] != 1 {',
     '        } else if sj != 0 {'),
    ('where: errors beside true conditions are no error', 'src/exec.cho',
     '    if errs % 2 == 1 {\n        note(w, 1);\n    }',
     '    if errs % 2 == 3 {\n        note(w, 1);\n    }'),
    ('select: an error under a limit is certain', 'src/execs.cho',
     '        if bounded {\n',
     '        if false {\n'),
    ('order: nulls first going up', 'src/execs.cho',
     '        if tx == 0 {\n            return 1;\n        }\n        return 0 - 1;',
     '        if tx == 0 {\n            return 0 - 1;\n        }\n        return 1;'),
    ('order: integers the other way', 'src/execs.cho',
     '        if a < b {\n            return 0 - 1;\n        }\n        if a > b {\n            return 1;\n        }',
     '        if a < b {\n            return 1;\n        }\n        if a > b {\n            return 0 - 1;\n        }'),
    ('order: text by its first bytes only', 'src/execs.cho',
     '        let d = int_of(rows[x + 3 + i]) - int_of(rows[y + 3 + i]);\n        if d != 0 {\n            return d;\n        }\n        i = i + 1;\n    }\n    return xn - yn;',
     '        let d = int_of(rows[x + 3 + i]) - int_of(rows[y + 3 + i]);\n        if d != 0 {\n            return d;\n        }\n        i = i + 1;\n    }\n    return 0;'),
    ('order: text as numbers of bytes', 'src/execs.cho',
     '        let d = int_of(rows[x + 3 + i]) - int_of(rows[y + 3 + i]);\n        if d != 0 {\n            return d;\n        }',
     '        let d = int_of(rows[x + 3 + i]) - int_of(rows[y + 3 + i]);\n        if d != 0 && xn == yn {\n            return d;\n        }'),
    ('order: desc ignored', 'src/execs.cho',
     '        if pos[exec.p_odir() + j] == 1 {',
     '        if pos[exec.p_odir() + j] == 2 {'),
    ('order: only the first expression', 'src/execs.cho',
     '        if c != 0 {\n            return c;\n        }\n        j = j + 1;',
     '        if c != 0 || j == 0 {\n            return c;\n        }\n        j = j + 1;'),
    ('distinct: every row kept', 'src/execs.cho',
     '            if kept == 0 || order(contents(w.rows), contents(w.pos), contents(w.idx)[kept - 1], cur, 1, ni, no) != 0 {',
     '            if true {'),
    ('distinct: rows compared on their first item', 'src/execs.cho',
     '        let ea = nth(rows, a, nitems);\n        let eb = nth(rows, b, nitems);',
     '        let ea = nth(rows, a, 1);\n        let eb = nth(rows, b, 1);'),
    ('offset: ignored', 'src/execs.cho',
     '        first = offset;\n',
     '        first = 0;\n'),
    ('limit: 0 is no limit', 'src/execs.cho',
     '    if limit >= 0 && limit < count {',
     '    if limit > 0 && limit < count {'),
    ('limit: a negative one is no error', 'src/execs.cho',
     '    if v < 0 {\n        exec.note(w, which);\n        return end;\n    }',
     '    if v < 0 {\n        return end;\n    }'),
    ('limit: null is zero', 'src/execs.cho',
     '    if st == 1 && (ty == 0 || ty == 1 || ty == 5 || ty == 6) {\n        return end;\n    }',
     '    if st == 1 && (ty == 0 || ty == 1 || ty == 5 || ty == 6) {\n        contents(w.info)[2] = 0;\n        return end;\n    }'),
    ('order by 2 is order by 1', 'src/execs.cho',
     '            slot = place - 1;',
     '            slot = 0;'),
    ("select: a literal's type is unknown", 'src/execs.cho',
     '        } else {\n            var ty = contents(w.ws)[b];\n            if ty == 0 {\n                ty = 3;\n            }\n            contents(w.pos)[exec.p_itype() + i] = ty;',
     '        } else {\n            var ty = contents(w.ws)[b];\n            contents(w.pos)[exec.p_itype() + i] = ty;'),
    ('select: an error in a row is no error', 'src/execs.cho',
     '                    if contents(w.ws)[b + 1] == 2 {\n                        exec.note(w, contents(w.ws)[b + 2] - 1);\n                        bad = true;',
     '                    if contents(w.ws)[b + 1] == 2 {\n                        bad = true;'),
    ('an error of types is always 42883', 'src/exec.cho',
     '        note(w, 0 - r);\n        return 0;',
     '        note(w, 5);\n        return 0;'),
    ('where: a condition that is no boolean is 42883', 'src/exec.cho',
     '        } else if ty != 2 {\n            note(w, 6);',
     '        } else if ty != 2 {\n            note(w, 5);'),
    ('scan: the rows of the next table too', 'src/exec.cho',
     '    if nk < 4 || commit.be(contents(w.key2), 0, 4) != w.tid {\n        return 0 - 1;\n    }\n    if w.hin >= 0 {',
     '    if nk < 4 {\n        return 0 - 1;\n    }\n    if w.hin >= 0 {'),
    ('text: a byte that is no UTF-8 is taken', 'src/exec.cho',
     '        } else {\n            return false;\n        }\n        if i + more >= n {\n            return false;\n        }',
     '        } else {\n            more = 0;\n        }\n        if i + more >= n {\n            return false;\n        }'),
    ('text: a sequence cut short is taken', 'src/exec.cho',
     '        if i + more >= n {\n            return false;\n        }',
     '        if i + more >= n {\n            return true;\n        }'),
    ('change: the image before left out', 'src/exec.cho',
     '        build.put_be(contents(w.chg), at, il, 4);\n        at = at + 4 + il;\n    } else {\n        build.put_be(contents(w.chg), at, 4294967295, 4);\n        at = at + 4;\n    }\n    if at + 4 > rows_size() {',
     '        build.put_be(contents(w.chg), at, 0, 4);\n        at = at + 4;\n    } else {\n        build.put_be(contents(w.chg), at, 4294967295, 4);\n        at = at + 4;\n    }\n    if at + 4 > rows_size() {'),
    ('a null is taken where not null is said', 'src/execw.cho',
     '(row.col_pk(contents(w.ctx)[64..64 + dl], c) > 0 || tables.not_null(contents(w.ent)[0..el], c))',
     'row.col_pk(contents(w.ctx)[64..64 + dl], c) > 0'),
    ('a null is taken in a key', 'src/execw.cho',
     '(row.col_pk(contents(w.ctx)[64..64 + dl], c) > 0 || tables.not_null(contents(w.ent)[0..el], c))',
     'tables.not_null(contents(w.ent)[0..el], c)'),
    ("a constant's error waits for a row", 'src/execw.cho',
     '    if contents(w.ws)[b + 4] != 1 {\n        if !eval.assignable(contents(w.ws)[b], to) {',
     '    if true {\n        if !eval.assignable(contents(w.ws)[b], to) {'),
    ('a value of another type is 42883', 'src/execw.cho',
     '        if !eval.assignable(contents(w.ws)[b], to) {\n            exec.note(w, 6);',
     '        if !eval.assignable(contents(w.ws)[b], to) {\n            exec.note(w, 5);'),
    ('insert: defaults ignored', 'src/execw.cho',
     '                    let da = tables.default_at(contents(w.ent)[0..el], c);\n                    if da < 0 {',
     '                    let da = tables.default_at(contents(w.ent)[0..el], c);\n                    if true {'),
    ('insert: a key that is there is overwritten', 'src/execw.cho',
     '        if g >= 0 && !skip {\n            return exec.e_unique();\n        }',
     '        if false {\n            return exec.e_unique();\n        }'),
    ('insert: a null is a unique violation', 'src/execw.cho',
     '        if null_in(w, contents(w.cur)[0..rl]) {\n            return exec.e_not_null();',
     '        if null_in(w, contents(w.cur)[0..rl]) {\n            return exec.e_unique();'),
    ('insert: the key is checked before the null', 'src/execw.cho',
     '        if null_in(w, contents(w.cur)[0..rl]) {\n            return exec.e_not_null();\n        }\n',
     ''),
    ('insert: rows counted twice', 'src/execw.cho',
     '            w.count = w.count + 1;\n        }\n        r = r + 1;',
     '            w.count = w.count + 2;\n        }\n        r = r + 1;'),
    ('update: a row that did not change is a change', 'src/execw.cho',
     '                if !bad && !exec.same(contents(w.cur), 0, rl, contents(w.nrow), 0, ra) {',
     '                if !bad {'),
    ('update: a changed key stays where it was', 'src/execw.cho',
     '                        moved = !exec.same(contents(w.key), 0, okl, contents(w.key2), 0, kl);',
     '                        moved = false;'),
    ('update: two rows take one key', 'src/execw.cho',
     '                            // two rows of this statement take one key\n                            exec.note(w, exec.e_unique());',
     '                            // two rows of this statement take one key\n                            exec.note(w, 0);'),
    ('update: a null assigned is no error', 'src/execw.cho',
     '                    if null_in(w, contents(w.nrow)[0..ra]) {\n                        exec.note(w, exec.e_not_null());\n                        bad = true;',
     '                    if null_in(w, contents(w.nrow)[0..ra]) {\n                        bad = true;'),
    ('update: only matched rows that changed are counted', 'src/execw.cho',
     '            if pass == 1 {\n                w.count = w.count + 1;\n                var bad = false;',
     '            if pass == 1 {\n                var bad = false;'),
    ('update: a taken key that a row leaves is an error', 'src/execw.cho',
     '                if g2 >= 0 {\n                    w.orderdep = true;',
     '                if g2 >= 0 {\n                    exec.note(w, exec.e_unique());'),
    ('update: a taken key that a row keeps is no error', 'src/execw.cho',
     '                } else if g2 == btree.not_found() {\n                    exec.note(w, exec.e_unique());',
     '                } else if g2 == btree.not_found() {\n                    exec.note(w, 0);'),
    ('update: the old keys are not left', 'src/execw.cho',
     '                if pass == 0 {\n                    nw = exec.del_key(p, w, out, contents(w.tmp)[65536..65539 + nk], 3 + nk);',
     '                if pass == 0 {\n                    nw = out;'),
    ('delete: the row stays', 'src/execw.cho',
     '                nroot = nw;\n                let cr = exec.change(w, contents(w.cur)[0..rl], true, contents(w.cur)[0..0], false);',
     '                let cr = exec.change(w, contents(w.cur)[0..rl], true, contents(w.cur)[0..0], false);'),
    ('delete: no change recorded', 'src/execw.cho',
     '                let cr = exec.change(w, contents(w.cur)[0..rl], true, contents(w.cur)[0..0], false);\n                if cr < 0 {\n                    return cr;\n                }\n                let rr = exec.ret_row',
     '                let rr = exec.ret_row'),
    ('create: smallint is integer', 'src/execw.cho',
     '            ty = row.t_int2();',
     '            ty = row.t_int4();'),
    ('create: not null forgotten', 'src/execw.cho',
     '        var marks = flags % 2;',
     '        var marks = 0;'),
    ('create: a table that is there is made again', 'src/execw.cho',
     '    let g = tables.find(p, contents(w.sc), root, e[4..4 + nl], contents(w.key), contents(w.cur));\n    if g >= 0 {\n        exec.note(w, exec.e_table_exists());',
     '    let g = tables.find(p, contents(w.sc), root, e[4..4 + nl], contents(w.key), contents(w.cur));\n    if false {\n        exec.note(w, exec.e_table_exists());'),
    ('create: two keys taken', 'src/execw.cho',
     '            if keys > 1 {\n                exec.note(w, exec.e_two_keys());\n                place = 0;',
     '            if keys > 1 {\n                place = 0;'),
    ('create: a column twice taken', 'src/execw.cho',
     '                exec.note(w, exec.e_column_twice());\n            }\n            oa = oa + 4 + ol;\n            k = k + 1;',
     '                exec.note(w, 0);\n            }\n            oa = oa + 4 + ol;\n            k = k + 1;'),
    ('create: a default of another type taken as null', 'src/execw.cho',
     '                    let s = exec.stat(w, r2);\n                    if s < 0 {\n                        return s;\n                    }\n                } else if contents(w.ws)[b + 1] == 2 {',
     '                    let s = 0;\n                    if s < 0 {\n                        return s;\n                    }\n                } else if contents(w.ws)[b + 1] == 2 {'),
    ('tables: every table has number 1', 'src/tables.cho',
     '            build.put_be(b, 0, id + 1, 4);',
     '            build.put_be(b, 0, id, 4);'),
    ("tables: a default read as the next column's marks", 'src/tables.cho',
     '        if m / 2 % 2 == 1 {\n            at = at + stored_len(ent, at);\n        }\n        if m / 4 % 2 == 1 {\n            at = at + 16;\n        }\n        k = k + 1;',
     '        if false {\n            at = at + stored_len(ent, at);\n        }\n        if m / 4 % 2 == 1 {\n            at = at + 16;\n        }\n        k = k + 1;'),
    ('assign: an integer is not stored as text', 'src/eval.cho',
     '    return from == to || from == 0 || is_int(from) && is_int(to) || to == 3;',
     '    return from == to || from == 0 || is_int(from) && is_int(to);'),
    ('params: the second parameter is read where the third is', 'src/eval.cho',
     '            set(ws, out, 0, 0, cx[params_at() + 2 * idx - 1], pn, constant);',
     '            set(ws, out, 0, 0, cx[params_at() + 2 * idx + 1], pn, constant);'),
    ('params: a null parameter is an empty text', 'src/eval.cho',
     '        if pn < 0 {\n            set(ws, out, 0, 1, 0, 0, constant);',
     '        if pn < 0 {\n            set(ws, out, 0, 0, 0, 0, constant);'),
    ('params: a parameter is a literal (one that meets no type is read as text)', 'src/eval.cho',
     '        ws[out + 5] = 1;\n',
     ''),
    ('params: a parameter that meets a type is not counted as met', 'src/eval.cho',
     '        ws[v + 5] = 0;\n        info[3] = info[3] + 1;',
     '        ws[v + 5] = 0;'),
    ('params: a parameter that met no type is let through', 'src/eval.cho',
     '                if info[3] != open {',
     '                if info[3] > open {'),
    ('params: a parameter tested by IN is read as a literal', 'src/eval.cho',
     '        if ws[x + 5] == 1 {',
     '        if ws[x + 5] == 2 {'),
    ('params: a parameter among integers of two widths is read at the widest', 'src/eval.cho',
     '        if mixed && text {',
     '        if mixed && text && t == 0 {'),
    ('params: a statement need not name every parameter bound', 'src/exec.cho',
     '    return part || seen == count;',
     '    return part || seen <= count;'),
    ('params: a parameter used twice needs no cast', 'src/exec.cho',
     '                if later && (i + 2 >= n || toks[4 * (i + 1)] != lex.t_cast() || toks[4 * (i + 2)] != lex.t_ident()) {',
     '                if later && i + 2 >= n {'),
    ('params: a parameter used twice may have two casts', 'src/exec.cho',
     '            } else if i + 2 >= n || toks[4 * (i + 1)] != lex.t_cast() || !same_word(sql, toks, first + 2, i + 2) {',
     '            } else if i + 2 >= n || toks[4 * (i + 1)] != lex.t_cast() {'),
    ('params: BETWEEN is one use of the value it tests', 'src/exec.cho',
     '                    later = k < n && is_word(sql, toks, k, "between");',
     '                    later = false;'),
    ('params: the arena starts over the parameters', 'src/exec.cho',
     '    return w.pend;\n}',
     '    return 0;\n}'),
    ('params: a negative LIMIT bound to a parameter is no error', 'src/execs.cho',
     '        if v0 < 0 {\n            exec.note(w, which);\n            return end;\n        }',
     ''),
    ('schema: the marks after a column with a range are read 8 bytes early', 'src/tables.cho',
     '        if m / 4 % 2 == 1 {\n            at = at + 16;\n        }\n        k = k + 1;',
     '        if m / 4 % 2 == 1 {\n            at = at + 8;\n        }\n        k = k + 1;'),
    ("schema: a range is read where the column's default is", 'src/tables.cho',
     '        return at + 1 + stored_len(ent, at + 1);',
     '        return at + 1;'),
    ('schema: a value below its range is stored', 'src/execw.cho',
     '            if v < row.int_at(contents(w.ent), ra) || v > row.int_at(contents(w.ent), ra + 8) {',
     '            if v > row.int_at(contents(w.ent), ra + 8) {'),
    ('schema: a value above its range is stored', 'src/execw.cho',
     '            if v < row.int_at(contents(w.ent), ra) || v > row.int_at(contents(w.ent), ra + 8) {',
     '            if v < row.int_at(contents(w.ent), ra) {'),
    ('schema: an insert does not look at the ranges', 'src/execw.cho',
     '        if range_out(w, contents(w.cur)[0..rl]) {\n            return exec.e_check();\n        }\n',
     ''),
    ('schema: an update does not look at the ranges', 'src/execw.cho',
     '                    } else if range_out(w, contents(w.nrow)[0..ra]) {',
     '                    } else if range_out(w, contents(w.nrow)[0..0]) {'),
    ('schema: a check written before the default is read as the default', 'src/execw.cho',
     '        if flags / 64 % 2 == 1 {',
     '        if flags / 64 % 2 == 2 {'),
    ('schema: NOT BETWEEN is a range', 'src/execw.cho',
     'nodes[6 * cn] != parse.n_between() || nodes[6 * cn + 1] != 0 || nodes[6 * cn + 3] != 3',
     'nodes[6 * cn] != parse.n_between() || nodes[6 * cn + 3] != 3'),
    ('schema: a check of another column is a range of this one', 'src/execw.cho',
     '            if sl < 0 || !exec.same(contents(w.nrow), 0, sl, contents(w.ent), da - cl, cl) {',
     '            if sl < 0 {'),
    ('schema: a negative bound is read without its sign', 'src/execw.cho',
     '                    sign = 0 - 1;',
     '                    sign = 1;'),
    ('schema: IF NOT EXISTS makes a table over an index of its name', 'src/execw.cho',
     '        if g0 >= 0 || g1 >= 0 {',
     '        if g0 >= 0 {'),
    ('schema: every column of a table key is its first', 'src/execw.cho',
     '                        contents(w.ent)[oa + 1] = byte_of(j + 1);',
     '                        contents(w.ent)[oa + 1] = byte_of(1);'),
    ('schema: a table key beside a column key is no error', 'src/execw.cho',
     '        if keys > 0 {\n            exec.note(w, exec.e_two_keys());\n        }\n        var j = 0;',
     '        var j = 0;'),
    ('schema: ADD COLUMN IF NOT EXISTS adds a column that is there', 'src/execw.cho',
     '        if how == 1 && at >= 0 {',
     '        if how == 3 && at >= 0 {'),
    ('schema: a change of type to another type is nothing', 'src/execw.cho',
     'code == 3 && ty == row.t_int()',
     'code == 3'),
    ('schema: a default outside the range is given to the rows there are', 'src/execw.cho',
     '        } else if outside {',
     '        } else if outside && nulls {'),
    ("schema: a row gets the new column's range after its default", 'src/execw.cho',
     '                ra = exec.copy(contents(w.tmp), xl + 1, dlen2, contents(w.nrow), ra);',
     '                ra = exec.copy(contents(w.tmp), xl + 1, xa - xl - 1, contents(w.nrow), ra);'),
    ('schema: the condition of an index is one of its columns', 'src/execw.cho',
     '        ncols = ncols - 1;',
     '        ncols = ncols - 0;'),
    ('schema: any column is a condition of an index', 'src/execw.cho',
     '        if !isbool {',
     '        if !isbool && cl < 0 {'),
    ('schema: CREATE INDEX IF NOT EXISTS says a name is taken', 'src/execw.cho',
     '    if there && !ine {',
     '    if there {'),
    ('identity: no column is an identity column', 'src/tables.cho',
     '        if int_of(ent[marks_at(ent, i)]) / 8 == 1 {',
     '        if int_of(ent[marks_at(ent, i)]) / 8 == 2 {'),
    ("identity: a table's counter is read as a table", 'src/tables.cho',
     '            } else if int_of(key2[4]) == 2 || int_of(key2[4]) == 3 || int_of(key2[4]) == 4 {',
     '            } else if int_of(key2[4]) == 3 || int_of(key2[4]) == 4 {'),
    ('identity: every row of an insert draws the same value', 'src/execw.cho',
     '                    exec.put_i64(contents(w.nrow), ra + 1, last + r);',
     '                    exec.put_i64(contents(w.nrow), ra + 1, last);'),
    ('identity: the row an insert failed at gives its value back', 'src/execw.cho',
     '            drawn = exec.failed_row(w) + 1;',
     '            drawn = exec.failed_row(w);'),
    ('identity: a failed statement and a rollback give the values back', 'src/exec.cho',
     '        if last >= 0 && last < v {\n            let nw = seq_put(p, w, nroot, id, v);',
     '        if last >= 0 && last > v {\n            let nw = seq_put(p, w, nroot, id, v);'),
    ('identity: a new counter starts at two', 'src/execw.cho',
     '        let sr = exec.seq_put(p, w, nw, tables.id_of(contents(w.ent)), 1);',
     '        let sr = exec.seq_put(p, w, nw, tables.id_of(contents(w.ent)), 2);'),
    ('identity: an update sets an identity column', 'src/execw.cho',
     '        if c == tables.identity_col(contents(w.ent)[0..el0]) {',
     '        if c == tables.identity_col(contents(w.ent)[0..el0]) + 100 {'),
    ('identity: an insert gives an identity column a value', 'src/execw.cho',
     '        if c == ic {\n            // a value given to an identity column',
     '        if c == ic + 100 {\n            // a value given to an identity column'),
    ('identity: a text column is an identity column', 'src/execw.cho',
     'if ty != row.t_int() && ty != row.t_int4() && ty != row.t_int2() || contents(w.pos)[exec.p_ddl() + 2] != 0 {',
     'if contents(w.pos)[exec.p_ddl() + 2] != 0 {'),
    ('identity: a table has two identity columns', 'src/execw.cho',
     'if ty != row.t_int() && ty != row.t_int4() && ty != row.t_int2() || contents(w.pos)[exec.p_ddl() + 2] != 0 {',
     'if ty != row.t_int() && ty != row.t_int4() && ty != row.t_int2() {'),
    ('identity: an identity column is added to a table', 'src/execw.cho',
     'if flags / 32 % 2 == 1 && (c0 != 0 || flags / 8 % 2 == 1',
     'if flags / 32 % 2 == 1 && (flags / 8 % 2 == 1'),
    ('conflict: ON CONFLICT DO NOTHING raises the conflict', 'src/execw.cho',
     '        if g >= 0 && !skip {',
     '        if g >= 0 {'),
    ('conflict: every insert leaves out a row whose key is there', 'src/execw.cho',
     '    let sr = store_rows(p, w, root, stored, skip);',
     '    let sr = store_rows(p, w, root, stored, true);'),
    ('eval: digits out of range and then a letter are text that is no number', 'src/eval.cho',
     '    if i != end && digits >= 5 {',
     '    if i != end && digits >= 50 {'),
    ('eval: four digits and then a letter are not answered', 'src/eval.cho',
     '    if i != end && digits >= 5 {',
     '    if i != end && digits >= 4 {'),
    ('returning: an update returns the row as it was', 'src/execw.cho',
     '                        let rr = exec.ret_row(w, contents(w.nrow)[0..ra]);',
     '                        let rr = exec.ret_row(w, contents(w.cur)[0..rl]);'),
    ('returning: a delete returns nothing', 'src/execw.cho',
     '                let rr = exec.ret_row(w, contents(w.cur)[0..rl]);\n                if rr < 0 {\n                    return rr;\n                }\n                w.count = w.count + 1;',
     '                w.count = w.count + 1;'),
    ('returning: an insert returns nothing', 'src/execw.cho',
     '            let rr = exec.ret_row(w, contents(w.cur)[0..rl]);\n            if rr < 0 {\n                return rr;\n            }\n            w.count = w.count + 1;',
     '            w.count = w.count + 1;'),
    ('returning: an item that can raise an error is read', 'src/execs.cho',
     '            if !quiet(e, contents(w.pos)[exec.p_item() + i], contents(w.pos)[exec.p_iend() + i]) {\n                return exec.unsupported();\n            }\n            i = i + 1;\n        }\n    }\n    if ng > 0',
     '            i = i + 1;\n        }\n    }\n    if ng > 0'),
    ("returning: reading the items forgets what the statement changed", 'src/exec.cho',
     '    if w.ret < 2 {\n        // (the SELECT',
     '    if w.ret < 9 {\n        // (the SELECT'),
    ('coalesce: an error in an argument after the one that is taken is raised', 'src/eval.cho',
     '        while m < ops && failed == 0 && (which != 1 || chosen < 0) {',
     '        while m < ops && failed == 0 {'),
    ('coalesce: GREATEST is the least', 'src/eval.cho',
     '                    if which == 2 && c > 0 || which == 3 && c < 0 {',
     '                    if which == 2 && c < 0 || which == 3 && c < 0 {'),
    ('coalesce: LEAST is the first that is not null', 'src/eval.cho',
     '                    if which == 2 && c > 0 || which == 3 && c < 0 {',
     '                    if which == 2 && c > 0 {'),
    ('coalesce: COALESCE of a constant is not a constant', 'src/eval.cho',
     '                if !(ws[v + 4] == 1 && ws[v + 1] == 1) {\n                    folded = ws[v + 4];',
     '                if !(ws[v + 4] == 1 && ws[v + 1] == 1) {\n                    folded = 0;'),
    ('coalesce: COALESCE is an aggregate', 'src/execs.cho',
     '        if int_of(e[at]) == 4 && eval.scalar_fn(e, at) == 0 {',
     '        if int_of(e[at]) == 4 {'),
    ('grouped: an aggregate that PostgreSQL folds away is computed', 'src/execs.cho',
     '    return constant && cnt > 0 && has_call(e, at, end);',
     '    return constant && cnt < 0 && has_call(e, at, end);'),
    ('subquery: a row is stored whatever its condition', 'src/execw.cho',
     '    if held == 0 {\n        stored = 0;\n    }',
     ''),
    ('subquery: WHERE NULL holds', 'src/exec.cho',
     '        // `where null`\n        return 0;',
     '        // `where null`\n        return 1;'),
    ("subquery: a subquery's value is a constant of the plan", 'src/eval.cho',
     '        if cx[inner_at()] != 0 && idx >= cx[inner_at()] {\n            constant = 0;',
     '        if cx[inner_at()] != 0 && idx >= cx[inner_at()] {\n            constant = 1;'),
    ("subquery: a condition that is wrong comes after a row that is wrong", 'src/execw.cho',
     '        held = exec.guard_holds(w);\n        if held < 0 {\n            return held;\n        }',
     '        held = exec.guard_holds(w);'),
    ('sequence: a row that fails gives the value back', 'src/execw.cho',
     '    if exec.draw_id(w) != 0 && sr >= 0 {',
     '    if exec.draw_id(w) != 0 && sr == 0 {'),
    ('sequence: a nextval beside a condition is answered', 'src/execw.cho',
     '    if exec.draw_id(w) != 0 && exec.guard_len(w) > 0 {',
     '    if exec.draw_id(w) != 0 && exec.guard_len(w) > 99999 {'),
    ('sequence: it starts at its least value, whatever START says', 'src/execw.cho',
     '    let sr = exec.seq_put(p, w, nroot, id, first);',
     '    let sr = exec.seq_put(p, w, nroot, id, low);'),
    ('sequence: a start below the least value is taken', 'src/execw.cho',
     '    if low < 0 || first < low {',
     '    if low < 0 {'),
    ("sequence: a sequence takes a table's name", 'src/execw.cho',
     '    let g1 = tables.find(p, contents(w.sc), root, contents(w.nrow)[0..nl], contents(w.key), contents(w.cur));\n    if g1 >= 0 {\n        there = true;',
     '    let g1 = tables.find(p, contents(w.sc), root, contents(w.nrow)[0..nl], contents(w.key), contents(w.cur));\n    if g1 > 9999 {\n        there = true;'),
    ("sequence: a table takes a sequence's name", 'src/execw.cho',
     '    if gq >= 0 {\n        exec.note(w, exec.e_table_exists());',
     '    if gq > 9999 {\n        exec.note(w, exec.e_table_exists());'),
    ("sequence: an index takes a sequence's name", 'src/execw.cho',
     '    if gq >= 0 {\n        there = true;',
     '    if gq > 9999 {\n        there = true;'),
    ('sequence: IF NOT EXISTS says the name is taken', 'src/execw.cho',
     '        if nodes[6 * stmt + 3] == 1 {\n            // IF NOT EXISTS: a notice',
     '        if nodes[6 * stmt + 3] == 2 {\n            // IF NOT EXISTS: a notice'),
    ('sequence: a sequence is read as a table', 'src/tables.cho',
     '            } else if int_of(key2[4]) == 2 || int_of(key2[4]) == 3 || int_of(key2[4]) == 4 {',
     '            } else if int_of(key2[4]) == 2 || int_of(key2[4]) == 4 {'),
    ('sequence: an error before the rows is answered beside a draw', 'src/execw.cho',
     '        if exec.draw_id(w) != 0 || ic >= 0 && exec.params_inner_bound(w) {',
     '        if ic >= 0 && exec.params_inner_bound(w) {'),
    ("identity: an error before the rows is answered beside a subquery's value", 'src/execw.cho',
     '        if exec.draw_id(w) != 0 || ic >= 0 && exec.params_inner_bound(w) {',
     '        if exec.draw_id(w) != 0 {'),
    ('drive: a subquery of several rows gives its first', 'src/drive.cho',
     '            if rc != 0 || exec.count_of(w) > 1 || exec.columns_of(w) != 1 {',
     '            if rc != 0 || exec.columns_of(w) != 1 {'),
    ('drive: a subquery of several columns gives its first', 'src/drive.cho',
     '            if rc != 0 || exec.count_of(w) > 1 || exec.columns_of(w) != 1 {',
     '            if rc != 0 || exec.count_of(w) > 1 {'),
    ('drive: a subquery that fails is a null', 'src/drive.cho',
     '            if rc != 0 || exec.count_of(w) > 1 || exec.columns_of(w) != 1 {',
     '            if exec.count_of(w) > 1 || exec.columns_of(w) != 1 {'),
    ('drive: a subquery after IN is a value', 'src/drive.cho',
     '                let p = i - 1;\n                ok = parse.kw(',
     '                let p = i - 1;\n                ok = true || parse.kw('),
    ('drive: a subquery among the output columns is answered', 'src/drive.cho',
     '        if named && tok_is(sql, contents(b.t2), i, n, \'(\') && parse.kw(sql, contents(b.t2), i + 1, n, "select") {\n            return 0 - 2;\n        }\n',
     ''),
    ('drive: a subquery of no row is an empty text', 'src/drive.cho',
     '            if vn < 0 {\n                added = exec.param_add(w, contents(b.vtx)[0..0], true);',
     '            if vn < 0 {\n                added = exec.param_add(w, contents(b.vtx)[0..0], false);'),
    ('drive: a nextval in a later row is drawn', 'src/drive.cho',
     "                if k + 2 < i && tok_is(sql, contents(b.t2), k, n, ')') && tok_is(sql, contents(b.t2), k + 1, n, ',') && tok_is(sql, contents(b.t2), k + 2, n, '(') {\n                    ok = false;\n                }\n",
     ''),
    ('drive: a nextval under a CASE is drawn', 'src/drive.cho',
     '                if parse.kw(sql, contents(b.t2), k, n, "case") {\n                    ok = false;\n                }\n',
     ''),
    ('drive: a nextval after a COALESCE, an AND, an OR or an IN is drawn', 'src/drive.cho',
     '                if k < i && (parse.kw(sql, contents(b.t2), k, n, "coalesce") || parse.kw(sql, contents(b.t2), k, n, "and") || parse.kw(sql, contents(b.t2), k, n, "or") || parse.kw(sql, contents(b.t2), k, n, "in")) {\n                    ok = false;\n                }\n',
     ''),
    ('drive: a second nextval takes the place of the first', 'src/drive.cho',
     'var ok = parse.kw(sql, contents(b.t2), 0, n, "insert") && exec.draw_id(w) == 0 && i >= 2',
     'var ok = parse.kw(sql, contents(b.t2), 0, n, "insert") && i >= 2'),
    ('drive: a nextval outside an insert is drawn', 'src/drive.cho',
     'var ok = parse.kw(sql, contents(b.t2), 0, n, "insert") && exec.draw_id(w) == 0 && i >= 2',
     'var ok = exec.draw_id(w) == 0 && i >= 2'),
    ('drive: the value drawn is given again', 'src/drive.cho',
     '            exec.draw_set(w, id, v + 1);',
     '            exec.draw_set(w, id, v);'),
    ('drive: a statement with a subquery need not name every parameter bound', 'src/drive.cho',
     '    if !exec.params_fit(w, sql, contents(b.t2), n, false) {',
     '    if !exec.params_fit(w, sql, contents(b.t2), n, true) {'),
    ('facts: a row touched twice is a fact from its second touch', 'src/facts.cho',
     '            exec.copy(contents(w.cur), 0, 33, contents(w.uval), 0);\n        } else if g != btree.not_found() {',
     '        } else if g != btree.not_found() {'),
    ('facts: a row made and removed in a transaction is a fact', 'src/facts.cho',
     '            nw = root;\n            if g == 66 {\n                nw = btree.del(p, contents(w.sc), root, contents(w.key)[0..fk]);\n            }',
     '            nw = root;'),
    ('facts: an insert is a delete', 'src/facts.cho',
     '                if !was {\n                    kind = 0;\n                    ol = 0;',
     '                if !was {\n                    kind = 2;\n                    ol = 0;'),
    ('facts: the image after is hashed as the image before', 'src/facts.cho',
     '            let o = 33 * side;',
     '            let o = 0;'),
    ('facts: the count is one more than the facts', 'src/facts.cho',
     '    state.changes(n, contents(w.uval)[0..32], out);\n    return n;',
     '    state.changes(n + 1, contents(w.uval)[0..32], out);\n    return n;'),
    ('salts: a row that is changed keeps its salt', 'src/exec.cho',
     '        copy(contents(w.salts), 0, 16, contents(w.nsalts), 0);\n        salt(w, 16);',
     '        copy(contents(w.salts), 0, 32, contents(w.nsalts), 0);'),
    ("salts: a row that is changed gets a new key salt", 'src/exec.cho',
     '        copy(contents(w.salts), 0, 16, contents(w.nsalts), 0);\n        salt(w, 16);',
     '        salt(w, 0);\n        salt(w, 16);'),
    ("ddl: a row given a column gets a new key salt", 'src/execw.cho',
     'contents(w.nrow)[0..ra], contents(w.cur)[0..rl], 1);\n            if nw < 0 {\n                return nw;\n            }\n            nroot = nw;\n            let cr = exec.change_def(',
     'contents(w.nrow)[0..ra], contents(w.cur)[0..rl], 0);\n            if nw < 0 {\n                return nw;\n            }\n            nroot = nw;\n            let cr = exec.change_def('),
    ('ddl: the image of a row given a column is of the definition before', 'src/execw.cho',
     'contents(w.nrow)[0..ra], true, da - 6);', 'contents(w.nrow)[0..ra], true, 0);'),
    ('ddl: a column added reports no row', 'src/execw.cho',
     'let cr = exec.change_def(w, contents(w.cur)[0..rl], true, contents(w.nrow)[0..ra], true, da - 6);', 'let cr = 0;'),
    ('ddl: a table dropped reports no row', 'src/execw.cho',
     '            // each row that goes with the table is a row deleted, and a fact of the commit (6ai)\n            let cr = exec.change(w, contents(w.cur)[0..rl], true, contents(w.cur)[0..0], false);',
     '            // each row that goes with the table is a row deleted, and a fact of the commit (6ai)\n            let cr = 0;'),
    ('salts: every salt is the first', 'src/exec.cho',
     '    w.scount = w.scount + 1;\n    build.put_be(contents(w.seed), 32, w.scount, 8);',
     '    build.put_be(contents(w.seed), 32, w.scount, 8);'),
    ('salts: the salts of the row read are those of the row read before', 'src/exec.cho',
     '    copy(contents(w.cur), 0, 32, contents(w.salts), 0);\n    shift(contents(w.cur), 32, nv);',
     '    shift(contents(w.cur), 32, nv);'),
    ('salts: a row is written with no seed', 'src/exec.cho',
     '    if !w.seeded {\n        return no_entropy();\n    } else if how == 0 || how == 3 {',
     '    if how == 0 || how == 3 {'),
    ('salts: a row that moves is written with no seed', 'src/exec.cho',
     '    if !w.seeded {\n        return no_entropy();\n    }\n    salt(w, 0);',
     '    salt(w, 0);'),
    ('salts: a row that moves keeps the salts of the last row written', 'src/exec.cho',
     '    salt(w, 0);\n    salt(w, 16);\n    return 0;',
     '    return 0;'),
    ("salts: a change says the old row had the new row's salt", 'src/exec.cho',
     '        at = copy(contents(w.salts), 16, 16, contents(w.chg), at + 1);',
     '        at = copy(contents(w.nsalts), 16, 16, contents(w.chg), at + 1);'),
    ("facts: the commitment is over the old row's salt", 'src/facts.cho',
     'state.key_commit(contents(w.chg)[ia..ia + 16],',
     'state.key_commit(contents(w.chg)[ia + 17..ia + 33],'),
    ("facts: an image is hashed with the key's salt", 'src/facts.cho',
     'state.row_hash2(contents(w.chg)[sa + 1..sa + 17],',
     'state.row_hash2(contents(w.chg)[ia..ia + 16],'),
    ('joins: a joined row is read with its salts in front', 'src/execs.cho',
     'fill = exec.copy(contents(w.cur), 32, nv, contents(w.jbuf), fill + 2);',
     'fill = exec.copy(contents(w.cur), 0, nv, contents(w.jbuf), fill + 2);'),
    ("assign: a constant's error is a refusal", 'src/eval.cho',
     '    let constant = ws[v + 4];\n    ws[v + 4] = 0;',
     '    let constant = ws[v + 4];'),
    ('session: in a transaction a key is written once', 'src/session.cho',
     'exec.set_once(w, ss[0] == idle());',
     'exec.set_once(w, true);'),
    ("session: a statement in a transaction runs on the branch's tree", 'src/session.cho',
     '        return branch;\n    }\n    return ss[1];',
     '        return branch;\n    }\n    return branch;'),
    ("session: a statement writes with the branch's last number", 'src/session.cho',
     'exec.set_txn(w, last + 1);',
     'exec.set_txn(w, last);'),
    ("session: BEGIN does not start from the branch's tree", 'src/session.cho',
     '            ss[1] = branch;\n            ss[2] = 0;',
     '            ss[2] = 0;'),
    ('session: what a failed statement drew is given back', 'src/session.cho',
     '            root = exec.seq_replay(p, w, branch);\n        } else if after != branch {',
     '            root = branch;\n        } else if after != branch {'),
    ("session: a statement's commit takes no number", 'src/session.cho',
     'root = exec.mark_txn(p, w, after, last + 1);',
     'root = after;'),
    ('session: what was drawn is not forgotten when nothing can roll back', 'src/session.cho',
     '            exec.seq_forget(w);\n        }\n        return root;',
     '        }\n        return root;'),
    ('session: BEGIN in a failed transaction is answered as in an open one', 'src/session.cho',
     '            ss[5] = 4;',
     '            ss[5] = 1;'),
    ('session: the COMMIT of a failed transaction commits', 'src/session.cho',
     'if after == is_commit() && ss[0] == open_txn() {',
     'if after == is_commit() {'),
    ("session: a transaction's commit takes no number", 'src/session.cho',
     'root = exec.mark_txn(p, w, ss[1], last + 1);',
     'root = ss[1];'),
    ('session: a transaction that wrote has no facts', 'src/session.cho',
     '            ss[3] = 1;\n',
     ''),
    ('session: what a rolled back transaction drew is given back', 'src/session.cho',
     '            ss[5] = 3;\n            root = exec.seq_replay(p, w, branch);',
     '            ss[5] = 3;\n            root = branch;'),
    ('session: an error leaves the transaction open', 'src/session.cho',
     '        ss[0] = failed();',
     '        ss[0] = open_txn();'),
    ("session: a statement's tree is not the transaction's next", 'src/session.cho',
     '        ss[1] = after;\n',
     ''),
    ("session: a transaction's facts are its last statement's", 'src/session.cho',
     'ss[2] = facts.take(p, w, ss[2]);',
     'ss[2] = facts.take(p, w, 0);'),
    ('session: a failed transaction runs its statements', 'src/session.cho',
     '    if ss[0] == failed() {\n        return 3;',
     '    if ss[0] == failed() {\n        return 0;'),
    ('session: a ROLLBACK leaves the transaction open', 'src/session.cho',
     '        ss[0] = idle();\n',
     ''),
    ("log: a transaction's commit is sealed on the branch's tree", 'src/session.cho',
     'root = seal_on(p, w, ss, root, ss[2], key, who, rec);',
     'root = seal_on(p, w, ss, branch, ss[2], key, who, rec);'),
    ("session: a transaction's facts stay for the next", 'src/session.cho',
     '            ss[2] = 0;\n            ss[3] = 0;\n            ss[5] = 1;',
     '            ss[3] = 0;\n            ss[5] = 1;'),
    ("session: a transaction that wrote nothing is a commit after one that wrote", 'src/session.cho',
     '            ss[2] = 0;\n            ss[3] = 0;\n            ss[5] = 1;',
     '            ss[2] = 0;\n            ss[5] = 1;'),
    ('run: a failed transaction runs its statements', 'src/drive.cho',
     '    if mode == 3 {',
     '    if false {'),
    ('run: a sequence is made on a tree read AS OF', 'src/drive.cho',
     "        // CREATE SEQUENCE has no IR: it is the engine's alone\n        if mode != 0 || exec.params_bound(w) > 0 {",
     "        // CREATE SEQUENCE has no IR: it is the engine's alone\n        if exec.params_bound(w) > 0 {"),
    ('run: a tree read AS OF is written to', 'src/drive.cho',
     '        if mode == 1 && kind != 6 {',
     '        if false {'),
    ('run: the items of a RETURNING are not read before the statement', 'src/drive.cho',
     '                exec.ret_set(w, 3);\n',
     ''),
    ('run: a RETURNING returns no rows', 'src/drive.cho',
     '                        returned = rn;\n',
     ''),
    ('run: ON CONFLICT DO NOTHING is not passed on', 'src/drive.cho',
     '        } else if kind == 1 {\n            rc = execw.insert(pg, w, root, e, contents(m.sc), contents(m.nb)[6 * top + 4] == 1);',
     '        } else if kind == 1 {\n            rc = execw.insert(pg, w, root, e, contents(m.sc), false);'),
    ('run: COMMIT is a ROLLBACK', 'src/drive.cho',
     '        if head == parse.n_commit() {\n            return session.is_commit();',
     '        if head == parse.n_commit() {\n            return session.is_rollback();'),
    ('run: an error is a refusal', 'src/drive.cho',
     '        done(hw, o_error(), rc);',
     '        done(hw, o_refused(), rc);'),
    ("run: the names of a RETURNING are the statement's", 'src/drive.cho',
     '            top2 = returned;\n',
     ''),
    ('run: the parameters bound are not held against the statement', 'src/drive.cho',
     'if !exec.params_fit(w, sql, contents(m.tb), n, part) {',
     'if false {'),
    ('run: the guard of the statement before stays', 'src/drive.cho',
     '    exec.set_guard(w, 0);\n',
     ''),
    ('run: the tree after a statement is the tree before', 'src/drive.cho',
     '    return exec.root_of(w);\n}',
     '    return root;\n}'),
    ('run: a refusal where the statement is lowered is one where it is read', 'src/drive.cho',
     '            done(hw, o_lower(), 0 - ln);',
     '            done(hw, o_parse(), 0 - ln);'),
    ('truncate: the rows stay', 'src/execd.cho',
     '    // the table stays: what is left is its tree with no row of it\n    w.root = nroot;',
     '    // the table stays: what is left is its tree with no row of it\n    w.root = root;'),
    ('truncate: reports no row', 'src/execd.cho',
     '            // each row is a row deleted, and a fact of the commit (6ao)\n            let cr = exec.change(w, contents(w.cur)[0..rl], true, contents(w.cur)[0..0], false);',
     '            // each row is a row deleted, and a fact of the commit (6ao)\n            let cr = 0;'),
    ("truncate: what follows the table's name is ignored", 'src/stmt.cho',
     '    if pos < end {\n        return parse.fail(st, pos, parse.e_unsupported_statement());\n    }\n    let root = parse.mk(nodes, kids, st, parse.n_truncate(),',
     '    let root = parse.mk(nodes, kids, st, parse.n_truncate(),'),
    ("truncate: the word TABLE is the table's name", 'src/stmt.cho',
     '    if parse.kw(sql, toks, at, end, "table") {\n        at = at + 1;\n    }\n    let pos = plain_name(sql, toks, at, end, st);',
     '    let pos = plain_name(sql, toks, at, end, st);'),
    ("truncate: its tag is another command's", 'src/answer.cho',
     '            at = word(out, 0, "TRUNCATE TABLE");',
     '            at = word(out, 0, "DELETE");'),
    ('truncate: on a tree read AS OF', 'src/drive.cho',
     '        // TRUNCATE has no IR either\n        if mode != 0 || exec.params_bound(w) > 0 {',
     '        // TRUNCATE has no IR either\n        if exec.params_bound(w) > 0 {'),
    ('insert: with no columns listed a row must have a value for every column', 'src/lower.cho',
     '            width = first;\n',
     ''),
    ('insert: more values than the table has columns are taken', 'src/lower.cho',
     '            if first > width {\n                return fail(sc, 0, parse.e_syntax());\n            }',
     ''),
    ('rename: the rows are not said to leave the table of the old name', 'src/execd.cho',
     '            let cr = exec.change(w, contents(w.cur)[0..rl], true, contents(w.cur)[0..0], false);\n            if cr < 0 {\n                return cr;\n            }\n        }\n    }\n    // the entry moves',
     '            let cr = 0;\n            if cr < 0 {\n                return cr;\n            }\n        }\n    }\n    // the entry moves'),
    ('rename: the rows are not said to enter the table of the new name', 'src/execd.cho',
     '            let cr = exec.change(w, contents(w.cur)[0..0], false, contents(w.nrow)[0..rl], true);',
     '            let cr = 0;'),
    ("rename: a row keeps its key's salt under the new name", 'src/execd.cho',
     'contents(w.nrow)[0..rl], contents(w.cur)[0..rl], 3);',
     'contents(w.nrow)[0..rl], contents(w.cur)[0..rl], 1);'),
    ('rename: onto a name that is taken', 'src/execd.cho',
     '    if g1 >= 0 || g2 >= 0 || g3 >= 0 {\n        return exec.e_table_exists();\n    }',
     ''),
    ('rename: onto the name of an index', 'src/execd.cho',
     '    if g1 >= 0 || g2 >= 0 || g3 >= 0 {',
     '    if g1 >= 0 || g3 >= 0 {'),
    ('rename: the old name stays', 'src/execd.cho',
     '    nroot = exec.del_key(p, w, nroot, contents(w.key), kl);\n    if nroot < 0 {\n        return nroot;\n    }\n    // its indexes are',
     '    // its indexes are'),
    ('rename: its indexes stay with the old name', 'src/execd.cho',
     '                if exec.same(contents(w.cur), 0, r % 1024, contents(w.lit), 2, ol) {',
     '                if false {'),
    ('rename: what follows the new name is ignored', 'src/stmt.cho',
     '        if pos < end {\n            return parse.fail(st, pos, parse.e_syntax());\n        }\n        let root = parse.mk(nodes, kids, st, parse.n_rename(),',
     '        let root = parse.mk(nodes, kids, st, parse.n_rename(),'),
    ('rename: on a tree read AS OF', 'src/drive.cho',
     "        // nor has a table's renaming\n        if mode != 0 || exec.params_bound(w) > 0 {",
     "        // nor has a table's renaming\n        if exec.params_bound(w) > 0 {"),
    ('log: a record is not kept in the tree', 'src/facts.cho',
     '            nw = btree.put(p, contents(w.sc), nw, contents(w.key)[0..rk], out[ra..ra + pl]);\n            if nw < 0 {\n                return exec.tree_err(nw);\n            }\n',
     ''),
    ('log: a record of several parts keeps its first', 'src/facts.cho',
     '            if pl > 700 {\n                pl = 700;\n            }\n            let rk = tables.record_key(seq, part, contents(w.key));',
     '            if pl > 700 {\n                pl = 700;\n            }\n            let rk = tables.record_key(seq, 0, contents(w.key));'),
    ('log: the facts of every commit are kept under the first', 'src/facts.cho',
     '                    let dk = tables.fact_key(seq, contents(w.lit));',
     '                    let dk = tables.fact_key(0, contents(w.lit));'),
    ('log: a commit signed with another key is recorded', 'src/facts.cho',
     '        } else if lr != 32 || !exec.same(contents(w.cur), 0, 32, sig, 0, 32) {',
     '        } else if false {'),
    ('log: a commit that cannot be recorded is made', 'src/session.cho',
     '        ss[7] = 0 - 1;\n        return nw;',
     '        ss[7] = 0 - 1;\n        return root;'),
    ('log: the facts read back go on into what follows them', 'src/facts.cho',
     '    if nk < 5 || commit.be(contents(w.key2), 0, 4) != tables.log_space() || int_of(contents(w.key2)[4]) != 6 {\n        return 0;',
     '    if false {\n        return 0;'),
    ('log: a record read back is cut at its first part', 'src/facts.cho',
     '            at = exec.copy(contents(w.cur), 0, r, out, at);\n            part = part + 1;',
     '            at = exec.copy(contents(w.cur), 0, r, out, at);\n            more = false;'),
    ('facts: the key is the table and the key with nothing between', 'src/facts.cho',
     '        contents(w.key)[fk] = byte_of(0);\n        state.key_commit(',
     '        contents(w.key)[fk] = byte_of(1);\n        state.key_commit('),
    ('session: a statement that wrote has no facts', 'src/session.cho',
     '                note_facts(ss, fr);\n            }\n            root = exec.mark_txn(p, w, after, last + 1);',
     '            }\n            root = exec.mark_txn(p, w, after, last + 1);'),
    ('log: the facts of a commit are not kept', 'src/facts.cho',
     '                if int_of(contents(w.key2)[0]) > 3 {\n                    let dk = tables.fact_key(seq, contents(w.lit));',
     '                if false {\n                    let dk = tables.fact_key(seq, contents(w.lit));'),
    ('log: what the statements were is kept among the facts', 'src/facts.cho',
     '                if int_of(contents(w.key2)[0]) > 3 {\n                    let dk = tables.fact_key(seq, contents(w.lit));',
     '                if true {\n                    let dk = tables.fact_key(seq, contents(w.lit));'),
    ('log: what the statements were is counted among the facts', 'src/facts.cho',
     '            if int_of(contents(w.key2)[0]) <= 3 {',
     '            if false {'),
    ('stmts: a commit names no statement', 'src/facts.cho',
     '                    il = exec.copy(contents(w.cur), 0, 32, ids, il);',
     '                    il = il;'),
    ('stmts: a commit has no effect', 'src/facts.cho',
     '                el = exec.copy(contents(w.key2), 2, nk - 2, effs, el + 3);',
     '                el = el;'),
    ("stmts: an effect's kind is a read", 'src/facts.cho',
     '                effs[el] = contents(w.key2)[1];',
     '                effs[el] = byte_of(0);'),
    ("stmts: a statement's record is not kept with the log", 'src/facts.cho',
     '                    let sk = tables.kept_key(8, st, part - 1, contents(w.lit));\n                    nw = btree.put(p, contents(w.sc), nw, contents(w.lit)[0..sk], contents(w.cur)[0..r % 1024]);',
     '                    let sk = tables.kept_key(8, st, part - 1, contents(w.lit));'),
    ("stmts: every statement's record is kept under the first's id", 'src/facts.cho',
     '                    // whose parts follow\n                    exec.copy(contents(w.cur), 0, 32, st, 0);',
     '                    // whose parts follow'),
    ("stmts: a statement's constants are kept", 'src/facts.cho',
     'contents(vw)[0..info[1]], info[2], salt, id, true);',
     'contents(vw)[0..info[1]], info[2], salt, id, false);'),
    ('stmts: a transaction has one statement, its last', 'src/facts.cho',
     '                            build.put_be(num, 0, count + 1, 4);',
     '                            build.put_be(num, 0, count, 4);'),
    ('stmts: the effects of a statement are not noted', 'src/facts.cho',
     '                        root = put(p, w, root, kl, "e");',
     '                        root = root;'),
    ('stmts: a transaction of any length is committed', 'src/facts.cho',
     '                    if r % 1024 != 32 || il + 32 > len(ids) {',
     '                    if r % 1024 != 32 {'),
    ("stmts: a statement of a transaction that wrote nothing is not one of its commit's", 'src/session.cho',
     '        if ss[2] >= 0 && len(key) > 0 {\n            // every statement of a transaction that ran',
     '        if ss[2] >= 0 && len(key) > 0 && exec.changes_of(w) > 0 {\n            // every statement of a transaction that ran'),
    ('stmts: a statement of its own is in no commit', 'src/session.cho',
     '                if fr >= 0 && len(key) > 0 {\n                    // a commit says what ran (6au)\n                    fr = facts.say(heap, p, w, fr);\n                }',
     ''),
    ('stmts: a commit too large for its record stops everything', 'src/session.cho',
     '            if root == exec.too_big() {\n                root = too_large(p, w, ss, branch);\n            } else {\n                exec.seq_forget(w);\n            }',
     '            exec.seq_forget(w);'),
    ('stmts: what a statement returns is not a statement', 'src/drive.cho',
     '                        if rc == 0 && !exec.stmt_add(w, ir2[0..l2]) {',
     '                        if false {'),
    ('stmts: a truncate is told as no statement', 'src/drive.cho',
     '        kept = keep_named(w, sql, contents(m.tb), contents(m.nb)[6 * top + 1], 3, 0 - 1);',
     '        kept = true;'),
    ('stmts: a truncate is told as a definition', 'src/drive.cho',
     '        kept = keep_named(w, sql, contents(m.tb), contents(m.nb)[6 * top + 1], 3, 0 - 1);',
     '        kept = keep_named(w, sql, contents(m.tb), contents(m.nb)[6 * top + 1], 4, 1);'),
    ('stmts: a renaming is told of the old name only', 'src/drive.cho',
     '        kept = keep_named(w, sql, contents(m.tb), contents(m.nb)[6 * top + 1], 4, 1) && keep_named(w, sql, contents(m.tb), contents(m.nb)[6 * top + 4], 4, 1);',
     '        kept = keep_named(w, sql, contents(m.tb), contents(m.nb)[6 * top + 1], 4, 1);'),
    ('stmts: a statement is not told at all', 'src/drive.cho',
     '        kept = exec.stmt_add(w, contents(m.ir)[0..hw[5]]);',
     '        kept = true;'),
    ('stmts: the statement before is told again', 'src/drive.cho',
     '    exec.stmts_clear(w);\n',
     ''),
    ('log: a commit has the number after its parent', 'src/facts.cho',
     'seq = commit.be(contents(w.cur), 0, 8) + 1;', 'seq = commit.be(contents(w.cur), 0, 8);'),
    ('log: a commit names its parent', 'src/facts.cho',
     '            np = 1;\n            exec.copy(contents(w.cur), 0, 72, head, 0);', '            exec.copy(contents(w.cur), 0, 72, head, 0);'),
    ("log: the state follows from the parent's state", 'src/facts.cho',
     'state.state(np, head[40..40 + 32 * np], chg, st);', 'state.state(np, head[8..8 + 32 * np], chg, st);'),
    ('log: the head keeps the state of its commit', 'src/facts.cho',
     '        exec.copy(st, 0, 32, head, 40);\n', ''),
    ('log: the head keeps the number of its commit', 'src/facts.cho',
     '        build.put_be(head, 0, seq, 8);\n', ''),
    ('log: the id is what is signed', 'src/facts.cho',
     'build.sign(seed, head[8..40], sig);', 'build.sign(seed, st, sig);'),
    ('log: the head is written whole', 'src/facts.cho',
     'nw = btree.put(p, contents(w.sc), root, contents(w.key)[0..hk2], head);', 'nw = btree.put(p, contents(w.sc), root, contents(w.key)[0..hk2], head[0..40]);'),
    ('log: the head is no table of the schema', 'src/tables.cho',
     '} else if int_of(key2[4]) == 2 || int_of(key2[4]) == 3 || int_of(key2[4]) == 4 {', '} else if int_of(key2[4]) == 2 || int_of(key2[4]) == 3 {'),
    ('log: the head a client is given counts one commit too few', 'src/facts.cho',
     '            n = commit.be(contents(w.cur), 0, 8) + 1;\n            exec.copy(contents(w.cur), 8, 32, ident, 0);',
     '            n = commit.be(contents(w.cur), 0, 8);\n            exec.copy(contents(w.cur), 8, 32, ident, 0);'),
    ("log: the id a client is given is the state's, not the commit's", 'src/facts.cho',
     'exec.copy(contents(w.cur), 8, 32, ident, 0);',
     'exec.copy(contents(w.cur), 40, 32, ident, 0);'),
    ('log: with no commit a client is given an id of zeros', 'src/facts.cho',
     '        if n == 0 {\n            rows[9] = byte_of(0);',
     '        if n < 0 {\n            rows[9] = byte_of(0);'),
    ("log: any call of a name that long is the head's", 'src/drive.cho',
     '        if int_of(e[3 + i]) != int_of(name[i]) {\n            return false;\n        }\n        i = i + 1;\n    }\n    return int_of(e[len(e) - 1]) == 0',
     '        if false {\n            return false;\n        }\n        i = i + 1;\n    }\n    return int_of(e[len(e) - 1]) == 0'),
    ('log: the head is given under no column names', 'src/drive.cho',
     '    if called {\n',
     '    if false {\n'),
]

# The engine's server (docs/m3-engine.md 6al): the messages and one connection. Judged by tests/engine_wire.py, which holds the server against the test program.
WIRE = [
    ('wire: the startup is answered with a request for a password', 'src/wire.cho',
     "return shut(out, at, be(out, open(out, at, 'R'), 0, 4));",
     "return shut(out, at, be(out, open(out, at, 'R'), 3, 4));"),
    ('wire: a transaction that is open is said to be idle', 'src/wire.cho',
     "        c = 'T';",
     "        c = 'I';"),
    ('wire: a transaction that has failed is said to be open', 'src/wire.cho',
     "        c = 'E';",
     "        c = 'T';"),
    ('wire: a tag is not ended', 'src/wire.cho',
     '    return shut(out, at, zero(out, b + tn));',
     '    return shut(out, at, b + tn);'),
    ('wire: a bigint is said to be four bytes', 'src/wire.cho',
     '    if oid == 20 {\n        return 8;',
     '    if oid == 20 {\n        return 4;'),
    ('wire: a text is said to be of a fixed size', 'src/wire.cho',
     '    return 65535;\n}',
     '    return 0;\n}'),
    ('wire: a column is said to come from a table', 'src/wire.cho',
     '        p = be(out, be(out, p, 0, 4), 0, 2);\n        p = be(out, be(out, p, oid, 4)',
     '        p = be(out, be(out, p, 1, 4), 0, 2);\n        p = be(out, be(out, p, oid, 4)'),
    ('wire: a column has a type modifier', 'src/wire.cho',
     'p = be(out, be(out, p, 4294967295, 4), 0, 2);',
     'p = be(out, be(out, p, 0, 4), 0, 2);'),
    ('wire: a null is an empty string', 'src/wire.cho',
     '            p = build.put_be(out, p, 4294967295, 4);',
     '            p = build.put_be(out, p, 0, 4);'),
    ('wire: an error says its severity once', 'src/wire.cho',
     "p = be(out, p, 'S' + 3 * side, 1);",
     "p = be(out, p, 'S' + 0 * side, 1);"),
    ('wire: an error that ends the connection is not said to', 'src/wire.cho',
     '        if fatal {\n            p = text(out, p, "FATAL");',
     '        if false {\n            p = text(out, p, "FATAL");'),
    ('wire: a semicolon is part of the statement', 'src/wire.cho',
     "    if e > 0 && int_of(body[e - 1]) == ';' {",
     '    if false {'),
    ('wire: a query need not be a string', 'src/wire.cho',
     '    if e == 0 || int_of(body[e - 1]) != 0 {',
     '    if e == 0 {'),
    ('wire: a refusal has another SQLSTATE', 'src/wire.cho',
     '    return "0A000";',
     '    return "XX000";'),
    ('serve: a commit is acknowledged before it is on the disk', 'src/serve.cho',
     '            if session.state(st[8..16]) == session.idle() {\n                let seq = pstore.commit(',
     '            if false {\n                let seq = pstore.commit('),
    ("serve: what a statement wrote is not the branch's", 'src/serve.cho',
     '            roots[0] = nr;\n            if session.state',
     '            if session.state'),
    ('serve: a connection that ends in a transaction leaves it open', 'src/serve.cho',
     '    if st[0] == 2 && session.state(st[8..16]) != session.idle() && gs[g_stop()] == 0 {\n        pager.begin(pg);',
     '    if false {\n        pager.begin(pg);'),
    ('serve: a client from anywhere is served', 'src/serve.cho',
     '                        if !from_here(tw, a) {',
     '                        if false {'),
    ('serve: BEGIN in a failed transaction has another SQLSTATE', 'src/serve.cho',
     'p = wire.error(out, p, false, "25P02",',
     'p = wire.error(out, p, false, "25P01",'),
    ('serve: an error is a refusal', 'src/serve.cho',
     '            } else if said == 0 && o == drive.o_error() {',
     '            } else if false {'),
    ('serve: what follows a message in the buffer is lost', 'src/serve.cho',
     '        buf[j] = buf[n + j];',
     '        buf[j] = buf[j];'),
    ('serve: what a client sent after its startup is lost', 'src/serve.cho',
     '    st[1] = shift(buf, 4 + n, st[1]);',
     '    st[1] = 0;'),
    ('serve: an SSLRequest is answered yes', 'src/serve.cho',
     "        out[0] = byte_of('N');",
     "        out[0] = byte_of('S');"),
    ('serve: an empty query is run', 'src/serve.cho',
     '                    } else if e == 0 {\n                        op = wire.ready(',
     '                    } else if false {\n                        op = wire.ready('),
    ('serve: a row that does not fit after the others is the end', 'src/serve.cho',
     '                        if next < 0 && p > 0 {',
     '                        if false {'),
    ('serve: a Terminate is no end', 'src/serve.cho',
     "                if t == 'X' {\n                    st[3] = 1;",
     "                if t == 'X' {\n                    st[3] = 0;"),
    ('serve: a Sync does not end the skipping', 'src/serve.cho',
     '                    st[2] = 0;\n                    xi[5] = 0;',
     '                    xi[5] = 0;'),
    ('wire: a format that is not text is taken for text', 'src/wire.cho',
     '        if commit.be(body, at + 2 + size * i, size) != 0 {',
     '        if false {'),
    ('wire: a null among the values is a value of a huge length', 'src/wire.cho',
     '        if l != 4294967295 {\n            if l > len(body)',
     '        if true {\n            if l > len(body)'),
    ('serve: a name is prepared twice', 'src/serve.cho',
     '        if named(ar, xi, body[0..ne]) >= 0 {',
     '        if false {'),
    ("serve: a closed statement's place is not used again", 'src/serve.cho',
     '        while k < xi[1] && xi[8 + 4 * k + 1] >= 0 {',
     '        while k < xi[1] {'),
    ('serve: a named portal is the unnamed one', 'src/serve.cho',
     '    if pe != 0 {\n        return fails(out, at, st, wire.refused_state(), "cancho-db: refused ", "named-portal");',
     '    if false {\n        return fails(out, at, st, wire.refused_state(), "cancho-db: refused ", "named-portal");'),
    ('serve: a name never prepared is the unnamed statement', 'src/serve.cho',
     '    if which < 0 && (se > pe + 1 || xi[0] < 0) {',
     '    if which < 0 && xi[0] < 0 {'),
    ('serve: more values than the engine binds are refused late', 'src/serve.cho',
     '    if nv > 64 || ve - fe - 2 - 4 * nv > 65536 - 256 {',
     '    if ve - fe - 2 - 4 * nv > 65536 - 256 {'),
    ('serve: an Execute with no portal runs', 'src/serve.cho',
     '    if pe != 0 || xi[3] == 0 - 2 {\n        return fails(out, at, st, "34000", "cancho-db: no portal of that name", "");\n    }\n    if commit.be(',
     '    if pe != 0 {\n        return fails(out, at, st, "34000", "cancho-db: no portal of that name", "");\n    }\n    if commit.be('),
    ('serve: a row limit is ignored', 'src/serve.cho',
     '    if commit.be(body, pe + 1, 4) != 0 {',
     '    if false {'),
    ('serve: a second Execute before the Sync runs', 'src/serve.cho',
     '    if xi[5] > 0 && session.state(st[8..16]) == session.idle() {',
     '    if false {'),
    ('serve: a second Execute is refused in a transaction too', 'src/serve.cho',
     '    if xi[5] > 0 && session.state(st[8..16]) == session.idle() {',
     '    if xi[5] > 0 {'),
    ('serve: a portal is run again', 'src/serve.cho',
     '    // the portal is run once\n    xi[3] = 0 - 2;\n',
     '    // the portal is run once\n'),
    ('serve: a description asked for is not sent', 'src/serve.cho',
     '    if xi[4] == 1 {\n        ext = 1;',
     '    if xi[4] == 1 {\n        ext = 2;'),
    ('serve: an empty statement is run', 'src/serve.cho',
     '    if sl == 0 {',
     '    if false {'),
    ('serve: a statement is described before values are bound', 'src/serve.cho',
     "    if int_of(body[0]) == 'S' {\n        // the types of a statement's parameters",
     "    if false {\n        // the types of a statement's parameters"),
    ('serve: a closed statement stays', 'src/serve.cho',
     '            xi[8 + 4 * k + 1] = 0 - 1;\n',
     ''),
    ('serve: the unnamed statement closed stays', 'src/serve.cho',
     '    } else if len(body) == 2 {\n        xi[0] = 0 - 1;',
     '    } else if len(body) == 2 {\n        xi[0] = xi[0];'),
    ('serve: a portal closed stays', 'src/serve.cho',
     '        if len(body) == 2 {\n            xi[3] = 0 - 2;\n            xi[4] = 0;\n        }',
     '        if len(body) == 2 {\n            xi[4] = 0;\n        }'),
    ('serve: a portal outlives the unnamed statement it was bound to', 'src/serve.cho',
     '        xi[0] = copy(body, ne + 1, sl, ar, 0);\n        if xi[3] == 0 - 1 {\n            xi[3] = 0 - 2;\n        }',
     '        xi[0] = copy(body, ne + 1, sl, ar, 0);'),
    ('serve: a statement run by name is described', 'src/serve.cho',
     '                    if ext != 2 {',
     '                    if true {'),
    ('serve: a command run by name says NoData', 'src/serve.cho',
     '                } else if ext == 1 {',
     '                } else if ext != 0 {'),
    ('serve: an error at an Execute skips nothing', 'src/serve.cho',
     '            } else if failed {\n                st[2] = 1;',
     '            } else if failed {\n                st[2] = 0;'),
    ('serve: a simple query keeps the unnamed statement', 'src/serve.cho',
     '                    xi[0] = 0 - 1;\n                    xi[3] = 0 - 2;\n                    xi[4] = 0;\n                    let e = wire.query_end(',
     '                    let e = wire.query_end('),
    ('serve: answers wait for more than the client', 'src/serve.cho',
     "    } else if op > 0 {\n        // the connection gets what was answered before anyone else's statement runs\n        if !push(tab, slot, gs, out[0..op]) {",
     "    } else if false {\n        // the connection gets what was answered before anyone else's statement runs\n        if !push(tab, slot, gs, out[0..op]) {"),
    ('serve: a Flush after a Describe is waited on', 'src/serve.cho',
     '                        if xi[4] == 1 {',
     '                        if false {'),
    ('serve: a connection has the statements of the last', 'src/serve.cho',
     '                            forget(xis[index_size() * a..index_size() * a + index_size()]);\n',
     ''),
    ('serve: a null bound is an empty string', 'src/serve.cho',
     '        if l == 4294967295 {\n            bound = exec.param_add(w, vals[0..0], true);',
     '        if l == 4294967295 {\n            bound = exec.param_add(w, vals[0..0], false);'),
    ('serve: a function call is not refused', 'src/serve.cho',
     '                        op = fails(out, op, st, wire.refused_state(), "cancho-db: refused ", "function-call");',
     '                        op = op;'),
    ('serve: a buffer that is full is not sent before it is written again', 'src/serve.cho',
     '                            if !push(tab, slot, gs, out[0..p]) {\n                                next = 0 - 1;',
     '                            if false {\n                                next = 0 - 1;'),
    ('serve: types given for parameters are ignored', 'src/serve.cho',
     '    if te == 0 - 2 {',
     '    if false {'),
    ('serve: a connection in a transaction does not have the database to itself', 'src/serve.cho',
     '                                        if st[0] == 2 && session.state(st[8..16]) != session.idle() {\n                                            gs[g_owner()] = slot + 1;',
     '                                        if st[0] == 2 && session.state(st[8..16]) != session.idle() {\n                                            gs[g_owner()] = 0;'),
    ('serve: a transaction that ended still has the database', 'src/serve.cho',
     '                                        } else if gs[g_owner()] == slot + 1 {\n                                            gs[g_owner()] = 0;',
     '                                        } else if gs[g_owner()] == slot + 1 {\n                                            gs[g_owner()] = slot + 1;'),
    ("serve: an Execute does not wait for another's transaction", 'src/serve.cho',
     "            } else if (t == 'Q' || t == 'E' && st[2] == 0) && !free {",
     "            } else if t == 'Q' && !free {"),
    ('serve: a connection that ends keeps the database', 'src/serve.cho',
     '    if gs[g_owner()] == slot + 1 {\n        gs[g_owner()] = 0;\n    }\n    conns.close(tab, slot);',
     '    conns.close(tab, slot);'),
    ('serve: a transaction may idle for ever while another waits', 'src/serve.cho',
     '                            if waiting && gs[g_now()] - sts[stride() * owner + 5] > gs[g_idle_ms()] {',
     '                            if false {'),
    ('serve: a transaction that idles is ended with nobody waiting', 'src/serve.cho',
     '                            if waiting && gs[g_now()] - sts[stride() * owner + 5] > gs[g_idle_ms()] {',
     '                            if gs[g_now()] - sts[stride() * owner + 5] > gs[g_idle_ms()] {'),
    ('serve: a connection beyond the places is served', 'src/serve.cho',
     '                        } else if a >= max_clients() {',
     '                        } else if false {'),
    ('serve: a message too long to hold is waited for', 'src/serve.cho',
     '            } else if n > len(buf) {',
     '            } else if false {'),
    ('serve: the rest of a message too long is read as messages', 'src/serve.cho',
     '                st[4] = n - st[1];\n',
     ''),
    ('serve: a client that takes none of its answer is waited on for ever', 'src/serve.cho',
     '                if !writable(tab, slot, gs[g_write_ms()]) {\n                    return false;\n                }',
     '                writable(tab, slot, gs[g_write_ms()]);'),
    ('serve: a client that closed is not noticed', 'src/serve.cho',
     '            Received::End => {\n                st[16] = 1;',
     '            Received::End => {\n                st[16] = 0;'),
    ('serve: a statement that waits is not counted as waiting', 'src/serve.cho',
     '                st[7] = 1;\n',
     ''),
    ('serve: a message of length under four is read', 'src/serve.cho',
     '            if n < 5 {',
     '            if false {'),
    ('serve: a message is whole one byte early', 'src/serve.cho',
     '            } else if st[1] < n {',
     '            } else if st[1] < n - 1 {'),
    ('serve: with a key no commit is recorded', 'src/serve.cho',
     '            if gs[g_logs()] == 1 {\n                kn = 32;\n            }',
     ''),
    ('login: with a root key a startup is served without a password', 'src/serve.cho',
     '    } else if kind == login.kind_startup() && gs[g_login()] == 1 {\n        // a login',
     '    } else if false {\n        // a login'),
    ('login: any password is right', 'src/serve.cho',
     '    if rule != login.login_ok() {\n        xi[token_len()] = 0;',
     '    if false {\n        xi[token_len()] = 0;'),
    ('login: a message that is no password is taken for one', 'src/serve.cho',
     "    if int_of(buf[0]) != 'p' || n < 6 || n > len(buf) {",
     '    if n < 6 || n > len(buf) {'),
    ('login: any database is the branch', 'src/serve.cho',
     '                xi[token_len()] = copy(buf, 4 + at[2], at[3], ar, token_at()) - token_at();',
     '                xi[token_len()] = copy("main", 0, 4, ar, token_at()) - token_at();'),
    ("login: the clock is at 0 when a token's expiry is checked", 'src/serve.cho',
     '            let now = gs[g_now()];\n            rule = login.check(',
     '            let now = 0;\n            rule = login.check('),
    ('login: the token does not stay with the connection', 'src/serve.cho',
     '    xi[token_len()] = tl;\n',
     '    xi[token_len()] = 0;\n'),
    ('login: a statement is held against no token', 'src/serve.cho',
     'ar[token_at()..token_at() + xi[token_len()]], 0, out, op, roots, st);',
     'ar[token_at()..token_at()], 0, out, op, roots, st);'),
    ('login: an Execute is held against no token', 'src/serve.cho',
     '    let tl = xi[token_len()];\n',
     '    let tl = 0;\n'),
    ("login: a denial is answered as a refusal of the engine's", 'src/serve.cho',
     '            } else if said == 0 && o == drive.o_denied() {',
     '            } else if false {'),
    ('login: a record does not name its token', 'src/serve.cho',
     '                token.prefix_id(tk, token.blocks(tk), who[0..32]);\n',
     ''),
    ('login: a record has no time', 'src/serve.cho',
     '                build.put_be(who, 64, gs[g_now()], 8);\n',
     ''),
    ('login: the token is not kept with the log', 'src/serve.cho',
     '                wn = facts.who_fixed() + len(tk);',
     '                wn = facts.who_fixed();'),
    ('login: the effects of a statement are not held against the token', 'src/drive.cho',
     '        if !permitted(heap, tk, e) {\n            done(hw, o_denied(), kind);\n            return root;\n        }\n',
     ''),
    ('login: what a statement returns is not held against the token', 'src/drive.cho',
     '                if !permitted(heap, tk, ir2[0..l2]) {',
     '                if false {'),
    ('login: a sequence is made whatever the token', 'src/drive.cho',
     '        } else if !permitted_name(tk, sql, contents(m.tb), contents(m.nb)[6 * top + 1], 2) {\n            done(hw, o_denied(), 2);\n            return root;\n        } else {\n            rc = execw.create_sequence(',
     '        } else {\n            rc = execw.create_sequence('),
    ('login: a table is truncated whatever the token', 'src/drive.cho',
     '        } else if !permitted_name(tk, sql, contents(m.tb), contents(m.nb)[6 * top + 1], 1) {',
     '        } else if false {'),
    ('login: a truncate is a definition', 'src/drive.cho',
     'contents(m.nb)[6 * top + 1], 1) {',
     'contents(m.nb)[6 * top + 1], 2) {'),
    ('login: a table is renamed whatever the token', 'src/drive.cho',
     '        } else if !permitted_name(tk, sql, contents(m.tb), contents(m.nb)[6 * top + 1], 2) || !permitted_name(tk, sql, contents(m.tb), contents(m.nb)[6 * top + 4], 2) {',
     '        } else if false {'),
    ('login: one effect allowed is enough', 'src/drive.cho',
     '                yes = allows(tk, int_of(key[0]), key[1..len(key)]);',
     '                yes = allows(tk, int_of(key[0]), key[1..len(key)]) || i > 0;'),
    ("login: a record's time is 0", 'src/facts.cho',
     'zero[0..0], chg, st, 0, zero[0..0], commit.be(who, 64, 8));',
     'zero[0..0], chg, st, 0, zero[0..0], 0);'),
    ("login: a record's principal is its token's id", 'src/facts.cho',
     'effs[0..el], who[0..32], who[32..64],',
     'effs[0..el], who[0..32], who[0..32],'),
    ('serve: a place is not freed when its connection ends', 'src/serve.cho',
     '    conns.close(tab, slot);\n    st[0] = 0;',
     '    conns.close(tab, slot);'),
    ('reclaim: the pages left behind are never looked for', 'src/serve.cho',
     '    if pager.free_count(pg) > 0 || pager.next_page(pg) < gs[g_sweep_at()] {\n        return 0;\n    }',
     '    if pager.next_page(pg) >= 0 {\n        return 0;\n    }'),
    ('reclaim: after one sweep there is no other until the server starts again', 'src/serve.cho',
     '    gs[g_sweep_at()] = next;',
     '    gs[g_sweep_at()] = next + 100000000;'),
    ('disk: a commit the page file refused is acknowledged', 'src/serve.cho',
     '                if seq < 0 {\n                    nr = seq;\n                } else {\n                    gs[g_seq()] = seq;',
     '                if false {\n                    nr = seq;\n                } else {\n                    gs[g_seq()] = seq;'),
    ('disk: the server goes on after the page file refused a write', 'src/serve.cho',
     '        if nr < 0 {\n            gs[g_stop()] = 7;\n            push(',
     '        if nr < 0 {\n            gs[g_stop()] = 0;\n            push('),
]


# The export tool (docs/m3-engine.md 6av): judged by tests/engine_log.py with the mutant as the tool; those of the race, by tests/engine_wire.py.
EXPORT = [
    ("export: the anchor's id is the first commit's", 'proxy/logexport.cho',
     '        build.id(rec[4..n - 64], ident);',
     '        if seq == 0 {\n            build.id(rec[4..n - 64], ident);\n        }'),
    ('export: `log N` is the whole log', 'proxy/logexport.cho',
     'status = put_log(io, pg, w, root, stop, rec);',
     'status = put_log(io, pg, w, root, n, rec);'),
    ('export: `facts N` is every fact', 'proxy/logexport.cho',
     'status = put_facts(io, pg, w, root, stop, rec);',
     'status = put_facts(io, pg, w, root, n, rec);'),
    ('export: one commit more than there are is not behind', 'proxy/logexport.cho',
     'if status == 0 && upto > n {',
     'if status == 0 && upto > n + 1 {'),
    ('export: the rows now are given for an earlier head', 'proxy/logexport.cho',
     'if upto >= 0 && upto != n {',
     'if upto >= 0 && upto > n {'),
    ('export: beside: a commit made meanwhile is not noticed', 'proxy/logexport.cho',
     'if state_of(hh, fsr, arg(g, 1), contents(rw)) != seq {',
     'if state_of(hh, fsr, arg(g, 1), contents(rw)) < 0 {'),
    ("export: every fact is under the first commit's id", 'proxy/logexport.cho',
     '                if seq != of {',
     '                if of < 0 {'),
    ("export: a fact's hashes are left out", 'proxy/logexport.cho',
     'if int_of(fv[33 * side]) == 1 {',
     'if int_of(fv[33 * side]) == 2 {'),
    ('export: the statements are given for the tokens', 'proxy/logexport.cho',
     'status = put_kept(io, pg, w, root, 7);',
     'status = put_kept(io, pg, w, root, 8);'),
    ('export: tables late in the alphabet are not dumped', 'proxy/logexport.cho',
     'if int_of(at[4]) > 4 {',
     "if int_of(at[4]) > 4 && int_of(at[4]) < 'n' {"),
    ('export: a file with no log exports an empty one', 'proxy/logexport.cho',
     'status = no_log();',
     'status = 0;'),
    ('export: a count that is not a number is no count', 'proxy/logexport.cho',
     'good = upto >= 0;',
     'good = true;'),
    ('export: a count of 13 digits is read', 'proxy/logexport.cho',
     'len(text) > 12',
     'len(text) > 13'),
    ("export: a row's two salts are the same one", 'proxy/logexport.cho',
     'put_hex(io, contents(w.cur), 16, 32);',
     'put_hex(io, contents(w.cur), 0, 16);'),
    ('export: a refusal ends with status 0', 'proxy/logexport.cho',
     '            if status != usage() {\n                status = 1;',
     '            if status != usage() {\n                status = 0;'),
    ('export: a damaged record ends the log quietly', 'proxy/logexport.cho',
     '    if n < 0 {\n        return 0 - damaged();\n    }\n    return seq;',
     '    return seq;'),
    ('export: a page file that is not one is an empty database', 'proxy/logexport.cho',
     '} else if seq < 0 {\n                                            status = damaged();',
     '} else if seq < 0 {\n                                            status = 0;'),
]


def run_export(cancho):
    """Each mutant is an export tool of its own, held against what the test assembles from the test program's output (build/enginecheck, not mutated here)."""
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in EXPORT if not only or only in m[0]]
    srcs = ("lex.cho", "parse.cho", "stmt.cho", "lower.cho", "state.cho", "commit.cho", "build.cho", "row.cho", "eval.cho", "pager.cho", "btree.cho", "pstore.cho", "tables.cho", "exec.cho", "execs.cho",
            "execw.cho", "execd.cho", "facts.cho", "token.cho", "ir.cho")
    survivors = []
    for label, rel, old, new in table:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            text = (ROOT / rel).read_text()
            if text.count(old) != 1:
                print("STALE  %-48s original text occurs %d times" % (label, text.count(old)), flush=True)
                survivors.append(label)
                continue
            (work / "logexport.cho").write_text(text.replace(old, new))
            exe = work / "logexport"
            b = subprocess.run([cancho, "build", "--std", str(work / "logexport.cho")] + [str(ROOT / "src" / x) for x in srcs] + ["-o", str(exe)], capture_output=True, text=True)
            if b.returncode != 0:
                print("BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]), flush=True)
                survivors.append(label)
                continue
            env = dict(os.environ, LOGEXPORT=str(exe))
            if label.startswith("export: beside"):
                cmd = [sys.executable, str(ROOT / "tests/engine_wire.py"), str(ROOT / "build/engine"), str(ROOT / "build/enginecheck"), "300", "1"]
            else:
                cmd = [sys.executable, str(ROOT / "tests/engine_log.py"), str(ROOT / "build/enginecheck"), "300", "1"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)
            if r.returncode != 0:
                first = [l for l in (r.stdout + r.stderr).splitlines() if l.startswith("FAIL")]
                print("killed   %-46s %s" % (label, (first[0] if first else "a crash")[:90]), flush=True)
            else:
                print("SURVIVED %-46s the test accepts what it wrote" % label, flush=True)
                survivors.append(label)
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


def run_wire(cancho):
    """Each mutant is a server of its own, built and held against the test program (build/enginecheck, which is not mutated here)."""
    import concurrent.futures
    import threading
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in WIRE if not only or only in m[0]]
    srcs = ("lex.cho", "parse.cho", "stmt.cho", "lower.cho", "state.cho", "commit.cho", "build.cho", "row.cho", "eval.cho", "pager.cho", "btree.cho", "pstore.cho", "tables.cho", "exec.cho", "execs.cho",
            "execw.cho", "execd.cho", "answer.cho", "drive.cho", "facts.cho", "session.cho", "wire.cho", "serve.cho", "login.cho", "token.cho", "ir.cho")

    def one(mutant):
        label, rel, old, new = mutant
        db = "cdb_wiremut_" + "".join(c for c in threading.current_thread().name if c.isdigit())
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                return label, "STALE  %-48s original text occurs %d times" % (label, text.count(old)), True
            f.write_text(text.replace(old, new))
            exe = work / "engine"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/engine.cho")] + [str(work / "src" / x) for x in srcs] + ["-o", str(exe)], capture_output=True, text=True)
            if b.returncode != 0:
                return label, "BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]), True
            try:
                r = subprocess.run([sys.executable, str(ROOT / "tests/engine_wire.py"), str(exe), str(ROOT / "build/enginecheck"), "300", "1"], capture_output=True, text=True, timeout=600, env=dict(os.environ, E2E_DB=db))
                rc, out = r.returncode, r.stdout + r.stderr
            except subprocess.TimeoutExpired:
                rc, out = 1, "FAIL timed out"
            if rc != 0:
                first = [l for l in out.splitlines() if l.startswith("FAIL")] or [l for l in out.splitlines() if l.strip()][-1:]
                return label, "killed   %-46s %s" % (label, (first[0] if first else "a crash")[:90]), False
            return label, "SURVIVED %-46s the server answers as the test program" % label, True

    survivors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(4, os.cpu_count() or 1))) as pool:
        for label, line, alive in pool.map(one, table):
            print(line, flush=True)
            if alive:
                survivors.append(label)
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


def run_engine(cancho):
    """Each mutant is built and judged on its own, so several are run at once (a database a worker): the group is the longest of the gate."""
    import concurrent.futures
    import threading
    only = os.environ.get("MUTANT_ONLY")
    table = [m for m in ENGINE if not only or only in m[0]]
    srcs = ("lex.cho", "parse.cho", "stmt.cho", "lower.cho", "state.cho", "commit.cho", "build.cho", "row.cho", "eval.cho", "pager.cho", "btree.cho", "pstore.cho", "tables.cho", "exec.cho", "execs.cho", "execw.cho", "execd.cho", "answer.cho", "drive.cho", "facts.cho", "session.cho", "token.cho", "ir.cho")

    def one(mutant):
        label, rel, old, new = mutant
        db = "cdb_enginemut_" + "".join(c for c in threading.current_thread().name if c.isdigit())
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            f = work / rel
            text = f.read_text()
            if text.count(old) != 1:
                return label, "STALE  %-48s original text occurs %d times" % (label, text.count(old)), True
            f.write_text(text.replace(old, new))
            exe = work / "enginecheck"
            b = subprocess.run([cancho, "build", "--std", str(ROOT / "proxy/enginecheck.cho")] + [str(work / "src" / x) for x in srcs] + ["-o", str(exe)], capture_output=True, text=True)
            if b.returncode != 0:
                return label, "BROKEN %-48s does not build: %s" % (label, (b.stdout + b.stderr).strip()[:160]), True
            if label.startswith(("log: ", "stmts: ")):
                # the log's mutants are judged by the verifiers (tests/engine_log.py), which need no database
                r = subprocess.run([sys.executable, str(ROOT / "tests/engine_log.py"), str(exe), "300", "1"], capture_output=True, text=True, timeout=900)
                if r.returncode != 0:
                    first = [l for l in (r.stdout + r.stderr).splitlines() if l.startswith("FAIL")]
                    return label, "killed   %-46s %s" % (label, (first[0] if first else "a crash")[:90]), False
                return label, "SURVIVED %-46s the verifiers accept the log" % label, True
            for seed in ("1", "2", "3"):
                try:
                    r = subprocess.run([sys.executable, str(ROOT / "tests/engine_check.py"), str(exe), "2500", seed], capture_output=True, text=True, timeout=900, env=dict(os.environ, E2E_DB=db))
                    rc, out = r.returncode, r.stdout + r.stderr
                except subprocess.TimeoutExpired:
                    rc, out = 1, "FAIL timed out"
                if rc != 0:
                    first = [l for l in out.splitlines() if l.startswith("FAIL")] or [l for l in out.splitlines() if l.startswith("engine_check:")][-1:]
                    return label, "killed   %-46s seed %s: %s" % (label, seed, (first[0] if first else "a crash")[:80]), False
            return label, "SURVIVED %-46s every statement agrees" % label, True

    survivors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(4, os.cpu_count() or 1))) as pool:
        for label, line, alive in pool.map(one, table):
            print(line, flush=True)
            if alive:
                survivors.append(label)
    print("%d mutants, %d not killed" % (len(table), len(survivors)))
    return 1 if survivors else 0


def run(kind, cancho):
    if kind == "engine":
        return run_engine(cancho)
    if kind == "wire":
        return run_wire(cancho)
    if kind == "export":
        return run_export(cancho)
    if kind == "guard":
        return run_guard(cancho)
    if kind == "build":
        return run_build(cancho)
    if kind == "store":
        return run_store(cancho)
    if kind == "btree":
        return run_btree(cancho)
    if kind == "row":
        return run_row(cancho)
    if kind == "eval":
        return run_eval(cancho)
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
