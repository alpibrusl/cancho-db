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
    ("check ok up to 2", "tools/verify.py", "if r.u8() > 1:", "if r.u8() > 2:"),
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
    ("L2: effects checked before branch", "tools/verify.py", '    if any(not pattern_matches(b[1], branch) for b in blocks):\n        return "branch-denied"\n    if any(not block_permits_effect(b, e) for b in blocks for e in effects):\n        return "effect-denied"',
     '    if any(not block_permits_effect(b, e) for b in blocks for e in effects):\n        return "effect-denied"\n    if any(not pattern_matches(b[1], branch) for b in blocks):\n        return "branch-denied"'),
    ("L2: branch checked before principal", "tools/verify.py", '    if any(b[0] != ZERO32 and b[0] != principal for b in blocks):\n        return "principal-denied"\n    if any(not pattern_matches(b[1], branch) for b in blocks):\n        return "branch-denied"',
     '    if any(not pattern_matches(b[1], branch) for b in blocks):\n        return "branch-denied"\n    if any(b[0] != ZERO32 and b[0] != principal for b in blocks):\n        return "principal-denied"'),
    ("L2: principal checked before expiry", "tools/verify.py", '    if any(b[3] != NO_EXPIRY and time > b[3] for b in blocks):\n        return "token-expired"\n    if any(b[0] != ZERO32',
     '    if any(b[0] != ZERO32 and b[0] != principal for b in blocks):\n        return "principal-denied"\n    if any(b[3] != NO_EXPIRY and time > b[3] for b in blocks):\n        return "token-expired"\n    if any(b[0] != ZERO32'),
    ("L2: signature checked after revocation", "tools/verify.py", '    if not chain_valid(blocks, root):\n        return "token-bad-signature"\n    for k in range(1, len(blocks) + 1):\n        since = revoked.get(prefix_id(blocks, k))\n        if since is not None and since <= time:\n            return "token-revoked"',
     '    for k in range(1, len(blocks) + 1):\n        since = revoked.get(prefix_id(blocks, k))\n        if since is not None and since <= time:\n            return "token-revoked"\n    if not chain_valid(blocks, root):\n        return "token-bad-signature"'),
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
    ("record limit off by one", "src/verify.cho", "if length > 16777216 {", "if length >= 16777216 {"),
    ("signature length off", "src/verify.cho", "< length + 64 {", "< length + 63 {"),
    ("duplicates allowed", "src/verify.cho", "if is_dup {", "if false {"),
    ("signature unchecked", "src/verify.cho", "} else if crypto_ok(data[8..40], ident, sig) == 0 {", "} else if false {"),
    ("sig over wrong domain", "src/verify.cho", "crypto.sha256_update(sha, nul);\n", ""),
    ("seq may skip ahead", "src/verify.cho", "out[commit.f_seq_lo()] != count_here {", "out[commit.f_seq_lo()] < count_here {"),
    ("seq may repeat", "src/verify.cho", "out[commit.f_seq_lo()] != count_here {", "out[commit.f_seq_lo()] > count_here {"),
    ("seq high half ignored", "src/verify.cho", "if out[commit.f_seq_hi()] != 0 ||", "if false ||"),
    ("root may have 2 parents", "src/verify.cho", "if np == 2 {\n                                rule = commit.parent_count();\n                            } else if np == 1 {", "if np == 1 {"),
    ("fork parent unchecked", "src/verify.cho", "if !known {\n                                    rule = commit.parent_unknown();\n                                }\n                            }\n                        } else if np == 0 {", "if false {\n                                    rule = commit.parent_unknown();\n                                }\n                            }\n                        } else if np == 0 {"),
    ("seq>0 needs no parent", "src/verify.cho", "} else if np == 0 {\n                            rule = commit.parent_count();\n                        } else {", "} else if np == 0 {\n                            rule = 0;\n                        } else {"),
    ("first parent unchecked", "src/verify.cho", "rule = commit.parent_mismatch();", "rule = 0;"),
    ("merge parents may be equal", "src/verify.cho", "if same(enc[pat..pat + 32], enc[pat + 32..pat + 64]) {", "if false {"),
    ("merge parent may be unknown", "src/verify.cho", "                                    if !known {\n                                        rule = commit.parent_unknown();\n                                    }\n                                }\n                            }\n                        }\n\n",
     "                                }\n                            }\n                        }\n\n"),
    ("expected id unchecked", "src/verify.cho", "if rule == 0 && len(expect) == 32 {", "if false {"),
    ("magic unchecked", "src/verify.cho", "} else if !same(data[0..8], \"CHODBLG1\") {", "} else if false {"),
    ("short header accepted", "src/verify.cho", "} else if len(data) < 40 {", "} else if len(data) < 8 {"),
    ("record index off by one", "src/verify.cho", "bad_at = index;", "bad_at = index + 1;"),
    ("commit not counted per branch", "src/verify.cho", "counts = map.put(heap, counts, branch, count_here + 1);", "counts = map.put(heap, counts, branch, commits + 1);"),
    ("tip not updated", "src/verify.cho", "tips = map.put(heap, tips, branch, commits);", "tips = tips;"),
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
    ("L2: effects checked before branch", "src/l2.cho", "} else if token.branch_denied(tk, enc[bat..bat + out[commit.f_branch_len()]]) {\n                        rule = commit.branch_denied();\n                    } else if token.effect_denied(tk, enc, out[commit.f_effects_at()], out[commit.f_effects_n()]) {\n                        rule = commit.effect_denied();",
     "} else if token.effect_denied(tk, enc, out[commit.f_effects_at()], out[commit.f_effects_n()]) {\n                        rule = commit.effect_denied();\n                    } else if token.branch_denied(tk, enc[bat..bat + out[commit.f_branch_len()]]) {\n                        rule = commit.branch_denied();"),
]


# Mutants that cannot be killed because they change nothing observable, with the reason. Empty: every mutant above
# changes behaviour, and the ones that looked equivalent (the count guard against the bytes left) are not listed
# because they are not mutants here: removing the guard leaves every field read bounds-checked, so the verdict is the
# same and only the allocation is not bounded (spec §1), which a verdict cannot show.
EQUIVALENT = []


def run(kind, cancho):
    table = PY if kind == "py" else CHO
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
