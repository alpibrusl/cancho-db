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
    ("effect kind 5 allowed", "tools/verify.py", "if kind > 4:", "if kind > 5:"),
    ("effects: allow duplicates", "tools/verify.py", "not key > last", "key < last"),
    ("effects: unordered allowed", "tools/verify.py", "not key > last", "False"),
    ("effects: kind ignored", "tools/verify.py", "key = (kind, r.b16())", "key = (0, r.b16())"),
    ("check ok up to 2", "tools/verify.py", "if r.u8() > 1:", "if r.u8() > 2:"),
    ("nondet tag 3 allowed", "tools/verify.py", "        else:\n            raise Reject(\"bad-encoding\")\n    r.take(32); r.take(32)",
     "        else:\n            r.take(0)\n    r.take(32); r.take(32)"),
    ("trailing bytes allowed", "tools/verify.py", "if r.at != len(enc):", "if False:"),
    ("record limit off by one", "tools/verify.py", "if length > MAX_RECORD:", "if length >= MAX_RECORD:"),
    ("signature length off", "tools/verify.py", "< length + 64:", "< length + 63:"),
    ("duplicates allowed", "tools/verify.py", "if ident in seen:", "if False:"),
    ("signature unchecked", "tools/verify.py", "server.verify(sig, ident)", "pass"),
    ("sig over wrong domain", "tools/verify.py", "server.verify(sig, ident)", "server.verify(sig, hashlib.sha256(enc).digest())"),
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
    ("expected id checked before records", "tools/verify.py", "    while at < len(data):\n        if len(data) - at < 4:",
     "    if expect is not None and expect not in seen:\n        raise Reject(\"expected-missing\")\n    while at < len(data):\n        if len(data) - at < 4:"),
    ("magic unchecked", "tools/verify.py", "if data[:8] != MAGIC:", "if False:"),
    ("short header accepted", "tools/verify.py", "if len(data) < 40:", "if len(data) < 8:"),
    ("record index off by one", "tools/verify.py", "raise Reject(e.rule, index)", "raise Reject(e.rule, index + 1)"),
    ("signature after chain rules", "tools/verify.py", "            try:\n                server.verify(sig, ident)\n            except InvalidSignature:\n                raise Reject(\"bad-signature\")\n            if seq != count.get(branch, 0):",
     "            if seq != count.get(branch, 0):\n                raise Reject(\"seq-gap\")\n            try:\n                server.verify(sig, ident)\n            except InvalidSignature:\n                raise Reject(\"bad-signature\")\n            if False:"),
    ("decode after signature", "tools/verify.py", "            branch, seq, parents = decode(enc)\n            ident = hashlib.sha256(DOMAIN + enc).digest()\n            if ident in seen:",
     "            ident = hashlib.sha256(DOMAIN + enc).digest()\n            try:\n                server.verify(sig, ident)\n            except InvalidSignature:\n                raise Reject(\"bad-signature\")\n            branch, seq, parents = decode(enc)\n            if ident in seen:"),
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
                b = subprocess.run([cancho, "build", "--std", str(work / "src/commit.cho"),
                                    str(work / "src/verify.cho"), "-o", str(exe)], capture_output=True, text=True)
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
