#!/usr/bin/env python3
"""L3a at a size: thousands of commits on two branches, a fork, updates and deletes, with the live tables, against every verifier given; then the same session with one image, one row and one live line damaged. Both
verifiers must answer alike and the large one must not trap (a cancho region holds 64 KiB; what grows with the input is on the heap).

    python3 tests/l3a_scale.py "python3 tools/l3a.py" build/l3averify [COMMITS_PER_BRANCH]
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import gen_l3a as gen  # noqa: E402

VERIFIERS = sys.argv[1:3] if len(sys.argv) > 2 else ["python3 tools/l3a.py"]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 600
A, img, key = gen.A, gen.img, gen.key

w = gen.World()
rows = {}                                   # (branch, k) -> image


def commit(branch, changes):
    for t, k, o, n in changes:
        rows[(branch, k)] = n
    return w.commit(branch, changes)


serial = 0
for c in range(N):
    ch = []
    for _ in range(6):
        serial += 1
        ch.append((A["t"], key(serial), None, img(id=serial, v="a")))
    if c % 5 == 4:
        old = key(serial - 9)               # a row of an earlier commit
        ch.append((A["t"], old, rows[("main", old)], img(id=serial - 9, v="b")))
    commit("main", ch)
tip = w.ids[-1]
w.commit("side", [], parents=[tip], effects=(gen.C,))
w.live["side"] = dict(w.live["main"])
for (b, k), im in list(rows.items()):
    rows[("side", k)] = im
for c in range(N):
    ch = []
    for _ in range(4):
        serial += 1
        ch.append((A["u"], key(serial), None, img(id=serial, name="s")))
    victim = key(1 + c)                     # rows the fork inherited, removed one by one
    if ("side", victim) in rows and rows[("side", victim)] is not None:
        ch.append((A["t"], victim, rows[("side", victim)], None))
    commit("side", ch)
    if c % 7 == 0:
        commit("main", [(A["u"], key(10_000_000 + c), None, img(id=c, name="m"))])

tmp = Path(tempfile.mkdtemp())
(tmp / "x.log").write_bytes(w.log_bytes())
(tmp / "x.deltas").write_text(w.deltas_text())
(tmp / "x.live").write_text(w.live_text())


def run(deltas, live, log=None):
    outs = []
    for v in VERIFIERS:
        r = subprocess.run(v.split() + [str(log or tmp / "x.log"), "--deltas", str(deltas), "--live-dump", str(live)], capture_output=True, text=True, timeout=600)
        outs.append((r.returncode, r.stdout.strip(), r.stderr.strip()[:200]))
    return outs


failed = 0


def check(name, outs, want):
    global failed
    good = all(o[1] == want or (want.endswith("*") and o[1].startswith(want[:-1])) for o in outs) and all(o[0] in (0, 1) for o in outs)
    print("%s %s: %s" % ("ok  " if good else "FAIL", name, [o[1] or o[2] for o in outs]))
    failed += 0 if good else 1


outs = run(tmp / "x.deltas", tmp / "x.live")
check("the session verifies, tables compared", outs, "ok commits=%d facts=%d branches=2 final" % (len(w.ids), sum(len(gen.net([(r["table"], r["key"], r["old_image"], r["new_image"])])) for r in w.rows)))
lines = (tmp / "x.deltas").read_text().split("\n")
(tmp / "y.deltas").write_text("\n".join(lines[:len(lines) // 2] + lines[len(lines) // 2 + 1:]))
check("a delta row in the middle removed", run(tmp / "y.deltas", tmp / "x.live"), "reject rule=changes-mismatch record=*")
live = (tmp / "x.live").read_text().split("\n")
(tmp / "y.live").write_text("\n".join(live[:-3] + live[-2:]))
check("a live row removed", run(tmp / "x.deltas", tmp / "y.live"), "reject rule=replay-final record=-1")
print("%d commits, %d delta lines; %d failed" % (len(w.ids), len(lines), failed))
sys.exit(1 if failed else 0)
