#!/usr/bin/env python3
"""What survives a restart, and a crash at every durable step (src/pstore.cho, docs/m3-engine.md D-M3-3 and gate 2, slice M3a).

    python3 tests/pstore_check.py build/btcheck

`proxy/btcheck.cho` can `init`, `commit` (the roots of its 16 slots become the state: the catalog page, a sync, a superblock, a sync) and, in a new process, `load`. Checked:

  * a database made, written and committed in one process is read back whole in the next, and the next commit goes on from its sequence number; uncommitted work is not there;
  * the file after a crash: the script of several commits is run once to count its durable steps (every page write and every sync) and to find the step that writes each commit's superblock; then for EVERY step n it is
    run again with the process stopped at n (the n-th write does not happen, or happens in part: 0, 1, 100 and 4095 bytes of it; nothing after it happens) and a new process loads the file. The state it finds must be
    exactly the state after the last commit whose superblock write was done before n (none: the empty database), never a mixture, and the file must stay usable: a write and a commit after the restart are read
    back by a third process together with the state the restart found;
  * a crash while the database is being made (`init`: the catalog, a sync, the superblock, a sync) leaves an empty file (the catalog page not whole), a file that is refused (err 102: the catalog is there and no superblock),
    or a database, never a database with the wrong content; a torn write of a superblock that reaches its
    last non-zero byte (27) is a whole one, so a torn write of 100 or 4095 bytes makes the commit visible, and one of 0 or 1 does not;
  * the order of the calls, read from the kernel's side with `strace` (a crash simulation cannot see a missing `fsync`: nothing is lost from the page cache): the pages and the catalog, `fsync`, the superblock of its
    parity alone, `fsync`, for the creation and for every commit;
  * the sweep (M3b, `pstore.sweep`): a deleted value is still in the file after one commit and a sweep and in no byte of it after a second commit and a sweep; a file rewritten for 60 commits stays small; work not
    yet committed survives a sweep; the superblock before the current one still works after one; random scripts with sweeps equal the model; the crash runs above include the sweep's own writes;
  * a bit flipped in the current superblock: the previous commit's state; in both superblocks, or in the catalog page the current one names: refused (err 102), not read as an empty database.
"""
import os
import random
import subprocess
import sys
import tempfile

EXE = sys.argv[1]
FAILED = []
KEYS = [bytes([i, i ^ 5]) for i in range(60)]


def check(name, ok, detail=""):
    if not ok:
        print("FAIL %s   %s" % (name, str(detail)[:400]))
        FAILED.append(name)


def run(path, lines, extra=()):
    r = subprocess.run([EXE, path] + [str(x) for x in extra], input="\n".join(lines) + "\n", capture_output=True, text=True)
    return r.stdout.split("\n")[:len(lines)]


def state_lines():
    return ["get %d %s" % (s, k.hex()) for s in (0, 1) for k in KEYS]


def expect_state(model):
    return [("val " + model[s][k].hex()) if k in model[s] else "none" for s in (0, 1) for k in KEYS]


def script(seed, commits=6, ops=22, sweeps=False):
    """The commands, the model after each commit, and the index in the command list of each `commit`."""
    rng = random.Random(seed)
    model = [{}, {}]
    lines, snaps, at = ["init"], [], []
    for c in range(commits):
        for _ in range(ops):
            s, k = rng.randrange(2), rng.choice(KEYS)
            r = rng.random()
            if r < .6:
                v = os.urandom(rng.choice([1, 8, 40, 300]))
                lines.append("put %d %s %s" % (s, k.hex(), v.hex()))
                model[s][k] = v
            elif r < .8:
                lines.append("del %d %s" % (s, k.hex()))
                model[s].pop(k, None)
            else:
                t = 1 - s
                lines.append("fork %d %d" % (s, t))
                model[t] = dict(model[s])
        lines.append("commit")
        at.append(len(lines) - 1)
        snaps.append([dict(model[0]), dict(model[1])])
        if sweeps and c % 2 == 1:
            lines.append("sweep")
    return lines, snaps, at


def main():
    # restarts without a crash
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "pages")
        lines, snaps, at = script(1)
        out = run(path, lines + ["steps"])
        check("the script runs: every commit answers seq N", all(out[i] == "seq %d" % (n + 1) for n, i in enumerate(at)), [out[i] for i in at])
        out = run(path, ["load"] + state_lines() + ["put 0 %s 01" % KEYS[0].hex(), "commit", "load"])
        check("a new process loads the last commit (sequence %d) and its whole state" % len(at), out[0] == "loaded %d" % len(at) and out[1:1 + 120] == expect_state(snaps[-1]), out[:2])
        check("... and goes on: its commit is number %d" % (len(at) + 1), out[121] == "ok " + out[121][3:] and out[122] == "seq %d" % (len(at) + 1) and out[123] == "loaded %d" % (len(at) + 1), out[121:])
        out = run(os.path.join(d, "fresh"), ["load", "put 0 aa 01", "commit"])
        check("an empty file is `empty`", out[0] == "empty", out)
        lines2 = lines[:at[2] + 1] + ["put 0 %s ff" % KEYS[1].hex()]
        run(os.path.join(d, "unc"), lines2)
        out = run(os.path.join(d, "unc"), ["load"] + state_lines())
        check("work after the last commit is not there in the next process", out[0] == "loaded 3" and out[1:] == expect_state(snaps[2]), out[:2])

    # a crash at every durable step
    for seed in (2, 3, 5):
        lines, snaps, at = script(seed, sweeps=(seed != 2))
        with tempfile.TemporaryDirectory() as d:
            probe = run(os.path.join(d, "probe"), [l for i, l in enumerate(lines)] + ["steps"] + [])
            # steps after each commit: run again asking for `steps` after every commit
            with_steps, pos = [], []
            for i, l in enumerate(lines):
                with_steps.append(l)
                if i in at:
                    with_steps.append("steps")
                    pos.append(len(with_steps) - 1)
            out = run(os.path.join(d, "probe2"), with_steps)
            after = [int(out[p].split()[1]) for p in pos]
            total = after[-1]
            super_step = [a - 1 for a in after]      # the superblock write is the step before the last sync of a commit
            init_steps = 4
            bad = 0
            runs = 0
            for n in range(1, total + 1):
                for torn in ((0, 1, 100, 4095) if True else (0,)):
                    path = os.path.join(d, "c%d_%d" % (n, torn))
                    run(path, lines, (n, torn))
                    runs += 1
                    out = run(path, ["load"] + state_lines())
                    # a superblock write is whole in effect if it reached the byte after the last one that is not zero (byte 27): a torn write of 100 or 4095 bytes is a whole one
                    visible = [c for c, s in enumerate(super_step) if s < n or (s == n and torn >= 27)]
                    if n <= init_steps:
                        want_first = "empty" if n == 1 else ("err 102" if n == 2 else ("loaded 0" if (n == 4 or torn >= 27) else "err 102"))
                        ok = out[0] == want_first and (want_first != "loaded 0" or out[1:] == expect_state([{}, {}]))
                    elif visible:
                        c = visible[-1]
                        ok = out[0] == "loaded %d" % (c + 1) and out[1:] == expect_state(snaps[c])
                    else:
                        ok = out[0] == "loaded 0" and out[1:] == expect_state([{}, {}])
                    if ok and n > init_steps and out[0].startswith("loaded"):
                        # the file is still usable: a write and a commit, read back with what was found
                        seq = int(out[0].split()[1])
                        before = out[1:]
                        out2 = run(path, ["load", "sweep", "put 0 %s abcd" % KEYS[59].hex(), "commit", "sweep"])
                        out3 = run(path, ["load"] + state_lines())
                        want3 = list(before)
                        want3[59] = "val abcd"
                        ok = out2[1].startswith("swept ") and out2[3] == "seq %d" % (seq + 1) and out2[4].startswith("swept ") and out3[0] == "loaded %d" % (seq + 1) and out3[1:] == want3
                    if not ok:
                        bad += 1
                        if bad <= 2:
                            print("FAIL seed %d: crash at step %d (torn %d): loaded %r" % (seed, n, torn, out[0]))
                    os.remove(path) if os.path.exists(path) else None
            check("seed %d: %d crash runs (every one of %d steps, torn writes of 0, 1, 100 and 4095 bytes): the state is the last whole commit's and the file goes on" % (seed, runs, total), bad == 0, bad)

    # the sweep (M3b): zero and reuse the pages nothing names
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "pages")
        marker = b"PERSONAL-DATA-" + bytes(range(65, 91)) * 4
        k = KEYS[3].hex()
        out = run(path, ["init", "put 0 %s %s" % (k, marker.hex()), "put 1 %s 01" % KEYS[4].hex(), "commit"])
        check("a value is in the file after its commit", marker in open(path, "rb").read(), out)
        out = run(path, ["load", "del 0 %s" % k, "commit", "sweep"])
        check("deleted, committed once and swept: the value is still in the file (the superblock before the current one names its page)", marker in open(path, "rb").read() and out[3].startswith("swept "), out)
        out = run(path, ["load", "put 1 %s 02" % KEYS[5].hex(), "commit", "sweep", "get 1 %s" % KEYS[4].hex()])
        raw = open(path, "rb").read()
        check("a second commit and a sweep later no byte of the file is the value's, and the rest is read back", marker not in raw and marker[:14] not in raw and out[4] == "val 01", out)
        out = run(path, ["load", "get 1 %s" % KEYS[4].hex(), "get 1 %s" % KEYS[5].hex(), "get 0 %s" % k])
        check("... by a new process too", out == ["loaded 3", "val 01", "val 02", "none"], out)

        # five values of 700 bytes fill one page: every one of them, wherever it sits in the page, is gone
        p5 = os.path.join(d, "five")
        marks = [b"MARK-%d-" % i + bytes([97 + i]) * 690 for i in range(5)]
        run(p5, ["init"] + ["put 0 %s %s" % (KEYS[i].hex(), m.hex()) for i, m in enumerate(marks)] + ["commit"])
        raw = open(p5, "rb").read()
        check("five values of 700 bytes are in the file, some in the second half of a page", all(m in raw for m in marks) and any(raw.find(m) % 4096 > 2048 for m in marks))
        run(p5, ["load"] + ["del 0 %s" % KEYS[i].hex() for i in range(5)] + ["commit", "put 1 aa 01", "commit", "sweep"])
        raw = open(p5, "rb").read()
        check("... and none of their bytes after the deletes, two commits and a sweep", not any(m[:8] in raw or m[-64:] in raw for m in marks))

        # the file stops growing: the same 40 keys rewritten for 60 commits
        def churn(pth, sweep):
            lines = ["init"]
            for c in range(60):
                lines += ["put 0 %s %s" % (KEYS[i].hex(), bytes([c, i]).hex() * 50) for i in range(40)] + ["commit"] + (["sweep"] if sweep else [])
            lines += ["get 0 %s" % KEYS[i].hex() for i in range(40)]
            o = run(pth, lines)
            return os.path.getsize(pth) // 4096, o[-40:] == ["val " + bytes([59, i]).hex() * 50 for i in range(40)]
        grown, ok1 = churn(os.path.join(d, "grow"), False)
        kept, ok2 = churn(os.path.join(d, "keep"), True)
        check("60 commits rewriting 40 keys: with a sweep after each the file stays small (%d pages against %d without) and the last values are read" % (kept, grown), ok1 and ok2 and kept * 5 < grown, (kept, grown, ok1, ok2))

        # work that is not committed is not swept away, and the superblock before the current one still works after a sweep
        p2 = os.path.join(d, "unc")
        out = run(p2, ["init", "put 0 aa 01", "commit", "put 0 ab 02", "sweep", "get 0 ab", "get 0 aa", "commit", "sweep"])
        check("a sweep keeps what is written and not yet committed", out[4].startswith("swept ") and out[5:7] == ["val 02", "val 01"], out)
        raw = bytearray(open(p2, "rb").read())
        cur = 1 + 2 % 2
        raw[cur * 4096 + 40] ^= 1
        open(p2, "wb").write(raw)
        out = run(p2, ["load", "get 0 aa", "get 0 ab"])
        check("after a sweep, a damaged current superblock still falls back to the commit before it, whole", out == ["loaded 1", "val 01", "none"], out)

        # random scripts with sweeps against the model, read back by a new process
        for seed in (11, 12, 13):
            lines, snaps, at = script(seed, commits=10, ops=30, sweeps=True)
            pth = os.path.join(d, "m%d" % seed)
            run(pth, lines)
            out = run(pth, ["load"] + state_lines())
            check("seed %d: ten commits with sweeps between: the state is the model's" % seed, out[0] == "loaded 10" and out[1:] == expect_state(snaps[-1]), out[:1])

    # the order of the calls, from the kernel's side: strace
    if subprocess.run(["which", "strace"], capture_output=True).returncode == 0:
        with tempfile.TemporaryDirectory() as d:
            trace = os.path.join(d, "trace")
            cmds = "init\nput 0 aa 01\ncommit\nput 0 ab 02\nput 1 ac 03\ncommit\nput 0 ad 04\ncommit\nsweep\n"
            subprocess.run(["strace", "-f", "-e", "trace=pwrite64,fsync", "-o", trace, EXE, os.path.join(d, "pages")], input=cmds, capture_output=True, text=True)
            ev = []
            for line in open(trace):
                if "pwrite64(" in line:
                    ev.append(("w", int(line.split(", ")[-1].split(")")[0])))
                elif "fsync(" in line:
                    ev.append(("f", 0))
            segs, cur = [], []
            for kind, off in ev:
                if kind == "f":
                    segs.append(cur)
                    cur = []
                else:
                    cur.append(off)
            supers = (4096, 8192)
            # init: [catalog] f [superblock 0 at page 1] f ; then each commit seq: [tree pages, catalog] f [superblock at page 1 + seq % 2] f
            swept = segs[-1] if segs else []
            segs = segs[:-1]
            check("a sweep writes its zeros and ends with an fsync (strace): %d pages zeroed, none of them a superblock" % len(swept), len(swept) >= 2 and not cur and all(o >= 3 * 4096 for o in swept), swept)
            ok = len(segs) == 2 + 2 * 3 and not cur
            if ok:
                ok = segs[0] == [12288] and segs[1] == [4096]
                for c in range(1, 4):
                    pre, sup = segs[2 * c], segs[2 * c + 1]
                    ok = ok and len(pre) >= 2 and all(o not in supers for o in pre) and sup == [4096 * (1 + c % 2)]
            check("the order of a commit, read from the kernel (strace): the pages and the catalog, fsync, the superblock of its parity alone, fsync; the database is made in the same order", ok, segs)
    else:
        print("pstore_check: strace is not installed: the order of the calls is not checked")

    # a damaged superblock
    with tempfile.TemporaryDirectory() as d:
        lines, snaps, at = script(4)
        path = os.path.join(d, "pages")
        run(path, lines)
        seq = len(at)
        cur, prev = 1 + seq % 2, 1 + (seq - 1) % 2
        def flipped(pages):
            p2 = os.path.join(d, "f%s" % "_".join(map(str, pages)))
            raw = bytearray(open(path, "rb").read())
            for pg in pages:
                raw[pg * 4096 + 40] ^= 1
            open(p2, "wb").write(raw)
            return p2
        out = run(flipped([cur]), ["load"] + state_lines())
        check("the current superblock flipped: the commit before it is current (loaded %d, its whole state)" % (seq - 1), out[0] == "loaded %d" % (seq - 1) and out[1:] == expect_state(snaps[seq - 2]), out[:2])
        out = run(flipped([cur, prev]), ["load"])
        check("both superblocks flipped: refused (err 102), not an empty database", out == ["err 102"], out)
        raw = open(path, "rb").read()
        cat = int.from_bytes(raw[cur * 4096 + 23:cur * 4096 + 27], "big")
        out = run(flipped([cat]), ["load"])
        check("the catalog page the current superblock names flipped: refused (err 102)", out == ["err 102"], out)
    print("pstore_check: %d failures" % len(FAILED))
    return 1 if FAILED else 0


sys.exit(main())
