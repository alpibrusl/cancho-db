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


def script(seed, commits=6, ops=22):
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
    for seed in (2, 3):
        lines, snaps, at = script(seed)
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
                        out2 = run(path, ["load", "put 0 %s abcd" % KEYS[59].hex(), "commit"])
                        out3 = run(path, ["load"] + state_lines())
                        want3 = list(before)
                        want3[59] = "val abcd"
                        ok = out2[2] == "seq %d" % (seq + 1) and out3[0] == "loaded %d" % (seq + 1) and out3[1:] == want3
                    if not ok:
                        bad += 1
                        if bad <= 2:
                            print("FAIL seed %d: crash at step %d (torn %d): loaded %r" % (seed, n, torn, out[0]))
                    os.remove(path) if os.path.exists(path) else None
            check("seed %d: %d crash runs (every one of %d steps, torn writes of 0, 1, 100 and 4095 bytes): the state is the last whole commit's and the file goes on" % (seed, runs, total), bad == 0, bad)

    # the order of the calls, from the kernel's side: strace
    if subprocess.run(["which", "strace"], capture_output=True).returncode == 0:
        with tempfile.TemporaryDirectory() as d:
            trace = os.path.join(d, "trace")
            cmds = "init\nput 0 aa 01\ncommit\nput 0 ab 02\nput 1 ac 03\ncommit\nput 0 ad 04\ncommit\n"
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
