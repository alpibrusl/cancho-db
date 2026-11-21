#!/usr/bin/env python3
"""The engine's statements across a crash at every durable step (docs/m3-engine.md gate 2, at the level of SQL).

    python3 tests/engine_crash.py build/enginecheck

A history of statements in six commits (creates, multi-row inserts, updates that change keys, deletes, a dropped table, sweeps) is run once whole, to learn at which step (a page write or an `fsync`,
src/pager.cho) each commit ends and what every table holds after it. Then it is run again from the same starting file once for every step n and for a write torn at 0 and at 100 bytes: the process can
write nothing from step n on, as if it had been killed there. A new process then opens the file. What it must find is known exactly: a commit's last two steps are the write of its superblock and the
`fsync` of it, so the tables are those after the last commit whose superblock was WRITTEN whole before step n (a write of it torn at 100 bytes may be the whole write, the rest of the page being zeros
before and after: then either answer is right) (the commit in flight counts once its superblock is in the file, even unsynced: a process that
died is not a machine that lost power, and nothing was acknowledged for it either way). Never anything else: not a table half updated, not a statement of the commit in flight, not an unreadable file.

After every restart a table is created, committed, and read back by a third process: the file a crash leaves is one that can be written to again.

The starting file is a database that was initialised whole. A crash while the two superblocks of a NEW file are first written leaves a file that is refused (`err -102`: it holds nothing and is not empty);
that case is checked too, and is a file to delete.
"""
import os
import shutil
import subprocess
import sys
import tempfile

EXE = sys.argv[1]
TABLES = ["t1", "t2", "t3"]
DUMP = ["select * from %s order by 1" % t for t in TABLES]


def rows(a, b, f):
    return ", ".join("(%d, %s)" % (k, f(k)) for k in range(a, b))


HISTORY = [
    ["create table t1 (k integer primary key, a integer not null, s text default 'd')",
     "insert into t1 (k, a) values " + rows(1, 31, lambda k: str(k * 7 % 11)),
     "insert into t1 values (40, 4, 'forty'), (41, 5, null)"],
    ["update t1 set a = a + 1 where k < 10",
     "delete from t1 where k > 25 and k < 40",
     "create table t2 (name text primary key, n bigint)",
     "insert into t2 values ('a', 1), ('b', 2), ('', 3), ('zz', null)",
     "!sweep"],
    ["update t1 set k = k + 100 where k < 5",
     "update t1 set s = 'x' where a = 3",
     "insert into t1 (k, a) values " + rows(50, 90, lambda k: "0"),
     "update t2 set n = 10 where name = 'b'"],
    ["drop table t2",
     "create table t3 (k smallint primary key, b boolean)",
     "insert into t3 values (1, true), (2, false), (3, null)",
     "!sweep"],
    ["delete from t1",
     "insert into t1 values (7, 7, 'seven')"],
    ["insert into t1 (k, a) values " + rows(100, 140, lambda k: str(k)),
     "update t3 set b = not b",
     "delete from t1 where a > 120",
     "!sweep"],
]


def run(path, lines, crash=None):
    args = [EXE, path] + ([str(crash[0]), str(crash[1])] if crash else [])
    r = subprocess.run(args, input="\n".join(lines) + "\n", capture_output=True, text=True)
    return r.returncode, r.stdout


def dump(path):
    rc, out = run(path, DUMP)
    return rc, out


def main():
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "base.db")
        rc, out = run(base, [])
        if rc != 0:
            raise SystemExit("engine_crash: a new database: status %d %s" % (rc, out))
        # the whole history once: where each commit ends, and what the tables hold after it
        whole = os.path.join(d, "whole.db")
        shutil.copy(base, whole)
        lines = []
        for block in HISTORY:
            lines += block + ["!commit", "!steps", "!mark"] + DUMP + ["!mark"]
        rc, out = run(whole, ["!mark"] + DUMP + ["!mark"] + lines)
        if rc != 0 or "refused engine" in out.replace("refused engine-unsupported", "") or "error " in out:
            raise SystemExit("engine_crash: the history does not run: status %d\n%s" % (rc, out[-600:]))
        chunks, cur = [], []
        for line in out.split("\n"):
            if line == "mark":
                chunks.append(cur)
                cur = []
            else:
                cur.append(line)
        chunks.append(cur)
        # chunks: [before first mark], dump0, [history 1 ... steps], dump1, ...
        states = [chunk for i, chunk in enumerate(chunks) if i % 2 == 1]
        ends = [int(line.split()[1]) for line in out.split("\n") if line.startswith("steps ")]
        if len(states) != len(HISTORY) + 1 or len(ends) != len(HISTORY):
            raise SystemExit("engine_crash: could not read the whole run (%d states, %d commits)" % (len(states), len(ends)))
        total = ends[-1]
        runs = 0
        seen = [0] * len(states)
        history = []
        for block in HISTORY:
            history += block + ["!commit"]
        for n in range(1, total + 1):
            for torn in (0, 100):
                path = os.path.join(d, "crash.db")
                shutil.copy(base, path)
                rc, out = run(path, history, (n, torn))
                if rc != 6 or "crashed" not in out:
                    raise SystemExit("engine_crash: step %d: the process did not stop there (status %d)" % (n, rc))
                want = sum(1 for e in ends if e - 1 < n)
                # a superblock is a few bytes at the head of a page of zeros: a write of it torn after those bytes is the whole write, and then the commit is there
                allowed = [want, want + 1] if torn > 0 and any(e - 1 == n for e in ends) else [want]
                rc, got = dump(path)
                if rc != 0:
                    raise SystemExit("engine_crash: step %d torn %d: the file does not open after the crash (status %d): %s" % (n, torn, rc, got[:200]))
                got = [line for line in got.split("\n")]
                which = [i for i in allowed if [e for e in states[i] if e] == [g for g in got if g]]
                if not which:
                    other = [i for i, s in enumerate(states) if [e for e in s if e] == [g for g in got if g]]
                    raise SystemExit("engine_crash: step %d torn %d: the tables are not those after commit %d (they are those after %s)" % (n, torn, want, other or "no commit at all"))
                want = which[0]
                exp = states[want]
                seen[want] += 1
                # the file can be written to again, and what is written is there for the next process
                rc, out = run(path, ["create table zz (k integer primary key)", "insert into zz values (%d)" % n, "!commit"])
                if rc != 0 or "committed" not in out:
                    raise SystemExit("engine_crash: step %d torn %d: no write after the restart: %s" % (n, torn, out[-200:]))
                rc, out = run(path, ["select * from zz"] + DUMP)
                if rc != 0 or "R %d" % n not in out:
                    raise SystemExit("engine_crash: step %d torn %d: the write after the restart is not there" % (n, torn))
                rest = [line for line in out.split("\n")[4:] if line]
                if rest != [e for e in exp if e]:
                    raise SystemExit("engine_crash: step %d torn %d: the write after the restart changed the other tables" % (n, torn))
                runs += 1
        if min(seen) == 0:
            raise SystemExit("engine_crash: some commit was never the one found after a crash: %s" % seen)
        # a crash while a new file's superblocks are first written
        refused = 0
        for n in range(1, 5):
            for torn in (0, 100):
                path = os.path.join(d, "new.db")
                if os.path.exists(path):
                    os.remove(path)
                rc, out = run(path, [], (n, torn))
                rc, out = run(path, DUMP)
                if rc == 0:
                    if "refused unknown-table" not in out:
                        raise SystemExit("engine_crash: a new file stopped at step %d holds something: %s" % (n, out[:200]))
                elif "err -102" in out:
                    refused += 1
                else:
                    raise SystemExit("engine_crash: a new file stopped at step %d: status %d %s" % (n, rc, out[:200]))
        print("engine_crash: %d steps, %d crashes; after each the tables are those of the last commit whose superblock was written (found after a crash: %s times for the states 0 to %d);"
              % (total, runs, seen, len(HISTORY)))
        print("engine_crash: every file was written to again after its restart; a new file stopped while it was first written is empty or refused (%d of 8 refused)" % refused)
        print("engine_crash: ok")


main()
