#!/usr/bin/env python3
"""The pager's cache under statements larger than it (docs/m3-engine.md 6t).

    python3 tests/engine_big.py build/enginecheck

A statement keeps the pages it hands out in memory and writes each once when it ends (`src/pager.cho`); the cache has a slot a page number, so two pages of one statement can want one slot, and the one
that is only in memory has to be written before it is replaced. The other tests are too small to make that happen. Here a table of 30,000 rows is rewritten, committed and swept twice, so that the free
pages are scattered through a file of thousands of pages, and then rewritten again in single statements; the sums a model predicts must be read back, in the same process and from a new one after a commit.
"""
import os
import subprocess
import sys
import tempfile

EXE = sys.argv[1]
N = 30000


def run(path, lines):
    r = subprocess.run([EXE, path], input="\n".join(lines) + "\n", capture_output=True, text=True)
    if r.returncode != 0 or "\nerr " in r.stdout or "refused" in r.stdout or "error" in r.stdout:
        bad = [l for l in r.stdout.split("\n") if l.startswith(("err", "refused", "error"))]
        raise SystemExit("engine_big: status %d: %s" % (r.returncode, bad[:3]))
    return [l.split()[1:] for l in r.stdout.split("\n") if l.startswith("R ")]


def main():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "big.db")
        a = {k: k % 97 for k in range(1, N + 1)}
        script = ["create table b (k integer primary key, a integer, s text)"]
        for j in range(1, N + 1, 300):
            script.append("insert into b values " + ", ".join("(%d, %d, 'row %d of the big table, padded so that a page holds few of them')" % (k, a[k], k) for k in range(j, min(j + 300, N + 1))))
        script += ["!commit", "update b set a = a + 1", "!commit", "!sweep", "update b set s = s || '!'", "!commit", "!sweep"]
        for k in a:
            a[k] += 1
        # now the free pages are spread through the file: statements that write most of the table take them in any order
        script += ["update b set a = a * 2 where k % 3 = 0", "delete from b where k % 7 = 0", "update b set a = a + k where k % 2 = 1", "select count(*), sum(a), min(k), max(k) from b"]
        for k in list(a):
            if k % 3 == 0:
                a[k] *= 2
        for k in list(a):
            if k % 7 == 0:
                del a[k]
        for k in a:
            if k % 2 == 1:
                a[k] += k
        want = [str(len(a)), str(sum(a.values())), str(min(a)), str(max(a))]
        got = run(path, script + ["!commit"])
        if got != [want]:
            raise SystemExit("engine_big: after the statements the table reads %s, the model %s" % (got, want))
        got = run(path, ["select count(*), sum(a), min(k), max(k) from b", "select a from b where k = %d" % max(a), "!asof 101", "select count(*), sum(a) from b"])
        first = {k: k % 97 for k in range(1, N + 1)}
        if got != [want, [str(a[max(a)])], [str(N), str(sum(first.values()))]]:
            raise SystemExit("engine_big: from a new process the table reads %s" % got)
        print("engine_big: %d rows rewritten five times through a cache smaller than the statements, read back as the model says, now and AS OF the first load; file %d MiB" % (N, os.path.getsize(path) >> 20))
        print("engine_big: ok")


main()
