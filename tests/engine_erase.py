#!/usr/bin/env python3
"""An erased row leaves nothing of itself in the page file, wherever the tree had put it (docs/m3-engine.md 6bc).

    python3 tests/engine_erase.py ENGINECHECK_BINARY [SEED]

The older check of this (tests/engine_log.py, tests/engine_check.py) erased one row and looked for its value. It passed for months by where a page happened to be
split: the key of a row is copied into an internal page of the tree when a leaf is split there, and stayed when the row was deleted and erased. This test does not
leave it to chance. Rows with keys and values that occur nowhere else, enough of them and long enough that the tree splits at many of them (text keys, so that
the key itself is in the internal pages; a second table with an index on a text column, so that a value is a key too); they are written, updated (a history),
some deleted first, and then half are erased, in an order of the seed. After two commits and a sweep the whole file is searched for every erased row's key and
values, and every row that was not erased must still be read whole.
"""
import os
import random
import subprocess
import sys
import tempfile

EXE = sys.argv[1]
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 1
FAILED = []
KEY = bytes(range(32)).hex()


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "   " + str(detail)[:500]))
    if not ok:
        FAILED.append(name)


def run(path, lines):
    r = subprocess.run([EXE, path], input="\n".join(lines) + "\n", capture_output=True, text=True)
    if r.returncode != 0:
        check("the engine ran", False, "status %d: %s" % (r.returncode, r.stderr[:200]))
    return r.stdout.split("\n")


def main():
    rng = random.Random(SEED)
    n = 600
    # each row: a key, a value and a later value, none a part of another, each long enough to split pages often
    def word(tag, i):
        return "%s%04d%s" % (tag, i, "".join(rng.choice("bcdfghjklmnpqrstvwxz") for _ in range(40)))
    rows = [(word("kq", i), word("vq", i), word("wq", i), word("eq", i)) for i in range(n)]
    order = list(range(n))
    rng.shuffle(order)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "pages")
        lines = ["!log " + KEY, "create table person (name text primary key, note text)", "create table contact (id integer primary key, mail text, who text)",
                 "create index contact_mail on contact (mail)"]
        for i in order:
            k, v, w2, e = rows[i]
            lines.append("insert into person values ('%s', '%s')" % (k, v))
            lines.append("insert into contact values (%d, '%s', '%s')" % (i, e, k))
        for i in order[::3]:
            lines.append("update person set note = '%s' where name = '%s'" % (rows[i][2], rows[i][0]))
        out = run(path, lines + ["!commit"])
        check("%d rows in each of two tables, a third of them updated: every statement done" % n, not [l for l in out if l.startswith(("refused", "err"))],
              [l for l in out if l.startswith(("refused", "err"))][:3])
        data = open(path, "rb").read()
        inner = sum(1 for p in range(len(data) // 4096) if data[p * 4096] == 2)
        check("the tree has internal pages (%d of them), so keys have been copied up" % inner, inner >= 3, inner)
        gone = sorted(rng.sample(range(n), n // 2))
        lines = ["!log " + KEY]
        for j, i in enumerate(gone):
            k, v, w2, e = rows[i]
            if j % 3 == 0:
                # deleted by an ordinary statement first, then erased: the row is not there when the erase comes
                lines.append("delete from person where name = '%s'" % k)
            lines.append("!erase delete from person where name = '%s'" % k)
            if j % 3 == 1:
                lines.append("delete from contact where id = %d" % i)
            lines.append("!erase delete from contact where id = %d" % i)
        out = run(path, lines + ["!commit", "!sweep", "!commit", "!sweep", "select count(*) from person", "select count(*) from contact"])
        bad = [l for l in out if l.startswith(("refused", "err"))]
        counts = [l for l in out if l.startswith("R ")][-2:]
        check("%d rows of each erased, some after an ordinary delete: every statement done, %d left in each table" % (len(gone), n - len(gone)),
              not bad and counts == ["R " + str(n - len(gone)).encode().hex()] * 2, (bad[:3], counts))
        data = open(path, "rb").read()
        found = []
        for i in gone:
            for what, text in zip(("key", "value", "later value", "indexed value"), rows[i]):
                # (the whole text, and its first 12 bytes: a key cut short is still the person's)
                for needle in (text.encode(), text.encode()[:12]):
                    if needle in data:
                        at = data.index(needle)
                        found.append((i, what, len(needle), at // 4096, data[at // 4096 * 4096]))
        check("no byte of an erased row is in the page file: of %d keys, values, later values and indexed values, whole or their first 12 bytes" % (4 * len(gone)),
              not found, (len(found), found[:6]))
        # the rows that were not erased are whole, and found by key and by the index
        kept = [i for i in range(n) if i not in set(gone)]
        probe = rng.sample(kept, 40)
        lines = []
        for i in probe:
            lines.append("select note from person where name = '%s'" % rows[i][0])
            lines.append("select who from contact where mail = '%s'" % rows[i][3])
        out = [l for l in run(path, lines) if l.startswith("R ")]
        want = []
        for i in probe:
            want.append("R " + (rows[i][2] if i in set(order[::3]) else rows[i][1]).encode().hex())
            want.append("R " + rows[i][0].encode().hex())
        check("the rows not erased are read whole, by key and by the index (40 of %d tried)" % len(kept), out == want, [(a, b) for a, b in zip(out, want) if a != b][:2])
    if FAILED:
        print("FAIL engine erase: %d failed" % len(FAILED))
        return 1
    print("PASS engine erase")
    return 0


if __name__ == "__main__":
    sys.exit(main())
