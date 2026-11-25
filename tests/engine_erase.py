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


def purging(rng):
    """An erase's garbage found from what was written since the last sweep or erase, not by walking the file (docs/m3-engine.md 6bh). `!purge` runs it and holds it to the
    sweep's walk before it writes: `purge-unsafe` if it would zero a page a tree names, `purge-incomplete` if it would leave a page no tree names that is not zeros."""
    def word(tag, i):
        return "%s%05d%s" % (tag, i, "".join(rng.choice("bcdfghjklmnpqrstvwxz") for _ in range(30)))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "pages")
        model, erased, serial = {}, [], [0]
        lines = ["!log " + KEY, "create table person (name text primary key, note text)", "create index person_note on person (note)"]

        def fresh():
            serial[0] += 1
            return word("kz", serial[0]), word("vz", serial[0])

        def op(state):
            """One statement on `state` (a copy of the model inside a transaction): its text."""
            r = rng.random()
            if r < 0.5 or len(state) < 20:
                k, v = fresh()
                state[k] = [v]
                return "insert into person values ('%s', '%s')" % (k, v)
            k = rng.choice(sorted(state))
            if r < 0.8:
                v = fresh()[1]
                state[k] = state[k] + [v]
                return "update person set note = '%s' where name = '%s'" % (v, k)
            del state[k]
            return "delete from person where name = '%s'" % k

        for _ in range(300):
            lines.append(op(model))
        # a base: the file is one tree and zeroed pages
        lines += ["!commit", "!commit", "!sweep"]
        purges = kinds = 0
        seen = {"rollback": 0, "failed": 0, "asof": 0, "erase": 0, "txn": 0}
        for step in range(500):
            r = rng.random()
            if r < 0.45:
                lines.append(op(model))
            elif r < 0.6:
                # a transaction, committed or rolled back
                state = {k: list(v) for k, v in model.items()}
                lines.append("begin")
                for _ in range(rng.randrange(1, 6)):
                    lines.append(op(state))
                if rng.random() < 0.5:
                    lines.append("commit")
                    model.clear()
                    model.update(state)
                    seen["txn"] += 1
                else:
                    lines.append("rollback")
                    seen["rollback"] += 1
            elif r < 0.7:
                # a statement that fails after it has written: the last of its rows has a key that is there
                rows = [fresh() for _ in range(12)] + [(rng.choice(sorted(model)), "dup")]
                lines.append("insert into person values " + ", ".join("('%s', '%s')" % kv for kv in rows))
                seen["failed"] += 1
            elif r < 0.8:
                # the tree as it was, built to be read and left
                lines += ["!asof %d" % rng.randrange(1, 200), "select count(*) from person", "!asof -"]
                seen["asof"] += 1
            else:
                k = rng.choice(sorted(model))
                erased.append((k, model.pop(k)))
                lines.append("!erase delete from person where name = '%s'" % k)
                seen["erase"] += 1
            if step % 4 == 3:
                lines += ["!commit", "!commit", "!purge"]
                purges += 1
        lines += ["!commit", "!commit", "!purge", "select name, note from person order by name"]
        purges += 1
        out = run(path, lines)
        got = [l for l in out if l.startswith("purge")]
        bad = [l for l in got if not l.startswith("purged ")]
        check("%d times, after %d erases, %d transactions, %d rollbacks, %d statements that failed half-way and %d reads of the past: the garbage found from what was written "
              "since is no page a tree names, and leaves no page that is not zeros (%d pages zeroed in all, never a fall back to the sweep)"
              % (purges, seen["erase"], seen["txn"], seen["rollback"], seen["failed"], seen["asof"], sum(int(l.split()[1]) for l in got if l.startswith("purged "))),
              len(got) == purges and not bad and min(seen.values()) > 5, (len(got), purges, bad[:3], seen))
        rows = [l for l in out if l.startswith("R ")][-len(model):]
        want = ["R %s %s" % (k.encode().hex(), model[k][-1].encode().hex()) for k in sorted(model)]
        check("the %d rows that were not erased are read whole after it" % len(model), rows == want, [(a, b) for a, b in zip(rows, want) if a != b][:2])
        data = open(path, "rb").read()
        found = [(k[:8], len(n)) for k, vs in erased for t in [k] + vs for n in (t.encode(), t.encode()[:12]) if n in data]
        check("no byte of the %d erased rows is in the page file: their keys and every value they had, whole or the first 12 bytes" % len(erased), not found, (len(found), found[:5]))
        again = [l for l in run(path, ["!commit", "!commit", "!sweep", "update person set note = 'zz' where name = '%s'" % sorted(model)[0], "!commit", "!commit", "!purge", "select count(*) from person"])
                 if l.startswith(("purge", "err", "R "))]
        check("in a process of its own: after a sweep that leaves a base it is used", len(again) == 2 and again[0].startswith("purged ") and again[0] != "purged 0", again)
        # when it must not be done this way, it says so and touches nothing
        cases = [("no sweep has left a base", ["insert into person values ('a1', 'b1')", "!commit", "!commit", "!purge"]),
                 ("the two superblocks do not name the same tree", ["!commit", "!commit", "!sweep", "insert into person values ('a2', 'b2')", "!commit", "!purge"]),
                 ("a sweep that ran after one commit left no base", ["insert into person values ('a3', 'b3')", "!commit", "!sweep", "!commit", "!commit", "!purge"]),
                 ("the tree is not committed", ["!commit", "!commit", "!sweep", "insert into person values ('a4', 'b4')", "!purge"]),
                 ("there is a second tree", ["!commit", "!commit", "!sweep", "!fork 1", "!commit", "!commit", "!purge"])]
        said = [[l for l in run(path, c[1]) if l.startswith(("purge", "err"))] for c in cases]
        check("it falls back, and writes nothing, when: " + "; ".join(c[0] for c in cases), said == [["purge-fallback"]] * len(cases), said)

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
    purging(random.Random(SEED * 101))
    if FAILED:
        print("FAIL engine erase: %d failed" % len(FAILED))
        return 1
    print("PASS engine erase")
    return 0


if __name__ == "__main__":
    sys.exit(main())
