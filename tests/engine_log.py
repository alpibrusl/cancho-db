#!/usr/bin/env python3
"""A log the engine made, read by the verifiers that were written for the proxy's (docs/m3-engine.md 6ah).

    python3 tests/engine_log.py ENGINECHECK_BINARY STATEMENTS SEED [VERIFIER ...]

The engine runs a history of statements (fixed ones, then random ones from SEED; in two processes over one page file, so the head of the log is read back from the file) with a
signing key, and prints a record of the log for every commit that changed rows, and what each statement changed (keys, images, salts). This program does no more than move those
bytes into the three files the specification names:

  * the log: the header and the records, as printed;
  * the delta store (version 2, docs/spec/l3a.md section 9): a line for each change, under the commit whose record came next. The commitment and the hashes of a line are computed
    here from the specification's formulas, the engine prints none of them;
  * the live dump (section 3b): every row of every table as the engine holds it at the end.

Then tools/verify.py must accept the log (chain, numbers, signatures) and every L3a verifier (default: tools/l3a.py) must say `ok ... final`: each commit's `changes` is the
hash of the facts of its lines, each `state` follows from its parent's, and replaying the facts from nothing gives exactly the rows of the dump. Then what must not pass is tried:
a line of the store removed, an image changed, a row missing from the dump, a row in the dump changed, a record cut out of the log.

A column added to a table and a table dropped are in the history: each changes rows (6ai), and the log has to tell it for the replay to end at the rows there are.

No PostgreSQL is needed: nothing here asks whether the answers are right (tests/engine_check.py does), only whether the log tells what the engine did.
"""
import hashlib
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE, COUNT, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
VERIFIERS = sys.argv[4:] or ["python3 tools/l3a.py"]
KEY = bytes(range(32)).hex()
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:600]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def key_commit(plain, salt): return hashlib.sha256(b"cancho-db/key/v1\0" + salt + plain).digest()
def row_hash(image, salt): return hashlib.sha256(b"cancho-db/row/v2\0" + salt + image).digest()
def commit_id(enc): return hashlib.sha256(b"cancho-db/commit/v1\0" + enc).digest()


FIXED = [
    "create table acct (id integer primary key, owner text not null, cents bigint not null)",
    "create table note (k text primary key, body text)",
    "create table pair (a integer, b text, v integer, primary key (a, b))",
    "insert into acct values (1, 'ana', 100), (2, 'bo', 250), (3, 'cy', 0)",
    "insert into note values ('first', 'hello'), ('', null)",
    "update acct set cents = cents + 5 where id = 2",
    "delete from acct where id = 3",
    "insert into acct values (3, 'cy', 7)",                       # a key put back: a new row, a new key salt
    "begin", "insert into pair values (1, 'x', 10)", "update pair set v = 11 where a = 1", "insert into note values ('second', 'x')", "commit",
    "begin", "insert into acct values (9, 'gone', 1)", "rollback",
    "begin", "insert into acct values (8, 'eve', 1)", "delete from acct where id = 8", "commit",       # nets to nothing: a commit with no fact
    "begin", "update acct set cents = 1 where id = 1", "update acct set cents = 100 where id = 1", "commit",
    "update acct set id = 30 where id = 3",                       # a row moved: a delete and an insert
    "insert into acct values (1, 'dup', 0)",                      # an error: no commit
    "update acct set cents = cents where id = 1",                 # nothing changed: no commit
    "insert into acct values (4, 'di', 4) on conflict do nothing",
    "insert into acct values (4, 'di', 5) on conflict do nothing",
    "update note set body = 'bye' where k = 'first' returning k",
    "delete from pair",
    "select count(*) from acct",
    "alter table acct add column note text default 'n'",          # every row of the table is another row (6ai)
    "update acct set note = 'm' where id = 2",
    "create table gone (k integer primary key, v text)",
    "insert into gone values (1, 'a'), (2, 'b')",
    "begin", "update gone set v = 'c' where k = 1", "alter table gone add column w integer", "insert into gone values (3, 'd', 4)", "commit",
    "truncate gone",                                              # every row deleted, the table kept (6ao)
    "insert into gone values (1, 'again', 1)",
    "begin", "truncate acct", "rollback",
    "drop table gone",                                            # its rows are rows deleted
    "create table gone (k integer primary key)",                  # the name again: other rows
    "insert into gone values (1)",
]
TABLES = ["acct", "note", "pair", "rnd", "gone"]


def random_history(rng, n):
    out = ["create table rnd (k integer primary key, t text, n bigint)"]
    intxn = False
    ncol = [0]
    for _ in range(n):
        c = rng.random()
        k = rng.randrange(40)
        if c < 0.06 and not intxn:
            out.append("begin")
            intxn = True
        elif c < 0.14 and intxn:
            out.append(rng.choice(["commit", "commit", "rollback"]))
            intxn = False
        elif c < 0.50:
            out.append("insert into rnd (k, t, n) values (%d, '%s', %d)%s" % (k, rng.choice(["a", "bb", "", "ccc"]), rng.randrange(1000), rng.choice(["", " on conflict do nothing"])))
        elif c < 0.75:
            op = rng.choice(["=", "<", ">"])
            # a key is moved one row at a time: moving several is refused, since the order would decide the answer (engine-order-dependent)
            out.append("update rnd set n = %d%s where k %s %d" % (rng.randrange(1000), rng.choice(["", ", t = 'u'"] + ([", k = k + 40"] if op == "=" else [])), op, k))
        elif c < 0.92:
            out.append("delete from rnd where k %s %d" % (rng.choice(["=", "=", "<"]), k))
        elif c < 0.985 or intxn:
            out.append("update acct set cents = cents + 1 where id = %d" % rng.choice([1, 2, 4, 30]))
        elif c < 0.989:
            out.append("truncate rnd")
        elif c < 0.993:
            ncol[0] += 1
            out.append("alter table rnd add column x%d %s" % (ncol[0], rng.choice(["integer", "text default 'd'", "bigint default 7"])))
        else:
            # the table dropped and made again, with the columns it has
            out.append("drop table rnd")
            out.append("create table rnd (k integer primary key, t text, n bigint)")
            ncol[0] = 0
    if intxn:
        out.append("commit")
    return out


def run(path, lines):
    r = subprocess.run([EXE, path], input="\n".join(lines) + "\n", capture_output=True, text=True)
    if r.returncode != 0:
        check("the engine ran", False, "status %d: %s" % (r.returncode, r.stderr))
    return r.stdout.split("\n")


class Files:
    """What the engine printed, sorted into the three files."""

    def __init__(self):
        self.header, self.records, self.deltas, self.pending, self.seq, self.fline, self.agree = None, [], [], [], 0, None, True

    def unhex(self, f):
        return None if f == "-" else b"" if f == "." else bytes.fromhex(f)

    def take(self, out):
        for line in out:
            f = line.split(" ")
            if f[0] in ("refused", "err"):
                check("no statement of the history is refused", False, line)
            if f[0] == "C":
                self.pending.append([self.unhex(x) for x in f[1:]])
            elif f[0] == "F":
                self.fline = f
            elif f[0] == "L" and len(f) == 2 and f[1] != "-" and bytes.fromhex(f[1])[:8] == b"CHODBLG1":
                if self.header is None:
                    self.header = bytes.fromhex(f[1])
                elif self.header != bytes.fromhex(f[1]):
                    check("one key signs the log", False)
            elif f[0] == "L":
                if len(f) != 2 or f[1] == "-":
                    check("a commit has a record", False, line)
                    continue
                rec = bytes.fromhex(f[1])
                n = int.from_bytes(rec[:4], "big")
                cid = commit_id(rec[4:4 + n])
                self.records.append(rec)
                # the `changes` the engine printed for the test (6af) is the one in the record
                if self.fline is None or len(self.fline) != 3 or bytes.fromhex(self.fline[2]) not in rec:
                    self.agree = False
                for table, key, old, new, ksalt, osalt, nsalt in self.pending:
                    self.deltas.append((self.seq, cid, table, key, old, new, ksalt, osalt, nsalt))
                    self.seq += 1
                self.pending = []
            elif line == "S I":
                self.pending = []                                 # a statement that failed, a rollback: what it changed is not in any commit

    def log(self, skip=None):
        return self.header + b"".join(r for i, r in enumerate(self.records) if i != skip)

    def store(self, drop=None, bend=None):
        hx = lambda b: "" if b is None else b.hex()
        lines = ["CHODBDL2"]
        for i, (seq, cid, table, key, old, new, ksalt, osalt, nsalt) in enumerate(self.deltas):
            if i == drop:
                continue
            oh = None if old is None else row_hash(old, osalt)
            nh = None if new is None else row_hash(new, nsalt)
            if i == bend:
                new = None if new is None else new + b"\0"
                old = None if old is None else old + b"\0"
            lines.append("\t".join([str(seq), cid.hex(), "public", table.hex(), key_commit(key, ksalt).hex(), hx(oh), hx(nh), hx(old), hx(new), hx(osalt), hx(nsalt), hx(key), hx(ksalt)]))
        return ("\n".join(lines) + "\n").encode()


def dump(out, tables, drop=None, bend=None):
    lines, name, n = ["CHODBLV2"], iter(tables), 0
    table = next(name)
    for line in out:
        f = line.split(" ")
        if f[0] == "D":
            if n == bend:
                f[3] = f[3] + "00"
            if n != drop:
                lines.append("\t".join(["public", table.encode().hex(), f[1], f[2], "" if f[3] == "." else f[3], f[4]]))
            n += 1
        elif f[0] == "rows":
            table = next(name, None)
    return ("\n".join(lines) + "\n").encode(), n


def verdict(cmd, work, log, store, live):
    (work / "log").write_bytes(log)
    (work / "deltas").write_bytes(store)
    (work / "live").write_bytes(live)
    r = subprocess.run(cmd.split() + [str(work / "log"), "--deltas", str(work / "deltas"), "--live-dump", str(work / "live")], capture_output=True, text=True, cwd=ROOT)
    return (r.stdout + r.stderr).strip()


def main():
    rng = random.Random(SEED)
    history = FIXED + random_history(rng, COUNT)
    cut = len(FIXED) // 2
    while history[cut] != "begin":                                # the first process ends between two transactions
        cut += 1
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        path = str(work / "pages")
        files = Files()
        files.take(run(path, ["!log " + KEY] + history[:cut] + ["!commit"]))
        first = len(files.records)
        out = run(path, ["!log " + KEY] + history[cut:] + ["!commit", "!mark"] + ["!rows " + t for t in TABLES])
        files.take(out[:out.index("mark")])
        live, nrows = dump(out[out.index("mark"):], TABLES)
        check("commits in both processes", first >= 3 and len(files.records) > first + 3, (first, len(files.records)))
        check("the changes printed for the test are the records'", files.agree)
        (work / "log").write_bytes(files.log())
        r = subprocess.run([sys.executable, str(ROOT / "tools/verify.py"), str(work / "log")], capture_output=True, text=True)
        check("the log verifies: chain, numbers, signatures", r.stdout.startswith("ok ") and "commits=%d" % len(files.records) in r.stdout, r.stdout + r.stderr)
        mid = len(files.records) // 2
        (work / "cut").write_bytes(files.log(skip=mid))
        r = subprocess.run([sys.executable, str(ROOT / "tools/verify.py"), str(work / "cut")], capture_output=True, text=True)
        check("a record cut out of the log is refused", r.stdout.startswith("reject "), r.stdout + r.stderr)
        # a line that is the whole of its commit, so that taking it away or changing it must show (one of several changes of a row in a transaction may net to the same facts)
        per = {}
        for d in files.deltas:
            per[d[1]] = per.get(d[1], 0) + 1
        alone = [i for i, d in enumerate(files.deltas) if per[d[1]] == 1]
        pick = alone[len(alone) // 2]
        for cmd in VERIFIERS:
            v = verdict(cmd, work, files.log(), files.store(), live)
            check("%s: ok, the rows at the end compared" % cmd, v.startswith("ok commits=%d " % len(files.records)) and v.endswith(" final") and "branches=1" in v, v)
            for name, st, lv, want in (("a line of the store removed", files.store(drop=pick), live, "changes-mismatch"),
                                       ("an image changed", files.store(bend=pick), live, "facts-image"),
                                       ("a row missing from the dump", files.store(), dump(out[out.index("mark"):], TABLES, drop=nrows // 2)[0], "replay-final"),
                                       ("a row changed in the dump", files.store(), dump(out[out.index("mark"):], TABLES, bend=nrows // 2)[0], "replay-final")):
                v = verdict(cmd, work, files.log(), st, lv)
                check("%s: %s is %s" % (cmd, name, want), v.startswith("reject rule=%s " % want), v)
        print("commits %d, changes %d, rows at the end %d" % (len(files.records), len(files.deltas), nrows))
    if FAILED:
        print("FAIL engine log: %d failed" % len(FAILED))
        return 1
    print("PASS engine log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
