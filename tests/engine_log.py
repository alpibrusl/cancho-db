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
import base64
import hashlib
import os
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE, COUNT, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
VERIFIERS = sys.argv[4:] or ["python3 tools/l3a.py"]
KEY = bytes(range(32)).hex()
# who: a token of the test root that allows everything, so that the commits name a token and their statements can be judged (L2 with statements, docs/spec/ir.md section 4)
PASSWORD = subprocess.run([sys.executable, str(ROOT / "tools/mint.py"), "password", "--effects", "r:*,w:*,d:*,c:*,n:*"], capture_output=True, text=True, check=True).stdout.strip()
TOKEN = base64.urlsafe_b64decode(PASSWORD + "=" * (-len(PASSWORD) % 4))[:-32].hex()
ROOT_KEY = subprocess.run([sys.executable, str(ROOT / "tools/mint.py"), "root"], capture_output=True, text=True, check=True).stdout.strip()
WHO = ["!log " + KEY, "!token " + TOKEN]
# the verifiers of L1 and L2: the reference, and the two others if the gate built them
L2 = ["python3 tools/verify.py"] + [x for x in ("build/verify", "build/verify-go") if (ROOT / x).exists()]
NEEDLE = "zq-needle-constant"
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
    "insert into note values ('needle', '%s')" % NEEDLE,          # a value that will be erased: it comes in a statement, and again in a condition
    "update note set body = body || '!' where body = '%s'" % NEEDLE,
    "begin", "select k from note where body = '%s!'" % NEEDLE, "update note set body = '%s' where k = 'needle'" % NEEDLE, "commit",
    "delete from pair",
    "select count(*) from acct",
    "alter table acct add column note text default 'n'",          # every row of the table is another row (6ai)
    "update acct set note = 'm' where id = 2",
    "create table gone (k integer primary key, v text)",
    "insert into gone values (1, 'a'), (2, 'b')",
    "begin", "update gone set v = 'c' where k = 1", "alter table gone add column w integer", "insert into gone values (3, 'd', 4)", "commit",
    "alter table gone rename to went",                            # its rows leave one table and enter another (6ar)
    "update went set v = 'moved' where k = 2",
    "alter table went rename to gone",
    "truncate gone",                                              # every row deleted, the table kept (6ao)
    "insert into gone values (1, 'again', 1)",
    "begin", "truncate acct", "rollback",
    "drop table gone",                                            # its rows are rows deleted
    "create table gone (k integer primary key)",                  # the name again: other rows
    "insert into gone values (1)",
]
# a transaction over many tables: its record names each (an effect a table) and is longer than one value of the tree holds, so it is kept in parts (6as)
MANY = ["many_tables_in_one_commit_%02d" % i for i in range(40)]
FIXED += ["create table %s (k integer primary key)" % t for t in MANY] + ["begin"] + ["insert into %s values (%d)" % (t, i) for i, t in enumerate(MANY)] + ["commit"]
TABLES = ["acct", "note", "pair", "rnd", "gone"] + MANY


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
        self.wrote = False
        self.ran, self.named = 0, []       # how many statements ran in the transaction that is open (or the statement that is one); for each record, that number

    def unhex(self, f):
        return None if f == "-" else b"" if f == "." else bytes.fromhex(f)

    def take(self, out):
        for line in out:
            f = line.split(" ")
            if f[0] in ("refused", "err"):
                check("no statement of the history is refused", False, line)
            if f[0] == "ok" and f[1] not in ("BEGIN", "COMMIT", "ROLLBACK"):
                self.ran += 1
                self.wrote = f[1] != "SELECT"
            if f[0] == "N" and self.wrote:
                # a write that returns what it wrote is two statements: the write, and the select of what it returns (6au)
                self.ran += 1
                self.wrote = False
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
                self.named.append(self.ran)
                # the `changes` the engine printed for the test (6af) is the one in the record
                if self.fline is None or len(self.fline) != 3 or bytes.fromhex(self.fline[2]) not in rec:
                    self.agree = False
                for table, key, old, new, ksalt, osalt, nsalt in self.pending:
                    self.deltas.append((self.seq, cid, table, key, old, new, ksalt, osalt, nsalt))
                    self.seq += 1
                self.pending = []
            elif line == "S I":
                self.ran = 0
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


def read_back(path, extra=()):
    """The log, the facts and the rows as a process that wrote none of them reads them out of the page file (6as): (log bytes, records, store lines, live dump, rows)."""
    out = run(path, list(extra) + ["!mark", "!records", "!store", "!tokens", "!stmts", "!mark"] + ["!rows " + t for t in TABLES])
    out = out[out.index("mark") + 1:]                             # what the process said while it ran `extra` is not the export
    cut = out.index("mark")
    recs = [bytes.fromhex(l.split()[1]) for l in out[:cut] if l.startswith("L ")]
    said = [l for l in out[:cut] if l.startswith("records ") or l.startswith("store ")]
    ids = [commit_id(r[4:4 + int.from_bytes(r[:4], "big")]) for r in recs[1:]]
    lines = []
    for l in out[:cut]:
        f = l.split()
        if f and f[0] == "X":
            # a line of the store with nothing but the hashes: the form of a line that has been erased (docs/spec/l3a.md section 9), for every line
            lines.append("\t".join([str(len(lines)), ids[int(f[1])].hex(), "public", f[2], f[3], "" if f[4] == "-" else f[4], "" if f[5] == "-" else f[5], "", "", "", "", "", ""]))
    live, n = dump(out[cut:], TABLES)
    KEPT[0] = [bytes.fromhex(l.split()[1]) for l in out[:cut] if l.startswith("K ")]
    KEPT[1] = [bytes.fromhex(l.split()[1]) for l in out[:cut] if l.startswith("Y ")]
    return b"".join(recs), recs[1:], lines, live, n, said


KEPT = [[], []]      # the tokens and the statements' records of the last read


def authority(work, log, tokens, stmts, name):
    """L2 with statements: every commit under a token of the root's, its statements all in the store, and its effects exactly what they infer."""
    (work / "a.log").write_bytes(log)
    (work / "a.tok").write_bytes(b"CHODBTK1" + b"".join(struct.pack(">I", len(t)) + t for t in tokens))
    store = lambda ss: b"CHODBST3" + b"".join(struct.pack(">I", len(x)) + x for x in ss)
    cases = [("the statements as kept", store(stmts), "ok"), ("a statement's record taken out of the store", store(stmts[:len(stmts) // 2] + stmts[len(stmts) // 2 + 1:]), "reject rule=stmt-missing"),
             ("a table's name changed in a statement", store([stmts[0][:3] + bytes([stmts[0][3] ^ 1]) + stmts[0][4:]] + stmts[1:]), "reject rule=stmt-")]
    for cmd in L2:
        for what, data, want in cases:
            (work / "a.st").write_bytes(data)
            r = subprocess.run(cmd.split() + [str(work / "a.log"), "--root", ROOT_KEY, "--tokens", str(work / "a.tok"), "--stmts", str(work / "a.st")], capture_output=True, text=True, cwd=ROOT)
            v = (r.stdout + r.stderr).strip()
            good = v.startswith(want) and (want != "ok" or v.endswith("level=2+ir"))
            check("%s, %s: %s (%d statements): %s" % (cmd, name, what, len(stmts), "level=2+ir" if want == "ok" else want), good, v)


def exported(work, path, files, live, nrows):
    log, recs, lines, live2, n2, said = read_back(path)
    check("the log read out of the page file by another process is the one printed, record for record (%d)" % len(recs),
          log == files.log() and recs == files.records and said == ["records %d" % len(recs), "store %d" % len(lines)] and live2 == live, (len(recs), len(files.records), said))
    store = lambda ls: ("\n".join(["CHODBDL2"] + ls) + "\n").encode()
    per = {}
    for l in lines:
        per[l.split("\t")[1]] = per.get(l.split("\t")[1], 0) + 1
    alone = [i for i, l in enumerate(lines) if per[l.split("\t")[1]] == 1]
    pick = alone[len(alone) // 2]
    bent = list(lines)
    f = bent[pick].split("\t")
    f[6 if f[6] else 5] = "00" * 32
    bent[pick] = "\t".join(f)
    for cmd in VERIFIERS:
        v = verdict(cmd, work, log, store(lines), live)
        check("%s, on the log and the facts out of the page file (%d facts, no image among them): ok, the rows at the end compared" % (cmd, len(lines)),
              v.startswith("ok commits=%d " % len(recs)) and v.endswith(" erased=%d final" % len(lines)), v)
        for name, st, want in (("a fact removed", store(lines[:pick] + lines[pick + 1:]), "changes-mismatch"), ("a hash changed", store(bent), "changes-mismatch")):
            v = verdict(cmd, work, log, st, live)
            check("%s: %s is %s" % (cmd, name, want), v.startswith("reject rule=%s " % want), v)
    # a row deleted and then erased (its past and its salts destroyed, 6o), the file swept: the log and the store are what they were and one commit more, and still verify
    log3, recs3, lines3, live3, n3, _ = read_back(path, WHO + ["delete from note where k = 'first'", "!erase delete from note where k = 'first'", "!commit", "!sweep", "!commit"])
    log4, recs4, lines4, live4, n4, _ = read_back(path)
    check("after a delete and an erase: one commit more, what was there before unchanged, and the same read again by another process",
          recs3[:-1] == recs and len(lines3) == len(lines) + 1 and [l.split("\t")[1:] for l in lines3[:len(lines)]] == [l.split("\t")[1:] for l in lines] and (log4, lines4, live4) == (log3, lines3, live3) and n3 == n2 - 1,
          (len(recs3), len(recs), len(lines3), len(lines), n3, n2))
    for cmd in VERIFIERS:
        v = verdict(cmd, work, log4, store(lines4), live4)
        check("%s, after the erase: ok, the rows at the end compared" % cmd, v.startswith("ok commits=%d " % len(recs4)) and v.endswith(" final"), v)
    # a commit names the statements of its transaction and no other: as many as ran in it (one more for each that returned what it wrote)
    sys.path.insert(0, str(ROOT / "tools"))
    import verify as l1  # noqa: E402
    counts = [len(l1.decode(r[4:4 + int.from_bytes(r[:4], "big")])[3][5]) for r in recs]
    # a renaming is two statements, one definition for each name (6au): the commits that define two names with one statement run are the renamings of the history
    defined = [len([e for e in l1.decode(r[4:4 + int.from_bytes(r[:4], "big")])[3][3] if e[0] == 2]) for r in recs]
    want = [n + 1 if n == 1 and d == 2 else n for n, d in zip(files.named, defined)]
    check("the history has its two renamings", sum(1 for n, d in zip(files.named, defined) if n == 1 and d == 2) == 2)
    check("each commit names the statements that ran in its transaction: %d statements in %d commits" % (sum(counts), len(counts)),
          len(counts) == len(want) and counts == want and min(counts) >= 1, [(i, c, n) for i, (c, n) in enumerate(zip(counts, want)) if c != n][:5])
    # who, what and when (6at, 6au): the log, the tokens and the statements out of the page file, judged at L2 with statements
    authority(work, log4, KEPT[0], KEPT[1], "after the erase")
    # the constants of the statements are nowhere: a row whose values came in statements, deleted and erased, leaves no byte of them in the file, which still has the
    # statements' records (their shapes) and verifies
    run(path, WHO + ["delete from note where k = 'needle'", "!erase delete from note where k = 'needle'", "!commit", "!sweep", "!commit", "!sweep"])
    log6, recs6, lines6, live6, n6, _ = read_back(path)
    data = open(path, "rb").read()
    check("a value that came in three statements is in no byte of the page file once its row is erased; the statements are still in the log, as shapes",
          NEEDLE.encode() not in data and b"needle" not in data and len(KEPT[1]) > 10 and len(recs6) == len(recs4) + 1, (NEEDLE.encode() in data, b"needle" in data, len(KEPT[1])))
    authority(work, log6, KEPT[0], KEPT[1], "after the value was erased")
    # a transaction of more statements than a commit names is refused when it commits, and rolled back
    out = run(path, WHO + ["begin"] + ["insert into pair values (%d, 'big', 1)" % (1000 + i) for i in range(501)] + ["commit", "select count(*) from pair where b = 'big'", "insert into pair values (2000, 'small', 1)", "!commit"])
    log7, recs7, lines7, live7, _, _ = read_back(path)
    check("a transaction of 501 statements: refused when it commits (commit-too-large), nothing of it stays, and the next commit is made",
          "refused commit-too-large" in out and "R 30" in out and len(recs7) == len(recs6) + 1, [l for l in out if l.startswith(("refused", "err", "R "))][:4])
    # the engine's forms that have no IR are told as the IR that says what they did: a renaming defines both names, a truncate writes its table
    run(path, WHO + ["insert into pair values (3000, 't', 1)", "alter table pair rename to pair2", "alter table pair2 rename to pair", "truncate pair", "!commit"])
    log7, recs8, lines7, live7, _, _ = read_back(path)
    effects = [sorted(l1.decode(r[4:4 + int.from_bytes(r[:4], "big")])[3][3]) for r in recs8[-3:]]
    check("a renaming is told as a definition of both names, a truncate as a write of its table",
          len(recs8) == len(recs7) + 4 and effects == [[(2, b"pair"), (2, b"pair2")], [(2, b"pair"), (2, b"pair2")], [(1, b"pair")]], effects)
    authority(work, log7, KEPT[0], KEPT[1], "at the end")
    # one key signs a log: a commit signed with another is not made, with or without its record
    other = bytes(range(1, 33)).hex()
    out = run(path, ["!log " + other, "insert into acct values (777, 'other key', 1)", "!commit", "select count(*) from acct where id = 777"])
    log5, recs5, lines5, live5, n5, _ = read_back(path)
    check("a commit signed with another key is not made: an error, no record, no row", any(l.startswith("err ") for l in out) and "R 30" in out and (log5, lines5, live5) == (log7, lines7, live7), [l for l in out if l[:2] in ("er", "ok", "R ", "L ")][:6])


TOOL = os.environ.get("LOGEXPORT", str(ROOT / "build/logexport"))             # the export tool (6av); a mutant of it is named by the environment


def export(path, *what):
    """What the export tool (6av) writes for `what`: (status, the bytes, the refusal's tag or '')."""
    r = subprocess.run([TOOL, path] + [str(x) for x in what], capture_output=True)
    said = r.stderr.decode().strip().split("\n")[-1]
    return r.returncode, r.stdout, said[8:] if said.startswith("refused ") else said


def tool(work, path, early):
    """The log out of the page file by the program an operator has (6av): the files the verifiers read, an anchor that a later log is held to, and every refusal."""
    log, recs, lines, live, _, _ = read_back(path)
    ids = [commit_id(r[4:4 + int.from_bytes(r[:4], "big")]) for r in recs]
    facts = ("\n".join(["CHODBDL2"] + lines) + "\n").encode()
    toks = b"CHODBTK1" + b"".join(struct.pack(">I", len(t)) + t for t in KEPT[0])
    stmts = b"CHODBST3" + b"".join(struct.pack(">I", len(t)) + t for t in KEPT[1])
    got = {w: export(path, w) for w in ("anchor", "log", "facts", "tokens", "stmts", "live")}
    check("the export tool writes the log, the facts, the tokens and the statements byte for byte as this test assembles them (%d commits, %d facts, %d tokens, %d statements)"
          % (len(recs), len(lines), len(KEPT[0]), len(KEPT[1])),
          all(got[w][0] == 0 and got[w][2] == "" for w in got) and (got["log"][1], got["facts"][1], got["tokens"][1], got["stmts"][1]) == (log, facts, toks, stmts),
          [(w, got[w][0], got[w][2], len(got[w][1])) for w in got])
    check("its live dump has every row of every table, the tables found in the catalog (%d lines)" % (len(live.split(b"\n")) - 2),
          got["live"][1].startswith(b"CHODBLV2\n") and sorted(got["live"][1].split(b"\n")) == sorted(live.split(b"\n")))
    check("its anchor is the number of commits and the id of the last", got["anchor"][1] == b"anchor %d %s\n" % (len(recs), ids[-1].hex().encode()), got["anchor"][1])
    for cmd in VERIFIERS:
        v = verdict(cmd, work, got["log"][1], got["facts"][1], got["live"][1])
        check("%s, on the files the export tool wrote: ok, the rows at the end compared" % cmd, v.startswith("ok commits=%d " % len(recs)) and v.endswith(" final"), v)
    n0, id0 = early
    check("an anchor taken earlier names a commit of this log (commit %d of %d)" % (n0, len(recs)), 0 < n0 < len(recs) and ids[n0 - 1].hex() == id0, (n0, id0))
    (work / "t.tok").write_bytes(got["tokens"][1])
    (work / "t.st").write_bytes(got["stmts"][1])

    def judged(cmd, data, expect):
        (work / "t.log").write_bytes(data)
        r = subprocess.run(cmd.split() + [str(work / "t.log"), "--expect", expect, "--root", ROOT_KEY, "--tokens", str(work / "t.tok"), "--stmts", str(work / "t.st")], capture_output=True, text=True, cwd=ROOT)
        return (r.stdout + r.stderr).strip()
    # another history under the same key and the same token: a log that verifies, and is not the one the anchor was taken from
    other = str(work / "other")
    run(other, WHO + FIXED[:3] + ["insert into acct values (1, 'another history', 1)", "!commit"])
    st, part, _ = export(path, "log", n0)
    check("`log N` is the first N records, and `facts N` the facts of those", st == 0 and part == log[:40] + b"".join(recs[:n0])
          and export(path, "facts", n0)[1] == ("\n".join(["CHODBDL2"] + [l for l in lines if l.split("\t")[1] in {i.hex() for i in ids[:n0]}]) + "\n").encode())
    olog, otok, ost = export(other, "log")[1], export(other, "tokens")[1], export(other, "stmts")[1]
    for cmd in L2:
        v = judged(cmd, got["log"][1], id0)
        check("%s: the log at the end holds the commit of the earlier anchor: level=2+ir" % cmd, v.startswith("ok commits=%d " % len(recs)) and v.endswith("level=2+ir"), v)
        v = judged(cmd, part, id0)
        check("%s: the log cut at the anchor holds it" % cmd, v.startswith("ok commits=%d " % n0), v)
        v = judged(cmd, part, ids[-1].hex())
        check("%s: the log cut at the anchor does not hold the last commit: expected-missing" % cmd, v.startswith("reject rule=expected-missing"), v)
        (work / "t.tok").write_bytes(otok)
        (work / "t.st").write_bytes(ost)
        v = judged(cmd, olog, id0)
        check("%s: another history under the same key does not hold the anchor's commit: expected-missing" % cmd, v.startswith("reject rule=expected-missing"), v)
        (work / "t.tok").write_bytes(got["tokens"][1])
        (work / "t.st").write_bytes(got["stmts"][1])
    # every refusal but the race (tests/engine_wire.py has a server to race with)
    nolog = str(work / "nolog")
    run(nolog, ["create table t (a integer primary key)", "insert into t values (1)", "!commit"])
    (work / "junk").write_bytes(bytes(range(256)) * 80)
    (work / "short").write_bytes(b"not a page file")
    cases = [((path, "log", len(recs) + 1), 1, "export-behind"), ((path, "facts", len(recs) + 1), 1, "export-behind"), ((path, "live", len(recs) - 1), 1, "export-behind"),
             ((str(work / "none"), "log"), 1, "export-no-file"), ((str(work / "short"), "log"), 1, "export-no-database"), ((str(work / "junk"), "log"), 1, "export-damaged"),
             ((nolog, "anchor"), 1, "export-no-log"), ((nolog, "log"), 1, "export-no-log"), ((nolog, "tokens"), 1, "export-no-log"),
             ((path,), 2, "export-usage"), ((path, "rows"), 2, "export-usage"), ((path, "log", "x"), 2, "export-usage"), ((path, "log", "-1"), 2, "export-usage"),
             ((path, "anchor", 1), 2, "export-usage"), ((path, "tokens", 1), 2, "export-usage"), ((path, "log", 1, 2), 2, "export-usage"), ((path, "log", "9" * 13), 2, "export-usage")]
    # a record of the log damaged where it lies in the page file (its length, in every copy the file has of it): the log does not end quietly before it
    whole = Path(path).read_bytes()
    victim = recs[len(recs) // 2]
    bent = whole.replace(victim[:40], victim[:3] + bytes([victim[3] ^ 1]) + victim[4:40])
    (work / "bent").write_bytes(bent)
    check("the damaged record is in the copy of the page file", bent != whole and len(bent) == len(whole))
    cases += [((str(work / "bent"), w), 1, "export-damaged") for w in ("anchor", "log", "facts")]
    seen = [(export(*a)[0], export(*a)[2]) for a, _, _ in cases]
    check("the export tool's refusals, each with its tag and nothing believed of it: " + ", ".join(sorted({t for _, _, t in cases})), seen == [(st, t) for _, st, t in cases],
          [(a[1:], s) for (a, _, _), s in zip(cases, seen) if s != (_, _)][:0] or [(a[1:], s) for (a, st, t), s in zip(cases, seen) if s != (st, t)])
    check("a page file with no log still has its rows to export; `live N` at the head it is at is the dump",
          export(nolog, "live")[0] == 0 and export(nolog, "live")[1].startswith(b"CHODBLV2\npublic\t74\t") and export(nolog, "live")[1].count(b"\n") == 2
          and export(path, "live", len(recs))[1] == got["live"][1], export(nolog, "live"))


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
        files.take(run(path, WHO + history[:cut] + ["!commit"]))
        first = len(files.records)
        st, said, _ = export(path, "anchor")
        early = (int(said.split()[1]), said.split()[2].decode()) if st == 0 and len(said.split()) == 3 else (0, "")
        out = run(path, WHO + history[cut:] + ["!commit", "!mark"] + ["!rows " + t for t in TABLES])
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
        exported(work, path, files, live, nrows)
        tool(work, path, early)
        print("commits %d, changes %d, rows at the end %d" % (len(files.records), len(files.deltas), nrows))
    if FAILED:
        print("FAIL engine log: %d failed" % len(FAILED))
        return 1
    print("PASS engine log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
