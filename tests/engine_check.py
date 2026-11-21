#!/usr/bin/env python3
"""The engine's statements against PostgreSQL (src/exec.cho, src/execw.cho; docs/m3-engine.md 6g, gate 4).

    PG_E2E_PORT=5532 python3 tests/engine_check.py build/enginecheck [STATEMENTS] [SEED]

A random history of statements (create table, insert, update, delete, select with where, order by, limit, offset and distinct; many of them wrong on purpose: a key that is there, a null where none is taken, a
value of another type, a division by zero in some row) is run by the engine over a page file, in two processes with a commit and a sweep between them, and then statement by statement by PostgreSQL 16 (a
database with the C locale). The rule (6g): the engine may REFUSE a statement, which then changes nothing (PostgreSQL runs it in a transaction that is rolled back, so the two stay in step); whenever it
answers, the answer is PostgreSQL's:

  * an error has the same SQLSTATE;
  * a SELECT has the same column types and the same rows (in order where the ORDER BY decides the order, as a set otherwise);
  * a statement that writes reports the same number of rows, and its `changes` (table, plain key, image before, image after) are exactly the difference between the table read from PostgreSQL before and
    after it: `jsonb_build_array(<key>)::text` and `to_jsonb(row)::text`.

A refusal `engine-ambiguous-error` is a claim too (PostgreSQL fails, with one of several codes) and is checked. A disagreement is a failure; so is an engine that refuses more than half of what PostgreSQL
answers.
"""
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile

EXE = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 1500
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1
PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_enginecheck")
OID = {20: 1, 23: 5, 21: 6, 16: 2, 25: 3, 17: 4}
INTS = {"smallint": 6, "integer": 5, "bigint": 1}
CODE = {"smallint": 6, "integer": 5, "bigint": 1, "boolean": 2, "text": 3}


class Pg:
    """The simple query protocol, enough of it: trust login, text results."""

    def __init__(self, db):
        self.s = socket.create_connection(("127.0.0.1", PORT))
        body = struct.pack(">I", 196608) + b"user\0postgres\0database\0" + db.encode() + b"\0client_encoding\0UTF8\0\0"
        self.s.sendall(struct.pack(">I", len(body) + 4) + body)
        self.buf = b""
        self.until_ready()

    def msg(self):
        while len(self.buf) < 5 or len(self.buf) < 1 + struct.unpack(">I", self.buf[1:5])[0]:
            got = self.s.recv(65536)
            if not got:
                raise SystemExit("engine_check: PostgreSQL closed the connection")
            self.buf += got
        n = struct.unpack(">I", self.buf[1:5])[0]
        t, body, self.buf = self.buf[0:1], self.buf[5:1 + n], self.buf[1 + n:]
        return t, body

    def until_ready(self):
        out = []
        while True:
            t, body = self.msg()
            out.append((t, body))
            if t == b"Z":
                return out

    def query(self, sql):
        """(error code or None, column type oids, rows, command tag)"""
        q = sql.encode() + b"\0"
        self.s.sendall(b"Q" + struct.pack(">I", len(q) + 4) + q)
        err, oids, rows, tag = None, [], [], ""
        for t, body in self.until_ready():
            if t == b"E":
                for f in body.split(b"\0"):
                    if f[:1] == b"C":
                        err = f[1:].decode()
            elif t == b"T":
                n = struct.unpack(">H", body[:2])[0]
                at = 2
                for _ in range(n):
                    at = body.index(b"\0", at) + 1
                    oids.append(struct.unpack(">I", body[at + 6:at + 10])[0])
                    at += 18
            elif t == b"D":
                n = struct.unpack(">H", body[:2])[0]
                at, row = 2, []
                for _ in range(n):
                    ln = struct.unpack(">i", body[at:at + 4])[0]
                    at += 4
                    if ln < 0:
                        row.append(None)
                    else:
                        row.append(body[at:at + ln])
                        at += ln
                rows.append(row)
            elif t == b"C":
                tag = body.rstrip(b"\0").decode()
        return err, oids, rows, tag


def admin(sql):
    r = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PORT), "-U", "postgres", "-At", "-q", "-d", "postgres", "-c", sql], capture_output=True, text=True)
    return r


def q(s):
    return "'" + s.replace("'", "''") + "'"


class Table:
    def __init__(self, name, cols, pk):
        self.name, self.cols, self.pk = name, cols, pk   # cols: (name, sql type, not null, default sql or None)

    def of(self, kind):
        if kind == "int":
            return [c[0] for c in self.cols if c[1] in INTS]
        return [c[0] for c in self.cols if c[1] == kind]

    def ddl(self):
        parts = []
        for i, (name, ty, nn, dflt) in enumerate(self.cols):
            s = "%s %s" % (name, ty)
            if i == self.pk:
                s += " primary key"
            if nn:
                s += " not null"
            if dflt is not None:
                s += " default " + dflt
            parts.append(s)
        return "create table %s (%s)" % (self.name, ", ".join(parts))


TEXTS = ["", "a", "b", "abc", "A", "12", " 7", "x%", "ñ", "a_c", "it's", "zz"]
SMALL = [0, 1, 2, 3, 5, 7, 10, 12, 100, -1, -3]
EDGE = [32767, -32768, 2147483647, -2147483648, 9223372036854775807, 3000000000, 65536, 46341]


class Gen:
    def __init__(self, rng):
        self.r = rng
        self.t = None

    def pick(self, xs):
        return xs[self.r.randrange(len(xs))]

    def lit_int(self):
        v = self.pick(EDGE) if self.r.random() < 0.12 else self.pick(SMALL)
        return str(v) if v >= 0 else "- %d" % -v

    def int_(self, d):
        r = self.r.random()
        cols = self.t.of("int")
        if d <= 0 or r < 0.3:
            if cols and self.r.random() < 0.65:
                return self.pick(cols)
            return self.lit_int()
        if r < 0.75:
            return "(%s %s %s)" % (self.int_(d - 1), self.pick(["+", "-", "*", "/", "%", "+", "-"]), self.int_(d - 1))
        if r < 0.8:
            return "(- %s)" % self.int_(d - 1)
        if r < 0.88:
            return "case when %s then %s else %s end" % (self.bool_(d - 1), self.int_(d - 1), self.int_(d - 1))
        if r < 0.95:
            return "cast(%s as %s)" % (self.int_(d - 1), self.pick(["smallint", "integer", "bigint"]))
        return "cast(%s as integer)" % self.text_(d - 1)

    def text_(self, d):
        r = self.r.random()
        cols = self.t.of("text")
        if d <= 0 or r < 0.45:
            if cols and self.r.random() < 0.6:
                return self.pick(cols)
            return q(self.pick(TEXTS))
        if r < 0.75:
            return "(%s || %s)" % (self.text_(d - 1), self.text_(d - 1))
        if r < 0.88:
            return "cast(%s as text)" % self.int_(d - 1)
        return "case when %s then %s else %s end" % (self.bool_(d - 1), self.text_(d - 1), self.text_(d - 1))

    def bool_(self, d):
        r = self.r.random()
        cols = self.t.of("boolean")
        if d <= 0 or r < 0.12:
            if cols and self.r.random() < 0.7:
                return self.pick(cols)
            return self.pick(["true", "false"])
        if r < 0.45:
            return "(%s %s %s)" % (self.int_(d - 1), self.pick(["=", "<>", "<", "<=", ">", ">="]), self.int_(d - 1))
        if r < 0.58:
            return "(%s %s %s)" % (self.text_(d - 1), self.pick(["=", "<>", "<", ">="]), self.text_(d - 1))
        if r < 0.72:
            return "(%s %s %s)" % (self.bool_(d - 1), self.pick(["and", "or"]), self.bool_(d - 1))
        if r < 0.77:
            return "(not %s)" % self.bool_(d - 1)
        if r < 0.86:
            return "(%s is %snull)" % (self.any_(d - 1), self.pick(["", "not "]))
        if r < 0.92:
            return "(%s in (%s))" % (self.int_(d - 1), ", ".join(self.int_(0) for _ in range(self.r.randrange(1, 4))))
        if r < 0.97:
            return "(%s like %s)" % (self.text_(d - 1), q(self.pick(["a%", "%", "_", "%b%", "a_c", "x\\%"])))
        return "(%s between %s and %s)" % (self.int_(d - 1), self.int_(0), self.int_(0))

    def any_(self, d):
        return self.pick([self.int_, self.text_, self.bool_])(d)

    def of(self, ty, d):
        if self.r.random() < 0.04:
            return self.any_(d)
        if ty in INTS:
            return self.int_(d)
        return self.text_(d) if ty == "text" else self.bool_(d)

    def key_lit(self, ty):
        if ty in INTS:
            return str(self.r.randrange(1, 25))
        if ty == "text":
            return q(self.pick(["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "a", "b", "", "ñ"]))
        return self.pick(["true", "false"])

    def value(self, col, is_pk):
        name, ty, nn, dflt = col
        r = self.r.random()
        if r < 0.05:
            return self.pick(["'abc'", "true", "1", "'5'", "null", "100000", "3000000000", "'t'", "(1 + 1)", "('a' || 'b')", "cast('7' as integer)", "(1 / 0)", "''"])
        if is_pk:
            return "null" if r < 0.07 else self.key_lit(ty)
        if r < 0.2:
            return "null"
        if ty in INTS:
            if r < 0.3:
                return self.lit_int()
            return str(self.pick(SMALL))
        if ty == "text":
            return q(self.pick(TEXTS))
        return self.pick(["true", "false"])

    def where(self):
        r = self.r.random()
        pk = self.t.cols[self.t.pk]
        if r < 0.25:
            return "%s = %s" % (pk[0], self.key_lit(pk[1]))
        if r < 0.36:
            return "%s %s %s" % (pk[0], self.pick(["<", ">=", "<>", "<=", ">"]), self.key_lit(pk[1]))
        if r < 0.4:
            # the constant first, and a range
            return "%s %s %s and %s %s %s" % (self.key_lit(pk[1]), self.pick(["<", "<=", ">", ">=", "="]), pk[0], pk[0], self.pick(["<", "<=", ">", ">="]), self.key_lit(pk[1]))
        if r < 0.45:
            return "%s %s %s and %s" % (pk[0], self.pick(["=", "<", ">="]), self.key_lit(pk[1]), self.bool_(1))
        if r < 0.6:
            return "%s and %s" % (self.bool_(1), self.bool_(1))
        return self.bool_(2)

    def table(self, name):
        kt = self.pick(["integer", "integer", "bigint", "smallint", "text", "text"])
        cols = [("k", kt, False, None)]
        for cname in ["a", "b", "c", "d", "e", "ff"][:self.r.randrange(2, 7)]:
            ty = self.pick(["smallint", "integer", "integer", "bigint", "text", "text", "boolean"])
            nn = self.r.random() < 0.2
            dflt = None
            if self.r.random() < 0.3:
                if self.r.random() < 0.08:
                    dflt = self.pick(["'abc'", "true", "7", "null"])
                elif ty in INTS:
                    dflt = self.pick(["0", "7", "- 1", "null", "'12'"])
                elif ty == "text":
                    dflt = self.pick(["'x'", "''", "null"])
                else:
                    dflt = self.pick(["true", "false", "'t'"])
            cols.append((cname, ty, nn, dflt))
        pk = 0
        if self.r.random() < 0.3:
            # the key is not always the first column
            pk = self.r.randrange(len(cols))
            if cols[pk][1] == "boolean":
                pk = 0
            cols[0], cols[pk] = cols[pk], cols[0]
            cols[pk] = ("k", cols[pk][1], False, None) if cols[pk][0] != "k" else cols[pk]
            pk = [c[0] for c in cols].index("k")
        return Table(name, cols, pk)

    def insert(self):
        t = self.t
        idx = list(range(len(t.cols)))
        listed = self.r.random() < 0.5
        if listed:
            self.r.shuffle(idx)
            keep = [i for i in idx if i == t.pk or self.r.random() < 0.7]
            if self.r.random() < 0.05:
                keep = [i for i in keep if i != t.pk] or keep
            idx = keep
        rows = []
        for _ in range(self.pick([1, 1, 1, 2, 3, 4])):
            rows.append("(%s)" % ", ".join(self.value(t.cols[i], i == t.pk) for i in idx))
        return "insert into %s%s values %s" % (t.name, " (%s)" % ", ".join(t.cols[i][0] for i in idx) if listed else "", ", ".join(rows))

    def update(self):
        t = self.t
        sets = []
        for i in self.r.sample(range(len(t.cols)), self.pick([1, 1, 2])):
            name, ty, nn, dflt = t.cols[i]
            if i == t.pk and self.r.random() < 0.8:
                continue
            r = self.r.random()
            if i == t.pk and ty in INTS:
                e = self.pick(["%s + 1" % name, "%s + 100" % name, "%s * 2" % name, "7", "- %s" % name, "%s + 30" % name])
            elif r < 0.15:
                e = self.value(t.cols[i], i == t.pk)
            else:
                e = self.of(ty, 2)
            sets.append("%s = %s" % (name, e))
        if not sets:
            other = [c for i, c in enumerate(t.cols) if i != t.pk]
            c = self.pick(other)
            sets.append("%s = %s" % (c[0], self.of(c[1], 2)))
        s = "update %s set %s" % (t.name, ", ".join(sets))
        if self.r.random() < 0.8:
            s += " where " + self.where()
        return s

    def delete(self):
        s = "delete from %s" % self.t.name
        if self.r.random() < 0.9:
            s += " where " + self.where()
        return s

    def select(self):
        """(sql, how to compare: 'order', 'set' or 'count')"""
        t = self.t
        pk = t.cols[t.pk][0]
        distinct = self.r.random() < 0.15
        star = self.r.random() < 0.25
        items = ["*"] if star else [self.any_(2) for _ in range(self.r.randrange(1, 5))]
        nout = len(t.cols) if star else len(items)
        s = "select %s%s from %s" % ("distinct " if distinct else "", ", ".join(items), t.name)
        if self.r.random() < 0.7:
            s += " where " + self.where()
        how = "set"
        if self.r.random() < 0.55:
            keys = []
            total = False
            for _ in range(self.pick([1, 1, 2])):
                r = self.r.random()
                if distinct or r < 0.4:
                    k = str(self.r.randrange(1, nout + 1))
                elif r < 0.7:
                    k = self.pick(t.cols)[0]
                else:
                    k = self.any_(1)
                keys.append(k + self.pick(["", "", " asc", " desc"]))
            if not distinct and self.r.random() < 0.75:
                keys.append(pk + self.pick(["", " desc"]))
                total = True
            if distinct and self.r.random() < 0.6:
                keys = ["%d%s" % (i + 1, self.pick(["", " desc"])) for i in range(nout)]
                total = True
            s += " order by " + ", ".join(keys)
            how = "order" if total else "set"
            if self.r.random() < 0.45:
                if self.r.random() < 0.85:
                    s += " limit " + self.pick(["0", "1", "2", "3", "5", "50", "null", "- 1", "1 + 1"])
                if self.r.random() < 0.5:
                    s += " offset " + self.pick(["0", "1", "2", "4", "- 1"])
                if not total:
                    how = "count"
        return s, how


def run_engine(path, lines):
    r = subprocess.run([EXE, path], input="\n".join(lines) + "\n", capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("engine_check: enginecheck ended with %d: %s%s" % (r.returncode, r.stdout[-300:], r.stderr[-300:]))
    out, cur = [], []
    for line in r.stdout.split("\n"):
        if line == ".":
            out.append(cur)
            cur = []
        elif line.startswith("committed ") or line.startswith("swept ") or line.startswith("err "):
            if line.startswith("err "):
                raise SystemExit("engine_check: %s" % line)
        elif line:
            cur.append(line)
    return out


def unhex(s):
    return b"" if s == "." else bytes.fromhex(s)


def compare(pg, stmts, eng, must):
    """Run `stmts` on PostgreSQL and hold the engine's answers `eng` against its: (counts, failures, answered by PostgreSQL and refused by the engine, answered by PostgreSQL)."""
    if len(eng) != len(stmts):
        raise SystemExit("engine_check: %d answers for %d statements" % (len(eng), len(stmts)))
    def snapshot(name):
        err, _, rows, _ = pg.query("select jsonb_build_array(k)::text, to_jsonb(x)::text from %s x" % name)
        return None if err else {r[0]: r[1] for r in rows}

    counts = {}
    fails = 0
    refused_answered = 0
    answered = 0

    def fail(i, why, extra=""):
        nonlocal fails
        fails += 1
        if fails <= 12:
            print("FAIL %d: %s\n     %s\n     engine: %s\n     %s" % (i, why, stmts[i][0], " | ".join(eng[i])[:400], extra))

    def count(k):
        counts[k] = counts.get(k, 0) + 1

    for i, (sql, how, tname) in enumerate(stmts):
        head = eng[i][0] if eng[i] else "<nothing>"
        if head.startswith("refused "):
            tag = head.split()[1]
            if must:
                fail(i, "refused, and this statement is one the engine answers")
            pg.query("begin")
            err, _, _, _ = pg.query(sql)
            pg.query("rollback")
            count("refused:" + tag)
            if err is None:
                refused_answered += 1
            if tag == "engine-ambiguous-error" and err is None:
                fail(i, "refused as an error of several codes, and PostgreSQL has none")
            continue
        before = snapshot(tname) if how == "write" else None
        err, oids, rows, tag = pg.query(sql)
        if err is None:
            answered += 1
        if head.startswith("error "):
            code = head.split()[1]
            if err == code:
                count("agree-error")
            else:
                fail(i, "error %s, PostgreSQL: %s" % (code, err or "no error"))
                if err is None:
                    raise SystemExit("engine_check: the two are out of step; stopping")
            continue
        if not head.startswith("ok "):
            fail(i, "no answer")
            continue
        if err is not None:
            fail(i, "answered, PostgreSQL: error %s" % err)
            raise SystemExit("engine_check: the two are out of step; stopping")
        kind, n = head.split()[1], int(head.split()[2])
        if kind == "SELECT":
            types = [int(x) for x in eng[i][1].split()[1:]]
            erows = []
            for line in eng[i][2:]:
                row = []
                for ty, v in zip(types, line.split()[1:]):
                    if v == "-":
                        row.append(None)
                    elif ty in (1, 5, 6):
                        row.append(v.encode())
                    elif ty == 2:
                        row.append(b"t" if v == "1" else b"f")
                    else:
                        row.append(unhex(v))
                erows.append(row)
            if how == "count":
                ok = len(erows) == len(rows)
            else:
                ok = [OID.get(o) for o in oids] == types
                if how == "set":
                    key = lambda r: [(x is None, x or b"") for x in r]
                    ok = ok and sorted(erows, key=key) == sorted(rows, key=key)
                else:
                    ok = ok and erows == rows
            if ok:
                count("agree-rows")
            else:
                fail(i, "rows differ (%s)" % how, "postgres: %s %s" % ([OID.get(o) for o in oids], rows[:14]))
            continue
        pn = int(tag.split()[-1]) if kind in ("INSERT", "UPDATE", "DELETE") else 0
        if pn != n:
            fail(i, "%d rows, PostgreSQL: %s" % (n, tag))
            continue
        if how == "write":
            after = snapshot(tname)
            want = set()
            for k in set(before) | set(after):
                if before.get(k) != after.get(k):
                    want.add((tname.encode(), k, before.get(k), after.get(k)))
            got = set()
            for line in eng[i][1:]:
                _, t, k, o, nw = line.split()
                got.add((unhex(t), unhex(k), None if o == "-" else unhex(o), None if nw == "-" else unhex(nw)))
            if got == want and len(got) == len(eng[i]) - 1:
                count("agree-changes")
            else:
                fail(i, "changes differ", "only engine: %s\n     only postgres: %s" % (sorted(got - want, key=str)[:3], sorted(want - got, key=str)[:3]))
        else:
            count("agree-ddl")
    return counts, fails, refused_answered, answered


# Statements the engine ANSWERS (a refusal of one is a failure): what stops a change that refuses more from passing as "never wrong".
FIXED = [
    ("create table fx (k integer primary key, a smallint, b text not null default 'd', c boolean, n bigint)", "ddl"),
    ("insert into fx values (1, 1, 'one', true, 10), (2, 2, 'two', false, 20), (3, null, 'three', null, 30)", "write"),
    ("insert into fx (k) values (4)", "write"),
    ("insert into fx (k, a) values (5, 'abc')", "write"),
    ("insert into fx (k, a) values (5, 100000)", "write"),
    ("insert into fx (k, b) values (5, null)", "write"),
    ("insert into fx (k, b) values (1, 'dup')", "write"),
    ("insert into fx (k, c) values (5, 1)", "write"),
    ("insert into fx (k, b) values (5, 12)", "write"),
    ("insert into fx (k, b) values (6, 'x'), (6, 'y')", "write"),
    ("insert into fx (k, b) values (7, 'x'), (8, null)", "write"),
    ("update fx set a = a + 1 where k < 3", "write"),
    ("update fx set a = 100000 where k = 99", "write"),
    ("update fx set a = 32767 * k where k = 1", "write"),
    ("update fx set a = 32767 * k where k = 2", "write"),
    ("update fx set b = k where k = 2", "write"),
    ("update fx set c = 1 where k = 99", "write"),
    ("update fx set k = k + 10 where k = 1", "write"),
    ("update fx set k = 2 where k = 3", "write"),
    ("update fx set k = 50 where k > 3", "write"),
    ("update fx set k = k + 100", "write"),
    ("update fx set b = null where k = 102", "write"),
    ("update fx set c = not c, n = n * 2", "write"),
    ("update fx set n = n where k = 102", "write"),
    ("select * from fx order by k", "order"),
    ("delete from fx where k = 103", "write"),
    ("delete from fx where c", "write"),
    ("select * from fx order by k", "order"),
    ("select k, 10 / (k - 104) from fx", "set"),
    ("select k from fx where 10 / (k - 104) > 0", "set"),
    ("select k from fx where k > 0 and 10 / (k - 104) > 0", "set"),
    ("select k from fx where k > 0 and 10 / (k - 104) > 0 and b <> 'zz'", "set"),
    ("select k from fx where k > 104 and 10 / (k - 105) > 0 and b <> 'zz'", "set"),
    ("update fx set n = 10 / (k - 104) where k > 0 and c is null", "write"),
    ("delete from fx where k > 0 and 10 / (k - 104) > 0", "write"),
    ("select k, a, n from fx order by n desc, k limit 2 offset 1", "order"),
    ("select k from fx order by a, k", "order"),
    ("select k from fx order by a desc, k", "order"),
    ("select distinct c from fx order by 1", "order"),
    ("select distinct b, c from fx", "set"),
    ("select b, k from fx order by b desc, 2", "order"),
    ("select cast(k as text) from fx order by k", "order"),
    ("select case when c then 1 else k end, 'lit', null from fx order by k desc", "order"),
    ("select k from fx order by k limit 0", "order"),
    ("select k from fx order by k limit null offset 2", "order"),
    ("select k from fx limit - 1", "set"),
    ("select k from fx offset - 1", "set"),
    ("select k + c from fx", "set"),
    ("select k from fx where b", "set"),
    ("select k from fx where b like 't%' or c is null", "set"),
    ("select k from fx where k in (102, 105, 1) and not (b = 'x')", "set"),
    ("create table fx (k integer primary key)", "ddl"),
    ("create table fy (k integer primary key, k text)", "ddl"),
    ("create table fy (k integer primary key, j integer primary key)", "ddl"),
    ("create table fy (k integer primary key, a integer default 'abc')", "ddl"),
    ("create table fy (k integer primary key, a integer default true)", "ddl"),
    ("create table fy (j bigint, k text primary key, a integer default - 3, b boolean default 'yes', s smallint not null default '12')", "ddl"),
    ("insert into fy (k) values ('p'), ('')", "write"),
    ("insert into fy (k, j) values ('p', 1)", "write"),
    ("update fy set k = k || 'q'", "write"),
    ("select * from fy order by k", "order"),
    ("drop table fx", "ddl"),
    ("drop table fy", "ddl"),
]


# Statements whose outcome in PostgreSQL depends on the order it works in (6g), which the engine REFUSES as `engine-order-dependent`, and what PostgreSQL 16 does with each here. The rows were stored 3, 2, 1.
DEP_SETUP = ["create table fz (k integer primary key, n integer)", "insert into fz values (3, 30)", "insert into fz values (2, 20)", "insert into fz values (1, 10)"]
DEP = [
    # the cheaper condition is computed first, wherever it is written: the row with k = 2 never reaches the division
    ("select k from fz where k > 2 and 10 / (k - 2) > 0", None),
    ("select k from fz where 10 / (k - 2) > 0 and k > 2", None),
    # the key is looked up and the other rows are never read: an engine that did the same would also answer, by luck (the lookup is only safe when no condition can raise)
    ("select k from fz where k = 3 and 10 / (k - 2) > 0", None),
    # the limit is reached before the row that divides by zero
    ("select 10 / (k - 2) from fz order by k limit 1", None),
    # the row with 3 is moved first, then 2, then 1: no key is ever taken twice
    ("update fz set k = k + 1", None),
    # the same rows the other way: 3 becomes 2, which is there
    ("update fz set k = k - 1", "23505"),
]


def order_dependent(pg):
    with tempfile.TemporaryDirectory() as d:
        eng = run_engine(os.path.join(d, "dep.db"), DEP_SETUP + [x[0] for x in DEP])
    for sql in DEP_SETUP:
        err, _, _, _ = pg.query(sql)
        if err is not None:
            raise SystemExit("engine_check: %s: %s" % (sql, err))
    for (sql, want), ans in zip(DEP, eng[len(DEP_SETUP):]):
        pg.query("begin")
        err, _, _, _ = pg.query(sql)
        pg.query("rollback")
        if ans != ["refused engine-order-dependent"]:
            raise SystemExit("engine_check: %s: the engine says %s, and the answer depends on PostgreSQL's order" % (sql, ans))
        if err != want:
            raise SystemExit("engine_check: %s: PostgreSQL says %s, expected %s" % (sql, err, want))
    pg.query("drop table fz")


def erasure():
    """What a DELETE or a DROP TABLE removed is gone from the page file two commits and a sweep later (docs/m3-engine.md 6c, D-M3-2), and what was not removed is still there."""
    one, two = "MARKER-ROW-ONE-xyzzy", "MARKER-ROW-TWO-plugh"
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "erase.db")
        run_engine(path, ["create table er (k integer primary key, s text)", "insert into er values (1, '%s'), (2, '%s')" % (one, two), "!commit"])
        data = open(path, "rb").read()
        if one.encode() not in data or two.encode() not in data:
            raise SystemExit("engine_check: the rows are not in the page file after a commit")
        run_engine(path, ["delete from er where k = 1", "!commit", "!sweep", "!commit", "!sweep"])
        data = open(path, "rb").read()
        if one.encode() in data:
            raise SystemExit("engine_check: a deleted row is still in the page file after two commits and a sweep")
        if two.encode() not in data:
            raise SystemExit("engine_check: a row that was not deleted is gone from the page file")
        out = run_engine(path, ["select s from er"])
        if out != [["ok SELECT 1", "T 3", "R " + two.encode().hex()]]:
            raise SystemExit("engine_check: after the sweep the table reads %s" % out)
        run_engine(path, ["drop table er", "!commit", "!sweep", "!commit", "!sweep"])
        if two.encode() in open(path, "rb").read():
            raise SystemExit("engine_check: a row of a dropped table is still in the page file after two commits and a sweep")
        # text that is not UTF-8 is refused (PostgreSQL would not take it either), and the engine goes on
        r = subprocess.run([EXE, path], input=b"create table u8 (k integer primary key, s text)\ninsert into u8 values (1, '\xff\xfe')\ninsert into u8 values (2, 'a\xc3')\ninsert into u8 values (3, '\xc3\xb1')\nselect k from u8\n", capture_output=True)
        heads = [b.split(b"\n")[0] for b in r.stdout.split(b"\n.\n")]
        if r.returncode != 0 or not heads[1].startswith(b"refused") or not heads[2].startswith(b"refused") or heads[3] != b"ok INSERT 1" or heads[4] != b"ok SELECT 1":
            raise SystemExit("engine_check: text that is not UTF-8: %s" % heads)


def main():
    admin("drop database if exists %s" % DB)
    r = admin("create database %s encoding 'UTF8' lc_collate 'C' lc_ctype 'C' template template0" % DB)
    if r.returncode != 0:
        raise SystemExit("engine_check: " + r.stderr)
    pg = Pg(DB)
    rng = random.Random(SEED)
    g = Gen(rng)
    tables = {}
    stmts = []   # (sql, how, table name)
    for name in ["ta", "tb", "tc"][:rng.randrange(2, 4)]:
        tables[name] = g.table(name)
        stmts.append((tables[name].ddl(), "ddl", name))
    spare = 0
    while len(stmts) < N:
        g.t = tables[rng.choice(sorted(tables))]
        r = rng.random()
        if r < 0.012:
            stmts.append((g.t.ddl(), "ddl", g.t.name))
        elif r < 0.02:
            # a table is dropped and another definition made under its name
            name = g.t.name
            stmts.append(("drop table %s" % name, "ddl", name))
            tables[name] = g.table(name)
            stmts.append((tables[name].ddl(), "ddl", name))
        elif r < 0.03:
            spare += 1
            bad = g.table("tz%d" % spare)
            stmts.append((bad.ddl() + rng.choice(["", "", " "]), "ddl", bad.name))
            stmts.append(("drop table %s" % bad.name, "ddl", bad.name))
        elif r < 0.33:
            stmts.append((g.insert(), "write", g.t.name))
        elif r < 0.52:
            stmts.append((g.update(), "write", g.t.name))
        elif r < 0.6:
            stmts.append((g.delete(), "write", g.t.name))
        elif r < 0.64:
            pk = g.t.cols[g.t.pk][0]
            stmts.append(("select * from %s order by %s" % (g.t.name, pk), "order", g.t.name))
        else:
            sql, how = g.select()
            stmts.append((sql, how, g.t.name))
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "engine.db")
        half = len(stmts) // 2
        eng = run_engine(path, [s[0] for s in stmts[:half]] + ["!commit", "!sweep"])
        eng += run_engine(path, [s[0] for s in stmts[half:]] + ["!commit"])
    counts, fails, refused_answered, answered = compare(pg, stmts, eng, False)
    with tempfile.TemporaryDirectory() as d:
        feng = run_engine(os.path.join(d, "fixed.db"), [f[0] for f in FIXED])
    fstmts = [(sql, how, "fy" if " fy" in sql else "fx") for sql, how in FIXED]
    fcounts, ffails, _, _ = compare(pg, fstmts, feng, True)
    print("engine_check: %d fixed statements, none refused: %s" % (len(FIXED), ", ".join("%s=%d" % kv for kv in sorted(fcounts.items()))))
    fails += ffails
    order_dependent(pg)
    print("engine_check: %d statements whose outcome depends on PostgreSQL's order are refused as such" % len(DEP))
    erasure()
    print("engine_check: a deleted row and a dropped table are gone from the page file two commits and a sweep later")
    print("engine_check: %d statements (seed %d): %s" % (len(stmts), SEED, ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    print("engine_check: PostgreSQL answers %d that the engine refuses, of %d it answers in all" % (refused_answered, refused_answered + answered))
    if fails:
        raise SystemExit("engine_check: %d disagreements" % fails)
    if refused_answered * 2 > refused_answered + answered:
        raise SystemExit("engine_check: the engine refuses more than half of what PostgreSQL answers")
    print("engine_check: ok")


main()
