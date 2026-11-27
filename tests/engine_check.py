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
import hashlib
import os
import random
import re
import socket
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import state as refstate  # noqa: E402  (the reference for docs/spec/state.md: facts and `changes`)

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
        self.status = "I"
        self.names = []
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
        """(error code or None, column type oids, rows, command tag); the column names of the last result are left in `self.names`.
        A statement with parameters (`P`) goes by the extended protocol, as cancho-pg sends it: Parse with no types given, Bind with the values as text, Describe, Execute, Sync."""
        params = getattr(sql, "params", None)
        if params is None:
            q = sql.encode() + b"\0"
            self.s.sendall(b"Q" + struct.pack(">I", len(q) + 4) + q)
        else:
            def m(t, body):
                return t + struct.pack(">I", len(body) + 4) + body
            bind = b"\0\0" + struct.pack(">HH", 0, len(params))
            for v in params:
                bind += struct.pack(">i", -1) if v is None else struct.pack(">i", len(v.encode())) + v.encode()
            bind += struct.pack(">H", 0)
            self.s.sendall(m(b"P", b"\0" + sql.encode() + b"\0" + struct.pack(">H", 0)) + m(b"B", bind) + m(b"D", b"P\0") + m(b"E", b"\0" + struct.pack(">I", 0)) + m(b"S", b""))
        err, oids, rows, tag = None, [], [], ""
        for t, body in self.until_ready():
            if t == b"E":
                for f in body.split(b"\0"):
                    if f[:1] == b"C":
                        err = f[1:].decode()
            elif t == b"T":
                n = struct.unpack(">H", body[:2])[0]
                at = 2
                self.names = []
                for _ in range(n):
                    end = body.index(b"\0", at)
                    self.names.append(body[at:end])
                    at = end + 1
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
            elif t == b"Z":
                self.status = body.decode()
        return err, oids, rows, tag


def sequences(pg):
    """Where every sequence of the database is: [(name, last value or None)]."""
    return [(r[0].decode(), None if r[1] is None else r[1].decode()) for r in pg.query("select quote_ident(sequencename), last_value from pg_sequences where schemaname = 'public'")[2]]


def take_back(pg, sql):
    """Run `sql` and take it back, sequences included (PostgreSQL does not roll those back, and the engine, which refused the statement, drew nothing): the statement's error, or None."""
    seqs = sequences(pg)
    pg.query("begin")
    err = pg.query(sql)[0]
    pg.query("rollback")
    for name, last in seqs:
        if last is None:
            # never drawn from: back to its start
            pg.query("select setval('%s', (select start_value from pg_sequences where schemaname = 'public' and quote_ident(sequencename) = '%s'), false)" % (name, name))
        else:
            pg.query("select setval('%s', %s, true)" % (name, last))
    return err


def admin(sql):
    r = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PORT), "-U", "postgres", "-At", "-q", "-d", "postgres", "-c", sql], capture_output=True, text=True)
    return r


class P(str):
    """A statement and the values bound to its parameters (text, or None for a null)."""
    def __new__(cls, sql, *params):
        o = str.__new__(cls, sql)
        o.params = list(params)
        return o


def lines(stmts):
    """What the harness is fed for these statements: a `!params` line before one that has parameters."""
    out = []
    for st in stmts:
        params = getattr(st, "params", None)
        if params:
            out.append("!params " + " ".join("-" if v is None else "." if v == "" else v.encode().hex() for v in params))
        out.append(str(st))
    return out


LITERAL = re.compile(r"'(?:[^']|'')*'|(?<![\w$.])\d+\b")


def parametrise(rng, sql):
    """Some of the literals of `sql` as parameters: mostly each its own, bare or cast; now and then one parameter used twice (answered only if both uses are cast alike), a null, or text that is
    no number where a number is wanted."""
    # a number that is an item of ORDER BY or GROUP BY is a place in the select list; a parameter there would be a constant, and the order nobody's
    places = set()
    for clause in re.finditer(r"(?:order|group) by (.*?)(?= limit | offset | having | order by |$)", sql):
        for item in re.finditer(r"(?:^|, )(\d+)(?= asc| desc|,|$)", clause.group(1)):
            places.add(clause.start(1) + item.start(1))
    found = [m for m in LITERAL.finditer(sql) if m.start() not in places]
    if not found:
        return sql
    chosen = [m for m in found if rng.random() < 0.6] or [rng.choice(found)]
    params, out, at = [], [], 0
    for m in chosen:
        text = m.group(0)
        isstr = text[0] == "'"
        value = text[1:-1].replace("''", "'") if isstr else text
        r = rng.random()
        if r < 0.04:
            value = None
        elif r < 0.07:
            value = rng.choice(["x", "", " 3 ", "99999999999999999999", "t"])
        cast = ""
        r = rng.random()
        if r < 0.3:
            cast = "::" + (rng.choice(["text", "text", "integer"]) if isstr else rng.choice(["integer", "bigint", "bigint", "smallint", "text"]))
        if params and rng.random() < 0.12:
            # one already bound, used again
            n = rng.randrange(len(params)) + 1
            if rng.random() < 0.7:
                cast = casts[n - 1]
        else:
            params.append(value)
            n = len(params)
            if n == 1:
                casts = []
            casts.append(cast)
        out.append(sql[at:m.start()] + "$%d%s" % (n, cast))
        at = m.end()
    out.append(sql[at:])
    return P("".join(out), *params)


def q(s):
    return "'" + s.replace("'", "''") + "'"


class Table:
    def __init__(self, name, cols, pk):
        self.name, self.cols, self.pk = name, cols, pk   # cols: (name, sql type, not null, default sql or None)
        self.key2 = None     # a second column of the key: then the key is written for the table, `primary key (k, c)` or `(c, k)`
        self.key2_first = False
        self.checks = {}     # column -> (low, high): `check (c between low and high)`
        self.spoil = ""      # a table key that PostgreSQL refuses, now and then
        self.identity = None # a column whose values the table's counter gives (`generated always as identity`)

    def key_cols(self):
        k = self.cols[self.pk][0]
        if self.key2 is None:
            return [k]
        return [self.key2, k] if self.key2_first else [k, self.key2]

    def of(self, kind):
        if kind == "int":
            return [c[0] for c in self.cols if c[1] in INTS]
        return [c[0] for c in self.cols if c[1] == kind]

    def ddl(self, ine=False):
        parts = []
        for i, (name, ty, nn, dflt) in enumerate(self.cols):
            s = "%s %s" % (name, ty)
            if name == self.identity:
                s += " generated always as identity"
            if i == self.pk and (self.key2 is None or self.spoil == "two"):
                s += " primary key"
            if name in self.checks and i % 2 == 0:
                s += " check (%s between %d and %d)" % ((name,) + self.checks[name])
            if nn:
                s += " not null"
            if dflt is not None:
                s += " default " + dflt
            if name in self.checks and i % 2 == 1:
                s += " check (%s between %d and %d)" % ((name,) + self.checks[name])
            parts.append(s)
        if self.key2 is not None:
            keys = self.key_cols()
            if self.spoil == "twice":
                keys.append(keys[0])
            elif self.spoil == "nope":
                keys.append("nope")
            parts.insert(len(parts) if len(parts) % 2 else 1, "primary key (%s)" % ", ".join(keys))
        return "create table %s%s (%s)" % ("if not exists " if ine else "", self.name, ", ".join(parts))


TEXTS = ["", "a", "b", "abc", "A", "12", " 7", "x%", "ñ", "a_c", "it's", "zz"]
SMALL = [0, 1, 2, 3, 5, 7, 10, 12, 100, -1, -3]
# times (docs/m3-engine.md 6bp): the two types, and texts of them in the ways the engine reads, one it leaves to PostgreSQL and one no date has
TIMETYPES = ("timestamp", "timestamptz")
TIMES = ["2026-11-27 10:00:00", "2026-11-27 10:00:00+02", "2026-11-27T08:00:00Z", "2025-01-01", "1999-12-31 23:59:59.999999", "2026-11-27 10:00:00.5-03:30", "2000-02-29 12:30",
         "0001-01-01 00:00:00", "9999-12-31 23:59:59", "2026-11-27 10:00:01", "2026-02-30 10:00:00", "Nov 27 2026"]
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
        if r < 0.33 and d < 2:
            # a scalar subquery (docs/m3-engine.md 6ac): of this table or another one's name, now and then with more than one row, or naming a column of the statement around it
            c = self.pick(cols) if cols else "k"
            tn = self.pick([self.t.name, self.t.name, "ta", "tb"])
            return self.pick(["(select count(*) from T)", "(select count(*) from T)", "(select max(C) from T)", "(select min(C) from T where C is not null)", "(select C from T)"]).replace("T", tn).replace("C", c)
        if r < 0.37:
            # COALESCE, GREATEST, LEAST (docs/m3-engine.md 6ab)
            return "%s(%s)" % (self.pick(["coalesce", "coalesce", "greatest", "least"]), ", ".join(self.pick([self.int_(d - 1), self.int_(d - 1), "null"]) for _ in range(self.pick([1, 2, 2, 3]))))
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
        if r < 0.51:
            return "%s(%s)" % (self.pick(["coalesce", "coalesce", "greatest", "least"]), ", ".join(self.pick([self.text_(d - 1), self.text_(d - 1), "null"]) for _ in range(self.pick([1, 2, 2, 3]))))
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
        if r < 0.15:
            return "coalesce(%s, %s)" % (self.bool_(d - 1), self.bool_(d - 1))
        times = [c[0] for c in self.t.cols if c[1] in TIMETYPES]
        if times and r < 0.25:
            # a time beside a text of one, or another column of times
            other = q(self.pick(TIMES)) if self.r.random() < 0.75 or len(times) < 2 else self.pick(times)
            return "(%s %s %s)" % (self.pick(times), self.pick(["=", "<>", "<", "<=", ">", ">="]), other)
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
        if ty in TIMETYPES:
            return q(self.pick(TIMES[:6]))
        return self.pick(["true", "false"])

    def value(self, col, is_pk):
        name, ty, nn, dflt = col
        r = self.r.random()
        if r < 0.05:
            return self.pick(["'abc'", "true", "1", "'5'", "null", "100000", "3000000000", "'t'", "(1 + 1)", "('a' || 'b')", "cast('7' as integer)", "(1 / 0)", "''"])
        if ty in INTS and 0.05 <= r < 0.11:
            # a value drawn from a sequence (6ad), there or not
            return self.pick(["nextval('sq1')", "nextval('sq1')", "nextval('sq2')", "greatest(nextval('sq1'), 3)", "nextval('sq1') + 20", "nextval('nope')", "coalesce(nextval('sq1'), 1)"])
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
        if ty in TIMETYPES:
            return q(self.pick(TIMES))
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
        if r < 0.72:
            # a column that is not the key, and a constant: what an index on it is read by (docs/m3-engine.md 6bo, slice 2)
            c = self.pick(self.t.cols)
            lit = str(self.pick(SMALL)) if c[1] in INTS else q(self.pick(TEXTS)) if c[1] == "text" else self.pick(["true", "false"])
            sides = (c[0], lit) if self.r.random() < 0.8 else (lit, c[0])
            return "%s = %s%s" % (sides + (" and " + self.bool_(1) if self.r.random() < 0.3 else "",))
        return self.bool_(2)

    def table(self, name):
        kt = self.pick(["integer", "integer", "bigint", "smallint", "text", "text"])
        cols = [("k", kt, False, None)]
        for cname in ["a", "b", "c", "d", "e", "ff"][:self.r.randrange(2, 7)]:
            ty = self.pick(["smallint", "integer", "integer", "bigint", "text", "text", "boolean", "timestamptz", "timestamp"])
            nn = self.r.random() < 0.2
            dflt = None
            if self.r.random() < 0.3:
                if self.r.random() < 0.08:
                    dflt = self.pick(["'abc'", "true", "7", "null"])
                elif ty in INTS:
                    dflt = self.pick(["0", "7", "- 1", "null", "'12'"])
                elif ty == "text":
                    dflt = self.pick(["'x'", "''", "null"])
                elif ty in TIMETYPES:
                    dflt = self.pick(["'2020-01-01'", "null", "'2026-11-27 10:00:00+01'"])
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
        t = Table(name, cols, pk)
        r = self.r.random()
        if r < 0.3:
            # a key of two columns (docs/m3-engine.md 6x)
            others = [c[0] for c in cols if c[0] != "k" and c[1] != "boolean"]
            if others:
                t.key2 = self.pick(others)
                t.key2_first = self.r.random() < 0.4
        for cname, ty, _, _ in cols:
            if ty in INTS and self.r.random() < 0.15:
                t.checks[cname] = self.pick([(0, 10), (-5, 100), (1, 65535), (0, 0), (5, 1)])
        if self.r.random() < 0.3:
            # an identity column (docs/m3-engine.md 6y): its values show what every insert drew, the failed and the rolled back too
            t.identity = "idn"
            t.cols.insert(self.r.randrange(len(t.cols) + 1), ("idn", self.pick(["bigint", "bigint", "integer"]), False, None))
            t.pk = [c[0] for c in t.cols].index("k")
        return t

    def insert(self):
        t = self.t
        idx = list(range(len(t.cols)))
        listed = self.r.random() < 0.5 or (t.identity is not None and self.r.random() < 0.95)
        if listed:
            self.r.shuffle(idx)
            keep = [i for i in idx if i == t.pk or self.r.random() < 0.7]
            if self.r.random() < 0.05:
                keep = [i for i in keep if i != t.pk] or keep
            if self.r.random() < 0.95:
                # a value is not given to an identity column (PostgreSQL: 428C9), but now and then
                keep = [i for i in keep if t.cols[i][0] != t.identity] or keep
            idx = keep
        rows = []
        for _ in range(self.pick([1, 1, 1, 2, 3, 4])):
            rows.append("(%s)" % ", ".join(self.value(t.cols[i], i == t.pk) for i in idx))
        # ON CONFLICT DO NOTHING (docs/m3-engine.md 6z): the rows whose key is there are left out, the others stored
        tail = " on conflict do nothing" if self.r.random() < 0.2 else ""
        tail += self.returning()
        if len(rows) == 1 and self.r.random() < 0.25:
            # the row as a SELECT with no table, and a condition now and then (6ac)
            cond = ""
            if self.r.random() < 0.6:
                cond = " where " + self.pick(["(select count(*) from %s) < %d" % (t.name, self.r.randrange(0, 12)), "true", "false", "null", "1 < 2", "(select count(*) from %s) > 3" % t.name, "k > 0", "1 / 0 > 1", "7"])
            return "insert into %s%s select %s%s%s" % (t.name, " (%s)" % ", ".join(t.cols[i][0] for i in idx) if listed else "", rows[0][1:-1], cond, tail)
        return "insert into %s%s values %s%s" % (t.name, " (%s)" % ", ".join(t.cols[i][0] for i in idx) if listed else "", ", ".join(rows), tail)

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
        return s + self.returning()

    def delete(self):
        s = "delete from %s" % self.t.name
        if self.r.random() < 0.9:
            s += " where " + self.where()
        return s + self.returning()

    def returning(self):
        """RETURNING on two statements in ten (docs/m3-engine.md 6aa): columns, `*`, a comparison, a name; now and then something that is refused or wrong."""
        if self.r.random() > 0.2:
            return ""
        t = self.t
        items = []
        for _ in range(self.pick([1, 1, 2, 3])):
            r = self.r.random()
            c = self.pick(t.cols)[0]
            if r < 0.15:
                items.append("*")
            elif r < 0.7:
                items.append(c + (" as %s" % self.pick(["z1", "k", "\"Zed\""]) if self.r.random() < 0.2 else ""))
            elif r < 0.8:
                items.append("%s is null" % c)
            elif r < 0.88:
                items.append("%s.%s" % (t.name, c))
            elif r < 0.93:
                items.append(self.pick(["1", "'x'", "null", "true"]))
            elif r < 0.97:
                items.append(self.any_(1))
            else:
                items.append(self.pick(["nope", "count(*)", "%s / 0" % c]))
        return " returning " + ", ".join(items)

    def select(self):
        """(sql, how to compare: 'order', 'set' or 'count')"""
        t = self.t
        pk = t.cols[t.pk][0]
        distinct = self.r.random() < 0.15
        star = self.r.random() < 0.25
        items = ["*"] if star else [self.any_(2) + (" as %s" % self.pick(["z1", "z2", "k", "\"Zed\"", "count"]) if self.r.random() < 0.15 else "") for _ in range(self.r.randrange(1, 5))]
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
                # with the table's name: a bare `k` may be an output column that a cast or a CASE named k, and then it decides nothing
                for kc in t.key_cols():
                    keys.append(t.name + "." + kc + self.pick(["", " desc"]))
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


def ddl_more(g, counter):
    """ALTER TABLE ... ADD COLUMN, CREATE INDEX or DROP INDEX on the generator's table (docs/m3-engine.md 6q). An added column that is sure to be taken joins the generator's idea of the table."""
    t = g.t
    r = g.r.random()
    if r < 0.5:
        counter[0] += 1
        name = "x%d" % counter[0]
        ty = g.pick(["smallint", "integer", "bigint", "text", "boolean"])
        q2 = g.r.random()
        if q2 < 0.08:
            return "alter table %s add column %s%s %s" % (t.name, g.pick(["", "if not exists "]), g.pick(t.cols)[0], ty)
        if q2 < 0.14:
            return "alter table %s add column %s %s primary key" % (t.name, name, ty)
        if q2 < 0.22:
            return "alter table %s add column %s %s not null" % (t.name, name, ty)
        if q2 < 0.28:
            return "alter table %s add %s %s default %s" % (t.name, name, ty, g.pick(["'abc'", "true", "100000", "'7'"]))
        dflt = None
        if g.r.random() < 0.6:
            dflt = {"smallint": "5", "integer": "- 2", "bigint": "7", "text": "'dd'", "boolean": "true"}[ty]
        nn = dflt is not None and g.r.random() < 0.3
        chk = ""
        if ty in INTS and g.r.random() < 0.25:
            # a range the default is in, or (now and then) is not: then only an empty table takes the column, and the generator does not count on it
            lo, hi = g.pick([(-5, 10), (0, 100), (0, 1), (6, 9)])
            chk = " check (%s between %d and %d)" % (name, lo, hi)
            if dflt is None or lo <= int(dflt.replace(" ", "")) <= hi:
                t.checks[name] = (lo, hi)
                t.cols.append((name, ty, nn, dflt))
        else:
            t.cols.append((name, ty, nn, dflt))
        return "alter table %s add column %s%s %s%s%s%s" % (t.name, g.pick(["", "", "if not exists "]), name, ty, " not null" if nn else "", " default " + dflt if dflt else "", chk)
    if r < 0.85:
        cols = [g.pick(t.cols)[0] for _ in range(g.pick([1, 1, 2]))]
        if g.r.random() < 0.08:
            cols.append("nope")
        cond = ""
        if g.r.random() < 0.2:
            cond = " where " + g.pick(t.cols + [("nope",)])[0]
        return "create %sindex %s%s on %s (%s)%s" % ("unique " if g.r.random() < 0.08 else "", "if not exists " if g.r.random() < 0.3 else "", g.pick(["ix1", "ix2", "ix3", "ta", "tb"]), t.name, ", ".join(cols), cond)
    if r < 0.9:
        # a change of a column's type: to the type it has, now and then
        c = g.pick(t.cols)
        return "alter table %s alter %s%s %stype %s" % (t.name, g.pick(["column ", ""]), g.pick([c[0], c[0], c[0], "nope"]), g.pick(["", "set data "]), c[1] if g.r.random() < 0.6 else g.pick(["smallint", "integer", "bigint", "text", "boolean"]))
    if r < 0.95:
        # a sequence (docs/m3-engine.md 6ad): its name among the tables' and the indexes'
        return "create sequence %s%s%s%s" % ("if not exists " if g.r.random() < 0.3 else "", g.pick(["sq1", "sq1", "sq2", "ix1", "ta"]), g.pick(["", "", " minvalue 0", " minvalue 5"]), g.pick(["", "", " start 0", " start 7", " start with 3"]))
    if r < 0.975:
        # every row of a table at once (docs/m3-engine.md 6ao)
        return "truncate %s%s" % (g.pick(["", "table "]), g.pick([t.name, t.name, t.name, "nope"]))
    return "drop index %s" % g.pick(["ix1", "ix2", "ix3"])


def _agg(g):
    t = g.t
    r = g.r.random()
    ints = [c[0] for c in t.cols if c[1] in ("smallint", "integer")]
    if r < 0.25:
        return "count(*)"
    if r < 0.4:
        return "count(%s)" % g.any_(1)
    if r < 0.62:
        if ints and g.r.random() < 0.85:
            return "sum(%s)" % g.pick(ints + ["%s + 1" % g.pick(ints), "cast(%s as smallint)" % g.int_(0)])
        return "sum(%s)" % g.any_(1)
    arg = g.int_(1) if g.r.random() < 0.55 else (g.text_(1) if g.r.random() < 0.85 else g.any_(1))
    return "%s(%s)" % (g.pick(["min", "max"]), arg)


def gselect(g):
    """A grouped SELECT: (sql, how to compare)"""
    t = g.t
    groups = []
    for _ in range(g.pick([0, 0, 1, 1, 1, 2])):
        r = g.r.random()
        if r < 0.6:
            groups.append(g.pick(t.cols)[0])
        elif r < 0.8 and t.of("int"):
            groups.append("(%s %% %s)" % (g.pick(t.of("int")), g.pick(["2", "3"])))
        else:
            groups.append(g.any_(1))
    items = []
    by = []
    for i, ge in enumerate(groups):
        if g.r.random() < 0.85:
            items.append(ge)
            by.append(str(len(items)) if g.r.random() < 0.3 else ge)
        else:
            by.append(ge)
    for _ in range(g.r.randrange(1, 4)):
        r = g.r.random()
        if r < 0.7:
            items.append(_agg(g))
        elif r < 0.85:
            items.append("(%s %s %s)" % (_agg(g), g.pick(["+", "-", "*", "/"]), g.pick([_agg(g), "1", "2", "0"])))
        elif r < 0.93:
            items.append(g.pick(t.cols)[0])   # often not grouped: 42803
        else:
            items.append("case when %s > 1 then %s else %s end" % (_agg(g), _agg(g), g.lit_int()))
    g.r.shuffle(items) if g.r.random() < 0.3 and not any(b.isdigit() for b in by) else None
    sql = "select %s%s from %s" % ("distinct " if g.r.random() < 0.08 else "", ", ".join(items), t.name)
    if g.r.random() < 0.5:
        sql += " where " + g.where()
    if by:
        sql += " group by " + ", ".join(by)
    if g.r.random() < 0.3:
        sql += " having " + g.pick(["count(*) > 1", "count(*) > 0", "%s is not null" % _agg(g), "%s > 2" % _agg(g), "(%s / (count(*) - 1)) >= 0" % _agg(g), g.bool_(1)])
    how = "set"
    if g.r.random() < 0.6:
        if g.r.random() < 0.8:
            keys = ["%d%s" % (i + 1, g.pick(["", " desc"])) for i in range(len(items))]
            g.r.shuffle(keys)
            how = "order"
        else:
            keys = [_agg(g) + g.pick(["", " desc"])]
        sql += " order by " + ", ".join(keys)
        if g.r.random() < 0.3:
            sql += " limit " + g.pick(["1", "2", "5"])
            if how != "order":
                how = "count"
    return sql, how


def jselect(g, tables):
    """A SELECT over two or three tables: (sql, how to compare, the first table's name)"""
    names = sorted(tables)
    g.r.shuffle(names)
    names = names[:g.pick([2, 2, 2, 3])]
    ts = [tables[n] for n in names]

    def col(kind=None):
        t = g.pick(ts)
        cs = [c for c in t.cols if kind is None or (c[1] in INTS if kind == "int" else c[1] == kind)]
        if not cs:
            return None
        return "%s.%s" % (t.name, g.pick(cs)[0])

    def cond(quiet):
        r = g.r.random()
        a, b = col(), col()
        if r < 0.45:
            return "%s %s %s" % (a, g.pick(["=", "=", "=", "<", ">=", "<>"]), b)
        if r < 0.65:
            c = col("int")
            return "%s %s %s" % (c or a, g.pick(["=", "<", ">"]), g.pick(SMALL))
        if r < 0.75:
            return "%s is %snull" % (a, g.pick(["", "not "]))
        if r < 0.85:
            return "(%s = %s or %s is null)" % (a, b, col())
        if quiet or r < 0.93:
            c = col("text")
            return "%s <> %s" % (c or a, q(g.pick(TEXTS)))
        c = col("int")
        return "(10 / %s) > 0" % (c or "1")

    sql_from = names[0]
    wheres = []
    for n in names[1:]:
        r = g.r.random()
        if r < 0.25:
            sql_from += ", " + n
            wheres.append(cond(True))
        else:
            sql_from += " %s %s on %s" % (g.pick(["join", "join", "left join"]), n, " and ".join(cond(g.r.random() < 0.95) for _ in range(g.pick([1, 1, 2]))))
    if g.r.random() < 0.4:
        wheres.append(cond(g.r.random() < 0.9))
    grouped = g.r.random() < 0.25
    items = []
    by = []
    if grouped:
        for _ in range(g.pick([0, 1, 1, 2])):
            c = col()
            by.append(c)
            items.append(c)
        for _ in range(g.pick([1, 2])):
            c = col("int") if g.r.random() < 0.7 else col()
            items.append(g.pick(["count(*)", "count(%s)" % c, "sum(%s)" % c, "min(%s)" % c, "max(%s)" % c]))
    else:
        for _ in range(g.r.randrange(1, 5)):
            r = g.r.random()
            a, b = col("int"), col("int")
            if r < 0.7 or not a or not b:
                items.append(col())
            elif r < 0.9:
                items.append("(%s %s %s)" % (a, g.pick(["+", "-", "*"]), b))
            else:
                items.append("(%s / %s)" % (a, b))
    sql = "select %s%s from %s" % ("distinct " if g.r.random() < 0.08 else "", ", ".join(items), sql_from)
    if wheres:
        sql += " where " + " and ".join(wheres)
    if by:
        sql += " group by " + ", ".join(by)
    how = "set"
    if g.r.random() < 0.6:
        keys = ["%d%s" % (i + 1, g.pick(["", " desc"])) for i in range(len(items))]
        g.r.shuffle(keys)
        sql += " order by " + ", ".join(keys)
        how = "order"
        if g.r.random() < 0.25:
            sql += " limit " + g.pick(["1", "3", "10"])
    return sql, how, names[0]


VIA = [0]


def run_engine(path, lines):
    # Every run of the test program ends by holding each built index to its table's rows (docs/m3-engine.md 6bo): an index that has an entry too many or too few after
    # whatever the run did (statements that failed, transactions rolled back, a table dropped, a crash before it) ends the test.
    if os.environ.get("INDEX_EVERY"):
        # (to find the statement after which an index is wrong: the check after every line, and the line named)
        rr = subprocess.run([EXE, path + ".dbg"], input="\n".join(x for l in lines for x in (l, "!indexes")) + "\n", capture_output=True, text=True)
        seen = 0
        for o in rr.stdout.split("\n"):
            if o.startswith("indexes "):
                seen += 1
                if not o.endswith(" ok"):
                    raise SystemExit("engine_check: after line %d %r (before it %r): %s" % (seen, lines[seen - 1][:300], [x[:120] for x in lines[max(0, seen - 4):seen - 1]], o))
    r = subprocess.run([EXE, path], input="\n".join(list(lines) + ["!indexes", "!via"]) + "\n", capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("engine_check: enginecheck ended with %d: %s%s" % (r.returncode, r.stdout[-300:], r.stderr[-300:]))
    out, cur = [], []
    for line in r.stdout.split("\n"):
        if line.startswith("via "):
            # how many of the run's statements read by an index (6bo, slice 2)
            VIA[0] += int(line[4:])
        elif line.startswith("indexes "):
            if not line.endswith(" ok"):
                raise SystemExit("engine_check: %s" % line)
        elif line == ".":
            out.append(cur)
            cur = []
        elif line.startswith("committed ") or line.startswith("swept ") or line.startswith("err ") or line == "unseeded":
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
        # (a table that is not there is asked about without an error: an error would fail the transaction this may be in)
        _, _, there, _ = pg.query("select to_regclass('%s') is not null" % name)
        if not there or there[0][0] != b"t":
            return None
        # the key's columns, in the key's order, as PostgreSQL has them
        _, _, kr, _ = pg.query("select a.attname from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey) where i.indrelid = to_regclass('%s') and i.indisprimary "
                               "order by array_position(i.indkey, a.attnum)" % name)
        key = ", ".join(r[0].decode() for r in kr) or "k"
        err, _, rows, _ = pg.query("select jsonb_build_array(%s)::text, to_jsonb(x)::text from %s x" % (key, name))
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

    tx = []          # the changes of the open transaction, in order: (table, key, image before, image after, key salt, old salt, new salt)
    tx_ddl = [False]
    live = {}        # (table, key) -> (key salt, row salt) of every row there is, as the engine's changes gave them; None: no such row
    over = {}        # the same, for what the open transaction has changed
    given = set()    # every salt the engine has given

    def salts_follow(i, row):
        """One change's salts against the row's history (6ag): what it says the row had is what the write before gave; a key's salt stays while the row does; no salt is given twice."""
        t, k, o, nw, ks, osalt, nsalt = row
        had = over[(t, k)] if (t, k) in over else live.get((t, k))
        if o is None:
            if had is not None or osalt is not None or ks in given:
                fail(i, "a new row's salts: the row was there, or its key's salt is not new")
            given.add(ks)
        elif had != (ks, osalt):
            fail(i, "the salts a write says the row had are not the ones the write before gave", "%s %s" % (k, had))
        if nw is None:
            if nsalt is not None:
                fail(i, "a row that is gone has a salt")
            over[(t, k)] = None
        else:
            if nsalt is None or len(nsalt) != 16 or len(ks) != 16 or nsalt in given:
                fail(i, "a row's new salt is missing, or was given before")
            given.add(nsalt)
            over[(t, k)] = (ks, nsalt)

    def facts_agree(i, body, rows):
        """The engine's `changes` for the commit (its F line) against the reference's (tools/state.py), over the net facts of `rows`."""
        line = [x for x in body if x.startswith("F ")]
        # version 2 (docs/spec/l3a.md section 9): the key is a commitment over the key's salt, a hash is over the row's salt and the image; netted by commitment
        per = {}
        for t, k, o, nw, ks, osalt, nsalt in rows:
            kc = hashlib.sha256(b"cancho-db/key/v1\x00" + ks + k).digest()
            oh = None if o is None else hashlib.sha256(b"cancho-db/row/v2\x00" + osalt + o).digest()
            nh = None if nw is None else hashlib.sha256(b"cancho-db/row/v2\x00" + nsalt + nw).digest()
            if (t, kc) in per:
                per[(t, kc)][1] = nh
            else:
                per[(t, kc)] = [oh, nh]
        facts = []
        for (t, kc), (oh, nh) in sorted(per.items()):
            if oh == nh:
                continue
            facts.append((0 if oh is None else 2 if nh is None else 1, t, kc, oh, nh))
        if not line:
            if rows:
                fail(i, "no facts for a commit that changed rows")
            return
        if not rows:
            # a statement or a transaction that changed no row is no commit
            fail(i, "facts for a commit that changed no row")
            return
        if line[0] == "F -":
            if must:
                fail(i, "the facts of this commit are not to be had")
            count("facts-refused")
            return
        ok, want = refstate.changes(facts)
        if ok != "ok" or line[0] != "F %d %s" % (len(facts), want.hex()):
            fail(i, "the facts differ", "reference: %d %s" % (len(facts), want.hex() if ok == "ok" else want))
        else:
            count("agree-facts")

    for i, (sql, how, tname) in enumerate(stmts):
        blk = eng[i]
        head = blk[0] if blk else "<nothing>"
        state = blk[-1].split()[1] if blk and blk[-1].startswith("S ") else "?"
        body = blk[1:-1]
        pre = pg.status
        if pre == "I" and (over or tx):
            # a transaction that ended without its commit took its changes with it
            over.clear()
            del tx[:]
            tx_ddl[0] = False
        if head.startswith("refused "):
            tag = head.split()[1]
            if must:
                fail(i, "refused, and this statement is one the engine answers")
            if pre == "I":
                # outside a transaction a refusal changes nothing: PostgreSQL runs the statement and takes it back
                err = take_back(pg, sql)
            elif pre == "T" and sequences(pg):
                # inside one, a refusal fails the transaction as an error does. PostgreSQL's is failed without running the statement, which might draw from a sequence that no rollback gives back
                err = "skipped"
                pg.query("select 1 / 0")
            else:
                err, _, _, _ = pg.query(sql)
                if pg.status == "T":
                    pg.query("select 1 / 0")
            count("refused:" + tag)
            if err is None:
                refused_answered += 1
            if tag == "engine-ambiguous-error" and err is None:
                fail(i, "refused as an error of several codes, and PostgreSQL has none")
            if pg.status != state:
                fail(i, "the transaction is %s, PostgreSQL's: %s" % (state, pg.status))
                raise SystemExit("engine_check: the two are out of step; stopping")
            continue
        # a column added, a table dropped and a table truncated change rows too (docs/m3-engine.md 6ai, 6ao): every row of the table is another row, or gone
        rowsddl = how == "ddl" and sql.startswith(("alter table ", "drop table ", "truncate "))
        if rowsddl:
            how = "write"
            tname = re.match(r"(?:(?:alter|drop) table (?:if exists )?|truncate (?:table )?)(\w+)", sql).group(1)
        before = snapshot(tname) if how == "write" and pre != "E" else None
        err, oids, rows, tag = pg.query(sql)
        if err is None:
            answered += 1
        if pg.status != state:
            fail(i, "the transaction is %s, PostgreSQL's: %s (%s)" % (state, pg.status, err))
            raise SystemExit("engine_check: the two are out of step; stopping")
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
        kind = head.split()[1]
        # the command's tag, as a client is sent it
        if not body or body[0] != "G " + tag:
            fail(i, "the tag is %r, PostgreSQL's: %r" % (body[0][2:] if body else None, tag))
            continue
        if kind == "SELECT":
            names = [unhex(x) for x in body[1].split()[1:]]
            types = [int(x) for x in body[2].split()[1:]]
            if names != pg.names:
                fail(i, "the columns are named %s, PostgreSQL: %s" % (names, pg.names))
                continue
            # the values are the text a client is sent
            erows = [[None if v == "-" else unhex(v) for v in line.split()[1:]] for line in body[3:]]
            if how == "count":
                ok = len(erows) == len(rows)
            else:
                ok = oids == types
                if how == "set":
                    key = lambda r: [(x is None, x or b"") for x in r]
                    ok = ok and sorted(erows, key=key) == sorted(rows, key=key)
                else:
                    ok = ok and erows == rows
            if ok:
                count("agree-rows")
            else:
                fail(i, "rows differ (%s)" % how, "postgres: %s %s" % (oids, rows[:14]))
            continue
        returned = [line for line in body[1:] if line[:2] in ("N ", "T ", "R ") or line in ("N", "T")]
        if returned or oids:
            # RETURNING: the rows the statement wrote, in no order that is promised
            names = [unhex(x) for x in returned[0].split()[1:]] if returned else None
            types = [int(x) for x in returned[1].split()[1:]] if len(returned) > 1 else None
            erows = [[None if v == "-" else unhex(v) for v in line.split()[1:]] for line in returned[2:]]
            key = lambda r: [(x is None, x or b"") for x in r]
            if names != pg.names or types != oids or sorted(erows, key=key) != sorted(rows, key=key):
                fail(i, "the rows returned differ", "postgres: %s %s %s" % (pg.names, oids, rows[:10]))
                continue
            count("agree-returning")
        changes = [line for line in body[1:] if line.startswith("C ")]
        if rowsddl:
            count("agree-ddl")
        if how == "write" and before is not None:
            after = snapshot(tname) or {}
            want = set()
            for k in set(before) | set(after):
                if before.get(k) != after.get(k):
                    want.add((tname.encode(), k, before.get(k), after.get(k)))
            renamed = re.match(r"alter table \w+ rename to (\w+)$", sql)
            if renamed:
                # a table renamed (6ar): its rows left the table of the old name (above: it is not there any more) and are rows of the table of the new one
                for k, image in (snapshot(renamed.group(1)) or {}).items():
                    want.add((renamed.group(1).encode(), k, None, image))
            got = set()
            rows = []
            for line in changes:
                f = line.split()
                t, k = unhex(f[1]), unhex(f[2])
                o, nw = (None if f[3] == "-" else unhex(f[3])), (None if f[4] == "-" else unhex(f[4]))
                got.add((t, k, o, nw))
                rows.append((t, k, o, nw, bytes.fromhex(f[5]), None if f[6] == "-" else bytes.fromhex(f[6]), None if f[7] == "-" else bytes.fromhex(f[7])))
            if got == want and len(got) == len(changes):
                count("agree-changes")
                # the key and the images are PostgreSQL's: with the salts the engine gave them (docs/m3-engine.md 6ag) they are the facts of the commit (6af)
                for row in rows:
                    salts_follow(i, row)
                tx.extend(rows)
            else:
                fail(i, "changes differ", "only engine: %s\n     only postgres: %s" % (sorted(got - want, key=str)[:3], sorted(want - got, key=str)[:3]))
                tx_ddl[0] = True
            if pre == "I":
                if not tx_ddl[0]:
                    facts_agree(i, body, tx)
                live.update(over)
                over.clear()
                del tx[:]
                tx_ddl[0] = False
        else:
            count("agree-ddl")
            if sql == "commit" and pre == "T":
                if not tx_ddl[0]:
                    facts_agree(i, body, tx)
                # the transaction's rows are the branch's now
                live.update(over)
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
    ("select count(*), count(a), sum(a), min(a), max(b), min(n), max(k) from fx", "set"),
    ("select c, count(*) from fx group by c order by 1", "order"),
    ("select b, sum(a), count(a) from fx group by b having count(*) >= 1 order by b", "order"),
    ("select count(*), sum(a), min(b) from fx where k < 0", "set"),
    ("select count(*) from fx where k < 0 group by c", "set"),
    ("select a, count(*) from fx group by b", "set"),
    ("select count(*) from fx order by b", "set"),
    ("select count(*) from fx having b = 'x'", "set"),
    ("select min(c) from fx", "set"),
    ("select sum(b) from fx", "set"),
    ("select k % 2, count(*), sum(a) + min(k) from fx group by k % 2 order by 1", "order"),
    ("select 10 / (count(*) - count(*)) from fx", "set"),
    ("select count(*) from fx having count(*) / 0 > 1", "set"),
    ("select c from fx group by c having c", "set"),
    ("select distinct count(*) from fx group by c", "set"),
    ("select b from fx group by 1 order by count(*) desc, 1 limit 2", "order"),
    ("select b, c, max(n) from fx group by c, b order by 1, 2", "order"),
    ("select count(*) + 1, 'n', null from fx having min(a) > 30000", "set"),
    ("select max(a), min(a) from fx group by b order by max(a) desc, min(a)", "set"),
    ("select sum(a / (k - 104)) from fx", "set"),
    ("select count(*) from fx having count(*)", "set"),
    ("select k as kk, b as k, k + 1 as \"Sum\", cast(k as bigint), case when c then k end, case when c then 1 else k end, 'lit', - k from fx order by kk", "order"),
    ("select count(*) as n, max(k), min(b) as \"min b\", sum(a) + 1 from fx", "set"),
    ("select 1, 'x' from fx having count(*) > 0", "set"),
    ("select 1 from fx having false", "set"),
    ("select 2 from fx having true", "set"),
    ("select max(k), min(k), sum(k), count(*) from fx where n < 0", "set"),
    ("select b, min(k), max(k), sum(k - 200) from fx group by b order by 1", "order"),
    ("select 2, c, 1 + count(*) from fx group by 1, 2 order by 3, 2", "order"),
    ("select count(*) from fx group by 10 / (k - 104)", "set"),
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
    ("select fx.k, fy.k from fx, fy order by 1, 2", "order"),
    ("select fx.k, fy.j, fy.k from fx left join fy on fy.a = fx.a order by 1, 3", "order"),
    ("select fx.k, fy.k from fy left join fx on fy.a = fx.a order by 1, 2", "order"),
    ("select fx.b, fy.k from fx join fy on fx.b = fy.k or fy.k = 'q' order by 1, 2", "order"),
    ("select count(*), max(fy.k), count(fy.k), sum(fx.a) from fx left join fy on fx.k = fy.a", "set"),
    ("select fx.c, count(*), min(fy.s) from fx join fy on fy.s > fx.a group by fx.c order by 1", "order"),
    ("select fx.k / (fx.k - 102), fy.k from fx join fy on fy.s > fx.a", "set"),
    ("select fx.k from fx join fy on fx.k = fy.k", "set"),
    ("select fx.k from fx join fy on fx.k", "set"),
    ("select fx.k, fy.k from fx, fy where fx.k > 104 and fy.k <> '' and (fx.c is null or fy.j is null) order by 1, 2", "order"),
    ("select distinct fy.b from fx, fy", "set"),
    ("select fx.k from fx left join fy on fy.k = 'none' where fy.k is null order by 1 limit 2", "order"),
    ("create table fq (k integer primary key, v integer)", "ddl"),
    ("insert into fq values (1, 1), (2, 2), (105, 3)", "write"),
    ("alter table fq add column w text default 'dflt'", "ddl"),
    ("alter table fq add u integer", "ddl"),
    ("alter table fq add column v integer", "ddl"),
    ("alter table fq add column nn integer not null", "ddl"),
    ("alter table fq add column n2 smallint not null default 3", "ddl"),
    ("alter table fq add column pk2 integer primary key", "ddl"),
    ("alter table fq add column dn integer not null default null", "ddl"),
    ("alter table fq add column bad integer default 'abc'", "ddl"),
    ("select * from fq order by k", "order"),
    ("insert into fq (k, v) values (7, 7)", "write"),
    ("update fq set u = v + n2, w = w || 'x' where k < 100", "write"),
    ("select k, v, w, u, n2 from fq order by 1", "order"),
    ("delete from fq where k = 7", "write"),
    ("create index fqi on fq (v)", "ddl"),
    ("create index fqi on fq (k)", "ddl"),
    ("create index fq on fq (k)", "ddl"),
    ("create index fqj on fq (nope)", "ddl"),
    ("create table fqi (k integer primary key)", "ddl"),
    ("drop index fqi", "ddl"),
    ("create index fqi on fq (w, u)", "ddl"),
    ("select count(*) from fx, fy, fq", "set"),
    ("select fx.k, fy.k, fq.k from fx, fy, fq where fq.v > 1 order by 1, 2, 3", "order"),
    ("select fx.k, fy.k, fq.v from fx left join fy on fy.a = fx.a left join fq on fq.k = fx.k order by 1, 2, 3", "order"),
    ("select fx.k, fy.k, fq.v from fx join fq on fq.k < fx.k join fy on fy.j is null order by 1, 2, 3", "order"),
    ("select fx.k from fx, fq where fq.k = 1 order by 1", "order"),
    ("select fx.k, fq.k from fx, fq where fq.k >= 2 and fx.k > 0 order by 1, 2", "order"),
    # transactions: the statements between BEGIN and COMMIT build on one another; an error fails the transaction until it is ended
    ("begin", "ddl"),
    ("insert into fq (k, v) values (900, 1)", "write"),
    ("update fq set v = v + 1 where k = 900", "write"),
    ("update fq set v = v * 10 where k = 900", "write"),
    ("select k, v from fq where k = 900", "set"),
    ("commit", "ddl"),
    ("select v from fq where k = 900", "set"),
    ("begin", "ddl"),
    ("delete from fq", "write"),
    ("select count(*) from fq", "set"),
    ("rollback", "ddl"),
    ("select count(*) from fq", "set"),
    ("begin", "ddl"),
    ("update fq set v = 0 where k = 900", "write"),
    ("select 1 / (k - 900) from fq", "set"),
    ("select 1 from fq", "set"),
    ("update fq set v = 5", "write"),
    ("commit", "ddl"),
    ("select v from fq where k = 900", "set"),
    ("begin", "ddl"),
    ("begin", "ddl"),
    ("create table ftx (k integer primary key)", "ddl"),
    ("insert into ftx values (1)", "ddl"),
    ("rollback", "ddl"),
    ("commit", "ddl"),
    ("rollback", "ddl"),
    ("create table ftx (k integer primary key, z text)", "ddl"),
    ("drop table ftx", "ddl"),
    # a table of several leaves: a scan has to go from one to the next
    ("create table fwide (k integer primary key, a integer, s text)", "ddl"),
    ("insert into fwide values " + ", ".join("(%d, %d, 'row %d padded so that a leaf of the tree holds only some of them')" % (k * 37 % 601, k % 13, k) for k in range(1, 601)), "write"),
    ("select count(*), sum(k), sum(a), min(k), max(k) from fwide", "set"),
    ("select k, a from fwide where a = 5 order by k", "order"),
    ("select k from fwide where k >= 290 and k < 310 order by k desc", "order"),
    ("update fwide set a = a + 1 where k % 2 = 0", "write"),
    ("delete from fwide where k % 5 = 0", "write"),
    ("select a, count(*), max(k) from fwide group by a order by a", "order"),
    ("select * from fwide order by k", "order"),
    ("drop table fwide", "ddl"),
    ("drop table fq", "ddl"),
    ("drop table fx", "ddl"),
    ("drop table fy", "ddl"),
]


# Statements whose outcome in PostgreSQL depends on the order it works in (6g), which the engine REFUSES as `engine-order-dependent`, and what PostgreSQL 16 does with each here. The rows were stored 3, 2, 1.
FIXED += [
    ("create table fp (k integer primary key, a bigint, s text, f boolean)", "ddl"),
    (P("insert into fp values ($1, $2, $3, $4)", "1", "10", "one", "t"), "write"),
    (P("insert into fp values ($1, $2, $3, $4), ($5::integer, $6::bigint, $7::text, $8::boolean)", "2", None, "", "false", "3", "30", "it's", None), "write"),
    (P("insert into fp (k, s) values ($1, $2)", "1", "again"), "write"),
    (P("insert into fp (k, f) values ($1, $2)", "5", "maybe"), "write"),
    (P("insert into fp (k, a) values ($1, $2)", "99999999999", "1"), "write"),
    (P("select * from fp where k = $1", "2"), "order"),
    (P("select * from fp where k = $1", " 3 "), "order"),
    (P("select * from fp where k = $1", None), "order"),
    (P("select k, a + $1, s || $2, $3::bigint * 2, $4::text from fp order by k", "1", "x", "21", "t"), "order"),
    (P("select k from fp where s = $1 and f = $2 and a = $3", "one", "true", "10"), "order"),
    (P("select k from fp where k in ($1, $2) order by k", "1", "3"), "order"),
    (P("select k from fp where k between $1 and $2 order by k", "2", "3"), "order"),
    (P("select k from fp where s like $1 order by k", "o%"), "order"),
    (P("select k from fp order by k limit $1 offset $2", "2", "1"), "order"),
    (P("select k from fp order by k limit $1", None), "order"),
    (P("select k from fp order by k limit $1", "-1"), "order"),
    (P("select k from fp order by k offset $1::bigint", "-1"), "order"),
    (P("select $1::integer + k, case when $2::boolean then s else $3 end from fp order by k", "100", "f", "other"), "order"),
    (P("select $1::bigint, $1::bigint + 1 from fp where k = $2::integer or k = $2::integer + 1 order by k", "7", "1"), "order"),
    (P("select count(*), min(a + $1), max($2::integer) from fp where k > $3", "1", "5", "0"), "order"),
    (P("select f, count(*) from fp group by f having count(*) >= $1 order by 1", "1"), "order"),
    (P("select s, s || $1, min(s) || $2, count(*) from fp group by s having max(s) <> $3 order by 1", "-suffix", "!", "nothing"), "order"),
    (P("update fp set a = $1, s = $2 where k = $3", "11", "uno", "1"), "write"),
    (P("update fp set a = a + $1::bigint where k >= $2::integer and $1::bigint > 0", "5", "2"), "write"),
    (P("update fp set k = $1 where k = $2", "2", "1"), "write"),
    (P("delete from fp where k = $1 and s = $2", "3", "it's"), "write"),
    (P("delete from fp where a = $1::bigint / $2::bigint", "32", "2"), "write"),
    ("select * from fp order by k", "order"),
]

# the schema's forms (docs/m3-engine.md 6x): a key of several columns, a range, IF NOT EXISTS, a change of type to the same type, an index with a condition
FIXED += [
    ("create table fk (a integer, b bigint, c text, n smallint check (n between 0 and 9), primary key (a, b))", "ddl"),
    ("insert into fk values (1, 1, 'x', 0), (1, 2, 'y', 9), (2, 1, 'z', null)", "write"),
    ("insert into fk values (1, 2, 'again', 1)", "write"),
    ("insert into fk values (1, null, 'no', 1)", "write"),
    ("insert into fk values (null, 1, 'no', 1)", "write"),
    ("insert into fk values (3, 3, 'out', 10)", "write"),
    ("insert into fk values (3, 3, 'out', -1)", "write"),
    ("insert into fk (b, a) values (-5, 3), (5, -3)", "write"),
    ("select * from fk order by a, b", "order"),
    ("select * from fk where a = 1 and b = 2", "order"),
    ("select c from fk where b = 1 order by a desc", "order"),
    ("update fk set n = n + 5 where a = 1 and b = 1", "write"),
    ("update fk set n = n + 5 where a = 1 and b = 1", "write"),
    ("update fk set n = null where a = 1", "write"),
    ("update fk set b = 7 where a = 2", "write"),
    ("update fk set a = 1, b = 2 where a = 2", "write"),
    ("delete from fk where a = 3 and b = -5", "write"),
    ("select a, count(*) from fk group by a order by a", "order"),
    ("create table if not exists fk (zzz integer)", "ddl"),
    ("create table if not exists fk (zzz integer primary key, zzz text, nope integer default 'abc')", "ddl"),
    ("select * from fk order by a, b", "order"),
    ("create table if not exists fk2 (k integer primary key, v integer default 3 check (v between 1 and 5))", "ddl"),
    ("insert into fk2 (k) values (1)", "write"),
    ("insert into fk2 values (2, 0)", "write"),
    ("insert into fk2 values (2, 5), (3, 6)", "write"),
    ("alter table fk2 add column if not exists v text", "ddl"),
    ("alter table fk2 add column if not exists w integer check (w between 0 and 3) default 2", "ddl"),
    ("alter table fk2 add column z integer default 9 check (z between 0 and 3)", "ddl"),
    ("alter table fk2 add column y integer check (y between 0 and 3)", "ddl"),
    ("alter table fk2 alter column v type integer", "ddl"),
    ("alter table fk2 alter w set data type integer", "ddl"),
    ("alter table fk2 alter column nope type integer", "ddl"),
    ("update fk2 set w = w + 1", "write"),
    ("update fk2 set w = w + 1, y = 4", "write"),
    ("alter table fk2 add column flag boolean", "ddl"),
    ("create index if not exists fk on fk2 (nope)", "ddl"),
    ("create index if not exists fki on fk2 (nope)", "ddl"),
    ("create index if not exists fki on fk2 (v)", "ddl"),
    ("create index if not exists fki on fk2 (nope)", "ddl"),
    ("create index fki on fk2 (v)", "ddl"),
    ("create index fkp on fk2 (v, w) where flag", "ddl"),
    ("select * from fk2 order by k", "order"),
    ("create table fk3 (a integer primary key, b integer, primary key (a, b))", "ddl"),
    ("create table fk3 (a integer, b integer, primary key (a, a))", "ddl"),
    ("create table fk3 (a integer, b integer, primary key (a, nope))", "ddl"),
    ("create table fk3 (s text, t text, u integer, primary key (t, s))", "ddl"),
    ("insert into fk3 values ('a', 'b', 1), ('ab', '', 2), ('a', '', 3), ('', 'ab', 4), ('', '', 5)", "write"),
    ("insert into fk3 values ('ab', '', 6)", "write"),
    ("select * from fk3 order by t, s", "order"),
    ("select u from fk3 where t = '' and s = 'ab'", "order"),
    ("delete from fk3 where t = ''", "write"),
    ("select * from fk3 order by t, s", "order"),
    ("create table fk5 (k integer primary key, t integer check (t between -3 and -1))", "ddl"),
    ("insert into fk5 values (1, -2)", "write"),
    ("insert into fk5 values (2, 0)", "write"),
    ("insert into fk5 values (3, -4)", "write"),
    ("insert into fk5 values (4, -3), (5, -1), (6, null)", "write"),
    ("create index fkname on fk5 (t)", "ddl"),
    ("create table if not exists fkname (k integer primary key)", "ddl"),
    ("create table fkname (k integer primary key)", "ddl"),
    ("select * from fk5 order by k", "order"),
]

# an identity column (6y): the counter is drawn from by every row an insert reaches, and a failed statement and a rollback do not give the values back
FIXED += [
    ("create table fs (id bigint generated always as identity primary key, e text not null, n integer default 1 check (n between 0 and 5))", "ddl"),
    ("insert into fs (e) values ('a'), ('b')", "write"),
    ("insert into fs (e, n) values ('c', 2), (null, 3), ('d', 4)", "write"),
    ("insert into fs (e, n) values ('e', 2), ('f', 9), ('g', 4)", "write"),
    ("insert into fs (n, e) values (0, 'h')", "write"),
    ("begin", "ddl"),
    ("insert into fs (e) values ('i'), ('j'), ('k')", "write"),
    ("select * from fs order by id", "order"),
    ("rollback", "ddl"),
    ("insert into fs (e) values ('l')", "write"),
    ("begin", "ddl"),
    ("insert into fs (e) values ('m')", "write"),
    ("insert into fs (e) values (null)", "write"),
    ("commit", "ddl"),
    ("begin", "ddl"),
    ("insert into fs (e) values ('n')", "write"),
    ("commit", "ddl"),
    ("insert into fs (e) values ('o')", "write"),
    ("select * from fs order by id", "order"),
    ("select id, e from fs where id = 13", "order"),
    ("update fs set e = e || '!' where id < 3", "write"),
    ("delete from fs where id = 2", "write"),
    ("insert into fs (e) values ('p')", "write"),
    ("select * from fs order by id", "order"),
    ("create table fs2 (k integer primary key, c integer generated always as identity, s smallint)", "ddl"),
    ("insert into fs2 (k) values (5), (5)", "write"),
    ("insert into fs2 (k, s) values (6, 1), (7, 100000)", "write"),
    ("insert into fs2 (k, s) values (8, 'abc')", "write"),
    ("insert into fs2 (k) values (9)", "write"),
    ("select * from fs2 order by k", "order"),
    ("drop table fs2", "ddl"),
    ("create table fs2 (k integer primary key, c integer generated always as identity)", "ddl"),
    ("insert into fs2 (k) values (1)", "write"),
    ("select * from fs2 order by k", "order"),
    ("begin", "ddl"),
    ("create table fs3 (k integer primary key, c bigint generated always as identity)", "ddl"),
    ("insert into fs3 (k) values (1), (2)", "write"),
    ("rollback", "ddl"),
    ("create table fs3 (c bigint generated always as identity, k integer primary key)", "ddl"),
    ("insert into fs3 (k) values (1), (2)", "write"),
    ("select * from fs3 order by k", "order"),
]

# ON CONFLICT DO NOTHING (6z)
FIXED += [
    ("create table fo (k integer primary key, v text not null, n integer check (n between 0 and 9), c bigint generated always as identity)", "ddl"),
    ("insert into fo (k, v) values (1, 'a'), (2, 'b') on conflict do nothing", "write"),
    ("insert into fo (k, v) values (2, 'again'), (3, 'c'), (3, 'twice'), (4, 'd') on conflict do nothing", "write"),
    ("insert into fo (k, v) values (1, 'x'), (2, 'y') on conflict do nothing", "write"),
    ("insert into fo (k, v) values (1, null) on conflict do nothing", "write"),
    ("insert into fo (k, v, n) values (5, 'e', 1), (1, 'out', 10) on conflict do nothing", "write"),
    ("insert into fo (k, v) values (null, 'nokey') on conflict do nothing", "write"),
    ("insert into fo (k, v) values (6, 'f') on conflict do nothing", "write"),
    ("insert into fo (k, v) values (6, 'f')", "write"),
    ("select * from fo order by k", "order"),
    (P("insert into fo (k, v, n) values ($1, $2, $3) on conflict do nothing", "7", "g", "3"), "write"),
    (P("insert into fo (k, v, n) values ($1, $2, $3) on conflict do nothing", "7", "h", "4"), "write"),
    ("select * from fo order by k", "order"),
]

# fewer than five digits and then something else: the text is wrong, whatever the type
FIXED += [
    ("create table fn (k integer primary key, s text)", "ddl"),
    ("insert into fn values (1, '1234z'), (2, ' 12 3'), (3, '9999abc')", "write"),
    ("select cast(s as smallint) from fn", "order"),
    ("select cast(s as integer) from fn where k = 2", "order"),
    ("select cast(s as bigint) from fn where k > 2", "order"),
    ("update fn set s = '77 '", "write"),
    ("select cast(s as smallint), cast(s as bigint) from fn order by k", "order"),
    # the least and the greatest of texts that begin alike (a mutant of the comparison lived when the random history stopped meeting them)
    ("create table fm (k integer primary key, s text)", "ddl"),
    ("insert into fm values (1, 'ab'), (2, 'a'), (3, 'abc'), (4, 'ab'), (5, '')", "write"),
    ("select min(s), max(s) from fm", "order"),
    ("select min(s), max(s) from fm where k > 1 and k < 5", "order"),
    ("select k / 3, min(s), max(s) from fm group by k / 3 order by 1", "order"),
    # COALESCE, GREATEST, LEAST (6ab)
    ("create table fc (k integer primary key, a smallint, b bigint, s text, f boolean)", "ddl"),
    ("insert into fc values (1, 5, null, 'x', true), (2, null, 7, null, null), (3, null, null, 'abc', false), (4, -2, -9, '', null)", "write"),
    ("select k, coalesce(a, b), coalesce(a, b, 0), greatest(a, b, k), least(a, b, k), coalesce(s, 'none'), greatest(s, 'b'), least(s, 'b'), coalesce(f, false) from fc order by k", "order"),
    ("select coalesce(a, k / (k - 1)) from fc order by k", "order"),
    ("select greatest(a, k / (k - 1)) from fc where k > 1 order by k", "order"),
    ("select greatest(a, k / (k - 1)) from fc order by k", "order"),
    ("select coalesce(null, null), greatest(null, null), coalesce('a', 'b'), least(3, 2, 1), greatest('a', 'ab'), coalesce(null, 7) from fc where k = 1", "order"),
    ("select max(coalesce(a, 0)), coalesce(max(b), 0), least(count(*), 2), coalesce(sum(a), min(k)) from fc", "order"),
    ("select coalesce(a, 0), count(*) from fc group by coalesce(a, 0) order by 1", "order"),
    ("select coalesce(a, s) from fc", "order"),
    ("select greatest(f, true), least(f, false) from fc order by k", "order"),
    ("select k from fc where coalesce(b, a, 0) > 0 order by k", "order"),
    ("update fc set a = coalesce(a, 9) + 1, s = coalesce(s, 'was null') where k < 4", "write"),
    ("update fc set b = greatest(b, k), a = least(a, 3)", "write"),
    ("select * from fc order by k", "order"),
    # COALESCE of a constant is that constant, and an error made of it is raised whatever the rows
    ("update fc set k = - coalesce(null, 3000000000, k) where k < 0", "write"),
    ("update fc set k = - coalesce(k, 3000000000) where k < 0", "write"),
    (P("update fc set s = coalesce($1::text, s), a = coalesce($2::smallint, a) where k = $3::integer", None, "7", "1"), "write"),
    (P("update fc set s = coalesce($1::text, s), a = coalesce($2::smallint, a) where k = $3::integer", "new", None, "2"), "write"),
    (P("select case when $1::text is not null then coalesce($2::bigint, 0) else greatest(b, $2::bigint) end from fc order by k", None, "3"), "order"),
    ("select * from fc order by k", "order"),
]

# RETURNING (6aa)
FIXED += [
    ("create table fr (id bigint generated always as identity primary key, e text not null, n integer default 1 check (n between 0 and 9))", "ddl"),
    ("insert into fr (e) values ('a'), ('b') returning id, e", "write"),
    ("insert into fr (e, n) values ('c', 5) returning *", "write"),
    ("insert into fr (e, n) values ('d', 5), (null, 1) returning id", "write"),
    ("insert into fr (e, n) values ('e', 50) returning id", "write"),
    ("insert into fr (e) values ('f') returning id, n, e, fr.id as again, n is null, 7, 'x'", "write"),
    ("update fr set n = n + 1 where id < 3 returning id, n", "write"),
    ("update fr set n = n where id = 3 returning n as \"N\", id", "write"),
    ("update fr set n = n + 4 where id = 3 returning n", "write"),
    ("update fr set n = n + 4 where id = 3 returning n", "write"),
    ("update fr set e = 'none' where id = 99 returning *", "write"),
    ("delete from fr where id = 2 returning id, e, n", "write"),
    ("delete from fr where id = 2 returning id", "write"),
    ("insert into fr (e) values ('g') on conflict do nothing returning id", "write"),
    (P("insert into fr (e, n) values ($1, $2) returning id, e", "h", "3"), "write"),
    (P("update fr set e = $2::text where id = $1::bigint returning id", "1", "one"), "write"),
    (P("update fr set e = $2::text where id = $1::bigint returning id", "77", "none"), "write"),
    (P("delete from fr where id = $1::bigint returning id", "1"), "write"),
    ("select * from fr order by id", "order"),
    ("create table fr2 (a integer, b integer, v text, primary key (a, b))", "ddl"),
    ("insert into fr2 values (1, 1, 'x'), (1, 2, 'y'), (2, 1, 'z') returning b, a", "write"),
    ("insert into fr2 values (1, 1, 'dup'), (3, 3, 'new') on conflict do nothing returning a, b, v", "write"),
    ("update fr2 set b = b + 10 where a = 1 returning a, b, v", "write"),
    ("update fr2 set v = v where a > 0 returning v", "write"),
    ("delete from fr2 returning *", "write"),
    ("select * from fr2", "order"),
]

# a scalar subquery, and INSERT ... SELECT with no table (6ac)
FIXED += [
    ("create table fq2 (id bigint generated always as identity primary key, e text not null, n bigint)", "ddl"),
    ("insert into fq2 (e, n) select 'a', 5", "write"),
    ("insert into fq2 (e, n) select 'b', 6 where 1 < 2", "write"),
    ("insert into fq2 (e, n) select 'c', 7 where (select count(*) from fq2) < 2", "write"),
    ("insert into fq2 (e, n) select 'd', 8 where (select count(*) from fq2) < 64 returning id, e", "write"),
    ("insert into fq2 (e, n) select 'e', 9 where null", "write"),
    ("insert into fq2 (e, n) select null, 9 where false", "write"),
    ("insert into fq2 (e, n) select null, 9 where true", "write"),
    ("insert into fq2 (e, n) select 'f', 'abc' where false", "write"),
    ("insert into fq2 (e, n) select 'g', (select max(n) from fq2) + 1", "write"),
    (P("insert into fq2 (e, n) select $1::text, $2::bigint where (select count(*) from fq2) < $3::bigint returning id, e, n", "h", "20", "64"), "write"),
    (P("insert into fq2 (e, n) select $1::text, $2::bigint where (select count(*) from fq2) < $3::bigint returning id, e, n", "i", "21", "2"), "write"),
    ("select * from fq2 order by id", "order"),
    ("select id from fq2 where n = (select max(n) from fq2)", "order"),
    ("select id from fq2 where n > (select min(n) from fq2) and (select count(*) from fq2) > 1 order by id", "order"),
    ("select id from fq2 where n = (select n from fq2 where id = 99)", "order"),
    ("select id from fq2 where e = (select e from fq2 where id = 1) or n is null", "order"),
    ("update fq2 set n = (select max(n) from fq2) + id where n is not null", "write"),
    ("delete from fq2 where n = (select max(n) from fq2)", "write"),
    # a subquery's value is no constant of the plan: an error made of it in an assignment is a row's, and here no row is reached
    ("update fq2 set n = cast((select e from fq2 where id = 1) as bigint) where id = 99", "write"),
    ("select * from fq2 order by id", "order"),
]

# a sequence (6ad)
FIXED += [
    ("create sequence fseq minvalue 0 start 0", "ddl"),
    ("create sequence fseq", "ddl"),
    ("create sequence if not exists fseq start 100", "ddl"),
    ("create sequence fseq2", "ddl"),
    ("create sequence fseq3 start with 7", "ddl"),
    ("create sequence fq2", "ddl"),
    ("create table fseq (k integer primary key)", "ddl"),
    ("create table fe (id integer primary key, h text not null)", "ddl"),
    ("create index fseq2 on fe (h)", "ddl"),
    ("create index if not exists fseq2 on fe (h)", "ddl"),
    ("insert into fe (id, h) select nextval('fseq'), 'a'", "write"),
    ("insert into fe (id, h) select greatest(nextval('fseq'), 5), 'b'", "write"),
    ("insert into fe (id, h) select greatest(nextval('fseq'), coalesce((select max(id) from fe), -1) + 1), 'd' returning id", "write"),
    ("insert into fe (id, h) values (nextval('fseq'), 'v')", "write"),
    ("insert into fe (id, h) values (nextval('fseq'), null)", "write"),
    ("begin", "ddl"),
    ("insert into fe (id, h) values (nextval('fseq'), 'dup')", "write"),
    ("rollback", "ddl"),
    ("begin", "ddl"),
    ("insert into fe (id, h) values (nextval('fseq2') + 100, 'r')", "write"),
    ("rollback", "ddl"),
    ("insert into fe (id, h) values (nextval('fseq') + 10, 'z')", "write"),
    ("insert into fe (id, h) values (nextval('fseq') + 200, 'm1'), (500, 'm2')", "write"),
    ("insert into fe (id, h) values (nextval('fseq') + 300, 'm3'), (500, 'again')", "write"),
    ("insert into fe (id, h) values (nextval('fseq2'), 'two')", "write"),
    ("insert into fe (id, h) values (nextval('fseq3'), 'seven')", "write"),
    ("insert into fe (id, h) values (nextval('fseq3'), 'eight') on conflict do nothing returning id, h", "write"),
    (P("insert into fe (id, h) select greatest(nextval('fseq'), coalesce((select max(id) from fe), -1) + 1), $1::text returning id", "param"), "write"),
    ("select * from fe order by id", "order"),
]

# the facts of a commit (6af): what a transaction did to a row is one fact, from what the row was to what it is
FIXED += [
    ("create table ff (k integer primary key, v text)", "ddl"),
    ("create table ff2 (a text, b integer, v integer, primary key (a, b))", "ddl"),
    ("insert into ff values (1, 'one'), (2, 'two'), (3, 'three')", "write"),
    ("begin", "ddl"),
    ("insert into ff values (4, 'four')", "write"),
    ("update ff set v = 'FOUR' where k = 4", "write"),
    ("update ff set v = 'x' where k = 1", "write"),
    ("update ff set v = 'one' where k = 1", "write"),
    ("delete from ff where k = 2", "write"),
    ("insert into ff values (9, 'gone')", "write"),
    ("delete from ff where k = 9", "write"),
    ("update ff set v = 'y' where k = 3", "write"),
    ("delete from ff where k = 3", "write"),
    ("insert into ff2 values ('b', 2, 1), ('a', 10, 2), ('a', 9, 3), ('', 1, 4)", "write"),
    ("update ff2 set v = v + 1 where a = 'a'", "write"),
    ("commit", "ddl"),
    ("begin", "ddl"),
    ("insert into ff values (2, 'again')", "write"),
    ("delete from ff where k = 2", "write"),
    ("commit", "ddl"),
    ("begin", "ddl"),
    ("delete from ff where k = 1", "write"),
    ("insert into ff values (1, 'one')", "write"),
    ("commit", "ddl"),
    ("begin", "ddl"),
    ("update ff2 set b = b + 100 where a = 'a'", "write"),
    ("rollback", "ddl"),
    ("update ff2 set b = b + 100 where a = 'a'", "write"),
    ("select * from ff order by k", "order"),
    ("select * from ff2 order by a, b", "order"),
]

FIXED += [
    # BEGIN in a transaction that has failed is the error every statement there gets
    ("begin", "ddl"),
    ("select 1 / (k - k) from ff", "set"),
    ("begin", "ddl"),
    ("select 1 from ff", "set"),
    ("rollback", "ddl"),
    # a transaction that writes nothing, after one that wrote, is no commit
    ("create table fid (k integer primary key, v integer)", "ddl"),
    ("begin", "ddl"),
    ("insert into fid values (1, 1), (2, 2)", "write"),
    ("commit", "ddl"),
    ("begin", "ddl"),
    ("select count(*) from fid", "set"),
    ("commit", "ddl"),
    ("drop table fid", "ddl"),
]
# more counters drawn from, with no failure between, than a session remembers at once (32): what was drawn is forgotten whenever nothing is left to roll back
FIXED += [("create table fid%d (k integer generated always as identity primary key, v integer)" % i, "ddl") for i in range(34)]
FIXED += [("insert into fid%d (v) values (%d)" % (i, i), "write") for i in range(34)]
FIXED += [("drop table fid%d" % i, "ddl") for i in range(34)]

FIXED += [
    # truncate (6ao): every row goes, the table and its counter stay; it is taken back by a rollback like any write
    ("create table ftr (k integer generated always as identity primary key, v text)", "ddl"),
    ("insert into ftr (v) values ('a'), ('b'), ('c')", "write"),
    ("truncate ftr", "ddl"),
    ("select count(*) from ftr", "set"),
    ("truncate table ftr", "ddl"),
    ("insert into ftr (v) values ('d') returning k", "write"),
    ("begin", "ddl"),
    ("insert into ftr (v) values ('e')", "write"),
    ("truncate ftr", "ddl"),
    ("select count(*) from ftr", "set"),
    ("rollback", "ddl"),
    ("select k, v from ftr order by k", "order"),
    ("begin", "ddl"),
    ("truncate ftr", "ddl"),
    ("insert into ftr (v) values ('f')", "write"),
    ("commit", "ddl"),
    ("select k, v from ftr order by k", "order"),
    ("truncate nosuchtable", "ddl"),
    ("drop table ftr", "ddl"),
]

FIXED += [
    # an insert that lists no columns and has fewer values than the table has columns: the values are for its first columns (6ap)
    ("create table ffv (k integer primary key, a text not null, b integer not null default 7, c text)", "ddl"),
    ("insert into ffv values (1, 'one')", "write"),
    ("insert into ffv values (2, 'two', 2), (3, 'three', 3)", "write"),
    ("insert into ffv values (4)", "write"),
    ("insert into ffv values (5, 'five', 5, 'c')", "write"),
    ("insert into ffv values (6, 'six') returning k, b, c", "write"),
    ("insert into ffv values (1, 'dup') on conflict do nothing", "write"),
    ("select * from ffv order by k", "order"),
    ("drop table ffv", "ddl"),
]

FIXED += [
    # a table renamed (6ar): the same rows under another name, its counter and its indexes with it
    ("create table frn (k integer generated always as identity primary key, v text)", "ddl"),
    ("insert into frn (v) values ('x'), ('y')", "write"),
    ("create index frni on frn (v)", "ddl"),
    ("create table frno (k integer primary key)", "ddl"),
    ("alter table frn rename to frno", "ddl"),
    ("alter table frn rename to frni", "ddl"),
    ("alter table frnope rename to frnz", "ddl"),
    ("alter table frn rename to frn2", "ddl"),
    ("select * from frn2 order by k", "order"),
    ("insert into frn2 (v) values ('z') returning k", "write"),
    ("update frn2 set v = v || '!' where k = 1", "write"),
    ("create index frni on frno (k)", "ddl"),
    ("begin", "ddl"),
    ("alter table frn2 rename to frn3", "ddl"),
    ("insert into frn3 (v) values ('t')", "write"),
    ("rollback", "ddl"),
    ("select count(*) from frn2", "set"),
    ("begin", "ddl"),
    ("alter table frn2 rename to frn", "ddl"),
    ("delete from frn where k = 2", "write"),
    ("commit", "ddl"),
    ("select * from frn order by k", "order"),
    ("drop table frn", "ddl"),
    ("create index frni on frno (k)", "ddl"),
    # an index goes with its table under whatever name the table has when it is dropped
    ("create table frn4 (k integer primary key, v text)", "ddl"),
    ("create index frnx on frn4 (k)", "ddl"),
    ("alter table frn4 rename to frn5", "ddl"),
    ("insert into frn5 values (1, 'a'), (2, 'a')", "write"),
    ("drop table frn5", "ddl"),
    ("create index frnx on frno (k)", "ddl"),
    ("drop table frno", "ddl"),
]

DEP_SETUP = ["create table fz (k integer primary key, n integer)", "insert into fz values (3, 30)", "insert into fz values (2, 20)", "insert into fz values (1, 10)",
             "create table fw (wk integer primary key, m integer)", "insert into fw values (1, 5), (9, 0)",
             "create table fi (k integer primary key, c bigint generated always as identity)", "insert into fi (k) values (1)",
             "create table ft (k integer primary key, s text)", "insert into ft values (1, '3000000000 7abc')", "create sequence fzs",
             "create table fu (k integer primary key, u integer)", "insert into fu values (1, 1), (2, 2), (3, 3), (4, 40)", "create unique index fuu on fu (u)",
             "create table fuc (k integer primary key, u integer unique)", "create sequence fue_u_key",
             "create table fts (k integer primary key, at timestamptz, d timestamp)", "insert into fts values (1, '2026-11-27 10:00:00+00', '2026-11-27 10:00:00')"]
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
    # a unique index (6bo): each row takes the value the next one has, and PostgreSQL meets the next one still holding it
    ("update fu set u = u + 1 where k < 4", "23505"),
    # the other way no row takes a value that is still held when PostgreSQL gets to it
    ("update fu set u = u - 1 where k < 4", None),
    # two rows change places: an error in either order, and the engine does not reason that far
    ("update fu set u = 3 - u where k < 3", "23505"),
    # every row of a DISTINCT over a constant is the same row, so one is enough: PostgreSQL stops there
    ("select distinct 'x' from fz where 10 / (k - 2) > 0", None),
    # and under an aggregation too: the group whose HAVING divides by zero is not reached
    ("select distinct 'x' from fz group by n having 10 / (max(k) - 2) < 100", None),
    # a HAVING condition with no aggregate in it is applied to the rows before they are grouped: the row with k = 2 is never summed
    ("select k, sum(10 / (k - 2)) from fz group by k having k > 2", None),
    # and one that is false for certain means nothing is read at all, not even the WHERE
    ("select count(*) from fz where 10 / (k - 2) > 0 having false", None),
]


# Statements the engine REFUSES as `engine-unsupported` on purpose, and what PostgreSQL 16 does with each: answers PostgreSQL has rules for that the engine does not reproduce. A change that starts
# answering one of them has to show that the answer is PostgreSQL's.
UNSUP = [
    ("select sum(cast(n as bigint)) from fz", None),                    # a numeric
    ("select k, count(*) from fz group by cast(k as integer)", None),   # the cast is nothing, so k is grouped
    ("select k, n from fz group by k", None),                           # n depends on the key
    ("select count(*) from fz group by - 1", "42P10"),                  # a place that does not exist
    ("select sum(count(*)) from fz", "42803"),
    ("select k from fz where count(*) > 0", "42803"),
    ("select upper('a') from fz", None),
    ("select k from fz order by - 1", "42P10"),
    ("select k from fz order by - - 1", None),                           # the minus signs fold into the constant: the first item
    ("select count(*) from fz group by - - 9", "42P10"),
    ("select k from fz order by 'a'", "42601"),
    # joins (6k): a condition that can raise is refused, because PostgreSQL computes this one for the row (9, 0) of fw, which joins with nothing
    ("select fz.k from fz, fw where fz.k = fw.wk and 10 / fw.m > 0", "22012"),
    ("select fz.k from fz join fw on fz.k = fw.wk where 10 / fw.m > 0", "22012"),
    # and this one only for rows that join, so it answers
    ("select fz.k from fz join fw on fz.k = fw.wk and 10 / fw.m > fz.k", None),
    ("select a1.k from fz a1 join fz a2 on a1.k = a2.k", None),          # a table joined to itself
    ("update fu set k = k + 10, u = u + 100", None),                      # a key that changes on a table with a unique index, and the indexed value with it (6bo)
    ("update fu set k = k + 10, u = 1 where k = 2", "23505"),
    # times (6bp): what PostgreSQL reads or computes and the engine does not
    ("insert into fts values (2, 'Nov 27 2026', null)", None),            # a date as it is said
    ("insert into fts values (2, '2026-11-27 24:00:00', null)", None),    # midnight at the end of the day
    ("insert into fts values (2, '2026-11-27 23:59:60', null)", None),    # a leap second
    ("insert into fts values (2, 'infinity', null)", None),
    ("insert into fts values (2, '2026-11-27 10:00:00 Europe/Madrid', null)", None),   # a zone by its name
    ("insert into fts values (2, '2026-11-27 10:00:00.1234567', null)", None),          # more digits than are kept: PostgreSQL rounds
    ("select k from fts where at = '2026-13-01'", "22008"),              # a constant that is no date: an error when PostgreSQL plans
    ("select at - d from fts", None),                                    # an interval
    ("select d - d from fts", None),
    ("select at + 1 from fts", "42883"),
    ("select at || 'x' from fts", None),
    ("select case when k = 1 then at else d end from fts", None),         # the two types in one CASE: PostgreSQL makes them moments
    ("select coalesce(d, at) from fts", None),
    ("select cast(at as date) from fts", None),
    ("select date_trunc('day', at) from fts", None),
    ("create table ftq (k integer primary key, t date)", None),
    ("select now() from fts", None),
    ("insert into fts values (2, now(), null)", None),
    ("drop index fuc_u_key", "2BP01"),                                    # the index of a constraint: an error of its own, and another statement to drop it by
    ("alter table fuc add column v integer unique", None),               # a constraint added to a table that has rows
    ("create table fue (k integer primary key, u integer unique)", None), # the constraint's name is a sequence's: PostgreSQL takes another
    ("create table fuj (a integer, unique (a), b integer, primary key (b))", None),          # a constraint of the table written before a column
    ("create table fuj (a integer, b integer, unique (a, a), primary key (b))", "42701"),   # a column twice in one list
    ("create table fuj (k integer primary key, a integer, unique (a), unique (a))", None),    # the same constraint twice: PostgreSQL makes one
    ("create table fug (k integer primary key, %s)" % ", ".join("a%d integer unique" % i for i in range(9)), None),   # more unique columns than the engine takes
    ("create table fuf (k integer primary key, a_column_whose_name_is_not_too_long_but_is_with_the_tables integer unique)", None),
    ("select fw.m, count(*) from fz join fw on fz.k = fw.wk group by fw.wk", None),   # m depends on fw's key
    # digits that are out of range, then something that is no digit: PostgreSQL says out of range, having not read on
    ("select cast(s as integer) from ft", "22003"),
    ("select cast(s as smallint) from ft", "22003"),
    ("select cast(s as bigint) from ft", "22P02"),
    # an aggregate under an operator that PostgreSQL folds to null when it plans: the aggregate is never computed, nor its error raised
    ("select max(1 / (k - 1)) - null from fz", None),
    ("select count(*) from fz having max(1 / (k - 1)) > null", None),
    # the schema's forms (6x)
    ("create table fzc (k integer primary key, n integer check (n > 0))", None),                     # a check that is no range
    ("create table fzc (k integer primary key, n integer check (n not between 0 and 3))", None),
    ("create table fzc (k integer primary key, n integer, m integer check (n between 0 and 3))", None),   # of another column
    ("create table fzc (k integer primary key, s text check (s between 'a' and 'b'))", None),
    ("create table fzc (k integer primary key, a bigint generated always as identity, b bigint generated always as identity)", None),   # two identity columns
    ("create table fzc (k integer primary key, a text generated always as identity)", "22023"),
    ("alter table fz add column idn bigint generated always as identity", None),                     # the rows there would each draw a value
    ("insert into fz values (7, 7) returning n / 0", "22012"),                                        # an item that can raise an error for a row
    ("insert into fz values (7, 7) returning n + 1", None),
    ("delete from fz returning count(*)", "42803"),
    ("update fz set n = 1 returning k || 'x'", None),
    ("select coalesce(n, 1 / 0) from fz", "22012"),                                                    # a constant that is an error: raised when PostgreSQL plans, or never reached
    ("update fz set n = coalesce(n, 1 / 0)", "22012"),                                               # (and no row has a null there: the rows would not show it)
    ("select coalesce(n, 'abc') from fz", "22P02"),                                                   # a literal that is not of the type
    ("select coalesce() from fz", "42601"),
    ("select upper('a') || coalesce('b', 'c') from fz", None),
    # a subquery that is not a value computed once (6ac)
    ("select k from fz where n > (select n from fz)", "21000"),                                       # more than one row
    ("select k from fz where n in (select n from fz)", None),
    ("select k from fz where n not in (select n from fz where k = 99)", None),                        # no row: IN of nothing is not IN of a null
    (P("select k from fz where n = (select max(n) from fz) and k = $2", "1", "2"), "42P18"),         # a parameter the statement does not name
    ("select k from fz where n = (select k, n from fz where k = 1)", "42601"),                        # several columns
    ("select k from fz where n = (select nope from fz where k = 1)", "42703"),                        # it fails
    ("select k from fz f1 where n = (select max(n) from fz where k = f1.k)", None),                   # it names the statement around it
    ("select k from fz where n > (select count(*) from fz where n > (select 5 from fz where k = 1))", None),   # one in another
    ("select k from fz where cast((select 'x' from fz where k = 1) as integer) = 1 and k > 99", "22P02"),  # a condition with no column in it is computed once, before any row
    ("select (select max(n) from fz), k from fz", None),                                              # it would name the column
    ("select k, n - (select min(n) from fz) from fz", None),                                          # (under an operator it would not, and is refused all the same)
    ("select cast((select count(*) from fz) as text) from fz", None),
    ("delete from fz where k = 1 returning (select count(*) from fz)", None),
    ("select k from fz where n = (select 1 / (k - 1) from fz where k = 1)", "22012"),
    ("insert into fz select 9, 9 from fw", "23505"),
    ("insert into fz select 9, 9 where n > 0", "42703"),
    ("insert into fz select 9, 9 where 1 / 0 > 1", "22012"),
    ("insert into fz select 9, 9 where 7", "42804"),
    ("insert into fz select 9, 'abc' where 7", "42804"),                                              # the condition's error, not the row's
    # a sequence (6ad): a nextval that is not drawn once for certain, or not in an insert
    ("insert into fz values (nextval('fzs'), 1), (nextval('fzs'), 2)", "23505"),
    ("insert into fz values (coalesce(nextval('fzs'), 1), 1)", "23505"),
    ("insert into fz select nextval('fzs'), 1 where true", "23505"),
    ("insert into fz values (nextval('nope'), 1)", "42P01"),
    ("insert into fz values (1, 1), (nextval('fzs'), 2)", "23505"),                                  # the first row fails: the second's value is not drawn
    ("insert into fz values (1, 1), (greatest(nextval('fzs'), 3), 2)", "23505"),
    ("insert into fz values (case when false then greatest(nextval('fzs'), 1) else 55 end, 1)", None),   # under a CASE: not computed
    ("insert into fz values (coalesce(56, greatest(nextval('fzs'), 1)), 1)", None),                  # after a COALESCE that is settled
    ("insert into fz values (57, 1) returning k > 0 or greatest(nextval('fzs'), 1) > 0", None),
    ("insert into fz values (nextval('fzs') + 60, nextval('fzs'))", None),                           # twice
    ("insert into fz values (nextval('fzs') + 3000000000, 1)", "22003"),                              # an error of the value drawn: after the draw, to PostgreSQL
    ("insert into fi (k) values ((select max(k) from fz) + 3000000000)", "22003"),                    # the same, for an identity column and a subquery's value
    ("select nextval('fzs') from fz", None),
    ("update fz set n = nextval('fzs')", None),
    ("create sequence fzt start 0", "22023"),
    ("create sequence fzt increment 2", None),
    ("insert into fz values (9, 9, 9)", "42601"),                                                     # more values than the table has columns
    ("insert into fz values (8, 8), (7)", "42601"),                                                  # rows of different lengths
    ("alter table fz rename column n to m", None),                                                   # the engine renames a table, not what is in it
    ("alter table fz rename to fzz cascade", "42601"),
    ("truncate fz restart identity", None),                                                          # the options of TRUNCATE are not the engine's
    ("truncate fz, fw", None),
    ("truncate fz cascade", None),
    ("update fi set c = 7", "428C9"),                                                                # an identity column is given no value
    ("insert into fi values (2, 9)", "428C9"),
    ("insert into fi (c, k) values (9, 2)", "428C9"),
    ("alter table fz alter column n type bigint", None),                                              # a change of type
    ("create index fzp on fz (n) where n > 1", None),                                                 # a condition that is no boolean column
    ("create index fzp on fz (n) where n", "42804"),
    # parameters (6w): PostgreSQL gives one the type of its first use, and refuses one that meets no type
    (P("select k from fz where n > $1 or k = $1", "1"), None),          # used twice with no cast
    (P("select $1::bigint, $1::text from fz", "1"), None),              # and with two casts
    (P("select k from fz where $1 between k and n", "2"), None),         # BETWEEN uses it twice
    (P("select k from fz where $1 in (k, 1)", "2"), None),               # and so does IN
    (P("select k from fz where n in ($1, k::bigint)", "2"), None),       # a parameter among integers of two widths
    (P("select k from fz where $1 is null", "1"), "42P18"),
    (P("select k from fz where $1 = $2", "1", "1"), None),
    (P("select k from fz where k = $2", "1", "2"), "42P18"),             # a parameter the statement does not name
]


PGMAJOR = [0]


# Reads by an index (docs/m3-engine.md 6bo, slice 2). Each statement says whether it has to be read by one: the run's count of such reads has to be the number of
# those, so that an index read where it may not be, and one not read where it is there to be, both fail; PostgreSQL holds the answers.
LONG = "abcdefghijklmnopqrstuvwx"   # 24 bytes: what an entry keeps of a text
VIAFIXED = [
    ("create table fvi (k integer primary key, a integer, b text, c bigint not null, s smallint, f boolean)", "ddl", False),
    ("insert into fvi values (1, 5, 'x', 7, 3, true), (2, 5, '', 7, null, false), (3, 5, 'x', 8, 3, null), (4, 6, '%s-1', 7, -3, true), (5, null, '%s-2', 9, 3, true), (6, 5, null, 7, 4, false), "
     "(7, -5, '%s', 7, 3, true), (8, 0, 'xy', 8, 0, null), (9, 5, 'X', 8, 32767, true), (10, 2147483647, 'ñ', -7, -32768, false)" % (LONG, LONG, LONG), "write", False),
    ("select k from fvi where a = 5", "set", False),
    ("create index fvia on fvi (a)", "ddl", False),
    ("create index fvib on fvi (b)", "ddl", False),
    ("create index fvis on fvi (s)", "ddl", False),
    ("create index fvica on fvi (c, a)", "ddl", False),
    # (a partial index, named to be met before the whole one on the same column: it is not read, it has not every row)
    ("create index fvi0 on fvi (s) where f", "ddl", False),
    ("select k from fvi where a = 5", "set", True),
    ("select k, b from fvi where 5 = a", "set", True),
    ("select * from fvi where b = 'x'", "set", True),
    ("select * from fvi where b = ''", "set", True),
    ("select k from fvi where b = '%s-1'" % LONG, "set", True),
    ("select k from fvi where b = '%s'" % LONG, "set", True),
    ("select k from fvi where b = '%s-'" % LONG, "set", True),
    ("select k from fvi where b = 'ñ'", "set", True),
    ("select count(*), max(k), min(b) from fvi where a = 5", "set", True),
    ("select a, count(*) from fvi where c = 7 group by a", "set", True),
    ("select k from fvi where a = 5 and b = 'x'", "set", True),
    ("select k from fvi where a = 5 and (b = 'x' or c > 7)", "set", True),
    ("select k from fvi where a = 99", "set", True),
    ("select k from fvi where a = 2147483647", "set", True),
    ("select k from fvi where a = 3000000000", "set", True),
    ("select k from fvi where s = 3", "set", True),
    ("select k from fvi where s = 100000", "set", True),
    ("select k from fvi where a = 5 order by k desc limit 2", "order", True),
    ("select distinct b from fvi where a = 5", "set", True),
    (P("select k from fvi where a = $1", "5"), "set", True),
    (P("select k from fvi where b = $1 and a = $2", "x", "5"), "set", True),
    # not by an index: no constant, a null, the key bounds the scan, an OR, what can raise, a range, a partial index's column, an expression, a type that is not the column's (and, further down, a join)
    ("select k from fvi where a = c", "set", False),
    ("select k from fvi where a = null", "set", False),
    ("select k from fvi where a = 5 and k > 2", "set", False),
    ("select k from fvi where a = 5 or b = 'x'", "set", False),
    ("select k from fvi where a = 5 and 10 / (k - 3) > 0", "set", False),
    ("select k from fvi where a > 5", "set", False),
    ("select k from fvi where f = true", "set", False),
    ("select k from fvi where a + 0 = 5", "set", False),
    ("select k from fvi where not (a = 5)", "set", False),
    ("select k from fvi where b = 5", "set", False),
    ("select k from fvi where a = '5'", "set", True),
    ("select k from fvi where a = ' 5 '", "set", True),
    (P("select k from fvi where s = $1", "3"), "set", True),
    (P("select k from fvi where a = $1 and k > $2", "5", "2"), "set", False),
    (P("select k from fvi where a = $1", None), "set", False),
    ("select k from fvi where b = null", "set", False),
    (P("select k from fvi where b = $1", None), "set", False),
    # a negative number as it is written is a constant; a minus over anything else is not (it can overflow, and an error of the WHERE has to be found on every row: 6g)
    ("select k from fvi where a = -5", "set", True),
    ("select k from fvi where s = -32768", "set", True),
    ("select k from fvi where -7 = c", "set", True),
    ("select k from fvi where a = -2147483649", "set", True),
    ("select k from fvi where a = - -5", "set", False),
    ("select k from fvi where a = -s", "set", False),
    ("select k from fvi where a = -5 and c = -(-7)", "set", False),
    # after writes: a value changed, a row removed, a key moved, a transaction rolled back and one kept
    ("update fvi set a = 6 where k = 1", "write", False),
    ("select k from fvi where a = 5", "set", True),
    ("select k from fvi where a = 6", "set", True),
    ("update fvi set c = c + 1, b = b || '!' where a = 5", "write", False),
    ("select k, c from fvi where b = 'x!'", "set", True),
    ("select k from fvi where b = 'x'", "set", True),
    ("select k from fvi where c = 8", "set", True),
    ("delete from fvi where k = 2", "write", False),
    ("delete from fvi where a = 6", "write", False),
    ("select k from fvi where a = 5", "set", True),
    ("select k from fvi where a = 6", "set", True),
    ("update fvi set k = k + 100 where k = 3", "write", False),
    ("select k from fvi where a = 5", "set", True),
    ("begin", "ddl", False),
    ("insert into fvi values (20, 5, 'new', 1, 1, true), (21, 5, 'x', 1, 1, true)", "write", False),
    ("select k from fvi where a = 5", "set", True),
    ("select k from fvi where b = 'new'", "set", True),
    ("rollback", "ddl", False),
    ("select k from fvi where a = 5", "set", True),
    ("select k from fvi where b = 'new'", "set", True),
    ("begin", "ddl", False),
    ("insert into fvi values (22, 5, 'kept', 1, 1, true)", "write", False),
    ("commit", "ddl", False),
    ("select k from fvi where b = 'kept'", "set", True),
    ("insert into fvi values (23, 5, 'r', 1, 1, true) returning k, a", "write", False),
    # an index dropped is not read; made again it is
    ("drop index fvia", "ddl", False),
    ("select k from fvi where a = 5", "set", False),
    ("create index fvia on fvi (a)", "ddl", False),
    ("select k from fvi where a = 5", "set", True),
    # a key of two columns, one a text
    ("create table fvj (g text, h integer, v text, primary key (g, h))", "ddl", False),
    ("insert into fvj values ('a', 1, 'p'), ('a', 2, 'q'), ('', 1, 'p'), ('b', -1, null), ('ab', 1, 'p')", "write", False),
    ("create index fvjv on fvj (v)", "ddl", False),
    ("select * from fvj where v = 'p'", "set", True),
    ("select * from fvj where v = 'q' and g = 'a'", "set", True),
    ("select fvi.k, fvj.g from fvi join fvj on fvj.h = fvi.k where fvi.a = 5", "set", False),
    ("update fvj set h = h + 10 where g = 'a'", "write", False),
    ("select * from fvj where v = 'p'", "set", True),
    ("alter table fvj rename to fvk", "ddl", False),
    ("select * from fvk where v = 'p'", "set", True),
    # more rows of one value than a leaf of the tree has entries
    ("create table fvl (k integer primary key, a integer)", "ddl", False),
    ("create index fvla on fvl (a)", "ddl", False),
    ("insert into fvl values " + ", ".join("(%d, %d)" % (i, i % 3) for i in range(1200)), "write", False),
    ("select k from fvl where a = 1", "set", True),
    # a range of an indexed column (slice 4): by the index when the range is at most a quarter of it, by the table when it is more
    ("create table fvr (k integer primary key, a integer, b text, c text, f boolean)", "ddl", False),
    ("insert into fvr values " + ", ".join("(%d, %d, 'v%03d', '%s%03d', %s)" % (i, i, i % 50, LONG, i, "true" if i % 2 else "false") for i in range(400)), "write", False),
    ("insert into fvr values " + ", ".join("(%d, null, null, null, null)" % i for i in range(400, 410)), "write", False),
    ("create index fvra on fvr (a)", "ddl", False),
    ("create index fvrb on fvr (b)", "ddl", False),
    ("create index fvrc on fvr (c)", "ddl", False),
    ("create index fvr0 on fvr (k) where f", "ddl", False),
    ("select k from fvr where a >= 10 and a < 20", "set", True),
    ("select k from fvr where a > 10 and a < 12", "set", True),
    ("select k from fvr where a > 390", "set", True),
    ("select k from fvr where a < 5", "set", True),
    ("select k from fvr where 395 <= a", "set", True),
    ("select k from fvr where 3 > a", "set", True),
    ("select k from fvr where a between 100 and 110", "set", True),
    ("select count(*), min(a), max(b) from fvr where a between 100 and 110", "set", True),
    ("select k from fvr where a > -5 and a < 5", "set", True),
    ("select k from fvr where a > 1000", "set", True),
    ("select k from fvr where a < 20 and a > 30", "set", True),
    ("select k from fvr where a >= 20 and a <= 20", "set", True),
    ("select k from fvr where a > 3000000000", "set", True),
    ("select k from fvr where b >= 'v010' and b <= 'v011'", "set", True),
    ("select k from fvr where b > 'v048'", "set", True),
    ("select k from fvr where b < 'v001'", "set", True),
    (P("select k from fvr where a >= $1 and a < $2", "50", "60"), "set", True),
    ("select k from fvr where a >= 0 and a < 100", "set", True),
    # (with no lower bound the read begins after the nulls, and they are counted with the rest of the index)
    ("select k from fvr where a < 100", "set", True),
    # an equality is taken before a range
    ("select k from fvr where b > 'v000' and a = 5", "set", True),
    ("select k from fvr where a > 1 and b = 'v005'", "set", True),
    # more than a quarter: the table
    ("select k from fvr where a >= 0 and a < 104", "set", False),
    ("select k from fvr where a < 119", "set", False),
    ("select k from fvr where a > 100", "set", False),
    ("select k from fvr where a >= 0", "set", False),
    ("select k from fvr where a < 300", "set", False),
    ("select k from fvr where b >= 'v010'", "set", False),
    # (the first index with a bound is the one asked about, and its range is too much of it)
    ("select k from fvr where b > 'v01' and b < 'v02' and a < 300", "set", False),
    # texts that begin alike are all one entry's value: the range is all of them, and the table is read
    ("select k from fvr where c >= '%s010' and c <= '%s012'" % (LONG, LONG), "set", False),
    # not by an index: the key bounds the scan, an OR, what can raise, a column on both sides, the past is elsewhere
    ("select k from fvr where a > 390 and k > 5", "set", False),
    ("select k from fvr where a > 390 or a < 3", "set", False),
    ("select k from fvr where a > 390 and 10 / (k - 395) > 0", "set", False),
    ("select k from fvr where a > k + 390", "set", False),
    ("select k from fvr where a <> 5 and a is not null and k < 0", "set", False),
    # ORDER BY an indexed integer column with a LIMIT and no WHERE (slice 4, second part): the first rows of the index, forwards or backwards.
    # (the ten nulls tie: where they are at the edge of the limit the answer is held by its number of rows, as PostgreSQL's choice among them is its own)
    ("select k, a from fvr order by a limit 5", "order", True),
    ("select k, a from fvr order by a asc limit 3 offset 7", "order", True),
    ("select k, a from fvr order by a desc limit 5 offset 12", "order", True),
    ("select a, k from fvr order by a desc limit 30 offset 10", "order", True),
    ("select k from fvr order by a desc limit 4", "count", True),
    ("select k, a from fvr order by a limit 3 offset 398", "count", True),
    ("select k, a from fvr order by a limit 1024", "set", True),
    ("select k, a from fvr order by a desc limit 1024", "set", True),
    ("select a from fvr order by a limit 0", "set", True),
    ("select a is null, k, 7 from fvr order by a limit 2", "order", True),
    (P("select k, a from fvr order by a limit $1", "3"), "order", True),
    (P("select k, a from fvr order by a desc limit $1 offset $2", "3", "10"), "order", True),
    # not by an index: more rows than are read one by one, no limit, a text, two items, an expression, DISTINCT, a WHERE, a partial index, an item that can raise
    ("select k, a from fvr order by a limit 1025", "set", False),
    ("select k, a from fvr order by a", "set", False),
    ("select k, b from fvr order by b limit 3", "count", False),
    ("select k from fvr order by a, k limit 3", "order", False),
    ("select k from fvr order by a + 0 limit 3", "order", False),
    ("select distinct a from fvr order by a limit 3", "order", False),
    ("select k from fvr where k > 3 order by a limit 3", "order", False),
    ("select k from fvr where f order by a limit 3", "order", False),
    ("select k from fvr order by k limit 3", "order", False),
    ("select 10 / (k - 500), a from fvr order by a limit 2", "order", False),
    ("select b || 'x', a from fvr order by a limit 2", "order", False),
    # after writes
    ("update fvr set a = a + 1000 where k < 5", "write", False),
    ("delete from fvr where k = 398", "write", False),
    ("select k from fvr where a < 8", "set", True),
    ("select k from fvr where a > 395", "set", True),
    ("select k, a from fvr where a >= 1000 and a <= 1002", "set", True),
    ("select k, a from fvr order by a desc limit 12 offset 10", "order", True),
    ("select k, a from fvr order by a limit 6", "order", True),
    ("begin", "ddl", False),
    ("insert into fvr values (500, -1, 'new', 'new', true), (501, 5000, 'new', 'new', true)", "write", False),
    ("select k, a from fvr order by a limit 2", "order", True),
    ("select k, a from fvr order by a desc limit 2 offset 10", "order", True),
    ("rollback", "ddl", False),
    ("select k, a from fvr order by a limit 2", "order", True),
    # an index on a time (6bp): a value, a small range, the first and the last rows
    ("create table fvt (k integer primary key, at timestamptz, d timestamp)", "ddl", False),
    ("insert into fvt values " + ", ".join("(%d, '2026-01-%02d %02d:00:00+00', '2025-%02d-01 00:00:00')" % (i, 1 + i % 28, i % 24, 1 + i % 12) for i in range(60)), "write", False),
    ("insert into fvt values (60, null, null), (61, null, '2025-03-01')", "write", False),
    ("create index fvtat on fvt (at)", "ddl", False),
    ("create index fvtd on fvt (d)", "ddl", False),
    ("select k from fvt where at = '2026-01-05 04:00:00+00'", "set", True),
    ("select k from fvt where at = '2026-01-05 06:00:00+02'", "set", True),
    ("select k from fvt where d = '2025-03-01'", "set", True),
    (P("select k from fvt where at = $1", "2026-01-07T06:00:00Z"), "set", True),
    ("select k from fvt where at >= '2026-01-10' and at < '2026-01-12'", "set", True),
    ("select k from fvt where at > '2026-01-27 12:00:00+00'", "set", True),
    ("select k from fvt where at > '2026-01-05'", "set", False),
    ("select k, at from fvt order by at limit 3", "order", True),
    ("select k from fvt order by at desc limit 3", "count", True),
    ("select k, at from fvt order by at desc limit 3 offset 2", "order", True),
    ("truncate fvi", "ddl", False),
    ("select k from fvi where a = 5", "set", True),
    ("insert into fvi values (1, 5, 'x', 7, 3, true)", "write", False),
    ("select k from fvi where a = 5", "set", True),
]


# Unique indexes (docs/m3-engine.md 6bo, slice 3): every statement is answered, and as PostgreSQL answers it.
UNIQFIXED = [
    ("create table fua (k integer primary key, u integer, s text, f boolean, a integer, b integer, c integer)", "ddl"),
    ("insert into fua values (1, 1, 'a', true, 1, 1, 1), (2, 2, 'b', true, 1, 2, 2), (3, null, 'c', false, 2, 1, 2), (4, null, '%s-1', true, null, 1, 3), (5, 5, '%s-2', false, null, 1, 3)" % (LONG, LONG), "write"),
    # an index over rows that are not unique is not made, and its name stays free
    ("create unique index fuax on fua (a)", "ddl"),
    ("create index fuax on fua (a)", "ddl"),
    ("create unique index fuau on fua (u)", "ddl"),
    ("create unique index fuas on fua (s)", "ddl"),
    ("create unique index fuaab on fua (a, b)", "ddl"),
    ("create unique index fuac on fua (c) where f", "ddl"),
    # insert: a value that is held, in each index; a null is equal to nothing; a text that differs after what an entry keeps of it
    ("insert into fua values (10, 2, 'n1', false, 9, 9, 9)", "write"),
    ("insert into fua values (10, 9, 'b', false, 9, 9, 9)", "write"),
    ("insert into fua values (10, 9, '%s-1', false, 9, 9, 9)" % LONG, "write"),
    ("insert into fua values (10, 9, '%s-3', false, 9, 9, 9)" % LONG, "write"),
    ("insert into fua values (11, null, null, null, 9, null, null)", "write"),
    ("insert into fua values (12, null, null, null, 9, null, null)", "write"),
    ("insert into fua values (13, 13, 'n13', false, 1, 2, 9)", "write"),
    ("insert into fua values (13, 13, 'n13', false, null, 2, 9)", "write"),
    # a partial one holds only the rows its condition is true for
    ("insert into fua values (14, 14, 'n14', false, 14, 14, 1)", "write"),
    ("insert into fua values (15, 15, 'n15', true, 15, 15, 1)", "write"),
    ("insert into fua values (15, 15, 'n15', null, 15, 15, 1)", "write"),
    # two rows of one statement
    ("insert into fua values (16, 16, 'n16', false, 16, 16, 16), (17, 16, 'n17', false, 17, 17, 17)", "write"),
    ("insert into fua values (16, 16, 'n16', false, 16, 16, 16), (17, 17, 'n16', false, 17, 17, 17)", "write"),
    ("insert into fua values (16, 16, 'n16', false, 16, 16, 16), (17, 17, 'n17', false, 17, 17, 17)", "write"),
    # ON CONFLICT DO NOTHING leaves the row out, whichever index it is
    ("insert into fua values (18, 16, 'n18', false, 18, 18, 18) on conflict do nothing", "write"),
    ("insert into fua values (18, 18, 'n18', false, 18, 18, 18), (19, 18, 'n19', false, 19, 19, 19), (20, 20, 'n18', false, 20, 20, 20), (21, 21, 'n21', false, 21, 21, 21) on conflict do nothing returning k", "write"),
    ("select * from fua order by k", "order"),
    # a read by a unique index
    ("select k from fua where u = 16", "set"),
    ("select k from fua where s = '%s-3'" % LONG, "set"),
    # update: a value a row that stays holds; one two rows take; one a row keeps; and what conflicts with nothing
    ("update fua set u = 2 where k = 1", "write"),
    ("update fua set u = 5 where k = 1", "write"),
    # (texts that begin alike: their entries are the same bytes, and they are not the same value)
    ("update fua set s = '%s-2' where k = 4" % LONG, "write"),
    ("update fua set s = '%s-1' where k = 10" % LONG, "write"),
    ("update fua set s = '%s-5' where k = 10" % LONG, "write"),
    ("update fua set s = '%s-3' where k = 10" % LONG, "write"),
    ("update fua set u = 5 where k < 3", "write"),
    ("update fua set u = 100 where k < 3", "write"),
    ("update fua set u = 2 where k < 3", "write"),
    ("update fua set u = 100 where k = 1", "write"),
    ("update fua set u = 101 where k = 1 or k = 3", "write"),
    ("update fua set u = u + 1000", "write"),
    ("update fua set u = u - 1000, s = s || '!' where u > 1001", "write"),
    ("update fua set s = 'c' where k = 1", "write"),
    ("update fua set s = '%s-2' where k = 4" % LONG, "write"),
    ("update fua set s = '%s-4' where k = 4" % LONG, "write"),
    ("update fua set a = 1, b = 2 where k = 3", "write"),
    ("update fua set a = 2, b = 2 where k = 3", "write"),
    ("update fua set b = null where a = 1", "write"),
    ("update fua set f = true where k = 5", "write"),
    ("update fua set f = true where k = 3", "write"),
    ("update fua set c = 1 where k = 14", "write"),
    ("update fua set u = null", "write"),
    ("update fua set u = k", "write"),
    ("update fua set u = 1 where k = 1", "write"),
    ("select * from fua order by k", "order"),
    # a row that takes another key keeps its values in the unique indexes: it is moved, and its entries with it
    ("update fua set k = k + 200 where k = 1", "write"),
    ("select k from fua where u = 1", "set"),
    ("insert into fua values (1, 1, 'again', false, 77, 77, 77)", "write"),
    ("update fua set k = k - 200, c = c where k > 200", "write"),
    ("update fua set k = k + 1000", "write"),
    ("update fua set k = k - 1000, s = s where k > 1000", "write"),
    ("update fua set k = 2 where k = 1", "write"),
    ("select * from fua order by k", "order"),
    # a delete frees the value; a rollback frees what the transaction took
    ("delete from fua where k = 2", "write"),
    ("insert into fua values (30, 2, 'n30', false, 30, 30, 30)", "write"),
    ("begin", "ddl"),
    ("insert into fua values (31, 31, 'n31', false, 31, 31, 31)", "write"),
    ("insert into fua values (32, 31, 'n32', false, 32, 32, 32)", "write"),
    ("rollback", "ddl"),
    ("insert into fua values (32, 31, 'n31', false, 32, 32, 32)", "write"),
    ("begin", "ddl"),
    ("delete from fua where k = 32", "write"),
    ("insert into fua values (33, 31, 'n31', false, 33, 33, 33)", "write"),
    ("commit", "ddl"),
    # the index dropped, the value may be taken twice; and then no unique index can be made
    ("drop index fuau", "ddl"),
    ("insert into fua values (34, 31, 'n34', false, 34, 34, 34)", "write"),
    ("create unique index fuau on fua (u)", "ddl"),
    ("truncate fua", "ddl"),
    ("insert into fua values (1, 1, 'a', true, 1, 1, 1)", "write"),
    ("insert into fua values (2, 1, 'b', true, 1, 2, 2)", "write"),
    ("insert into fua values (2, 2, 'a', true, 1, 2, 2)", "write"),
    ("select * from fua order by k", "order"),
    # `unique` on a column of CREATE TABLE: an index of the constraint's name, made with the table
    ("create table fub (k integer primary key, u integer unique, s text not null unique, n integer unique default 7)", "ddl"),
    ("insert into fub values (1, 1, 'a', 1), (2, null, 'b', null)", "write"),
    ("insert into fub values (3, 1, 'c', 3)", "write"),
    ("insert into fub values (3, 3, 'a', 3)", "write"),
    ("insert into fub values (3, 3, 'c', 1)", "write"),
    ("insert into fub (k, s) values (3, 'c')", "write"),
    ("insert into fub (k, s) values (4, 'd')", "write"),
    ("insert into fub values (5, null, 'e', null), (6, 6, 'e', 6) on conflict do nothing", "write"),
    ("update fub set u = 1 where k = 2", "write"),
    ("update fub set u = 2 where k = 2", "write"),
    ("select k from fub where u = 2", "set"),
    ("select * from fub order by k", "order"),
    # the constraint's name is taken, as an index's is; and free again when the table is dropped
    ("create index fub_u_key on fub (n)", "ddl"),
    ("create table fub_s_key (k integer primary key)", "ddl"),
    ("create sequence fub_n_key", "ddl"),
    ("drop table fub", "ddl"),
    ("create index fub_u_key on fua (n)", "ddl"),
    ("create table fub (k integer primary key unique, u bigint unique)", "ddl"),
    ("insert into fub values (1, 1), (2, 1)", "write"),
    ("insert into fub values (1, 1), (2, 2)", "write"),
    ("alter table fub rename to fubr", "ddl"),
    ("insert into fubr values (3, 2)", "write"),
    ("select * from fubr order by k", "order"),
    # UNIQUE (column, ...) as a constraint of the table: of two columns, of one, beside a column's own
    ("create table fuh (k integer primary key, a integer, b text, c integer unique, unique (a, b), unique (b))", "ddl"),
    ("insert into fuh values (1, 1, 'x', 1), (2, 1, 'y', 2), (3, null, 'z', 3)", "write"),
    ("insert into fuh values (4, 1, 'w', 1)", "write"),
    ("insert into fuh values (4, 1, 'y', 4)", "write"),
    ("insert into fuh values (4, 2, 'x', 4)", "write"),
    ("insert into fuh values (4, null, 'z', 4)", "write"),
    ("insert into fuh values (4, null, null, 4), (5, null, null, 5)", "write"),
    ("update fuh set a = 1, b = 'x' where k = 2", "write"),
    ("update fuh set a = 2 where k = 2", "write"),
    ("create index fuh_a_b_key on fuh (a)", "ddl"),
    ("create index fuh_b_key on fuh (a)", "ddl"),
    ("select * from fuh order by k", "order"),
    # a column of the list that the table has not; the lists after the key, and one over the key's column
    ("create table fui (a integer, b integer, unique (a, nope), primary key (b))", "ddl"),
    ("create table fui (a integer, b integer, primary key (b), unique (a), unique (b, a))", "ddl"),
    ("insert into fui values (1, 1), (1, 2)", "write"),
    ("insert into fui values (1, 1), (2, 2)", "write"),
    ("select * from fui order by b", "order"),
]


# Times (docs/m3-engine.md 6bp, slice 1): every statement is answered, and as PostgreSQL answers it in a session whose zone is UTC.
TIMEFIXED = [
    ("create table ft1 (k integer primary key, at timestamptz not null, d timestamp, n text, e timestamptz default '2020-01-01 00:00:00+00')", "ddl"),
    ("insert into ft1 values (1, '2026-11-27 10:00:00+02', '2026-11-27 10:00:00.5', 'a'), (2, '2025-01-01T00:00:00Z', null, 'b'), (3, '2026-11-27 08:00:00', '1999-12-31 23:59:59', 'c')", "write"),
    ("insert into ft1 (k, at, d) values (4, '2026-11-27 10:00:00.123456-03:30', '2026-11-27 10:00:00+05'), (5, ' 2000-02-29 12:30 ', '0001-01-01'), (6, '9999-12-31 23:59:59.999999', '9999-12-31T23:59:59')", "write"),
    ("insert into ft1 (k, at, d, e) values (7, '2026-01-01 00:00:00 +00', '2026-01-01 00:00:00.100000', null), (8, '2026-01-01 00:00:00-0030', '2026-01-01', '2026-01-01 00:00:00z')", "write"),
    ("select * from ft1 order by k", "order"),
    # a text of the form with a field no date has is an error; a null where none is taken; a time where a text is wanted and the other way
    ("insert into ft1 (k, at) values (9, '2026-13-01')", "write"),
    ("insert into ft1 (k, at) values (9, '2026-02-30 10:00:00')", "write"),
    ("insert into ft1 (k, at) values (9, '2025-02-29')", "write"),
    ("insert into ft1 (k, at) values (9, '2026-01-01 25:00:00')", "write"),
    ("insert into ft1 (k, at) values (9, '2026-01-01 10:61:00')", "write"),
    ("insert into ft1 (k, at) values (9, '2026-00-01')", "write"),
    ("insert into ft1 (k, at) values (9, null)", "write"),
    ("insert into ft1 (k, at) values (9, 5)", "write"),
    ("insert into ft1 (k, at) values (9, true)", "write"),
    ("insert into ft1 (k, at, n) values (9, '2024-02-29', '2024-02-29')", "write"),
    ("update ft1 set n = at where k = 9", "write"),
    ("update ft1 set at = n where k = 9", "write"),
    ("update ft1 set d = at, e = d where k = 1", "write"),
    ("select k, d, e from ft1 where k = 1", "order"),
    # compared: with a text, the text first, one type with the other, each operator
    ("select k from ft1 where at = '2026-11-27 08:00:00+00'", "set"),
    ("select k from ft1 where '2026-11-27 10:00:00+02' = at", "set"),
    ("select k from ft1 where at <> '2026-11-27 08:00:00'", "set"),
    ("select k from ft1 where at > '2026-01-01' and at <= '2026-11-27 08:00:00'", "set"),
    ("select k from ft1 where d < '2000-01-01'", "set"),
    ("select k from ft1 where d >= '2026-11-27 10:00:00.5'", "set"),
    ("select k from ft1 where at between '2025-01-01' and '2026-06-01'", "set"),
    ("select k from ft1 where at in ('2025-01-01', '2000-02-29 12:30:00+00', '1990-01-01')", "set"),
    ("select k from ft1 where d is null", "set"),
    ("select k from ft1 where at = d", "set"),
    ("select k from ft1 where d < at", "set"),
    ("select k from ft1 where e is not null and e < at", "set"),
    ("select k from ft1 where at = 5", "set"),
    ("select k from ft1 where at = n", "set"),
    ("select k from ft1 where at = true", "set"),
    (P("select k from ft1 where at = $1", "2025-01-01 00:00:00+00"), "set"),
    (P("select k from ft1 where d > $1 and at < $2", "2000-01-01", "2026-06-01T00:00:00Z"), "set"),
    (P("insert into ft1 (k, at, d) values ($1, $2, $3)", "10", "2026-05-05 05:05:05+05", "2026-05-05 05:05:05"), "write"),
    # ordered, grouped, the least and the greatest
    ("select k, at from ft1 order by at, k", "order"),
    ("select k, d from ft1 order by d desc, k", "order"),
    ("select min(at), max(at), min(d), max(d), count(d), count(*) from ft1", "set"),
    ("select at, count(*) from ft1 group by at", "set"),
    ("select distinct d from ft1", "set"),
    ("select sum(at) from ft1", "set"),
    # cast: between the two, from a text, to a text
    ("select k, cast(at as text), cast(d as text), cast(at as timestamp), cast(d as timestamptz) from ft1 order by k", "order"),
    ("select cast('2026-01-02 03:04:05.6' as timestamp), cast('2026-01-02 03:04:05+01' as timestamptz), cast('2026-01-02 03:04:05+01' as timestamp) from ft1 where k = 1", "set"),
    ("select k, cast(n as timestamp) from ft1 where k = 9", "set"),
    ("select k from ft1 where cast(at as text) = '2025-01-01 00:00:00+00'", "set"),
    ("select cast(at as integer) from ft1", "set"),
    ("select cast(k as timestamp) from ft1", "set"),
    # a choice among times
    ("select k, coalesce(d, '2000-01-01') from ft1 order by k", "order"),
    ("select k, case when d is null then '1970-01-01' else d end from ft1 order by k", "order"),
    ("select k, greatest(at, e), least(at, e) from ft1 order by k", "order"),
    ("select k, coalesce(d, n) from ft1", "set"),
    # a time is a key, alone and with another column
    ("create table ft2 (t timestamp primary key, v integer)", "ddl"),
    ("insert into ft2 values ('2026-01-01 00:00:00', 1), ('2025-06-01', 2), ('1999-01-01 12:00:00', 3)", "write"),
    ("insert into ft2 values ('2025-06-01 00:00:00.000', 4)", "write"),
    ("insert into ft2 values (null, 4)", "write"),
    ("select * from ft2 where t = '2025-06-01'", "set"),
    ("select * from ft2 where t > '2000-01-01' and t < '2026-01-01'", "set"),
    ("select * from ft2 order by t", "order"),
    ("update ft2 set v = v + 1 where t = '1999-01-01 12:00:00'", "write"),
    ("update ft2 set t = '2030-01-01' where v = 1", "write"),
    ("delete from ft2 where t < '2000-01-01'", "write"),
    ("select * from ft2 order by t desc", "order"),
    ("create table ft3 (m timestamptz, k integer, v text, primary key (m, k))", "ddl"),
    ("insert into ft3 values ('2026-01-01 00:00:00+00', 1, 'a'), ('2026-01-01 01:00:00+01', 2, 'b'), ('2025-12-31 23:00:00-01', 3, 'c'), ('2026-01-02', 1, 'd')", "write"),
    ("insert into ft3 values ('2026-01-01 02:00:00+02', 1, 'dup')", "write"),
    ("select * from ft3 order by m, k", "order"),
    # an index on a time, a unique one, and what is read by them
    ("create index ft1at on ft1 (at)", "ddl"),
    ("create unique index ft1d on ft1 (d)", "ddl"),
    ("select k from ft1 where at = '2025-01-01 00:00:00+00'", "set"),
    ("select k from ft1 where at >= '2025-01-01' and at < '2025-01-02'", "set"),
    ("select k, at from ft1 order by at limit 2", "order"),
    ("select k, at from ft1 order by at desc limit 2", "order"),
    ("insert into ft1 (k, at, d) values (11, '2026-01-01', '1999-12-31 23:59:59')", "write"),
    ("insert into ft1 (k, at, d) values (11, '2026-01-01', '1999-12-31 23:59:59.000001')", "write"),
    ("delete from ft1 where at < '2001-01-01'", "write"),
    ("select * from ft1 order by k", "order"),
]


def order_dependent(pg):
    notes = []
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
        if ans[:1] != ["refused engine-order-dependent"]:
            raise SystemExit("engine_check: %s: the engine says %s, and the answer depends on PostgreSQL's order" % (sql, ans))
        if err != want:
            # what PostgreSQL 16 does is written down beside each statement; another version may plan otherwise, which is the point of refusing
            if PGMAJOR[0] == 16:
                raise SystemExit("engine_check: %s: PostgreSQL says %s, expected %s" % (sql, err, want))
            notes.append("%s: %s, where PostgreSQL 16 says %s" % (sql, err, want))
    with tempfile.TemporaryDirectory() as d:
        eng = run_engine(os.path.join(d, "unsup.db"), DEP_SETUP + lines(x[0] for x in UNSUP))
    for (sql, want), ans in zip(UNSUP, eng[len(DEP_SETUP):]):
        pg.query("begin")
        err, _, _, _ = pg.query(sql)
        pg.query("rollback")
        if ans[:1] not in (["refused engine-unsupported"], ["refused subquery"], ["refused insert-select"], ["refused nondeterministic"], ["refused unsupported-statement"], ["refused syntax"]):
            raise SystemExit("engine_check: %s: the engine says %s, and this is one it does not answer" % (sql, ans))
        if err != want:
            if PGMAJOR[0] == 16:
                raise SystemExit("engine_check: %s: PostgreSQL says %s, expected %s" % (sql, err, want))
            notes.append("%s: %s, where PostgreSQL 16 says %s" % (sql, err, want))
    pg.query("drop table fz")
    pg.query("drop table fw")
    pg.query("drop table fi")
    pg.query("drop table ft")
    pg.query("drop sequence fzs")
    return notes


def history(seed):
    """AS OF (docs/m3-engine.md 6n): what the tables held at a point of a random history of writes is what `!asof` reads there later: from another process after a commit, after a sweep and more writes,
    and on a fork that has gone its own way; and the branch that was forked from is as it was."""
    rng = random.Random(seed * 7919 + 5)
    g = Gen(rng)
    names = ["ta", "tb", "tc"]
    added = [0]
    dumps = ["select * from %s order by k" % n for n in names]
    tables = {}
    lines = []
    for name in names[:2]:
        tables[name] = g.table(name)
        lines.append(tables[name].ddl())

    def writes(n):
        out = []
        while len(out) < n:
            g.t = tables[rng.choice(sorted(tables))]
            r = rng.random()
            if r < 0.03:
                name = rng.choice(names)
                if name in tables:
                    out.append("drop table %s" % name)
                tables[name] = g.table(name)
                out.append(tables[name].ddl())
            elif r < 0.07:
                sql = ddl_more(g, added)
                if sql.startswith("alter"):
                    out.append(sql)
            elif r < 0.13:
                # a transaction of several writes: a key written twice in it has ONE record, of what it held before (6n); a rollback leaves none
                g2 = [g.insert(), g.update(), g.update(), g.delete(), g.update()][:rng.randrange(2, 6)]
                out += ["begin"] + g2 + [rng.choice(["commit", "commit", "rollback"])]
            elif r < 0.55:
                out.append(g.insert())
            elif r < 0.85:
                out.append(g.update())
            else:
                out.append(g.delete())
        return out

    def checkpoint():
        return ["!txn", "!mark"] + dumps + ["!mark"]

    def read(out):
        """the `txn` numbers and the blocks between pairs of marks"""
        txns = [int(l.split()[1]) for l in out.split("\n") if l.startswith("txn ")]
        blocks, cur, inside = [], [], False
        for l in out.split("\n"):
            if l == "mark":
                if inside:
                    blocks.append("\n".join(cur))
                cur, inside = [], not inside
            elif inside:
                cur.append(l)
        return txns, blocks

    def run(path, script):
        r = subprocess.run([EXE, path], input="\n".join(script) + "\n", capture_output=True, text=True)
        if r.returncode != 0 or "\nerr " in r.stdout or "engine-damaged" in r.stdout or "engine-io" in r.stdout:
            raise SystemExit("engine_check: history: status %d: %s" % (r.returncode, r.stdout[-300:]))
        return read(r.stdout)

    def asof(points):
        script = []
        for t, _ in points:
            script += ["!asof %d" % t, "!mark"] + dumps + ["!mark"]
        return script + ["!asof -"]

    def check(what, points, blocks):
        if len(blocks) != len(points):
            raise SystemExit("engine_check: history, %s: %d answers for %d points" % (what, len(blocks), len(points)))
        for (t, want), got in zip(points, blocks):
            if got != want:
                raise SystemExit("engine_check: history, %s: AS OF transaction %d the tables are not what they were then\n     then: %s\n     now:  %s" % (what, t, want[:300], got[:300]))

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "history.db")
        script = list(lines)
        for _ in range(8):
            script += writes(25) + checkpoint()
        txns, blocks = run(path, script + ["!commit"])
        points = list(zip(txns, blocks))
        if len(points) != 8 or len(set(txns)) < 6:
            raise SystemExit("engine_check: history: the transactions did not advance: %s" % txns)
        # the same process cannot have been asked (the numbers were not known): another one, after the commit
        _, got = run(path, asof(points))
        check("after a commit, from another process", points, got)
        # a sweep, more writes, more points: the old points still read the same, and so do the new
        script = ["!sweep"]
        for _ in range(3):
            script += writes(25) + checkpoint()
        txns, blocks = run(path, script + ["!commit", "!sweep"])
        points += list(zip(txns, blocks))
        _, got = run(path, asof(points) + ["!mark"] + dumps + ["!mark"])
        check("after a sweep and more writes", points, got[:-1])
        tip = got[-1]
        if tip != points[-1][1]:
            raise SystemExit("engine_check: history: after `!asof -` the tables are not the tip's")
        # a fork goes its own way: its history up to the fork is the branch's, and the branch is untouched
        script = ["!fork 1", "!branch 1"] + writes(40) + checkpoint()
        txns, blocks = run(path, script + ["!commit"])
        forked = points + list(zip(txns, blocks))
        _, got = run(path, ["!branch 1"] + asof(forked) + ["!branch 0", "!mark"] + dumps + ["!mark"] + asof(points))
        check("on a fork", forked, got[:len(forked)])
        if got[len(forked)] != tip:
            raise SystemExit("engine_check: history: the branch changed when its fork was written to")
        check("on the branch, after its fork was written to", points, got[len(forked) + 1:])
        # nothing may be written while the past is being read
        r = subprocess.run([EXE, path], input="!asof %d\ninsert into ta (k) values (1)\n" % points[0][0], capture_output=True, text=True)
        if "refused engine-as-of-write" not in r.stdout:
            raise SystemExit("engine_check: history: a write AS OF a past transaction: %s" % r.stdout[-200:])
        r = subprocess.run([EXE, path], input="!asof %d\nalter table ta rename to tren\n" % points[0][0], capture_output=True, text=True)
        if "refused engine-unsupported" not in r.stdout or "ok " in r.stdout:
            raise SystemExit("engine_check: history: a table renamed AS OF a past transaction: %s" % r.stdout[-200:])
        r = subprocess.run([EXE, path], input="!asof %d\ntruncate ta\n" % points[0][0], capture_output=True, text=True)
        if "refused engine-unsupported" not in r.stdout or "ok " in r.stdout:
            raise SystemExit("engine_check: history: a truncate AS OF a past transaction: %s" % r.stdout[-200:])
        r = subprocess.run([EXE, path], input="!asof %d\ncreate sequence hsq\n!asof -\nselect nextval('hsq')\n" % points[0][0], capture_output=True, text=True)
        if "refused engine-unsupported" not in r.stdout or "ok " in r.stdout:
            raise SystemExit("engine_check: history: a sequence made AS OF a past transaction: %s" % r.stdout[-200:])
        return len(points), len(forked)


def past_by_value():
    """A read of the past reads no index (docs/m3-engine.md 6bo): an index has no history, and the entries in the tree a past read is given are the present's."""
    with tempfile.TemporaryDirectory() as d:
        script = ["create table pv (k integer primary key, a integer, b text)", "create index pva on pv (a)", "create index pvb on pv (b)",
                  "insert into pv values (1, 5, 'x'), (2, 5, 'y'), (4, 7, 'x')", "!commit", "!txn",
                  "update pv set a = 6, b = 'z' where k = 1", "delete from pv where k = 2", "insert into pv values (3, 5, 'x')", "update pv set a = 5 where k = 4", "!commit"]
        r = subprocess.run([EXE, os.path.join(d, "pv.db")], input="\n".join(script) + "\n", capture_output=True, text=True)
        t = [int(l.split()[1]) for l in r.stdout.split("\n") if l.startswith("txn ")]
        if r.returncode != 0 or len(t) != 1:
            raise SystemExit("engine_check: the past by value: %s" % r.stdout[-300:])
        asks = ["select k from pv where a = 5", "select k from pv where b = 'x'", "select count(*) from pv where a = 6", "select k from pv order by a desc limit 1"]
        script = ["!asof %d" % t[0], "!mark"] + asks + ["!mark", "!via", "!asof -", "!mark"] + asks + ["!mark", "!via"]
        r = subprocess.run([EXE, os.path.join(d, "pv.db")], input="\n".join(script) + "\n", capture_output=True, text=True)
        blocks, cur, inside, via = [], [], False, []
        for l in r.stdout.split("\n"):
            if l == "mark":
                if inside:
                    blocks.append(cur)
                cur, inside = [], not inside
            elif inside and l.startswith("R "):
                cur.append(l[2:])
            elif l.startswith("via "):
                via.append(int(l[4:]))
        want = [["31", "32", "31", "34", "30", "34"], ["33", "34", "33", "34", "31", "31"]]
        if r.returncode != 0 or blocks != want or via != [0, 4]:
            raise SystemExit("engine_check: the past by value: the answers then and now %r (should be %r), read by an index %r (should be [0, 4])" % (blocks, want, via))


def first_rows():
    """ORDER BY an indexed column with a LIMIT reads as many rows as it gives (docs/m3-engine.md 6bo, slice 4): that is the point of it, and no answer shows it."""
    with tempfile.TemporaryDirectory() as d:
        script = ["create table fr1 (k integer primary key, a integer)", "create index fr1a on fr1 (a)",
                  "insert into fr1 values " + ", ".join("(%d, %s)" % (i, "null" if i % 10 == 0 else str(1000 - i)) for i in range(300)), "!commit"]
        asks = [("select k from fr1 order by a limit 3", 3), ("select k from fr1 order by a desc limit 2 offset 1", 3), ("select k from fr1 order by a limit 5 offset 268", 273),
                ("select k from fr1 order by a desc limit 40", 40), ("select k from fr1 order by a limit 0", 0), ("select k from fr1 where a = 999", 1)]
        for sql, _ in asks:
            script += [sql, "!viarows"]
        r = subprocess.run([EXE, os.path.join(d, "fr1.db")], input="\n".join(script) + "\n", capture_output=True, text=True)
        seen = [int(l[8:]) for l in r.stdout.split("\n") if l.startswith("viarows ")]
        got = [b - a for a, b in zip([0] + seen, seen)]
        if r.returncode != 0 or got != [n for _, n in asks]:
            raise SystemExit("engine_check: rows read by an index for %r: %r" % (asks, got))


def clocked(pg):
    """now() (docs/m3-engine.md 6bp, slice 2): with the test program's clock set, what the clock says; and what no clock changes, held to PostgreSQL."""
    def run(script):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([EXE, os.path.join(d, "clock.db")], input="\n".join(script) + "\n", capture_output=True, text=True)
        blocks, cur = [], None
        for l in r.stdout.split("\n"):
            if l.startswith(("ok ", "refused ", "error ")):
                cur = [l]
                blocks.append(cur)
            elif cur is not None and l.startswith(("R ", "T ")):
                cur.append(l[0] + " " + " ".join("-" if x == "-" else "" if x == "." else bytes.fromhex(x).decode() if l[0] == "R" else x for x in l.split()[1:]))
        return r.returncode, blocks
    make = "create table fn1 (k integer primary key, at timestamptz not null default now(), d timestamp default now(), n text)"
    t1, t2 = 849088800123000, 849088801999000        # 2026-11-27 10:00:00.123 and 10:00:01.999
    s1, s2 = "2026-11-27 10:00:00.123", "2026-11-27 10:00:01.999"
    script = [make, "insert into fn1 (k) values (0)", "select now() from fn1", "!clock %d" % t1,
              "insert into fn1 (k, n) values (1, 'a')", "insert into fn1 values (2, '2020-01-01', null, 'b')", "select k, at, d from fn1 order by k",
              "select now(), cast(now() as text), cast(now() as timestamp) from fn1 where k = 1", "select k from fn1 where at = now()", "select k from fn1 where at < now() and d is null",
              "begin", "insert into fn1 (k) values (3)", "select count(*) from fn1 where at = now() and d = now()", "commit",
              "!clock %d" % t2, "insert into fn1 (k, d) values (4, '2000-01-01')", "select k, at, d from fn1 order by at desc, k limit 2", "select k from fn1 where at = now()",
              "update fn1 set d = now() where k = 2", "select k, d from fn1 where k = 2", "delete from fn1 where at < now()", "select k from fn1 order by k",
              "create table fn2 (k integer primary key, n integer default now())", "create table fn2 (k integer primary key, n text default now())",
              "alter table fn1 add column x timestamptz default now()", "create table fn3 (k integer primary key, d timestamp default random())", "!indexes"]
    rc, got = run(script)
    want = [["ok CREATE 0"], ["refused engine-unsupported"], ["refused engine-unsupported"],
            ["ok INSERT 1"], ["ok INSERT 1"], ["ok SELECT 2", "T 23 1184 1114", "R 1 %s+00 %s" % (s1, s1), "R 2 2020-01-01 00:00:00+00 -"],
            ["ok SELECT 1", "T 1184 25 1114", "R %s+00 %s+00 %s" % (s1, s1, s1)], ["ok SELECT 1", "T 23", "R 1"], ["ok SELECT 1", "T 23", "R 2"],
            ["ok BEGIN 0"], ["ok INSERT 1"], ["ok SELECT 1", "T 20", "R 2"], ["ok COMMIT 0"],
            ["ok INSERT 1"], ["ok SELECT 2", "T 23 1184 1114", "R 4 %s+00 2000-01-01 00:00:00" % s2, "R 1 %s+00 %s" % (s1, s1)], ["ok SELECT 1", "T 23", "R 4"],
            ["ok UPDATE 1"], ["ok SELECT 1", "T 23 1114", "R 2 %s" % s2], ["ok DELETE 3"], ["ok SELECT 1", "T 23", "R 4"],
            ["refused engine-unsupported"], ["refused engine-unsupported"], ["refused engine-unsupported"], ["refused unknown-construct"]]
    if rc != 0 or got != want:
        diff = [(i, g, w2) for i, (g, w2) in enumerate(zip(got, want)) if g != w2][:2]
        raise SystemExit("engine_check: now() with the clock set: %r (%d answers for %d)" % (diff, len(got), len(want)))
    # what no clock changes: the same on PostgreSQL, whose clock is its own
    same = [make, "begin", "insert into fn1 (k, n) values (1, 'a')", "insert into fn1 (k) values (2)", "select count(*) from fn1 where at = now() and d = now()",
            "select now() = now(), now() > '2020-01-01', now() < '9000-01-01', now() is null, cast(now() as text) = cast(at as text) from fn1 where k = 1",
            "select k from fn1 where at <= now() order by k", "update fn1 set d = null where at = now()", "select count(*) from fn1 where d is null", "commit",
            "select count(*), min(at) = max(at), min(at) <= now() from fn1", "select k from fn1 where at > now()", "drop table fn1"]
    rc, got = run(["!clock %d" % t1] + same)
    for sql, ans in zip(same, got):
        err, oids, rows, tag = pg.query(sql)
        mine = [l[2:].split(" ") for l in ans if l.startswith("R ")]
        types = [[int(x) for x in l[2:].split()] for l in ans if l.startswith("T ")]
        theirs = [["-" if v is None else v.decode() for v in r] for r in rows]
        if err is not None or not ans[0].startswith("ok ") or mine != theirs or (types and types[0] != oids):
            raise SystemExit("engine_check: now(), %s: the engine says %r, PostgreSQL %r %r %r" % (sql, ans, err, oids, theirs))


def erasure():
    """A DELETE keeps the row in the history (it is read AS OF before it); an erase of its key removes the row and its past, and two commits and a sweep later no byte of the page file holds it
    (docs/m3-engine.md 6c, 6n, D-M3-2). What was not erased is still there."""
    one, two, three = "MARKER-ROW-ONE-xyzzy", "MARKER-ROW-TWO-plugh", "MARKER-ROW-THREE-frotz"
    settle = ["!commit", "!sweep", "!commit", "!sweep"]

    def heads(out):
        return [b[0] if b else "" for b in out]

    def texts(block):
        return [bytes.fromhex(l.split()[1]).decode() for l in block if l.startswith("R ")]

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "erase.db")
        salts = {}   # key -> every salt the engine gave it: its key's and each of its versions' (docs/m3-engine.md 6ag)

        def note(out):
            for b in out:
                for line in b:
                    if line.startswith("C "):
                        f = line.split()
                        salts.setdefault(bytes.fromhex(f[2]), set()).update(bytes.fromhex(x) for x in f[5:8] if x != "-")

        note(run_engine(path, ["create table er (k integer primary key, s text)", "insert into er values (1, '%s'), (2, '%s'), (3, '%s')" % (one, two, three), "!commit"]))
        data = open(path, "rb").read()
        if one.encode() not in data or two.encode() not in data or three.encode() not in data:
            raise SystemExit("engine_check: the rows are not in the page file after a commit")
        # an update and a delete: what the rows were stays in the history, in the file and to AS OF
        newer = "THIRD-NEW-rezrov"
        note(run_engine(path, ["update er set s = 'CHANGED-VALUE-nitfol' where k = 1", "delete from er where k = 2", "update er set s = '%s' where k = 3" % newer] + settle))
        data = open(path, "rb").read()
        if sorted(len(v) for v in salts.values()) != [2, 3, 3] or any(x not in data for v in salts.values() for x in v):
            raise SystemExit("engine_check: the salts of the rows and of their past are not all in the page file (%s)" % sorted(len(v) for v in salts.values()))
        if one.encode() not in data or two.encode() not in data:
            raise SystemExit("engine_check: the history of an updated and of a deleted row is not in the page file")
        out = run_engine(path, ["!asof 2", "select s from er order by k", "!asof -", "select s from er order by k"])
        if texts(out[0]) != [one, two, three] or texts(out[1]) != ["CHANGED-VALUE-nitfol", newer]:
            raise SystemExit("engine_check: before the erase, AS OF and now read %s and %s" % (texts(out[0]), texts(out[1])))
        # an erase of a key: of a row that is there (with a past) and of one that is gone (with a past)
        out = run_engine(path, ["!erase delete from er where k = 1", "!erase delete from er where k = 2", "!erase delete from er where k = 9",
                                "!erase delete from er where s = 'x'", "!erase delete from er", "!erase delete from er where k = 3 and s = 'y'"] + settle)
        if heads(out) != ["ok ERASE 3", "ok ERASE 2", "ok ERASE 0", "refused engine-unsupported", "refused engine-unsupported", "refused engine-unsupported"]:
            raise SystemExit("engine_check: the erases answered %s" % heads(out))
        data = open(path, "rb").read()
        for gone in (one, two, "CHANGED-VALUE-nitfol"):
            if gone.encode() in data:
                raise SystemExit("engine_check: %s is still in the page file after its key was erased, two commits and a sweep" % gone)
        if three.encode() not in data or newer.encode() not in data:
            raise SystemExit("engine_check: a row that was not erased, or its past, is gone from the page file")
        # and so are its salts: the key's and every version's; those of the row that was not erased are there
        for key, kept in ((b"[1]", False), (b"[2]", False), (b"[3]", True)):
            for x in salts[key]:
                if (x in data) != kept:
                    raise SystemExit("engine_check: a salt of the row %s is %s the page file after the erase" % (key.decode(), "not in" if kept else "still in"))
        # the row that was not erased still has its past: what it held before its update is read AS OF before it
        out = run_engine(path, ["!asof 2", "select s from er order by k", "!asof 4", "select s from er order by k", "!asof -", "select s from er order by k"])
        if [texts(b) for b in out] != [[three], [three], [newer]]:
            raise SystemExit("engine_check: after the erase, AS OF and now read %s" % [texts(b) for b in out])
        # a dropped table keeps its history like a deleted row: its rows are read AS OF before the drop, until their keys are erased
        run_engine(path, ["drop table er"] + settle)
        if three.encode() not in open(path, "rb").read():
            raise SystemExit("engine_check: the history of a dropped table is not in the page file")
        out = run_engine(path, ["!asof 5", "select s from er order by k", "!asof 2", "select s from er order by k"])
        if texts(out[0]) != [newer] or texts(out[1]) != [three]:
            raise SystemExit("engine_check: a dropped table AS OF before the drop reads %s" % out)
        # with no seed to make salts of, a statement that writes a row is refused and one that reads is not (6ag); a column added writes every row of its table (6ai)
        out = run_engine(path, ["create table ns (k integer primary key, v integer)", "insert into ns values (1, 1), (2, 2)", "!unseed", "insert into ns values (3, 3)", "update ns set v = 9 where k = 1",
                                "update ns set k = 7 where k = 2", "update ns set v = 1 where k = 1", "delete from ns where k = 2", "select count(*) from ns", "alter table ns add column z integer default 0"])
        if heads(out) != ["ok CREATE 0", "ok INSERT 2", "refused engine-no-entropy", "refused engine-no-entropy", "refused engine-no-entropy", "ok UPDATE 1", "ok DELETE 1", "ok SELECT 1", "refused engine-no-entropy"]:
            raise SystemExit("engine_check: with no seed the statements answered %s" % heads(out))
        # where a statement is refused is said by its tag: where it is read (the lexer's, the parser's), where it is lowered, or by the engine; and a parameter in a statement that
        # is no query is refused where the statement is lowered or made (docs/m3-engine.md 6ak)
        out = run_engine(os.path.join(d, "tags.db"), ["create table q (k integer primary key, v integer)", "select 'abc", "select from where", "select nosuch from q", "select k from q where k in (select k from q)",
                                                      "!params 35", "create table zz (k integer primary key, v integer default $1)", "!params 35", "alter table q add column c integer default $1",
                                                      "!params 35", "create index qi on q (v) where k = $1", "!params 35", "create sequence sq start $1", "select count(*) from q"])
        want = ["ok CREATE 0", "refused unterminated", "refused reserved-word", "refused unknown-column", "refused subquery", "refused unknown-construct", "refused unknown-construct", "refused engine-unsupported", "refused syntax", "ok SELECT 1"]
        if [h for h in heads(out) if h and not h.startswith("params")] != want:
            raise SystemExit("engine_check: the tags of refusals are %s" % heads(out))
        # text that is not UTF-8 is refused (PostgreSQL would not take it either), and the engine goes on
        r = subprocess.run([EXE, path], input=b"create table u8 (k integer primary key, s text)\ninsert into u8 values (1, '\xff\xfe')\ninsert into u8 values (2, 'a\xc3')\ninsert into u8 values (3, '\xc3\xb1')\nselect k from u8\n", capture_output=True)
        heads = [b.split(b"\n")[0] for b in r.stdout.split(b"\n.\n")]
        if r.returncode != 0 or not heads[1].startswith(b"refused") or not heads[2].startswith(b"refused") or heads[3] != b"ok INSERT 1" or heads[4] != b"ok SELECT 1":
            raise SystemExit("engine_check: text that is not UTF-8: %s" % heads)


def generate(rng, n, params=True):
    """A random history of `n` statements, as (sql, how it is compared, the table it is about); `params`: some go with parameters, by the extended protocol."""
    g = Gen(rng)
    tables = {}
    stmts = []   # (sql, how, table name)
    for name in ["ta", "tb", "tc"][:rng.randrange(2, 4)]:
        tables[name] = g.table(name)
        stmts.append((tables[name].ddl(), "ddl", name))
    spare = 0
    added = [0]
    open_txn = False
    while len(stmts) < n:
        # a transaction now and then: a few statements, then a commit or a rollback (and, rarely, one of those out of place)
        rt = rng.random()
        if not open_txn and rt < 0.03:
            stmts.append(("begin", "ddl", "ta"))
            open_txn = True
        elif open_txn and rt < 0.22:
            stmts.append((rng.choice(["commit", "commit", "rollback"]), "ddl", "ta"))
            open_txn = False
        elif rt > 0.997:
            stmts.append((rng.choice(["commit", "rollback", "begin"]), "ddl", "ta"))
            open_txn = stmts[-1][0] == "begin"
        g.t = tables[rng.choice(sorted(tables))]
        r = rng.random()
        if open_txn and r < 0.065:
            # the generator's idea of the tables is not taken back by a rollback: no DDL inside a transaction here (the fixed statements have some)
            r = 0.5
        if r < 0.012:
            stmts.append((g.t.ddl(rng.random() < 0.5), "ddl", g.t.name))
        elif r < 0.02:
            # a table is dropped and another definition made under its name
            name = g.t.name
            stmts.append(("drop table %s" % name, "ddl", name))
            tables[name] = g.table(name)
            stmts.append((tables[name].ddl(), "ddl", name))
        elif r < 0.055:
            stmts.append((ddl_more(g, added), "ddl", g.t.name))
        elif r < 0.065:
            spare += 1
            bad = g.table("tz%d" % spare)
            if bad.key2 is not None:
                bad.spoil = rng.choice(["", "two", "twice", "nope"])
            stmts.append((bad.ddl(rng.random() < 0.3) + rng.choice(["", "", " "]), "ddl", bad.name))
            stmts.append(("drop table %s" % bad.name, "ddl", bad.name))
        elif r < 0.35:
            stmts.append((g.insert(), "write", g.t.name))
        elif r < 0.52:
            stmts.append((g.update(), "write", g.t.name))
        elif r < 0.6:
            stmts.append((g.delete(), "write", g.t.name))
        elif r < 0.64:
            stmts.append(("select * from %s order by %s" % (g.t.name, ", ".join(g.t.key_cols())), "order", g.t.name))
        elif r < 0.74:
            sql, how = gselect(g)
            stmts.append((sql, how, g.t.name))
        elif r < 0.82:
            stmts.append(jselect(g, tables))
        else:
            sql, how = g.select()
            stmts.append((sql, how, g.t.name))
        if params and stmts[-1][1] != "ddl" and rng.random() < 0.3:
            stmts[-1] = (parametrise(rng, stmts[-1][0]),) + stmts[-1][1:]
    if open_txn:
        stmts.append(("commit", "ddl", "ta"))
    return stmts


def main():
    admin("drop database if exists %s" % DB)
    r = admin("create database %s encoding 'UTF8' lc_collate 'C' lc_ctype 'C' template template0" % DB)
    if r.returncode != 0:
        raise SystemExit("engine_check: " + r.stderr)
    # (times are written and read in the session's zone: the engine's is UTC, and so is PostgreSQL's here, 6bp)
    admin("alter database %s set timezone to 'UTC'" % DB)
    pg = Pg(DB)
    version = pg.query("show server_version")[2][0][0].decode().split()[0]
    PGMAJOR[0] = int(version.split(".")[0])
    stmts = generate(random.Random(SEED), N)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "engine.db")
        # the two processes part where no transaction is open
        half = len(stmts) // 2
        inside = False
        for j, st in enumerate(stmts):
            if j >= half and not inside:
                half = j
                break
            if st[0] == "begin":
                inside = True
            elif st[0] in ("commit", "rollback"):
                inside = False
        eng = run_engine(path, lines(s[0] for s in stmts[:half]) + ["!commit", "!sweep"])
        eng += run_engine(path, lines(s[0] for s in stmts[half:]) + ["!commit"])
    counts, fails, refused_answered, answered = compare(pg, stmts, eng, False)
    psent = [i for i, st in enumerate(stmts) if isinstance(st[0], P)]
    pok = sum(1 for i in psent if eng[i] and not eng[i][0].startswith("refused "))
    with tempfile.TemporaryDirectory() as d:
        feng = run_engine(os.path.join(d, "fixed.db"), lines(f[0] for f in FIXED))
    def ftable(sql, how):
        m = re.match(r"(?:insert into|update|delete from) (frn\d?|ffv|ftr|fid\d*|f[ksonmrcef]\d?|fq2)\b", sql)
        if m:
            return m.group(1)
        return "fwide" if " fwide" in sql and how == "write" else "fq" if " fq" in (sql + " ").replace(" fq ", " fq") and how == "write" else ("fy" if " fy" in sql else "fp" if " fp" in sql else "fx")
    fstmts = [(sql, how, ftable(sql, how)) for sql, how in FIXED]
    fcounts, ffails, _, _ = compare(pg, fstmts, feng, True)
    VIA[0] = 0
    with tempfile.TemporaryDirectory() as d:
        veng = run_engine(os.path.join(d, "via.db"), lines(v[0] for v in VIAFIXED))
    wanted = sum(1 for v in VIAFIXED if v[2])
    if VIA[0] != wanted:
        raise SystemExit("engine_check: %d statements read by an index, and %d should have" % (VIA[0], wanted))
    with tempfile.TemporaryDirectory() as d:
        teng = run_engine(os.path.join(d, "time.db"), lines(t[0] for t in TIMEFIXED))
    tcounts, tfails, _, _ = compare(pg, [(sql, how, "ft3" if " ft3" in str(sql) else "ft2" if " ft2" in str(sql) else "ft1") for sql, how in TIMEFIXED], teng, True)
    fails += tfails
    print("engine_check: %d statements on tables with times, none refused: %s" % (len(TIMEFIXED), ", ".join("%s=%d" % kv for kv in sorted(tcounts.items()))))
    with tempfile.TemporaryDirectory() as d:
        ueng = run_engine(os.path.join(d, "uniq.db"), lines(u[0] for u in UNIQFIXED))
    ucounts, ufails, _, _ = compare(pg, [(sql, how, "fubr" if " fubr" in sql else "fub" if " fub" in sql else "fuh" if " fuh" in sql else "fui" if " fui" in sql else "fua") for sql, how in UNIQFIXED], ueng, True)
    fails += ufails
    print("engine_check: %d statements on a table with four unique indexes, none refused: %s" % (len(UNIQFIXED), ", ".join("%s=%d" % kv for kv in sorted(ucounts.items()))))
    _, vfails, _, _ = compare(pg, [(sql, how, "fvj" if " fvj" in str(sql) else "fvl" if " fvl" in str(sql) else "fvr" if " fvr" in str(sql) else "fvt" if " fvt" in str(sql) else "fvi") for sql, how, _ in VIAFIXED], veng, True)
    fails += vfails
    print("engine_check: %d statements read by an index and %d beside them that may not be, each with PostgreSQL's answer" % (wanted, sum(1 for v in VIAFIXED if v[1] in ("set", "order") and not v[2])))
    print("engine_check: %d fixed statements, none refused: %s" % (len(FIXED), ", ".join("%s=%d" % kv for kv in sorted(fcounts.items()))))
    fails += ffails
    notes = order_dependent(pg)
    print("engine_check: %d statements whose outcome depends on PostgreSQL's order are refused as such, and %d that are refused on purpose" % (len(DEP), len(UNSUP)))
    for note in notes:
        print("engine_check: NOTE (PostgreSQL %s) %s" % (version, note))
    npoints, nforked = history(SEED)
    print("engine_check: AS OF %d points of a history reads what was there, from another process, after a sweep and more writes, and on a fork (%d points); the branch is untouched by its fork" % (npoints, nforked))
    past_by_value()
    first_rows()
    clocked(pg)
    print("engine_check: now() is what the clock says, the same through a transaction; a column's default now() is taken at each insert; what no clock changes is PostgreSQL's answer")
    print("engine_check: ORDER BY an indexed column with a LIMIT reads the rows it gives and no more")
    print("engine_check: a read of the past by an indexed column's value reads the table as it was, and no index")
    erasure()
    print("engine_check: a deleted row and a dropped table stay in the history; an erased key is gone from the page file two commits and a sweep later, with every salt it had, and from every AS OF")
    print("engine_check: %d statements (seed %d): %s" % (len(stmts), SEED, ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    print("engine_check: %d of the statements have parameters and go by the extended protocol; the engine answers %d of them (rows, changes or the error)" % (len(psent), pok))
    if pok * 3 < len(psent):
        raise SystemExit("engine_check: the engine refuses more than two thirds of the statements with parameters")
    print("engine_check: PostgreSQL answers %d that the engine refuses, of %d it answers in all" % (refused_answered, refused_answered + answered))
    if fails:
        raise SystemExit("engine_check: %d disagreements (PostgreSQL %s)" % (fails, version))
    if refused_answered * 2 > refused_answered + answered:
        raise SystemExit("engine_check: the engine refuses more than half of what PostgreSQL answers")
    print("engine_check: ok (PostgreSQL %s)" % version)


if __name__ == "__main__":
    main()
