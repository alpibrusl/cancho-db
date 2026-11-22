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
import re
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

    for i, (sql, how, tname) in enumerate(stmts):
        blk = eng[i]
        head = blk[0] if blk else "<nothing>"
        state = blk[-1].split()[1] if blk and blk[-1].startswith("S ") else "?"
        body = blk[1:-1]
        pre = pg.status
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
        if how == "write" and before is not None:
            after = snapshot(tname)
            want = set()
            for k in set(before) | set(after):
                if before.get(k) != after.get(k):
                    want.add((tname.encode(), k, before.get(k), after.get(k)))
            got = set()
            for line in changes:
                _, t, k, o, nw = line.split()
                got.add((unhex(t), unhex(k), None if o == "-" else unhex(o), None if nw == "-" else unhex(nw)))
            if got == want and len(got) == len(changes):
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

DEP_SETUP = ["create table fz (k integer primary key, n integer)", "insert into fz values (3, 30)", "insert into fz values (2, 20)", "insert into fz values (1, 10)",
             "create table fw (wk integer primary key, m integer)", "insert into fw values (1, 5), (9, 0)",
             "create table fi (k integer primary key, c bigint generated always as identity)", "insert into fi (k) values (1)",
             "create table ft (k integer primary key, s text)", "insert into ft values (1, '3000000000 7abc')"]
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
    ("create unique index fzu on fz (n)", None),                         # a constraint that needs an index to hold
    ("select fw.m, count(*) from fz join fw on fz.k = fw.wk group by fw.wk", None),   # m depends on fw's key
    # digits that are out of range, then something that is no digit: PostgreSQL says out of range, having not read on
    ("select cast(s as integer) from ft", "22003"),
    ("select cast(s as smallint) from ft", "22003"),
    ("select cast(s as bigint) from ft", "22P02"),
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
        if ans[:1] != ["refused engine-unsupported"]:
            raise SystemExit("engine_check: %s: the engine says %s, and this is one it does not answer" % (sql, ans))
        if err != want:
            if PGMAJOR[0] == 16:
                raise SystemExit("engine_check: %s: PostgreSQL says %s, expected %s" % (sql, err, want))
            notes.append("%s: %s, where PostgreSQL 16 says %s" % (sql, err, want))
    pg.query("drop table fz")
    pg.query("drop table fw")
    pg.query("drop table fi")
    pg.query("drop table ft")
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
        return len(points), len(forked)


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
        run_engine(path, ["create table er (k integer primary key, s text)", "insert into er values (1, '%s'), (2, '%s'), (3, '%s')" % (one, two, three), "!commit"])
        data = open(path, "rb").read()
        if one.encode() not in data or two.encode() not in data or three.encode() not in data:
            raise SystemExit("engine_check: the rows are not in the page file after a commit")
        # an update and a delete: what the rows were stays in the history, in the file and to AS OF
        newer = "THIRD-NEW-rezrov"
        run_engine(path, ["update er set s = 'CHANGED-VALUE-nitfol' where k = 1", "delete from er where k = 2", "update er set s = '%s' where k = 3" % newer] + settle)
        data = open(path, "rb").read()
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
    version = pg.query("show server_version")[2][0][0].decode().split()[0]
    PGMAJOR[0] = int(version.split(".")[0])
    rng = random.Random(SEED)
    g = Gen(rng)
    tables = {}
    stmts = []   # (sql, how, table name)
    for name in ["ta", "tb", "tc"][:rng.randrange(2, 4)]:
        tables[name] = g.table(name)
        stmts.append((tables[name].ddl(), "ddl", name))
    spare = 0
    added = [0]
    open_txn = False
    while len(stmts) < N:
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
        if stmts[-1][1] != "ddl" and rng.random() < 0.3:
            stmts[-1] = (parametrise(rng, stmts[-1][0]),) + stmts[-1][1:]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "engine.db")
        if open_txn:
            stmts.append(("commit", "ddl", "ta"))
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
        m = re.match(r"(?:insert into|update|delete from) (f[ksonmr]\d?)\b", sql)
        if m:
            return m.group(1)
        return "fwide" if " fwide" in sql and how == "write" else "fq" if " fq" in (sql + " ").replace(" fq ", " fq") and how == "write" else ("fy" if " fy" in sql else "fp" if " fp" in sql else "fx")
    fstmts = [(sql, how, ftable(sql, how)) for sql, how in FIXED]
    fcounts, ffails, _, _ = compare(pg, fstmts, feng, True)
    print("engine_check: %d fixed statements, none refused: %s" % (len(FIXED), ", ".join("%s=%d" % kv for kv in sorted(fcounts.items()))))
    fails += ffails
    notes = order_dependent(pg)
    print("engine_check: %d statements whose outcome depends on PostgreSQL's order are refused as such, and %d that are refused on purpose" % (len(DEP), len(UNSUP)))
    for note in notes:
        print("engine_check: NOTE (PostgreSQL %s) %s" % (version, note))
    npoints, nforked = history(SEED)
    print("engine_check: AS OF %d points of a history reads what was there, from another process, after a sweep and more writes, and on a fork (%d points); the branch is untouched by its fork" % (npoints, nforked))
    erasure()
    print("engine_check: a deleted row and a dropped table stay in the history; an erased key is gone from the page file two commits and a sweep later, and from every AS OF")
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
