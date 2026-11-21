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
                # with the table's name: a bare `k` may be an output column that a cast or a CASE named k, and then it decides nothing
                keys.append(t.name + "." + pk + self.pick(["", " desc"]))
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
            return "alter table %s add column %s %s" % (t.name, g.pick(t.cols)[0], ty)
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
        t.cols.append((name, ty, nn, dflt))
        return "alter table %s add column %s %s%s%s" % (t.name, name, ty, " not null" if nn else "", " default " + dflt if dflt else "")
    if r < 0.85:
        cols = [g.pick(t.cols)[0] for _ in range(g.pick([1, 1, 2]))]
        if g.r.random() < 0.08:
            cols.append("nope")
        return "create %sindex %s on %s (%s)" % ("unique " if g.r.random() < 0.08 else "", g.pick(["ix1", "ix2", "ix3", "ta", "tb"]), t.name, ", ".join(cols))
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
    ("drop table fq", "ddl"),
    ("drop table fx", "ddl"),
    ("drop table fy", "ddl"),
]


# Statements whose outcome in PostgreSQL depends on the order it works in (6g), which the engine REFUSES as `engine-order-dependent`, and what PostgreSQL 16 does with each here. The rows were stored 3, 2, 1.
DEP_SETUP = ["create table fz (k integer primary key, n integer)", "insert into fz values (3, 30)", "insert into fz values (2, 20)", "insert into fz values (1, 10)",
             "create table fw (wk integer primary key, m integer)", "insert into fw values (1, 5), (9, 0)"]
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
        if ans != ["refused engine-order-dependent"]:
            raise SystemExit("engine_check: %s: the engine says %s, and the answer depends on PostgreSQL's order" % (sql, ans))
        if err != want:
            # what PostgreSQL 16 does is written down beside each statement; another version may plan otherwise, which is the point of refusing
            if PGMAJOR[0] == 16:
                raise SystemExit("engine_check: %s: PostgreSQL says %s, expected %s" % (sql, err, want))
            notes.append("%s: %s, where PostgreSQL 16 says %s" % (sql, err, want))
    with tempfile.TemporaryDirectory() as d:
        eng = run_engine(os.path.join(d, "unsup.db"), DEP_SETUP + [x[0] for x in UNSUP])
    for (sql, want), ans in zip(UNSUP, eng[len(DEP_SETUP):]):
        pg.query("begin")
        err, _, _, _ = pg.query(sql)
        pg.query("rollback")
        if ans != ["refused engine-unsupported"]:
            raise SystemExit("engine_check: %s: the engine says %s, and this is one it does not answer" % (sql, ans))
        if err != want:
            if PGMAJOR[0] == 16:
                raise SystemExit("engine_check: %s: PostgreSQL says %s, expected %s" % (sql, err, want))
            notes.append("%s: %s, where PostgreSQL 16 says %s" % (sql, err, want))
    pg.query("drop table fz")
    pg.query("drop table fw")
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
        elif r < 0.055:
            stmts.append((ddl_more(g, added), "ddl", g.t.name))
        elif r < 0.065:
            spare += 1
            bad = g.table("tz%d" % spare)
            stmts.append((bad.ddl() + rng.choice(["", "", " "]), "ddl", bad.name))
            stmts.append(("drop table %s" % bad.name, "ddl", bad.name))
        elif r < 0.35:
            stmts.append((g.insert(), "write", g.t.name))
        elif r < 0.52:
            stmts.append((g.update(), "write", g.t.name))
        elif r < 0.6:
            stmts.append((g.delete(), "write", g.t.name))
        elif r < 0.64:
            pk = g.t.cols[g.t.pk][0]
            stmts.append(("select * from %s order by %s" % (g.t.name, pk), "order", g.t.name))
        elif r < 0.74:
            sql, how = gselect(g)
            stmts.append((sql, how, g.t.name))
        elif r < 0.82:
            stmts.append(jselect(g, tables))
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
    fstmts = [(sql, how, "fq" if " fq " in sql and how == "write" else ("fy" if " fy" in sql else "fx")) for sql, how in FIXED]
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
    print("engine_check: PostgreSQL answers %d that the engine refuses, of %d it answers in all" % (refused_answered, refused_answered + answered))
    if fails:
        raise SystemExit("engine_check: %d disagreements (PostgreSQL %s)" % (fails, version))
    if refused_answered * 2 > refused_answered + answered:
        raise SystemExit("engine_check: the engine refuses more than half of what PostgreSQL answers")
    print("engine_check: ok (PostgreSQL %s)" % version)


main()
