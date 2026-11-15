#!/usr/bin/env python3
"""The expression parser against PostgreSQL itself: does the rendering mean what the original means?
(docs/m1-lowering.md section 6, gate 2)

    PG_E2E_PORT=5532 python3 tests/parse_diff.py EXPRCHECK_BINARY [CASES] [SEED]

For each generated expression it asks:

  * `exprcheck` (src/parse.cho): `ok <rendering>`, or `refused <tag>`;
  * PostgreSQL, over the wire: `EXPLAIN (VERBOSE, COSTS OFF) SELECT <expr> FROM t` for the original and for the rendering.

The rendering is what the proxy will run, so what must hold when the parser accepts is:

  * the two plans are IDENTICAL: PostgreSQL parenthesises what it parsed in its `Output:` line, so a precedence or
    associativity mistake in the parser shows as a different line;
  * if one errors the other errors with the same SQLSTATE;
  * PostgreSQL does not refuse the original as a SYNTAX error (42601): that would be the parser accepting what PostgreSQL
    rejects, and running a statement nobody wrote.

A refusal by the parser is not compared (the safe direction); how many valid expressions it refused is reported, not hidden.
The strings come from two generators: a grammar of typed expressions written with and without redundant parentheses, spaced and
cased at random, where most are valid; and a fuzzer over a vocabulary of tokens, where most are not and PostgreSQL is the oracle.
"""
import os
import random
import socket
import struct
import subprocess
import sys

PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
EXPR = sys.argv[1]
CASES = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1


class PG:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
        body = struct.pack(">I", 196608) + b"user\0postgres\0database\0postgres\0\0"
        self.s.sendall(struct.pack(">I", len(body) + 4) + body)
        self.read_until_ready()

    def read_exact(self, n):
        buf = b""
        while len(buf) < n:
            d = self.s.recv(n - len(buf))
            if not d:
                raise EOFError("connection closed")
            buf += d
        return buf

    def read_until_ready(self):
        rows, err = [], None
        while True:
            t = self.read_exact(1)
            (ln,) = struct.unpack(">I", self.read_exact(4))
            body = self.read_exact(ln - 4)
            if t == b"D":
                (nc,) = struct.unpack(">H", body[:2])
                at, vals = 2, []
                for _ in range(nc):
                    (n,) = struct.unpack(">i", body[at:at + 4])
                    at += 4
                    vals.append(body[at:at + n].decode())
                    at += max(n, 0)
                rows.append(vals)
            elif t == b"E":
                fields = {}
                for part in body.split(b"\0"):
                    if part:
                        fields[part[:1]] = part[1:].decode()
                err = (fields.get(b"C", "?"), fields.get(b"M", ""))
            elif t == b"Z":
                return rows, err

    def run(self, sql):
        body = sql.encode() + b"\0"
        self.s.sendall(b"Q" + struct.pack(">I", len(body) + 4) + body)
        return self.read_until_ready()

    def plan(self, expr):
        rows, err = self.run("explain (verbose, costs off) select " + expr + " from t")
        if err:
            return ("error", err[0])
        return ("plan", "\n".join(r[0] for r in rows))


def check(src):
    r = subprocess.run([EXPR], input=src.encode(), capture_output=True, timeout=30)
    out = r.stdout.decode().rstrip("\n")
    if r.returncode != 0 or not out:
        return ("crash", r.stderr.decode()[:100])
    if out.startswith("ok "):
        return ("ok", out[3:])
    return ("refused", out.split(" ", 1)[1])


# --------------------------------------------------------------------------- the typed grammar
class Gen:
    def __init__(self, rng):
        self.r = rng

    def sp(self):
        return self.r.choice([" ", " ", " ", "  ", "\n", " /* c */ "])

    def kw(self, w):
        return self.r.choice([w, w, w.upper(), w.capitalize()])

    def maybe(self, e, p=0.5):
        return "(" + e + ")" if self.r.random() < p else e

    def col(self, name):
        c = self.r.random()
        if c < 0.15:
            return "t." + name
        if c < 0.25:
            return '"' + name + '"'
        if c < 0.3:
            return name.upper()
        return name

    def num(self):
        return self.r.choice(["0", "1", "2", "3", "7", "10", "255", "1.5", ".5", "2.", "1e2", "100000", "2147483648"])

    def text_lit(self):
        return self.r.choice(["'a'", "'ab'", "''", "'it''s'", "'%a%'", "'x_'", "'--'", "'/*'"])

    def i(self, d):
        r = self.r.random()
        if d <= 0 or r < 0.25:
            return self.r.choice([self.num(), self.col("a"), self.col("b"), self.col("a"), self.num()])
        s = self.sp
        if r < 0.6:
            op = self.r.choice(["+", "-", "*", "/", "%", "+", "-", "*"])
            return self.maybe(self.i(d - 1) + s() + op + s() + self.i(d - 1), 0.4)
        if r < 0.67:
            return "-" + self.maybe(self.i(d - 1), 0.5)
        if r < 0.75:
            return "(" + self.i(d - 1) + ")"
        if r < 0.82:
            return self.kw("case") + " " + self.kw("when") + " " + self.b(d - 1) + " " + self.kw("then") + " " + self.i(d - 1) + " " + self.kw("else") + " " + self.i(d - 1) + " " + self.kw("end")
        if r < 0.86:
            return self.kw("case") + " " + self.i(d - 1) + " " + self.kw("when") + " " + self.i(d - 1) + " " + self.kw("then") + " " + self.i(d - 1) + " " + self.kw("end")
        if r < 0.92:
            return self.r.choice(["abs(", "abs ( "]) + self.i(d - 1) + ")"
        if r < 0.95:
            return "mod(" + self.i(d - 1) + ", " + self.i(d - 1) + ")"
        if r < 0.97:
            return "length(" + self.t(d - 1) + ")"
        return self.maybe(self.i(d - 1), 1) + "::" + self.r.choice(["int", "integer", "bigint", "smallint", "numeric", "numeric(10,2)", "text::int"])

    def t(self, d):
        r = self.r.random()
        if d <= 0 or r < 0.3:
            return self.r.choice([self.text_lit(), self.col("c"), self.col("c")])
        s = self.sp
        if r < 0.55:
            return self.maybe(self.t(d - 1) + s() + "||" + s() + self.t(d - 1), 0.4)
        if r < 0.65:
            return self.maybe(self.t(d - 1) + s() + "||" + s() + self.i(d - 1), 0.4)
        if r < 0.75:
            return self.r.choice(["lower(", "upper("]) + self.t(d - 1) + ")"
        if r < 0.85:
            return self.kw("case") + " " + self.kw("when") + " " + self.b(d - 1) + " " + self.kw("then") + " " + self.t(d - 1) + " " + self.kw("end")
        if r < 0.92:
            return "(" + self.t(d - 1) + ")"
        return self.maybe(self.i(d - 1), 1) + "::" + self.r.choice(["text", "varchar", "varchar(5)"])

    def b(self, d):
        r = self.r.random()
        s = self.sp
        if d <= 0 or r < 0.12:
            return self.r.choice([self.kw("true"), self.kw("false"), self.kw("null"), self.col("d"), self.col("d")])
        if r < 0.3:
            op = self.r.choice(["=", "<>", "!=", "<", "<=", ">", ">="])
            return self.maybe(self.i(d - 1) + s() + op + s() + self.i(d - 1), 0.4)
        if r < 0.36:
            op = self.r.choice(["=", "<>", "<", ">="])
            return self.maybe(self.t(d - 1) + s() + op + s() + self.t(d - 1), 0.4)
        if r < 0.5:
            return self.maybe(self.b(d - 1) + " " + self.kw(self.r.choice(["and", "or", "and"])) + " " + self.b(d - 1), 0.4)
        if r < 0.58:
            return self.kw("not") + " " + self.maybe(self.b(d - 1), 0.5)
        if r < 0.66:
            n = self.kw("not") + " " if self.r.random() < 0.3 else ""
            return self.maybe(self.i(d - 1) + " " + n + self.kw("between") + " " + self.i(d - 1) + " " + self.kw("and") + " " + self.i(d - 1), 0.4)
        if r < 0.74:
            n = self.kw("not") + " " if self.r.random() < 0.3 else ""
            items = ", ".join(self.i(d - 2) for _ in range(self.r.randint(1, 4)))
            return self.maybe(self.i(d - 1) + " " + n + self.kw("in") + " (" + items + ")", 0.4)
        if r < 0.82:
            n = self.kw("not") + " " if self.r.random() < 0.3 else ""
            return self.maybe(self.t(d - 1) + " " + n + self.kw(self.r.choice(["like", "ilike"])) + " " + self.t(d - 1), 0.4)
        if r < 0.9:
            n = " " + self.kw("not") if self.r.random() < 0.4 else ""
            inner = self.r.choice([self.i, self.t, self.b])(d - 1)
            return self.maybe(self.maybe(inner, 0.6) + " " + self.kw("is") + n + " " + self.kw("null"), 0.3)
        if r < 0.95:
            return "(" + self.b(d - 1) + ")"
        return self.maybe(self.i(d - 1), 1) + "::" + self.r.choice(["boolean", "bool", "int::boolean"])

    def any(self):
        d = self.r.randint(1, 4)
        e = self.r.choice([self.i, self.t, self.b, self.b])(d)
        return self.r.choice(["", " ", "\n", "/* c */"]) + e + self.r.choice(["", " ", "-- c\n"])


VOCAB = ["a", "b", "c", "d", "1", "2", "'x'", "null", "true", "and", "or", "not", "is", "in", "like", "between", "case", "when",
         "then", "else", "end", "cast", "as", "int", "text", "::", "(", ")", ",", "+", "-", "*", "/", "%", "||", "=", "<", ">", "<=",
         ">=", "<>", "!=", "abs", "count(*)", "t.a", "isnull", "notnull", "ilike", "not like", "not in", "not between", "not null",
         "distinct", "from", "all", "any", "escape", "similar to", "at time zone", "collate", "^", "[", "]", ".", "1.", ".5"]


def fuzz(rng):
    return " ".join(rng.choice(VOCAB) for _ in range(rng.randint(1, 10)))


OPERANDS = ["a", "b", "1", "2", "c", "d", "'x'", "null", "true", "-a", "not d", "abs(a)", "a::int", "(a)", "case when d then a end"]
BINOPS = ["+", "-", "*", "/", "%", "||", "=", "<>", "<", ">=", "and", "or", "like", "ilike", "not like", "between", "not between",
          "in (1, 2)", "not in (a)", "is null", "is not null", "and", "and", "or"]


def chain(rng):
    """Operands and operators in a row, with no parentheses: it is the precedence and associativity of every pair that is
    being asked (`a < b < c`, `x between a < b and c`, `not a = b is null`)."""
    out = [rng.choice(OPERANDS)]
    for _ in range(rng.randint(1, 5)):
        op = rng.choice(BINOPS)
        out.append(op)
        if not op.startswith("is"):
            out.append(rng.choice(OPERANDS))
    return " ".join(out)


def main():
    rng = random.Random(SEED)
    pg = PG()
    err = pg.run("create temp table t(a int, b int, c text, d bool)")[1]
    if err:
        print("cannot create the table:", err)
        return 1
    g = Gen(rng)
    stats = {"cases": 0, "refused": 0, "refused_valid": 0, "same_plan": 0, "same_error": 0}
    bad = []
    for n in range(CASES):
        src = g.any() if n % 4 < 2 else (chain(rng) if n % 4 == 2 else fuzz(rng))
        got = check(src)
        stats["cases"] += 1
        if got[0] == "crash":
            bad.append(("crash", src, got))
            continue
        orig = pg.plan(src)
        if got[0] == "refused":
            stats["refused"] += 1
            if orig[0] == "plan":
                stats["refused_valid"] += 1
            continue
        render = got[1]
        rend = pg.plan(render)
        if orig[0] == "error" and orig[1] == "42601":
            bad.append(("accepted what PostgreSQL refuses as a syntax error", src, render))
        elif orig == rend:
            stats["same_plan" if orig[0] == "plan" else "same_error"] += 1
        else:
            bad.append(("different", src, render, orig, rend))
    print(stats)
    for b in bad[:10]:
        print("DISAGREEMENT", b)
    print(f"{len(bad)} disagreements in {stats['cases']} cases")
    return 1 if bad else 0


sys.exit(main())
