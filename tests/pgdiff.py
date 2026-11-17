"""Shared by tests/parse_diff.py and tests/stmt_diff.py: a minimal PostgreSQL wire client and the expression generators."""
import random
import socket
import struct

PORT = 0


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
        return self.explain("select " + expr + " from t")

    def explain(self, stmt):
        """-> ("plan", text) or ("error", sqlstate, is_syntax). SQLSTATE 42601 also covers semantic refusals ("non-integer
        constant in ORDER BY"), so `is_syntax` says whether PostgreSQL's own parser refused the text."""
        # a statement with parameters has only a generic plan (PostgreSQL 16: GENERIC_PLAN accepts `$n`)
        rows, err = self.run("explain (verbose, costs off%s) " % (", generic_plan" if "$" in stmt else "") + stmt)
        if err:
            return ("error", err[0], err[1].startswith("syntax error"))
        return ("plan", "\n".join(r[0] for r in rows))




# --------------------------------------------------------------------------- the typed grammar
class Gen:
    prefix = ""

    def __init__(self, rng):
        self.r = rng

    def sp(self):
        return self.r.choice([" ", " ", " ", "  ", "\n", " /* c */ "])

    def kw(self, w):
        return self.r.choice([w, w, w.upper(), w.capitalize()])

    def maybe(self, e, p=0.5):
        return "(" + e + ")" if self.r.random() < p else e

    def col(self, name):
        if self.prefix:
            return self.prefix + name
        c = self.r.random()
        if c < 0.15:
            return "t." + name
        if c < 0.25:
            return '"' + name + '"'
        if c < 0.3:
            return name.upper()
        return name

    def num(self):
        return self.r.choice(["0", "1", "2", "3", "7", "10", "255", "1.5", ".5", "2.", "1e2", "100000", "2147483648", "$1", "$2", "$3"])

    def text_lit(self):
        return self.r.choice(["'a'", "'ab'", "''", "'it''s'", "'%a%'", "'x_'", "'--'", "'/*'", "$1", "$2"])

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
         "distinct", "from", "all", "any", "escape", "similar to", "at time zone", "collate", "^", "[", "]", ".", "1.", ".5", "$1", "$2", "$1"]


def fuzz(rng):
    return " ".join(rng.choice(VOCAB) for _ in range(rng.randint(1, 10)))


OPERANDS = ["a", "b", "1", "2", "c", "d", "'x'", "null", "true", "-a", "not d", "abs(a)", "a::int", "(a)", "case when d then a end", "$1", "$2"]
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


