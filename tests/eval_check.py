#!/usr/bin/env python3
"""The engine's expression evaluator against PostgreSQL (src/eval.cho, docs/m3-engine.md gate 4, slice M3d).

    PG_E2E_PORT=5532 python3 tests/eval_check.py build/evalcheck [EXPRESSIONS] [SEED]

A table `t` of the engine's types with rows that hold nulls and the limits of each integer type is made in PostgreSQL 16 (a database with the C locale) and given to `evalcheck`. Random expressions, most of them
well typed and some not, are evaluated by both as `select <expression> from t`, row by row. The rule (D-M3-4): the engine may REFUSE (`unsupported`), and whenever it answers its answer is PostgreSQL's: the type
(`pg_typeof`), the value of every row, or the same SQLSTATE when the statement is an error. Printed: how many expressions each side answered and how. A disagreement is a failure; so is an engine that
refuses more than half of what PostgreSQL answers (the subset would be a sham).
"""
import os
import random
import struct
import subprocess
import sys

EXE = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1
PORT = os.environ.get("PG_E2E_PORT", "5532")
DB = os.environ.get("E2E_DB", "cdb_evalcheck")
PSQL = ["psql", "-h", "127.0.0.1", "-p", PORT, "-U", "postgres", "-At", "-q"]

COLS = [("id", 5, "integer", 1), ("i2", 6, "smallint", 0), ("i4", 5, "integer", 0), ("i8", 1, "bigint", 0), ("b", 2, "boolean", 0), ("s", 3, "text", 0), ("y", 4, "bytea", 0)]
ROWS = [
    (1, 0, 0, 0, True, "", b""),
    (2, 1, 1, 1, False, "a", b"\x00"),
    (3, -1, -1, -1, None, "abc", b"abc"),
    (4, 32767, 2147483647, 9223372036854775807, True, "ABC", b"\xff\x00"),
    (5, -32768, -2147483648, -9223372036854775808, False, "a%b_c", b"a"),
    (6, None, None, None, None, None, None),
    (7, 7, 100, 10000000000, True, "12", b"12"),
    (8, 2, 3, 5, False, " 42 ", b"zz"),
    (9, 10, 0, 3, True, "true", b""),
    (10, 3, 46341, 3037000500, False, "back\\slash", b"\\"),
    (11, 5, -7, -9, True, "ñandú", b"\xc3\xb1"),
    (12, 100, 65536, 4294967296, None, "yes", None),
]
TYPENAME = {0: "unknown", 1: "bigint", 5: "integer", 6: "smallint", 2: "boolean", 3: "text", 4: "bytea"}
STATIC = {5: "42883", 6: "42804", 7: "42846"}
DYNAMIC = {2: "22012", 3: "22003", 4: "22P02", 5: "22025"}


def enc_def():
    out = struct.pack(">H", len(COLS))
    for name, ty, _, pk in COLS:
        out += bytes([ty, pk]) + struct.pack(">H", len(name)) + name.encode()
    return out


def enc_row(row):
    out = b""
    for (name, ty, _, pk), v in zip(COLS, row):
        if v is None:
            out += b"\x00"
        elif ty in (1, 5, 6):
            out += b"\x01" + struct.pack(">q", v)
        elif ty == 2:
            out += b"\x02" + bytes([1 if v else 0])
        else:
            b = v.encode() if ty == 3 else v
            out += bytes([ty]) + struct.pack(">H", len(b)) + b
    return out


def sql_lit(ty, v):
    if v is None:
        return "null"
    if ty in (1, 5, 6):
        return str(v)
    if ty == 2:
        return "true" if v else "false"
    if ty == 3:
        return "convert_from(decode('%s', 'hex'), 'UTF8')" % v.encode().hex()
    return "decode('%s', 'hex')" % v.hex()


class Gen:
    def __init__(self, rng):
        self.r = rng

    def int_(self, d):
        r = self.r
        k = r.random()
        if d <= 0 or k < .3:
            return r.choice(["i2", "i4", "i8", "i4", "id", "0", "1", "2", "3", "7", "10", "100", "32767", "2147483647", "2147483648", "9223372036854775807", "'5'", "'12'"])
        if k < .62:
            return "(%s %s %s)" % (self.int_(d - 1), r.choice(["+", "-", "*", "/", "%", "+", "-"]), self.int_(d - 1))
        if k < .68:
            return "(- %s)" % self.int_(d - 1)
        if k < .80:
            return "case when %s then %s else %s end" % (self.bool_(d - 1), self.int_(d - 1), self.int_(d - 1))
        if k < .90:
            return "cast(%s as %s)" % (self.int_(d - 1), r.choice(["smallint", "integer", "bigint", "int", "int8"]))
        if k < .96:
            return "cast(%s as integer)" % self.text_(d - 1)
        return "cast(%s as integer)" % self.bool_(d - 1)

    def bool_(self, d):
        r = self.r
        k = r.random()
        if d <= 0 or k < .15:
            return r.choice(["b", "true", "false", "b", "null", "'t'", "cast('yes' as boolean)", "cast('off' as boolean)", "cast(' TRUE ' as boolean)", "cast(s as boolean)", "case when (s = 'yes') then cast(s as boolean) end", "case when (s in ('yes', 'true')) then cast(s as boolean) else b end",
                             "(s like '_andú')", "(s like '_b_')", "(s like 'a\\%b%')", "(s ilike 'abc')", "(s not ilike 'abc')", "(s not ilike 'ÑANDÚ')", "(s like '%')", "(s like 'a%c')", "(s not like '%b%')", "(s like s)"])
        if k < .40:
            return "(%s %s %s)" % (self.int_(d - 1), r.choice(["=", "<>", "<", "<=", ">", ">="]), self.int_(d - 1))
        if k < .50:
            return "(%s %s %s)" % (self.text_(d - 1), r.choice(["=", "<>", "<", ">=", "like", "not like", "ilike", "not ilike"]), self.text_(d - 1))
        if k < .66:
            return "(%s %s %s)" % (self.bool_(d - 1), r.choice(["and", "or"]), self.bool_(d - 1))
        if k < .72:
            return "(not %s)" % self.bool_(d - 1)
        if k < .80:
            return "(%s is %snull)" % (r.choice([self.int_, self.text_, self.bool_])(d - 1), r.choice(["", "not "]))
        if k < .88:
            return "(%s %sin (%s))" % (self.int_(d - 1), r.choice(["", "not "]), ", ".join(self.int_(d - 1) for _ in range(r.randrange(1, 4))))
        if k < .92:
            return "(%s in (%s))" % (self.text_(d - 1), ", ".join(self.text_(0) for _ in range(r.randrange(1, 4))))
        if k < .96:
            return "(b = %s)" % self.bool_(d - 1)
        return "cast(%s as boolean)" % r.choice([self.text_(d - 1), "i4", "'yes'", "'0'", "i8"])

    def text_(self, d):
        r = self.r
        k = r.random()
        if d <= 0 or k < .4:
            return r.choice(["s", "s", "'a'", "'abc'", "'%'", "'a%'", "'_b_'", "'ABC'", "''", "'12'", "' 42 '", "'x'", "'true'", "'a\\%b'", "'%b\\_c'", "'ñ%'", "'_andú'"])
        if k < .65:
            return "(%s || %s)" % (self.text_(d - 1), self.text_(d - 1))
        if k < .80:
            return "cast(%s as text)" % r.choice([self.int_, self.bool_, self.text_])(d - 1)
        if k < .9:
            return "case when %s then %s else %s end" % (self.bool_(d - 1), self.text_(d - 1), self.text_(d - 1))
        if k < .95:
            return "case when %s then %s end" % (self.bool_(d - 1), self.text_(d - 1))
        return "cast(y as text)"

    def wild(self, d):
        r = self.r
        if d <= 0:
            return r.choice(["i2", "i4", "i8", "b", "s", "y", "1", "'a'", "null", "true", "'1'", "1.5", "id"])
        k = r.random()
        if k < .5:
            return "(%s %s %s)" % (self.wild(d - 1), r.choice(["=", "<", "+", "-", "*", "/", "||", "and", "or", "like", "<>", "%"]), self.wild(d - 1))
        if k < .6:
            return "(not %s)" % self.wild(d - 1)
        if k < .7:
            return "(- %s)" % self.wild(d - 1)
        if k < .8:
            return "cast(%s as %s)" % (self.wild(d - 1), r.choice(["integer", "text", "boolean", "bigint", "smallint", "bytea", "varchar"]))
        if k < .9:
            return "case when %s then %s else %s end" % (self.wild(d - 1), self.wild(d - 1), self.wild(d - 1))
        return "(%s in (%s, %s))" % (self.wild(d - 1), self.wild(d - 1), self.wild(d - 1))

    def expr(self):
        k = self.r.random()
        d = self.r.randrange(1, 5)
        if k < .3:
            return self.int_(d)
        if k < .6:
            return self.bool_(d)
        if k < .8:
            return self.text_(d)
        return self.wild(min(d, 3))


def postgres(exprs):
    script = ["\\set VERBOSITY verbose", "\\pset null NULL"]
    for i, e in enumerate(exprs):
        script.append("\\echo ==%d" % i)
        script.append("select pg_typeof(%s)::text || ' ' || coalesce(encode(convert_to((%s)::text, 'UTF8'), 'hex'), 'NULL') from t order by id;" % (e, e))
    r = subprocess.run(PSQL + ["-d", DB], input="\n".join(script) + "\n", capture_output=True, text=True)
    out, cur = {}, None
    for line in (r.stdout + "\n").split("\n"):
        if line.startswith("=="):
            cur = int(line[2:])
            out[cur] = []
        elif cur is not None and line:
            out[cur].append(line)
    errs, cur = {}, 0
    # errors come on stderr, in order: match them to the statements that have no rows
    codes = [l.split(":")[1].strip() for l in r.stderr.split("\n") if l.startswith("ERROR:")]
    k = 0
    for i in range(len(exprs)):
        if not out.get(i):
            errs[i] = codes[k] if k < len(codes) else "?"
            k += 1
    return out, errs


def main():
    subprocess.run(PSQL + ["-d", "postgres", "-c", "drop database if exists %s" % DB], capture_output=True)
    r = subprocess.run(PSQL + ["-d", "postgres", "-c", "create database %s encoding 'UTF8' lc_collate 'C' lc_ctype 'C' template template0" % DB], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("eval_check: " + r.stderr)
    ddl = "create table t (%s);\n" % ", ".join("%s %s%s" % (c[0], c[2], " primary key" if c[3] else "") for c in COLS)
    ddl += "".join("insert into t values (%s);\n" % ", ".join(sql_lit(c[1], v) for c, v in zip(COLS, row)) for row in ROWS)
    r = subprocess.run(PSQL + ["-d", DB, "-v", "ON_ERROR_STOP=1"], input=ddl, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("eval_check: " + r.stderr)
    g = Gen(random.Random(SEED))
    exprs = []
    seen = set()
    while len(exprs) < N:
        e = g.expr()
        if e not in seen and len(e) < 600:
            seen.add(e)
            exprs.append(e)
    feed = "def %s\n" % enc_def().hex() + "".join("row %s\n" % enc_row(r).hex() for r in ROWS) + "".join("sql select %s from t\n" % e for e in exprs)
    eng = subprocess.run([EXE], input=feed, capture_output=True, text=True).stdout.split("\n")
    pg_rows, pg_errs = postgres(exprs)
    counts = {"agree-values": 0, "agree-error": 0, "engine-unsupported": 0, "proxy-refused": 0, "DISAGREE": 0}
    unsupported_when_pg_answers = 0
    shown = 0
    for i, e in enumerate(exprs):
        line = eng[i] if i < len(eng) else "<no answer>"
        pg_ok = i not in pg_errs
        verdict = "DISAGREE"
        if line.startswith("refused "):
            verdict = "proxy-refused"
        elif " static 1" in line:
            verdict = "engine-unsupported"
            if pg_ok:
                unsupported_when_pg_answers += 1
        elif " static " in line:
            code = int(line.split(" static ")[1])
            if not pg_ok and STATIC.get(code) == pg_errs[i]:
                verdict = "agree-error"
        else:
            vals = line.split()
            dyn = [DYNAMIC.get(int(v.split(":")[2])) for v in vals if v.split(":")[1] == "2"]
            if dyn:
                if not pg_ok and pg_errs[i] in dyn:
                    verdict = "agree-error"
            elif pg_ok and len(vals) == len(ROWS) == len(pg_rows[i]):
                same = True
                for v, p in zip(vals, pg_rows[i]):
                    ty, st, body = v.split(":")
                    ptype, phex = p.rsplit(" ", 1)
                    if TYPENAME[int(ty)] != ptype:
                        same = False
                    elif st == "1":
                        same = same and phex == "NULL"
                    elif int(ty) in (1, 5, 6):
                        same = same and phex == body.encode().hex()
                    elif int(ty) == 2:
                        same = same and phex == (b"true" if body == "1" else b"false").hex()
                    elif int(ty) == 4:
                        same = same and phex == (b"\\x" + ("" if body == "." else body).encode()).hex()
                    else:
                        same = same and phex == ("" if body == "." else body)
                if same:
                    verdict = "agree-values"
        counts[verdict] += 1
        if verdict == "DISAGREE" and shown < 12:
            shown += 1
            print("FAIL %s\n     engine: %s\n     postgres: %s" % (e, line[:300], (pg_errs.get(i) or pg_rows.get(i))))
    answered = counts["agree-values"] + counts["agree-error"]
    pg_answers = sum(1 for i in range(len(exprs)) if i not in pg_errs)
    print("eval_check: %d expressions (seed %d): %s" % (N, SEED, ", ".join("%s=%d" % kv for kv in counts.items())))
    version = subprocess.run(PSQL + ["-d", "postgres", "-c", "show server_version"], capture_output=True, text=True).stdout.strip()
    print("eval_check: PostgreSQL %s answers %d with values; the engine refuses %d of those as unsupported" % (version, pg_answers, unsupported_when_pg_answers))
    subprocess.run(PSQL + ["-d", "postgres", "-c", "drop database if exists %s" % DB], capture_output=True)
    bad = counts["DISAGREE"] > 0 or unsupported_when_pg_answers * 2 > pg_answers or answered == 0
    return 1 if bad else 0


sys.exit(main())
