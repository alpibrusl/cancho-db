#!/usr/bin/env python3
"""The lexer against PostgreSQL itself: do they count the same statements?  (docs/m1-lowering.md section 6)

    PG_E2E_PORT=5532 python3 tests/lex_diff.py LEXCHECK_BINARY [CASES] [SEED]

For each generated SQL string it asks two parties how many statements it holds:

  * `lexcheck` (src/lex.cho): `ok <tokens> <statements>`, or a refusal;
  * PostgreSQL, over the wire: the number of CommandComplete messages a simple Query produces.

When the lexer accepts and PostgreSQL runs the message without error, **the two counts must be equal**. A lexer that finds fewer
statements than PostgreSQL runs would let a statement through unchecked: that is the failure this test exists for. A refusal by
the lexer, or an error from PostgreSQL, is not compared (the first is the safe direction, the second means nothing ran).

The strings come from two generators: a grammar of VALID statement lists with hostile lexical content (semicolons in strings,
comments and quoted identifiers; nested comments; backslashes; doubled quotes), where the right count is known; and a fuzzer
over an alphabet of dangerous fragments, where it is not and PostgreSQL is the oracle. Every statement is a harmless `select`.
"""
import concurrent.futures
import os
import random
import socket
import struct
import subprocess
import sys

PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
LEX = sys.argv[1]
CASES = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
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
        kinds = []
        while True:
            t = self.read_exact(1)
            (ln,) = struct.unpack(">I", self.read_exact(4))
            self.read_exact(ln - 4)
            kinds.append(t)
            if t == b"Z":
                return kinds

    def run(self, sql):
        """-> (CommandComplete count, errored). The statements are all harmless selects."""
        body = sql + b"\0"
        self.s.sendall(b"Q" + struct.pack(">I", len(body) + 4) + body)
        kinds = self.read_until_ready()
        return kinds.count(b"C"), (b"E" in kinds)


def lex_full(sql):
    r = subprocess.run([LEX], input=sql, capture_output=True, timeout=30)
    out = r.stdout.decode().split()
    if r.returncode != 0 or not out:
        return ("crash", r.stderr.decode()[:100])
    if out[0] == "ok":
        return ("ok", int(out[2]), int(out[1]))
    return ("refused", out[1])


def lex(sql):
    got = lex_full(sql)
    return got[:2]


# --------------------------------------------------------------------------- generators
STATEMENTS = [
    b"select 1", b"select 'a;b'", b"select 'a'';b'", b"select ''''", b"select '--'", b"select '/*'", b"select '*/'",
    b"select 'a\\'", b"select 'a\\\\'", b"select 1 /* ; select 2 */", b"select 1 -- ; select 2\n",
    b"select /* /* ; */ ; */ 1", b"select 1 /* a */", b"select 1+-2", b"select 'x'::text", b"select 1 where 'a' = 'a'",
    b'select 1 as "a;b"', b'select 1 as "a""b"', b'select 1 as "--"', b'select 1 as "/*"', b"select 1 /**/",
    b"select 1 /*/ ; */", b"select ';'", b"select 1 -- c\n", b"select 1 /* -- */",
]
SEPARATORS = [b";", b" ; ", b";\n", b"; -- c\n", b"; /* c */ ", b";;", b"; ;", b";\n--x\n;", b" /* ; */ ; "]
LEADS = [b"", b" ", b"\n", b"-- c\n", b"/* c */ ", b"/* /* n */ */ ", b";", b" ; "]


def valid_list(rng):
    k = rng.randint(1, 4)
    stmts = [rng.choice(STATEMENTS) for _ in range(k)]
    out = rng.choice(LEADS)
    for i, st in enumerate(stmts):
        out += st
        if i < k - 1:
            out += rng.choice(SEPARATORS)
    if rng.random() < 0.5:
        out += rng.choice(SEPARATORS)
    return out, k


ALPHABET = [b"'", b"''", b'"', b'""', b"/*", b"*/", b"--", b";", b"\n", b" ", b"\\", b"E", b"e'", b"$", b"$$", b"a", b"1",
            b"select 1", b"select ", b"-", b"/", b"*", b":", b"::", b"(", b")", b"u&", b"U&'", b"b'", b"x'", b"\t", b"\r",
            b"--\n", b"/* ", b" */", b"'a'", b'"a"', b"+", b".", b"1e", b"1_0", b"0x1"]


def fuzz(rng):
    return b"".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 14)))


OPCHARS = "+-*/<>=~!@#%^&|`?"


def operator_diff(pg, rng, count):
    """How PostgreSQL ends an operator, read from its own error message, against where the lexer ends it.

    `select null::xml OP null::xml` always fails (the xml type has no operators), and when PostgreSQL lexed OP as ONE token the
    error is exactly `operator does not exist: xml OP xml`. Any other outcome (a different message, a syntax error) means it
    read OP as several tokens. The lexer must agree: one operator token (`aOPb` is three tokens) exactly when PostgreSQL read
    one. Two PostgreSQL scanner special cases are accounted for: `!=` is rewritten to `<>`, and `=>` is its own token (named
    arguments), not an operator."""
    bad, single, several = [], 0, 0
    seen = set()
    while len(seen) < count:
        op = "".join(rng.choice(OPCHARS) for _ in range(rng.randint(1, 3)))
        if rng.random() < 0.6:
            op += rng.choice("+-")          # the trimming rule is about a trailing sign: lean on it
        if op in seen or "--" in op or "/*" in op or op == "=>":
            continue
        seen.add(op)
        sql = ("select null::xml %s null::xml" % op).encode()
        body = sql + b"\0"
        pg.s.sendall(b"Q" + struct.pack(">I", len(body) + 4) + body)
        raw = b""
        while True:
            t = pg.read_exact(1)
            (ln,) = struct.unpack(">I", pg.read_exact(4))
            data = pg.read_exact(ln - 4)
            if t == b"E":
                raw = data
            if t == b"Z":
                break
        err = raw.decode(errors="replace")
        shown = {"!=": "<>"}.get(op, op)
        pg_single = ("M" + "operator does not exist: xml %s xml" % shown) in err.replace("\x00", "") \
            and err.split("operator does not exist: xml ", 1)[1].split(" xml")[0] == shown if "operator does not exist: xml " in err else False
        ours = lex_full(("a%sb" % op).encode())
        if ours[0] != "ok":
            bad.append((op, "the lexer refused an operator string", ours))
            continue
        if pg_single:
            single += 1
        else:
            several += 1
        if pg_single != (ours[2] == 3):
            bad.append((op, "PostgreSQL read %s, the lexer read %d tokens" % ("one operator" if pg_single else "several tokens", ours[2]), err[:100].replace("\x00", " ")))
    return bad, single, several


def main():
    rng = random.Random(SEED)
    pg = PG()
    stats = dict(valid=0, valid_agree=0, fuzz=0, compared=0, compared_multi=0, lex_refused=0, pg_error=0)
    failures = []
    cases = [valid_list(rng) for _ in range(CASES // 2)] + [(fuzz(rng), None) for _ in range(CASES - CASES // 2)]

    def lexed(case): return lex(case[0])

    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        results = list(ex.map(lexed, cases))
    for (sql, known), got in zip(cases, results):
        if got[0] == "crash":
            failures.append(("the lexer crashed", sql, got))
            continue
        ran, errored = pg.run(sql)
        if known is not None:
            stats["valid"] += 1
            if errored or ran != known:
                failures.append(("the generator's own count is wrong (a bad fragment)", sql, (ran, errored, known)))
                continue
            stats["valid_agree"] += 1
        else:
            stats["fuzz"] += 1
        if got[0] == "refused":
            stats["lex_refused"] += 1
            continue
        if errored:
            stats["pg_error"] += 1
            continue
        stats["compared"] += 1
        if ran > 1:
            stats["compared_multi"] += 1
        if got[1] != ran:
            failures.append(("LEXER AND POSTGRESQL DISAGREE ON THE NUMBER OF STATEMENTS", sql, "lexer %d, PostgreSQL %d" % (got[1], ran)))
    bad_ops, single, several = operator_diff(pg, rng, max(200, CASES // 4))
    for op, what, detail in bad_ops[:20]:
        failures.append((what, op.encode(), detail))
    print("operators: %d strings PostgreSQL reads as ONE operator, %d it reads as several; %d disagreements" % (
        single, several, len(bad_ops)))
    if single < 20 or several < 20:
        print("FAIL the operator comparison was rarely exercised")
        return 1
    for what, sql, detail in failures[:20]:
        print("FAIL %s: %r %s" % (what, sql, detail))
    print("%d strings (%d from a grammar of valid lists, %d fuzzed): %d compared with PostgreSQL (%d of them with 2 or more "
          "statements), the lexer refused %d, PostgreSQL rejected %d" % (
              CASES, stats["valid"], stats["fuzz"], stats["compared"], stats["compared_multi"], stats["lex_refused"],
              stats["pg_error"]))
    if stats["compared"] < CASES // 4 or stats["compared_multi"] < CASES // 20:
        print("FAIL the comparison was rarely exercised; the generators no longer reach it")
        return 1
    print("%d disagreements" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
