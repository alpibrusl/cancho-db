#!/usr/bin/env python3
"""Writes tests/lex_cases.cho: the cases for src/lex.cho (docs/m1-lowering.md section 3), as cancho source.

Every expected answer is written by hand below, from PostgreSQL's documented lexical rules, not computed by anything in src/.
Inputs and expected token renderings are hex in the generated file, so no byte (non-ASCII, NUL, a newline) can be mangled by
source escaping. A token renders as `K:text`, K being I ident, Q quoted ident, S string, N number, O operator, P punctuation,
C `::`, T `;`, M a parameter, joined by newlines; a refusal is its tag.

    python3 tools/gen_lex.py            # rewrites tests/lex_cases.cho
    python3 tools/gen_lex.py --check    # fails if the file on disk differs (the gate runs this)
"""
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "lex_cases.cho"
CASES = []  # (input bytes, ("ok", [(K, text)...], nstatements) | ("refuse", tag), cap)


def ok(sql, toks, stmts, cap=200):
    CASES.append((sql if isinstance(sql, bytes) else sql.encode("latin-1"), ("ok", toks, stmts), cap))


def refuse(sql, tag, cap=200):
    CASES.append((sql if isinstance(sql, bytes) else sql.encode("latin-1"), ("refuse", tag), cap))


I, Q, S, N, O, P, C, T, M = "I", "Q", "S", "N", "O", "P", "C", "T", "M"

# ---- the plain forms
ok("select 1", [(I, "select"), (N, "1")], 1)
ok("SELECT a,b FROM t;", [(I, "SELECT"), (I, "a"), (P, ","), (I, "b"), (I, "FROM"), (I, "t"), (T, ";")], 1)
ok("", [], 0)
ok("  \n\t \r\n ", [], 0)
ok(";", [(T, ";")], 0)
ok(";;", [(T, ";"), (T, ";")], 0)
ok("select 1;;select 2", [(I, "select"), (N, "1"), (T, ";"), (T, ";"), (I, "select"), (N, "2")], 2)
ok("select 1; select 2;", [(I, "select"), (N, "1"), (T, ";"), (I, "select"), (N, "2"), (T, ";")], 2)
ok("select * from t where a = 1 and b <> 'x'",
   [(I, "select"), (O, "*"), (I, "from"), (I, "t"), (I, "where"), (I, "a"), (O, "="), (N, "1"), (I, "and"), (I, "b"),
    (O, "<>"), (S, "x")], 1)
ok("a_b$c1", [(I, "a_b$c1")], 1)
ok("_x", [(I, "_x")], 1)

# ---- comments
ok("select 1 -- c", [(I, "select"), (N, "1")], 1)
ok("select 1 -- c\n, 2", [(I, "select"), (N, "1"), (P, ","), (N, "2")], 1)
ok("select /* c */ 1", [(I, "select"), (N, "1")], 1)
ok("select /* a /* b */ c */ 1", [(I, "select"), (N, "1")], 1)           # nested: PostgreSQL nests
ok("select 1 /* ; */", [(I, "select"), (N, "1")], 1)                     # a ; in a comment separates nothing
ok("select 1 -- ; select 2", [(I, "select"), (N, "1")], 1)
ok("/* a */ /* b */", [], 0)
ok("--", [], 0)
ok("select 1 --", [(I, "select"), (N, "1")], 1)
ok("a--b", [(I, "a")], 1)
ok("/**/ 1", [(N, "1")], 1)
ok("/*/ */ 1", [(N, "1")], 1)
ok("/* /* */ */ /* */ 1", [(N, "1")], 1)
refuse("/*/", "unterminated")
refuse("/* x", "unterminated")
refuse("/* /* x */", "unterminated")                                       # one level left open
refuse("select 1 /* ; select 2", "unterminated")
ok("select 1 -- caf\xc3\xa9", [(I, "select"), (N, "1")], 1)               # non-ASCII is fine inside a comment
ok("select /* caf\xc3\xa9 */ 1", [(I, "select"), (N, "1")], 1)

# ---- operators, and PostgreSQL's rules for where they end
ok("a - -b", [(I, "a"), (O, "-"), (O, "-"), (I, "b")], 1)
ok("a+--b", [(I, "a"), (O, "+")], 1)                                      # the comment starts inside the run
ok("a+/*c*/b", [(I, "a"), (O, "+"), (I, "b")], 1)
ok("1+-2", [(N, "1"), (O, "+"), (O, "-"), (N, "2")], 1)                   # +- ends in -, with no special char: trimmed
ok("x=-1", [(I, "x"), (O, "="), (O, "-"), (N, "1")], 1)
ok("x*-1", [(I, "x"), (O, "*"), (O, "-"), (N, "1")], 1)
ok("a/-b", [(I, "a"), (O, "/"), (O, "-"), (I, "b")], 1)
ok("1+@2", [(N, "1"), (O, "+@"), (N, "2")], 1)                           # a special char: it may end in anything
ok("x=~y", [(I, "x"), (O, "=~"), (I, "y")], 1)
ok("a<=b", [(I, "a"), (O, "<="), (I, "b")], 1)
ok("a<>b", [(I, "a"), (O, "<>"), (I, "b")], 1)
ok("a!=b", [(I, "a"), (O, "!="), (I, "b")], 1)
ok("a||b", [(I, "a"), (O, "||"), (I, "b")], 1)
ok("a-", [(I, "a"), (O, "-")], 1)
ok("-", [(O, "-")], 1)
ok("*/", [(O, "*/")], 1)
ok("`", [(O, "`")], 1)
ok("a?b", [(I, "a"), (O, "?"), (I, "b")], 1)
# an operator may end in + or - only if it also holds one of ~ ! @ # % ^ & | ` ?  (so each of them, once, and the control)
for ch in "~!@#%^&|`?":
    ok("a%s-b" % ch, [(I, "a"), (O, ch + "-"), (I, "b")], 1)
    ok("a%s+b" % ch, [(I, "a"), (O, ch + "+"), (I, "b")], 1)
ok("a<-b", [(I, "a"), (O, "<"), (O, "-"), (I, "b")], 1)                  # no special character: trimmed
ok("a>+b", [(I, "a"), (O, ">"), (O, "+"), (I, "b")], 1)
ok("a=+-b", [(I, "a"), (O, "="), (O, "+"), (O, "-"), (I, "b")], 1)       # trimmed one sign at a time
# a comment inside an operator run ends the run even when the run could otherwise keep a trailing sign
ok("a@--b\n", [(I, "a"), (O, "@")], 1)
ok("a@/*c*/b", [(I, "a"), (O, "@"), (I, "b")], 1)
ok("a!--b\nc", [(I, "a"), (O, "!"), (I, "c")], 1)
ok("a::int", [(I, "a"), (C, "::"), (I, "int")], 1)
ok("a:b", [(I, "a"), (P, ":"), (I, "b")], 1)
ok("a:::b", [(I, "a"), (C, "::"), (P, ":"), (I, "b")], 1)

# ---- strings
ok("select 'a;b'", [(I, "select"), (S, "a;b")], 1)                        # a ; in a string separates nothing
ok("select 'it''s'", [(I, "select"), (S, "it''s")], 1)
ok("select ''", [(I, "select"), (S, "")], 1)
ok("select ''''", [(I, "select"), (S, "''")], 1)
ok("select 'a' 'b'", [(I, "select"), (S, "a"), (S, "b")], 1)             # adjacent strings: the parser's to refuse
ok("select 'a\\'", [(I, "select"), (S, "a\\")], 1)                       # a backslash is a backslash
ok("select 'a\\';select 1", [(I, "select"), (S, "a\\"), (T, ";"), (I, "select"), (N, "1")], 2)
ok("select 'caf\xc3\xa9'", [(I, "select"), (S, "caf\xc3\xa9")], 1)       # non-ASCII is fine inside a string
ok("select '--'", [(I, "select"), (S, "--")], 1)
ok("select '/*'", [(I, "select"), (S, "/*")], 1)
ok("select 'x'--y", [(I, "select"), (S, "x")], 1)
ok("E 'x'", [(I, "E"), (S, "x")], 1)                                     # a space makes E an ordinary identifier
ok("xE'a'", [(I, "xE"), (S, "a")], 1)                                    # only a ONE-letter prefix changes the quote
ok("U &'x'", [(I, "U"), (O, "&"), (S, "x")], 1)
ok('b"x"', [(I, "b"), (Q, "x")], 1)
refuse("'abc", "unterminated")
refuse("select 'a''", "unterminated")
refuse("select 'a\x00b'", "nul-byte")
refuse("E'x'", "escape-string")
refuse("e'x'", "escape-string")
refuse("select E'\\x41'", "escape-string")
refuse("B'01'", "bit-string")
refuse("X'1f'", "bit-string")
refuse("N'x'", "bit-string")
refuse("x'1f'", "bit-string")
refuse("U&'x'", "unicode-escape")
refuse("u&'x'", "unicode-escape")
refuse('U&"x"', "unicode-escape")

# ---- quoted identifiers
ok('select "a;b" from t', [(I, "select"), (Q, "a;b"), (I, "from"), (I, "t")], 1)
ok('"a""b"', [(Q, 'a""b')], 1)
ok('"Select"', [(Q, "Select")], 1)
ok('"a b"', [(Q, "a b")], 1)
ok('"' + "a" * 63 + '"', [(Q, "a" * 63)], 1)
ok('"' + "a" * 62 + '"' + '"' + '"', [(Q, "a" * 62 + '""')], 1)           # 62 + one escaped quote = 63 wide
refuse('""', "empty-identifier")
refuse('"', "unterminated")
refuse('"abc', "unterminated")
refuse('"' + "a" * 64 + '"', "identifier-too-long")
refuse('"' + "a" * 63 + '""' + '"', "identifier-too-long")                 # 63 + an escaped quote = 64 wide
refuse('"caf\xc3\xa9"', "non-ascii")
refuse('"a\x00b"', "nul-byte")

# ---- unquoted identifiers
ok("a" * 63, [(I, "a" * 63)], 1)
refuse("a" * 64, "identifier-too-long")
refuse("caf\xc3\xa9", "non-ascii")
refuse("\xc3\xa9", "non-ascii")
refuse("select 1\x00", "nul-byte")
refuse("\x00", "nul-byte")
refuse("select 1 -- a\x00b", "nul-byte")
refuse("select 1 /* a\x00b */", "nul-byte")
ok("a$", [(I, "a$")], 1)
ok("$1", [(M, "$1")], 1)
ok("select $12", [(I, "select"), (M, "$12")], 1)
ok("$65535", [(M, "$65535")], 1)
ok("$1,$2", [(M, "$1"), (P, ","), (M, "$2")], 1)
ok("a=$10;", [(I, "a"), (O, "="), (M, "$10"), (T, ";")], 1)
ok("($1)", [(P, "("), (M, "$1"), (P, ")")], 1)
refuse("$0", "parameter")
refuse("$01", "parameter")
refuse("$65536", "parameter")
refuse("$99999999999999999999", "parameter")
refuse("$1a", "parameter")
refuse("$1_", "parameter")
refuse("$12x", "parameter")
refuse("$$x$$", "dollar-quote")
refuse("$tag$ x $tag$", "dollar-quote")
refuse("$", "dollar-quote")
refuse("select $a", "dollar-quote")

# ---- numbers
ok("1", [(N, "1")], 1)
ok("1.5", [(N, "1.5")], 1)
ok(".5", [(N, ".5")], 1)
ok("1.", [(N, "1.")], 1)
ok("1e5", [(N, "1e5")], 1)
ok("1E+5", [(N, "1E+5")], 1)
ok("1.5e-3", [(N, "1.5e-3")], 1)
ok("007", [(N, "007")], 1)
ok("1.2.3", [(N, "1.2"), (N, ".3")], 1)
ok("1..2", [(N, "1."), (N, ".2")], 1)
ok("1+2", [(N, "1"), (O, "+"), (N, "2")], 1)
ok("1-2", [(N, "1"), (O, "-"), (N, "2")], 1)
ok("t.c", [(I, "t"), (P, "."), (I, "c")], 1)
ok("t.*", [(I, "t"), (P, "."), (O, "*")], 1)
refuse("1e", "number-junk")
refuse("1e+", "number-junk")
refuse("1abc", "number-junk")
refuse("1_000", "number-junk")
refuse("0x1F", "number-junk")
refuse("1.5x", "number-junk")
refuse("12$", "number-junk")

# ---- punctuation and what is not in the grammar
ok("(a,b)[1]", [(P, "("), (I, "a"), (P, ","), (I, "b"), (P, ")"), (P, "["), (N, "1"), (P, "]")], 1)
refuse("\\", "unknown-character")
refuse("select {", "unknown-character")
refuse("select }", "unknown-character")
refuse("select \x0c1", "unknown-character")                              # form feed: whitespace in some versions only
refuse("select \x0b1", "unknown-character")                              # vertical tab: likewise
refuse("select \x7f", "unknown-character")
refuse("select \x01", "unknown-character")
refuse("select \x80", "non-ascii")

# ---- the token cap: the refusal is the same however it is reached
ok("a a a a", [(I, "a")] * 4, 1, cap=8)
ok("a a a a a a a", [(I, "a")] * 7, 1, cap=8)                              # the most that fits
refuse("a a a a a a a a", "too-long", cap=8)                              # one more does not
refuse("a a a a a a a a a a", "too-long", cap=8)


def hx(b): return b.hex()


def render(toks): return "\n".join("%s:%s" % (k, t) for k, t in toks).encode("latin-1")


def emit():
    o = ["module cdb.lex_cases;", "",
         "// GENERATED by tools/gen_lex.py: do not edit. The cases for src/lex.cho; every answer was written by hand in the",
         "// generator. Inputs and expected token renderings are hex.", "",
         "pub fn n_lex() -> [] int {\n    return %d;\n}\n" % len(CASES)]

    def table(fname, typ, f, default):
        lines = ["pub fn lex_%s(i: int) -> [] %s {" % (fname, typ)]
        for i, case in enumerate(CASES):
            lines.append("    if i == %d {\n        return %s;\n    }" % (i, f(case)))
        lines.append("    return %s;\n}\n" % default)
        o.append("\n".join(lines))

    table("input", "&static [byte]", lambda c: '"%s"' % hx(c[0]), '""')
    table("ok", "int", lambda c: "1" if c[1][0] == "ok" else "0", "0")
    table("want", "&static [byte]", lambda c: '"%s"' % (hx(render(c[1][1])) if c[1][0] == "ok" else ""), '""')
    table("stmts", "int", lambda c: str(c[1][2]) if c[1][0] == "ok" else "0", "0")
    table("tag", "&static [byte]", lambda c: '"%s"' % (c[1][1] if c[1][0] == "refuse" else ""), '""')
    table("cap", "int", lambda c: str(c[2]), "0")
    return "\n".join(o)


if __name__ == "__main__":
    text = emit()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("tests/lex_cases.cho is not what tools/gen_lex.py writes", file=sys.stderr)
            sys.exit(1)
        print("lexer cases reproducible: %d cases" % len(CASES))
    else:
        OUT.write_text(text)
        print("wrote %s: %d cases (%d refusals)" % (OUT.name, len(CASES), sum(1 for c in CASES if c[1][0] == "refuse")))
