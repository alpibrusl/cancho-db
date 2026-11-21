#!/usr/bin/env python3
"""The engine's rows against PostgreSQL (src/row.cho, docs/m3-engine.md D-M3-6, slice M3c).

    PG_E2E_PORT=5532 python3 tests/row_check.py build/rowcheck [TABLES]

For random tables (1 to 8 columns of the engine's types, names of several lengths so that jsonb's key order matters, a primary key of 1 to 3 columns) and random rows (nulls, the limits of 64-bit integers, empty
strings, quotes, backslashes, control characters, text in several scripts, binary bytes), the same rows are put into PostgreSQL 16 and the engine's encoding of them is given to `rowcheck`. Checked, for every row:
the image equals `to_jsonb(row)::text` byte for byte; the plain key equals `jsonb_build_array(<key columns>)::text`; and the rows sorted by their stored keys are in PostgreSQL's order of the key columns
(text with `COLLATE "C"`). Also: definitions and rows that are not well formed are refused.
"""
import os
import random
import struct
import subprocess
import sys

EXE = sys.argv[1]
TABLES = int(sys.argv[2]) if len(sys.argv) > 2 else 40
PORT = os.environ.get("PG_E2E_PORT", "5532")
DB = os.environ.get("E2E_DB", "cdb_rowcheck")
FAILED = []
PSQL = ["psql", "-h", "127.0.0.1", "-p", PORT, "-U", "postgres", "-At", "-q", "-v", "ON_ERROR_STOP=1"]


def check(name, ok, detail=""):
    if not ok:
        print("FAIL %s   %s" % (name, str(detail)[:400]))
        FAILED.append(name)


def pg(db, sql):
    r = subprocess.run(PSQL + ["-d", db, "-F", "\t"], input=sql, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("row_check: psql failed: " + r.stderr[:400])
    return [l.split("\t") for l in r.stdout.split("\n") if l]


TYPES = {1: ["bigint", "integer", "smallint"], 2: ["boolean"], 3: ["text", "varchar"], 4: ["bytea"]}
TEXTS = ["", "a", "ana@example.org", 'say "hi"', "back\\slash", "tab\there", "line\nbreak", "\r\x08\x0c", "\x01\x1f\x7f", "ñandú", "日本語", "🙂 emoji", "{\"json\": [1]}", "'quote'", " ", "a" * 300]


def rand_value(rng, ty, sqltype, key):
    if not key and rng.random() < .15:
        return None
    if ty == 1:
        lim = {"bigint": 63, "integer": 31, "smallint": 15}[sqltype]
        return rng.choice([0, 1, -1, 2 ** lim - 1, -2 ** lim, rng.randrange(-2 ** lim, 2 ** lim), rng.randrange(-1000, 1000)])
    if ty == 2:
        return rng.random() < .5
    if ty == 3:
        if rng.random() < .5:
            return rng.choice(TEXTS)
        return "".join(chr(rng.choice([rng.randrange(1, 128), rng.randrange(0xa0, 0x250), rng.randrange(0x4e00, 0x4e80)])) for _ in range(rng.randrange(0, 12)))
    return bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 2, 5, 40])))


def enc_def(cols):
    out = struct.pack(">H", len(cols))
    for name, ty, _, pk in cols:
        out += bytes([ty, pk]) + struct.pack(">H", len(name)) + name.encode()
    return out


def enc_row(cols, row):
    out = b""
    for (name, ty, _, pk), v in zip(cols, row):
        if v is None:
            out += b"\x00"
        elif ty == 1:
            out += b"\x01" + struct.pack(">q", v)
        elif ty == 2:
            out += b"\x02" + bytes([1 if v else 0])
        elif ty == 3:
            b = v.encode()
            out += b"\x03" + struct.pack(">H", len(b)) + b
        else:
            out += b"\x04" + struct.pack(">H", len(v)) + v
    return out


def sql_lit(ty, v):
    if v is None:
        return "null"
    if ty == 1:
        return str(v)
    if ty == 2:
        return "true" if v else "false"
    if ty == 3:
        return "convert_from(decode('%s', 'hex'), 'UTF8')" % v.encode().hex()
    return "decode('%s', 'hex')" % v.hex()


def engine(pairs):
    r = subprocess.run([EXE], input="".join("%s %s\n" % (d.hex(), w.hex()) for d, w in pairs), capture_output=True, text=True)
    return r.stdout.split("\n")[:len(pairs)]


def main():
    subprocess.run(PSQL + ["-d", "postgres", "-c", "drop database if exists %s" % DB], capture_output=True)
    r = subprocess.run(PSQL + ["-d", "postgres", "-c", "create database %s encoding 'UTF8' template template0" % DB], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("row_check: " + r.stderr)
    rng = random.Random(5)
    rows_total = 0
    for t in range(TABLES):
        n = rng.randrange(1, 9)
        names = set()
        while len(names) < n:
            names.add(rng.choice(["a", "b", "id", "ab", "ba", "z", "aa", "name", "email", "c1", "c10", "c2", "_x", "total_amount", "n"]) + rng.choice(["", "", "_2", "x"]))
        names = list(names)
        rng.shuffle(names)
        cols = []
        for nm in names:
            ty = rng.choice([1, 1, 2, 3, 3, 4])
            cols.append([nm, ty, rng.choice(TYPES[ty]), 0])
        kcount = rng.randrange(1, min(3, n) + 1)
        for place, i in enumerate(rng.sample(range(n), kcount)):
            cols[i][3] = place + 1
        keycols = [c for c in sorted(cols, key=lambda c: c[3]) if c[3] > 0]
        rows, seen = [], set()
        for _ in range(rng.choice([5, 30, 80])):
            row = [rand_value(rng, c[1], c[2], c[3] > 0) for c in cols]
            k = tuple(repr(row[cols.index(c)]) for c in keycols)
            if k in seen:
                continue
            seen.add(k)
            rows.append(row)
        ddl = "create table t%d (%s, primary key (%s));\n" % (t, ", ".join('"%s" %s' % (c[0], c[2]) for c in cols), ", ".join('"%s"' % c[0] for c in keycols))
        ins = "".join("insert into t%d values (%s);\n" % (t, ", ".join(sql_lit(c[1], v) for c, v in zip(cols, row))) for row in rows)
        order = ", ".join('"%s"%s' % (c[0], ' collate "C"' if c[1] == 3 else "") for c in keycols)
        q = "select encode(convert_to(to_jsonb(x)::text, 'UTF8'), 'hex'), encode(convert_to(jsonb_build_array(%s)::text, 'UTF8'), 'hex') from t%d x order by %s;\n" % (", ".join('x."%s"' % c[0] for c in keycols), t, order)
        want = pg(DB, ddl + ins + q)
        d = enc_def(cols)
        got = engine([(d, enc_row(cols, row)) for row in rows])
        got = [g.split(" ") for g in got]
        bad = [g for g in got if len(g) != 3]
        check("table %d: every row is taken" % t, not bad, bad[:1])
        if bad:
            continue
        got.sort(key=lambda g: bytes.fromhex(g[2]))
        rows_total += len(rows)
        diff = [(bytes.fromhex(g[0]), bytes.fromhex(w[0])) for g, w in zip(got, want) if g[0] != w[0]]
        check("table %d (%d columns, %d rows): the images are to_jsonb's, in PostgreSQL's key order when sorted by the stored key" % (t, n, len(rows)), not diff and len(got) == len(want), diff[:1])
        diff = [(bytes.fromhex(g[1]), bytes.fromhex(w[1])) for g, w in zip(got, want) if g[1] != w[1]]
        check("table %d: the plain keys are jsonb_build_array's" % t, not diff, diff[:1])

    # not well formed
    good_def = enc_def([["id", 1, "bigint", 1], ["v", 3, "text", 0]])
    good_row = enc_row([["id", 1, "bigint", 1], ["v", 3, "text", 0]], [7, "x"])
    cases = [
        ("a definition with no columns", struct.pack(">H", 0), good_row, "bad def"),
        ("a definition with a type 5", good_def.replace(b"\x01\x01\x00\x02id", b"\x05\x01\x00\x02id"), good_row, "bad def"),
        ("a definition with an empty name", struct.pack(">H", 1) + b"\x01\x01\x00\x00", good_row, "bad def"),
        ("a definition with bytes over", good_def + b"\x00", good_row, "bad def"),
        ("a definition whose key places are 1 and 1", enc_def([["a", 1, "", 1], ["b", 1, "", 1]]), good_row, "bad def"),
        ("a definition whose key places are 2 alone", enc_def([["a", 1, "", 2], ["b", 1, "", 0]]), good_row, "bad def"),
        ("a definition cut short", good_def[:-1], good_row, "bad def"),
        ("a row with a value missing", good_def, good_row[:9], "bad row"),
        ("a row with bytes over", good_def, good_row + b"\x00", "bad row"),
        ("a row with text where the integer is", good_def, b"\x03\x00\x01a" + good_row[9:], "bad row"),
        ("a row with a null key", good_def, b"\x00" + good_row[9:], "bad row"),
        ("a row with a boolean of 2", enc_def([["id", 1, "", 1], ["b", 2, "", 0]]), b"\x01" + bytes(8) + b"\x02\x02", "bad row"),
        ("a row whose text runs past the end", good_def, good_row[:9] + b"\x03\x00\x09x", "bad row"),
    ]
    out = engine([(d, r) for _, d, r, _ in cases])
    for (name, _, _, want), got in zip(cases, out):
        check("%s is refused (%s)" % (name, want), got == want, got)
    subprocess.run(PSQL + ["-d", "postgres", "-c", "drop database if exists %s" % DB], capture_output=True)
    print("row_check: %d tables, %d rows, %d failures" % (TABLES, rows_total, len(FAILED)))
    return 1 if FAILED else 0


sys.exit(main())
