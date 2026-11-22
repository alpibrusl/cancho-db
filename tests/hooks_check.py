#!/usr/bin/env python3
"""The first user's statements on the engine (docs/m3-engine.md 6w): the schema and the sixteen queries of `cancho-hooks`, as that service sends them.

    python3 tests/hooks_check.py build/enginecheck

`tests/hooks/schema.sql` and `tests/hooks/queries.sql` are copies of that repository's `sql/` (the commit is in tests/hooks/README). The schema is run on PostgreSQL and on the engine, then a
script of calls (a query's name and the values bound to its parameters, by the extended protocol) on both. After every call the answers are held against each other (the error, or the tag and the
rows) and so is what every table then holds. The engine may refuse; it may not differ. What it refuses PostgreSQL runs and takes back, so the two hold the same rows at the next call (a
sequence is not taken back, in PostgreSQL: a query that draws from one is not answered yet).

What is printed is the measure of the work from here: how many of the schema's statements and how many of the sixteen queries the engine answers (a query counts if every call of it is answered).
The two floors below only go up.
"""
import os
import re
import sys
import tempfile

sys.argv = sys.argv[:2]
import engine_check as ec

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks")
SCHEMA_FLOOR = 14
QUERY_FLOOR = 12
DUMPS = ["select * from attempts order by endpoint, event, replay, attempt", "select * from endpoints order by id", "select * from schedules order by id"]

# (query, values): text as the service's driver sends it, None for a null
CALLS = [
    ("endpoints_all", []),
    ("add_endpoint", ["7", "10.0.0.7", "8080", "whsec_YQ==", "", "", "", "0", "0", "0"]),
    ("add_endpoint", ["7", "10.0.0.8", "8081", "whsec_Yg==", "a.*", "X:1", "", "0", "2", "50"]),
    ("add_endpoint", ["3", "https://example.test", "443", "whsec_Yw==", "invoice.paid,user.*", "", "old", "1700000000000", "8", "100000"]),
    ("add_endpoint", ["1000000", "h", "1", "s", "", "", "", "0", "0", "0"]),
    ("add_endpoint", ["4", "h", "0", "s", "", "", "", "0", "0", "0"]),
    ("create_endpoint", ["10.0.0.9", "9000", "whsec_ZA==", "", "", "0", "0"]),
    ("create_endpoint", ["10.0.0.10", "9001", "whsec_ZQ==", "t", "H:v", "1", "10"]),
    ("endpoints_all", []),
    ("patch_endpoint", ["7", "10.0.0.70", "8088", None, None, None, None, None, None]),
    ("patch_endpoint", ["7", "10.0.0.70", "8088", "whsec_bmV3", "x.y", None, "1800000000000", "4", None]),
    ("patch_endpoint", ["3", "https://example.test", "443", None, None, "K:v", "0", None, "7"]),
    ("patch_endpoint", ["3", "https://example.test", "443", "whsec_bg==", None, None, None, None, None]),
    ("patch_endpoint", ["99", "h", "1", None, None, None, None, None, None]),
    ("patch_address", ["3", "https://other.test", "8443"]),
    ("patch_address", ["98", "h", "1"]),
    ("endpoints_all", []),
    ("add_attempt", ["7", "41", "0", "1", "2", "500", "1700000000100", "12", "12"]),
    ("add_attempt", ["7", "41", "0", "2", "1", "200", "1700000001100", "9", "0"]),
    ("add_attempt", ["7", "41", "0", "2", "3", "410", "1700000001200", "9", "13"]),
    ("add_attempt", ["3", "41", "1", "1", "2", "-3", "1700000002000", "30000", "6"]),
    ("add_attempt", ["3", "42", "0", "1", "1", "204", "1700000003000", "5", "0"]),
    ("add_attempt", ["70000", "43", "0", "1", "1", "200", "1700000004000", "1", "0"]),
    ("attempts_of", ["41"]),
    ("attempts_of", ["42"]),
    ("attempts_of", ["999"]),
    ("prune_attempts", ["1700000001150", "1"]),
    ("attempts_of", ["41"]),
    ("prune_attempts", ["1700000002500", "500"]),
    ("prune_attempts", ["0", "500"]),
    ("delete_endpoint", ["7"]),
    ("delete_endpoint", ["7"]),
    ("create_endpoint", ["10.0.0.11", "9002", "whsec_Zg==", "", "", "0", "0"]),
    ("endpoints_all", []),
    ("schedules_all", []),
    ("create_schedule", ["*/5 * * * *", "tick", "{}", "true", "1700000000"]),
    ("create_schedule", ["0 0 * * *", "daily", "{\"a\":1}", "f", "1700000010"]),
    ("schedule_by_id", ["1"]),
    ("schedule_by_id", ["77"]),
    ("schedules_due", ["1700000300"]),
    ("advance_schedule", ["1", "1700000000", "0", "0", "1700000300"]),
    ("advance_schedule", ["1", "1700000000", "0", "0", "1700000600"]),
    ("advance_schedule", ["1", "1700000000", "1700000300", "1700000300", "1700000600"]),
    ("schedules_due", ["1700000300"]),
    ("schedules_due", ["1700000600"]),
    ("patch_schedule", ["2", None, None, None, "true", "1700000500"]),
    ("patch_schedule", ["1", "*/10 * * * *", None, "{\"b\":2}", None, "1700000700"]),
    ("patch_schedule", ["1", None, "tock", None, "false", "1700000800"]),
    ("patch_schedule", ["55", None, None, None, None, "1"]),
    ("schedules_all", []),
    ("delete_schedule", ["2"]),
    ("delete_schedule", ["2"]),
    ("create_schedule", ["1 1 1 1 1", "again", "{}", "true", "1700000900"]),
    ("schedules_all", []),
]


def statements(text):
    """The statements of an SQL file, comments gone."""
    body = "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("--"))
    return [" ".join(st.split()) for st in body.split(";") if st.strip()]


def queries(text):
    out, name = {}, None
    for line in text.split("\n"):
        m = re.match(r"-- name: (\w+)", line)
        if m:
            name = m.group(1)
        elif name and line.strip() and not line.startswith("--"):
            out[name] = line.strip()
            name = None
    return out


def answer(blk):
    """An engine answer as (kind, detail): ('refused', tag), ('error', code), ('ok', (tag, oids, rows))."""
    head = blk[0]
    if head.startswith("refused "):
        return "refused", head.split()[1]
    if head.startswith("error "):
        return "error", head.split()[1]
    tag, oids, rows = None, [], []
    for line in blk[1:]:
        if line.startswith("G "):
            tag = line[2:]
        elif line.startswith("T "):
            oids = [int(x) for x in line.split()[1:]]
        elif line.startswith("R "):
            rows.append([None if v == "-" else ec.unhex(v) for v in line.split()[1:]])
    return "ok", (tag, oids, rows)


def main():
    ec.admin("drop database if exists %s_hooks" % ec.DB)
    r = ec.admin("create database %s_hooks encoding 'UTF8' lc_collate 'C' lc_ctype 'C' template template0" % ec.DB)
    if r.returncode != 0:
        raise SystemExit("hooks_check: " + r.stderr)
    pg = ec.Pg(ec.DB + "_hooks")
    schema = statements(open(os.path.join(HERE, "schema.sql")).read())
    qs = queries(open(os.path.join(HERE, "queries.sql")).read())
    if len(qs) != 16:
        raise SystemExit("hooks_check: %d queries read, and hooks has 16" % len(qs))
    missing = sorted(set(qs) - set(c[0] for c in CALLS))
    if missing:
        raise SystemExit("hooks_check: no call of %s" % missing)
    steps = [(None, st) for st in schema] + [(name, ec.P(qs[name], *vals)) for name, vals in CALLS]
    script = []
    for _, st in steps:
        script += ec.lines([st]) + DUMPS
    with tempfile.TemporaryDirectory() as d:
        eng = ec.run_engine(os.path.join(d, "hooks.db"), script)
    if len(eng) != 4 * len(steps):
        raise SystemExit("hooks_check: %d answers for %d lines" % (len(eng), 4 * len(steps)))
    ok_schema = 0
    refused = {}
    called = {}
    for i, (name, st) in enumerate(steps):
        kind, detail = answer(eng[4 * i])
        where = "%s %s" % (name or "schema", (st.params if name else st[:60]))
        if kind == "refused":
            # a refusal changes nothing: PostgreSQL runs the statement and takes it back, so that the two hold the same rows for the next call
            ec.take_back(pg, st)
            if name:
                refused.setdefault(name, detail)
            else:
                print("hooks_check:   refused schema: %s (%s)" % (st[:70], detail))
            err = None
        else:
            err, oids, rows, tag = pg.query(st)
        if kind == "refused":
            pass
        elif kind == "error":
            if err != detail:
                raise SystemExit("hooks_check: %s: the engine says error %s, PostgreSQL %s" % (where, detail, err or "no error"))
        else:
            if err is not None:
                raise SystemExit("hooks_check: %s: the engine answers, PostgreSQL says error %s" % (where, err))
            if detail[0] != tag or detail[2] != rows or (rows and detail[1] != oids):
                raise SystemExit("hooks_check: %s: the engine answers %s, PostgreSQL %s" % (where, detail, (tag, oids, rows)))
        if kind != "refused":
            if name:
                called[name] = called.get(name, 0) + 1
            else:
                ok_schema += 1
        # what the tables hold now: only where the engine has kept up (a refusal leaves the two apart from there on, and that table is no longer compared)
        for j, dump in enumerate(DUMPS):
            dk, dd = answer(eng[4 * i + 1 + j])
            _, _, prow, _ = pg.query(dump)
            if dk == "ok" and dd[2] != prow:
                raise SystemExit("hooks_check: after %s: %s differs\n  engine:   %s\n  postgres: %s" % (where, dump.split()[3], dd[2][:6], prow[:6]))
    answered = sorted(n for n in qs if n not in refused and called.get(n, 0) > 0)
    print("hooks_check: the schema of cancho-hooks: %d of %d statements answered" % (ok_schema, len(schema)))
    print("hooks_check: its queries: %d of 16 answered as PostgreSQL answers them, over %d calls%s" % (len(answered), len(CALLS), (": " + ", ".join(answered)) if answered else ""))
    for n in sorted(refused):
        print("hooks_check:   refused %-16s %s" % (n, refused[n]))
    if ok_schema < SCHEMA_FLOOR or len(answered) < QUERY_FLOOR:
        raise SystemExit("hooks_check: fewer than before (%d statements, %d queries)" % (SCHEMA_FLOOR, QUERY_FLOOR))
    print("hooks_check: ok")


main()
