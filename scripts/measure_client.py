#!/usr/bin/env python3
"""What a client's own SQL gets from the engine: how much of it runs, and what is refused, by reason (docs/m3-engine.md 6bx).

    python3 scripts/measure_client.py ENGINE_SERVER ENGINECHECK MIGRATIONS_DIR SOURCE_FILE [soft]

MIGRATIONS_DIR: `*.sql`, applied in name order, a statement at a time, as simple queries. SOURCE_FILE: a program's source; every string in it that begins
`select`, `insert`, `update`, `delete` or `with` is taken for a statement and sent by the extended protocol with `1` bound to each parameter (a value a
column of numbers and one of text both take). `soft`: the migrations with their CHECKs and REFERENCES taken out and `bigserial` written as an identity
column, to see what is refused past them.

It prints counts by refusal, and with EX=n in the environment the first n statements of each. **The statements are the client's, which may be private:
nothing of them is written anywhere by this script, and its output is not to be committed.** The counts are what a document quotes.
"""
import collections
import glob
import os
import re
import sys
import tempfile

SERVER, HARNESS, MIGRATIONS, SOURCE = sys.argv[1:5]
SOFT = len(sys.argv) > 5
sys.argv = [sys.argv[0], SERVER, HARNESS, "10", "1"]
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))
import engine_wire as ew  # noqa: E402


def split(sql):
    """The statements of a file: split at `;` outside strings, comments gone."""
    text = "\n".join(re.sub(r"--.*$", "", line) for line in sql.split("\n"))
    out, cur, quoted = [], "", False
    for ch in text:
        if ch == "'":
            quoted = not quoted
        if ch == ";" and not quoted:
            if cur.strip():
                out.append(" ".join(cur.split()))
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(" ".join(cur.split()))
    return out


def soften(s):
    out, i = "", 0
    while i < len(s):
        m = re.match(r"check\s*\(", s[i:], re.I)
        if m and (i == 0 or not s[i - 1].isalnum()):
            j, depth = i + m.end(), 1
            while depth > 0:
                depth += {"(": 1, ")": -1}.get(s[j], 0)
                j += 1
            i = j
            continue
        out += s[i]
        i += 1
    s = re.sub(r"\breferences\s+\w+\s*\(\s*\w+\s*\)(\s+on delete \w+( \w+)?)?", "", out, flags=re.I)
    s = re.sub(r"\bbigserial\b", "bigint generated always as identity", s, flags=re.I)
    s = re.sub(r",\s*,", ",", s)
    return " ".join(re.sub(r",\s*\)", ")", s).split())


def main():
    migrations = [soften(s) if SOFT else s for f in sorted(glob.glob(os.path.join(MIGRATIONS, "*.sql"))) for s in split(open(f).read())]
    queries, seen = [], set()
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', open(SOURCE).read()):
        s = " ".join(m.group(1).replace('\\"', '"').replace("\\n", " ").split())
        if re.match(r"(select|insert|update|delete|with)\b", s, re.I) and len(s) > 12 and s not in seen:
            seen.add(s)
            queries.append(s)
    tally, shown = collections.Counter(), collections.defaultdict(list)

    def note(kind, sql, ans):
        k = "ok" if ans[0] is None else "%s %s" % (ans[0], (ans[1] or "").replace("cancho-db: ", ""))
        tally[(kind, k)] += 1
        if k != "ok" and len(shown[(kind, k)]) < int(os.environ.get("EX", "0")):
            shown[(kind, k)].append(sql[:170])

    with tempfile.TemporaryDirectory() as d:
        srv = ew.Server(os.path.join(d, "client.db"), key=False)
        c = ew.Client(srv.port)
        for s in migrations:
            note("migration", s, c.query(s))
        for s in queries:
            n = max([int(x) for x in re.findall(r"\$(\d+)", s)] or [0])
            note("query", s, c.extended(s, ["1"] * n) if n else c.query(s))
            if c.status != "I":
                c.query("rollback")
        c.close()
        srv.stop()
    for kind, total in (("migration", len(migrations)), ("query", len(queries))):
        print("%s: %d of %d run" % (kind, tally[(kind, "ok")], total))
    for (kind, k), n in sorted(tally.items(), key=lambda x: (x[0][0], -x[1])):
        if k != "ok":
            print("  %-9s %4d  %s" % (kind, n, k))
            for e in shown[(kind, k)]:
                print("                 ", e)


if __name__ == "__main__":
    main()
