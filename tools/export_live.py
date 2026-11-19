#!/usr/bin/env python3
"""Export the rows a database holds, for the final comparison of docs/spec/l3a.md (section 3b), without a connection at verification time.

    python3 tools/export_live.py OUTPUT_FILE SCHEMA... -- [psql arguments ...]

for example `python3 tools/export_live.py live.tsv public cdb_b_side -- -h 127.0.0.1 -p 5432 -U postgres -d mydb`: every table with a primary key in each named schema, one line a row.
"""
import subprocess
import sys


def main(argv):
    if len(argv) < 4 or "--" not in argv:
        print(__doc__, file=sys.stderr)
        return 2
    cut = argv.index("--")
    out, schemas, psql = argv[1], argv[2:cut], argv[cut + 1:]

    def q(sql):
        r = subprocess.run(["psql"] + psql + ["-At", "-F", "\t", "-q", "-c", sql], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("export_live: psql failed: " + r.stderr.strip())
        return [line.split("\t") for line in r.stdout.split("\n") if line]
    lines = ["CHODBLV1"]
    for sch in schemas:
        for (t,) in q("select c.relname from pg_class c join pg_namespace s on s.oid = c.relnamespace where s.nspname = '%s' and c.relkind = 'r' order by 1" % sch):
            cols = [c[0] for c in q("select a.attname from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any (i.indkey) where i.indrelid = '%s.\\"%s\\"'::regclass and i.indisprimary order by array_position(i.indkey::int2[], a.attnum)" % (sch, t))]
            if not cols:
                continue
            key = "jsonb_build_array(%s)::text" % ", ".join('r."%s"' % c for c in cols)
            for k, im in q("select encode(convert_to(%s, 'UTF8'), 'hex'), encode(convert_to(to_jsonb(r)::text, 'UTF8'), 'hex') from \"%s\".\"%s\" r" % (key, sch, t)):
                lines.append("\t".join([sch, t.encode().hex(), k, im]))
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
