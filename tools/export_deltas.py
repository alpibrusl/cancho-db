#!/usr/bin/env python3
"""Export the delta store of docs/spec/l3a.md section 2 from a database the proxy has run against.

    python3 tools/export_deltas.py OUTPUT_FILE [psql arguments ...]

for example `python3 tools/export_deltas.py deltas.tsv -h 127.0.0.1 -p 5432 -U postgres -d mydb`. Only the rows that carry a commit's id are exported (a row of a transaction that is still open, or that was rolled back
and so is gone, has none).
"""
import subprocess
import sys

SQL = ("select d.seq, encode(d.commit_id, 'hex'), d.sch, encode(convert_to(d.tbl, 'UTF8'), 'hex'), encode(d.pk, 'hex'), coalesce(encode(d.old_hash, 'hex'), ''), coalesce(encode(d.new_hash, 'hex'), ''), "
       "coalesce(encode(convert_to(d.old_row::text, 'UTF8'), 'hex'), ''), coalesce(encode(convert_to(d.new_row::text, 'UTF8'), 'hex'), '') "
       "from cdb.delta d where d.commit_id is not null order by d.seq")


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    r = subprocess.run(["psql"] + argv[2:] + ["-At", "-F", "\t", "-q", "-c", SQL], capture_output=True, text=True)
    if r.returncode != 0:
        print("export_deltas: psql failed: " + r.stderr.strip(), file=sys.stderr)
        return 2
    with open(argv[1], "w", encoding="utf-8") as f:
        f.write("CHODBDL1\n" + r.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
