#!/usr/bin/env python3
"""L3a, delta replay (docs/spec/l3a.md): are `changes` and `state` what the stored row changes give, do the row changes fit together, and do the tables hold what they say?

    python3 tools/l3a.py LOG --deltas FILE [--base FILE] [--first-branch NAME] [--live-dump FILE | --live "psql args"]

`--live-dump` is a file of the rows the database holds (docs/spec/l3a.md section 3b, `tools/export_live.py`); `--live` is the arguments for `psql` that reach the database whose tables are compared (for example
`-h 127.0.0.1 -p 5432 -U postgres -d mydb`) and builds the same rows itself.
Output as L1's and L2's: `ok commits=N facts=M branches=B [final]` or `reject rule=TAG record=INDEX`; exit 0, 1, or 2 (a usage error or a file that cannot be read).

Written from the specification (l3a.md, state.md, commit.md); the Merkle root and the state chain are tools/state.py's, which was written from state.md. The log is read by this file's own minimal reader of commit.md
(no signatures are checked: L3a presupposes that L1 passed).
"""
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import state as ref  # noqa: E402

DOMAIN = b"cancho-db/commit/v1\x00"
ROWTAG = b"cancho-db/row/v1\x00"
ROWTAG2 = b"cancho-db/row/v2\x00"      # version 2 of the delta store: the row hash has a salt (l3a.md section 9)
KEYTAG = b"cancho-db/key/v1\x00"       # and the key is a commitment to the key and its salt


class Reject(Exception):
    def __init__(self, rule, record=-1):
        super().__init__(rule)
        self.rule, self.record = rule, record


def hash_image(image, salt=None):
    if salt is None:
        return hashlib.sha256(ROWTAG + image).digest()
    return hashlib.sha256(ROWTAG2 + salt + image).digest()


def key_commit(plain, salt):
    return hashlib.sha256(KEYTAG + salt + plain).digest()


def read_log(path):
    """[(id, branch, parents, effect kinds, changes, state)] in log order."""
    data = Path(path).read_bytes()
    if len(data) < 40 or data[:8] != b"CHODBLG1":
        raise Reject("log-malformed")
    at, out = 40, []
    try:
        while at < len(data):
            (n,) = struct.unpack(">I", data[at:at + 4])
            enc = data[at + 4:at + 4 + n]
            if len(enc) != n or at + 4 + n + 64 > len(data):
                raise Reject("log-malformed", len(out))
            at += 4 + n + 64
            o = 2
            (np_,) = struct.unpack(">I", enc[o:o + 4]); o += 4
            if np_ > len(enc):
                raise Reject("log-malformed", len(out))
            parents = [enc[o + 32 * i:o + 32 * i + 32] for i in range(np_)]; o += 32 * np_
            (bl,) = struct.unpack(">H", enc[o:o + 2]); o += 2
            branch = enc[o:o + bl].decode("latin-1"); o += bl
            o += 8 + 32                                           # seq, schema
            (ns,) = struct.unpack(">I", enc[o:o + 4]); o += 4 + 32 * ns
            (ne,) = struct.unpack(">I", enc[o:o + 4]); o += 4
            if ne > len(enc):
                raise Reject("log-malformed", len(out))
            kinds = []
            for _ in range(ne):
                kinds.append(enc[o])
                (ln,) = struct.unpack(">H", enc[o + 1:o + 3]); o += 3 + ln
            o += 32 + 32                                          # token, principal
            (nc,) = struct.unpack(">I", enc[o:o + 4]); o += 4 + 32 * nc
            (nn,) = struct.unpack(">I", enc[o:o + 4]); o += 4
            if nn > len(enc):
                raise Reject("log-malformed", len(out))
            for _ in range(nn):
                tag = enc[o]; o += 1
                if tag == 1:
                    o += 8
                elif tag == 2:
                    (ln,) = struct.unpack(">I", enc[o:o + 4]); o += 4 + ln
            changes, state = enc[o:o + 32], enc[o + 32:o + 64]
            if len(state) != 32:
                raise Reject("log-malformed", len(out))
            out.append((hashlib.sha256(DOMAIN + enc).digest(), branch, parents, kinds, changes, state))
    except (struct.error, UnicodeDecodeError, IndexError):
        raise Reject("log-malformed", len(out))
    return out


def hexb(text, what, nbytes=None, allow_empty=False):
    if text == "" and allow_empty:
        return None
    if len(text) % 2 or any(c not in "0123456789abcdef" for c in text) or text == "":
        raise Reject("store-malformed")
    b = bytes.fromhex(text)
    if nbytes is not None and len(b) != nbytes:
        raise Reject("store-malformed")
    return b


def read_text_lines(path):
    """The lines of a text file as the spec splits them. The bytes are kept as they are (latin-1 maps each to one character): a schema name is compared as bytes, and nothing else in the files is not ASCII."""
    data = Path(path).read_bytes().decode("latin-1")
    if data and not data.endswith("\n"):
        raise Reject("store-malformed")                      # every line, the last too, ends with a newline (l3a.md section 2)
    return data.split("\n")


def read_deltas(path):
    lines = read_text_lines(path)
    if lines[-1] == "":
        lines.pop()
    if not lines or lines[0] not in ("CHODBDL1", "CHODBDL2"):
        raise Reject("store-malformed")
    version = 1 if lines[0] == "CHODBDL1" else 2
    rows, seen = [], set()
    for line in lines[1:]:
        f = line.split("\t")
        if len(f) != (9 if version == 1 else 13):
            raise Reject("store-malformed")
        if not (f[0].isascii() and f[0].isdigit()) or (len(f[0]) > 1 and f[0][0] == "0") or int(f[0]) in seen:
            raise Reject("store-malformed")
        seen.add(int(f[0]))
        if f[2] == "" or any(c in f[2] for c in "\t\n"):
            raise Reject("store-malformed")
        row = dict(seq=int(f[0]), commit=hexb(f[1], "commit", 32), schema=f[2], table=hexb(f[3], "table"), key=hexb(f[4], "key", 32 if version == 2 else None),
                   old_hash=hexb(f[5], "old_hash", 32, True), new_hash=hexb(f[6], "new_hash", 32, True),
                   old_image=hexb(f[7], "old_image", None, True), new_image=hexb(f[8], "new_image", None, True))
        if version == 2:
            row.update(old_salt=hexb(f[9], "salt", 16, True), new_salt=hexb(f[10], "salt", 16, True), key_plain=hexb(f[11], "key", None, True), key_salt=hexb(f[12], "salt", 16, True))
        else:
            row.update(old_salt=None, new_salt=None, key_plain=None, key_salt=None)
        if row["old_hash"] is None and row["new_hash"] is None:
            raise Reject("store-malformed")
        rows.append(row)
    return version, rows


def read_base(path, version=1):
    lines = read_text_lines(path)
    if lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != "CHODBBS%d" % version:
        raise Reject("store-malformed")
    base = {}
    for line in lines[1:]:
        f = line.split("\t")
        if len(f) != (3 if version == 1 else 5):
            raise Reject("store-malformed")
        if version == 1:
            k, h = (hexb(f[0], "table"), hexb(f[1], "key")), hash_image(hexb(f[2], "image"))
        else:
            k = (hexb(f[0], "table"), key_commit(hexb(f[1], "key"), hexb(f[2], "salt", 16)))
            h = hash_image(hexb(f[3], "image"), hexb(f[4], "salt", 16))
        if k in base:
            raise Reject("store-malformed")                  # a key twice (section 3)
        base[k] = h
    return base


def read_live_dump(path, version=1):
    """Section 3b: {schema: {(table, key): hash}} with a key twice (or a line without four fields) refused as store-malformed... a key twice is replay-final, see compare."""
    lines = read_text_lines(path)
    if lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != "CHODBLV%d" % version:
        raise Reject("store-malformed")
    rows = []
    for line in lines[1:]:
        f = line.split("\t")
        if len(f) != (4 if version == 1 else 6) or f[0] == "":
            raise Reject("store-malformed")
        if version == 1:
            rows.append((f[0], hexb(f[1], "table"), hexb(f[2], "key"), hash_image(hexb(f[3], "image"))))
        else:
            rows.append((f[0], hexb(f[1], "table"), key_commit(hexb(f[2], "key"), hexb(f[3], "salt", 16)), hash_image(hexb(f[4], "image"), hexb(f[5], "salt", 16))))
    return rows


def schema_of(branch, first):
    return "public" if branch == first else "cdb_b_" + branch


def net_facts(rows):
    """Section 4: the facts of a commit from its raw changes, ordered (table, key)."""
    per = {}
    for r in sorted(rows, key=lambda r: r["seq"]):
        k = (r["table"], r["key"])
        if k not in per:
            per[k] = [r["old_hash"], r["new_hash"]]
        else:
            per[k][1] = r["new_hash"]
    facts = []
    for (t, k), (o, n) in sorted(per.items()):
        if o == n:
            continue
        facts.append((0 if o is None else 2 if n is None else 1, t, k, o, n))
    return facts


def verify(log_path, deltas_path, base_path=None, first=None, live=None, live_dump=None):
    commits = read_log(log_path)
    version, rows = read_deltas(deltas_path)
    base = read_base(base_path, version) if base_path else {}
    dump = read_live_dump(live_dump, version) if live_dump else None
    if live is not None and version == 2:
        raise SystemExit("l3a: --live reads version 1 only; use --live-dump")
    if first is None:
        first = commits[0][1] if commits else "main"
    ids = {c[0]: i for i, c in enumerate(commits)}
    by_commit = {}
    for r in rows:
        if r["commit"] not in ids:
            raise Reject("store-foreign-row", -1)
        by_commit.setdefault(r["commit"], []).append(r)
    state_of = {c[0]: c[5] for c in commits}
    maps, last, nfacts = {}, {}, 0
    for i, (cid, branch, parents, kinds, changes, state) in enumerate(commits):
        mine = by_commit.get(cid, [])
        # 1. the rows belong here
        if any(r["schema"] != schema_of(branch, first) for r in mine):
            raise Reject("store-foreign-row", i)
        if mine and not any(k in (1, 2, 3) for k in kinds):
            raise Reject("store-foreign-row", i)
        # 2. images (and, in version 2, keys)
        for r in mine:
            for side in ("old", "new"):
                h, im, sa = r[side + "_hash"], r[side + "_image"], r[side + "_salt"]
                if version == 1:
                    if (h is None) != (im is None) or (h is not None and hash_image(im) != h):
                        raise Reject("facts-image", i)
                elif h is None:
                    if im is not None or sa is not None:
                        raise Reject("facts-image", i)
                elif (im is None) != (sa is None) or (im is not None and hash_image(im, sa) != h):
                    raise Reject("facts-image", i)
        if version == 2:
            for r in mine:
                if (r["key_plain"] is None) != (r["key_salt"] is None) or (r["key_plain"] is not None and key_commit(r["key_plain"], r["key_salt"]) != r["key"]):
                    raise Reject("facts-key", i)
        # 3. changes
        facts = net_facts(mine)
        verdict = ref.run("C " + " ".join(ref.fact_text(*f) for f in facts))
        if verdict != "ok " + changes.hex():
            raise Reject("changes-mismatch", i)
        # 4. state
        if any(p not in state_of for p in parents) or ref.state([state_of[p] for p in parents], changes) != state:
            raise Reject("state-mismatch", i)
        # 5 and 6. replay
        if branch not in maps:
            if parents:
                src = commits[ids[parents[0]]][1]
                if last.get(src) != parents[0]:
                    raise Reject("replay-unsupported", i)
                maps[branch] = dict(maps[src])
            else:
                maps[branch] = dict(base) if branch == first else {}
        m = maps[branch]
        for kind, t, k, o, n in facts:
            cur = m.get((t, k))
            if kind == 0:
                if cur is not None:
                    raise Reject("replay-precondition", i)
            elif cur is None or cur != o:
                raise Reject("replay-precondition", i)
            if kind == 2:
                del m[(t, k)]
            else:
                m[(t, k)] = n
        last[branch] = cid
        nfacts += len(facts)
    suffix = ""
    if dump is not None or live is not None:
        compare_live(maps, first, dump if dump is not None else live_rows_from_psql(maps, first, live))
        suffix = " final"
    if version == 2:
        erased = sum(1 for r in rows if (r["old_hash"] is not None and r["old_image"] is None) or (r["new_hash"] is not None and r["new_image"] is None) or r["key_plain"] is None)
        suffix = " erased=%d%s" % (erased, suffix)
    return "ok commits=%d facts=%d branches=%d%s" % (len(commits), nfacts, len(maps), suffix)


def live_rows_from_psql(maps, first, psql_args):
    """The rows of section 3b read from a database: [(schema, table, key, hash)]."""
    def q(sql):
        r = subprocess.run(["psql"] + psql_args + ["-At", "-F", "\t", "-q", "-c", sql], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("l3a: psql failed: " + r.stderr.strip())
        return [line.split("\t") for line in r.stdout.split("\n") if line]
    rows = []
    for branch in maps:
        sch = schema_of(branch, first)
        for t in [t[0] for t in q("select c.relname from pg_class c join pg_namespace s on s.oid = c.relnamespace where s.nspname = '%s' and c.relkind = 'r' order by 1" % sch)]:
            cols = [c[0] for c in q("select a.attname from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any (i.indkey) where i.indrelid = '%s.%s'::regclass and i.indisprimary order by array_position(i.indkey::int2[], a.attnum)" % (sch, '"%s"' % t))]
            if not cols:
                continue
            key = "jsonb_build_array(%s)::text" % ", ".join('r."%s"' % c for c in cols)
            for k, im in q("select encode(convert_to(%s, 'UTF8'), 'hex'), encode(convert_to(to_jsonb(r)::text, 'UTF8'), 'hex') from \"%s\".\"%s\" r" % (key, sch, t)):
                rows.append((sch, t.encode(), bytes.fromhex(k), hash_image(bytes.fromhex(im))))
    return rows


def compare_live(maps, first, rows):
    """Step 7: the rows of each branch's schema are exactly the entries of its map."""
    by_schema = {schema_of(b, first): b for b in maps}
    seen = {b: {} for b in maps}
    for sch, t, k, h in rows:
        b = by_schema.get(sch)
        if b is None or (t, k) in seen[b]:
            raise Reject("replay-final", -1)
        seen[b][(t, k)] = h
    for b, m in maps.items():
        if seen[b] != m:
            raise Reject("replay-final", -1)


def main(argv):
    args, opts = [], {}
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("--deltas", "--base", "--first-branch", "--live", "--live-dump"):
            if i + 1 >= len(argv):
                print("usage: l3a.py LOG --deltas FILE [--base FILE] [--first-branch NAME] [--live-dump FILE | --live 'psql args']", file=sys.stderr)
                return 2
            opts[a] = argv[i + 1]
            i += 2
        else:
            args.append(a)
            i += 1
    if len(args) != 1 or "--deltas" not in opts:
        print("usage: l3a.py LOG --deltas FILE [--base FILE] [--first-branch NAME] [--live-dump FILE | --live 'psql args']", file=sys.stderr)
        return 2
    try:
        print(verify(args[0], opts["--deltas"], opts.get("--base"), opts.get("--first-branch"), opts["--live"].split() if "--live" in opts else None, opts.get("--live-dump")))
        return 0
    except Reject as e:
        print("reject rule=%s record=%d" % (e.rule, e.record))
        return 1
    except OSError as e:
        print("l3a: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
