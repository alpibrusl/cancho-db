#!/usr/bin/env python3
"""The golden cases for docs/spec/l3a.md, written to tests/l3a/ (NAME.log, NAME.deltas, NAME.base, NAME.expect, NAME.args).

    python3 tools/gen_l3a.py            writes them
    python3 tools/gen_l3a.py --check    fails if the files on disk are not what this would write

The expected line of every case is written here by hand from the spec, not computed by a verifier. The logs are built with the commit encoder of gen_vectors.py and the state reference of tools/state.py (a
commit's `changes` and `state` are right unless a case says it breaks them).
"""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import gen_vectors as g  # noqa: E402
import state as ref  # noqa: E402

OUT = ROOT / "tests" / "l3a"
W, D, C, R = 1, 2, 3, 0                        # effect kinds: write, ddl, call, read


def rowhash(image): return hashlib.sha256(b"cancho-db/row/v1\x00" + image).digest()


def img(**kw): return ("{" + ", ".join('"%s": %s' % (k, ('"%s"' % v) if isinstance(v, str) else v) for k, v in kw.items()) + "}").encode()


def key(*vals): return ("[" + ", ".join(('"%s"' % v) if isinstance(v, str) else str(v) for v in vals) + "]").encode()


def net(changes):
    """The facts of a commit's raw changes [(table, key, old image, new image)] in the order they happened: netted by (table, key), ordered."""
    per = {}
    for t, k, o, n in changes:
        oh, nh = (rowhash(o) if o is not None else None), (rowhash(n) if n is not None else None)
        if (t, k) not in per:
            per[(t, k)] = [oh, nh]
        else:
            per[(t, k)][1] = nh
    out = []
    for (t, k), (oh, nh) in sorted(per.items()):
        if oh == nh:
            continue
        out.append((0 if oh is None else 2 if nh is None else 1, t, k, oh, nh))
    return out


class World:
    def __init__(self, first="main"):
        self.chain = g.Chain()
        self.first = first
        self.rows = []          # delta rows as dicts
        self.seq = 0
        self.state = {}         # commit id -> state
        self.ids = []           # commit ids in log order
        self.branch_of = {}
        self.live = {}          # branch -> {(table, key): image}: what the tables hold after the commits so far, tracked here by applying each commit's changes

    def schema(self, branch): return "public" if branch == self.first else "cdb_b_" + branch

    def commit(self, branch, changes=(), parents=None, effects=(W,), changes_override=None, state_override=None, row_schema=None, parent_ids_for_state=None, tamper_rows=None):
        """One commit; `changes` [(table, key, old image, new image)] become its delta rows, in that order. Returns its id."""
        facts = net(changes)
        ch = ref.changes(facts)[1]
        if changes_override is not None:
            ch = changes_override
        b = branch.encode()
        if parents is None:
            parents = [self.chain.tip[b]] if b in self.chain.tip else []
        st_parents = parent_ids_for_state if parent_ids_for_state is not None else parents
        st = ref.state([self.state[p] for p in st_parents], ref.changes(facts)[1])
        if state_override is not None:
            st = state_override
        enc = self.chain.add(branch, parents=parents, effects=[g.effect(e, b"x") for e in effects], changes=ch, state=st)
        cid = g.cid(enc)
        self.state[cid] = st
        self.ids.append(cid)
        self.branch_of[cid] = branch
        if branch not in self.live:
            self.live[branch] = dict(self.live[self.branch_of[parents[0]]]) if parents else {}
        for t, k, o, n in changes:
            if n is None:
                self.live[branch].pop((t, k), None)
            else:
                self.live[branch][(t, k)] = n
        for t, k, o, n in changes:
            self.seq += 1
            self.rows.append(dict(seq=self.seq, commit=cid, schema=row_schema or self.schema(branch), table=t, key=k,
                                  old_image=o, new_image=n))
        return cid

    def log_bytes(self): return g.log(*[g.record(e) for e in self.chain.encs])

    def live_text(self, drop=None, add=None, twice=None, rewrite=None):
        """The rows the tables hold (section 3b), from the tracking above; `drop` removes the n-th line, `add` appends lines, `twice` repeats the n-th, `rewrite` maps (schema, table, key, image) to another."""
        lines = []
        for b in sorted(self.live):
            for (t, k), im in sorted(self.live[b].items()):
                row = (self.schema(b), t, k, im)
                if rewrite:
                    row = rewrite(row)
                lines.append("\t".join([row[0], row[1].hex(), row[2].hex(), row[3].hex()]))
        if drop is not None:
            del lines[drop]
        if twice is not None:
            lines.append(lines[twice])
        lines += add or []
        return "CHODBLV1\n" + "".join(l + "\n" for l in lines)

    def deltas_text(self, order=None, mutate=None):
        lines = ["CHODBDL1"]
        rows = list(self.rows)
        if order == "reverse":
            rows.reverse()
        for r in rows:
            f = [str(r["seq"]), r["commit"].hex(), r["schema"], r["table"].hex(), r["key"].hex(),
                 rowhash(r["old_image"]).hex() if r["old_image"] is not None else "", rowhash(r["new_image"]).hex() if r["new_image"] is not None else "",
                 r["old_image"].hex() if r["old_image"] is not None else "", r["new_image"].hex() if r["new_image"] is not None else ""]
            if mutate:
                f = mutate(r, f)
            lines.append("\t".join(f))
        return "\n".join(lines) + "\n"


CASES = {}   # name -> (log bytes, deltas text, base text or None, expect, extra args, live dump text or None)


def case(name, world, expect, deltas=None, base=None, args="", log=None, live=None):
    CASES[name] = (log if log is not None else world.log_bytes(), deltas if deltas is not None else world.deltas_text(), base, expect, args, live)


def ok(commits, facts, branches): return "ok commits=%d facts=%d branches=%d" % (commits, facts, branches)


def reject(rule, rec): return "reject rule=%s record=%d" % (rule, rec)


A = {"t": b"accounts", "u": b"users"}
k1, k2, k3, k4 = key(1), key(2), key(3), key(4)

# ------------------------------------------------------------------ valid
w = World()
case("ok_empty", w, ok(0, 0, 0))

w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
case("ok_insert", w, ok(1, 1, 1))

w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
w.commit("main", [(A["t"], k1, img(id=1, v="a"), img(id=1, v="b"))])
w.commit("main", [(A["t"], k1, img(id=1, v="b"), None)])
case("ok_insert_update_delete", w, ok(3, 3, 1))

# the netting rule: an insert then an update is an insert of the last image; an insert then a delete, and an update then its undoing, are no fact; a delete then an insert of one key is an update
w = World()
w.commit("main", [(A["t"], k3, None, img(id=3, v="x")), (A["t"], k4, None, img(id=4, v="z"))])
w.commit("main", [(A["t"], k1, None, img(id=1, v="a")), (A["t"], k1, img(id=1, v="a"), img(id=1, v="b")),
                  (A["t"], k2, None, img(id=2, v="q")), (A["t"], k2, img(id=2, v="q"), None),
                  (A["t"], k3, img(id=3, v="x"), img(id=3, v="y")), (A["t"], k3, img(id=3, v="y"), img(id=3, v="x")),
                  (A["t"], k4, img(id=4, v="z"), None), (A["t"], k4, None, img(id=4, v="w"))])
case("ok_netting", w, ok(2, 4, 1))
case("ok_netting_file_order_is_free", w, ok(2, 4, 1), deltas=w.deltas_text(order="reverse"))

w = World()
w.commit("main", [(A["u"], k2, None, img(id=2)), (A["t"], k1, None, img(id=1)), (A["u"], k1, None, img(id=1))])
case("ok_tables_in_any_order", w, ok(1, 3, 1))
case("ok_file_order_is_free", w, ok(1, 3, 1), deltas=w.deltas_text(order="reverse"))

w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
w.commit("main", [], effects=(R,))
w.commit("main", [], effects=(D,))
w.commit("main", [(A["t"], k1, img(id=1, v="a"), img(id=1, v="b"))])
case("ok_reads_and_ddl_have_no_rows", w, ok(4, 2, 1))

w = World()
f0 = w.commit("main", [(A["t"], k1, None, img(id=1, v="m"))])
fk = w.commit("side", [], parents=[f0], effects=(C,))
w.commit("side", [(A["t"], k1, img(id=1, v="m"), img(id=1, v="s"))])
w.commit("main", [(A["t"], k1, img(id=1, v="m"), img(id=1, v="m2"))])
case("ok_fork", w, ok(4, 3, 2))

w = World()
f0 = w.commit("main", [(A["t"], k1, None, img(id=1, v="m"))])
w.commit("side", [], parents=[f0], effects=(C,))
w.commit("side", [(A["t"], k3, None, img(id=3, v="s"))])
w.commit("main", [(A["t"], k2, None, img(id=2, v="m"))])
w.commit("main", [(A["t"], k3, None, img(id=3, v="s"))], parents=[w.chain.tip[b"main"], w.chain.tip[b"side"]], effects=(C,))
w.commit("side", [(A["t"], k4, None, img(id=4, v="s"))])
case("ok_merge", w, ok(6, 5, 2))

w = World()
w.commit("main", [(A["t"], k1, img(id=1, v="a"), img(id=1, v="a2")), (A["t"], k2, img(id=2, v="b"), None)])
base = "CHODBBS1\n" + "\n".join("\t".join([A["t"].hex(), k.hex(), im.hex()]) for k, im in ((k1, img(id=1, v="a")), (k2, img(id=2, v="b")))) + "\n"
case("ok_base", w, ok(1, 2, 1), base=base, args="--base")

w = World(first="trunk")
w.commit("trunk", [(A["t"], k1, None, img(id=1))])
case("ok_first_branch_named", w, ok(1, 1, 1), args="--first-branch trunk")

# ------------------------------------------------------------------ the store is not well formed
def one_insert():
    w = World()
    w.commit("main", [(A["t"], k1, None, img(id=1, v="a")), (A["t"], k2, None, img(id=2, v="b"))])
    return w


w = one_insert()
case("bad_store_magic", w, reject("store-malformed", -1), deltas=w.deltas_text().replace("CHODBDL1", "CHODBDL2", 1))
first_row = w.deltas_text().split("\n")[1].split("\t")
case("bad_store_eight_fields", w, reject("store-malformed", -1), deltas="CHODBDL1\n" + "\t".join(first_row[:8]) + "\n")
case("bad_store_odd_hex", w, reject("store-malformed", -1), deltas=w.deltas_text(mutate=lambda r, f: f[:4] + [f[4] + "0"] + f[5:] if r["seq"] == 1 else f))
case("bad_store_upper_hex", w, reject("store-malformed", -1), deltas=w.deltas_text(mutate=lambda r, f: f[:3] + [f[3].upper()] + f[4:] if r["seq"] == 1 else f))
case("bad_store_short_hash", w, reject("store-malformed", -1), deltas=w.deltas_text(mutate=lambda r, f: f[:6] + [f[6][:-2]] + f[7:] if r["seq"] == 1 else f))
case("bad_store_repeated_seq", w, reject("store-malformed", -1), deltas=w.deltas_text(mutate=lambda r, f: ["1"] + f[1:]))
case("bad_store_no_hash", w, reject("store-malformed", -1), deltas=w.deltas_text(mutate=lambda r, f: f[:5] + ["", "", "", ""] if r["seq"] == 1 else f))
case("bad_store_seq_leading_zero", w, reject("store-malformed", -1), deltas=w.deltas_text(mutate=lambda r, f: ["0" + f[0]] + f[1:] if r["seq"] == 2 else f))
case("bad_base_magic", w, reject("store-malformed", -1), base="CHODBBS2\n", args="--base")

# ------------------------------------------------------------------ rows that do not belong
w = one_insert()
case("foreign_row_unknown_commit", w, reject("store-foreign-row", -1), deltas=w.deltas_text().rstrip("\n") + "\n" + "\t".join(["9", "ab" * 32, "public", A["t"].hex(), k3.hex(), "", rowhash(b"x").hex(), "", b"x".hex()]) + "\n")
case("foreign_row_wrong_schema", w, reject("store-foreign-row", 0), deltas=w.deltas_text(mutate=lambda r, f: f[:2] + ["cdb_b_other"] + f[3:] if r["seq"] == 2 else f))
w = World()
w.commit("main", [(A["t"], k1, None, img(id=1))], effects=(R,))
case("foreign_row_on_a_read", w, reject("store-foreign-row", 0))

# ------------------------------------------------------------------ images
w = one_insert()
case("image_not_its_hash", w, reject("facts-image", 0), deltas=w.deltas_text(mutate=lambda r, f: f[:8] + [img(id=1, v="evil").hex()] if r["seq"] == 1 else f))
case("image_missing", w, reject("facts-image", 0), deltas=w.deltas_text(mutate=lambda r, f: f[:8] + [""] if r["seq"] == 1 else f))
case("image_without_hash", w, reject("facts-image", 0), deltas=w.deltas_text(mutate=lambda r, f: f[:7] + [img(id=9).hex(), f[8]] if r["seq"] == 1 else f))

# ------------------------------------------------------------------ changes and state
w = one_insert()
evil = img(id=1, v="changed")
case("changes_row_changed_consistently", w, reject("changes-mismatch", 0),
     deltas=w.deltas_text(mutate=lambda r, f: f[:6] + [rowhash(evil).hex(), f[7], evil.hex()] if r["seq"] == 1 else f))
lines = w.deltas_text().split("\n")
case("changes_row_dropped", w, reject("changes-mismatch", 0), deltas="\n".join([lines[0], lines[2], ""]))
case("changes_row_added", w, reject("changes-mismatch", 0),
     deltas=w.deltas_text().rstrip("\n") + "\n" + "\t".join(["9", w.ids[0].hex(), "public", A["t"].hex(), k3.hex(), "", rowhash(b"{}").hex(), "", b"{}".hex()]) + "\n")
w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
w.commit("main", [(A["t"], k1, img(id=1, v="a"), img(id=1, v="b"))], state_override=hashlib.sha256(b"not the state").digest())
case("state_wrong", w, reject("state-mismatch", 1))
w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
w.commit("main", [(A["t"], k1, img(id=1, v="a"), img(id=1, v="b"))], changes_override=hashlib.sha256(b"x").digest(), state_override=hashlib.sha256(b"y").digest())
case("changes_before_state", w, reject("changes-mismatch", 1))
w = World()
f0 = w.commit("main", [(A["t"], k1, None, img(id=1, v="m"))])
w.commit("side", [], parents=[f0], effects=(C,))
w.commit("side", [(A["t"], k3, None, img(id=3, v="s"))])
w.commit("main", [(A["t"], k2, None, img(id=2, v="m"))])
tm, ts = w.chain.tip[b"main"], w.chain.tip[b"side"]
w.commit("main", [(A["t"], k3, None, img(id=3, v="s"))], parents=[tm, ts], parent_ids_for_state=[ts, tm], effects=(C,))
case("state_parents_in_the_wrong_order", w, reject("state-mismatch", 4))

# ------------------------------------------------------------------ the replay
w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
w.commit("main", [(A["t"], k1, img(id=1, v="zz"), img(id=1, v="b"))])
case("replay_update_from_another_image", w, reject("replay-precondition", 1))
w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
w.commit("main", [(A["t"], k1, None, img(id=1, v="a2"))])
case("replay_insert_of_a_present_key", w, reject("replay-precondition", 1))
w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
w.commit("main", [(A["t"], k2, img(id=2, v="b"), None)])
case("replay_delete_of_an_absent_key", w, reject("replay-precondition", 1))
w = World()
w.commit("main", [(A["t"], k1, img(id=1, v="a"), img(id=1, v="a2"))])
case("replay_update_without_a_base", w, reject("replay-precondition", 0))
w = World()
w.commit("main", [(A["t"], k1, img(id=1, v="a"), img(id=1, v="a2"))])
case("replay_base_with_another_image", w, reject("replay-precondition", 0), base="CHODBBS1\n" + "\t".join([A["t"].hex(), k1.hex(), img(id=1, v="other").hex()]) + "\n", args="--base")
w = World()
f0 = w.commit("main", [(A["t"], k1, None, img(id=1, v="m"))])
w.commit("main", [(A["t"], k2, None, img(id=2, v="m"))])
w.commit("side", [], parents=[f0], effects=(C,))
case("replay_fork_from_an_older_commit", w, reject("replay-unsupported", 2))
w = World()
f0 = w.commit("main", [(A["t"], k1, None, img(id=1, v="m"))])
w.commit("side", [], parents=[f0], effects=(C,))
w.commit("side", [(A["t"], k1, img(id=1, v="m"), None)])
w.commit("main", [(A["t"], k1, img(id=1, v="m"), img(id=1, v="m2"))])
w.commit("side", [(A["t"], k1, None, img(id=1, v="again"))])
case("ok_branches_do_not_share_rows", w, ok(5, 4, 2))
w = World()
f0 = w.commit("main", [(A["t"], k1, None, img(id=1, v="m"))])
w.commit("side", [], parents=[f0], effects=(C,))
w.commit("main", [(A["t"], k1, img(id=1, v="m"), None)])
w.commit("side", [(A["t"], k1, None, img(id=1, v="x"))])
case("replay_a_fork_copies_the_row", w, reject("replay-precondition", 3))


# ------------------------------------------------------------------ the final comparison (section 3b and step 7)
w = World()
case("ok_live_empty", w, "ok commits=0 facts=0 branches=0 final", live="CHODBLV1\n", args="--live-dump")

w = World()
f0 = w.commit("main", [(A["t"], k1, None, img(id=1, v="m")), (A["u"], k1, None, img(id=1, name="u"))])
w.commit("side", [], parents=[f0], effects=(C,))
w.commit("side", [(A["t"], k2, None, img(id=2, v="s")), (A["t"], k1, img(id=1, v="m"), None)])
w.commit("main", [(A["t"], k1, img(id=1, v="m"), img(id=1, v="m2"))])
case("ok_live", w, ok(4, 5, 2) + " final", live=w.live_text(), args="--live-dump")
case("live_row_missing", w, reject("replay-final", -1), live=w.live_text(drop=0), args="--live-dump")
case("live_row_extra", w, reject("replay-final", -1), live=w.live_text(add=["\t".join(["public", A["t"].hex(), k4.hex(), img(id=4).hex()])]), args="--live-dump")
case("live_image_differs", w, reject("replay-final", -1), live=w.live_text(rewrite=lambda r: (r[0], r[1], r[2], img(id=1, v="evil")) if r[2] == k1 and r[0] == "public" and r[1] == A["t"] else r), args="--live-dump")
case("live_key_twice", w, reject("replay-final", -1), live=w.live_text(twice=0), args="--live-dump")
case("live_row_in_no_branchs_schema", w, reject("replay-final", -1), live=w.live_text(add=["\t".join(["cdb_b_ghost", A["t"].hex(), k4.hex(), img(id=4).hex()])]), args="--live-dump")
case("live_row_in_the_other_branch", w, reject("replay-final", -1), live=w.live_text(rewrite=lambda r: ("cdb_b_side",) + r[1:] if r[0] == "public" and r[1] == A["t"] and r[2] == k1 else r), args="--live-dump")
case("live_everything_missing", w, reject("replay-final", -1), live="CHODBLV1\n", args="--live-dump")
case("bad_live_magic", w, reject("store-malformed", -1), live="CHODBLV2\n", args="--live-dump")
case("bad_live_three_fields", w, reject("store-malformed", -1), live="CHODBLV1\npublic\t00\t00\n", args="--live-dump")
case("bad_live_empty_schema", w, reject("store-malformed", -1), live="CHODBLV1\n\t00\t00\t00\n", args="--live-dump")
case("bad_live_odd_hex", w, reject("store-malformed", -1), live="CHODBLV1\npublic\t0\t00\t00\n", args="--live-dump")
# a replay failure comes before the live comparison is looked at
w = World()
w.commit("main", [(A["t"], k1, None, img(id=1, v="a"))])
w.commit("main", [(A["t"], k1, None, img(id=1, v="a2"))])
case("replay_before_live", w, reject("replay-precondition", 1), live="CHODBLV1\n", args="--live-dump")


def write():
    OUT.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, (logb, deltas, base, expect, args, live) in sorted(CASES.items()):
        files[name + ".log"] = logb
        files[name + ".deltas"] = deltas.encode()
        if base is not None:
            files[name + ".base"] = base.encode()
        if live is not None:
            files[name + ".live"] = live.encode()
        files[name + ".expect"] = (expect + "\n").encode()
        files[name + ".args"] = (args + "\n").encode()
    return files


def main():
    files = write()
    if "--check" in sys.argv:
        on_disk = {p.name: p.read_bytes() for p in OUT.glob("*")} if OUT.exists() else {}
        if on_disk != files:
            extra, missing = sorted(set(on_disk) - set(files)), sorted(set(files) - set(on_disk))
            diff = sorted(n for n in files if n in on_disk and files[n] != on_disk[n])
            print("l3a vectors differ from the generator: extra %s, missing %s, changed %s" % (extra[:3], missing[:3], diff[:3]))
            return 1
        print("l3a vectors reproducible: %d cases" % len(CASES))
        return 0
    for p in OUT.glob("*"):
        p.unlink()
    for n, b in files.items():
        (OUT / n).write_bytes(b)
    print("wrote %d cases to %s" % (len(CASES), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
