#!/usr/bin/env python3
"""The copy-on-write B+tree (src/btree.cho, docs/m3-engine.md slice M3a) against a model: a sorted dict for each of the 16 slots.

    python3 tests/btree_check.py build/btcheck [SEED_COUNT]

`proxy/btcheck.cho` runs the tree on a page file and answers one line a command. For each seed a random script of puts, deletes, gets, ordered scans (`next`) and forks (a slot made the same tree as another, so that the
old root must stay whole while the other changes) is run, with keys and values of every size the tree takes (1 to 200 and 0 to 800 bytes), and every answer is compared with the model's. Every so often a whole slot is scanned in
order and equals the model's sorted keys. Also: a tree of more than 60,000 small entries (three levels); a page of the file with a bit flipped is refused by its CRC (`err 102`), never read as data; a key or value
that is too long is refused; a delete of every key leaves the empty tree.
"""
import os
import random
import subprocess
import sys
import tempfile

EXE = sys.argv[1]
SEEDS = int(sys.argv[2]) if len(sys.argv) > 2 else 12
FAILED = []


def check(name, ok, detail=""):
    if not ok:
        print("FAIL %s   %s" % (name, str(detail)[:300]))
        FAILED.append(name)


def run(path, lines, extra=()):
    r = subprocess.run([EXE, path] + [str(x) for x in extra], input="\n".join(lines) + "\n", capture_output=True, text=True)
    return r.stdout.split("\n")[:len(lines)], r.returncode


class Model:
    def __init__(self):
        self.slots = [dict() for _ in range(16)]

    def next_after(self, s, key, incl):
        ks = sorted(k for k in self.slots[s] if (k >= key if incl else k > key))
        return ks[0] if ks else None


def rand_key(rng, alphabet):
    return bytes(rng.choice(alphabet) for _ in range(rng.choice([1, 1, 2, 3, 5, 8, 20, 60, 200])))


def rand_val(rng):
    return os.urandom(rng.choice([0, 1, 4, 16, 64, 200, 500, 800]))


def script(seed, n):
    """(lines, expected): expected[i] is the answer's required prefix, or None where only `ok` is checked."""
    rng = random.Random(seed)
    m = Model()
    lines, want = [], []
    alphabet = rng.choice([b"ab", b"abcdefgh", bytes(range(256))])
    keys = [rand_key(rng, alphabet) for _ in range(rng.choice([30, 200, 2000]))]
    for _ in range(n):
        op = rng.random()
        s = rng.randrange(4)
        if op < 0.45:
            k, v = rng.choice(keys), rand_val(rng)
            lines.append("put %d %s %s" % (s, k.hex(), v.hex() or "-"))
            want.append("ok")
            m.slots[s][k] = v
        elif op < 0.60:
            k = rng.choice(keys)
            lines.append("del %d %s" % (s, k.hex()))
            if k in m.slots[s]:
                want.append("ok")
                del m.slots[s][k]
            else:
                want.append("none")
        elif op < 0.78:
            k = rng.choice(keys)
            lines.append("get %d %s" % (s, k.hex()))
            want.append("val " + m.slots[s][k].hex() if k in m.slots[s] else "none")
        elif op < 0.92:
            k, incl = (rng.choice(keys) if rng.random() < .9 else b""), rng.randrange(2)
            lines.append("next %d %s %d" % (s, k.hex() or "-", incl))
            nk = m.next_after(s, k, incl)
            want.append("none" if nk is None else "kv %s %s" % (nk.hex(), m.slots[s][nk].hex()))
        else:
            t = rng.randrange(4)
            lines.append("fork %d %d" % (s, t))
            want.append("ok")
            m.slots[t] = dict(m.slots[s])
    return lines, want, m


def main():
    for seed in range(SEEDS):
        n = [400, 1500, 4000][seed % 3]
        lines, want, m = script(seed, n)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pages")
            # the scans: after the script, every slot's keys in order, asked for by the model's own keys
            tail, tail_want = [], []
            for s in range(4):
                keys = sorted(m.slots[s])
                tail.append("next %d - 1" % s)
                tail_want.append("none" if not keys else "kv %s %s" % (keys[0].hex(), m.slots[s][keys[0]].hex()))
                for a, b in zip(keys, keys[1:]):
                    tail.append("next %d %s 0" % (s, a.hex()))
                    tail_want.append("kv %s %s" % (b.hex(), m.slots[s][b].hex()))
                if keys:
                    tail.append("next %d %s 0" % (s, keys[-1].hex()))
                    tail_want.append("none")
            out, rc = run(path, lines + tail)
            check("seed %d: the process ends well" % seed, rc == 0, rc)
            bad = [(i, a, w) for i, (a, w) in enumerate(zip(out, want + tail_want)) if not (a == w or (w == "ok" and a.startswith("ok ")))]
            check("seed %d: %d commands and %d scan steps all answer as the model does" % (seed, len(lines), len(tail)), not bad, bad[:2] + [(lines + tail)[bad[0][0]] if bad else ""])

    # a tree of three levels
    rng = random.Random(7)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "pages")
        ks = sorted({rng.randrange(10 ** 9).to_bytes(5, "big") for _ in range(60000)})
        order = list(ks)
        rng.shuffle(order)
        lines = ["put 0 %s %s" % (k.hex(), k[:2].hex()) for k in order]
        out, rc = run(path, lines + ["steps"])
        check("60,000 small entries: every put answers ok", rc == 0 and all(a.startswith("ok ") for a in out[:-1]), out[:2])
        sample = rng.sample(ks, 300)
        out, rc = run(path, lines + ["get 0 %s" % k.hex() for k in sample] + ["next 0 %s 0" % ks[i].hex() for i in range(0, 60000, 997)])
        tail = out[len(lines):]
        check("... and 300 gets and a scan sample answer as the model does", all(tail[i] == "val " + sample[i][:2].hex() for i in range(300)) and
              all(tail[300 + j] == ("kv %s %s" % (ks[i + 1].hex(), ks[i + 1][:2].hex()) if i + 1 < len(ks) else "none") for j, i in enumerate(range(0, 60000, 997))), tail[:2])
        size = os.path.getsize(path)
        check("... in a file that is a whole number of pages", size % 4096 == 0, size)
        # deleting every key leaves the empty tree
        dels = ["del 0 %s" % k.hex() for k in order[:3000]]
        small = ["put 0 %s 01" % k.hex() for k in order[:3000]] + dels + ["next 0 - 1", "root 0"]
        out, rc = run(os.path.join(d, "pages2"), small)
        check("3,000 puts and the 3,000 deletes leave the empty tree", out[-2] == "none" and out[-1] == "root 0", out[-3:])

    # copy-on-write: a fork keeps the old tree whole
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "pages")
        base = ["put 0 %s %s" % (bytes([i]).hex(), bytes([i]).hex()) for i in range(1, 250)]
        out, rc = run(path, base + ["fork 0 1"] + ["put 0 %s ff" % bytes([i]).hex() for i in range(1, 250)] + ["del 1 %s" % bytes([7]).hex(), "get 0 %s" % bytes([7]).hex(), "get 1 %s" % bytes([8]).hex(), "get 1 %s" % bytes([7]).hex(), "get 0 %s" % bytes([8]).hex()])
        check("a write to one slot leaves the fork's tree whole", out[-4:] == ["val ff", "val 08", "none", "val ff"], out[-4:])

    # a bit flipped in a page is refused, not read as data: for every page of the file in turn, flip it, ask for every key, flip it back and ask again
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "pages")
        keys = [bytes([i, (i * 7) % 256]) for i in range(1, 200)]
        build = ["put 0 %s %s" % (k.hex(), bytes([k[0]]).hex()) for k in keys]
        out, rc = run(path, build)
        pages = os.path.getsize(path) // 4096
        gets = ["get 0 %s" % k.hex() for k in keys]
        right = ["val " + bytes([k[0]]).hex() for k in keys]
        wrong_data, refused_pages, still_bad = 0, 0, 0
        for page in range(1, pages):
            out, rc = run(os.path.join(d, "p%d" % page), build + ["flip %d 100" % page] + gets + ["flip %d 100" % page] + gets)     # a fresh file: the page numbers are the same each time
            first, second = out[len(build) + 1:len(build) + 1 + len(keys)], out[len(build) + 2 + len(keys):]
            wrong_data += sum(1 for a, w in zip(first, right) if a != w and a != "err 102")
            refused_pages += 1 if any(a == "err 102" for a in first) else 0
            still_bad += sum(1 for a, w in zip(second, right) if a != w)
        check("%d pages flipped one at a time: no read ever answers with wrong data" % (pages - 1), wrong_data == 0, wrong_data)
        check("... a flipped page that the tree reads is refused (err 102), and there are such pages (%d)" % refused_pages, refused_pages > 0, refused_pages)
        check("... and flipped back, every read is right again", still_bad == 0, still_bad)
    # too long
    with tempfile.TemporaryDirectory() as d:
        out, rc = run(os.path.join(d, "p"), ["put 0 %s 01" % ("aa" * 201), "put 0 01 %s" % ("bb" * 801), "put 0 00 01", "get 0 00"])
        check("a key of 201 bytes and a value of 801 are refused (err 104), and the next put works", out == ["err 104", "err 104", "ok 1", "val 01"] or (out[0] == "err 104" and out[1] == "err 104" and out[3] == "val 01"), out)
    print("btree_check: %d seeds, %d failures" % (SEEDS, len(FAILED)))
    return 1 if FAILED else 0


sys.exit(main())
