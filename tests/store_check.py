#!/usr/bin/env python3
"""Checks src/store.cho (P2c): the log directory, its lock, its startup scan and the repair of a torn tail.

    python3 tests/store_check.py build/storecheck build/verify build/verify-go

Every commit here is made by this file's own encoder and signed with `cryptography`, so what the store reads back and what the
three verifiers accept does not depend on the code under test. Cuts the log (and the two stores) at every byte of their last
record, as a crash during an append would, and a flipped byte in a record must be refused, not repaired.
"""
import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

STORE, *VERIFIERS = sys.argv[1:]
ROOT = Path(__file__).resolve().parent.parent
PY = ["python3", str(ROOT / "tools" / "verify.py")]
failures = 0
rng = random.Random(11)


def check(name, ok, detail=""):
    global failures
    if not ok:
        failures += 1
        print("FAIL", name, str(detail)[:300])


def u16(n): return struct.pack(">H", n)
def u32(n): return struct.pack(">I", n)
def u64(n): return struct.pack(">Q", n)
def lst(items): return u32(len(items)) + b"".join(items)
def rb(n): return bytes(rng.randrange(256) for _ in range(n))


SEED = rb(32)
SK = Ed25519PrivateKey.from_private_bytes(SEED)
PK = SK.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
DOMAIN = b"cancho-db/commit/v1\x00"


class Chain:
    def __init__(self):
        self.tip, self.n = {}, {}

    def commit(self, branch=b"main"):
        seq = self.n.get(branch, 0)
        parents = [self.tip[branch]] if branch in self.tip else []
        enc = b"".join([u16(1), lst(parents), u16(len(branch)) + branch, u64(seq), rb(32), lst([rb(32)]), lst([]), rb(32), rb(32),
                        lst([]), lst([]), rb(32), rb(32), lst([]), u64(1_700_000_000_000 + seq)])
        cid = hashlib.sha256(DOMAIN + enc).digest()
        self.tip[branch], self.n[branch] = cid, seq + 1
        token, stmt = rb(rng.randrange(1, 40)), rb(rng.randrange(1, 30))
        return {"enc": enc, "sig": SK.sign(cid), "id": cid, "token": token, "stmt": stmt}


def log_record(c): return u32(len(c["enc"])) + c["enc"] + c["sig"]
def store_record(b): return u32(len(b)) + b


LAST_ERR = [""]


def run(d, key, branch, mode, stdin="", timeout=60):
    r = subprocess.run([STORE, str(d), str(key), branch, mode], input=stdin, capture_output=True, text=True, timeout=timeout)
    LAST_ERR[0] = r.stderr
    return r.stdout.strip(), r.returncode



def syscalls(d, key, branch, mode, stdin=""):
    """The durable operations of one run, in order, as ("write"|"fsync"|"ftruncate"|"flock", file name). It is `strace` that sees them:
    nothing a program prints says whether it asked the kernel to make a write durable, and in what order."""
    trace = work / "trace"
    subprocess.run(["strace", "-f", "-e", "trace=openat,close,write,fsync,ftruncate,flock", "-o", str(trace), STORE, str(d), str(key), branch, mode],
                   input=stdin, capture_output=True, text=True, timeout=60)
    names, ops = {}, []
    for line in trace.read_text().splitlines():
        line = line.split(None, 1)[1] if line.split(None, 1)[0].isdigit() else line
        if line.startswith("openat(") and ") = " in line and not line.rstrip().endswith("ENOENT (No such file or directory)"):
            fd = int(line.rsplit("= ", 1)[1].split()[0])
            args = line[len("openat("):line.index(")")] if False else line
            if "O_DIRECTORY" in line:
                names[fd] = "."
            elif '"' in line.split(",")[1]:
                names[fd] = line.split('"')[1]
        elif line.startswith("close("):
            names.pop(int(line[6:line.index(")")]), None)
        else:
            for op in ("write", "fsync", "ftruncate", "flock"):
                if line.startswith(op + "("):
                    fd = int(line[len(op) + 1:].split(",")[0].split(")")[0])
                    if names.get(fd) not in (None, "key") and fd > 2:
                        ops.append((op, names[fd]))
    return ops


def feed(commits):
    return "".join("%s\n%s\n%s\n%s\n" % (c["enc"].hex(), c["sig"].hex(), c["token"].hex(), c["stmt"].hex()) for c in commits)


def verify_ok(path, n):
    for name, argv in [("python", PY)] + [("verifier %s" % v, [v]) for v in VERIFIERS]:
        r = subprocess.run(argv + [str(path)], capture_output=True, text=True).stdout.strip()
        check("%s accepts the log" % name, r.startswith("ok commits=%d " % n), r)


work = Path(tempfile.mkdtemp())
key = work / "key"
key.write_bytes(SEED)
HEAD = b"CHODBLG1" + PK

# 1. an empty directory: the three files are made, the log is the header
d = work / "a"
d.mkdir()
out, rc = run(d, key, "main", "open")
check("empty dir opens", out == "ok commits=0 next=0 torn=0 tip=-" and rc == 0, out)
check("the log is the 40-byte header", (d / "log").read_bytes() == HEAD)

# 2. append, read back
chain = Chain()
cs = [chain.commit() for _ in range(5)]
out, rc = run(d, key, "main", "append", feed(cs))
check("five commits appended", out.splitlines()[-1] == "appended 5" and rc == 0, out)
check("the log holds the records", (d / "log").read_bytes() == HEAD + b"".join(log_record(c) for c in cs))
check("the token store holds the tokens", (d / "tokens").read_bytes() == b"CHODBTK1" + b"".join(store_record(c["token"]) for c in cs))
check("the statement store holds the statements", (d / "stmts").read_bytes() == b"CHODBST2" + b"".join(store_record(c["stmt"]) for c in cs))
out, rc = run(d, key, "main", "open")
check("restart reads the log back", out == "ok commits=5 next=5 torn=0 tip=%s" % cs[-1]["id"].hex(), out)
verify_ok(d / "log", 5)
check("the log's commit ids are handed over, in order, whatever the branch", LAST_ERR[0].strip() == "ids " + "".join(c["id"].hex() for c in cs), LAST_ERR[0])
out, rc = run(d, key, "other", "open")
check("another branch has no tip", out == "ok commits=5 next=0 torn=0 tip=-", out)

# 3. the tip is the branch's own
chain2 = Chain()
mixed = [chain2.commit(b"main"), chain2.commit(b"dev"), chain2.commit(b"main"), chain2.commit(b"dev"), chain2.commit(b"dev")]
d2 = work / "m"
d2.mkdir()
run(d2, key, "main", "append", feed(mixed))
out, rc = run(d2, key, "main", "open")
check("... and for a log of two branches, all five in log order", LAST_ERR[0].strip() == "ids " + "".join(c["id"].hex() for c in mixed), LAST_ERR[0])
check("main's tip among two branches", out == "ok commits=5 next=2 torn=0 tip=%s" % mixed[2]["id"].hex(), out)
out, rc = run(d2, key, "dev", "open")
check("dev's tip among two branches", out == "ok commits=5 next=3 torn=0 tip=%s" % mixed[4]["id"].hex(), out)

# a log of more commits than the table holds (64 here) is refused, not truncated
big = Chain()
bigcs = [big.commit() for _ in range(65)]
d3 = work / "big"
d3.mkdir()
(d3 / "log").write_bytes(HEAD + b"".join(log_record(c) for c in bigcs))
out, rc = run(d3, key, "main", "open")
check("a log of more commits than the recovery table holds is refused", out.startswith("refused log-too-big") and rc != 0, out)

# 4. a torn tail at every byte of the last record is cut, and what is left verifies
good = (d / "log").read_bytes()
last_start = len(HEAD + b"".join(log_record(c) for c in cs[:-1]))
for cut in range(last_start, len(good)):
    t = work / "t"
    shutil.rmtree(t, ignore_errors=True)
    shutil.copytree(d, t)
    (t / "log").write_bytes(good[:cut])
    out, rc = run(t, key, "main", "open")
    expect = "ok commits=4 next=4 torn=%d tip=%s" % (cut - last_start, cs[3]["id"].hex())
    check("torn log at %d" % cut, out == expect and (t / "log").read_bytes() == good[:last_start], out)
    out, rc = run(t, key, "main", "open")
    check("second open at %d is clean" % cut, out.startswith("ok commits=4 next=4 torn=0 "), out)
verify_ok(t / "log", 4)

# 5. a torn header is rewritten
for cut in range(0, 40):
    t = work / "h"
    shutil.rmtree(t, ignore_errors=True)
    t.mkdir()
    (t / "log").write_bytes(HEAD[:cut])
    out, rc = run(t, key, "main", "open")
    check("torn header at %d" % cut, out == "ok commits=0 next=0 torn=%d tip=-" % cut and (t / "log").read_bytes() == HEAD, out)

# 6. the two stores: a torn last record is cut on open
for name, magic, bodies in [("tokens", b"CHODBTK1", [c["token"] for c in cs]), ("stmts", b"CHODBST2", [c["stmt"] for c in cs])]:
    full = (d / name).read_bytes()
    boundary = len(magic + b"".join(store_record(b) for b in bodies[:-1]))
    for cut in range(boundary, len(full)):
        t = work / "s"
        shutil.rmtree(t, ignore_errors=True)
        shutil.copytree(d, t)
        (t / name).write_bytes(full[:cut])
        out, rc = run(t, key, "main", "append", "")
        check("torn %s at %d" % (name, cut), out.splitlines()[-1] == "appended 0" and (t / name).read_bytes() == full[:boundary], out)
    t = work / "s"
    shutil.rmtree(t, ignore_errors=True)
    shutil.copytree(d, t)
    (t / name).write_bytes(magic[:3])
    out, rc = run(t, key, "main", "append", "")
    check("torn %s magic" % name, (t / name).read_bytes() == magic, out)
    (t / name).write_bytes(b"NOTMAGIC" + b"x" * 5)
    out, rc = run(t, key, "main", "append", "")
    check("%s with the wrong magic is refused" % name, out.startswith("ok commits=5") and "refused bad-magic" in out and (t / name).read_bytes() == b"NOTMAGIC" + b"x" * 5, out)

# a torn store is cut and the cut made durable
t = work / "s"
shutil.rmtree(t, ignore_errors=True)
shutil.copytree(d, t)
(t / "tokens").write_bytes((d / "tokens").read_bytes()[:-3])
ops = syscalls(t, key, "main", "append", "")
i = ops.index(("ftruncate", "tokens")) if ("ftruncate", "tokens") in ops else len(ops)
check("a torn token store: cut, then synced", ops[i + 1:i + 2] == [("fsync", "tokens")], ops)

# 7. a log that does not verify is refused and not touched
for label, mut in [("a flipped byte in a record", lambda b: b[:60] + bytes([b[60] ^ 1]) + b[61:]),
                   ("a flipped signature byte", lambda b: b[:40 + 4 + len(cs[0]["enc"]) + 3] + bytes([b[40 + 4 + len(cs[0]["enc"]) + 3] ^ 1]) + b[40 + 4 + len(cs[0]["enc"]) + 4:]),
                   ("a record out of order", lambda b: HEAD + log_record(cs[1]) + log_record(cs[0]) + b"".join(log_record(c) for c in cs[2:]))]:
    t = work / "c"
    shutil.rmtree(t, ignore_errors=True)
    shutil.copytree(d, t)
    bad = mut(good)
    (t / "log").write_bytes(bad)
    out, rc = run(t, key, "main", "open")
    check("%s is refused" % label, out.startswith("refused log-corrupt") and rc != 0 and (t / "log").read_bytes() == bad, out)

# 8. another key's log, another magic, a lying length
t = work / "k"
shutil.rmtree(t, ignore_errors=True)
shutil.copytree(d, t)
other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
(t / "log").write_bytes(b"CHODBLG1" + other + good[40:])
out, rc = run(t, key, "main", "open")
check("another key's log is refused", out.startswith("refused foreign-key"), out)
(t / "log").write_bytes(b"NOTMAGIC" + good[8:])
out, rc = run(t, key, "main", "open")
check("another magic is refused", out.startswith("refused bad-magic"), out)
(t / "log").write_bytes(HEAD + u32(0xFFFFFFFF) + b"x" * 10)
out, rc = run(t, key, "main", "open")
check("a lying length is refused, not waited for", out.startswith("refused record-too-large"), out)

# 9. a second process on the same directory is refused while the first holds the log; afterwards it is not
t = work / "l"
shutil.rmtree(t, ignore_errors=True)
shutil.copytree(d, t)
holder = subprocess.Popen([STORE, str(t), str(key), "main", "hold"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
first = holder.stdout.readline().strip()
check("the first process opens", first.startswith("ok commits=5"), first)
out, rc = run(t, key, "main", "open")
check("the second is refused while the first holds the log", out.startswith("refused locked") and rc != 0, out)
holder.stdin.close()
holder.wait(timeout=30)
out, rc = run(t, key, "main", "open")
check("and is not refused after", out.startswith("ok commits=5"), out)
holder = subprocess.Popen([STORE, str(t), str(key), "main", "hold"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
holder.stdout.readline()
holder.kill()
holder.wait()
out, rc = run(t, key, "main", "open")
check("a killed holder leaves no lock behind", out.startswith("ok commits=5"), out)

# 10. what is made durable, and in what order (P2-D10): the header, then each commit's token and statement before the commit itself
t = work / "o"
t.mkdir()
ops = syscalls(t, key, "main", "open")
check("a new log: the header is written, the file synced, then the directory", ops[:3] == [("write", "log"), ("fsync", "log"), ("fsync", ".")], ops)
c1 = Chain().commit()
ops = syscalls(t, key, "main", "append", feed([c1]))
tail = ops[ops.index(("flock", "log")) + 1:]
check("a new store is made durable, then the entry order is token, statement, commit, each synced",
      tail[:3] == [("write", "tokens"), ("fsync", "tokens"), ("fsync", ".")] and tail[3:6] == [("write", "stmts"), ("fsync", "stmts"), ("fsync", ".")]
      and tail[6:] == [("write", "tokens"), ("fsync", "tokens"), ("write", "stmts"), ("fsync", "stmts"), ("write", "log"), ("fsync", "log")], tail)
t2 = work / "o2"
shutil.copytree(t, t2)
c2 = Chain().commit()
ops = syscalls(t2, key, "main", "append", feed([c2]))
tail = ops[ops.index(("flock", "log")) + 1:]
check("a commit: token, statement, then the log, each synced before the next",
      tail == [("write", "tokens"), ("fsync", "tokens"), ("write", "stmts"), ("fsync", "stmts"), ("write", "log"), ("fsync", "log")], tail)
(t2 / "log").write_bytes((t2 / "log").read_bytes()[:-5])
ops = syscalls(t2, key, "main", "open")
check("a torn tail is cut and the cut synced before anything else is done", ops[-2:] == [("ftruncate", "log"), ("fsync", "log")], ops)

shutil.rmtree(work, ignore_errors=True)
print("store_check: %d failures" % failures)
sys.exit(1 if failures else 0)
