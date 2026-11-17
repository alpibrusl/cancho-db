#!/usr/bin/env python3
"""Real drivers through the proxy (docs/m1-extended.md P3d): psycopg 3, psycopg2, pg8000, asyncpg and, where it is installed, node-postgres.

    PG_E2E_PORT=5532 python3 tests/drivers_e2e.py PROXY_BINARY      (needs build/venv; node-postgres from build/node when present)

Each driver connects with a capability token as its password, then: a parametrised select, an insert, a transaction of two inserts that
commits, one that rolls back, a prepared statement used three times, and executemany. The rows each driver reads back are the same, the
rows of the committed work are in the database and the rolled-back ones are not, and the proxy's log of the whole session is accepted by
the verifiers.
"""
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))
import socket  # noqa: E402
import struct  # noqa: E402
import time  # noqa: E402
import verify as pyverify  # noqa: E402

PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "postgres")
PROXY = sys.argv[1]
VERIFIERS = os.environ.get("E2E_VERIFIERS", "").split()
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:600]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def mint(*args): return subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "mint.py")] + list(args), capture_output=True, text=True, check=True).stdout.strip()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class R:  # a psql result
    def __init__(self, r): self.stdout, self.stderr = r.stdout, r.stderr


def psql(sql):
    return R(subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", DB, "-c", sql], capture_output=True, text=True))


def read_log(path):
    data = Path(path).read_bytes()
    at, out = 40, []
    while at < len(data):
        n = struct.unpack(">I", data[at:at + 4])[0]
        out.append(pyverify.decode(data[at + 4:at + 4 + n]))
        at += 4 + n + 64
    return out


ROOT = mint("root")
token = mint("password", "--effects", "r:*,w:*,d:*,c:*,n:*")
work = Path(tempfile.mkdtemp())
(work / "key").write_bytes(bytes(range(32)))
ldir = work / "log"
ldir.mkdir()
for t in ("xe", "xo"):
    psql("drop table if exists %s" % t)
psql("create table xe(a int primary key, b text, c numeric)")
psql("insert into xe values (1, 'one', 1.5), (2, 'two', 2.5)")
psql("create table xo(a int primary key, b text)")
port = free_port()
proc = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(PG_PORT), "main", ROOT, "postgres", DB, str(ldir), str(work / "key")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
for _ in range(200):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        break
    except OSError:
        time.sleep(0.05)
check("the proxy starts", proc.poll() is None)
PY = str(ROOT_DIR / "build/venv/bin/python")


def run_py(code):
    r = subprocess.run([PY, "-c", code, str(port), token], capture_output=True, text=True, timeout=120)
    return r.stdout.strip(), r.stderr.strip()


PSYCOPG = '''
import sys, {mod} as d
port, tok = sys.argv[1:3]
c = d.connect(host="127.0.0.1", port=int(port), user="agent", password=tok, dbname="main"{extra})
cur = c.cursor()
cur.execute("select b from xe where a = %s", (1,)); print(cur.fetchall())
cur.execute("insert into xo values (%s, %s)", ({base} + 1, "one")); c.commit()
cur.execute("insert into xo values (%s, %s)", ({base} + 2, "two")); cur.execute("insert into xo values (%s, %s)", ({base} + 3, "three")); c.commit()
cur.execute("insert into xo values (%s, %s)", ({base} + 4, "gone")); c.rollback()
for a in (1, 2, 1):
    cur.execute("select b from xe where a = %s", (a,)); print(cur.fetchall())
cur.executemany("insert into xo values (%s, %s)", [({base} + 5, "m"), ({base} + 6, "n")]); c.commit()
c.close()
'''
PG8000 = '''
import sys, pg8000.native as d
port, tok = sys.argv[1:3]
c = d.Connection("agent", host="127.0.0.1", port=int(port), password=tok, database="main")
print(c.run("select b from xe where a = :a", a=1))
c.run("insert into xo values (:a, :b)", a=%d + 1, b="one")
c.run("begin"); c.run("insert into xo values (:a, :b)", a=%d + 2, b="two"); c.run("insert into xo values (:a, :b)", a=%d + 3, b="three"); c.run("commit")
c.run("begin"); c.run("insert into xo values (:a, :b)", a=%d + 4, b="gone"); c.run("rollback")
for a in (1, 2, 1):
    print(c.run("select b from xe where a = :a", a=a))
c.run("insert into xo values (:a, :b)", a=%d + 5, b="m"); c.run("insert into xo values (:a, :b)", a=%d + 6, b="n")
c.close()
'''
ASYNCPG = '''
import sys, asyncio, asyncpg
port, tok = sys.argv[1:3]
async def main():
    c = await asyncpg.connect(host="127.0.0.1", port=int(port), user="agent", password=tok, database="main", ssl=False)
    print([tuple(r) for r in await c.fetch("select b from xe where a = $1", 1)])
    await c.execute("insert into xo values ($1, $2)", %d + 1, "one")
    async with c.transaction():
        await c.execute("insert into xo values ($1, $2)", %d + 2, "two"); await c.execute("insert into xo values ($1, $2)", %d + 3, "three")
    try:
        async with c.transaction():
            await c.execute("insert into xo values ($1, $2)", %d + 4, "gone"); raise RuntimeError
    except RuntimeError: pass
    st = await c.prepare("select b from xe where a = $1")
    for a in (1, 2, 1): print([tuple(r) for r in await st.fetch(a)])
    await c.executemany("insert into xo values ($1, $2)", [(%d + 5, "m"), (%d + 6, "n")])
    await c.close()
asyncio.run(main())
'''
drivers = [("psycopg 3", PSYCOPG.format(mod="psycopg", extra="", base=100), 100), ("psycopg2", PSYCOPG.format(mod="psycopg2", extra="", base=200), 200),
           ("pg8000", PG8000 % ((300,) * 6), 300), ("asyncpg", ASYNCPG % ((400,) * 6), 400)]
n_before = len(read_log(ldir / "log"))
for name, code, base in drivers:
    out, err = run_py(code)
    import re
    words = re.findall(r"one|two", out)  # (a driver may give str or bytes, a tuple or a list: the values are what is compared)
    check("%s: the rows it reads are the database's, through the proxy" % name, words == ["one", "one", "two", "one"], (out, err))
    rows = psql("select string_agg(a::text, ',' order by a) from xo where a > %d and a < %d" % (base, base + 10)).stdout.strip()
    want = ",".join(str(base + i) for i in (1, 2, 3, 5, 6))
    check("%s: the commits are there and the rolled-back insert is not (%s)" % (name, want), rows == want, (rows, err))

node = ROOT_DIR / "tests/drivers_node.js"
if (ROOT_DIR / "build/node/node_modules/pg").exists() and shutil.which("node"):
    r = subprocess.run(["node", str(node), str(port), "agent", token, "main"], capture_output=True, text=True, timeout=120, env=dict(os.environ, NODE_PATH=str(ROOT_DIR / "build/node/node_modules")))
    check("node-postgres: connects and reads through the proxy", r.returncode == 0 and "one" in r.stdout, (r.stdout, r.stderr))

log = read_log(ldir / "log")[n_before:]
check("the proxy logged commits for the drivers' work (at least one per driver)", len(log) >= len(drivers), len(log))
for vname, cmd in [("python", ["python3", str(ROOT_DIR / "tools" / "verify.py")])] + [(v, [v]) for v in VERIFIERS]:
    o = subprocess.run(cmd + [str(ldir / "log"), "--root", ROOT, "--tokens", str(ldir / "tokens"), "--stmts", str(ldir / "stmts")], capture_output=True, text=True).stdout.strip()
    check("the drivers' session: %s accepts the log, the tokens and the statements" % vname, o.startswith("ok commits=%d " % (n_before + len(log))), o)
psql("drop table if exists xe"); psql("drop table if exists xo")
proc.terminate()
proc.communicate(timeout=10)
if FAILED:
    print("\n%d checks failed" % len(FAILED))
    sys.exit(1)
print("\nall driver checks passed")
