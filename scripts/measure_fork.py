#!/usr/bin/env python3
"""What a fork costs (docs/m2-branches.md D25): `select cancho_fork('<name>')` through the proxy on tables of growing size, and the copy alone (cdb.fork in PostgreSQL).

    PG_E2E_PORT=5532 python3 scripts/measure_fork.py PROXY_BINARY [ROWS ...]

Prints, per size, the median of three forks through the proxy (the whole statement: guard, copy, commit, log) and of three direct copies, in milliseconds.
"""
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))
from pgtee import ensure_database  # noqa: E402

PG = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_e2e")
PROXY = sys.argv[1]
SIZES = [int(x) for x in sys.argv[2:]] or [1000, 101000]
ensure_database(PG, DB)


def direct(sql, timeout=600):
    return subprocess.run(["psql", "-At", "-h", "127.0.0.1", "-p", str(PG), "-U", "postgres", "-d", DB, "-c", sql], capture_output=True, text=True, timeout=timeout)


def mint(*a): return subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "mint.py")] + list(a), capture_output=True, text=True, check=True).stdout.strip()


root = mint("root")
token = mint("password", "--effects", "r:*,w:*,d:*,c:*,n:*")
work = Path(tempfile.mkdtemp())
(work / "key").write_bytes(bytes(range(32)))
(work / "log").mkdir()
for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
    direct('drop schema "%s" cascade' % sc)
direct("drop schema public cascade; create schema public")
s = socket.socket()
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()
proc = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(PG), "main", root, "postgres", DB, str(work / "log"), str(work / "key")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(200):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        break
    except OSError:
        time.sleep(0.05)
env = dict(os.environ, PGPASSWORD=token, PGHOST="127.0.0.1", PGPORT=str(port), PGUSER="agent", PGDATABASE="main", PGSSLMODE="prefer")
direct("create table m_t (id int primary key, a text, b int); create index m_t_b on m_t (b)")
have, n = 0, 0
for size in SIZES:
    direct("insert into m_t select g, md5(g::text), g %% 100 from generate_series(%d, %d) g" % (have + 1, size))
    have = size
    via, copy = [], []
    for i in range(3):
        n += 1
        t = time.perf_counter()
        r = subprocess.run(["psql", "-w", "-At", "-c", "select cancho_fork('m%d')" % n], env=env, capture_output=True, text=True, timeout=600)
        via.append((time.perf_counter() - t) * 1000)
        assert r.returncode == 0 and "ERROR" not in r.stderr, r.stderr
        n += 1
        t = time.perf_counter()
        r = direct("select cdb.fork('public', 'cdb_b_d%d')" % n)
        copy.append((time.perf_counter() - t) * 1000)
        assert r.returncode == 0, r.stderr
    print("%8d rows: through the proxy %8.0f ms   the copy alone %8.0f ms" % (size, statistics.median(via), statistics.median(copy)))
proc.terminate()
for sc in direct("select nspname from pg_namespace where nspname like 'cdb\\_b\\_%'").stdout.split():
    direct('drop schema "%s" cascade' % sc)
direct("drop schema public cascade; create schema public")
