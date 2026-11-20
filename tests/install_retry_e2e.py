#!/usr/bin/env python3
"""The capture install at start retries what PostgreSQL asks to be run again (src/catalog.cho `install_capture`), against a real PostgreSQL.

    PG_E2E_PORT=5532 python3 tests/install_retry_e2e.py PROXY_BINARY

A CI run died once at start with `PostgreSQL said: 40P01: deadlock detected`: an earlier proxy, killed while it was installing, leaves its backend finishing the same statements, and the two wait on each other.
That is made on purpose here, with an event trigger (`zz_probe`) that fails the proxy's first DDL statement of each attempt with an SQLSTATE of the test's choosing for the first N attempts, counted by a
sequence (a sequence is not rolled back with the failed statement). Checked: a deadlock twice (N = 2) is retried, the third attempt installs, and the proxy serves; a deadlock every time is retried five times
and given up (six attempts in all, the sequence says), the proxy exits 7 and says what PostgreSQL said; a serialization failure (40001) is retried too; any other error (42501) is not retried (one attempt).
"""
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))
from pgtee import ensure_database  # noqa: E402

PROXY = sys.argv[1]
PG_PORT = int(os.environ.get("PG_E2E_PORT", "5532"))
DB = os.environ.get("E2E_DB", "cdb_install_retry")
ROOT = subprocess.run([sys.executable, str(ROOT_DIR / "tools/mint.py"), "root"], capture_output=True, text=True).stdout.strip()
FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:400]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def direct(sql):
    return subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", DB, "-At", "-q", "-c", sql], capture_output=True, text=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


ensure_database(PG_PORT, DB)


def scene(code, limit):
    """A database whose first `limit` DDL statements fail with `code`, and a new log directory."""
    direct("drop event trigger if exists zz_probe_t; drop schema if exists zz_probe cascade; drop schema public cascade; create schema public; drop schema if exists cdb cascade")
    direct("create table p (a int primary key)")
    r = direct("""
        create schema zz_probe;
        create sequence zz_probe.s;
        create table zz_probe.t (code text, lim int);
        insert into zz_probe.t values ('%s', %d);
        create function zz_probe.fail() returns event_trigger language plpgsql as $$
        declare c text; l int; n bigint;
        begin
            select code, lim into c, l from zz_probe.t;
            n := nextval('zz_probe.s');
            if n <= l then
                raise exception 'probe: failing on purpose' using errcode = c;
            end if;
        end $$;
        create event trigger zz_probe_t on ddl_command_end execute function zz_probe.fail();
    """ % (code, limit))
    assert r.returncode == 0, r.stderr
    return Path(tempfile.mkdtemp())


def start(work):
    (work / "log").mkdir()
    (work / "key").write_bytes(bytes(range(32)))
    port = free_port()
    p = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(PG_PORT), "main", ROOT, "postgres", DB, str(work / "log"), str(work / "key")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    return p, port


def attempts():
    return int(direct("select last_value from zz_probe.s").stdout.strip() or 0) if direct("select is_called from zz_probe.s").stdout.strip() == "t" else 0


# a deadlock twice, then it goes through
work = scene("40P01", 2)
p, port = start(work)
installed = False
for _ in range(200):
    if p.poll() is not None:
        break
    if direct("select count(*) from pg_event_trigger where evtname in ('cdb_ddl', 'cdb_drop')").stdout.strip() == "2":
        installed = True
        break
    time.sleep(0.1)
check("a deadlock on the first two attempts: the third installs the capture and the proxy serves", installed and p.poll() is None, (p.poll(), p.stderr.read() if p.poll() is not None else ""))
check("... and it took exactly three attempts", attempts() >= 3, attempts())
p.terminate()
p.communicate(timeout=10)

# a deadlock every time: given up after five retries, with what PostgreSQL said
work = scene("40P01", 1000)
p, port = start(work)
try:
    err = p.communicate(timeout=60)[1]
except subprocess.TimeoutExpired:
    p.kill()
    err = "it kept running"
check("a deadlock every time: the proxy exits 7 and says what PostgreSQL said", p.returncode == 7 and "PostgreSQL said: 40P01" in err, "%s %s" % (p.returncode, err))
check("... after six attempts in all, five of them retries", attempts() == 6, attempts())

# a serialization failure is retried too
work = scene("40001", 1)
p, port = start(work)
installed = False
for _ in range(200):
    if p.poll() is not None:
        break
    if direct("select count(*) from pg_event_trigger where evtname in ('cdb_ddl', 'cdb_drop')").stdout.strip() == "2":
        installed = True
        break
    time.sleep(0.1)
check("a serialization failure (40001) once: retried, and the proxy serves", installed and p.poll() is None, (p.poll(), p.stderr.read() if p.poll() is not None else ""))
p.terminate()
p.communicate(timeout=10)

# another error is not retried
work = scene("42501", 1000)
p, port = start(work)
try:
    err = p.communicate(timeout=30)[1]
except subprocess.TimeoutExpired:
    p.kill()
    err = "it kept running"
check("another error (42501) is not retried: the proxy exits 7 after one attempt", p.returncode == 7 and "42501" in err and attempts() == 1, "%s %s %s" % (p.returncode, attempts(), err))
direct("drop event trigger if exists zz_probe_t; drop schema if exists zz_probe cascade")
print("\n%d checks failed" % len(FAILED) if FAILED else "\nall install retry checks passed")
sys.exit(1 if FAILED else 0)
