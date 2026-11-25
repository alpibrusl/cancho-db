#!/usr/bin/env python3
"""What the engine's server costs as its file grows, each thing by itself (docs/m3-engine.md 6bj).

    python3 tests/engine_grow.py SERVER_BINARY ENGINECHECK_BINARY

Run by hand: it measures and holds nothing. One client, nothing beside it, the server without the check of its erases (PURGE_CHECK=0 is set here):

  * a transfer (two updates and an insert in a transaction) a second, at four sizes of the file; a read of a small table as of a few hundred commits back; and how
    long the server takes to start after it was killed (it sweeps the file before it serves, 6ay);
  * a read of a table as of a commit, by how many commits back it is;
  * a count and a sum over a table, by how many rows it has, now and as of the head.

The soak (tests/engine_soak.py) does all of these beside its load, the last two more the longer it runs.
"""
import os
import signal
import sys
import tempfile
import time

SERVER, HARNESS = sys.argv[1], sys.argv[2]
os.environ["PURGE_CHECK"] = "0"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.argv = ["engine_wire.py", SERVER, HARNESS, "0", "1"]
sys.path.insert(0, os.path.join(ROOT, "tests"))
import engine_wire as ew  # noqa: E402  (its Server and Client)


def transfers(c, seconds, at):
    t0, n = time.time(), 0
    while time.time() - t0 < seconds:
        a = (at + n) % 200
        for q in ("begin", "update acct set cents = cents - 1 where id = %d" % a, "update acct set cents = cents + 1 where id = %d" % ((a + 7) % 200),
                  "insert into journal values (%d, %d, 1)" % (int(time.time() * 1e6), a), "commit"):
            c.query(q)
        n += 1
    return n / seconds


def by_size(d):
    path = os.path.join(d, "size.db")
    srv = ew.Server(path)
    c = ew.Client(srv.port)
    c.query("create table acct (id integer primary key, cents integer not null)")
    c.query("create table journal (tid bigint primary key, src integer not null, amount integer not null)")
    c.query("create table bulk (id integer primary key, v text not null)")
    c.query("insert into acct values " + ", ".join("(%d, 1000)" % k for k in range(200)))
    i = 0
    for target in (20, 80, 160, 320):
        while os.path.getsize(path) < target * 1048576:
            c.query("insert into bulk values " + ", ".join("(%d, '%s')" % (k, "x" * 200) for k in range(i, i + 200)))
            i += 200
        rate = transfers(c, 10, i)
        head = c.query("select cancho_last_commit()")[4][0][1].decode()
        back = int(transfers(c, 3, i + 5000) * 3)
        t = time.time()
        c.query("select sum(cents) from acct as of '%s'" % head)
        past = time.time() - t
        srv.stop(signal.SIGKILL)
        c.close(False)
        t = time.time()
        srv = ew.Server(path)
        start = time.time() - t
        c = ew.Client(srv.port)
        print("%4d MiB: %3.0f transfers a second; 200 rows as of %d commits back %5.1f ms; the start after a kill %5.0f ms"
              % (os.path.getsize(path) / 1048576, rate, back, past * 1000, start * 1000), flush=True)
    c.close()
    srv.stop()


def by_commits_back(d):
    srv = ew.Server(os.path.join(d, "back.db"))
    c = ew.Client(srv.port)
    c.query("create table acct (id integer primary key, cents integer not null)")
    c.query("create table mark (k integer primary key, v integer not null)")
    c.query("insert into acct values " + ", ".join("(%d, 1000)" % k for k in range(200)))
    c.query("insert into mark values (0, 0)")
    heads, n = {}, 8000
    for k in range(1, n + 1):
        c.query("update acct set cents = cents + 1 where id = %d" % (k % 200))
        if n - k in (0, 100, 500, 2000, 7900):
            heads[n - k] = c.query("select cancho_last_commit()")[4][0][1].decode()
    for back in sorted(heads):
        ts = []
        for _ in range(5):
            t = time.time()
            c.query("select v from mark as of '%s'" % heads[back])
            ts.append(time.time() - t)
        print("one row as of %4d commits back: %5.1f ms (the median of 5)" % (back, sorted(ts)[2] * 1000), flush=True)
    c.close()
    srv.stop()


def by_rows(d):
    srv = ew.Server(os.path.join(d, "rows.db"))
    c = ew.Client(srv.port)
    c.query("create table journal (tid bigint primary key, src integer not null, dst integer not null, amount integer not null)")
    n = 0
    for target in (5000, 20000, 60000):
        while n < target:
            c.query("insert into journal values " + ", ".join("(%d, 1, 2, 3)" % k for k in range(n, n + 500)))
            n += 500
        head = c.query("select cancho_last_commit()")[4][0][1].decode()
        ts = []
        for q in ("select count(*), sum(amount) from journal", "select count(*), sum(amount) from journal as of '%s'" % head):
            t = time.time()
            c.query(q)
            ts.append((time.time() - t) * 1000)
        print("%5d rows: a count and a sum %5.1f ms; the same as of the head %5.1f ms" % (n, ts[0], ts[1]), flush=True)
    c.close()
    srv.stop()


def main():
    with tempfile.TemporaryDirectory() as d:
        by_size(d)
        by_commits_back(d)
        by_rows(d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
