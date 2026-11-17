#!/usr/bin/env python3
"""What the commit path costs (docs/m1-commit-path.md section 5.11, slice P2e): the same statements, directly against PostgreSQL and through the proxy.

    PG_PORT=5611 python3 scripts/measure_p2e.py build/proxy

PostgreSQL must be on 127.0.0.1:$PG_PORT with trust login for `postgres` and max_prepared_transactions > 0 (scripts/pg_throwaway.sh). The script turns
`fsync` and `synchronous_commit` ON for the server (the throwaway config has fsync off, which would flatter the direct side), builds a table of its own
(`p2e`), and prints one line per measurement: latency of one statement as a client sees it (median, 95th percentile, mean, in milliseconds) from a
raw simple-query client with no driver in the way, one client after another. Also the cost of one `fsync` of a small file on this disk, the
floor under every commit, and the throughput of four clients at once.

Nothing is asserted except that every statement answered as it should: this is a measurement, on one machine, and says so.
"""
import os
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
PROXY = sys.argv[1]
PG_PORT = int(os.environ.get("PG_PORT", "5611"))
N = int(os.environ.get("N", "600"))


def mint(*args):
    return subprocess.run([sys.executable, str(ROOT_DIR / "tools" / "mint.py")] + list(args), capture_output=True, text=True, check=True).stdout.strip()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Conn:
    """A raw simple-query client: startup (and a password message if asked), then Query messages."""

    def __init__(self, port, password=None, db="postgres"):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=30)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        body = struct.pack(">I", 196608) + b"user\0postgres\0database\0" + db.encode() + b"\0\0"
        self.s.sendall(struct.pack(">I", len(body) + 4) + body)
        self.buf = b""
        if password is not None:
            self.expect(b"R")
            pw = password.encode() + b"\0"
            self.s.sendall(b"p" + struct.pack(">I", len(pw) + 4) + pw)
        self.drain()

    def expect(self, t):
        while True:
            m = self.message()
            if m[0] == t:
                return m
            if m[0] == b"E":
                raise RuntimeError(m[1])

    def message(self):
        while len(self.buf) < 5 or len(self.buf) < 1 + struct.unpack(">I", self.buf[1:5])[0]:
            d = self.s.recv(65536)
            if not d:
                raise EOFError("closed")
            self.buf += d
        n = struct.unpack(">I", self.buf[1:5])[0]
        m = (self.buf[:1], self.buf[5:1 + n])
        self.buf = self.buf[1 + n:]
        return m

    def drain(self):
        tags, err = [], None
        while True:
            t, body = self.message()
            if t == b"C":
                tags.append(body[:-1].decode())
            elif t == b"E":
                err = body
            elif t == b"Z":
                return tags, err

    def query(self, sql):
        q = sql.encode() + b"\0"
        self.s.sendall(b"Q" + struct.pack(">I", len(q) + 4) + q)
        tags, err = self.drain()
        if err:
            raise RuntimeError(err)
        return tags


def timed(conn, statements):
    out = []
    for sql in statements:
        t0 = time.perf_counter()
        conn.query(sql)
        out.append((time.perf_counter() - t0) * 1000)
    return out


def line(name, ms, extra=""):
    ms = sorted(ms)
    print("%-62s median %7.3f  p95 %7.3f  mean %7.3f ms  (n=%d)%s" % (name, statistics.median(ms), ms[int(len(ms) * 0.95) - 1], statistics.mean(ms), len(ms), extra))


def psql(sql):
    subprocess.run(["psql", "-q", "-At", "-h", "127.0.0.1", "-p", str(PG_PORT), "-U", "postgres", "-d", "postgres", "-c", sql], capture_output=True, check=True)


# the server: fsync on, as a real deployment has it
psql("alter system set fsync = on")
psql("alter system set synchronous_commit = on")
psql("select pg_reload_conf()")
psql("drop table if exists p2e")
psql("create table p2e(a int primary key, b text)")
psql("insert into p2e select g, md5(g::text) from generate_series(1, 1000) g")

# the floor: one fsync of a small file on this disk
d = tempfile.mkdtemp(dir=str(ROOT_DIR / "build"))
fd = os.open(os.path.join(d, "f"), os.O_WRONLY | os.O_CREAT | os.O_APPEND)
fs = []
for _ in range(300):
    os.write(fd, b"x" * 300)
    t0 = time.perf_counter()
    os.fsync(fd)
    fs.append((time.perf_counter() - t0) * 1000)
os.close(fd)
line("one fsync of a file appended 300 bytes (this disk)", fs)

# the proxy, with a log directory of its own
logdir = Path(d, "log")
logdir.mkdir()
Path(d, "key").write_bytes(bytes(range(32)))
port = free_port()
proc = subprocess.Popen([PROXY, str(port), "127.0.0.1", str(PG_PORT), "main", mint("root"), "postgres", "postgres", str(logdir), str(Path(d, "key"))],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        break
    except OSError:
        time.sleep(0.05)
token = mint("password", "--effects", "r:*,w:*,d:*,c:*,n:*")

direct = Conn(PG_PORT)
via = Conn(port, token, db="main")
sel = ["select a from p2e where a = %d" % (1 + i % 1000) for i in range(N)]
line("select, direct to PostgreSQL", timed(direct, sel))
line("select, through the proxy (a commit: log append and fsyncs)", timed(via, sel))
ins_d = ["insert into p2e values (%d, 'd')" % (100000 + i) for i in range(N)]
ins_p = ["insert into p2e values (%d, 'p')" % (200000 + i) for i in range(N)]
line("insert (autocommit), direct to PostgreSQL", timed(direct, ins_d))
line("insert (autocommit), through the proxy (PREPARE, append, COMMIT PREPARED)", timed(via, ins_p))
# a transaction of ten selects: ten statements, one commit
txn = []
for i in range(N // 10):
    t0 = time.perf_counter()
    via.query("begin")
    for j in range(10):
        via.query("select a from p2e where a = %d" % (1 + (i * 10 + j) % 1000))
    via.query("commit")
    txn.append((time.perf_counter() - t0) * 1000)
line("transaction of 10 selects + BEGIN + COMMIT, through the proxy (one commit)", txn, "  per statement ~%.3f ms" % (statistics.median(txn) / 12))
now = [("select now() from p2e where a = %d" % (1 + i % 1000)) for i in range(N // 2)]
line("select now() (one more statement to read the clock), through the proxy", timed(via, now))
direct.query("select 1 from p2e where a = 1")

# four clients at once
def burst(make, sqls, results, i):
    c = make()
    t0 = time.perf_counter()
    for sql in sqls:
        c.query(sql)
    results[i] = time.perf_counter() - t0


def concurrent(name, make, k):
    sqls = ["select a from p2e where a = %d" % (1 + i % 1000) for i in range(N // 2)]
    res = [0.0] * k
    th = [threading.Thread(target=burst, args=(make, sqls, res, i)) for i in range(k)]
    t0 = time.perf_counter()
    for t in th:
        t.start()
    for t in th:
        t.join()
    wall = time.perf_counter() - t0
    print("%-62s %5d statements in %.2f s = %7.0f statements/s" % (name, k * len(sqls), wall, k * len(sqls) / wall))


concurrent("4 clients at once, selects, direct to PostgreSQL", lambda: Conn(PG_PORT), 4)
concurrent("4 clients at once, selects, through the proxy (one commit at a time)", lambda: Conn(port, token, db="main"), 4)
proc.terminate()
proc.wait(timeout=10)
data = Path(logdir, "log").read_bytes()
at, commits = 40, 0
while at < len(data):
    at += 4 + struct.unpack(">I", data[at:at + 4])[0] + 64
    commits += 1
sizes = {f.name: f.stat().st_size for f in logdir.iterdir()}
print("the log directory after the run: %d commits; log %d, tokens %d, stmts %d bytes (%.0f bytes of log and %.0f of statements a commit; the token once per connection)"
      % (commits, sizes["log"], sizes["tokens"], sizes["stmts"], sizes["log"] / commits, sizes["stmts"] / commits))

# leave the server as it was found
psql("alter system reset fsync")
psql("alter system reset synchronous_commit")
psql("select pg_reload_conf()")
psql("drop table if exists p2e")
