#!/usr/bin/env python3
"""What TLS costs the engine's server (docs/m3-engine.md 6bq): a handshake, and a statement on a connection, in clear and through TLS.

    python3 scripts/measure_tls.py ENGINE_SERVER ENGINECHECK [N]

One server with a certificate made for the run; both kinds of client on it, one after the other. No key file is named, so no commit is logged: the numbers are the
transport's. It prints the medians, the server's resident memory, and the size of its binary.
"""
import os
import statistics
import sys
import tempfile
import time

N = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
sys.argv = [sys.argv[0], sys.argv[1], sys.argv[2], "10", "1"]
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))
import engine_tls as et  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec as curves  # noqa: E402

ew = et.ew


def connect(port, ctx):
    t = time.perf_counter()
    c = ew.Client(port, tls=ctx)
    return c, (time.perf_counter() - t) * 1000


def main():
    with tempfile.TemporaryDirectory() as d:
        key = curves.generate_private_key(curves.SECP256R1())
        ident = et.identity(d, "id", key, et.certificate(key))
        ctx = et.context(ident)
        srv = ew.Server(os.path.join(d, "m.db"), key=False, tls=ident)
        c = ew.Client(srv.port)
        c.query("create table m (k integer primary key, v text)")
        c.query("insert into m values " + ", ".join("(%d, 'value-%d')" % (k, k) for k in range(1000)))
        c.close()
        for name, how in (("in clear", None), ("through TLS", ctx)):
            opens = []
            for _ in range(200):
                c, ms = connect(srv.port, how)
                opens.append(ms)
                c.close()
            c, _ = connect(srv.port, how)
            reads, writes = [], []
            for i in range(N):
                t = time.perf_counter()
                c.query("select v from m where k = %d" % (i % 1000))
                reads.append((time.perf_counter() - t) * 1e6)
            for i in range(N):
                t = time.perf_counter()
                c.query("update m set v = '%s%d' where k = %d" % (name[:2], i, i % 1000))
                writes.append((time.perf_counter() - t) * 1e6)
            t = time.perf_counter()
            rows = c.query("select k, v from m order by k")[4]
            big = (time.perf_counter() - t) * 1000
            c.close()
            print("%-12s connect and startup %.2f ms; a select by key %.0f us; an update (committed, synced) %.0f us; %d rows %.2f ms" % (
                name, statistics.median(opens), statistics.median(reads), statistics.median(writes), len(rows), big))
        rss = [l for l in open("/proc/%d/status" % srv.p.pid) if l.startswith("VmRSS")][0].split()[1]
        print("the server's resident memory: %s kB; its binary: %d bytes" % (rss, os.path.getsize(ew.SERVER)))
        srv.stop()


if __name__ == "__main__":
    main()
