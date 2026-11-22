#!/usr/bin/env python3
"""The engine's server, over a socket, against the test program (docs/m3-engine.md 6al).

    python3 tests/engine_wire.py ENGINE_SERVER ENGINECHECK STATEMENTS SEED

The oracle is the test program (build/enginecheck), whose answers tests/engine_check.py holds against PostgreSQL's. A history (the differential's fixed statements that
have no parameters, then random ones from its generator) is run through the test program and, by PostgreSQL's simple query protocol, through the server. For every statement
the two must agree: the command's tag, or the SQLSTATE, or the refusal's tag; the names and type oids of the columns; every row's text; the transaction's state. Then the
server is stopped and the test program reads THE SERVER'S page file: every table must answer as the test program's own file does.

Then, each on a server of its own:

  * killed (SIGKILL) right after a commit was acknowledged, restarted: the rows are there;
  * a connection closed inside a transaction: nothing of it is there, and the next connection writes what it wrote;
  * the extended protocol: refused with one error, the connection goes on;
  * an SSLRequest is answered N and the startup goes on;
  * garbage (random bytes for a startup, a message of a huge length, of no known type, half a message and a close, a query that is no string): the server answers the next
    connection as if nothing had happened.

If a PostgreSQL is reachable (PG_E2E_PORT) and `psql` is installed, a script is run with psql against both and what psql prints must be the same: a client this project did
not write. Without one that step is skipped, and says so.
"""
import difflib
import os
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

SERVER, HARNESS, COUNT, SEED = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
sys.argv = ["engine_check.py", HARNESS, str(COUNT), str(SEED)]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine_check as ec  # noqa: E402  (the generator, the fixed statements, and how the test program is run)

FAILED = []


def check(name, ok, detail=""):
    print("%-4s %s%s" % ("ok" if ok else "FAIL", name, ("   " + str(detail)[:700]) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Server:
    def __init__(self, path):
        self.path, self.port = path, free_port()
        self.p = subprocess.Popen([SERVER, path, str(self.port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        line = self.p.stderr.readline()
        if line != b"listening\n":
            raise SystemExit("engine_wire: the server did not start: %r (status %s)" % (line, self.p.poll()))

    def stop(self, sig=signal.SIGTERM):
        self.p.send_signal(sig)
        self.p.wait()
        self.p.stderr.close()

    def alive(self):
        return self.p.poll() is None


def message(t, body):
    return t + struct.pack(">I", len(body) + 4) + body


class Client:
    """The simple query protocol, and the bytes of anything else."""

    def __init__(self, port, ssl_first=False):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=20)
        self.buf, self.status, self.names, self.params = b"", "?", [], {}
        if ssl_first:
            self.s.sendall(struct.pack(">II", 8, 80877103))
            self.ssl_answer = self.s.recv(1)
        body = struct.pack(">I", 196608) + b"user\0tester\0database\0anything\0\0"
        self.s.sendall(struct.pack(">I", len(body) + 4) + body)
        self.first = self.until_ready()

    def msg(self):
        while len(self.buf) < 5 or len(self.buf) < 1 + struct.unpack(">I", self.buf[1:5])[0]:
            got = self.s.recv(65536)
            if not got:
                raise EOFError
            self.buf += got
        n = struct.unpack(">I", self.buf[1:5])[0]
        t, body, self.buf = self.buf[0:1], self.buf[5:1 + n], self.buf[1 + n:]
        return t, body

    def until_ready(self):
        out = []
        while True:
            t, body = self.msg()
            out.append((t, body))
            if t == b"S":
                k, v = body.rstrip(b"\0").split(b"\0")
                self.params[k.decode()] = v.decode()
            if t == b"Z":
                self.status = body.decode()
                return out

    def answer(self, msgs):
        """(SQLSTATE or None, message, names, oids, rows, tag, which messages came)"""
        err, text, names, oids, rows, tag = None, None, None, None, [], None
        for t, body in msgs:
            if t == b"E":
                fields = body.split(b"\0")
                # severity twice (S, and V which is never translated), the SQLSTATE, the message; then the zero that ends the list
                if [f[:1] for f in fields] != [b"S", b"V", b"C", b"M", b"", b""] or fields[0][1:] != fields[1][1:] or fields[0][1:] not in (b"ERROR", b"FATAL"):
                    check("an error has its fields as PostgreSQL's protocol has them", False, body)
                for f in fields:
                    if f[:1] == b"C":
                        err = f[1:].decode()
                    elif f[:1] == b"M":
                        text = f[1:].decode()
            elif t == b"T":
                n = struct.unpack(">H", body[:2])[0]
                at, names, oids = 2, [], []
                for _ in range(n):
                    end = body.index(b"\0", at)
                    names.append(body[at:end])
                    table, col, oid, size, mod, fmt = struct.unpack(">IHIhiH", body[end + 1:end + 19])
                    oids.append(oid)
                    if (table, col, mod, fmt) != (0, 0, -1, 0) or size != {16: 1, 20: 8, 21: 2, 23: 4}.get(oid, -1):
                        check("a column is described as PostgreSQL's protocol has it", False, (table, col, oid, size, mod, fmt))
                    at = end + 19
            elif t == b"D":
                n = struct.unpack(">H", body[:2])[0]
                at, row = 2, []
                for _ in range(n):
                    ln = struct.unpack(">i", body[at:at + 4])[0]
                    at += 4
                    if ln < 0:
                        row.append(None)
                    else:
                        row.append(body[at:at + ln])
                        at += ln
                rows.append(row)
            elif t == b"C":
                if body[-1:] != b"\0" or b"\0" in body[:-1]:
                    check("a command's tag is a string", False, body)
                tag = body[:-1].decode()
        return err, text, names, oids, rows, tag, b"".join(t for t, _ in msgs)

    def query(self, sql):
        self.s.sendall(message(b"Q", sql.encode() + b"\0"))
        return self.answer(self.until_ready())

    def close(self, terminate=True):
        if terminate:
            self.s.sendall(message(b"X", b""))
        self.s.close()


def harness_view(block):
    """A block of the test program's output as the client would see the same answer: (SQLSTATE or None, message, names, oids, rows, tag, state)."""
    head, state = block[0], block[-1].split()[1]
    if head.startswith("refused "):
        return "0A000", "cancho-db: refused " + head.split()[1], None, None, [], None, state
    if head.startswith("error "):
        return head.split()[1], None, None, None, [], None, state
    tag = [l[2:] for l in block if l.startswith("G ")][0]
    names = oids = None
    rows = []
    for l in block[1:]:
        if l == "N" or l.startswith("N "):
            names = [ec.unhex(x) for x in l.split()[1:]]
        elif l == "T" or l.startswith("T "):
            oids = [int(x) for x in l.split()[1:]]
        elif l == "R" or l.startswith("R "):
            rows.append([None if v == "-" else ec.unhex(v) for v in l.split()[1:]])
    return None, None, names, oids, rows, tag, state


def differential(d):
    fixed = [sql for sql, _ in ec.FIXED if not isinstance(sql, ec.P)]
    rnd = [st[0] for st in ec.generate(random.Random(SEED), COUNT, params=False)]
    history = fixed + rnd
    blocks = ec.run_engine(os.path.join(d, "harness.db"), history + ["!commit"])
    if len(blocks) != len(history):
        raise SystemExit("engine_wire: %d answers of the test program for %d statements" % (len(blocks), len(history)))
    srv = Server(os.path.join(d, "server.db"))
    c = Client(srv.port)
    check("the startup is answered: AuthenticationOk, the parameters, a key, ReadyForQuery", b"".join(t for t, _ in c.first) == b"RSSSSSSKZ" and c.status == "I" and c.params.get("client_encoding") == "UTF8"
          and c.params.get("server_version", "").startswith("16."), (c.first, c.params))
    kinds, bad = {}, 0
    for i, sql in enumerate(history):
        err, text, names, oids, rows, tag, seen = c.query(sql)
        want = harness_view(blocks[i])
        got = (err, text if err == "0A000" else None, names, oids, rows, tag, c.status)
        k = "refused" if want[0] == "0A000" else "error" if want[0] else "rows" if want[2] is not None else "command"
        kinds[k] = kinds.get(k, 0) + 1
        if got != want:
            bad += 1
            if bad <= 5:
                print("FAIL %d: %s\n     server:       %s\n     test program: %s" % (i, sql[:200], str(got)[:500], str(want)[:500]))
    check("%d statements: the server answers as the test program does (%s)" % (len(history), ", ".join("%s %d" % kv for kv in sorted(kinds.items()))), bad == 0, "%d differ" % bad)
    c.close()
    srv.stop()
    # the server's page file, read by the test program
    tables = sorted(set(re.findall(r"create table (?:if not exists )?(\w+)", " ".join(history))))
    dump = ["select * from %s order by 1" % t for t in tables]
    mine = ec.run_engine(os.path.join(d, "harness.db"), dump)
    theirs = ec.run_engine(os.path.join(d, "server.db"), dump)
    answered = sum(1 for b in mine if b and b[0].startswith("ok "))
    check("the server's page file holds what the test program's does (%d tables read)" % answered, mine == theirs and answered >= 3)


def durability(d):
    path = os.path.join(d, "kill.db")
    srv = Server(path)
    c = Client(srv.port)
    c.query("create table dur (k integer primary key, v text)")
    for k in range(40):
        c.query("insert into dur values (%d, 'row %d')" % (k, k))
    c.query("begin")
    c.query("update dur set v = 'seen' where k < 10")
    got = c.query("commit")
    srv.stop(signal.SIGKILL)                      # the commit was acknowledged: it is on the disk
    c.close(False)
    srv = Server(path)
    c = Client(srv.port)
    rows = c.query("select count(*) from dur where v = 'seen'")[4]
    all_rows = c.query("select count(*) from dur")[4]
    check("killed after an acknowledged commit, restarted: the commit is there", got[5] == "COMMIT" and rows == [[b"10"]] and all_rows == [[b"40"]], (got, rows, all_rows))
    # a connection that ends inside a transaction
    c.query("begin")
    c.query("insert into dur values (100, 'half')")
    c.query("update dur set v = 'half' where k = 1")
    c.close(False)
    c = Client(srv.port)
    a = c.query("select count(*) from dur where v = 'half'")[4]
    b = c.query("insert into dur values (100, 'whole')")
    check("a connection closed inside a transaction: nothing of it stays, and its key is free", a == [[b"0"]] and b[5] == "INSERT 0 1" and c.status == "I", (a, b))
    # what the lost transaction drew from a counter stays drawn, as after any rollback
    c.query("create table drawn (id integer generated always as identity primary key, v text)")
    first = c.query("insert into drawn (v) values ('a') returning id")[4]
    c.query("begin")
    lost = c.query("insert into drawn (v) values ('lost') returning id")[4]
    c.close(False)
    c = Client(srv.port)
    nxt = c.query("insert into drawn (v) values ('b') returning id")[4]
    check("a value drawn in a transaction the connection took with it is not given again", (first, lost, nxt) == ([[b"1"]], [[b"2"]], [[b"3"]]) and c.status == "I", (first, lost, nxt))
    # the same with a Terminate, after which the server closes its side
    c.query("begin")
    c.query("delete from dur")
    c.s.sendall(message(b"X", b""))
    c.s.settimeout(5)
    try:
        closed = c.s.recv(100) == b""
    except OSError:
        closed = False
    c.s.close()
    c = Client(srv.port)
    check("a Terminate ends the connection, and inside a transaction rolls it back", closed and c.query("select count(*) from dur")[4] == [[b"41"]], closed)
    # a message that arrives in two pieces, the second being its last byte, after a longer one has been through the buffer
    c.query("select count(*) from dur where v = '%s'" % ("x" * 300))
    whole = message(b"Q", b"select count(*) from dur\0")
    c.s.sendall(whole[:-1])
    time.sleep(0.3)
    c.s.sendall(whole[-1:])
    check("a message in two pieces is read when it is whole", c.answer(c.until_ready())[4] == [[b"41"]])
    # the extended protocol is refused, once, and the connection goes on
    c.s.sendall(message(b"P", b"\0select 1\0" + struct.pack(">H", 0)) + message(b"B", b"\0\0" + struct.pack(">HHH", 0, 0, 0)) + message(b"E", b"\0" + struct.pack(">I", 0)) + message(b"S", b""))
    err, text, _, _, _, _, seen = c.answer(c.until_ready())
    c.s.sendall(message(b"P", b"\0select 1\0" + struct.pack(">H", 0)) + message(b"D", b"S\0") + message(b"S", b""))
    again = c.answer(c.until_ready())[6]
    after = c.query("select count(*) from dur")
    check("the extended protocol: one error for each batch, ReadyForQuery at its Sync, and the connection goes on", (err, text, seen, again) == ("0A000", "cancho-db: refused extended-protocol", b"EZ", b"EZ") and after[4] == [[b"41"]], (err, text, seen, again, after))
    # an empty query, and a statement that ends with a semicolon
    c.s.sendall(message(b"Q", b"  ;  \0"))
    seen = b"".join(t for t, _ in c.until_ready())
    semi = c.query("select count(*) from dur ; ")
    two = c.query("select 1 from dur; select 2 from dur")
    check("an empty query is EmptyQueryResponse; one semicolon ends a statement; two statements are refused", seen == b"IZ" and semi[4] == [[b"41"]] and two[0] == "0A000", (seen, semi, two))
    # an answer larger than the server's buffer (1 MiB): every row arrives, in order
    c.query("create table big (k integer primary key, v text)")
    for i in range(0, 30000, 500):
        c.query("insert into big values " + ", ".join("(%d, '%s')" % (k, "%06d" % k * 10) for k in range(i, i + 500)))
    rows = c.query("select * from big order by k")[4]
    check("an answer of 30,000 rows and 2.4 MB arrives whole and in order", [r[0] for r in rows] == [b"%d" % k for k in range(30000)] and all(r[1] == b"%06d" % k * 10 for k, r in enumerate(rows)), len(rows))
    # an answer is not a write for each of its messages (each would wait for the client's acknowledgement of the one before: 40 ms a query, as first built)
    t0 = time.time()
    for k in range(500):
        c.query("insert into dur values (%d, 'speed')" % (1000 + k))
    t1 = time.time()
    for k in range(500):
        c.query("select v from dur where k = %d" % (1000 + k))
    t2 = time.time()
    c.query("delete from dur where k >= 1000")
    print("     500 inserts, each committed to the disk before its answer: %.2f s; 500 selects of a row: %.2f s" % (t1 - t0, t2 - t1))
    check("500 selects of one row take under 5 s", t2 - t1 < 5, t2 - t1)
    c.close()
    # an SSLRequest first
    c = Client(srv.port, ssl_first=True)
    check("an SSLRequest is answered N and the startup goes on", c.ssl_answer == b"N" and c.query("select count(*) from dur")[4] == [[b"41"]])
    c.close()
    # a client that is not on this machine's loopback is closed unread. The nearest thing a test has: this machine's other address
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        mine = probe.getsockname()[0]
    except OSError:
        mine = "127.0.0.1"
    probe.close()
    if mine.startswith("127."):
        print("skip a client from another address: this machine has only the loopback")
    else:
        try:
            far = socket.create_connection((mine, srv.port), timeout=10)
            body = struct.pack(">I", 196608) + b"user\0far\0\0"
            far.sendall(struct.pack(">I", len(body) + 4) + body)
            got = far.recv(100)
            far.close()
        except OSError:
            got = b""
        check("a client from another address (%s) is closed unread" % mine, got == b"", got)
    return srv


def garbage(srv):
    rng = random.Random(SEED)
    startup = struct.pack(">I", 196608) + b"user\0g\0\0"
    startup = struct.pack(">I", len(startup) + 4) + startup
    cases = [("random bytes for a startup", bytes(rng.randrange(256) for _ in range(64))),
             ("a startup of no length", struct.pack(">I", 3)),
             ("a startup of another protocol", struct.pack(">II", 8, 131072)),
             ("a cancel request", struct.pack(">IIII", 16, 80877102, 1, 2)),
             ("nothing at all", b""),
             ("half a startup", startup[:7]),
             ("a message of a huge length", startup + b"Q" + struct.pack(">I", 1 << 30) + b"select"),
             ("a message of length 3", startup + b"Q" + struct.pack(">I", 3)),
             ("a message of no known type", startup + message(b"!", b"what")),
             ("half a query and a close", startup + message(b"Q", b"select count(*) from dur\0")[:12]),
             ("a query that is no string", startup + message(b"Q", b"select 1")),
             ("a query of bytes that are no text", startup + message(b"Q", bytes(rng.randrange(1, 256) for _ in range(300)) + b"\0")),
             ("many messages at once", startup + message(b"Q", b"select count(*) from dur\0") * 50),
             ("a COPY message", startup + message(b"d", b"data"))]
    for _ in range(40):
        cases.append(("random bytes after a startup", startup + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 200)))))
    bad = []
    # what the server says before it closes: a message it cannot read past is a protocol violation, said so; and every whole message before the end is answered
    says = {"a message of a huge length": b"SFATAL\0VFATAL\0C08P01\0", "a message of length 3": b"C08P01\0", "a message of no known type": b"C08P01\0", "a query that is no string": b"C08P01\0",
            "a COPY message": b"C08P01\0", "many messages at once": b"Z\0\0\0\x05I" * 51}
    for name, data in cases:
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=20)
        reply = b""
        try:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            while True:
                got = s.recv(65536)
                if not got:
                    break
                reply += got
        except OSError:
            pass
        s.close()
        if name in says and (says[name] not in reply if name != "many messages at once" else reply.count(b"Z\0\0\0\x05I") != 51):
            bad.append(name + ": the reply")
        try:
            c = Client(srv.port)
            if c.query("select count(*) from dur")[4] != [[b"41"]] or not srv.alive():
                bad.append(name)
            c.close()
        except (OSError, EOFError):
            bad.append(name)
            break
    check("garbage (%d kinds of it): the server answers the next connection as before" % len(cases), not bad, bad)


def with_psql(d):
    port = int(os.environ.get("PG_E2E_PORT", "5532"))
    if shutil.which("psql") is None or subprocess.run(["pg_isready", "-h", "127.0.0.1", "-p", str(port)], capture_output=True).returncode != 0:
        print("skip psql against the server and against PostgreSQL: no psql, or no PostgreSQL on port %d" % port)
        return
    db = os.environ.get("E2E_DB", "cdb_e2e") + "_wire"
    subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-d", "postgres", "-q", "-c", "drop database if exists %s" % db, "-c", "create database %s" % db], capture_output=True)
    script = ["create table ps (k integer primary key, name text not null, n bigint, ok boolean)",
              "insert into ps values (1, 'ana', 10, true), (2, 'bo', null, false), (3, 'c''y', -5, null)",
              "select * from ps order by k",
              "select name, n + 1 as m from ps where ok or n < 0 order by name desc",
              "update ps set n = coalesce(n, 0) + k returning k, n",
              "begin", "delete from ps where k = 2", "select count(*), sum(k), min(k), max(k) from ps", "rollback",
              "select count(*) from ps",
              "insert into ps values (4, 'd', 1, true) on conflict do nothing",
              "select k, name from ps where name like '%a%' or k in (3, 4) order by k limit 3",
              "alter table ps add column extra text default 'x'",
              "select * from ps order by k desc",
              "drop table ps"]
    args = []
    for s in script:
        args += ["-c", s]
    srv = Server(os.path.join(d, "psql.db"))
    theirs = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(srv.port), "-U", "postgres", "-d", db, "-X"] + args, capture_output=True, text=True)
    srv.stop()
    pg = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-d", db, "-X"] + args, capture_output=True, text=True)
    check("psql prints for the server what it prints for PostgreSQL (%d statements, %d lines)" % (len(script), len(pg.stdout.splitlines())),
          theirs.returncode == 0 and pg.returncode == 0 and theirs.stdout == pg.stdout and theirs.stderr == pg.stderr and len(pg.stdout.splitlines()) > 30,
          "\n".join(difflib.unified_diff((theirs.stdout + theirs.stderr).splitlines(), (pg.stdout + pg.stderr).splitlines(), "server", "postgres", lineterm="")))


def main():
    with tempfile.TemporaryDirectory() as d:
        differential(d)
        srv = durability(d)
        garbage(srv)
        check("the server is still running at the end", srv.alive())
        srv.stop()
        with_psql(d)
    if FAILED:
        print("FAIL engine wire: %d failed" % len(FAILED))
        return 1
    print("PASS engine wire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
