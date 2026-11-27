#!/usr/bin/env python3
"""Reads beside a transaction (docs/m3-engine.md 6bs).

    python3 tests/engine_beside.py ENGINE_SERVER ENGINECHECK STATEMENTS SEED

  * The history of tests/engine_wire.py's differential, transactions and all, run by one connection while a second reads its tables after every statement. The first
    connection's answers, the page file and the log must be what the test program gives for the history alone; and what the second reads while a transaction is open must
    be what it read before the transaction began, answered at once.
  * `now()` in a transaction does not move when another connection reads beside it.
  * Beside a transaction, what does not only read waits for it to end: an insert, a select that draws from a sequence, one of the engine's own functions, a `begin`, two
    statements in one query, a statement by the extended protocol.
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine_wire as ew  # noqa: E402  (the server, the client, the checks; it reads the command line)

check, Server, Client = ew.check, ew.Server, ew.Client
PROBES = ["select * from %s order by 1" % t for t in ("ta", "tb", "tc")]


def interleaved(d):
    state = {"b": None, "before": None, "beside": 0, "waited": 0, "moved": 0, "first": None}

    def between(srv, a):
        if state["b"] is None:
            state["b"] = Client(srv.port)
        b = state["b"]
        seen = []
        state["n"] = state.get("n", 0) + 1
        for q in PROBES:
            if state["n"] % 2 == 0:
                # every other time by the extended protocol, as a driver that prepares its statements sends it
                b.s.sendall(ew.message(b"P", b"\0" + q.encode() + b"\0\0\0") + b.bind(b"", []) + ew.message(b"D", b"P\0") + ew.message(b"E", b"\0\0\0\0\0") + ew.message(b"S", b""))
            else:
                b.ask(q)
            got = b.answered(5)
            if got is None:
                # it waits for the transaction: the test is over for this connection, and says so
                state["waited"] += 1
                state["b"] = Client(srv.port)
                return
            seen.append((got[0], got[2], got[4]))
        if a.status == "I":
            state["before"] = seen
        else:
            state["beside"] += 1
            if seen != state["before"]:
                state["moved"] += 1
                if state["first"] is None:
                    state["first"] = (seen, state["before"])

    os.mkdir(os.path.join(d, "diff"))
    ew.differential(os.path.join(d, "diff"), between=between)
    check("%d times a second connection read three tables while the first was in a transaction: answered at once (%d waited), and what it read was what it had read before the transaction began (%d were not)"
          % (state["beside"], state["waited"], state["moved"]), state["beside"] > 50 and state["waited"] == 0 and state["moved"] == 0, state["first"])
    if state["b"] is not None:
        state["b"].close()


def ext(c, name, sql, params):
    """Parse, Bind, Execute, Sync, and no wait for the answer."""
    c.s.sendall(ew.message(b"P", name + b"\0" + sql.encode() + b"\0\0\0") + c.bind(name, params) + ew.message(b"E", b"\0\0\0\0\0") + ew.message(b"S", b""))


def rules(d):
    srv = Server(os.path.join(d, "rules.db"), 30000, 10000)
    a, b = Client(srv.port), Client(srv.port)
    a.query("create table one (k integer primary key, v text)")
    a.query("insert into one values (1, 'a')")
    a.query("create sequence sq")
    # the clock
    a.query("begin")
    t1 = a.query("select now() from one")[4]
    a.query("update one set v = 'b' where k = 1")
    time.sleep(1.3)
    mine = b.query("select now(), v from one")[4]
    t2 = a.query("select now() from one")[4]
    check("now() in a transaction is the same after another connection read beside it a second later, and the reader's is its own and later; the reader sees the row as it was committed",
          t1 == t2 and len(t1) == 1 and mine[0][0] > t1[0][0] and mine[0][1] == b"a", (t1, t2, mine))
    # what waits
    waits = [("an insert", lambda c: c.ask("insert into one values (2, 'x')")),
             ("an update that changes nothing", lambda c: c.ask("update one set v = v where false")),
             ("a select that draws from a sequence", lambda c: c.ask("select nextval('sq') from one")),
             ("a select that sets a sequence", lambda c: c.ask("select setval('sq', 5) from one")),
             ("a select into a table", lambda c: c.ask("select k into two from one")),
             ("a select of one of the engine's own functions", lambda c: c.ask("select cancho_erase('one', '9')")),
             ("a begin", lambda c: c.ask("begin")),
             ("a read and a write in one query", lambda c: c.ask("select k from one; delete from one")),
             ("a write by the extended protocol", lambda c: ext(c, b"", "insert into one values ($1, 'x')", ["3"])),
             ("a select that draws from a sequence, by the extended protocol", lambda c: ext(c, b"", "select nextval('sq') from one where k = $1", ["1"])),
             ("a write prepared under a name, when the unnamed statement is a read",
              lambda c: (c.prepare(b"w", "delete from one where k = $1"), c.prepare(b"", "select k from one"), c.s.sendall(c.bind(b"w", ["1"]) + ew.message(b"E", b"\0\0\0\0\0") + ew.message(b"S", b""))))]
    bad = []
    for name, send in waits:
        c = Client(srv.port)
        send(c)
        if c.answered(0.7) is not None:
            bad.append(name)
        c.s.close()
    check("beside a transaction each of these waits (%s)" % "; ".join(n for n, _ in waits), not bad, bad)
    # and what reads does not, whatever its strings and names say
    reads = ["select v from one where v <> 'nextval' and v <> 'into'", "SELECT count(*) FROM one", "select k as into_x from one", "select k from one;"]
    slow = [q for q in reads if (b.ask(q), b.answered(3))[1] is None]
    # and by the extended protocol: with a parameter, and prepared under a name
    ext(b, b"", "select v from one where k = $1", ["1"])
    by_param = b.answered(3)
    b.prepare(b"r", "select k from one where k >= $1")
    b.s.sendall(b.bind(b"r", ["0"]) + ew.message(b"E", b"\0\0\0\0\0") + ew.message(b"S", b""))
    by_name = b.answered(3)
    if by_param is None or by_param[4] != [[b"a"]]:
        slow.append("by the extended protocol, with a parameter: %r" % (by_param,))
    if by_name is None or by_name[4] != [[b"1"]]:
        slow.append("by the extended protocol, prepared under a name: %r" % (by_name,))
    check("and each of these is answered (%d selects, with the words of the rule in a string, in a name, and a semicolon at the end; and two by the extended protocol)" % len(reads), not slow, slow)
    a.query("commit")
    after = b.query("select v from one")[4]
    b2 = Client(srv.port)
    check("after the commit the reader sees it, and the statements that waited and were dropped changed nothing", after == [[b"b"]] and b2.query("select count(*) from one")[4] == [[b"1"]], after)
    for c in (a, b, b2):
        c.close()
    srv.stop()


def main():
    with tempfile.TemporaryDirectory() as d:
        interleaved(d)
        rules(d)
    if ew.FAILED:
        print("FAIL engine beside: %d failed" % len(ew.FAILED))
        return 1
    print("PASS engine beside")
    return 0


if __name__ == "__main__":
    sys.exit(main())
