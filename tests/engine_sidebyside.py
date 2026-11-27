#!/usr/bin/env python3
"""Transactions side by side (docs/m3-engine.md 6bv).

    python3 tests/engine_sidebyside.py ENGINE_SERVER ENGINECHECK TRANSACTIONS SEED

The oracle is the server itself, one client at a time: every history must be one a single client could have produced.

  * Four connections run random transactions beside the others (`begin isolation level serializable`), with statements outside any transaction among them, interleaved
    by a seeded schedule. Then everything is run again by one connection on a fresh server, each transaction whole: one that committed having written, where it
    committed; any other (one that only read, was rolled back, failed, or was refused) where it began, ended with what it ended with (a refused one with a rollback).
    Every statement must get the answer it got, and the tables at the end must be the same. The log of the first server verifies.
  * Fixed cases: who is refused and who is not; a plain transaction beside one that is not; counters; the clock.
  * The file is not swept while one is open, an erase then is refused, and one that idles while a sweep is due is ended.
"""
import os
import random
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine_wire as ew  # noqa: E402  (the server, the client, the checks; it reads the command line)

check, Server, Client, ec = ew.check, ew.Server, ew.Client, ew.ec
BEGINS = ["begin isolation level serializable", "start transaction isolation level repeatable read", "begin transaction isolation level serializable", "BEGIN WORK ISOLATION LEVEL REPEATABLE READ"]
DUMPS = ["select * from acc order by k", "select * from led order by n"]


def statement(rng, who):
    """A statement over the two tables every connection shares: keys few enough that they meet."""
    k, r = rng.randrange(24), rng.random()
    if r < 0.22:
        return "insert into acc values (%d, %d, 'c%d')" % (k, rng.randrange(100), who)
    if r < 0.42:
        return "update acc set v = v + %d where k = %d" % (rng.randrange(1, 9), k)
    if r < 0.50:
        return "update acc set v = v - 1, who = 'c%d' where v > %d" % (who, rng.randrange(40, 120))
    if r < 0.58:
        return "delete from acc where k = %d" % k
    if r < 0.66:
        return "insert into led (n, k, note) values (%d, %d, 'by c%d')" % (rng.randrange(100000), k, who)
    if r < 0.80:
        return "select k, v, who from acc where k between %d and %d order by k" % (k, k + rng.randrange(8))
    if r < 0.90:
        return "select count(*), sum(v), min(k), max(k) from acc"
    return "select count(*) from led where k = %d" % k


def seen(ans):
    """What of an answer must be the same when the history is run by one client: the SQLSTATE, the rows, the tag."""
    return ans[0], ans[4], ans[5]


def schedule(d, units, seed):
    rng = random.Random(seed * 104729 + 7)
    setup = ["create table acc (k integer primary key, v integer not null, who text)", "create table led (n integer primary key, k integer, note text)",
             "insert into acc values " + ", ".join("(%d, %d, 'start')" % (k, 50 + k) for k in range(0, 24, 3))]
    srv = Server(os.path.join(d, "side.db"))
    conns = [Client(srv.port) for _ in range(4)]
    for s in setup:
        conns[0].query(s)
    # each connection's work: a unit is a transaction beside the others, or one statement outside any
    open_txn = [None] * 4                    # for a connection in a transaction: its record
    done = []                                # every unit, as it was run: {"at": where it goes in the one client's order, "sql": [...], "got": [...]}
    step, started = 0, 0
    counts = {"committed having written": 0, "committed having only read": 0, "refused": 0, "rolled back": 0, "failed": 0, "outside": 0}
    while started < units or any(open_txn):
        step += 1
        i = rng.randrange(4)
        c, t = conns[i], open_txn[i]
        if t is None:
            if started >= units:
                continue
            started += 1
            if rng.random() < 0.30:
                sql = statement(rng, i)
                done.append({"at": step, "sql": [sql], "got": [seen(c.query(sql))], "end": None})
                counts["outside"] += 1
            else:
                first = rng.choice(BEGINS)
                got = c.query(first)
                if got[5] != "BEGIN" or c.status != "T":
                    raise SystemExit("engine_sidebyside: %s: %r" % (first, got))
                open_txn[i] = {"began": step, "sql": [], "got": [], "left": rng.randrange(1, 6), "wrote": False}
        elif t["left"] > 0:
            t["left"] -= 1
            sql = statement(rng, i)
            got = c.query(sql)
            t["sql"].append(sql)
            t["got"].append(seen(got))
            if got[0] is None and got[5] and got[5].split()[0] in ("INSERT", "UPDATE", "DELETE") and not got[5].endswith(" 0"):
                t["wrote"] = True
        else:
            failed = c.status == "E"
            how = "rollback" if rng.random() < 0.15 else "commit"
            got = c.query(how)
            if c.status != "I":
                raise SystemExit("engine_sidebyside: after %s the connection is in %r" % (how, c.status))
            if got[0] is not None:
                # refused: it had written, and the branch had moved. Nothing else is a reason, and nothing else is the answer
                if how != "commit" or (got[0], got[1]) != ("40001", "cancho-db: refused serialization-failure") or not t["wrote"]:
                    raise SystemExit("engine_sidebyside: a %s answered %r (wrote: %s)" % (how, got[:2], t["wrote"]))
                kind, at, end = "refused", t["began"], "rollback"
            elif how == "rollback" or failed:
                kind, at, end = ("failed" if failed else "rolled back"), t["began"], how
                if got[5] != "ROLLBACK":
                    raise SystemExit("engine_sidebyside: a %s of a transaction that %s answered %r" % (how, kind, got[5]))
            elif t["wrote"]:
                kind, at, end = "committed having written", step, "commit"
            else:
                kind, at, end = "committed having only read", t["began"], "commit"
            counts[kind] += 1
            done.append({"at": at, "sql": t["sql"], "got": t["got"], "end": end})
            open_txn[i] = None
    finals = [seen(conns[0].query(q)) for q in DUMPS]
    for c in conns:
        c.close()
    srv.stop()
    # one client, a fresh server, the same history in the order the rule says it happened in
    done.sort(key=lambda u: u["at"])
    srv2 = Server(os.path.join(d, "one.db"))
    one = Client(srv2.port)
    for s in setup:
        one.query(s)
    bad, n = [], 0
    for u in done:
        if u["end"] is not None:
            one.query("begin")
        for sql, want in zip(u["sql"], u["got"]):
            n += 1
            got = seen(one.query(sql))
            if got != want and len(bad) < 4:
                bad.append((sql, "side by side: %r" % (want,), "one client: %r" % (got,)))
        if u["end"] is not None:
            one.query(u["end"])
    alone = [seen(one.query(q)) for q in DUMPS]
    one.close()
    srv2.stop()
    check("%d transactions and statements of four connections side by side (%s): run again by one client in the order the rule gives, each of the %d statements gets the answer it got, and the tables end the same"
          % (len(done), ", ".join("%d %s" % (v, k) for k, v in counts.items()), n), not bad and finals == alone and counts["refused"] > 3 and counts["committed having written"] > 3
          and counts["committed having only read"] > 0, bad or (counts, finals[0][1][:3], alone[0][1][:3]))
    history = setup + [s for u in done for s in u["sql"]]
    ew.verified(d, os.path.join(d, "side.db"), history, "transactions side by side")


def fixed(d):
    srv = Server(os.path.join(d, "fixed.db"))
    a, b, c = Client(srv.port), Client(srv.port), Client(srv.port)
    c.query("create table t (k integer primary key, v integer)")
    c.query("insert into t values (1, 10), (2, 20)")
    c.query("create sequence sq")
    side = "begin isolation level serializable"
    # two that write different rows: the first to commit wins, the other is refused. (The second part, 6bv, is to let both commit; this is the line it must change.)
    a.query(side), b.query(side)
    a.query("update t set v = v + 1 where k = 1"), b.query("update t set v = v + 5 where k = 2")
    mine, theirs, outside = a.query("select v from t order by k")[4], b.query("select v from t order by k")[4], c.query("select v from t order by k")[4]
    first, second = a.query("commit"), b.query("commit")
    after = c.query("select v from t order by k")[4]
    check("two beside each other that write different rows: each sees its own write and not the other's, nobody outside sees either; the first to commit does, the second is refused 40001 and nothing of it is there",
          mine == [[b"11"], [b"20"]] and theirs == [[b"10"], [b"25"]] and outside == [[b"10"], [b"20"]] and first[5] == "COMMIT" and (second[0], second[1]) == ("40001", "cancho-db: refused serialization-failure")
          and b.status == "I" and after == [[b"11"], [b"20"]], (mine, theirs, outside, first[5], second[:2], after))
    # one that only reads commits whatever was written meanwhile, and read one state throughout
    a.query(side)
    r1 = a.query("select v from t order by k")[4]
    c.query("insert into t values (3, 30)")
    c.query("update t set v = 0 where k = 1")
    r2 = a.query("select v from t order by k")[4]
    done = a.query("commit")
    r3 = a.query("select v from t order by k")[4]
    check("one that only reads sees one state while others write, and commits", r1 == r2 == [[b"11"], [b"20"]] and done[5] == "COMMIT" and done[0] is None and r3 == [[b"0"], [b"20"], [b"30"]], (r1, r2, done[:2], r3))
    # a statement outside any transaction, beside an open one that has written: it commits at once, and the open one has lost
    a.query(side)
    a.query("update t set v = 99 where k = 3")
    quick = c.query("update t set v = v + 1 where k = 2")
    lost = a.query("commit")
    check("a statement outside any transaction does not wait for one beside it, which is then refused", quick[5] == "UPDATE 1" and lost[0] == "40001" and c.query("select v from t where k = 3")[4] == [[b"30"]], (quick[5], lost[:2]))
    # a plain transaction has the database to itself: one beside it goes on on its own tree, and its end waits for the plain one's
    a.query(side)
    b.query("begin")
    b.query("update t set v = 1000 where k = 1")
    went = a.query("update t set v = 7 where k = 3")
    a.ask("commit")
    early = a.answered(0.5)
    plain = b.query("commit")
    late = a.answered(5)
    check("a plain transaction is never refused; one beside it runs its statements meanwhile, waits at its commit for the plain one to end, and is then refused for what the plain one wrote",
          went[5] == "UPDATE 1" and early is None and plain[5] == "COMMIT" and plain[0] is None and late is not None and late[0] == "40001" and c.query("select v from t where k in (1, 3) order by k")[4] == [[b"1000"], [b"30"]],
          (went[5], early, plain[:2], late and late[:2]))
    # counters: inside a transaction beside the others a number is drawn from the counter as it was when the transaction began, so two may draw the same one;
    # a draw counts as a write, so only one of them commits and the other's number is void. No number is ever held by two that committed
    a.query(side), b.query(side)
    n1 = a.query("insert into t values (nextval('sq') + 100, 1) returning k")[4]
    n2 = b.query("insert into t values (nextval('sq') + 100, 2) returning k")[4]
    won = a.query("commit")
    refused = b.query("commit")
    n3 = c.query("insert into t values (nextval('sq') + 100, 3) returning k")[4]
    check("two beside each other draw from a counter: one commits with its number, the other is refused, and the next number drawn is a new one", n1 == [[b"101"]] and won[5] == "COMMIT" and refused[0] == "40001" and n3 == [[b"102"]],
          (n1, n2, won[5], refused[:2], n3))
    # one that only drew (an insert that met a row that was there, and so wrote none) while another drew outside: it is refused, though it changed no row.
    # (A select cannot draw: the engine refuses `select nextval(...)`.)
    draw = "insert into t values (1, nextval('sq')) on conflict do nothing"
    a.query(side)
    d1 = a.query(draw)[5]
    d2 = c.query("insert into t values (nextval('sq') + 100, 4) returning k")[4]
    void = a.query("commit")
    d3 = c.query("insert into t values (nextval('sq') + 100, 5) returning k")[4]
    check("one that only drew a number (the counter is in its tree: it has written) is refused when another drew outside meanwhile, and the counter goes on from the other's", d1 == "INSERT 0 0" and d2 == [[b"103"]] and void[0] == "40001" and d3 == [[b"104"]], (d1, d2, void[:2], d3))
    # and one that drew with nobody else committing keeps its number
    a.query(side)
    a.query(draw)
    kept = a.query("commit")
    d5 = c.query("insert into t values (nextval('sq') + 100, 6) returning k")[4]
    check("one that drew a number with nobody committing meanwhile commits, and its number is not given again", kept[5] == "COMMIT" and kept[0] is None and d5 == [[b"106"]], (kept[:2], d5))
    # what one drew stays drawn when it is rolled back, whatever others ran meanwhile: its draws are its own, kept across the statements of other connections
    a.query(side)
    mine = int(a.query("insert into t values (nextval('sq') + 100, 7) returning k")[4][0][0])
    c.query("select count(*) from t")
    b.query(side), b.query("select count(*) from t"), b.query("commit")
    a.query("rollback")
    nxt = int(c.query("insert into t values (nextval('sq') + 100, 8) returning k")[4][0][0])
    check("a number drawn in one that is rolled back, with other connections' statements in between, is not given again", nxt == mine + 1, (mine, nxt))
    # the clock is each one's own
    a.query(side)
    t1 = a.query("select now() from t where k = 1")[4]
    time.sleep(1.2)
    b.query(side)
    t2 = b.query("select now() from t where k = 1")[4]
    t3 = a.query("select now() from t where k = 1")[4]
    a.query("commit"), b.query("commit")
    check("now() is the time each began", t1 == t3 and t2 > t1, (t1, t2, t3))
    # what is no beginning of one: these are refused as every option of BEGIN is, and no transaction is open after
    bad = [q for q in ("begin isolation level read committed", "begin isolation level serializable read only", "begin isolation level", "begin isolation level repeatable read write") if a.query(q)[0] is None or a.status != "I"]
    check("an isolation level that is neither, or with more after it, is refused and begins nothing", not bad, bad)
    # END is a commit, and is held to the same rule; ABORT is a rollback
    a.query(side)
    a.query("update t set v = v + 1 where k = 2")
    c.query("update t set v = v + 1 where k = 3")
    ended = a.query("end")
    a.query(side)
    a.query("delete from t")
    aborted = a.query("abort")
    check("END is refused as COMMIT is, and ABORT rolls back", ended[0] == "40001" and aborted[5] == "ROLLBACK" and a.status == "I" and c.query("select count(*) from t")[4] != [[b"0"]], (ended[:2], aborted[5]))
    # by the extended protocol, as a driver sends it
    x = a.extended(side, [])
    a.extended("update t set v = v + $1 where k = $2", ["1", "2"])
    y = c.query("update t set v = 5 where k = 1")
    z = a.extended("commit", [])
    check("by the extended protocol: it begins, writes, and is refused at its commit after another's write", x[5] == "BEGIN" and y[5] == "UPDATE 1" and z[0] == "40001", (x[5], y[5], z[:2]))
    # a connection that goes away inside one: nothing of it is there, and the others go on
    before = c.query("select * from t order by k")[4]
    a.query(side)
    a.query("delete from t")
    a.close(False)
    time.sleep(0.3)
    a = Client(srv.port)
    check("a connection that ends inside one leaves nothing", a.query("select * from t order by k")[4] == before and len(before) > 3 and srv.alive(), before)
    for x in (a, b, c):
        x.close()
    srv.stop()


def pages(d):
    """The file is not swept while a transaction beside the others is open (its tree is pages no committed tree names)."""
    path = os.path.join(d, "pages.db")
    srv = Server(path, 1500, 10000)
    a, b = Client(srv.port), Client(srv.port)
    b.query("create table big (k integer primary key, v text)")
    b.query("create table mine (k integer primary key, v text)")
    for lo in range(0, 2000, 200):
        b.query("insert into big values " + ", ".join("(%d, '%s')" % (k, "x" * 60) for k in range(lo, lo + 200)))
    a.query("begin isolation level serializable")
    for lo in range(0, 1000, 200):
        a.query("insert into mine values " + ", ".join("(%d, 'mine-%06d')" % (k, k) for k in range(lo, lo + 200)))
    erase = b.query("select cancho_erase('big', '[1]')")
    # the other connection rewrites its table many times: the file grows past where it is swept, and every page a sweep freed would be written again
    for r in range(12):
        b.query("update big set v = '%s'" % (("%02d" % r) * 30))
        a.query("select count(*) from mine")                       # (it does something: it is not idle)
    rows = a.query("select k, v from mine order by k")[4]
    ok = rows == [[str(k).encode(), b"mine-%06d" % k] for k in range(1000)]
    lost = a.query("commit")
    check("while one beside the others is open and another connection rewrites 2,000 rows twelve times, its own thousand rows are whole, and an erase is refused; it is then refused, having written",
          ok and (erase[0], erase[1]) == ("25001", "cancho-db: refused erase-beside-transaction") and lost[0] == "40001" and srv.alive(), (len(rows), erase[:2], lost[:2]))
    erased = b.query("select cancho_erase('big', '[1]')")
    check("when it has ended an erase runs", erased[0] is None and b.query("select count(*) from big")[4] == [[b"1999"]], erased[:2])
    # one that idles while a sweep is due is ended
    a.query("begin isolation level serializable")
    a.query("select count(*) from big")
    t0 = time.time()
    msgs, took = [], None
    while time.time() - t0 < 8 and took is None:
        b.query("update big set v = 'again' where k < 400")
        b.query("update big set v = 'more' where k < 400")
        a.s.settimeout(0.05)
        try:
            msgs.append(a.msg())
            took = time.time() - t0
        except (OSError, EOFError):
            pass
    fatal = a.answer(msgs) if msgs else None
    check("one that is idle past the limit (1.5 s) while the file waits to be swept is ended with 25P03", fatal is not None and fatal[0] == "25P03" and took is not None and took > 1.4, (fatal and fatal[:2], took))
    again = b.query("select cancho_erase('big', '[2]')")
    after = b.query("select count(*) from big")[4]
    b.close()
    srv.stop()
    dump = ec.run_engine(path, ["select count(*) from big", "select count(*) from mine"])
    check("an erase runs once the server has ended it, and the page file, read whole by the test program afterwards, holds the tables", again[0] is None and after == [[b"1998"]] and [b[0] for b in dump] == ["ok SELECT 1", "ok SELECT 1"], (again[:2], after, [b[:2] for b in dump]))
    # one that idles with no sweep due is left alone
    srv = Server(os.path.join(d, "quiet.db"), 1500, 10000)
    q = Client(srv.port)
    q.query("create table q (k integer primary key)")
    q.query("begin isolation level serializable")
    q.query("insert into q values (1)")
    time.sleep(3.2)
    still = q.query("commit")
    check("one that idles past the limit with no sweep due is left alone", still[5] == "COMMIT" and still[0] is None, still[:2])
    q.close()
    srv.stop()


def main():
    with tempfile.TemporaryDirectory() as d:
        schedule(d, ew.COUNT, ew.SEED)
        fixed(d)
        pages(d)
    if ew.FAILED:
        print("FAIL engine side by side: %d failed" % len(ew.FAILED))
        return 1
    print("PASS engine side by side")
    return 0


if __name__ == "__main__":
    sys.exit(main())
