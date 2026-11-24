#!/usr/bin/env python3
"""The engine's server under load for a while (docs/m3-engine.md 6az).

    python3 tests/engine_soak.py SERVER_BINARY ENGINECHECK_BINARY SECONDS [SEED [archive]]

Not a differential: several clients at once have no single order to compare with. What is held is what must be true whatever the order:

  * money moves between 200 accounts in transactions and is never made or lost: every reader's `sum(cents)` is the first sum, always;
  * a journal gets one row for every transfer acknowledged, and at the end has exactly those (none lost, none twice, none that was not acknowledged, except
    the one in flight when the server was killed, which may be there or not);
  * every so often the export tool (6av) takes an anchor, the log and the facts beside the running server: a run is whole and verifies, or says it raced;
  * a client takes the head of the log (6ax) and the next export holds it (`--expect`);
  * every so often the server is killed (SIGKILL) and started again;
  * the page file's size is noted through the run (6aw): what it does over time is the measurement, and it must stay under a bound per commit;
  * at the end, everything the tool exports at one anchor verifies: the chain, every commit's changes, and the replay ends at the rows the file holds.

It prints a line every 30 seconds and a summary. Seconds is the length of the load; the gate runs a short one, the long ones are run by hand and reported in the design.
"""
import os
import random
import signal
import subprocess
import sys
import tempfile
import threading
import time

SERVER, HARNESS, SECONDS = sys.argv[1], sys.argv[2], int(sys.argv[3])
SEED = int(sys.argv[4]) if len(sys.argv) > 4 else 1
ARCHIVE = len(sys.argv) > 5 and sys.argv[5] == "archive"       # the exporter has the server take out of the page file what the copy has (6ba)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.argv = ["engine_wire.py", SERVER, HARNESS, "0", str(SEED)]
sys.path.insert(0, os.path.join(ROOT, "tests"))
import engine_wire as ew  # noqa: E402  (its Server and Client; its checks are not run)

TOOL = os.environ.get("LOGEXPORT", os.path.join(ROOT, "build", "logexport"))
ACCOUNTS, WRITERS, START = 200, 4, 1000
FAILED = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else "   " + str(detail)[:600]), flush=True)
    if not ok:
        FAILED.append(name)


class Shared:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = False
        self.port = 0
        self.acked = set()         # the transfers a client was told are committed
        self.maybe = set()         # those whose commit was sent and never answered (the server was killed)
        self.sums = 0              # how many times a reader saw the sum
        self.wrong = []            # what must not happen
        self.refused = 0           # transfers that would overdraw: rolled back by the client
        self.reconnects = 0


def connect(sh):
    """A connection to the server as it is now; it may be between two lives."""
    for _ in range(200):
        if sh.stop:
            return None
        try:
            return ew.Client(sh.port)
        except Exception:
            time.sleep(0.05)
    return None


def ask(c, sql):
    """An answer, or an error if the server ended the connection before it was whole (it was killed)."""
    got = c.query(sql)
    if c.status == "closed":
        raise EOFError
    return got


def writer(sh, w):
    rng = random.Random(SEED * 1000 + w)
    c, n = connect(sh), 0
    while not sh.stop and c is not None:
        a, b = rng.randrange(ACCOUNTS), rng.randrange(ACCOUNTS)
        amount = rng.randrange(1, 50)
        tid = w * 100000000 + n
        n += 1
        sent_commit = False
        try:
            if a == b:
                continue
            ask(c, "begin")
            left = ask(c, "select cents from acct where id = %d" % a)[4]
            if not left or int(left[0][0]) < amount:
                ask(c, "rollback")
                with sh.lock:
                    sh.refused += 1
                continue
            r1 = ask(c, "update acct set cents = cents - %d where id = %d" % (amount, a))
            r2 = ask(c, "update acct set cents = cents + %d where id = %d" % (amount, b))
            r3 = ask(c, "insert into journal values (%d, %d, %d, %d)" % (tid, a, b, amount))
            if (r1[5], r2[5], r3[5]) != ("UPDATE 1", "UPDATE 1", "INSERT 0 1"):
                # another connection's transaction ended ours (the idle limit), or the server is going: nothing of it may stay
                ask(c, "rollback")
                continue
            sent_commit = True
            done = ask(c, "commit")
            if done[5] == "COMMIT":
                with sh.lock:
                    sh.acked.add(tid)
            elif done[5] != "ROLLBACK":
                with sh.lock:
                    sh.wrong.append(("a commit answered", done[:2], done[5]))
        except Exception:
            # the server was killed under us: a commit sent and not answered may have been made
            if sent_commit:
                with sh.lock:
                    sh.maybe.add(tid)
            try:
                c.s.close()
            except Exception:
                pass
            with sh.lock:
                sh.reconnects += 1
            c = connect(sh)
    if c is not None:
        try:
            c.close()
        except Exception:
            pass


def reader(sh):
    c = connect(sh)
    while not sh.stop and c is not None:
        try:
            got = ask(c, "select sum(cents), count(*) from acct")[4]
            if got != [[str(ACCOUNTS * START).encode(), str(ACCOUNTS).encode()]]:
                with sh.lock:
                    sh.wrong.append(("the sum", got))
            with sh.lock:
                sh.sums += 1
            time.sleep(0.01)
        except Exception:
            try:
                c.s.close()
            except Exception:
                pass
            c = connect(sh)
    if c is not None:
        try:
            c.close()
        except Exception:
            pass


def export(path, *what):
    r = subprocess.run([TOOL, path] + [str(x) for x in what], capture_output=True)
    return r.returncode, r.stdout, r.stderr.decode().strip()


def verify(d, log, more=()):
    with open(os.path.join(d, "s.log"), "wb") as f:
        f.write(log)
    tool = "l3a.py" if "--deltas" in more else "verify.py"
    return subprocess.run([sys.executable, os.path.join(ROOT, "tools", tool), os.path.join(d, "s.log")] + list(more), capture_output=True, text=True).stdout.strip()


def main():
    rng = random.Random(SEED)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "soak.db")
        srv = ew.Server(path)
        sh = Shared()
        sh.port = srv.port
        c = ew.Client(srv.port)
        c.query("create table acct (id integer primary key, cents integer not null)")
        c.query("create table journal (tid bigint primary key, src integer not null, dst integer not null, amount integer not null)")
        for i in range(0, ACCOUNTS, 50):
            c.query("insert into acct values " + ", ".join("(%d, %d)" % (k, START) for k in range(i, i + 50)))
        c.close()
        threads = [threading.Thread(target=writer, args=(sh, w)) for w in range(WRITERS)] + [threading.Thread(target=reader, args=(sh,)) for _ in range(2)]
        for t in threads:
            t.start()
        t0 = time.time()
        whole = raced = sets = kills = held = 0
        odd, sizes, anchor, last_n = [], [], None, 0
        have, copy_log, copy_facts, copy_stmts, archived = 0, b"", b"", b"", 0
        next_line, next_kill = t0 + 30, t0 + rng.uniform(20, 40)
        while time.time() - t0 < SECONDS:
            time.sleep(rng.uniform(0.2, 0.6))
            # a client takes the head; the next whole export must hold it
            if anchor is None:
                try:
                    cc = ew.Client(sh.port)
                    got = cc.query("select cancho_last_commit()")[4]
                    cc.close()
                    if got and got[0][1]:
                        anchor = got[0][1].decode()
                except Exception:
                    pass
            st, out, err = export(path, "anchor")
            if st == 0:
                n = int(out.split()[1])
                if n < last_n:
                    odd.append(("the log got shorter", n, last_n))
                last_n = n
                # the copy is kept up in parts (6az): what is new since the last part, appended
                a, b, c3 = export(path, "log", n, have), export(path, "facts", n, have), export(path, "stmts", n, have)
                for st2, _, err2 in (a, b, c3):
                    if st2 == 0:
                        whole += 1
                    elif (st2, err2) == (1, "refused export-raced"):
                        raced += 1
                    else:
                        odd.append((st2, err2))
                if a[0] == 0 and b[0] == 0 and c3[0] == 0:
                    copy_log += a[1]
                    copy_facts += b[1]
                    copy_stmts += c3[1]
                    have = n
                    sets += 1
                    if ARCHIVE:
                        # the copy has them: the server may take them out of its file (128 commits a call)
                        try:
                            cc = ew.Client(sh.port)
                            floor = -1
                            for _ in range(200):
                                got = cc.query("select cancho_log_archive(%d)" % have)
                                if cc.status == "closed" or not got[4]:
                                    break
                                floor = int(got[4][0][0])
                                if floor >= have:
                                    break
                            cc.close()
                            if floor >= 0:
                                archived = max(archived, floor)
                        except Exception:
                            pass
                    if sets % 10 == 0 or anchor:
                        v = verify(d, copy_log, ["--expect", anchor] if anchor else [])
                        if not v.startswith("ok commits=%d " % n):
                            # (a head taken after this part was read is not in it yet: the next part has it)
                            if not (anchor and v.startswith("reject rule=expected-missing")):
                                odd.append(("log", n, v))
                        elif anchor:
                            held += 1
                            anchor = None
                    if sets % 25 == 0:
                        # the facts of every commit so far: now and then, the replay being the long part
                        with open(os.path.join(d, "s.facts"), "wb") as f:
                            f.write(copy_facts)
                        v = verify(d, copy_log, ["--deltas", os.path.join(d, "s.facts")])
                        if not v.startswith("ok commits=%d " % n):
                            odd.append(("facts", n, v))
            elif (st, err) == (1, "refused export-raced"):
                raced += 1
            else:
                odd.append((st, err))
            now = time.time()
            if now >= next_kill:
                srv.stop(signal.SIGKILL)
                kills += 1
                srv = ew.Server(path)
                sh.port = srv.port
                next_kill = now + rng.uniform(20, 40)
            if now >= next_line:
                sizes.append((int(now - t0), last_n, os.path.getsize(path)))
                with sh.lock:
                    print("     %4d s: %6d commits, %6d transfers acknowledged, %6d sums read, page file %.1f MiB, %d kills, exports %d whole %d raced"
                          % (now - t0, last_n, len(sh.acked), sh.sums, os.path.getsize(path) / 1048576, kills, whole, raced), flush=True)
                next_line = now + 30
        sh.stop = True
        for t in threads:
            t.join()
        # the end: one more life, and everything at one anchor
        srv.stop()
        srv = ew.Server(path)
        c = ew.Client(srv.port)
        total = c.query("select sum(cents), count(*) from acct")[4]
        low = c.query("select count(*) from acct where cents < 0")[4]
        tids = set()
        for w in range(WRITERS):
            # by writer, so that no answer is larger than the server's buffers hold in one statement's rows
            lo = w * 100000000
            for row in c.query("select tid from journal where tid >= %d and tid < %d" % (lo, lo + 100000000))[4]:
                tids.add(int(row[0]))
        moved = c.query("select sum(amount) from journal")[4]
        c.close()
        srv.stop()
        check("money is never made or lost: %d readings of the sum during the load, all the first sum; at the end %d cents in %d accounts, none below zero"
              % (sh.sums, ACCOUNTS * START, ACCOUNTS), not sh.wrong and sh.sums > 10 and total == [[str(ACCOUNTS * START).encode(), str(ACCOUNTS).encode()]] and low == [[b"0"]],
              (sh.wrong[:3], total, low))
        lost, extra = sh.acked - tids, tids - sh.acked - sh.maybe
        check("the journal has every transfer acknowledged (%d) and nothing else but commits sent and never answered (%d of %d such are there); %d would have overdrawn and were rolled back"
              % (len(sh.acked), len(tids & sh.maybe), len(sh.maybe), sh.refused), not lost and not extra and len(sh.acked) > 10, (sorted(lost)[:5], sorted(extra)[:5]))
        check("the export tool beside the load: %d runs whole, the copy verifying (%d times holding the head a client had taken), %d parts appended; %d runs raced; nothing else"
              % (whole, held, sets, raced), not odd and whole > 0 and (held > 0 or SECONDS < 20), odd[:3])
        st, out, err = export(path, "anchor")
        n = int(out.split()[1]) if st == 0 else -1
        floor = int(export(path, "floor")[1].split()[1])
        # what the copy lacks, from where it ends; the copy with it is the whole log
        rest = {w: export(path, w, n, have) for w in ("log", "facts", "stmts")}
        files = {"log": (rest["log"][0], copy_log + rest["log"][1]), "facts": (rest["facts"][0], copy_facts + rest["facts"][1]), "live": export(path, "live", n)}
        for w in files:
            with open(os.path.join(d, "e." + w), "wb") as f:
                f.write(files[w][1])
        if ARCHIVE:
            check("the server took out of its file what the copy had: the floor is %d of %d commits (the copy has %d), and from before the floor the tool is refused export-archived"
                  % (floor, n, have), 0 < floor <= have and floor == archived and export(path, "log", n, 0)[::2] == (1, "refused export-archived"), (floor, archived, have, n))
        else:
            whole = export(path, "log", n, 0), export(path, "facts", n, 0)
            check("the copy kept up in parts through the load (%d commits of %d) and what it lacks are the log and the store exported whole at the end, byte for byte" % (have, n),
                  have > 0 and floor == 0 and whole[0][1] == files["log"][1] and whole[1][1] == files["facts"][1], (have, n, floor))
        t1 = time.time()
        v = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "l3a.py"), os.path.join(d, "e.log"), "--deltas", os.path.join(d, "e.facts"), "--live-dump", os.path.join(d, "e.live")],
                           capture_output=True, text=True).stdout.strip()
        check("at the end, %d commits through %d kills: the copy's log and facts and the rows the file holds verify, the replay ending at those rows (%.0f s to verify)"
              % (n, kills, time.time() - t1), all(files[w][0] == 0 for w in files) and v.startswith("ok commits=%d " % n) and v.endswith(" final"), v)
        use = export(path, "usage")[1].decode().strip().replace("usage ", "").replace("\n", "; ")
        print("     what the file holds (entries, bytes): " + use)
        size = os.path.getsize(path)
        check("the page file: %.1f MiB after %d commits, %.1f KiB a commit (%s)" % (size / 1048576, n, size / 1024 / max(n, 1),
              "the log taken out as it is copied: the rows and their history are what grows" if ARCHIVE else "the history of every row and the whole log are in it"),
              n > 0 and size / max(n, 1) < 64 * 1024, sizes[-3:])
        print("sizes (s, commits, bytes): " + " ".join("%d:%d:%d" % s for s in sizes))
    if FAILED:
        print("FAIL engine soak: %d failed" % len(FAILED))
        return 1
    print("PASS engine soak")
    return 0


if __name__ == "__main__":
    sys.exit(main())
