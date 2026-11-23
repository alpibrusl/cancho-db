#!/usr/bin/env python3
"""cancho-hooks, the program, against the engine's server: no PostgreSQL (docs/m3-engine.md 6an).

    HOOKS_BIN=/path/to/hooks [HOOKS_REPO=/path/to/cancho-hooks] python3 tests/hooks_server.py ENGINE_SERVER

tests/hooks_check.py asks whether the engine answers hooks' statements. This asks whether hooks runs: its schema is applied with psql (sql/schema.sql, the copy in
tests/hooks/), an endpoint is put in its table, the service is started with `--pg-host` at the engine's server and a receiver is started for it to deliver to. Then events
are posted to the service, and:

  * the service says it is ready, and that it read its endpoints from the database;
  * every event is delivered to the receiver;
  * every attempt is a row the service wrote through the engine, read back through the service's own API (`GET /events/:id/attempts`), and, once the service is
    stopped, with psql from the engine's page file: the same rows.

The service is a binary built from cancho-hooks' repository (`scripts/build.sh --pure`); without HOOKS_BIN the test is skipped and says so. With HOOKS_REPO (that
repository) hooks' own test of the feature is run against the engine too: 11 scenarios of a service whose database is there, absent, silent, cut off, wrong (6ar). What is measured is what it
says: one service, one endpoint, a few events. It is not hooks' own test suite (6an and 6aq say how far that runs against the engine).
"""
import base64
import http.server
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = sys.argv[1]
HOOKS = os.environ.get("HOOKS_BIN", "")
FAILED = []
EVENTS = 12


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


def psql(port, *args):
    return subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(port), "-U", "hooks", "-d", "hooks", "-X", "-At"] + list(args), capture_output=True, text=True)


class Receiver(http.server.BaseHTTPRequestHandler):
    got = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        Receiver.got.append(json.loads(body))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


def get(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read())


# What hooks' own test does that is the administration of a PostgreSQL, not a use of a database: the role its scenario 9 makes, grants to, looks for in
# pg_stat_activity and drops. The engine has no roles (no login at all yet, 6al). These lines are cut from a copy of the test; nothing else is touched.
ROLE_LINES = ['    psql("drop role if exists hooks")\n', '    psql("create role hooks login")\n', '    psql("grant insert, select on attempts to hooks")\n',
              '    psql("grant select on endpoints to hooks")\n', '    psql("revoke insert, select on attempts from hooks")\n', '    psql("revoke select on endpoints from hooks")\n',
              '    psql("drop role hooks")\n']
ROLE_CHECK = ('        check("9. ... and the server sees the connections as user hooks on database hooks",', '        stop(svc)\n')


def own_test():
    """cancho-hooks' own test of its history in PostgreSQL (tests/history_test.py of its repository, HOOKS_REPO), against the engine's server: unchanged, as far as it
    gets; and a copy with the role administration of its scenario 9 cut, which must pass every check it has left."""
    repo = os.environ.get("HOOKS_REPO", "")
    src = os.path.join(repo, "tests", "history_test.py")
    if not repo or not os.path.exists(src):
        print("skip hooks' own history test against the engine: no HOOKS_REPO (cancho-hooks' repository)")
        return
    text = open(src).read()
    cut = text
    for line in ROLE_LINES:
        if cut.count(line) != 1:
            check("hooks' own test has the role lines this test cuts (it has changed: cut them by hand)", False, line)
            return
        cut = cut.replace(line, "")
    a = cut.find(ROLE_CHECK[0])
    b = cut.find(ROLE_CHECK[1], a)
    if a < 0 or b < 0:
        check("hooks' own test has the pg_stat_activity check this test cuts (it has changed: cut it by hand)", False)
        return
    cut = cut[:a] + cut[b:]
    copy = os.path.join(repo, "tests", "history_test_no_roles.py")
    open(copy, "w").write(cut)
    try:
        for name, path, want in (("unchanged", src, None), ("with the role administration of scenario 9 cut", copy, 0)):
            with tempfile.TemporaryDirectory() as d:
                port = free_port()
                srv = subprocess.Popen([SERVER, os.path.join(d, "own.db"), str(port)], stderr=subprocess.PIPE)
                srv.stderr.readline()
                r = subprocess.run([sys.executable, path, HOOKS], capture_output=True, text=True, cwd=repo, timeout=900, env=dict(os.environ, HOOKS_PG="127.0.0.1:%d:hooks:hooks" % port))
                srv.send_signal(signal.SIGTERM)
                srv.wait()
            oks = sum(1 for l in r.stdout.splitlines() if l.startswith("ok "))
            fails = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
            last = [l for l in (r.stdout + r.stderr).splitlines() if l.strip()][-1:]
            print("     hooks' own history test, %s: %d checks pass, %d fail, status %d; its last line: %s" % (name, oks, len(fails), r.returncode, (last[0] if last else "")[:120]))
            if want is None:
                # as far as it gets: no check of its own may fail, and it stops where the engine has nothing to offer (a role)
                check("hooks' own history test, unchanged: every check it reaches passes (it stops at the roles of its scenario 9)", not fails and oks >= 24 and "refused unsupported-statement" in r.stderr, (oks, fails[:2], r.stderr[-300:]))
            else:
                check("hooks' own history test, %s: all of it passes" % name, r.returncode == 0 and not fails and oks >= 43 and "all history checks passed" in r.stdout, (oks, fails[:3], r.stderr[-300:]))
    finally:
        os.remove(copy)


def main():
    if not HOOKS or not os.path.exists(HOOKS) or shutil.which("psql") is None:
        print("skip hooks against the engine's server: no HOOKS_BIN (a hooks binary built from its repository), or no psql")
        return 0
    with tempfile.TemporaryDirectory() as d:
        port, http_port = free_port(), free_port()
        page = os.path.join(d, "hooks.db")
        srv = subprocess.Popen([SERVER, page, str(port)], stderr=subprocess.PIPE)
        srv.stderr.readline()
        r = psql(port, "-f", os.path.join(ROOT, "tests", "hooks", "schema.sql"))
        check("hooks' schema is applied with psql", r.returncode == 0 and "ERROR" not in r.stderr and r.stdout.count("CREATE TABLE") == 3, r.stdout + r.stderr)
        rx = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        threading.Thread(target=rx.serve_forever, daemon=True).start()
        secret = "whsec_" + base64.b64encode(bytes(range(24))).decode()
        r = psql(port, "-c", "insert into endpoints (id, host, port, secret) values (0, '127.0.0.1', %d, '%s')" % (rx.server_address[1], secret))
        check("an endpoint is put in its table", r.stdout.strip() == "INSERT 0 1", r.stdout + r.stderr)
        os.mkdir(os.path.join(d, "data"))
        svc = subprocess.Popen([HOOKS, "--port", str(http_port), "--dir", os.path.join(d, "data"), "--allow-private-hosts", "1", "--pg-host", "127.0.0.1", "--pg-port", str(port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        said = []
        threading.Thread(target=lambda: said.extend(iter(svc.stderr.readline, "")), daemon=True).start()
        base = "http://127.0.0.1:%d" % http_port
        ready = None
        for _ in range(100):
            try:
                ready = get(base + "/readyz")
                break
            except OSError:
                time.sleep(0.1)
        time.sleep(0.5)
        check("the service is ready and read its endpoint from the engine", ready == {"ready": True} and any("endpoints loaded: 1" in l for l in said), (ready, said))
        ids = []
        for i in range(EVENTS):
            req = urllib.request.Request(base + "/events", data=json.dumps({"type": "user.created", "n": i}).encode())
            with urllib.request.urlopen(req, timeout=15) as r:
                ids.append(json.loads(r.read())["id"])
        for _ in range(100):
            if len(Receiver.got) >= EVENTS:
                break
            time.sleep(0.1)
        check("%d events are delivered to the receiver" % EVENTS, sorted(e.get("n") for e in Receiver.got) == list(range(EVENTS)), len(Receiver.got))
        rows = []
        for _ in range(50):
            rows = [get(base + "/events/%d/attempts" % i) for i in ids]
            if all(rows):
                break
            time.sleep(0.2)
        check("every attempt is a row, read back through the service's API", all(len(a) == 1 and a[0]["outcome"] == "delivered" and a[0]["status"] == 204 and a[0]["attempt"] == 1 for a in rows), rows[:3])
        metrics = urllib.request.urlopen(base + "/metrics", timeout=15).read().decode()
        written = [l for l in metrics.splitlines() if l.startswith('hooks_history_rows_total{result="written"}')]
        live = [l for l in metrics.splitlines() if l.startswith("hooks_history_connections ")]
        print("     the service says: %s; %s; %s" % (" / ".join(l.strip() for l in said if "database" in l), written, live))
        check("both of the service's connections to the database are live", live == ["hooks_history_connections 2"] and any("2 of 2 connections live" in l for l in said), (live, said))
        check("the service counts %d rows written and none failed or dropped" % EVENTS, written == ['hooks_history_rows_total{result="written"} %d' % EVENTS]
              and 'hooks_history_rows_total{result="failed"} 0' in metrics and 'hooks_history_rows_total{result="dropped"} 0' in metrics, written)
        svc.send_signal(signal.SIGTERM)
        svc.wait(timeout=30)
        # the service is gone, and with it its connection: the rows as the engine holds them
        r = psql(port, "-c", "select event, attempt, outcome, status from attempts order by event")
        check("the same rows, read from the engine with psql after the service stopped", r.stdout.splitlines() == ["%d|1|1|204" % i for i in ids], r.stdout + r.stderr)
        srv.send_signal(signal.SIGTERM)
        srv.wait()
        rx.shutdown()
    own_test()
    if FAILED:
        print("FAIL hooks on the engine's server: %d failed" % len(FAILED))
        return 1
    print("PASS hooks on the engine's server")
    return 0


if __name__ == "__main__":
    sys.exit(main())
