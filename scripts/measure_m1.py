#!/usr/bin/env python3
"""The measurements behind docs/m1-proxy.md section 2, against a real PostgreSQL and psql.

    PGHOST=127.0.0.1 PGPORT=5532 PGUSER=postgres python3 scripts/measure_m1.py

The server must have max_prepared_transactions > 0 and allow trust login for PGUSER. It creates and drops its own tables
(`m1_orders`, `m1_t2pc`, `m1_perf`) in PGDATABASE. It prints one line per fact; nothing is asserted except what the design
relies on, which is checked at the end (exit status 1 if a fact the design rests on no longer holds).
"""
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from pgtee import Tee  # noqa: E402

PORT = int(os.environ.get("PGPORT", "5432"))
FACTS = {}


def psql(sql, port=PORT, args=(), check=False):
    env = dict(os.environ, PGPORT=str(port))
    return subprocess.run(["psql", "-q", "-At", "-v", "ON_ERROR_STOP=0", *args], input=sql.encode(), env=env,
                          capture_output=True, check=check)


def out(sql, port=PORT):
    return psql(sql, port).stdout.decode().strip()


def fact(key, text, ok=True):
    FACTS[key] = ok
    print("%-34s %s" % (key, text))


psql("drop table if exists m1_orders, m1_t2pc, m1_perf;"
     "create table m1_orders(id int primary key, customer text, total numeric);"
     "create table m1_t2pc(id int primary key, v text default 'x', ts timestamptz default now());"
     "create table m1_perf(id int primary key, v text);", check=True)
tee = Tee(PORT)

# -- 1. what psql sends at connect, and for statements
tee.clear()
psql("select 1;", tee.port)
time.sleep(0.3)
kinds = tee.kinds()
fact("psql.connect_sequence", "%s" % [k for k in kinds if k not in ("X",)][:3],
     kinds[:3] == ["SSLRequest", "Startup", "Query"])
startup = [d for k, d in tee.messages if k == "Startup"][0]
fact("psql.startup_parameters", "%s" % sorted(startup), set(startup) == {"user", "database", "application_name"})

tee.clear()
psql("insert into m1_orders values (1,'a',10);\nbegin;\ninsert into m1_orders values (2,'b',20);\n"
     "select count(*) from m1_orders;\ncommit;\n", tee.port)
time.sleep(0.3)
fact("psql.script_one_query_per_stmt", "%s" % tee.queries(), len(tee.queries()) == 5)
tee.clear()
psql("", tee.port, args=("-c", "select 1; select 2"))
time.sleep(0.3)
fact("psql.c_multi_statement", "one message: %s" % tee.queries(), tee.queries() == ["select 1; select 2"])

# -- 2. the backslash commands
for cmd in ["\\dt", "\\d m1_orders", "\\l", "\\du", "\\dn", "\\di", "\\df"]:
    tee.clear()
    psql(cmd + "\n", tee.port)
    time.sleep(0.4)
    qs = tee.queries()
    n = lambda pat: sum(len(re.findall(pat, q, re.I)) for q in qs)
    fact("psql.meta " + cmd, "%d queries, %d bytes, LEFT JOIN x%d, subselect x%d, regex x%d" % (
        len(qs), sum(map(len, qs)), n(r"\bLEFT\b"), n(r"\(\s*SELECT"), n(r"OPERATOR\(pg_catalog\.~\)|\s~\s")),
         len(qs) >= 1)
psql("select 1;", tee.port)

# -- 3. two-phase commit
psql("begin; insert into m1_t2pc(id) values (1); prepare transaction 'cdb-m1-1';")
invisible = out("select count(*) from m1_t2pc")
prepared = out("select gid from pg_prepared_xacts where gid = 'cdb-m1-1'")
psql("commit prepared 'cdb-m1-1';")
visible = out("select count(*) from m1_t2pc")
fact("2pc.prepare_then_commit_elsewhere", "prepared=%s rows before=%s after=%s" % (prepared, invisible, visible),
     prepared == "cdb-m1-1" and invisible == "0" and visible == "1")
psql("begin; insert into m1_t2pc(id) values (2); prepare transaction 'cdb-m1-2';")
psql("rollback prepared 'cdb-m1-2';")
fact("2pc.rollback_prepared", "rows=%s" % out("select count(*) from m1_t2pc"), out("select count(*) from m1_t2pc") == "1")
temp = psql("begin; create temp table tt(a int); prepare transaction 'cdb-m1-3';").stderr.decode()
psql("rollback;")
listen = psql("begin; listen foo; prepare transaction 'cdb-m1-4';").stderr.decode()
psql("rollback;")
fact("2pc.cannot_prepare_temp", temp.strip().splitlines()[-1] if temp.strip() else "(no error)", "temporary" in temp)
fact("2pc.cannot_prepare_listen", listen.strip().splitlines()[-1] if listen.strip() else "(no error)", "LISTEN" in listen)
ddl = psql("begin; create table m1_ddl(a int); prepare transaction 'cdb-m1-5';").stderr.decode()
left = out("select gid from pg_prepared_xacts where gid = 'cdb-m1-5'")
psql("rollback prepared 'cdb-m1-5'; drop table if exists m1_ddl;")
fact("2pc.ddl_can_prepare", "prepared gid=%s" % left, left == "cdb-m1-5")
fact("2pc.max_prepared_default", "postgresql.conf.sample says: %s" % subprocess.run(
    "grep -h '^#max_prepared_transactions' /usr/share/postgresql/*/postgresql.conf.sample | head -1", shell=True,
    capture_output=True).stdout.decode().strip().split("#")[1].strip(), True)

# -- 4. now() captured inside the transaction is the one the statements used
res = out("""begin;
select now() as captured \\gset
select pg_sleep(0.3);
insert into m1_t2pc(id) values (10);
select (select ts from m1_t2pc where id=10) = :'captured'::timestamptz, statement_timestamp() <> :'captured'::timestamptz;
commit;""")
fact("now.captured_equals_default", "same=%s statement_clock_differs=%s" % tuple(res.split("\n")[-1].split("|")),
     res.split("\n")[-1] == "t|t")

# -- 5. what two-phase commit costs
N = 400


def timed(sql):
    t = time.time()
    psql(sql, check=True)
    return (time.time() - t) * 1000 / N


psql("truncate m1_perf;")
auto = timed("".join("insert into m1_perf values (%d,'x');\n" % i for i in range(N)))
psql("truncate m1_perf;")
two = timed("".join("begin; insert into m1_perf values (%d,'x'); prepare transaction 'p%d'; commit prepared 'p%d';\n"
                    % (i, i, i) for i in range(N)))
fact("2pc.cost_per_commit", "autocommit %.2f ms, begin/prepare/commit prepared %.2f ms, ratio %.1fx (fsync=%s)" % (
    auto, two, two / auto, out("show fsync")), two / auto < 10)
psql("drop table if exists m1_orders, m1_t2pc, m1_perf;")

failed = [k for k, ok in FACTS.items() if not ok]
print("%d facts, %d no longer hold%s" % (len(FACTS), len(failed), (": " + ", ".join(failed)) if failed else ""))
sys.exit(1 if failed else 0)
