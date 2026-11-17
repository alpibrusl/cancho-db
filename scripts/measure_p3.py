#!/usr/bin/env python3
"""What real drivers put on the wire (docs/m1-extended.md section 2): each scenario run through a driver, with a tee between it and PostgreSQL.

    PG_PORT=5611 build/venv/bin/python scripts/measure_p3.py

Needs psycopg 3, psycopg2, asyncpg and pg8000 (a venv: `python3 -m venv build/venv && build/venv/bin/pip install "psycopg[binary]" psycopg2-binary asyncpg pg8000`)
and node-postgres (`cd build/node && npm install pg`). PostgreSQL on 127.0.0.1:$PG_PORT with trust login. It prints, per driver and scenario, the client's
messages in order: the startup (after the SSLRequest), then each Parse (the text), Bind (statement, portal, the parameters, the formats), Describe, Execute,
Sync, Close and Query. Nothing is asserted: it is the table the design note reads.
"""
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from pgtee import Tee  # noqa: E402

PG_PORT = int(os.environ.get("PG_PORT", "5611"))
tee = Tee(PG_PORT)


def show(driver, scenario):
    rows = [(k, d) for k, d in tee.messages if k not in ("SSLRequest", "GSSENCRequest", "Password", "Terminate", "X")]
    print("\n## %s: %s" % (driver, scenario))
    for k, d in rows:
        if k == "Startup":
            print("  Startup      %s" % {x: y for x, y in d.items() if x in ("user", "database", "client_encoding", "application_name", "options", "extra_float_digits", "DateStyle")})
        elif k == "Parse.detail":
            print("               (%s)" % d)
        else:
            print("  %-12s %s" % (k, d if d is not None else ""))
    tee.clear()


def psql(sql, port=PG_PORT):
    subprocess.run(["psql", "-q", "-At", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-d", "postgres", "-c", sql], capture_output=True, check=True)


psql("drop table if exists p3; create table p3(a int primary key, b text, c numeric, d timestamptz default now())")
psql("insert into p3(a, b, c) values (1, 'one', 1.5), (2, 'two', 2.5)")

import psycopg                                   # noqa: E402
import psycopg2                                 # noqa: E402
import pg8000.dbapi                             # noqa: E402
import asyncpg                                  # noqa: E402

P = tee.port

# ---- psycopg 3 (extended protocol with parameters, binary where it can)
c = psycopg.connect(host="127.0.0.1", port=P, user="postgres", dbname="postgres", autocommit=True)
tee.clear()
c.execute("select a, b from p3 where a = %s", (1,)).fetchall()
show("psycopg 3", "select with one parameter (autocommit)")
c.execute("select a, b from p3 where a = %s", (2,)).fetchall()
c.execute("select a, b from p3 where a = %s", (2,)).fetchall()
show("psycopg 3", "the same statement twice more (after 1 earlier)")
c.execute("insert into p3(a, b, c) values (%s, %s, %s)", (3, "three", 3.5))
show("psycopg 3", "insert with three parameters")
c.execute("select 1").fetchall()
show("psycopg 3", "select 1 (no parameters)")
c.autocommit = False
c.execute("insert into p3(a, b) values (%s, %s)", (4, "four"))
c.execute("select count(*) from p3").fetchall()
c.commit()
show("psycopg 3", "a transaction: insert, select, commit")
cur = c.cursor()
cur.executemany("insert into p3(a, b) values (%s, %s)", [(10, "x"), (11, "y")])
c.commit()
show("psycopg 3", "executemany of 2 rows")
c.close()
psql("delete from p3 where a > 2")

# ---- psycopg 2 (simple protocol, values put into the text by the client)
c = psycopg2.connect(host="127.0.0.1", port=P, user="postgres", dbname="postgres")
c.autocommit = True
tee.clear()
cur = c.cursor()
cur.execute("select a, b from p3 where a = %s", (1,))
cur.fetchall()
show("psycopg 2", "select with one parameter (autocommit)")
cur.execute("insert into p3(a, b, c) values (%s, %s, %s)", (3, "three", 3.5))
show("psycopg 2", "insert with three parameters")
c.close()
psql("delete from p3 where a > 2")

# ---- pg8000 (extended protocol, text)
c = pg8000.dbapi.connect(host="127.0.0.1", port=P, user="postgres", database="postgres")
c.autocommit = True
tee.clear()
cur = c.cursor()
cur.execute("select a, b from p3 where a = %s", (1,))
cur.fetchall()
show("pg8000", "select with one parameter (autocommit)")
cur.execute("insert into p3(a, b, c) values (%s, %s, %s)", (3, "three", 3.5))
show("pg8000", "insert with three parameters")
c.close()
psql("delete from p3 where a > 2")


# ---- asyncpg (extended protocol, binary, named prepared statements, type introspection at first use)
async def run_asyncpg():
    con = await asyncpg.connect(host="127.0.0.1", port=P, user="postgres", database="postgres")
    show("asyncpg", "connect")
    await con.fetch("select a, b from p3 where a = $1", 1)
    show("asyncpg", "first select with one parameter (autocommit)")
    await con.fetch("select a, b from p3 where a = $1", 2)
    show("asyncpg", "the same statement again (it is prepared and cached)")
    await con.execute("insert into p3(a, b, c) values ($1, $2, $3)", 3, "three", 3.5)
    show("asyncpg", "insert with three parameters")
    async with con.transaction():
        await con.execute("insert into p3(a, b) values ($1, $2)", 4, "four")
    show("asyncpg", "a transaction: insert")
    await con.close()


asyncio.run(run_asyncpg())
psql("delete from p3 where a > 2")

# ---- node-postgres
js = r"""
const { Client } = require('pg');
(async () => {
  const c = new Client({ host: '127.0.0.1', port: %d, user: 'postgres', database: 'postgres' });
  await c.connect();
  console.log('MARK connect');
  await c.query('select a, b from p3 where a = $1', [1]);
  console.log('MARK select-param');
  await c.query('select a, b from p3 where a = $1', [2]);
  console.log('MARK select-param-again');
  await c.query({ name: 'named', text: 'select a, b from p3 where a = $1', values: [1] });
  await c.query({ name: 'named', text: 'select a, b from p3 where a = $1', values: [2] });
  console.log('MARK named-twice');
  await c.query('insert into p3(a, b, c) values ($1, $2, $3)', [3, 'three', 3.5]);
  console.log('MARK insert-param');
  await c.query('select 1');
  console.log('MARK select-1');
  await c.query('begin'); await c.query('insert into p3(a, b) values ($1, $2)', [4, 'four']); await c.query('commit');
  console.log('MARK transaction');
  await c.end();
})();
""" % P
Path(ROOT / "build" / "node" / "p3.js").write_text(js)
r = subprocess.run(["node", "p3.js"], cwd=ROOT / "build" / "node", capture_output=True, text=True)
marks = [l[5:] for l in r.stdout.splitlines() if l.startswith("MARK ")]
print("\n## node-postgres (the whole script; the marks are %s)" % marks)
show("node-postgres", "all scenarios in order")
if r.returncode:
    print(r.stderr[:400])

# ---- pgx (Go), built into build/gopgx (`cd build/gopgx && go mod init p3pgx && go get github.com/jackc/pgx/v5 && go build -o p3pgx .`)
if (ROOT / "build" / "gopgx" / "p3pgx").exists():
    r = subprocess.run([str(ROOT / "build" / "gopgx" / "p3pgx"), str(P)], capture_output=True, text=True)
    print("\n## pgx (the whole script; marks %s)" % [l[5:] for l in r.stdout.splitlines() if l.startswith("MARK ")])
    show("pgx", "all scenarios in order")
psql("drop table if exists p3")
