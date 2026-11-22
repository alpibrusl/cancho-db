#!/usr/bin/env python3
"""The query guard (src/guard.cho, docs/m1-lowering.md section 5) against hand-written verdicts.

    python3 tests/guard_check.py GUARDCHECK_BINARY

Each case is a capability token (minted here with real Ed25519 signatures by this file's own code, not by src/), a query
message's text, and the verdict written by hand from the rules: allowed, with the exact text that goes to PostgreSQL instead of
what the client sent; or refused, with its kind (1 lexer, 2 parser or lowering, 3 an effect the token does not allow), its tag,
its SQLSTATE, and the statement it stopped at. The rule under test is the one the whole of M1 rests on: **a statement is allowed
only if every effect it has is allowed by the token, and a message is allowed only if every statement in it is**.
"""
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import verify as pyverify  # noqa: E402  (the second verifier: its IR reader and effect inference are the independent check)

GUARD = sys.argv[1]
NONE = 2**64 - 1
BLOCK_DOMAIN = b"cancho-db/token-block/v1\x00"
R, W, D, C, N = 0, 1, 2, 3, 4
SCHEMA = "orders: id customer total\ncustomers: id name\nindex oi on orders\n"


def u16(n): return struct.pack(">H", n)
def u32(n): return struct.pack(">I", n)
def u64(n): return struct.pack(">Q", n)
def b16(b): return u16(len(b)) + b
def lst(items): return u32(len(items)) + b"".join(items)


def key(name):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"cancho-db guard test key: " + name.encode()).digest())
    return sk, sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


ROOT, _ = key("root")


def token(label, effects):
    """One block that allows exactly `effects` (kind, target pattern) on every branch, for every principal, forever."""
    pl = bytes(32) + b16(b"*") + lst([bytes([k]) + b16(t.encode()) for k, t in effects]) + u64(NONE)
    _, npk = key(label)
    block = pl + npk + ROOT.sign(BLOCK_DOMAIN + pl + npk)
    return (u32(1) + block).hex()


ALL = token("all", [(k, "*") for k in range(5)])
NOTHING = token("nothing", [])
READ_ORDERS = token("read orders", [(R, "orders"), (R, "orders.id"), (R, "orders.total")])
RW_ORDERS = token("rw orders", [(R, "orders"), (R, "orders.*"), (W, "orders"), (C, "count"), (N, "now")])

CASES = []


def ok(tok, sql, sent): CASES.append((tok, sql, "ok " + sent))
def no(tok, sql, kind, tag, state, stmt=0): CASES.append((tok, sql, "refused %d %s %s %d" % (kind, tag, state, stmt)))



# ---- AS OF (docs/m2-branches.md D27 to D29): a token of the current rows does not allow a read of the past; one that names it does; the statement is sent as it was written
HX = "3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f"
HIST_ORDERS = token("history orders", [(R, "orders@*")])
CALL = 'cdb.asof(null::"orders", cdb.ord(\'' + HX + '\'))'
ok(ALL, "select id from orders as of '" + HX + "'", 'select "id" from ' + CALL + ' as "orders"')
ok(HIST_ORDERS, "select id from orders as of '" + HX + "'", 'select "id" from ' + CALL + ' as "orders"')
ok(ALL, "select o.id from orders as of '" + HX + "' o where o.total > 1", 'select "o"."id" from ' + CALL + ' as "o" where ("o"."total" > 1)')
ok(ALL, "select o.id from orders as of '" + HX + "' o, orders", 'select "o"."id" from ' + CALL + ' as "o", "orders"')
ok(ALL, "select ' as of ''" + HX + "''' from orders", "select ' as of ''" + HX + "''' from \"orders\"")
ok(ALL, "select '\"orders\" as of ''" + HX + "''' from orders", "select '\"orders\" as of ''" + HX + "''' from \"orders\"")
# a double quote inside a constant must not shift the scan's idea of what is a quoted name: the clause after it is still rewritten
ok(ALL, "select 'a\"b' from orders as of '" + HX + "'", "select 'a\"b' from " + CALL + ' as "orders"')
ok(ALL, "select 'it''s' from orders as of '" + HX + "' o where o.id = 1", "select 'it''s' from " + CALL + ' as "o" where ("o"."id" = 1)')
ok(ALL, "select id from orders where id = 1; select id from orders as of '" + HX + "'", 'select "id" from "orders" where ("id" = 1); select "id" from ' + CALL + ' as "orders"')
no(READ_ORDERS, "select id from orders as of '" + HX + "'", 3, "effect-denied", "42501")
no(RW_ORDERS, "select id from orders as of '" + HX + "'", 3, "effect-denied", "42501")
no(HIST_ORDERS, "select id from orders", 3, "effect-denied", "42501")
no(ALL, "update orders as of '" + HX + "' set total = 1", 2, "as-of-write", "0A000")
no(ALL, "select id from orders as of 'zz'", 2, "as-of-bad-commit", "0A000")

# ---- reads: every column a statement touches is a read, wherever it sits
ok(READ_ORDERS, "select id, total from orders", 'select "id", "total" from "orders"')
no(READ_ORDERS, "select customer from orders", 3, "effect-denied", "42501")
no(READ_ORDERS, "select id from orders where customer > 1", 3, "effect-denied", "42501")
no(READ_ORDERS, "select id from orders order by customer", 3, "effect-denied", "42501")
no(READ_ORDERS, "select id from orders group by id, customer", 3, "effect-denied", "42501")
no(READ_ORDERS, "select id from orders having customer > 1", 3, "effect-denied", "42501")
no(READ_ORDERS, "select id from orders limit (select 1)", 2, "subquery", "0A000")
no(READ_ORDERS, "select * from orders", 3, "effect-denied", "42501")
no(READ_ORDERS, "select o.id from orders o join customers c on c.id = o.id", 3, "effect-denied", "42501")
no(READ_ORDERS, "select id from customers", 3, "effect-denied", "42501")
ok(READ_ORDERS, "select o.id from orders o where o.total > 5 order by id", 'select "o"."id" from "orders" as "o" where ("o"."total" > 5) order by "id"')
no(NOTHING, "select id from orders", 3, "effect-denied", "42501")
# ---- parameters (docs/m1-extended.md P3-D1): allowed where the token allows the columns, rendered with `$n`; a parameter has no effect of its own
ok(READ_ORDERS, "select id from orders where id = $1", 'select "id" from "orders" where ("id" = $1)')
no(READ_ORDERS, "select id from orders where customer = $1", 3, "effect-denied", "42501")
ok(ALL, "insert into orders (id, customer, total) values ($1, $2, $3)", 'insert into "orders" ("id", "customer", "total") values ($1, $2, $3)')
ok(ALL, "update orders set total = $2 where id = $1", 'update "orders" set "total" = $2 where ("id" = $1)')
ok(ALL, "select id from orders where id in ($1, $2) limit $3", 'select "id" from "orders" where ("id" in ($1, $2)) limit $3')
no(ALL, "select id from orders where id = $0", 1, "parameter", "0A000")
no(ALL, "select id from orders where id = $65536", 1, "parameter", "0A000")
no(ALL, "select id from orders where id = $1x", 1, "parameter", "0A000")
no(NOTHING, "select id from orders where id = $1", 3, "effect-denied", "42501")
# a message of more statements than a commit can name (16) is refused whole, not cut: the seventeenth is where it stops
no(ALL, "; ".join(["select id from orders"] * 17), 2, "too-big", "0A000", 16)
ok(ALL, "; ".join(["select id from orders"] * 16), "; ".join(['select "id" from "orders"'] * 16))

# ---- writes, DDL and calls
no(READ_ORDERS, "insert into orders values (1, 2, 3)", 3, "effect-denied", "42501")
no(READ_ORDERS, "update orders set total = 1", 3, "effect-denied", "42501")
no(READ_ORDERS, "delete from orders", 3, "effect-denied", "42501")
no(READ_ORDERS, "drop table customers", 3, "effect-denied", "42501")
no(READ_ORDERS, "select count(*) from orders", 3, "effect-denied", "42501")
ok(RW_ORDERS, "select count(*) from orders", 'select count(*) from "orders"')
ok(RW_ORDERS, "select now() from orders", 'select now() from "orders"')
ok(RW_ORDERS, "insert into orders (id) values (1)", 'insert into "orders" ("id") values (1)')
ok(RW_ORDERS, "update orders set total = total + 1 where id = 5", 'update "orders" set "total" = ("total" + 1) where ("id" = 5)')
no(RW_ORDERS, "select lower(customer) from orders", 3, "effect-denied", "42501")
no(RW_ORDERS, "alter table orders add column z int", 3, "effect-denied", "42501")
ok(ALL, "drop table customers", 'drop table "customers"')

# ---- a message is allowed only if every statement in it is; no part of a refused one is sent
ok(ALL, "select 1 from orders; delete from orders", 'select 1 from "orders"; delete from "orders"')
no(READ_ORDERS, "select id from orders; insert into orders values (1, 2, 3)", 3, "effect-denied", "42501", 1)
no(READ_ORDERS, "select id from orders; select customer from orders", 3, "effect-denied", "42501", 1)
no(READ_ORDERS, "select customer from orders; select id from orders", 3, "effect-denied", "42501", 0)
no(ALL, "select id from orders; drop table nowhere", 2, "unknown-table", "42P01", 1)
no(ALL, "select id from orders; begin", 2, "mixed-transaction-control", "0A000", 1)
no(ALL, "select id from orders; select id from orders; select nope from orders", 2, "unknown-column", "42703", 2)
no(ALL, "select id from orders; savepoint a", 2, "unsupported-statement", "0A000", 1)     # a parser refusal of a later statement
no(ALL, "select id from orders; select id from orders; select id from orders where", 2, "syntax", "0A000", 2)
ok(ALL, "select id from orders; ;; select id from orders", 'select "id" from "orders"; select "id" from "orders"')

# ---- transaction control is the proxy's own to answer: nothing is rendered, and it must be alone in its message
ok(ALL, "begin", "txn 1 ")
ok(NOTHING, "begin", "txn 1 ")                # it has no effects, so any token may open a transaction
ok(READ_ORDERS, "commit", "txn 2 ")
ok(ALL, "rollback", "txn 3 ")
ok(ALL, "  End Transaction ;", "txn 2 ")
ok(ALL, "start transaction", "txn 1 ")
no(ALL, "begin; select id from orders", 2, "mixed-transaction-control", "0A000", 0)
no(ALL, "select id from orders; commit", 2, "mixed-transaction-control", "0A000", 1)
no(ALL, "begin; commit", 2, "mixed-transaction-control", "0A000", 0)
no(ALL, "commit prepared 'x'", 2, "unknown-construct", "0A000")
no(ALL, "begin isolation level serializable", 2, "unknown-construct", "0A000")
no(ALL, "savepoint a", 2, "unsupported-statement", "0A000")

# ---- what the client sent is not what is sent: only the rendering goes upstream
ok(ALL, "select 'a;b' from orders", "select 'a;b' from \"orders\"")
ok(ALL, "select id from orders /* ; drop table orders */", 'select "id" from "orders"')
ok(ALL, "select id from orders -- ; drop table orders\n", 'select "id" from "orders"')
ok(ALL, "SELECT Id FROM Orders", 'select "id" from "orders"')
ok(ALL, "select id from orders where customer = 'it''s'", "select \"id\" from \"orders\" where (\"customer\" = 'it''s')")
ok(ALL, "", "")
ok(ALL, "  ;  ", "")

# ---- refusals outside the subset
no(ALL, "select nope from orders", 2, "unknown-column", "42703")
no(ALL, "select id from nowhere", 2, "unknown-table", "42P01")
no(ALL, "select id from orders, customers", 2, "ambiguous-column", "42702")
no(ALL, "select random() from orders", 2, "nondeterministic", "0A000")
no(ALL, "set search_path = x", 2, "unsupported-statement", "0A000")
no(ALL, "copy orders from stdin", 2, "unsupported-statement", "0A000")
# forms that only the engine takes (docs/m3-engine.md 6x): the parser reads them, and the guard refuses them as it did before they were read
no(ALL, "create table if not exists t9 (k integer primary key)", 2, "unsupported-statement", "0A000")
no(ALL, "create table t9 (a integer, b integer, primary key (a, b))", 2, "unsupported-statement", "0A000")
no(ALL, "create table t9 (k integer primary key check (k between 0 and 9))", 2, "unsupported-statement", "0A000")
no(ALL, "create table t9 (k bigint generated always as identity primary key)", 2, "unsupported-statement", "0A000")
no(ALL, "alter table orders add column if not exists note text", 2, "unsupported-statement", "0A000")
no(ALL, "alter table orders alter column total type bigint", 2, "unsupported-statement", "0A000")
no(ALL, "create index if not exists oi2 on orders (total)", 2, "unsupported-statement", "0A000")
no(ALL, "create index oi2 on orders (total) where id", 2, "unsupported-statement", "0A000")
no(ALL, "insert into orders values (1, 2, 3) on conflict do nothing", 2, "on-conflict", "0A000")
no(ALL, "insert into orders values (1, 2, 3) on conflict (id) do nothing", 2, "on-conflict", "0A000")
no(ALL, "insert into orders values (1, 2, 3) on conflict do nothing returning id", 2, "on-conflict", "0A000")
no(ALL, "update orders set total = 1 where id = 2 returning id, total", 2, "returning", "0A000")
no(ALL, "delete from orders returning *", 2, "returning", "0A000")
no(ALL, "insert into orders select 1, 2, 3", 2, "insert-select", "0A000")
no(ALL, "insert into orders select 1, 2, 3 where true", 2, "insert-select", "0A000")
no(ALL, "insert into orders select id, 2, 3 from customers", 2, "insert-select", "0A000")
no(ALL, "select id from orders where total = (select 1)", 2, "subquery", "0A000")
no(ALL, "insert into orders values (1, 2, 3) returning nope", 2, "returning", "0A000")
no(ALL, "select id from orders; create table if not exists t9 (k integer primary key)", 2, "unsupported-statement", "0A000", 1)
no(ALL, "select id from orders union select id from customers", 2, "set-operation", "0A000")
no(ALL, "insert into orders values (1, 2, 3) returning id", 2, "returning", "0A000")
no(ALL, "select e'x' from orders", 1, "escape-string", "0A000")
no(ALL, "select $$x$$ from orders", 1, "dollar-quote", "0A000")
no(ALL, "select 1 from orders where", 2, "syntax", "0A000")


def run(tok, sql):
    r = subprocess.run([GUARD], input=(tok + "\n" + SCHEMA + "---\n" + sql).encode(), capture_output=True, timeout=30)
    out = r.stdout.decode().rstrip("\n")
    return out if r.returncode == 0 and out else "crash: " + r.stderr.decode()[:200]


def parts(tok, sql):
    """What the guard hands over for a commit: the statements' ids, their IR as store records, and the effects they infer (stderr)."""
    r = subprocess.run([GUARD], input=(tok + "\n" + SCHEMA + "---\n" + sql).encode(), capture_output=True, timeout=30)
    got = {}
    for line in r.stderr.decode().splitlines():
        label, _, hexed = line.partition(" ")
        got[label] = bytes.fromhex(hexed)
    return got


def check_parts(tok, sql):
    """The ids are recomputed from the IR bytes, and the effects from the IR by the Python verifier's own inference; none of it is read
    back from the guard's own words."""
    got = parts(tok, sql)
    if set(got) != {"ids", "irs", "effs"}:
        return "no parts: %s" % sorted(got)
    irs, at, stmts = got["irs"], 0, []
    while at < len(irs):
        n = struct.unpack(">I", irs[at:at + 4])[0]
        stmts.append(irs[at + 4:at + 4 + n])
        at += 4 + n
    if at != len(irs):
        return "ragged irs"
    if len(got["ids"]) != 32 * len(stmts):
        return "%d ids for %d statements" % (len(got["ids"]) // 32, len(stmts))
    want_effs = set()
    for i, ir in enumerate(stmts):
        if hashlib.sha256(b"cancho-db/stmt/v1\x00" + ir).digest() != got["ids"][32 * i:32 * i + 32]:
            return "statement %d: the id is not the hash of its bytes" % i
        want_effs |= {(k, t) for k, t in pyverify.infer_effects(ir, v2=True)}
    effs, at, have = got["effs"], 0, []
    while at < len(effs):
        n = struct.unpack(">H", effs[at + 1:at + 3])[0]
        have.append((effs[at], effs[at + 3:at + 3 + n]))
        at += 3 + n
    if at != len(effs):
        return "ragged effects"
    if set(have) != want_effs:
        return "effects %s, the Python verifier infers %s" % (sorted(have), sorted(want_effs))
    return None


def main():
    bad = []
    for tok, sql, want in CASES:
        got = run(tok, sql)
        if got != want:
            bad.append((sql, "want " + want, "got " + got))
    # every allowed message, and a few made to have several statements: what a commit would be made of is right
    allowed = [sql for tok, sql, want in CASES if want.startswith("ok") and tok == ALL and not want.startswith("ok txn") and want.strip() != "ok"]
    extra = ["select id from orders; select name from customers", "insert into orders (id, customer, total) values (1, 2, 3); select id from orders",
             "update orders set total = 1 where id = 2; delete from orders where id = 9; select id from orders"]
    n_parts = 0
    for sql in allowed + extra:
        why = check_parts(ALL, sql)
        n_parts += 1
        if why:
            bad.append((sql, "parts", why))
    print("guard parts: %d messages" % n_parts)
    print("guard: %d cases, %d refusals, %d allowed" % (len(CASES), sum(1 for c in CASES if c[2].startswith("refused")),
                                                          sum(1 for c in CASES if c[2].startswith("ok"))))
    for b in bad[:15]:
        print("FAIL", *b)
    print("%d failures" % len(bad))
    return 1 if bad else 0


sys.exit(main())
