#!/usr/bin/env python3
"""The lowering (src/lower.cho, docs/m1-lowering.md section 4.1) against two hand writings per case.

    python3 tests/lower_check.py LOWERCHECK_BINARY VERIFY_BINARY

Each case is a statement, a schema snapshot, and BOTH of:

  * the IR bytes the lowering must produce, built below from the structure of the statement by hand with this file's own encoder
    (ir.md sections 2 and 6), not by anything in src/;
  * the effect set the statement must have, written below by hand from the inference rules (ir.md section 3), as a literal list.

The first is compared byte for byte with what `lowercheck` prints. The second is checked by the VERIFIER, the code that will
check the log: a commit that records exactly that set, over the statement the lowering produced, must verify
(`ok ... level=2+ir`); and the same commit with one effect removed, and with one added, must be refused `effects-mismatch`,
which shows the check has teeth. A refusal case names the tag it must get.
"""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import gen_vectors as g  # noqa: E402

LOWER, VERIFY = sys.argv[1], sys.argv[2]
R, W, D, C, N = 0, 1, 2, 3, 4

SCHEMA = "orders: id customer total\ncustomers: id name\nindex oi on orders\n"

u32, lst = g.u32, g.lst


def b16(x): return g.b16(x.encode() if isinstance(x, str) else x)


# ------------------------------------------------------------------ this file's own IR encoder (ir.md sections 2 and 6)
def Col(t, c): return b"\x00" + b16(t) + b16(c)
def Int(v): return b"\x01\x01" + __import__("struct").pack(">q", v)
def Txt(v): return b"\x01\x02" + u32(len(v)) + v
NULLC = b"\x01\x00"
def Nondet(s): return b"\x03" + b16(s)
def Param(n): return b"\x02" + u32(n)
def Call(f, *a): return b"\x04" + b16(f) + u32(len(a)) + b"".join(a)
def Op(op, a, b): return b"\x05" + bytes([op]) + a + b
STAR = b"\x06"
def Un(op, e): return b"\x07" + bytes([op]) + e
def In(neg, e, *members): return b"\x08" + bytes([neg]) + u32(len(members)) + e + b"".join(members)
def Case(pairs, els=None): return b"\x09" + u32(len(pairs)) + bytes([0 if els is None else 1]) + b"".join(c + r for c, r in pairs) + (els or b"")
def Cast(t, e): return b"\x0a" + b16(t) + e
EQ, NE, LT, LE, GT, GE, AND, OR, ADD, SUB, MUL, DIV, LIKE, ILIKE, NLIKE, NILIKE, CONCAT, MOD = range(18)
def opt(e=None): return b"\x00" if e is None else b"\x01" + e
def From(t, kind=0, on=None): return b16(t) + bytes([kind]) + opt(on)
def Order(e, desc=0): return e + bytes([desc, 0])
def Select2(items, froms, where=None, group=(), having=None, order=(), limit=None, offset=None, distinct=0):
    return (b"\x06" + bytes([distinct]) + lst(items) + lst(froms) + opt(where) + lst(group) + opt(having) + lst(order)
            + opt(limit) + opt(offset))
def Insert(t, cols, rows): return b"\x01" + b16(t) + lst([b16(c) for c in cols]) + lst([lst(r) for r in rows])
def Update(t, sets, where=None): return b"\x02" + b16(t) + lst([b16(c) + e for c, e in sets]) + opt(where)
def Delete(t, where=None): return b"\x03" + b16(t) + opt(where)
def Ddl(kind, t): return b"\x04" + bytes([kind]) + b16(t)


def rd(t, c=None): return (R, t if c is None else t + "." + c)


CASES = []  # (sql, expected IR bytes, hand-written effects) or (sql, tag)


def ok(sql, ir, effects): CASES.append((sql, ir, sorted(set(effects))))
def no(sql, tag): CASES.append((sql, tag))


# ---- SELECT: columns, aliases, stars
# ---- parameters (docs/m1-extended.md P3-D1): `Param n`, the number as written; no effect of their own
ok("select id from orders where id = $1", Select2([Col("orders", "id")], [From("orders")], where=Op(EQ, Col("orders", "id"), Param(1))),
   [rd("orders"), rd("orders", "id")])
ok("select id from orders where total > $2 and customer = $1",
   Select2([Col("orders", "id")], [From("orders")], where=Op(AND, Op(GT, Col("orders", "total"), Param(2)), Op(EQ, Col("orders", "customer"), Param(1)))),
   [rd("orders"), rd("orders", "id"), rd("orders", "total"), rd("orders", "customer")])
ok("select id from orders where id in ($3, $1) limit $2",
   Select2([Col("orders", "id")], [From("orders")], where=In(0, Col("orders", "id"), Param(3), Param(1)), limit=Param(2)),
   [rd("orders"), rd("orders", "id")])
ok("insert into orders (id, customer, total) values ($1, $2, $3)", Insert("orders", ["id", "customer", "total"], [[Param(1), Param(2), Param(3)]]), [(W, "orders")])
ok("update orders set total = $1 where id = $2", Update("orders", [("total", Param(1))], Op(EQ, Col("orders", "id"), Param(2))),
   [(W, "orders"), rd("orders", "id")])
ok("delete from orders where id = $65535", Delete("orders", Op(EQ, Col("orders", "id"), Param(65535))), [(W, "orders"), rd("orders", "id")])
ok("select id from orders", Select2([Col("orders", "id")], [From("orders")]), [rd("orders"), rd("orders", "id")])
ok("SELECT ID FROM Orders", Select2([Col("orders", "id")], [From("orders")]), [rd("orders"), rd("orders", "id")])
ok("select o.total from orders o", Select2([Col("orders", "total")], [From("orders")]), [rd("orders"), rd("orders", "total")])
ok("select * from orders", Select2([Col("orders", c) for c in ("id", "customer", "total")], [From("orders")]),
   [rd("orders")] + [rd("orders", c) for c in ("id", "customer", "total")])
ok("select o.* from orders o", Select2([Col("orders", c) for c in ("id", "customer", "total")], [From("orders")]),
   [rd("orders")] + [rd("orders", c) for c in ("id", "customer", "total")])
ok("select name, total from customers, orders",
   Select2([Col("customers", "name"), Col("orders", "total")], [From("customers"), From("orders")]),
   [rd("customers"), rd("customers", "name"), rd("orders"), rd("orders", "total")])
ok("select distinct customer from orders", Select2([Col("orders", "customer")], [From("orders")], distinct=1),
   [rd("orders"), rd("orders", "customer")])
ok("select id as x from orders", Select2([Col("orders", "id")], [From("orders")]), [rd("orders"), rd("orders", "id")])

# ---- joins: the base table is named, never the alias; the ON is a read
ok("select c.name from orders o join customers c on o.customer = c.id",
   Select2([Col("customers", "name")],
           [From("orders"), From("customers", 1, Op(EQ, Col("orders", "customer"), Col("customers", "id")))]),
   [rd("orders"), rd("orders", "customer"), rd("customers"), rd("customers", "id"), rd("customers", "name")])
ok("select o.id from orders o left outer join customers c on c.id = o.customer",
   Select2([Col("orders", "id")],
           [From("orders"), From("customers", 2, Op(EQ, Col("customers", "id"), Col("orders", "customer")))]),
   [rd("orders"), rd("orders", "id"), rd("orders", "customer"), rd("customers"), rd("customers", "id")])
ok("select 1 from orders a join orders b on a.id = b.id",
   Select2([Int(1)], [From("orders"), From("orders", 1, Op(EQ, Col("orders", "id"), Col("orders", "id")))]),
   [rd("orders"), rd("orders", "id")])

# ---- the clauses
ok("select id from orders where total > 10 and customer is not null",
   Select2([Col("orders", "id")], [From("orders")],
           where=Op(AND, Op(GT, Col("orders", "total"), Int(10)), Un(3, Col("orders", "customer")))),
   [rd("orders"), rd("orders", "id"), rd("orders", "total"), rd("orders", "customer")])
ok("select customer from orders group by customer having count(*) > 1 order by customer desc limit 3 offset 1",
   Select2([Col("orders", "customer")], [From("orders")], group=[Col("orders", "customer")],
           having=Op(GT, Call("count", STAR), Int(1)), order=[Order(Col("orders", "customer"), 1)], limit=Int(3), offset=Int(1)),
   [rd("orders"), rd("orders", "customer"), (C, "count")])
ok("select total as t from orders order by t",
   Select2([Col("orders", "total")], [From("orders")], order=[Order(Col("orders", "total"))]),
   [rd("orders"), rd("orders", "total")])
ok("select id from orders order by total",
   Select2([Col("orders", "id")], [From("orders")], order=[Order(Col("orders", "total"))]),
   [rd("orders"), rd("orders", "id"), rd("orders", "total")])
ok("select id from orders order by 1", Select2([Col("orders", "id")], [From("orders")], order=[Order(Int(1))]),
   [rd("orders"), rd("orders", "id")])

# ---- expressions
ok("select id from orders where total between 1 and 5",
   Select2([Col("orders", "id")], [From("orders")],
           where=Op(AND, Op(GE, Col("orders", "total"), Int(1)), Op(LE, Col("orders", "total"), Int(5)))),
   [rd("orders"), rd("orders", "id"), rd("orders", "total")])
ok("select id from orders where total not between 1 and 5",
   Select2([Col("orders", "id")], [From("orders")],
           where=Un(0, Op(AND, Op(GE, Col("orders", "total"), Int(1)), Op(LE, Col("orders", "total"), Int(5))))),
   [rd("orders"), rd("orders", "id"), rd("orders", "total")])
ok("select id from orders where id in (1, 2, 3)",
   Select2([Col("orders", "id")], [From("orders")], where=In(0, Col("orders", "id"), Int(1), Int(2), Int(3))),
   [rd("orders"), rd("orders", "id")])
ok("select id from orders where customer not in (id)",
   Select2([Col("orders", "id")], [From("orders")], where=In(1, Col("orders", "customer"), Col("orders", "id"))),
   [rd("orders"), rd("orders", "id"), rd("orders", "customer")])
ok("select case when total > 1 then 'a' else 'b' end from orders",
   Select2([Case([(Op(GT, Col("orders", "total"), Int(1)), Txt(b"a"))], Txt(b"b"))], [From("orders")]),
   [rd("orders"), rd("orders", "total")])
ok("select case id when 1 then 2 when 3 then 4 end from orders",
   Select2([Case([(Op(EQ, Col("orders", "id"), Int(1)), Int(2)), (Op(EQ, Col("orders", "id"), Int(3)), Int(4))])],
           [From("orders")]),
   [rd("orders"), rd("orders", "id")])
ok("select total::numeric(10,2), cast(id as bigint) from orders",
   Select2([Cast("numeric(10, 2)", Col("orders", "total")), Cast("bigint", Col("orders", "id"))], [From("orders")]),
   [rd("orders"), rd("orders", "total"), rd("orders", "id")])
ok("select lower(name) || 'x' from customers",
   Select2([Op(CONCAT, Call("lower", Col("customers", "name")), Txt(b"x"))], [From("customers")]),
   [rd("customers"), rd("customers", "name"), (C, "lower")])
ok("select now() from orders", Select2([Nondet("now")], [From("orders")]), [rd("orders"), (N, "now")])
ok("select -total, not true, 1.5, 'it''s', null from orders",
   Select2([Un(1, Col("orders", "total")), Un(0, Txt(b"true")), Txt(b"1.5"), Txt(b"it's"), NULLC], [From("orders")]),
   [rd("orders"), rd("orders", "total")])
ok("select id from orders where customer like 'a%' or customer not ilike 'b%' or id % 2 = 0",
   Select2([Col("orders", "id")], [From("orders")],
           where=Op(OR, Op(OR, Op(LIKE, Col("orders", "customer"), Txt(b"a%")), Op(NILIKE, Col("orders", "customer"), Txt(b"b%"))),
                    Op(EQ, Op(MOD, Col("orders", "id"), Int(2)), Int(0)))),
   [rd("orders"), rd("orders", "id"), rd("orders", "customer")])

# ---- ORDER BY takes an output name first, and refuses one that two different outputs have
ok("select id, id from orders order by id",
   Select2([Col("orders", "id"), Col("orders", "id")], [From("orders")], order=[Order(Col("orders", "id"))]),
   [rd("orders"), rd("orders", "id")])
ok("select orders.*, * from orders order by id",
   Select2([Col("orders", c) for _ in range(2) for c in ("id", "customer", "total")], [From("orders")],
           order=[Order(Col("orders", "id"))]),
   [rd("orders")] + [rd("orders", c) for c in ("id", "customer", "total")])
ok("select total as id from orders order by id",
   Select2([Col("orders", "total")], [From("orders")], order=[Order(Col("orders", "total"))]),
   [rd("orders"), rd("orders", "total")])

# ---- INSERT, UPDATE, DELETE
ok("insert into orders values (1, 2, 3)",
   Insert("orders", ["id", "customer", "total"], [[Int(1), Int(2), Int(3)]]), [(W, "orders")])
ok("insert into orders (total, id) values (3, 1), (4, 2)",
   Insert("orders", ["total", "id"], [[Int(3), Int(1)], [Int(4), Int(2)]]), [(W, "orders")])
ok("insert into orders as o (id) values (now())", Insert("orders", ["id"], [[Nondet("now")]]), [(W, "orders"), (N, "now")])
ok("update orders set total = total + 1, customer = 7 where id = 5",
   Update("orders", [("total", Op(ADD, Col("orders", "total"), Int(1))), ("customer", Int(7))],
          Op(EQ, Col("orders", "id"), Int(5))),
   [(W, "orders"), rd("orders", "total"), rd("orders", "id")])
ok("update orders o set total = 0 where o.id in (1)",
   Update("orders", [("total", Int(0))], In(0, Col("orders", "id"), Int(1))), [(W, "orders"), rd("orders", "id")])
ok("delete from orders where customer = 1", Delete("orders", Op(EQ, Col("orders", "customer"), Int(1))),
   [(W, "orders"), rd("orders", "customer")])
ok("delete from customers", Delete("customers"), [(W, "customers")])

# ---- DDL
ok("create table x (a int)", Ddl(0, "x"), [(D, "x")])
ok("alter table orders add column z int", Ddl(1, "orders"), [(D, "orders")])
ok("drop table customers", Ddl(2, "customers"), [(D, "customers")])
ok("create unique index i on orders (id, total)", Ddl(3, "orders"), [(D, "orders")])
ok("drop index oi", Ddl(4, "orders"), [(D, "orders")])

# ---- refusals
no("select id from nowhere", "unknown-table")
no("select nope from orders", "unknown-column")
no("select id from orders, customers", "ambiguous-column")
no("select z.id from orders", "unknown-table")
no("select o.name from orders o", "unknown-column")
no("select orders.id from orders o", "unknown-table")                  # the alias hides the table's own name
no("select random() from orders", "nondeterministic")
no("select nextval('s') from orders", "nondeterministic")
no("select clock_timestamp() from orders", "nondeterministic")
no("select 1", "cannot-lower")
no("insert into nowhere values (1)", "unknown-table")
no("insert into orders (nope) values (1)", "unknown-column")
no("insert into orders values (1)", "syntax")
no("insert into orders (id) values (id)", "unknown-column")
no("update orders set nope = 1", "unknown-column")
no("update orders set total = nope", "unknown-column")
no("update nowhere set a = 1", "unknown-table")
no("delete from nowhere", "unknown-table")
no("delete from orders where nope = 1", "unknown-column")
no("alter table nowhere add column z int", "unknown-table")
no("drop table nowhere", "unknown-table")
no("drop index nope", "unknown-table")
no("create index i on nowhere (a)", "unknown-table")
no("select * from orders, customers order by id", "ambiguous-column")
no("select id::bigint, id from orders order by id", "ambiguous-column")
no("select total as id, id from orders order by id", "ambiguous-column")
no("select id from orders where nope", "unknown-column")
no("select id from orders group by nope", "unknown-column")
no("select id from orders having nope > 1", "unknown-column")
no("select id from orders order by nope", "unknown-column")
no("select id from orders limit nope", "unknown-column")


# ------------------------------------------------------------------ running it
ROOT, ROOT_PK = g.key("root")
T = 1_700_000_000_000
NONE = 2**64 - 1
BLOCK = b"cancho-db/token-block/v1\x00"
TOKEN = b"cancho-db/token/v1\x00"
STMT = b"cancho-db/stmt/v1\x00"


def allow_all_token():
    pl = bytes(32) + b16(b"*") + lst([g.effect(k, b"*") for k in range(5)]) + g.u64(NONE)
    nsk, npk = g.key("lower token")
    block = pl + npk + ROOT.sign(BLOCK + pl + npk)
    return block


def run(cmd, stdin=None):
    return subprocess.run(cmd, input=stdin, capture_output=True, timeout=60)


def lower(sql):
    r = run([LOWER], (SCHEMA + "---\n" + sql).encode())
    out = r.stdout.decode().strip()
    if r.returncode != 0 or not out:
        return ("crash", r.stderr.decode()[:200])
    kind, _, rest = out.partition(" ")
    return (kind, bytes.fromhex(rest) if kind == "ok" else rest)


def verify_with(stmt, effects, tmp, label):
    """Does the verifier accept a commit that records exactly `effects` over `stmt`?"""
    block = allow_all_token()
    tid = hashlib.sha256(TOKEN + u32(1) + block).digest()
    sid = hashlib.sha256(STMT + stmt).digest()
    c = g.Chain()
    c.add("main", token=tid, time=T, statements=[sid], effects=[g.effect(k, t.encode()) for k, t in effects])
    d = Path(tmp)
    (d / (label + ".log")).write_bytes(g.log(*[g.record(e) for e in c.encs]))
    (d / (label + ".tokens")).write_bytes(b"CHODBTK1" + u32(4 + len(block)) + u32(1) + block)
    (d / (label + ".stmts")).write_bytes(b"CHODBST2" + u32(len(stmt)) + stmt)
    r = run([VERIFY, str(d / (label + ".log")), "--root", ROOT_PK.hex(), "--tokens", str(d / (label + ".tokens")), "--stmts",
             str(d / (label + ".stmts"))])
    return r.stdout.decode().strip()


def main():
    bad, byte_ok, effect_ok, refused = [], 0, 0, 0
    with tempfile.TemporaryDirectory() as tmp:
        for n, case in enumerate(CASES):
            sql = case[0]
            got = lower(sql)
            if len(case) == 2:
                if got != ("refused", case[1]):
                    bad.append((sql, "want refused %s" % case[1], got))
                else:
                    refused += 1
                continue
            _, want_ir, effects = case
            if got[0] != "ok" or got[1] != want_ir:
                bad.append((sql, "IR differs", "want " + want_ir.hex(), "got " + (got[1].hex() if got[0] == "ok" else str(got))))
                continue
            byte_ok += 1
            line = verify_with(got[1], effects, tmp, "c%d" % n)
            if line != "ok commits=1 branches=1 level=2+ir":
                bad.append((sql, "the verifier does not accept the hand-written effects", line))
                continue
            # the same statement recorded with one effect fewer, and with one more, must be refused: the check can fail
            fewer = effects[:-1]
            extra = effects + [(R, "zzz.zzz")]
            for what, eff in (("fewer", fewer), ("extra", sorted(set(extra)))):
                line = verify_with(got[1], eff, tmp, "c%d%s" % (n, what))
                if "effects-mismatch" not in line:
                    bad.append((sql, "recording %s effects was not refused" % what, line))
            effect_ok += 1
    print("lowering: %d IR byte-for-byte, %d effect sets accepted by the verifier (each also refused with one fewer and "
          "one more), %d refusals with the right tag" % (byte_ok, effect_ok, refused))
    for b in bad[:12]:
        print("FAIL", *b)
    print("%d failures in %d cases" % (len(bad), len(CASES)))
    return 1 if bad else 0


sys.exit(main())
