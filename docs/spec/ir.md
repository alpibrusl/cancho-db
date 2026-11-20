# Statement IR and effect inference, version 1

This extends [`commit.md`](commit.md) and [`token.md`](token.md). It closes a gap those two leave open: L2 checks the
**recorded** effect set of a commit against its token, and says nothing about whether the recorded set is what the commit's
statements actually do. A server that recorded a smaller set than it ran would pass. This page defines the **statement IR**
(what `statements: [Hash]` in a commit hashes), the **effect inference** from an IR statement to an effect set, and the check
that **the recorded set equals the inferred one**, so that L2's token check is about what ran.

A verifier needs this page, `commit.md` (notation, §1, and `Value`), `token.md`, SHA-256 and Ed25519.

## 1. Scope

The IR is the **bound** form of a SQL statement: names are resolved (aliases replaced by base tables, `*` expanded to
columns), so inference needs no schema. Lowering SQL to this IR is the server's job and is not specified here; what is
specified is what a verifier can check *given* the IR.

**v1 is deliberately small**: one table (or a list of tables) per statement, no subqueries, no `RETURNING`, no CTEs, no
set operations. The design says the SQL subset grows only when a listed client needs it; a construct that does not fit
here is a new IR `version`, not a quiet extension. A statement the server cannot express in v1 IR it cannot run.

## 2. The IR

```
Statement = tag body
  0 Select   items:[Expr]  from:[Name]  where:Opt          // from has at least one
  1 Insert   table:Name  columns:[Name]  rows:[Row]        // Row = [Expr]; each row as long as `columns`
  2 Update   table:Name  sets:[Set]  where:Opt             // Set = column:Name Expr; at least one
  3 Delete   table:Name  where:Opt
  4 Ddl      kind:u8  table:Name                           // 0 create table, 1 alter table, 2 drop table,
                                                           // 3 create index, 4 drop index
  5 Call     fn:Name  args:[Expr]
Opt       = 0 | 1 Expr                                     // a u8 flag, then an Expr if it is 1
Name      = bytes16                                        // length at least 1
Expr      = tag body, in PREFIX order (the operator first, then its operands):
  0 Col      table:Name  column:Name
  1 Const    Value                                         // commit.md §2
  2 Param    index:u32                                     // the number as written in the statement: `$1` is 1 (P3, m1-extended.md)
  3 Nondet   source:Name                                   // now, random, a sequence: a value the server chose
  4 Call     fn:Name  argc:u32   then argc Exprs
  5 Op       op:u8 (0 to 11)     then 2 Exprs              // eq ne lt le gt ge and or add sub mul div
```

Every `Name` is at least one byte. `Name`s of tables and columns (every `Name` except a `Call`'s `fn` and a `Nondet`'s
`source`) MUST ALSO NOT contain the byte `.` (0x2E): effect targets join a table and a column with it (§3), and a name that
held one would make two different reads look the same. A name of length 0, or a table or column name that breaks this, is
`stmt-bad-encoding`. A function or source name may contain a `.` (`pg.round`).

**Prefix order is what makes this checkable without recursion.** An expression is well formed if reading it leaves no
operand missing and none over: keep a count of operands still owed, start it at 1, and at each node subtract 1 and add
that node's operand count (0 for `Col`, `Const`, `Param`, `Nondet`; `argc` for `Call`; 2 for `Op`). **An expression is
exactly the shortest prefix of the bytes at which the count reaches 0**: what follows belongs to whatever comes next, and if
the bytes run out while the count is above 0 the statement is malformed. A count larger than the bytes left is malformed
(every node is at least one byte), so no number is ever trusted to size anything.

Other malformations, all `stmt-bad-encoding` (and, being one tag, in no order a verifier could be caught out on): an unknown
tag, kind, op, flag or `Const` value tag; an `Insert` row whose own `u32` count differs from the number of `columns`, or
one containing a `Col` (a column reference means nothing in `VALUES`); a `Select` with no `from`; an `Update` with no `sets`;
any count larger than the bytes left; bytes after the end of the statement. **Not malformed:** an `Insert` with no columns
or no rows, a `Select` with no items, and a `Col` whose table is not in the statement's `from` (this IR has no scope check:
the lowering resolves names, and inference records the reads of whatever is named, so `read t.c` is recorded and `read t` is
not).

**Identity.** `id = SHA-256("cancho-db/stmt/v1" || 0x00 || encoding(statement))`. This is what `statements` lists, in
execution order.

## 3. Effect inference

The effect set of a statement is a set of `(kind, target)` as in `commit.md` §2 (kinds: 0 read, 1 write, 2 ddl, 3 call,
4 nondet), built by these rules, with `t` and `c` names:

| Where | Effects |
|---|---|
| `Select` | `read t` for **each** table in `from`; `read t.c` for each `Col(t, c)` in its items and its `where` |
| `Insert` | `write t` (the effects of a row's expressions below) |
| `Update` | `write t`; `read t'.c'` for each `Col(t', c')` in its `sets` expressions and its `where` |
| `Delete` | `write t`; `read t'.c'` for each `Col(t', c')` in its `where` |
| `Ddl` | `ddl t` |
| `Call fn` (a statement) | `call fn`, and the expression effects of its arguments |
| `Call fn` (an expression) | `call fn` |
| `Nondet source` (an expression) | `nondet source` |
| `Const`, `Param`, `Op`, `Col`'s table alone | nothing beyond the columns above |

A `Select` records `read t` as well as the columns because *which rows exist* is information: `SELECT 1 FROM orders` or a
count reads the table though it names no column. Consequently a token that allows `read orders.*` does **not** allow a
select from `orders` (`token.md` §2: `orders.*` does not match `orders`); the token must grant `read orders` too. An
`Update` or `Delete` does not record `read t` for its row count, the writer having `write t`; that is a stated limit, not an
oversight (`claims.md`).

A `Call` effect names the function and is **not expanded** into what the stored function itself does; expanding it needs
the function's declared effects, which are M1's. So L2 over `call fn` says the token allowed *calling* `fn`.

The **inferred set** of a commit is the union over its `statements`, in no order and without repeats. A commit with no
statements has the empty set.

## 4. The store and the check

```
stmts = ( "CHODBST1" | "CHODBST2" ) ( u32 length  Statement )*      |      "CHODBST3" ( u32 length  record )*     (section 8)
```

The magic selects the grammar: `CHODBST1` is v1 (§2), `CHODBST2` is v2 (§6, a strict superset), `CHODBST3` is v3 (§8: the records of a store whose constants are payloads). Any other magic is
`stmts-bad-magic`.

A statement listed twice is the same statement (its id is the same, and the `record` of a malformed entry counts entries,
repeats included). The verifier is given the store with `--stmts FILE` (which requires
`--root`: this is a further check on L2, `token.md` §6).

**The store** is read after the token store and the revocation list and before any commit (`token.md` §4), with, as
there, `record` the index of the entry, or `-1` for the header, and entries read and judged one at a time, in order, the
first failure being the verdict (an earlier malformed statement beats a later truncated entry): fewer than 8 bytes `stmts-truncated`; the magic differs
`stmts-bad-magic`; an entry whose `length` runs past the end `stmts-truncated`; a statement that does not decode
`stmt-bad-encoding`.

**Commits.** With `--stmts`, the checks of `token.md` §4 run in their order **except that `effect-denied` moves to the
end**, and two checks come before it:

| # | Rule | Fails when |
|---|---|---|
| 1 to 6 | as `token.md` §4 | |
| 7 | `stmt-missing` | some hash in the commit's `statements` is not the id of a statement in `stmts` |
| 8 | `effects-mismatch` | the commit's `effects` is not **exactly** the inferred set of its statements |
| 9 | `effect-denied` | as `token.md` §4 check 7, now judged on a set that has been shown to be the real one |

Equality, not containment: a recorded set larger than what ran is as much a falsehood as a smaller one, and a log that
over-reports hides what was actually done among what was not.

With `--stmts` the success line is `ok commits=<N> branches=<B> level=2+ir`.

## 5. What this does and does not give

- **Given** a statement store the reader trusts to be the statements that ran, L2 now says each commit was allowed to
  do *what its statements do*, at the granularity of tables for writes and columns for reads.
- **Not given:** that the store holds the statements the server *actually executed*. The log commits to their hashes
  (`statements`), and a verifier shows the IR hashes to the same bytes, but whether the server then executed that IR, and
  whether it lowered the client's SQL to it faithfully, is the server's honesty again. L3 (replay, M2) is what checks
  execution; this makes the claim *about* the statements checkable.
- **Lowering is not specified.** A bug in the lowering (an alias resolved to the wrong table) yields an IR that is
  consistent with its own effects and wrong about the SQL. Differential testing against Postgres (design, "Verification
  strategy") is what covers that, at M1.
- **Not in v1:** subqueries and anything else §1 lists, `call` expansion, row-level predicates.

## 6. IR version 2

v1 (§2) cannot say what a psql user types: no `ORDER BY`, `GROUP BY`, `HAVING`, `LIMIT`, `DISTINCT`, outer joins, `IS NULL`,
`IN`, `LIKE`, `CASE`, casts, `NOT`, or `*` as an aggregate's argument. Each matters to inference, because **a column named
in an `ORDER BY`, a `HAVING` or a join condition is a read**, and inference that skipped them would under-report
(`docs/m1-proxy.md` D4). v2 adds exactly those and nothing else.

**v2 is a strict superset of v1, selected by the statement store's magic.** A store that starts `CHODBST2` may hold v2
statements; one that starts `CHODBST1` holds v1 only, and a v2 tag in it is `stmt-bad-encoding`. A statement that is valid in
v1 has the same bytes, the same meaning, the same effects and **the same id** in v2 (the id's domain string names the hash
construction, not the grammar). So moving a store from v1 to v2 never changes a commit's `statements` hashes.

**Statement.** One new tag:

```
  6 Select2   distinct:u8  items:[Expr]  from:[From]  where:Opt  group:[Expr]  having:Opt  order:[Order]  limit:Opt  offset:Opt
From      = table:Name  kind:u8  on:Opt         // kind 0 a comma (no ON), 1 inner join, 2 left join
Order     = Expr  dir:u8  nulls:u8              // dir 0 ascending, 1 descending; nulls 0 default, 1 first, 2 last
```

`distinct` is 0 or 1. `from` has at least one entry; the **first** has kind 0 and flag 0 (no `on`); any other entry of kind 1
or 2 has an `on` (flag 1), and one of kind 0 has none. **`items`, `group` and `order` may be empty; only `from` may not.** A
`Select` (tag 0) is still valid and means what it did. Every `Opt` flag, in v1 and in v2, is 0 or 1.

**Expressions.** New tags, in prefix order like the old ones:

```
  6 Star                                          // the argument of count(*); no operand
  7 Unary     op:u8  then 1 Expr                  // 0 NOT, 1 negation, 2 IS NULL, 3 IS NOT NULL
  8 In        negated:u8  n:u32  then 1 + n Exprs // the tested expression, then the n list members
  9 Case      n:u32  has_else:u8  then 2n + has_else Exprs   // n (condition, result) pairs, then the else
 10 Cast      type:Name  then 1 Expr              // the type name is free (any bytes, at least one)
```

and `Op`'s operator range grows from 0..11 to **0..17**: 12 `LIKE`, 13 `ILIKE`, 14 `NOT LIKE`, 15 `NOT ILIKE`, 16 `||`,
17 `%`. `negated` is 0 or 1. A simple `CASE x WHEN a ...` and `x BETWEEN a AND b` have no node: lowering writes them with
`Op` and `Case`, and inference sees the same columns. `Case` needs `n` of at least 1.

**Effects.** v1's rules (§3) hold, with the same targets, and a `Col(t, c)` **anywhere in** `items`, `where`, `group`, `having`,
`order`, `limit`, `offset` or an `on` is `read t.c`; each `from` table is `read t`. `Star`, `Unary`, `In`, `Case` and `Cast` add
nothing of their own: **a cast is not a call**, and a type name is not an effect. A `Call` is `call fn` as before, so an
aggregate (`count`, `sum`) or a builtin (`lower`) is a `call` the token must grant (`call *` for all of them).

All the new expression nodes obey §2's owed-operand rule, and their counts come from the data (`In`'s `n`, `Case`'s `n` and
`has_else`) as `Call`'s `argc` does: a shortfall or a surplus of operands is `stmt-bad-encoding`, as before. A `Cast`'s type
name may contain `.` (`pg_catalog.text`): only table and column names may not. **The success line is `level=2+ir` for either
magic**: the grammar does not show in it.

**Malformations**, all `stmt-bad-encoding`, in addition to §2's: a tag or operator or `dir`/`nulls`/`kind`/`negated`/
`has_else`/`distinct` outside its range; a first `from` entry with a kind or an `on`; a join without an `on`, a comma with
one; a `Case` with no pairs; an `In` with no members; any count larger than the bytes left; and, in a `CHODBST1` store, any v2 tag
or operator (a v1 store holds v1 statements only).

### 6.1 History reads: a table's name may end in `@<commit id>`

A statement that reads a table **as it was** at a commit (`docs/m2-branches.md` D27 to D31) writes that table's `Name`, in `from` and in every `Col` that refers to it, as the table's name, `@`, and the commit's id as 64 lower-case hexadecimal digits: `orders@3f2a...`. **This is a convention about what a `Name` holds and not a new
construct: nothing in this specification, and no verifier, treats such a `Name` differently from any other.** What follows from the rules already here is the point of it:

* the statement's id hashes the commit that was read, so two reads of one table at two commits are two statements in the log;
* inference gives `read orders@3f2a...` and `read orders@3f2a....id` (§3, with the name as written), so a recorded set that drops the suffix, or names another commit, is `effects-mismatch`;
* a token's pattern matches the name as written (`token.md` §2): `orders` and `orders.*` do **not** permit a history read, `orders@*` does, and so does `orders*`, any pattern that is a prefix of the name and ends in `*`, which is the sharp edge of that rule and not a feature to rely on. A token that may read the current rows may not read the past unless it says so;
* the `.` rule (§2) holds: the `@` and the hex digits contain none.

Whether the commit exists, belongs to the branch, and is what the data was read as of, is the producer's business and not checked by L1 or L2. Vectors: `ir2_history_*` (`tools/gen_ir2.py`): accepted by all three verifiers, the suffix dropped, another commit recorded, a token of the plain table denied, a history token and a prefix token allowed, a history token denied the current table, and a history read joined to the current table.

## 8. Version 3: constants are payloads

**Status: specified, with vectors and three verifiers; the proxy does not write it yet.** The design is [`../m2g-erasure.md`](../m2g-erasure.md) D-E7 (Q14). Versions 1 and 2 are unchanged and keep their stores.

*Why.* A `Const` holds a value in clear in the statement store, and the statement id in the log hashes it unsalted, so a literal that a person could guess is recoverable from the log alone, and a statement cannot be erased without making L2 refuse the commit that cites it (m2g-erasure.md section 2b).

*What changes.* A store that starts `CHODBST3` holds **records** of a new form, and a v3 statement is a v2 statement whose constants have been **lifted out**:

```
Expr  += 11 Hole  vtype:u8                 // in place of a `Const`: only the type tag of its `Value` (commit.md §2) stays: 0 null, 1 int, 2 bytes (any other is `stmt-bad-encoding`)
record = u32 length  shape:Statement  chash:Hash  payload     // `length` covers all three; the shape is v2 grammar with `Hole` for `Const` (so v2's tags 6 to 10 are there, and `Select` is tag 6 of a statement)
payload = 0x00                              // erased: the constants and the salt are gone
        | 0x01  salt:bytes16(16 bytes)  n:u32  n Values     // the constants, in the order of their `Hole`s (prefix order), and the salt
chash   = SHA-256( "cancho-db/consts/v1" || 0x00 || salt || u32(n) || the n Values as written )
id      = SHA-256( "cancho-db/stmt/v3" || 0x00 || encoding(shape) || chash )
```

*What a verifier checks.* The id of a record is computed from the shape and `chash` alone, so a statement whose payload was erased has the id the log recorded. Inference (§3) runs on the shape (a `Hole` has no effect: no effect ever depended on the value of a constant, only on names). If the payload is present, the number of `Hole`s equals `n`, each `Value`'s type tag equals its `Hole`'s `vtype`, and `chash` is the hash above; otherwise **`stmt-consts-mismatch`** (new tag). A `Const` in a v3 shape, or a `Hole` in a v1 or v2 store, is `stmt-bad-encoding`.

*What it gives.* The log's `stmts` hashes commit to the constants through a salted hash, so they test nothing; erasing a statement means destroying its payload, after which L2 with statements still proves that the recorded effects are what the shape infers. *What it does not give:* the shape itself is not secret (table and column names, operators), and the constants are no longer checked to be those the statement ran with once erased.

*Malformations*, all `stmt-bad-encoding` and at the record's index: a `Const` in a shape; a `Hole` in a v1 or v2 store; a `vtype` over 2; a record that ends before `chash` and the payload tag; a payload tag other than 0 and 1; an erased payload (tag 0) followed by anything; a salt that is not 16 bytes (a payload shorter than its salt and count); a value with a tag over 2 or cut short; bytes after the last value. The order of checking in a record is: the shape and the record's structure (`stmt-bad-encoding`), then the payload against the shape and the hash (`stmt-consts-mismatch`). In a v3 store a commit's statement is found by the id of section 8, so a record whose `chash` is not the one the log was made with is a statement the store does not have (`stmt-missing`).

*Vectors:* `ir3_*` (`tools/gen_ir3.py`): accepted with the constants and erased (one id for both), with a `Param`, with null, int and empty or binary bytes holes; each malformation above; each way a payload fails to be what the record committed to (a flipped hash, a changed value, too few or too many values, a value of another type than its hole, another salt); and the commit and the store disagreeing.

*Slice.* E3b of m2g-erasure.md: this section, the vectors and the three verifiers (this); the proxy writing the v3 form is the next, and until then the statement store is not erasable and `cancho_erase` is not served through the proxy.

## 7. Vectors

IR vectors (v2 ones have a `CHODBST2` store) are L2 vectors (`token.md` §7) with a `NAME.stmts`, and an `args` line that adds `--stmts {dir}/NAME.stmts`.
`tools/gen_ir.py` writes them. In each, the effects a commit records are written out **by hand** from §3, not computed by
any inference function, as the expected lines are elsewhere.
