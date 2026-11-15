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
  2 Param    index:u32
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
stmts = "CHODBST1" ( u32 length  Statement )*
```

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

## 6. Vectors

IR vectors are L2 vectors (`token.md` §7) with a `NAME.stmts`, and an `args` line that adds `--stmts {dir}/NAME.stmts`.
`tools/gen_ir.py` writes them. In each, the effects a commit records are written out **by hand** from §3, not computed by
any inference function, as the expected lines are elsewhere.
