# M1, slice P3: the extended protocol

Status: **designed; P3a built (section 7); P3b to P3d not.** Written against measurements (section 2, `scripts/measure_p3.py`) and against the proxy as it is after P2.
The decisions (section 3) are recommendations; the slices (section 5) start when they are accepted.

## 1. What this adds, and why it is the last open M1 criterion

M1's exit criteria are three: the log verifies at L1 and L2 (built: P2, with the IR check, accepted by three verifiers), a statement outside a narrowed
token is refused before PostgreSQL sees it (built: P1), and **the client list passes unmodified**. Today only `psql` does. The proxy refuses every
extended-protocol message (`0A000`, one error, discarded to `Sync`), and every driver but one sends the extended protocol for a statement with
parameters. P3 makes the proxy understand it, with the same rule as everywhere else: **nothing reaches PostgreSQL that the guard has not seen, and
nothing is acknowledged that the log does not hold.**

## 2. Measured facts

`scripts/measure_p3.py` puts a tee (`tools/pgtee.py`, which now decodes Parse, Bind, Describe, Execute and Close) between each driver and PostgreSQL 16.15 and prints the
client's messages for the same few scenarios. Drivers: psycopg 3.3.9, psycopg2 2.9.13, pg8000 1.31.6, asyncpg 0.32.0, node-postgres (`pg`), pgx 5.7.1.
(JDBC was not measured: it needs a Maven download and a JVM harness; it is on the list as unmeasured.)

| # | Fact | Consequence |
|---|---|---|
| F1 | **psycopg2 uses the simple protocol**: it puts the values into the text (`select ... where a = 1`). Through the proxy today it works end to end. Every other driver sends `Parse` with `$1`, `$2` and the values in `Bind`. | psycopg2 needs nothing. The rest need P3. |
| F2 | Through the proxy today, psycopg 3, pg8000, asyncpg and node-postgres **log in with the token as the password** (cleartext) and then fail at the first parametrised statement with the proxy's own refusal. pgx was not exercised (the measuring program passed no password: a gap in the script, not a result). | Login is not the obstacle. |
| F3 | Message sequences differ by driver. psycopg 3, node-postgres: `Parse, Bind, Describe(P), Execute, Sync` with an **unnamed** statement, every time. asyncpg: `Parse(name), Describe(S), Flush, Bind, Execute, Sync`, and the **named** statement is reused by `Bind` alone. pgx: `Parse(name), Describe(S), Sync`, then `Bind, Describe(P), Execute, Sync` with a cached name. pg8000: a `Flush` or `Sync` after every message and `Describe(S)` first. | The proxy cannot assume a shape; it must follow the protocol's own state machine, and keep a table of named statements (asyncpg, pgx, node's `name:`, psycopg 3's `executemany`: `_pg3_0`). |
| F4 | `Bind` carries each parameter in **text or binary** (psycopg 3 sends an int as 2 binary bytes, numeric as binary; node-postgres sends everything as text; asyncpg and pgx binary), and result formats vary. NULL is length -1. | The proxy must not interpret values. Everything it needs is in the SQL text of `Parse`. |
| F5 | A statement's effects depend on its **text** only (`where a = $1` reads `a` whatever `$1` is). | The guard works on `Parse`, once per statement, not per `Execute`. |
| F6 | psycopg 3's `executemany` sends `BEGIN` **as a Parse/Bind/Execute**, then `Parse(_pg3_0)`, `Bind, Describe, Execute` twice, then `Sync`, `Flush`. asyncpg and pgx send `BEGIN;` / `begin` and `COMMIT` as a simple `Query` even though they use extended for the rest. | Transaction control arrives both ways and must mean the same. |
| F7 | A parametrised statement with no `FROM` (`select $1`) is not something the guard lowers (no table), and PostgreSQL itself refuses `select $1` without a type. A bare `select 1` (a health check) is refused by the guard today (`cannot-lower`). | Noted for the compatibility list; not P3's to change. |
| F8 | **PostgreSQL 16 accepts `EXPLAIN (GENERIC_PLAN)` for a statement containing `$n`.** | The differential tests of the SQL pipeline can compare the plan of a parametrised statement and of its rendering, as they do for literals. |
| F9 | **The lexer refuses `$1` today** (`parameter`), and so does everything after it; but the IR spec already has the node (`Param index:u32`) and the three verifiers decode it. | P3a is the SQL pipeline (lexer, parser, lowering, renderer), not the verifiers or the spec's grammar. |
| F10 | **A bug in P2a, found while measuring**: a simple-protocol message of two selects reached the client as `T D T D C C Z` and psql lost the first tag (the proxy held every `CommandComplete` and streamed the rows after them). Fixed first (`docs/m1-commit-path.md` section 5.1, corrected in place; two mutants): only the newest tag is held now. | The held-tag rule P3 needs (one tag, in order) exists and is tested. |

What is not measured and the design rests on PostgreSQL's documentation for it: portal suspension (`Execute` with a row limit, which server-side cursors use), `Describe`
of a portal vs a statement, the error rule (an error discards messages up to `Sync`).

## 3. Decisions

**P3-D1. Parameters are `Param` nodes.** `$n` lexes as a parameter token and parses as an expression atom wherever the grammar takes an expression; the
lowering writes `Param n` with the number **as written** (`$1` is 1; one sentence added to `ir.md`, no verifier changes: they decode a `u32`); the renderer writes `$n`;
inference gives it no effect. `$0`, a number over 65,535 (PostgreSQL's own limit) or a name that is not a number is refused (`parameter`). A statement is
its own prepared statement: the highest `$n` is its parameter count.

**P3-D2. The messages.** Accepted: `Parse`, `Bind`, `Describe`, `Execute`, `Sync`, `Flush`, `Close` (and `Terminate`, as now). Refused as now: `CopyData`,
`CopyDone`, `CopyFail`, `FunctionCall` (a protocol violation, `0A000`, the connection closed), and SQL-level `PREPARE`, `EXECUTE`, `DEALLOCATE`, `COPY`, `SET`, `SHOW`
(each is outside the subset today and **must stay so**: `EXECUTE` would run a statement the guard never saw).

**P3-D3. The proxy keeps, per client: the unnamed statement and up to 32 named ones, the unnamed portal and up to 16 named ones.** A statement record holds what
the guard produced for it at `Parse`: the IR id, the IR record, the effects, the parameter count, and whether it is transaction control. A portal record
holds its statement, and whether it has already been executed (portal continuation, D7). More than the caps: `54000` and the pipeline is aborted to `Sync`.
A record is at most 4 KiB of IR; larger is refused `54000`. `Close` and a `Parse` over an existing name (PostgreSQL's error, which the proxy leaves to the server
for named statements and replaces for the unnamed one) keep the tables as the server's are.

**P3-D4. `Parse`: the guard sees it, the server gets the rendering.** The query text goes through exactly the path of a simple `Query` of one statement (lexer,
parser, lowering, `ir.infer`, token check). A message of more than one statement is refused (`multiple-statements`, `0A000`: PostgreSQL refuses it too). If it is
refused, the proxy answers `ErrorResponse` and **discards every message up to `Sync`** (what PostgreSQL does and what the proxy already does), then answers `ReadyForQuery`
with the right status. If allowed, the rendering is sent upstream in a `Parse` with the **same statement name and parameter types**.

**P3-D5. The rest is forwarded as it is, after bookkeeping.** `Bind` (the portal and statement names, the parameters: untouched), `Describe`, `Close`, `Flush`, `Sync`.
`Execute` is the moment the statement counts. **Transaction control never reaches the server**: for a `BEGIN`, `COMMIT` or `ROLLBACK` statement the proxy answers `Parse` with
`ParseComplete`, `Bind` with `BindComplete`, `Describe` with `NoData`, `Close` with `CloseComplete`, and `Execute` with what the simple protocol gives (`CommandComplete BEGIN`
and so on), keeping its own transaction record (P2-D2) and running the commit sequence on `COMMIT`.

**P3-D6. What a commit records.** `statements` lists the IR id **of each `Execute`**, in order, so a statement executed twice is listed twice; `effects` is the union, as
now. **The bound values are not recorded.** The commit says which statement shapes ran, in what order, with what effects; it does not say with what values, so a
parameterised statement cannot be replayed (L3, M2) from the log alone. This is a limit to state in `claims.md`, not a bug: M1's log is L1 and L2 and the IR check, and M2 will
need the values for `changes` and `state` anyway and will add them to the commit (a new version of the format, with its own spec and vectors). *Chosen over* putting the
values into the SQL text, which would break prepared statements and binary parameters and change PostgreSQL's plans, and over recording them now, which is a format change for
no M1 gate to test it.

**P3-D7. Transactions.** An implicit transaction is the messages from the first one after a `ReadyForQuery` to `Sync`. At its first message the proxy has an idle server (every
earlier answer was consumed: the proxy holds `ReadyForQuery` until a commit is durable), so it opens a transaction there exactly as for a simple `Query` (`BEGIN`, answer swallowed). At
`Sync` the server's `ReadyForQuery` is held and the commit sequence runs (P2-D4 to D6, unchanged), then it is released. In an explicit transaction `Sync` commits nothing; the
`COMMIT` statement does (via a `Query` or an `Execute`, both end in the same code). **Portal continuation**: an `Execute` with a row limit may be answered `PortalSuspended` and
resumed by a later `Execute` of the same portal; the statement is recorded at the portal's **first** `Execute` and not again.

**P3-D8. The held tag.** The rule from the F10 fix applies unchanged: only the newest `CommandComplete` is held; anything that follows releases it; `ReadyForQuery` is
released after the commit.

**P3-D9. Errors.** A server error inside a pipeline fails the transaction exactly as for a simple `Query`: the proxy sees the `ErrorResponse` and marks the client `E`; the server discards to `Sync`.
A refused message (D4) inside an explicit transaction aborts it (P2-D3): the proxy rolls the upstream transaction back and answers `25P02` to what follows until `ROLLBACK`.

**P3-D10. What the client list means for M1** (a decision for the owner, section 6): the six drivers measured, plus `psql`, are what P3 targets. **SQLAlchemy, Prisma, Metabase and JDBC are not
in P3**: they read `pg_catalog` and `information_schema`, send `SET` statements and use savepoints, none of which is in the subset, and each needs its own measured, allow-listed
catalog read (the "long tail" of `design.md`). Calling M1's third criterion met means these seven.

## 4. What does not change

The simple-protocol path, the login, the token check, the commit builder and the log, recovery, the verifiers and every format. P3 adds a way to reach the same guard and the same
commit sequence.

## 5. Slices

| Slice | Delivers | Gate |
|---|---|---|
| **P3a** | `$n` through the lexer, parser, lowering and renderer; one sentence in `ir.md` | the differential suites (parser, SELECT, statements, lowering) grow parametrised cases and compare `EXPLAIN (GENERIC_PLAN)` of the original and of the rendering against PostgreSQL; hand-written IR and effects with `Param` checked by the real verifiers; mutants |
| **P3b** | the extended messages in the proxy: the statement and portal tables, `Parse` through the guard, pass-through of the rest, the discard-to-`Sync` error rule, transaction control answered by the proxy | every sequence of section 2 replayed byte for byte from the tee captures: the proxy's answer equals PostgreSQL's (except the rendering inside `Parse`); the wire tee shows the upstream messages; mutants |
| **P3c** | the commit path for the extended protocol: begin at the first message, accumulate at `Execute`, commit at `Sync`, portal continuation | the log, tokens and statements of a pipeline session accepted by the three verifiers at L2 and IR; the rows equal the commits; the fault windows of `m1-commit-path.md` section 4 for a pipeline; mutants |
| **P3d** | the six drivers through the proxy, end to end, in the gate | for each: connect, a parametrised select, an insert, a transaction, a prepared statement reused, `executemany` where it has one; the rows right; the commits in the log are the statements run, in order; CI installs the drivers (a venv, `npm`, `go`) |

## 6. Decisions the owner is asked for

1. **D6: bound values are not recorded in M1** (a statement of a given shape ran; replay will need the values and M2 adds them to the format).
2. **D10: the client list for M1** is `psql` and the six drivers; the catalog-reading tools (SQLAlchemy, Prisma, Metabase, JDBC) are a later, separate piece of work.
3. **D2: SQL-level `PREPARE`, `EXECUTE`, `DEALLOCATE`, `SET`, `SHOW` stay refused.**
4. The order: P3a to P3d as above.

## 7. P3a as built: `$n` through the SQL pipeline

`$n` lexes as a parameter token (`t_param`, 9; `$1` to `$65535`; `$0`, a leading zero, a number over 65535 and a number followed by identifier characters or digits are refused `parameter`),
parses as a leaf (`n_param`, 50), is written back as written, and lowers to `Param n` (tag 2 and a `u32`, the number as written). It has no effect. `ir.md` says the index is the
number as written (one sentence; no verifier or vector changed). Where the grammar takes an expression a parameter may stand: `where a = $1`, `values ($1, $2)`, `set b = $1`,
`in ($1, $2)`, `limit $1`, `case`, casts, calls. PostgreSQL's own rules about types stay PostgreSQL's: `select $1 from t` is allowed through (PostgreSQL will refuse it at `Parse` with
"could not determine data type of parameter $1", which is the proxy's answer too, because the error comes from the server).

Gates, all passing: the lexer cases (`$1`, `$12`, `$65535`, `$1,$2` and the refusals) and `lex_diff` (4000 strings); the parser cases (nine parameter shapes) and `parse_diff` with parameters in
the generators (4000 cases, two seeds): **the plan of the original and of the rendering are compared with `EXPLAIN (GENERIC_PLAN)` for any statement with a `$`**; `stmt_diff` and `ddl_diff`
(8000 and 3000 cases); `lower_check`, whose six new cases give the IR bytes byte for byte as hand-written and effect sets the real verifier accepts (each refused with one fewer and one more);
the guard (nine cases, including a token narrowed to `orders.id` allowing `where id = $1` and refusing `where customer = $1`, and the ids and effects of the IR handed over checked by the
Python verifier's own inference). 8 mutants (lexer 4, parser 2, lowering 3 and one old lexer mutant moved to the new code); one more that the tests could not see turned out to be equivalent
(`emit_close` of a leaf falls through to the same result) and was dropped.

Not yet: nothing in the proxy reads `$n` from a client (P3b); a `Parse` still reaches the proxy's refusal of the extended protocol.
