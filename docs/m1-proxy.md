# M1: the proxy, psql first

> **Status: design, written before the code.** Section 2 is measured (`scripts/measure_m1.py`, reproducible against any
> PostgreSQL 16 and `psql`); sections 3 to 7 are decisions, each with what it was chosen over; nothing here is built yet.
> A claim that turns out false is corrected in place, with the change that corrected it.

M1 of [`design.md`](design.md) is the cancho proxy in front of stock PostgreSQL: wire protocol, SQL parser, effect
inference, tokens, attested log. Its exit criterion there is *"the client list passes unmodified; the log verifies at L1
and L2; a statement outside a narrowed token is rejected before reaching Postgres"*, and it is the **demand test**: if
nobody wants the proxy, stop before building an engine. This document narrows the first pass to **`psql`** and says, with
measurements, what that does and does not include.

## 1. Scope

**In, for psql:** connect with a capability token as the password; run SQL from the subset of §4 D4, in autocommit and in
explicit transactions; get an ordinary `ERROR:` back for anything refused; and have every committed transaction appear in
a signed log that `verify` (L1, L2 and the statement IR) accepts.

**Out, said now so it is not discovered later:**

- **psql's backslash commands that read the catalog (`\d`, `\dt`, `\l`, ...).** Measured in §2: they cannot be lowered to
  the IR, and serving them is `pg_catalog` emulation, which the design puts at M4. In M1 they fail with a clear error
  naming the rule. This is a real loss of psql's most-used feature, accepted for now; section 8 asks whether to relax it.
- **The extended protocol** (`Parse`/`Bind`/`Execute`): psql does not use it for ordinary input (§2); drivers do. A driver
  slice follows psql.
- **Branches.** M1 serves one real database; the database name is checked against a configured branch name and no other is
  served, because isolation between branches is M2.
- **`COPY`, `LISTEN`/`NOTIFY`, temporary tables, `SET`**: session state, which a proxy that attributes every commit to a
  token should not let ride along unseen. Refused with a rule tag.
- **TLS**, replication connections, and L3 replay (the log's `changes` and `state` are zero until M2).

## 2. What was measured

Run against PostgreSQL 16.15 and psql 16.15 from the same Ubuntu packages, a throwaway cluster on ext4 with `fsync=on`,
by `PGHOST=127.0.0.1 PGPORT=5532 PGUSER=postgres python3 scripts/measure_m1.py`. Nineteen facts; the script exits non-zero
if one the design rests on stops holding. The ones that decide something:

| Fact | Measured | What it decides |
|---|---|---|
| What psql sends at connect | `SSLRequest`, then `StartupMessage` with exactly `user`, `database`, `application_name`; then `Query` | The proxy answers `SSLRequest` with `N` (psql carries on in clear), and the startup it must understand is three parameters. |
| psql with a script | one `Query` message **per statement**, `begin;` and `commit;` each their own | Transactions are visible as separate messages; the proxy tracks them from the messages and from `ReadyForQuery`'s status byte. |
| psql `-c "select 1; select 2"` | **one** `Query` message with both statements | A message can carry several statements, which PostgreSQL runs as one implicit transaction; the proxy must treat the message as the unit (D6). |
| `\dt` | 1 query, 740 bytes, two `LEFT JOIN`s | Not expressible in the IR (no outer joins). |
| `\d table` | **9 queries**, 4,349 bytes, four `LEFT JOIN`s, four subselects, one regex match | Not expressible, and not close. |
| `\l`, `\du`, `\dn`, `\di`, `\df` | 1 query each (186 to 887 bytes), `pg_catalog` functions, up to four `LEFT JOIN`s | Same: the backslash commands are catalog reads. |
| `PREPARE TRANSACTION` then `COMMIT PREPARED` from **another session** | works; the prepared transaction is invisible until committed | Atomic "Postgres commits" and "log appended" is possible (D7). |
| `ROLLBACK PREPARED` | works | The recovery path (§6) is available. |
| `PREPARE TRANSACTION` after temp tables, or `LISTEN` | **refused by PostgreSQL** (`cannot PREPARE a transaction that has operated on temporary objects` / `... executed LISTEN, UNLISTEN, or NOTIFY`) | Those constructs must be refused up front, which §1 already does. |
| `PREPARE TRANSACTION` after DDL | works | DDL can be committed through the same path. |
| `max_prepared_transactions` | **default 0** (`postgresql.conf.sample`: "zero disables the feature") | The operator must raise it; the proxy checks at start and refuses to run otherwise. |
| `now()` read inside a transaction | equals the `now()` that a later statement in it used (`DEFAULT now()`), while `statement_timestamp()` differs | The transaction's `now()` can be recorded by one extra `SELECT now()` before commit (D8). |
| Cost of the two-phase path | 0.82 and 0.86 ms per commit against 0.48 and 0.43 ms for an autocommit insert: **1.7 to 2.0 times**, over two runs | Acceptable for M1; the log's own `fsync` is on top and is measured at P2. |

**Not measured, and said so:** the cost on a real disk (this is a sandbox) and concurrency beyond a few dozen clients. (How
long a password psql will send was measured at P0: a token of 2, 3 and 5 blocks is a password of 440, 636 and 1,028
characters, about 196 per block, and psql sent all of them; see §7.)

## 3. How it works

```
psql ── 1 listener ── 2 startup + token ── 3 message loop ──────────────────────────── upstream PostgreSQL
                          │                    │  Query ─ lex ─ lower ─ infer ─ check(token) ─ forward
                          │                    │  tx state ─ commit builder ─ 2PC ─ log
                          └ root key           └ schema snapshot (introspected from upstream)
```

1. **Listener.** One thread and one event loop on `std.conns`, as `cancho-pg`'s pooler (`pooler/proxy.cho`); `cancho authority`
   on the proxy reports the network, the clock, the console and the heap, and that it never touches the filesystem,
   signals, other programs or foreign code. *Corrected at P0:* this said "names the network" as if bounded. It is **not**:
   this compiler revision has one `Net` per program and narrowing consumes it, so a program that both listens and dials
   cannot carry a narrowed one (`cancho/docs/net-bounds.md` §1), and the report says `net_in("")` and `net_out("")`
   *unbounded*. Which upstream the proxy dials is therefore enforced by its configuration, not shown by its report. P2
   adds the log directory, and with it a filesystem row.
2. **Startup.** `SSLRequest` is answered `N`; the startup message is parsed; the server asks for a **cleartext password**,
   which carries the token (D1). The proxy verifies the token against the root key (`token.md`), checks that the database
   name is a branch the token allows, opens the upstream connection with its own configured credentials, and relays the
   server's `AuthenticationOk`, `ParameterStatus`, `BackendKeyData` and `ReadyForQuery`.
3. **Message loop.** Every client message is read whole. `Query` text goes through the lexer and lowering (D4) to IR
   statements; their inferred effects are checked against the token **before anything is sent upstream**; what passes is
   forwarded. Everything else the client may send (`Terminate`, and in later slices the extended protocol) is handled
   explicitly or refused.
4. **Commit.** A transaction's statements are buffered as it runs. At its end a commit is built, written and made durable
   together with Postgres's own commit (D7).

## 4. Decisions

**D1. The token is the password, cleartext, with proof of possession.** (Built in `src/login.cho`; the principal a commit records is
the one non-zero principal the token's blocks name, or all zeros for a bearer token, and a token that names two is refused at
login: `login-principal-conflict`.) The password carries `base64url(token ‖ seed)`,
where `seed` is the 32-byte private key of the token's last block; the proxy checks that it derives the last block's
`next_key`. That is the missing piece `token.md` §1 deferred ("a client that presents a token also proves it holds the
private key of the last block"), in the form Biscuit calls an open token: the holder presents the key. *Chosen over* SCRAM,
which needs the server to know the secret in advance and cannot verify a token it has never seen, and over a challenge
signature, which needs a protocol change psql would not follow. *Cost, stated:* the token and its key cross the wire in
clear, so until TLS exists M1 serves loopback clients only. *Corrected at P0:* this said the proxy "listens on loopback
only". It cannot be told to: cancho's `tcp_listen` binds every address (measured: a client on the host's other address
connects). The rule is enforced where the connection is accepted instead: a peer that is not 127.0.0.0/8 or `::1` is closed
without a byte being read (measured: the client sees a reset, which is what closing with unread data does;
`login.is_loopback` is unit-tested at the boundary of every range). The proxy, having seen the key, could attenuate on the holder's
behalf (it is trusted with the root key's verification anyway).

**D2. The database name is the branch, and M1 serves exactly one.** The configured branch name is the only one accepted
(`3D000` otherwise). Accepting others would present isolation that M1 does not have.

**D3. Simple query protocol only.** `Parse`, `Bind`, `Execute` and `Describe` are refused (`0A000`) until a driver slice,
since psql does not use them for ordinary input (§2).

**D4. The SQL subset, and an IR version 2.** What psql users type in a session already exceeds `ir.md` v1: v1 has no
`ORDER BY`, `LIMIT`, `GROUP BY`, `HAVING`, `DISTINCT`, outer joins, `IS NULL`, `IN`, `LIKE`, `BETWEEN`, `CASE`, casts, `NOT`,
or `*` as an aggregate argument, and the `select count(*) from orders` that psql sent in §2 is one of the things it cannot
say. Each of those matters to effect inference, because a column named in an `ORDER BY` or a `HAVING` is a read, and an
inference that ignored them would under-report. So M1 begins with **IR v2, its own spec slice**, adding exactly those, with
their effect rules written first and vectors with hand-written expected sets, as v1 was. Still out: subqueries, CTEs, set
operations, window functions, `RETURNING`, `INSERT ... SELECT`, `ON CONFLICT`. Anything outside is refused before it
reaches Postgres with `0A000`, a message naming the construct, and a stable **rule tag** (`unsupported-sql`, with the
construct), as every refusal in this project has one.

**D5. Names are resolved from an introspected schema.** An unqualified column in a join (`select total from orders join
users ...`) cannot be attributed to a table without the schema, and `SELECT *` cannot be expanded without it. The proxy
reads the catalog from upstream with its own credentials, keeps a
snapshot, and records the snapshot's hash as the commit's `schema`. *Corrected at P1d:* the snapshot is read **fresh for each
query** (`pg_class`, `pg_attribute`, `pg_indexes` of the public schema, over one connection the proxy keeps), not at start and after DDL:
there is nothing to invalidate, a DDL that bypassed the proxy is seen too, and the price is one local round trip a query
(`m1-lowering.md` section 5.2). For a commit, `schema` is the hash of the snapshot read before the transaction's first statement
(`m1-commit-path.md` P2-D9). It is read-only and the proxy's, not the client's, so
it is not itself a logged commit.

**D6. A transaction is one commit; an autocommit message is one commit.** From the messages and `ReadyForQuery`'s status
byte the proxy knows when a transaction is open. An explicit `BEGIN ... COMMIT` is one commit with all its statements, in
order. A `Query` message outside a transaction is one commit with all the statements of that message, because PostgreSQL
runs a multi-statement message as one implicit transaction (§2) and the proxy must not change that. A message that mixes
transaction control with other statements (`begin; select 1; commit` in one message) is refused in M1. `ROLLBACK` discards the
buffered statements: **only committed transactions enter the log.** A statement the proxy refuses inside a transaction
aborts it, as an error would in PostgreSQL (`25P02` for what follows, until `ROLLBACK`), and the upstream transaction is
rolled back with it.

**D7. Postgres's commit and the log's append are made one decision by two-phase commit.** At the client's `COMMIT` (or the
end of an autocommit message) the proxy builds the commit (it needs no result of the commit itself), then:

1. sends `PREPARE TRANSACTION 'cdb:<commit id in hex>'` upstream;
2. appends the statements and token to their stores and the commit to the log, and `fsync`s them;
3. sends `COMMIT PREPARED` with that gid;
4. only then answers the client `COMMAND COMPLETE COMMIT`.

The window table is in §6. *Chosen over* committing upstream first and logging after (a crash between leaves a committed
transaction the log never saw, and **that is the silent divergence this whole design exists to prevent**), and over logging
first (a log entry for a transaction PostgreSQL then rolled back). *Costs:* `max_prepared_transactions` must be nonzero (§2),
the commit is about two times slower (§2), and every transaction must be preparable, which the refusals of §1 make true for
what the IR can express.

**D8. `now()` is recorded; other nondeterminism is refused.** `now()`, `current_timestamp` and `transaction_timestamp()`
return the same value throughout a transaction (§2), so the proxy runs one `SELECT now()` inside the transaction before the
commit and records it in `nondet`. `random()`, `clock_timestamp()`, `nextval`, `gen_random_uuid()` and the like cannot be
recovered after the fact from stock PostgreSQL, so statements using them are refused (`unsupported-sql`, rule
`nondeterministic`). **A column default does the same invisibly:** `insert into t(a) values (1)` calls `nextval` if `t.id` is
`serial`. The introspected schema (D5) shows each column's default, and an `INSERT` that omits a column whose default is
nondeterministic other than `now()` is refused. That makes `serial` and `uuid` primary keys unusable for inserts in M1, a real
limit, stated; capturing those values is M2's row-delta work.

**D9. Refusals look like PostgreSQL's.** A refused statement is answered with an `ErrorResponse` (`42501` for a token
denial, `0A000` for an unsupported construct, `25P02` after an abort) whose message begins with the rule tag, then
`ReadyForQuery` with the right transaction status, so psql prints an ordinary `ERROR:` and carries on.

**D10. The proxy writes three append-only files, which are exactly the inputs `verify` takes**: the log (`commit.md`), the
token store (`token.md`) and the statement store (`ir.md`). The stores are sets, so the order is: stores first (`fsync`),
then the log, which is the commit point. A crash between leaves a store entry no commit refers to, which the verifier
ignores.

**D11. Commits in M1 carry zero `changes` and `state`.** Row deltas are M2's; L3 replay is impossible until then, and the
spec says so rather than letting a zero hash look like a root.

**D12. Code.** `src/commit.cho`, `token.cho` and `ir.cho` already decode and check; the proxy builds the same structures and
reuses their layout code rather than copying it. `cancho-pg` has the framing and event-loop pieces, but it is not a
published package (`cancho.toml` takes stores), so the first slice writes the (small) framing it needs here and names the
duplication in its PR, to be removed if `cancho-pg` publishes.

## 5. What a psql user sees

| Input | M1 |
|---|---|
| connect with a valid token, branch allowed | works; `application_name` is psql's |
| wrong token, bad key proof, branch not allowed | `FATAL` at login (`28P01`, `28000`, or `3D000`), nothing reaches Postgres |
| `select`, `insert`, `update`, `delete`, DDL in the v2 subset | works, in autocommit or a transaction |
| the same, outside the token's grants | `ERROR: effect-denied: ...`, and **the statement is not in Postgres's log** (measured at P1) |
| `begin ... commit`, `rollback` | works; one commit per transaction |
| `select 1; select 2` | works; one commit for the message |
| `\dt`, `\d table`, `\l`, `\du`, ... | `ERROR: unsupported-sql: catalog ...`; the measured gap of §2 |
| `\timing`, `\x`, `\set`, `\copy` | client-side ones work; `\copy` and `COPY` refused |
| a column default that is `serial` | inserts omitting it refused (D8) |

## 6. Failure windows

For one commit, in D7's order. "PG" is PostgreSQL's state, "log" the commit log.

| The proxy dies... | PG | log | On restart |
|---|---|---|---|
| before `PREPARE` | transaction open, then rolled back with the connection | no commit | nothing to do; the client saw no `COMMIT` acknowledgement |
| after `PREPARE`, before the log's `fsync` | prepared, in `pg_prepared_xacts` | no commit | **roll back** the prepared gid: no log entry, never acknowledged |
| after the log's `fsync`, before `COMMIT PREPARED` | prepared | commit present | **commit** the prepared gid: the log says it happened |
| after `COMMIT PREPARED`, before the client's acknowledgement | committed | commit present | nothing; the client does not know the outcome, as with any database |
| the log append fails (disk full) while running | prepared | not written | `ROLLBACK PREPARED`, `ErrorResponse` to the client |

Recovery reads `pg_prepared_xacts` for gids with the `cdb:` prefix and compares each with the log: present means
`COMMIT PREPARED`, absent means `ROLLBACK PREPARED`. The log is trusted for this only after `verify` L1 on it. **What this
does not cover:** someone with write access to the log file deleting its tail (`commit.md` §5, which `--expect` addresses)
or to PostgreSQL directly (a write that bypasses the proxy is not in the log at all: M1 makes the proxy the only door by
configuration, not by construction).

## 7. Slices

Each is one change with its own gate, and a gate is a test that fails when the slice is wrong.

| Slice | Delivers | Gate |
|---|---|---|
| **P0** | listener, `SSLRequest` answered, startup parsed, token login (D1, D2), upstream relay of the login, then every message forwarded untouched with framing. **Built** (`src/login.cho`, `proxy/proxy.cho`); the gate below is `tests/proxy_e2e.py`, run against a real PostgreSQL 16 and psql 16, and what it shows and does not show is in `claims.md` C22 to C27 | psql connects with a valid token and runs `select 1` against a real PostgreSQL; a wrong token, a bad key proof and a branch outside the token are each refused at login and **no connection reaches PostgreSQL** (checked in the server's log); `cancho authority` on it; the measured password length of a token |
| **IR v2** | `ir.md` v2: the constructs of D4, effect rules, vectors with hand-written expected sets, all three verifiers | the same gates as v1: three verifiers agree, mutants killed |
| **P1** | lexer, parser, lowering, schema snapshot, effect check, refusals with rule tags. **Built** in four slices (`m1-lowering.md`: P1a lexer, P1b parser and renderer, P1c lowering, P1d the guard and the proxy's query path); the claims are C33 to C61 in `claims.md` | a corpus of statements: each lowers to IR whose id and effects equal hand-written ones; **a refused statement never appears in PostgreSQL's log** (`log_statement=all`); psql output through the proxy equals psql output direct, for every accepted statement, as a diff |
| **P2** | transaction tracking, commit builder, three files, two-phase commit, recovery, `now()`: **designed in [`m1-commit-path.md`](m1-commit-path.md)** (slices P2a to P2e, the fault-injection table, and the decisions that need the owner) | after a psql session, all three verifiers accept the files at L2+IR with `--expect` the last commit id; **fault injection** at each window of §6 leaves PostgreSQL's rows and the log's commits equal in number and identity |
| **P3** | the psql end-to-end suite and the documentation of §5 | the suite passes unmodified `psql`; every row of §5 is a test |

## 8. Risks and open questions

- **The backslash commands.** Losing `\d` makes psql feel broken. Options: leave as designed (M4 emulation); or serve a fixed
  allow-list of psql's own catalog queries as opaque read-only statements with a declared effect, which would put a
  server-asserted effect set into the log (the thing `ir.md` exists to remove) and is therefore not recommended. **Needs a
  decision from the project's owner before P3.**
- **IR v2 is the largest slice.** A SQL parser and lowering is more code than everything built so far; the corpus measures
  progress and nothing else does. If it proves much larger than the rest, the answer is a smaller subset, not a looser check.
- **Password length.** Measured at P0: 440, 636 and 1,028 characters for tokens of 2, 3 and 5 blocks (about 196 per block), all sent by psql; the proxy's login buffer allows about 80 blocks.
- **Nondeterministic defaults** (D8) make M1 unfriendly to `serial` keys; whether a demo can live with that is the demand
  test's business.
- **Concurrency.** One event loop and one upstream connection per client; many clients committing at once are serialised by
  the log's single writer. Not measured; M1 is not a throughput claim.
- **Demand.** M1 exists to find out whether anyone wants this. The gate for going on to M2 is that answer, not a test.
