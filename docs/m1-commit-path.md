# M1, P2: the commit path

> **Status: design, written before the code.** Companion to [`m1-proxy.md`](m1-proxy.md) (D6 to D11 and section 6 are the outline
> this refines) and [`m1-lowering.md`](m1-lowering.md) (what P1 built). A claim that turns out false is corrected here, in place.

P1 made the proxy refuse what the token forbids. It does not yet **write anything down**. P2 is where the project's central claim
becomes true or false: *every transaction PostgreSQL commits through the proxy is in a signed, hash-chained log, and nothing is in
the log that PostgreSQL did not commit.* Everything below is in service of those two clauses; where a choice trades them against
speed or convenience, they win.

## 1. What P1 left, and what P2 adds

Built and merged: login with a token (D1, D2), every simple `Query` lexed, parsed, lowered and checked against the token, the
guard's **rendering** sent upstream, the extended protocol refused, the schema read fresh per query. Not built:

- **a transaction concept.** `BEGIN`/`COMMIT`/`ROLLBACK` are `unsupported-statement`; every query runs in PostgreSQL's own
  autocommit, and the server's answers flow back unparsed, so the proxy cannot see a `ReadyForQuery` or an error;
- **a commit builder** (the encoder for `commit.md`; only decoders exist), **the three files**, **a signing key**,
  **two-phase commit**, **recovery**, and **`now()` as recorded input**.

## 2. Facts measured on PostgreSQL 16.15 (the design rests on them)

Run on the throwaway cluster of `scripts/pg_throwaway.sh` (`max_prepared_transactions = 20`).

| # | Fact | Consequence |
|---|---|---|
| F1 | A read-only transaction can be `PREPARE`d. | Allowed but pointless: reads are not made two-phase (P2-D4). |
| F2 | A prepared transaction's rows are invisible until **another session** runs `COMMIT PREPARED`, and then are there. | Recovery can finish what a dead proxy started, from a new connection. |
| F3 | `PREPARE TRANSACTION` fails (`cannot PREPARE a transaction that has operated on temporary objects`) after a temp table. | The subset already refuses `CREATE TEMP TABLE` and `CREATE ... ON COMMIT`; a prepare failure is still handled (P2-D6). |
| F4 | A gid already in use is refused (`transaction identifier "dup" is already in use`). | A gid is the commit's id, which is unique by construction; a clash is a bug and a refusal, never a silent reuse. |
| F5 | A gid of `cdb:` plus 64 hex digits (68 bytes) is accepted (the limit is 200). | The gid names the commit exactly (P2-D5). |
| F6 | A prepared transaction **keeps its row locks** until it ends: another session's conflicting write waits (or hits `lock_timeout`). | The window between `PREPARE` and `COMMIT PREPARED` must be short, and the commit sequence is serialised (P2-D7). |
| F7 | `now()` is the same value throughout a transaction, and `(extract(epoch from now()) * 1000000)::bigint` reads it as an integer (`1794844248603995`). | `nondet` records it as an `int` value in microseconds (P2-D9). |

Not measured, and said so: the cost of the two extra fsyncs a commit adds to the log directory on real storage (the throwaway
cluster runs `fsync=off`); the P2 gate measures it on the machine it runs on and reports the number, not a claim.

## 3. Decisions

**P2-D1. The proxy sees both directions.** Today the server's bytes are copied to the client unread. P2 frames them too (a type
byte and a length, as the client side already is) and acts on three messages: `ErrorResponse` (the statement failed), `CommandComplete`
and `ReadyForQuery` (its status byte is the transaction state). Everything else (`RowDescription`, `DataRow`, `ParameterStatus`,
`NoticeResponse`) is relayed immediately and untouched, so a large result still streams.

**P2-D2. The proxy tracks the transaction state itself** and does not take the client's word or the server's alone: `I` idle,
`T` in a transaction, `E` failed. It answers the client's `ReadyForQuery` with its own state. `BEGIN` (and `START TRANSACTION`),
`COMMIT` (and `END`), `ROLLBACK` (and `ABORT`) become statements the parser understands, **with no options** (no isolation level, no
`READ ONLY`, no `DEFERRABLE`: each is refused `unsupported-sql`), and `SAVEPOINT`, `SET`, `LOCK` and the rest stay refused. A message that
mixes transaction control with other statements is refused (m1-proxy D6): its meaning would depend on where the commit falls inside it.

**P2-D3. What is a commit.** An explicit `BEGIN ... COMMIT` is one commit; a `Query` message outside a transaction is one commit with
all its statements (PostgreSQL runs a multi-statement message as one implicit transaction, and the proxy must not change that). A
`ROLLBACK`, a refused statement inside a transaction (which aborts it, as an error would: the proxy rolls the upstream transaction
back and answers `25P02` to what follows until `ROLLBACK`), or a statement PostgreSQL itself fails, makes **no commit**: only committed
transactions enter the log. The commit's `statements` are the IR ids of its statements in order, `effects` the union of their inferred
effects (`ir.infer`, the verifier's code), `token` the id of the token the client logged in with, `principal` that token's
principal, `time` the clock at the commit's building.

**P2-D4. Writes are two-phase; reads are log-then-complete.** A transaction whose inferred effects include a `write`, a `ddl` or a
`call` (a stored function can write, and the IR cannot see inside it: conservative) runs m1-proxy D7 exactly: `PREPARE TRANSACTION`,
log append and fsync, `COMMIT PREPARED`, then the client's acknowledgement. A **read-only** transaction has nothing in PostgreSQL to
make atomic with the log, so it is **appended to the log first and then `COMMIT`ted** upstream (a crash between leaves a commit for a
read PostgreSQL then rolled back, which says a read happened that left no state: true, and harmless). Both release the client only
after the commit is durable (P2-D8). *Chosen over* logging only writes, because a log that omits what was read is not an audit of
what the token's holder could see, which `read` effects exist to say; the price is that **every `select` is a commit**, with the
append and the fsyncs that costs (measured at the gate, not assumed cheap).

**P2-D5. The commit is built before `PREPARE`, and its id is the gid.** The commit needs nothing from the commit itself: its parents
(the branch's tip), `seq`, statements, effects, token, nondet and time are all known before. So the gid is `cdb:` and the 64 hex digits of the
commit id, and recovery can say, from the gid alone and the log, which prepared transaction is whose (m1-proxy section 6).

**P2-D6. The commit sequence is synchronous, one at a time, bounded.** When a transaction ends, the proxy performs the whole sequence
inside the event loop with the same bounded waits as login (`login_ms()`, 5 s each): build; `PREPARE TRANSACTION`; append to the three
files and fsync; `COMMIT PREPARED`; release the client. While it runs the loop serves nobody else. That is **a stated limit of M1, not
an accident**: it makes the order of commits the order of log appends with no locking (the log is single-writer by construction, and
`seq` and `parents` are trivially right), it avoids a state machine across events for four round trips, and M1 makes no throughput
claim (m1-proxy section 8). Any failure inside the sequence (a refused `PREPARE`, a log error, a timeout) ends in `ROLLBACK
PREPARED` where one was made, an `ErrorResponse` (`58000` for a log failure, `08006` for an upstream failure) to the
client, **no commit in the log**, and a recovery pass (P2-D10) before the next query.

**P2-D7. One upstream connection per client, plus the catalog's.** Unchanged from P1. While a client's transaction is prepared its
row locks are held (F6), so the window between `PREPARE` and `COMMIT PREPARED` is one round trip, one append and one fsync: the
bound of other clients' waits. It is short, not zero, and a conflicting writer sees a lock wait of that length.

**P2-D8. What the client is told, and when.** Rows stream as they arrive; the statement's final `CommandComplete` messages and
`ReadyForQuery` are **held** until the commit is durable and are then released (for a transaction, the client's own `COMMIT` is
answered by the proxy with `CommandComplete COMMIT` and `ReadyForQuery I`). A client that has seen `COMMIT` therefore has its commit
in the log; a client that has seen only rows has seen nothing a crash can un-say that PostgreSQL would not also un-say. For an autocommit
message the proxy sends the server `BEGIN` first (swallowing its answer), then the rendered text, so that the statement is inside
a transaction it can prepare.

**P2-D9. `now()` and the other nondeterminism.** If any statement's inferred effects contain `nondet now`, the proxy runs `select
(extract(epoch from now()) * 1000000)::bigint` inside that transaction before `PREPARE` (F7) and records the answer as one `int`
value in `nondet`. The other nondeterministic calls stay refused (P1c). `changes` and `state` stay zero hashes, `code` and `checks` empty (m1-proxy D11).
`schema` is the SHA-256 of the **schema snapshot text read before the transaction's first statement**: the schema the transaction
began with. A DDL inside the transaction changes it for what follows, which the next transaction's snapshot shows; the commit does not
claim more than that.

**P2-D10. Three files and a key, in one directory.** `--log-dir DIR` holds `log`, `tokens` and `stmts`, **exactly the inputs
`verify` takes** (m1-proxy D10): the log (`CHODBLG1`, the server's public key, then records), the token store (`CHODBTK1`) and the
statement store (`CHODBST2`). The server's signing key is a 32-byte seed in `--key FILE`, read once; the proxy signs each commit
with it. Order of a commit's writes: statements and token to their stores, **fsync both**, then the commit to the log, **fsync the
log and, when a file was created, the directory** (`dir_sync`). The log is the commit point; a store entry no commit names is
ignored by the verifier. The proxy takes `file_lock` on the log so a second proxy on the same directory refuses to start. Each distinct
token is appended once per proxy run (a set in memory; a repeat across runs is a harmless duplicate, which `token.md` §4 permits).
`cancho authority` for the proxy gains `dir_write` and `fs_read` for the key file, and that row is pinned
(`tests/authority.sh`).

**P2-D11. Startup scans the log, then recovers, then listens.** The proxy reads the log with the verifier's own decoder and
L1 check: any record that fails refuses to start (`log-corrupt`, naming the record); it keeps, per branch, the tip's id and `seq`. A
**torn tail** (a record cut short by a crash during the append) is detected by `commit.md`'s length framing and is **truncated to
the last whole record** with a message, because no client was acknowledged for it: it is the one repair the proxy makes on its own
log. It then checks `max_prepared_transactions > 0` (`show`; refuses to start otherwise, with the reason), and runs recovery:

> for every row of `pg_prepared_xacts` whose gid starts `cdb:`: if the log holds the commit with that id, `COMMIT PREPARED`; if not,
> `ROLLBACK PREPARED`. A gid that is `cdb:` but not 64 hex digits is left alone and reported.

Recovery is also what runs after any failed commit sequence (P2-D6). Only then does the listener open.

**P2-D12. Refusals look like PostgreSQL's** (m1-proxy D9), with these additions: `25P02` for statements after an abort until
`ROLLBACK`; `58000` `log-unavailable` when the append fails; `08006` `upstream-unavailable` when the commit sequence loses the
server; `40P01`-style conflicts come from PostgreSQL untouched.

## 4. The failure windows, for both kinds of commit

"PG" is PostgreSQL's state, "log" the commit log. Kills are SIGKILL of the proxy.

**Writes** (two-phase):

| The proxy dies... | PG | log | On restart |
|---|---|---|---|
| before `PREPARE` | transaction open, rolled back with the connection | no commit | nothing; the client saw no acknowledgement |
| after `PREPARE`, before the log's fsync | prepared | no commit | gid not in the log: **`ROLLBACK PREPARED`** |
| after the log's fsync, before `COMMIT PREPARED` | prepared | commit present | gid in the log: **`COMMIT PREPARED`** |
| after `COMMIT PREPARED`, before the client is released | committed | commit present | nothing; the client does not know the outcome, as with any database |
| the log append fails while running | prepared | not written | `ROLLBACK PREPARED`, `ErrorResponse` to the client |
| mid-append (a torn record) | prepared | torn tail | the tail is truncated; the gid is then not in the log: `ROLLBACK PREPARED` |

**Reads** (log then `COMMIT`): dying before the log's fsync leaves no commit and a rolled-back transaction; after it, a commit for a
read that left no state. There is no prepared transaction to recover.

**What this does not cover** (m1-proxy section 6, unchanged): someone with write access to the log deleting its tail (`--expect`
on the verifier addresses it), or to PostgreSQL directly (a write that bypasses the proxy is not in the log at all: M1 makes the proxy the
only door by configuration, not by construction), or the signing key being stolen.

## 5. How it is tested: fault injection without test code in the proxy

The gate is not "it passes when nothing fails". The existing wire tee (`tools/pgtee.py`) sits between the proxy and PostgreSQL, sees
every message in both directions and can **kill the proxy at a chosen message**, which reaches each window of section 4 from outside:

| Window | The tee kills the proxy... |
|---|---|
| before `PREPARE` | when the client's `COMMIT` has been seen, before the `PREPARE` reaches the server |
| after `PREPARE`, before the log | when the server's answer to `PREPARE` is about to be relayed (the proxy has not read it) |
| log fsync'd, before `COMMIT PREPARED` | when `COMMIT PREPARED` is seen **before it is forwarded** (the append precedes it, so the log has the commit) |
| after `COMMIT PREPARED` | when the server's answer to it is about to be relayed |
| the log cannot be appended | not a kill: the log's file is replaced by a directory, so the open fails, and the client must get `58000` and PostgreSQL no row |
| a torn log tail | the log is cut by hand after a good commit, then the proxy is restarted |

After each: restart the proxy (which recovers), and compare PostgreSQL's rows with the log. **The assertion is equality of the two
sets**: the commits the log contains (decoded by the verifier, which also checks signatures, chaining, effects, tokens with
`--expect`) and the rows PostgreSQL holds, by count **and identity** (each commit's statement is an insert with a distinct key, so a row
and a commit match one for one). Then the three verifiers (cancho, Python, Go) accept the files at L2+IR. A test that kills at a
window must fail if recovery chooses the opposite action: the mutants "roll back what the log has" and "commit what it lacks" are the
proof that it can.

## 5.1 P2a as built, and what it changed in the design

P2a (the proxy tracks transactions; **no log yet**) is built. The plan held; these are the differences, written where they were found.

- **The proxy now opens a transaction for every autocommit statement** (`BEGIN`, the rendering, then `COMMIT`), which is what P2d
  needs to prepare it; today the `COMMIT` is a plain one. The client sees exactly what it saw before: rows stream as they come, the
  statement's `CommandComplete` messages are **held** and released only after the proxy's `COMMIT` succeeded, and the client's
  `ReadyForQuery` is the proxy's own `I`. A statement that fails is rolled back, the error reaches the client, and **no
  `CommandComplete` of an earlier statement in the same message does**.
- **`BEGIN`, `COMMIT`, `ROLLBACK`** (and `START TRANSACTION`, `END`, `ABORT`, with `WORK` or `TRANSACTION`) are parsed as leaves with no
  effects and answered by the proxy itself from its own record of the client's state; an option, `AND CHAIN`, `TO SAVEPOINT` or
  `PREPARED` is `unknown-construct`. In a message with other statements they are refused (`mixed-transaction-control`).
- **Deviations from PostgreSQL, stated**: `BEGIN` inside a transaction is an **error** here (`25001`, the transaction stays open)
  where PostgreSQL warns; `COMMIT` or `ROLLBACK` with no transaction open are answered with the command tag and **no warning**; a
  refused statement inside a transaction aborts it (as D6 says) and the proxy rolls the upstream back at once.
- **The synchronous round trips are `BEGIN`, `COMMIT` and `ROLLBACK`** (bounded by `login_ms()`, as the catalog read); the
  statement itself is not synchronous: it streams through the event loop, and a second query from the same client waits until the
  first has finished (the proxy does not serve a client whose statement is in flight).
- **Server messages are now framed.** `CommandComplete` and `ReadyForQuery` are collected whole (they are small), everything else is
  relayed as it arrives, in pieces if need be, so a 7 MB result still streams (the 200,000-row test is byte for byte).
- **Cost**: three upstream messages for every autocommit statement instead of one, and a round trip each for `BEGIN` and `COMMIT`.
  Measured at P2e, with the rest.

## 6. Slices

Each is one change with its own gate.

| Slice | Delivers | Gate |
|---|---|---|
| **P2a** | **built**: server-to-client framing; transaction tracking; `BEGIN`/`COMMIT`/`ROLLBACK` parsed and answered by the proxy's own state; autocommit wrapped in a transaction; held `CommandComplete`/`ReadyForQuery`; **no log yet** | `psql` transactions, rollbacks, errors inside a transaction (`25P02`), statuses `I`/`T`/`E` on the wire; refused options and mixed messages; the wire tee shows the exact upstream messages; mutants |
| **P2b** | **built** (section 5.3): the commit builder (`src/build.cho`, sans-io: encode, id, sign) and the store encoders | bytes equal an independent Python encoder's over hand-written commits; the verifier accepts them; mutants; **the signing is checked by the three verifiers** |
| **P2c** | **store built** (section 5.4): the log directory, the key, append and fsync, the lock, the startup scan, the torn-tail repair | restart reads the log back; torn tails; a second proxy refused; `cancho authority` pinned |
| **P2d** | **built** (sections 5.8 to 5.10): the two-phase sequence, recovery, `now()` | the fault-injection table of section 5, equality of rows and commits at each window, the three verifiers on the files |
| **P2e** | the cost, measured, and the claims | `select` and `insert` latency through the proxy vs direct on the same machine, with the fsyncs on |

## 7. Risks and what needs the owner's decision

- **Every read is a commit** (P2-D4). It makes the log a complete record and makes `select` cost an append and fsyncs. If the first
  measurement shows that is too much, the alternatives are batching commits (several reads in one fsync: a different durability story:
  stated first) or logging reads asynchronously (a weaker claim for reads). **Needs a decision if the number is bad; recommended: build it
  as designed and let the P2e number decide.**
- **A synchronous commit sequence stalls other clients** for a round trip and an fsync (P2-D6). Fine for M1's purpose (finding out whether
  anyone wants this); the cost of changing it later is a state machine, not a protocol change.
- **One signing key in a file** (P2-D10): no rotation, no HSM, and a stolen key signs a perfect forgery. The verifiers check chains and
  signatures against the key the log names; nothing here says who is allowed to be the server. M2's business, written down now so it is
  not read as solved.
- **`call` effects make a transaction two-phase** (P2-D4), including a harmless `count(*)`: **every aggregate and builtin is a `call`**
  (`ir.md` §6), so `select count(*) from t` is a two-phase commit. That is the conservative reading and it is probably too
  conservative: a token that grants `call count` names a function, not a promise that it does not write. A list of builtins known
  to be pure (and a token's way to say "pure only") would remove the cost; it is a spec question for `ir.md`, so it is not done here
  and the cost is stated.
- **`max_prepared_transactions`** must be above zero on the database (checked at start). With the commit sequence serialised one is
  enough; the default of 0 means the proxy refuses to start with a message that says so.
- **The torn-tail repair is the one thing the proxy rewrites in its own log.** It only removes bytes no client was ever told were
  committed, and it prints what it removed. A reviewer should look at it first.
- **A restart after the proxy is killed in the third window** means a client saw no acknowledgement of a commit that is in the log and
  in PostgreSQL. It will retry. That is the usual unknown-outcome problem of any database; nothing here dedupes retries (an
  idempotency key would be a client contract, M2).

### 5.2 Housekeeping before P2b: the proxy is split

`proxy/proxy.cho` had reached 1,811 lines against the 2,000 ceiling, with P2b-P2d still to come. The schema-snapshot builder
(`snapshot_sql`, `plain_name`, `append`, `build_snapshot`: pure functions on bytes, no I/O) moved to `src/snapshot.cho`, so
`proxy.cho` is 1,695 lines. Nothing else changed: the end-to-end checks pass on the split build, `tests/authority.sh` shows the same
authority, and the proxy mutants build with the new file. P2c/P2d will need a second split (the upstream I/O helpers) before they land.

### 5.3 P2b as built

`src/build.cho` is sans-io and heap-free: `encode` (a commit's bytes; the effects arrive in any order with repeats and leave
sorted and distinct, so the encoder owns the ordering rule the verifiers enforce), `id`, `sign`, `public_key`, and the record
writers for the three files (`log_header`, `log_record`, `tokens_header`, `stmts_header`, `store_record`). Every writer takes the
position and returns the new one, or -1, which sticks, so a caller chains them and tests the end once. `nondet` and `checks` come
in already encoded with their counts; P2d encodes `now()` as the one int value D9 says.

`tests/build_check.py` drives `proxy/buildcheck.cho` with random commits and compares with an encoder written from `commit.md`
alone, with `hashlib` for the id and `cryptography` for the signature; then writes a 120-commit chain as a log that the three
verifiers accept, and a copy with one flipped byte that each rejects. 21 mutants, all killed. It found one real bug in the first
run: the effects writer did not stop when an earlier field had already failed, so a ragged parent list still produced bytes.

### 5.4 P2c, the store as built

`src/store.cho` (edition 9: directory handles) opens the log directory through a `Dir`, so no path is resolved twice and no link is
followed. `open_log` makes the files if they are missing (`dir_open_new`, write, `fsync`, then `dir_sync`), opens the log for
appending, takes the `flock`, reads the file whole, cuts a torn tail, runs the verifier's own check and finds the tip. The verifier's
check was moved out of `verify.cho` into `src/l1.cho` for this (428 vectors and 139 verifier mutants still agree), so the proxy does not carry a second copy.
`open_store` does the same for `tokens` and `stmts` (their entries are `u32 length, body`). `append` writes the three files in the order D10
gives and syncs each. Refusals are `Opened::Failed(code)` with codes from 1000 so none can be taken for an errno.

Two things the build changed: the tip is found by decoding each record again after the verifier has accepted them (the verifier
does not export its tips), which is linear and was not worth a second interface; and `fsync` order is checked with `strace`, which
CI now installs, because no program output says whether a write was made durable. **The proxy opens it** (second commit of P2c): two arguments after the seven, `<log directory> <signing key file>` (**mandatory since P2d-2**; positional, like the rest; `--log-dir` and `--key` were the design's spelling). The
store is opened, locked and scanned *before* the listener, the summary goes to standard error, and `proxy.cho` is now edition 9 (directory
handles). The authority pin changed on purpose (it now names `fs_read("")`, `dir_read`, `dir_write`, `file_read`, `file_write`), and the claim "never touches the filesystem" is gone from it. **`proxy.cho` is at 1,873 lines**: P2d needs the second split (the upstream I/O helpers `write_all`, `read_until_ready`, `startup_msg`) first. The proxy has no commit to append until P2d.

### 5.5 The second split (before P2d)

`proxy.cho` was 1,873 lines. `src/upstream.cho` (141 lines) now holds the proxy's side of the upstream connection: `put_cstr`, `login_read`,
`startup_msg`, `write_all`, `read_until_ready`. `proxy.cho` is 1,741 lines. The end-to-end checks and the authority pin are unchanged;
one proxy mutant's anchor moved with the code it mutates (and now swaps the role for the database name, since the hello
buffer it used to name is not visible there).

### 5.6 P2d, planned: what the commit sequence needs that does not exist yet

Reading the proxy against D3 to D11 shows that P2d is five pieces, not one. Each is its own commit with its own gate, in this order.

1. **The guard hands over what a commit is made of.** Today `guard.check` decides and renders, then throws away what it computed. The
   commit needs, per statement, the **IR bytes** (the statement store holds them; their `ir.id` is what the commit names) and the
   **inferred effects** (the commit's `effects` is their union). `guard.check` gains two output slices: the IR of each allowed statement
   (a `u32` length, the bytes, one after another, with their ids in a third slice) and the effects, encoded as the commit encodes them,
   repeats allowed (`build.encode` sorts and de-duplicates). Gate: `tests/guard_check.py` compares the ids and the effect set with
   hand-written expectations, and the verifier's `ir.id` recomputes each id from the bytes handed over. Size limits are stated and refused
   with a tag (`transaction-too-large`), not truncated.
2. **The proxy keeps the store, and `Core` moves out of `proxy.cho`.** The three files, the branch's tip and next `seq`, and the
   signing seed live in `Core`, which is `res` and may hold `File`s. **The log becomes mandatory:** a proxy without a log would be a
   proxy that does not do what it is for, and keeping an unlogged mode means dummy files in `Core`. P0 to P2a tests get a temporary
   log directory from `start_proxy`. `Core` and the per-slot state helpers (`stride()`, the slot layout, `send`, `answer_*`) move to
   `src/core.cho` so that the commit path can be a module of its own (`src/commitpath.cho`) and `proxy.cho` stays under its ceiling.
3. **The accumulator and the sequence.** Per client, while a transaction is open: the IR bytes and ids, the effects, whether any is a
   write, a `ddl` or a `call`, and the hash of the schema snapshot read before the first statement. At the end of the transaction (the
   client's `COMMIT`, or the end of an autocommit statement): build the commit; for a write `PREPARE TRANSACTION 'cdb:<id>'`; append (D10's
   order); `COMMIT PREPARED`; advance the tip; release the held answer. A read appends first, then `COMMIT`s. Gate: after a run
   of mixed statements the log and the stores are accepted by the cancho, Python and Go verifiers **at L2 and IR** (tokens, effects and
   statements checked), the commits are in the order the statements were run, and PostgreSQL holds exactly the rows the commits name.
4. **Recovery and the fault table of section 5.** Recovery needs the ids the log holds (a bounded table, 4 MiB: 131,072 commits, stated, refused
   beyond), the catalog connection at startup, and `pg_prepared_xacts`. The `tools/pgtee.py` kills of section 5, each followed by a restart and
   an equality check of rows and commits; the two mutants "roll back what the log has" and "commit what it lacks".
5. **`now()`.** The `select ... extract(epoch from now())` inside the transaction before `PREPARE` (F7), the value recorded in `nondet`.

Not in P2d: concurrency (D6), more than one branch, `changes`/`state`/`code`/`checks` (D9).

### 5.7 P2d-2 as built

`src/shared.cho` holds `Core` and what every part of the proxy uses (the limits, the slot layout, sending and answering), so `proxy.cho`
is 1,413 lines and the commit path can be a module of its own. `Core` now holds a `Store`: the three open, locked files, the signing
seed, the branch's tip and the next `seq` (from the scan). The log is mandatory (nine arguments after the program name); the
P0-P2a end-to-end checks get a log directory of their own per proxy. Nothing appends yet. The proxy mutant "the log directory is not opened" went with the
optional mode; the two P2c startup mutants that remain are "the signing key is not required" and the checks of section 5.4.

### 5.8 P2d-3 as built: the sequence

`src/commitpath.cho` holds it. Per client slot the proxy keeps (in `Core`, `acc` and `acci`) the ids, the IR records and the effects of the
statements the guard has allowed in the open transaction, whether any effect is a write, a `ddl` or a `call`, and the SHA-256 of the schema snapshot
read when the transaction began. A transaction is at most 64 statements, 16 KiB of IR and 4 KiB of effects: more is refused `54000`
`transaction-too-large` and aborts the transaction as any refused statement does. When the transaction ends the commit is built (parents: the
branch's tip; `seq`: the next; token: the id of the whole token; principal: the token's; time: the clock at the **start of that pass of the event loop**, not
at the append, which is a few milliseconds earlier than the fsync; `changes`, `state` zero hashes; `code`, `nondet` and `checks` empty), signed, and
made durable: a write is `PREPARE TRANSACTION 'cdb:<id>'`, then token, statements and commit appended and synced, then `COMMIT PREPARED`; a read is the
appends, then `COMMIT`. The tip moves when the log has the record, whatever PostgreSQL then says. Answers: `40000` if PostgreSQL refuses the
commit, `58000` if the log cannot be written (and PostgreSQL is rolled back), and a closed connection if the upstream is lost.

What it does **not** do yet, stated so that nothing reads as more than it is: **a log failure is not yet exercised** (the fault table is P2d-4: the code
for `ROLLBACK PREPARED` exists and has no test); **recovery on restart does not exist** (a prepared transaction left by a crash waits for P2d-4);
**a statement that reads `now()` is recorded since P2d-5** (section 5.10; it was refused with `0A000` before, and this paragraph said so: corrected here); `BEGIN; COMMIT` with no statement writes no commit; a token is appended once per connection (a repeat across connections is a duplicate the store
permits). **Every `select` is a commit with its fsyncs; the latency is not measured** (P2e).

### 5.9 P2d-4 as built: recovery and the failure windows

`src/catalog.cho` now holds the proxy's own connection to PostgreSQL (moved out of `proxy.cho`: the schema snapshot, and `recover`). **Recovery**
runs at the start of `run`, before anything is accepted: it asks `show max_prepared_transactions` (0 refuses to start: a write could not be two-phase),
lists `pg_prepared_xacts` whose gid starts `cdb:` **and which belong to the database served** (the view is cluster-wide; found when a mutant run left prepared transactions in other databases and the proxy refused to start, because PostgreSQL will not settle another database's prepared transaction from this connection), and for each of 64 per pass issues `COMMIT PREPARED` if the log holds the commit its gid names and
`ROLLBACK PREPARED` if not; a `cdb:` gid that is not 64 lowercase hex digits is left alone and counted. The ids the log holds are a table of 1,048,576
commits (32 MiB; `store.open_log` fills it, `conclude` extends it): a log with more is refused at startup, and a proxy whose table fills refuses further
commits. A summary goes to standard error when anything was done. **The listener is bound before recovery, so the port is open and connections
wait in the kernel's backlog; none is accepted until recovery is done** (the design said "the listener opens only then": this is the difference).
**A proxy needs a reachable PostgreSQL to start**: if it cannot be asked, the proxy exits (code 6); four end-to-end tests that had pointed the proxy at a dead or silent
upstream now start it against a tee that goes bad afterwards.

The failure windows of section 4 are reached by `tools/pgtee.py`, which can now `fault(prefix, when, action)`: drop a `Query` before it reaches the server
(`before`), forward it and drop the server's answer (`reply`), or forward it and act (`after`); the action kills the proxy. Four windows, each followed by
a look at PostgreSQL's prepared transactions and rows and the log, a restart, and the same look: before `PREPARE` (nothing anywhere, nothing to settle); after
`PREPARE` with the answer dropped (prepared, not logged: **rolled back** on restart); at `COMMIT PREPARED` before it is sent (logged, prepared: **committed**
on restart); after `COMMIT PREPARED` with the answer dropped (committed, logged: nothing to do). In each the rows left are the commits in the log, one for one,
and the three verifiers accept the files. The log that cannot be written is a file-size limit just under one commit's log (`RLIMIT_FSIZE`, `SIGXFSZ`
ignored): the client gets `58000`, PostgreSQL holds nothing and no prepared transaction, a read is refused the same way, and the torn record the write left is
cut at the next start.

**Recovery while running** is tested too (found by CI: the mutant "a commit's id is not in the recovery table" survived, because the table is read only by a live recovery): the tee `drop`s the connection at `COMMIT PREPARED`, so the proxy loses its upstream after the log has the commit; the client's connection is closed, the running proxy settles the prepared transaction itself at its next turn by committing it (the log has it), and the next commit continues the chain.

Not tested, stated: **`max_prepared_transactions = 0`** refusing to start (the throwaway server has it above 0); a torn tail **and** a prepared
transaction together (the two repairs are tested apart); more than 64 prepared transactions in one pass (the rest wait for the next).

### 5.10 P2d-5 as built: `now()`

A statement the lowering turns into `Nondet now` (`select now() from t`: `now()` needs a table, ir.md section 6) has the effect `nondet now`, and the
guard lets it through if the token allows `n`. The transaction notes it. When the transaction ends, **before** anything is made durable, the proxy runs
`select (extract(epoch from now()) * 1000000)::bigint` inside the same transaction (PostgreSQL's `now()` is the transaction's start, the same for every
statement in it: F7) and records the answer as one `int` in the commit's `nondet`, in microseconds, as D9 says. A transaction that read no clock records an
empty `nondet`; one that read it twice records one value, because there is one. If the read fails the transaction is rolled back and nothing is logged.

The test compares the recorded value with **what the client was shown** by its own `select now()`, to the microsecond, in an explicit transaction (two selects, one
value) and in an autocommit statement (its own value); the three verifiers accept the log, whose `Value` encoding they check. `random()`, `clock_timestamp()` and
the other sources stay refused by the lowering (`nondeterministic`, `0A000`): only `now()` is recorded.

What this does not give: **replay** (L3) is not specified, so nothing yet *uses* the recorded value; it says what a replay would have to substitute. The value is
read by a second statement, so a transaction with `now()` costs one more upstream round trip (measured with the rest at P2e).
