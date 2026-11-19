# M2: branches, `AS OF`, checked merge, row deltas and replay

**Status: design, with the measurements it rests on (section 3). M2a (section 5) is built: the spec of facts, `changes` and `state` ([`spec/state.md`](spec/state.md)), `src/state.cho` and `tools/state.py`, with golden cases and 20 mutants; nothing else is.** M1's last slice is merged ([`m1-extended.md`](m1-extended.md)
section 8). This document is written before the code, as the project's practice is: a claim that turns out false is corrected in place, in this file, with the PR
that corrected it.

The exit criteria from [`design.md`](design.md) (Milestones) are the gate:

> Two agents on separate branches merge, with a conflict detected. L3 replay reproduces the state root.

## 1. What M2 adds

| Piece | What the user sees | What is new underneath |
|---|---|---|
| **Branch per connection** | the database name in the connection string names the branch | one proxy process serves several branches; a branch is a schema of the one upstream database |
| **Fork** | `SELECT cancho_fork('<new>', '<from>')` | a copy of the source branch's tables, and a first commit of the new chain whose `parents[0]` is the source's tip |
| **Row deltas** | none (they are what `changes` and `state` are made of) | every table of a branch has triggers that record the facts a statement changed, inside the commit's transaction |
| **`AS OF`** | `select ... from t as of '<commit id>'` | the proxy renders the table as of that commit from the deltas after it |
| **Checked merge** | `SELECT cancho_merge('<branch>')` | three-way by primary key from the two branches' deltas since their merge base; a conflict aborts the merge, naming it |
| **L3 replay** | a verifier that says whether the log's `changes` and `state` are what the data became | a replay engine and a state-root definition (section 4.2) |

What does not change: the commit format's field list (`docs/spec/commit.md`, `version` 1) for everything but what `changes` and `state` *contain*, the
token format, the guard, the two-phase commit path. M1's proxy serves **one** branch named on its command line and writes `changes = state = 0` (32
zero bytes): both become real here.

## 2. What the spec and M1 already give

* The commit has `branch`, a per-branch `seq`, up to **two** `parents` (a fork point at `seq = 0`, a merge at `seq > 0`), `changes`, `state`, `nondet`
  and `checks`; L1 already checks the chain, the fork's parent and a merge's second parent. The vectors include a fork and a merge
  (`docs/spec/commit.md` sections 5 and 7). **L1 needs no change for M2.**
* A token's grant names a branch; `call[fn]` is an effect kind. `cancho_fork` and `cancho_merge` are therefore effects a token must grant, with no
  new kind: a token that cannot `call[cancho_merge]` cannot merge.
* The commit path is two-phase and the log is appended before `COMMIT PREPARED` (`m1-commit-path.md` section 5). A delta written by a trigger is
  inside the prepared transaction, so it is atomic with the data it describes: a crash leaves both or neither.
* M1 has one chain; the chain state is `chain[0..2]` and a tip in `Store` (`src/shared.cho`). One log file holds several chains because `seq` is per
  branch: the file format already allows it.

## 3. Measured facts

One machine (a sandbox container), PostgreSQL 16.15, `wal_level = replica`, `max_prepared_transactions = 20`; a table of one million rows of about
110 bytes with a primary key and an index; numbers are for ordering and magnitude. Scripts: the experiment SQL is in section 3.5 so that it can be rerun.

**3.1 A fork by copying costs the size of the data.** `create table b.t (like m.t including all); insert into b.t select * from m.t`: **2.5 s for 1,000,000
rows** (one table), **0.17 s for 100,000**. The copy has every constraint and index the original has, so every constraint PostgreSQL enforces is
enforced on the branch with no work of ours.

**3.2 An overlay (a view over the base plus a table of changed rows) forks in O(1) and reads in sub-milliseconds, but gives up native constraints.**
`create view b.t as select ... from m.t where not exists (select 1 from b.t_ovr ...) union all select ... from b.t_ovr where not _deleted`: the planner
uses indexes (`Nested Loop Anti Join` over `t_pkey` and `t_ovr_pkey`): a point select by key **0.39 ms against 0.09 ms** direct and 0.19 ms on a copied
branch; a range aggregate over 1,000,000 rows 8.4 ms against 7.3 ms. Writes through such a view need `INSTEAD OF` triggers, and unique, foreign-key and
check constraints are not enforced across the base and the overlay by PostgreSQL: we would have to.

**3.3 Capturing row deltas with statement-level transition-table triggers** (`AFTER INSERT/UPDATE/DELETE ... REFERENCING NEW/OLD TABLE`, writing one
row per fact into a delta table as `jsonb`):

| | plain | with capture |
|---|---|---|
| 2,000 single-row inserts, one statement each | 7.4 ms | 20.1 ms (**+6 microseconds** a statement) |
| one insert of 100,000 rows | 154 ms | 352 ms (2.3 times) |
| one update of 100,000 rows | 293 ms | **3,216 ms (11 times)** |
| one delete of 100,000 rows | 46 ms | 269 ms (5.8 times) |

The deltas of about 300,000 changed rows take **59 MB** (`jsonb` of both row images). A point statement pays nothing visible against the 3.7 ms a
commit already costs; a bulk update pays an order of magnitude. That is the price of `changes`, and it is paid by the statements that change the most.

**Corrected in M2b-1 (the measurement above was of a prototype).** The real capture (`sql/capture.sql`) hashes both row images with SHA-256, builds its insert with
`format()` per statement so that one trigger function serves every table and any key, and joins old and new rows by key with a full join. Measured with
`scripts/measure_m2.sql` (two runs, same machine, PostgreSQL 16.15; the first number of each pair is plain, the second captured):

| | plain | with capture | factor |
|---|---|---|---|
| 2,000 single-row inserts, one statement each | 7.3 to 9.5 ms | 222 to 239 ms | **+0.11 ms a statement** (the prototype said +6 microseconds: that was 18 times too small) |
| one insert of 100,000 rows | 174 to 197 ms | 1,142 to 1,342 ms | 6.5 to 7.7 times (the prototype said 2.3) |
| one update of 100,000 rows | 319 to 334 ms | 2,090 to 2,745 ms | 6.3 to 8.2 times (the prototype said 11) |
| one delete of 100,000 rows | 42 ms | 902 to 940 ms | 22 times (the prototype said 5.8) |

A point statement through the proxy costs about 3.7 ms a commit, so 0.11 ms is about 3 % of it; a bulk statement pays 6 to 22 times. The conclusion of section 3.3 stands (the
price is paid by the statements that change the most) and the figures above replace the prototype's. The 59 MB of deltas is also the prototype's, with both row images as `jsonb`; the real
table holds the same two images and two hashes, so it is larger.

**3.4 `AS OF` can be answered from the deltas alone.** The state at commit *C* of a table is: the current rows whose key no later delta touched, plus,
for each key a later delta touched, the *old* image of its **earliest** later delta when that delta is an update or a delete (an insert means the row did not
exist at *C*). For a 100,000-row table with 70,000 later changes (50,000 updates, 10,000 deletes, 10,000 inserts) this rebuilt the table as of the mark in
**550 ms, with 0 differences** from the known state. It costs the number of later deltas and a scan of the table; a signed snapshot (M3) bounds it.

**3.5 Rerun.** The statements were: the `m2.t` table of 1,000,000 rows (3.1, 3.2); the `d1.t` table with the three `cap_*` trigger functions of 3.3 and
`d1.delta(seq bigserial, tbl, op, pk, old_row jsonb, new_row jsonb)`; and the `create temp table asof0 as ... distinct on (pk) ... jsonb_populate_record`
query of 3.4. They are reproduced in `scripts/measure_m2.sql` when the first slice that needs them lands (M2b), not before.

## 4. Decisions

Each says what, why, and what was measured. **Open** ones are for the owner (section 6); the rest follow from the measurements and the existing design.

### 4.1 Branches

* **D1. A branch is a schema of the one upstream database; the database name in the connection string is the branch.** `main` is the existing `public`
  schema (M1's data stays where it is); another branch `b` is the schema `cdb_b_<b>`. The proxy sets `search_path` to the branch's schema on the upstream
  connection it opens for the client (its own command, through the extended protocol, as M1's are), so unqualified names resolve to the branch's tables.
  The guard's catalog snapshot (`src/snapshot.cho`, today `n.nspname = 'public'`) is read for the connection's branch.
* **D2. A fork copies (3.1).** `cancho_fork('new')` (*corrected in M2c: it first said `cancho_fork('new', 'from')`; a connection is on a branch and forks that one, as `cancho_merge` merges into it*) creates the schema, `create table ... (like ... including all)` and `insert ... select` for every table of the
  source, recreates what `including all` does not carry (foreign keys, sequences' current values, defaults that call sequences), then appends the first commit of the
  new chain. **Limit, stated:** a fork costs O(data), 2.5 s per million rows, and a branch holds a full copy. The overlay of 3.2 is faster to create and cheaper to
  hold, and loses native constraint enforcement; it is deferred, to be reconsidered if fork cost is what users hit (it is a change of what `cancho_fork` does, not
  of the format).
* **D3. A branch is created by a statement a token must allow**, `select cancho_fork(...)` (effect `call[cancho_fork]`), not by connecting to an unknown name.
  Connecting to a branch that does not exist is `3D000` with a rule tag, as M1 refuses a branch the token does not allow. Which branch a token may use is its grant
  (`token.md`), unchanged.
* **D4. One log, several chains.** The log file stays one (a commit names its branch). The proxy keeps a chain state (`chain`, `tip`) **per branch** and a
  recovery table of commit ids as now. A new branch's tip is established by its fork commit.

### 4.2 Deltas, `changes` and `state`

* **D5. Row deltas are captured by triggers the proxy installs** on every table of a branch (at fork, and when a migration creates a table, which is the proxy's
  own DDL), in a per-branch table `cdb_delta`, inside the commit's transaction (3.3). The proxy, not the client, creates them, in the same transaction as a client's `CREATE TABLE` (a branch's new table is
  captured from its first row); a client cannot create or drop one, because the guard parses only `create table` and `create index` (`create trigger` is
  `unsupported-statement`, `src/stmt.cho`). The delta table is **not** a table of the branch for the guard (it is not in the catalog snapshot).
* **D6. A fact is `(table, primary key, kind, old image, new image)`; `changes` is the Merkle root over the commit's facts.** Leaf = `SHA-256("cancho-db/fact/v1" ||
  0x00 || table || pk || kind || H(old) || H(new))` with the encodings of a new spec section (`docs/spec/state.md`, written in M2a with golden vectors); leaves sorted by
  `(table, pk)`; a binary tree, an odd node promoted. A commit with no changed row (a read) has `changes` of the empty root, defined in the spec. The row images are
  **stored beside the chain** (the delta table and, for erasure later, a payload store), as `design.md` says: the chain holds hashes.
* **D7. `state` is a chain of the changes, not a hash of the contents:** `state = SHA-256("cancho-db/state/v1" || 0x00 || u8(p) || state(parent_0) || ... || changes)`, `p` the number of parents (0, 1 or 2; a merge folds both parents' states in order).
  *Corrected in M2a:* this section first wrote `state_{n-1} || changes_n` with no parent count and "`state_0` the empty root"; the spec (`spec/state.md` section 4) has the count, so that a root, a normal commit and a merge cannot be confused, and a root has no parent state. It is O(1) a commit and a function of history. **What it does and does not prove:** that two
  logs with the same `state` have the same history of changes, not that the tables hold what the history says. The second is what L3 checks (4.5). A
  content-addressed root (a Merkle tree over all rows) is O(data) a commit and is left to the signed snapshots of M3; **Open (section 6, Q1)**.

### 4.3 `AS OF`

* **D8. `from t as of '<commit id>'` is a rendering rule.** The lexer and parser grow the clause (`AS OF` followed by a string literal of 64 hex digits, as the id of a commit
  of the connection's branch or an ancestor of its tip); the renderer emits a derived table built by the 3.4 query over `cdb_delta`, which PostgreSQL parses and
  plans; the lowered IR carries the table as read with the commit id, so L2 can say a statement read history. **`AS OF` never writes:** a statement with `AS OF`
  that writes is refused with its own rule. The cost is that of 3.4 (the later deltas and a scan); stated, not hidden.
* **D9. `AS OF` is the proxy's syntax, not PostgreSQL's:** the differential suites (`parse_diff`, `stmt_diff`) compare against PostgreSQL, which rejects the clause;
  the new cases are checked against **the result of the same query on a copy of the table as it was** (made by the test with `create table ... as` at the time), the
  oracle being the data and not the parser.

### 4.4 Merge

* **D10. `cancho_merge('<source>')` merges the source branch into the connection's branch**, a statement needing `call[cancho_merge]` and `write` on every table the source
  changed. The **merge base** is the nearest common ancestor in the commit graph (the log has it); the facts changed on each side since the base are read from `cdb_delta`.
  Per key: changed only by the source is applied; only by the target is kept; changed by both to the **same** final image is a no-op; changed by both to different images,
  or deleted by one and updated by the other, is a **conflict**.
* **D11. A conflict aborts the whole merge** (the transaction rolls back; the client gets an `ErrorResponse` with its own rule tag and a message naming the tables and
  keys, bounded). There is no resolution policy in M2: choosing ours or theirs is a later decision (**Open, Q2**). **Constraints are re-checked by applying:** the source's
  facts are applied in the target's transaction, so a unique, foreign-key or check violation PostgreSQL raises is a conflict of kind `constraint`, also an abort. The merge
  is **one commit** with two parents; its `statements` is the IR hash of the merge call, its `effects` the writes, its `changes` the facts applied, its `checks` the
  constraint results.

### 4.5 L3

* **D12. L3 has two parts, and M2 delivers the first.** **L3a, delta replay:** a verifier takes the log, the delta store and a base state (empty, or a snapshot), applies each
  commit's facts in order to a scratch PostgreSQL, and checks that (a) the stored facts hash to the commit's `changes`, (b) the folded chain equals `state`, and (c) the
  tables at the end are what the facts say (a content digest computed by the verifier). That proves the data is the history of facts, and `changes` is what was applied.
  **L3b, statement re-execution** (the original design's wording: "re-executing statements with the recorded `nondet` reproduces `changes` and `state`") needs the statement
  *and its bound values*, and M1 records neither the SQL nor the values (P3-D6: the commit says which shape ran and its effects). L3b therefore needs the commit format to
  carry values: a decision for the owner (**Open, Q3**), and a `version` 2.
* **D13. The verifiers.** L3a is a fourth tool, not a change to L1/L2: it needs a database and an executor, which the first two verifiers deliberately do not. It is written in
  cancho on the proxy's own wire client (`cancho-pg`), checked against a Python one written from `docs/spec/state.md` alone (the "second verifier" rule), both fed the golden
  vectors of M2a.

## 5. Slices

| Slice | Delivers | Gate |
|---|---|---|
| **M2a** (**built**, with Q1 and Q3 taken as recommended) | `docs/spec/state.md` (fact leaf, Merkle root, state chain, empty root), golden vectors, the fact/state code in cancho and Python | both agree on every vector; tampered fact lists are rejected; L1 and L2 vectors unchanged |
| **M2b** | row-delta capture in the commit path: triggers installed for a table, `changes` and `state` in the commit, `scripts/measure_m2.sql` | the log's `changes` equals the Python root of the delta table; a crash between prepare and commit leaves delta and data together; the cost rows of 3.3 reproduced |
| **M2c** | branches: per-connection branch and `search_path`, snapshot per branch, `cancho_fork`, several chains in one log, `3D000` | two connections on two branches see their own data; the fork commit verifies at L1 and L2; fork cost reported |
| **M2d** (split in section 13: **M2d-1** the spec convention and the three verifiers, **M2d-2** the clause in the lexer, parser, statements and lowering, **M2d-3** `cdb.asof`, `ord` and the proxy) | `AS OF` | the lexer, parser and renderer cases; results equal the copy-at-the-time oracle (D9); `AS OF` write refused; mutants |
| **M2e** (split in section 15: **M2e-1** `cdb.merge` in SQL against a Python reference, **M2e-2** the commit graph, the statement and the two-parent commit in the proxy) | `cancho_merge` | the exit criterion: two agents on separate branches merge; a conflict, a delete-vs-update and a constraint violation each abort with their tag; the merge commit verifies (two parents) |
| **M2f** (split in section 18: **M2f-1** the spec, a Python verifier, the export and the vectors, **M2f-2** the cancho verifier, **M2f-3** a second reading from the spec alone) | L3a verifier (cancho and Python) | replay reproduces the state root on the M2b to M2e sessions; a flipped delta, a dropped fact and a tampered row are each rejected |

Each slice is one PR with its mutants, its claims in [`claims.md`](claims.md) and the gate `scripts/check.sh` passing.

## 6. Decisions the owner is asked for

These change what M2 builds. The recommended answer is first; none blocks M2a.

* **Q1. What is `state`?** *Recommended:* the chain of changes (D7), with a content-addressed root deferred to the M3 snapshots. *Alternative:* a Merkle root over all rows
  every commit: stronger, O(data) a commit.
* **Q2. Conflict policy for merge.** *Recommended:* abort and report (D11); resolution policies (`ours`, `theirs`, a function) are a separate slice with the typed-migration
  work. *Alternative:* a `prefer` argument now.
* **Q3. Record bound values (and the SQL) so that L3b can exist?** *Recommended:* not in M2; L3a is the criterion. If yes: commit format `version` 2 carrying values (a
  change in three verifiers) and the question of erasure for values (they are personal data). *Alternative:* record values in the delta payload store only, outside the chain.
* **Q4. Is a fork by copy acceptable for M2** (2.5 s per million rows, a full copy per branch), or is the overlay (3.2) required? *Recommended:* copy; the overlay would give up
  native constraint enforcement, which M2e's merge relies on.

* **Q5. How does a history read appear in the IR?** *Recommended:* in the table's `Name`, as `orders@<64 hex digits>` (D29): no IR version, no change in the verifiers' code, only their vectors; a token that may read `orders` may not read `orders@...` unless it says so. *Alternative:* an IR version 3 with a field in `From` (three verifiers, the store magic, the generators).
* **Q6. May `AS OF` name a commit from before the connection's branch was forked?** *Recommended:* no (D28): only commits of the branch's own chain, the fork commit being the copy as made. *Alternative:* walk back through the source branch's deltas as well: more code, and the fork point must be found in the log.

* **Q7. How does a merge show what it may write?** *Recommended:* the commit's effects are `call cancho_merge` (all that the IR of the call infers, so L2 passes), and the proxy refuses a merge unless the token allows `write` on every table of the branch (D38): L2 cannot check that independently, which is stated. *Alternative:* an IR statement for a merge that lists the tables, three verifiers changed.

* **Q8. What is the state before the first commit?** *Recommended:* empty, and optionally a **base snapshot** file the verifier is given (the rows that were in the tables when the capture was installed); without one, a log whose first commits update or delete rows the facts never inserted is `replay-precondition`. *Alternative:* the proxy takes the snapshot itself when it installs the capture (a signed base commit).
* **Q9. Who writes the second reading of the L3a spec (D13)?** *Recommended:* a separate agent session given only `docs/spec/l3a.md` and the vectors, as the Go verifier was written (and then the cancho and Python implementations are checked against each other and against it). *Alternative:* the same author, which agrees with itself and shows nothing.

## 7. Non-goals of M2

Row-level capabilities, resolution policies, garbage collection of branches, erasure, cold-storage snapshots (M3/M4), `AS OF` on a branch other than the connection's, and a
content-addressed state root. Each is listed so that its absence is a decision and not an omission.

## 8. M2b-1 as built: the producer's definitions, and the capture SQL

`docs/spec/state.md` leaves three things to the producer; M2b-1 fixes them and builds the database side. **The proxy does not use any of it yet** (M2b-2 wires the commit path).

* **Row image and hash.** An image is PostgreSQL's own `jsonb` text of the row (`to_jsonb(row)::text`: keys in a fixed order, numbers and text normalised; it does not depend on the client or the
  session). Its hash is `SHA-256("cancho-db/row/v1" || 0x00 || that text)`. **Limit:** a column PostgreSQL's `jsonb` cannot represent exactly is not distinguished (a `float` and a `numeric`
  that print alike are the same image); a table is a table of what `to_jsonb` shows.
* **Primary key.** The `jsonb` text of the array of the key's column values in index order (`[3]`, `[3, "b3"]`). A table without a primary key cannot be tracked: `cdb.track` raises `55000`.
  M2b-2 must decide what the proxy does with a write to such a table (refuse it is the recommendation, with its own rule tag).
* **Net facts.** `cdb.facts(xid)` reads the transaction's delta rows and gives per `(table, key)` the image before the first change and the image after the last: an insert then an update is
  one insert, an insert then a delete is nothing, a change and its undoing is nothing, a delete then an insert of the same key is an update, a key change is a delete and an insert. It
  emits the text `tools/state.py` reads, in `(table, key)` order with PostgreSQL's `bytea` ordering (unsigned bytes, a prefix first), so no re-sorting is needed.
* **Capture.** Statement-level `AFTER` triggers with transition tables on every tracked table, in the schema `cdb` (`cdb.delta`, `cdb.capture`, `cdb.track`, `cdb.track_all`, `cdb.facts`),
  idempotent to install. An `UPDATE` is matched old to new by key with a full join: a changed key is a delete and an insert, a swap of two keys is two updates.
  `TRUNCATE` bypasses row triggers and is not captured; the guard parses no `TRUNCATE` (it is `unsupported-statement`), so a client cannot issue it.

**Tested** (`tests/capture_check.py`, in the gate): 17 transactions named for the rule they exercise and 300 random ones over an integer-key, a composite-key and a text-key table (including
non-ASCII keys and the empty string), each compared with a **snapshot diff of the table before and after**, rebuilt in Python from the `jsonb` text alone (the hash, the key, the order and the kind);
a rolled-back transaction leaves no delta row; every facts text is accepted by `tools/state.py`. **The test found two bugs in the SQL when first run**: a `full join` on `is not distinct from`
cannot be hashed or merged and made every `UPDATE` fail, and the new side of a changed key was given the key `[null]` (the old side's all-null array was picked by `coalesce`). Both are fixed.

**Not yet:** the proxy reading `cdb.facts`, `changes` and `state` in the commit, the crash-consistency test (M2b-2); a limit on the number of facts a transaction may carry (the facts text is read
whole; M2b-2 sets it, with its own rule).

## 9. M2b-2: how the proxy uses the capture (M2b-2a and M2b-2b built)

M2b-2 is the first change to the trusted commit path since P2d, so it is written down, with what was measured for it, before any code. It is two PRs: **M2b-2a** installs the capture and changes
no commit; **M2b-2b** puts `changes` and `state` in the commit.

**Measured for it** (PostgreSQL 16.15, the throwaway server, a superuser role):

* An **event trigger** on `CREATE TABLE` that calls `cdb.track` on the new table captures writes **in the same transaction**: a table created, then two rows inserted and one updated, gave two net facts
  (both inserts, the second image of the updated row). Creating a table **without a primary key fails** at the `CREATE TABLE` with `cdb.track: table ev2 has no primary key`. Creating the event trigger
  needs a **superuser** (PostgreSQL's rule), so the upstream role must be one, or an administrator installs `sql/capture.sql` once and the proxy only checks it is there.
* `cdb.facts` is about **150 bytes a fact** for an ordinary row (1,000 changed rows: 149,785 bytes). It is a text, read whole.

**Decisions.** Each follows from the above or from M1; the ones marked *Open* change what a client can do and are for the owner.

* **D14. The proxy installs `sql/capture.sql` at start and an event trigger on `CREATE TABLE`.** The file is turned into a generated cancho module (one statement per function, the file's `$$` bodies
  kept whole) by a tool that has a `--check` mode like the other generated files, and run statement by statement through the proxy's own extended-protocol command. Idempotent, so a restart is safe.
* **D15. *Open.* A table without a primary key cannot exist behind the proxy.** `CREATE TABLE` of one fails (above), and at start the proxy **refuses to start** if the schema `public` already holds one,
  naming it. The alternative, skipping such a table and refusing writes to it, leaves a state where `changes` silently misses a table if the refusal has a hole; refusing to start does not. A client that
  needs a keyless table does not get one until the format has a row identity for it (not in M2).
* **D16. Reads cost nothing extra.** A transaction whose effects have no `write` or `ddl` has the empty `changes` (a constant computed once, `c068815f...`) and does not ask the database for facts. A
  write transaction asks `select cdb.facts(txid_current())` in its own transaction **before** building the commit (the facts feed `changes`, which feeds the commit id, which is the prepared transaction's name),
  then `update cdb.delta set commit_id = <id> where xid = txid_current()` in the same transaction, then `PREPARE TRANSACTION`. That is two more round trips on a write (not measured yet: M2b-2b reports it);
  the delta rows join the data's fate, because they are inside the prepared transaction.
* **D17. *Open.* A transaction may carry facts up to a bound; beyond it the commit is refused.** The bound is the size of the facts text the proxy reads. *Corrected in M2b-2b:* this first said 256 KB, about 1,700 ordinary facts; the answer has to fit the proxy's 256 KB read buffer **with its headers**, so the bound is **200,000 bytes** of facts text (`shared.facts_text_max()`), about 1,300 facts of ordinary rows (150 bytes each) and about 700 updates of a table with a long name. The refusal is the
  existing `transaction-too-large` (54000) with the transaction rolled back. *Alternative:* compute the Merkle root inside PostgreSQL (`cdb.changes(xid)`), so that the proxy reads 32 bytes and the bound is
  gone; it costs a third implementation of the tree (in SQL), checked against the same golden cases. *Recommended:* the bound, now; the SQL root when a user hits it.
* **D18. `state` of a branch's tip is kept with the tip.** The chain record gains the 32 bytes; recovery at start takes it from the last commit of the branch in the log (the commit holds its own `state`), so
  there is no new file.
* **D19. Recovery is unchanged.** The prepared transaction is still `cdb:<id>`; settling it commits or rolls back the data and its delta rows together.

**Gate for M2b-2b:** the `changes` of every commit through the proxy equals the Python reference over the net facts recomputed from the rows of `cdb.delta` with that `commit_id` (the test recomputes the
net effect itself); the `state` chain recomputes from the log alone; the verifiers at L1 and L2 still accept the log; a kill between `PREPARE TRANSACTION` and `COMMIT PREPARED` leaves, after recovery,
the data and its delta rows both present or both absent; the cost of the two extra round trips is reported.

**Not in M2b-2:** branches (M2c), `AS OF`, merge, L3 replay.

### 9.1 M2b-2a as built

The proxy installs the capture at start, after it has settled the prepared transactions and before it serves anyone, through the catalog connection that recovery uses (`catalog.install_capture`):
the 13 statements of `sql/capture.sql` (turned into `src/capture_sql.cho` by `tools/gen_capture.py`, with a `--check` in the gate), then `select cdb.untrackable()`, then `select cdb.track_all()`.
**No commit changes yet**: `changes` and `state` are still zero.

* **An event trigger** (`cdb.on_ddl`, on `CREATE TABLE`, `CREATE TABLE AS` and `ALTER TABLE`) tracks a table in the transaction that makes it, so its first write is captured. A keyless table, or a partitioned one, makes the
  statement fail (`55000` / `0A000`); dropping the key of a tracked table is refused the same way. It is created before the tracking pass, so there is no moment in which a new table is neither tracked nor refused.
* **A start puts the event trigger back on.** The install drops and re-creates it (`drop event trigger if exists`, then create), so an administrator who disabled it by hand gets it enabled at the next start, even if that start is then
  refused for a keyless table; tables made while it was off are tracked by the start's `track_all`. (`tests/proxy_e2e.py` checks both.)
* **`cdb.untrackable()`** lists what the capture cannot track: tables without a primary key and partitioned tables with their partitions. If there are any, **the proxy refuses to start (exit 7) and says which**.
* **A failed install** names the statement and says what the event trigger needs (a superuser upstream role), exit 7.

**Found while building it:**

* **Partitioned tables are a hole, not a corner.** A write through a partitioned parent fires the parent's statement triggers and a write straight into a partition fires the partition's, so the same row would be recorded under two table
  names depending on the path it was written through (measured: a row inserted through the parent was captured, one inserted into the partition directly was not captured against the parent). They are therefore refused like keyless tables.
  The guard cannot create one (`PARTITION BY` is not parsed), so only a table that was already there can trip this.
* **The guard accepts a column-level `primary key` and refuses a table-level `primary key (a, b)`** (`reserved-word`, `tools/gen_stmt.py`): so D15 does not stop a client from creating tables, but a table made through the proxy has a one-column key. A composite-key
  table made around the proxy is tracked fine (`tests/capture_check.py` covers one).
* **An event trigger is per database, and the differential suites share the server's `postgres` database.** The first run of the gate would have broken `ddl_diff` (it makes keyless tables) as soon as an end-to-end test had started a proxy there.
  The proxy tests (`proxy_e2e`, `ext_e2e`, `drivers_e2e`, `measure_p2e`) now run in their own database, `cdb_e2e` (`E2E_DB` overrides it; mutant workers already had theirs), made on demand by `tools/pgtee.py ensure_database`.
  Two fixtures that made keyless tables (`p0_big`, `p0_fresh`, `m1_ddl`) have keys now. This is what D15 costs a test suite, and it is the same cost to anyone who points the proxy at a database that has keyless tables.

**Tested:** `tests/proxy_e2e.py` (9 checks): the delta table exists and a table made after the start has three triggers; an insert, an update and a delete through the proxy are captured in order and the new-row hash is recomputed in the test as
SHA-256 of the prefix and the `jsonb` text; a keyless `CREATE TABLE` through the proxy fails and creates nothing, a keyed one works and its first write is captured; with a keyless and a partitioned table present the proxy exits 7 naming both,
and starts once they are gone, and the start tracks a table that was made while the event trigger was off. `tests/capture_check.py` grew 11 checks for the event trigger and `untrackable()`. Three proxy mutants (the install loop skipped, the keyless
check skipped, `track_all` skipped), all killed.

**Not yet (M2b-2b):** the commit path reading `cdb.facts`, `changes` and `state` in the commit, the bound on facts (D17), the crash-consistency test, and the cost of the two extra round trips on a write.

### 9.2 M2b-2b as built

**A commit now carries real `changes` and `state`.** `commitpath.conclude`, for a transaction that wrote, asks the database (inside the transaction) for `select ... cdb.facts(txid_current())`, hands the text to `state.changes_of`
(the parser of `C` lines moved from the test tool into `src/state.cho`, so `statecheck` and the proxy run the same code), and builds `state` from the tip's state and these changes. A read has the constant empty `changes`
(one SHA-256, no round trip). Before `PREPARE TRANSACTION` the delta rows of the transaction are given the commit's id (`update cdb.delta set commit_id = ... where xid = txid_current()`), so they are in the prepared transaction and live
or die with the data. The tip is now 64 bytes (the commit's id and its `state`); a restart reads the state from the last commit of the log (`commit.f_state_at`, new in the decoder), so the chain goes on across restarts.

**Measured** (`scripts/measure_p2e.py`, 600 statements, two runs each of the proxy from `main` before this change and after it, same machine and compiler, a noisier machine than in section 3: the `select` baseline was 4.9 to 5.3 ms, not 3.7):

| median ms | before | after |
|---|---|---|
| `insert` (autocommit, a write) | 5.73, 5.15 | **6.75, 6.68** (+1.3 ms, about 23 %) |
| `select` (a read) | 4.86, 5.26 | 5.25, 4.37 (no consistent change: a read asks nothing extra) |
| a transaction of 10 selects | 19.9, 18.7 | 21.4, 20.7 (within the noise) |
| four clients at once, selects | 191, 208 statements/s | 203, 193 |

A write pays the facts question, the stamping `update`, the capture triggers and one more hash: about 1.3 ms on top of five. **Not measured here:** the same on a disk whose `fsync` is slow (it is the same two round trips, no `fsync`).

**Found while building it:**

* **Large `INSERT`s meet a different limit first.** A transaction of four 250-row inserts is refused by the accumulator (`the transaction is larger than one commit can record`, the existing per-transaction limit on statement text) long before it has many facts, so
  the facts bound matters for what changes many rows with little text: an `UPDATE` or `DELETE` of a big table. The test uses an `UPDATE` of 900 rows of a table with a long name (245 KB of facts text) and an `UPDATE` of 600 (160 KB, within).
* **Every write's delta rows are stamped, not only those with net facts.** First built to stamp only when the net facts were non-empty, which left a no-op `UPDATE`'s delta row (equal images) without a commit; it is now stamped (the test found it). A
  transaction that calls a function (`pg_sleep`) is a write to the commit path, so it pays the facts question too.
* **`cdb.facts` is capped in SQL, not in the proxy.** The query returns `'!'` instead of a text past the bound, so the refusal is graceful (`54000 transaction-too-large`, rolled back, nothing in the log, the connection goes on) and does not
  depend on a read that overflows the buffer closing the connection. A mutant that moves the cap far past the buffer is killed by exactly that check.

**Tested** (`tests/changes_e2e.py`, 28 checks, in the gate; and the crash windows of `tests/proxy_e2e.py`): seven kinds of step through the proxy (an autocommit insert; a transaction of insert, update of it, insert, delete; a read; a write that changes
nothing; DDL; a composite key; 300 rows); then for **every commit of the log**, `changes` and `state` are read from the bytes by a parser written in the test from `commit.md`, the commit's delta rows are read back from the database, the net
facts are worked out again in the test and `tools/state.py` gives their `changes`: it is the log's; `state` recomputed along the chain; the empty `changes` for the read, the DDL and the no-op; the three verifiers accept the log; the bound is
refused and leaves nothing; a restart chains the next commit from the recovered state. **Crash consistency** (`proxy_e2e` P2d-4): in all four windows a kill leaves the delta rows exactly when the data is there, each stamped with the commit's id (0 and
0 for the two windows that roll back, 1 and 1 for the two that commit). Six `chg:` mutants (facts not asked, state ignoring the parent, the tip not keeping the state, delta rows not stamped, the bound off, a restart not reading the state), all killed.

**Not yet:** branches (M2c), `AS OF`, merge, L3 replay; and an independent reading of `spec/state.md` (D13).

## 10. M2c: branches (design; nothing here is built)

M2c turns the one branch the proxy serves (a command-line argument) into several, and a connection chooses its branch. It is two PRs: **M2c-1** is the refactor (a table of branches, a branch per connection,
`search_path`, a schema snapshot per branch) and changes no behaviour of the one branch; **M2c-2** adds the fork.

**Measured for it** (PostgreSQL 16.15; `forkexp`: two tables of 100,000 and 1,000 rows, the capture installed):

* The fork as one transaction (`create schema`, `create table ... (like ... including all)`, `insert ... select`, then `cdb.track` of each copy) takes **about 125 ms** for 101,000 rows *(corrected in M2c-2: 261 ms for the copy alone on a table of three columns and an index, 293 ms through the proxy, section 12)*, and **the transaction records no facts**
  (`cdb.facts` is empty): the copy is made before the triggers exist, so it is a base and not a change. A connection started with `-c search_path=cdb_b_feat` (the startup `options`) sees only its branch; an `UPDATE` there left `main` untouched.
* **`cdb.delta` names a table, not its schema**: a write to `acc` in two branches is two rows of the same `tbl`. Within one commit this is harmless (a commit is on one branch) but the store needs the schema for merge and `AS OF`.
* **The guard cannot lower `select cancho_fork('x')` today**: `cannot-lower`, as for `select now()` with no `FROM`. The IR already has a `Call` statement whose effect is `call <fn>` (`ir.md` §1, §2) and the token already grants `call` effects, so
  the fork can go through the whole authority path unchanged once a bare `select f(constants)` lowers to it.

**Decisions.**

* **D20. A branch is `[a-z0-9_]{1,40}`, at most 64 of them, in a table the `Store` keeps** (name, next `seq`, whether it has a tip, the tip's id and `state`, and for a fresh fork the parent's id and `state`). At start the proxy scans the log and
  builds every branch's tip (today it finds one). The branch on the command line is the first one and exists with no commits; its schema is `public`. Any other branch `b` has the schema `cdb_b_<b>`. A name outside the rule is refused.
* **D21. A connection's branch is the database name in its startup** (today compared with the one the server serves; it becomes a lookup in the table). A branch that is not in the table is refused as now (`login-branch-denied`, 3D000); the token must allow it (its `branch` pattern,
  `token.md` §2) as now. The branch is kept in the connection's state; every commit of that connection is on it.
* **D22. The upstream connection of a client on `cdb_b_<b>` is opened with the startup option `-c search_path=cdb_b_<b>`**, so unqualified names resolve there (measured above); the guard, which never accepts a schema-qualified name, cannot escape it. The schema snapshot
  the guard reads (`src/snapshot.cho`, today `nspname = 'public'`) is read for the connection's schema, and its hash is the commit's `schema`.
* **D23. `select cancho_fork('<new>')` forks the connection's branch.** A bare `select f(constants)` lowers to the IR `Call` statement (the lowering gets one rule and its differential cases); the guard checks the token as for any statement (`call cancho_fork` must be granted),
  and the proxy, seeing that the approved statement is that call, does the fork instead of forwarding it. **The commit is on the new branch**, so the token's `branch` pattern must match the new name as well as the connection's: an agent whose token says `agent-*` can fork
  `agent-7` and nothing else; a token for `main` alone cannot fork at all (L2 would refuse the commit, so the proxy refuses first).
* **D24. The fork commit** has `branch` the new name, `seq` 0, `parents` the source branch's tip (none if the source has no commit: then it is a root), `statements` the IR hash of the call, `effects` `call cancho_fork`, `changes` the empty root and
  `state` the chain over the source tip's `state` and that. It is made in the transaction that copies the tables (the proxy's `PREPARE TRANSACTION`, the log, `COMMIT PREPARED`), so the schema exists exactly when the commit does and a crash is settled by the recovery that already exists.
* **D25. The copy is of what is committed, which is the source's tip**: ~~the proxy runs one commit at a time and the fork is one of them, so none interleaves.~~ *(Corrected in M2c-2: another connection's commit can land while the copy runs, so the fork notes the source's tip when it begins and is refused `fork-raced` if the tip has moved, section 12.)* **Limits, stated:** ~~the fork blocks the proxy's loop for as long as the copy takes (about 290 ms for 101,000 rows through the proxy, *corrected in M2c-2 from 125 ms*; 2.5 s a million is the copy alone and not re-measured) and is bounded by the upstream
  wait (5 s), so a bigger fork fails and rolls back with an error;~~ *(Corrected in M2e: the fork is the connection's own query, relayed asynchronously, so the proxy does not wait for it and no 5 s bound applies to it: the connection that forked waits for the copy, which takes about 290 ms for 101,000 rows through the proxy (corrected in M2c-2 from 125 ms; 2.5 s a million is the copy alone and not re-measured), and the locks it takes are held until the commit. What is synchronous is the commit's own steps (facts, stamp, `PREPARE`, the log, `COMMIT PREPARED`), as for any transaction.)* a branch holds a full copy of the tables.
* **D26. `cdb.delta` gets a `sch` column** (the table's schema, from the trigger), so a branch's deltas can be told apart; `cdb.on_ddl` and `cdb.track_all` handle `cdb_b_*` as well as `public`.

**Slices.**

| Slice | Delivers | Gate |
|---|---|---|
| **M2c-1** | the branch table, every tip found at start, the branch per connection; the one branch behaves as before (**`search_path` and the snapshot per branch moved to M2c-2**, section 11: until a fork exists no branch has a schema of its own to point them at) | the whole existing suite; `store_check` with logs of several chains (the L1 vectors of forks and merges); a connection to a branch that is not there is refused; mutants |
| **M2c-2** | `sch`, the lowering of `select f(constants)` to `Call`, the fork (copy, track, commit), connections to the new branch | two connections on two branches see their own data and a write in one is not in the other; the fork commit verifies at L1 and L2 (the three verifiers); a token that does not cover the new name cannot fork; a crash between the copy and the commit leaves a schema if and only if a commit; the fork's cost reported |

**Not in M2c:** `AS OF`, merge, deleting a branch, forking another branch than the connection's, a branch of a branch of a name that was removed.

## 11. M2c-1 as built

The proxy's one branch became a table of branches, and a connection has one of them. Nothing a client of a single-branch log can see changed (the whole existing suite passes unchanged).

* **The table** (`store.open_log`): the configured branch is entry 0 whether or not it has a commit; every other branch appears when its first commit is met in the log scan, in log order. For each branch the table has its name (at most
  `branch_name_max()` = 64 bytes), its next `seq`, whether it has a tip, and the tip (the last commit's id, then its `state`). At most `branches_max()` = 64 branches; a log with more, or a name over 64 bytes, is refused at start as `r_too_big`.
  `info[3]` and `info[5]` still describe the configured branch, so `tools` and tests that read them are unchanged.
* **Login** looks the startup database up in the table: found, the token is checked against that branch as before (its `branch` pattern must allow it) and the index is kept in state slot 23; not found, `login-branch-denied` `3D000`, exactly the refusal
  a database that was not the one branch got before. A server therefore serves every branch its log already holds, though a branch can only come to exist, until M2c-2, by an operator starting a server configured with a new name.
* **A commit** takes its name, `seq`, parent and parent's `state` from the connection's branch, and advances that branch's chain only.
* **Moved to M2c-2:** the `search_path` startup option and the schema snapshot per branch. Every branch of M2c-1 shares schema `public`, so there is nothing to point them at, and writing them now would be code no test can exercise. The claim
  that comes with M2c-1 is therefore the narrow one, C108 to C110 in `claims.md`: chains are independent, and a branch that is not in the log is not reachable.

## 12. M2c-2 as built

`select cancho_fork('<name>')` makes a branch. What was built, and where it differs from section 10:

* **The statement.** The lowering turns a bare `select f(constants)` (one item, no FROM, no WHERE, GROUP, ORDER, LIMIT, no DISTINCT) into the IR statement `Call` (ir.md section 2, tag 5; `now()` stays a `Nondet` and is refused); the guard checks the token for `call cancho_fork` as for any statement. The text is then read by `src/fork.cho` for exactly `select cancho_fork('<name>')`
  (spaces, an optional `;`, nothing else): a computed or second argument is `fork-malformed`, a name outside `[a-z0-9_]{1,40}` is `fork-bad-name`.
* **Decided before it runs** (`src/forkpath.cho`): it must be the only statement and outside a transaction block (`fork-in-transaction`, 25001); the token's `branch` pattern must allow the NEW name (`fork-branch-denied`, 42501); the name must not be in the table (`fork-branch-exists`, 42710) and the table not full
  (`fork-too-many-branches`, 54000). The proxy then sends upstream, in place of the guard's rendering, `select cdb.fork('<source schema>', 'cdb_b_<name>')`, and notes the source's tip. **Simple protocol only**: a Parse of the statement is `fork-extended-protocol` (0A000), since its argument would be a parameter.
* **The copy** (`cdb.fork` in `sql/capture.sql`): `create table ... (like ... including all)` and `insert ... select` of every table (generated columns left to be computed, identity columns set past the copied rows), the foreign keys between the copies, then `cdb.track` of each; the event trigger skips the copy's own `CREATE TABLE`s (`cdb.forking`) so that the copy is a base and records no facts.
  `cdb.delta` has the `sch` column (D26); the event trigger, `cdb.track_all` and `cdb.untrackable` handle `cdb_b_*`. **Not copied:** views, functions, types, and sequences: a `serial` column's default goes on drawing from the source's sequence.
* **The commit** (`commitpath.conclude`): the first of the new branch (seq 0, parent the source's tip, `call cancho_fork`, empty `changes`, `state` over the source's state and it), made in the transaction that did the copy (`PREPARE TRANSACTION`, log, `COMMIT PREPARED`). The branch enters the table only when its commit is in the log. **Two checks at commit time:** if the source branch's tip is not the one noted when the fork began (another connection committed on the source while the copy ran), the fork is rolled back,
  `fork-raced` (40001), and can be tried again; if the name is in the table or the table is full by then, `fork-branch-exists` (42710, rolled back). The second is defensive: two forks of one name cannot both get past PostgreSQL's own `create schema`, and a table filling in between needs 64 branches; it has no test.
* **A connection to the branch** opens its upstream session with `-c search_path=cdb_b_<name>` and its guard reads the snapshot of that schema (`snapshot.sql_for`); a branch that is not the first and whose name is not a plain one cannot be connected to.
* **Found on the way, and fixed:** the flag that says a client's token is in the token store (`acci[8k + 4]`) was never cleared when another client took the slot, so a second, different token was never stored and L2 refused its commits (`token-missing`). Every earlier test used one token. A client now starts with it cleared, so a token is stored once per connection and the store may hold it more than once.
* **Cost** (`scripts/measure_fork.py`, one table of three columns and an index, median of three): 63 ms through the proxy for 1,000 rows (the copy alone 49 ms) and 293 ms for 101,000 (261 ms). The proxy's own part, the guard, the commit and the log, is 14 to 32 ms. This is slower than section 3's 125 ms for 101,000 rows (a different table: its shape was not recorded, so the cause is not known); that claim is corrected in place at sections 3 and 10 (C113).
  *(Corrected in M2e: this also said that the proxy's loop waits for the copy; it does not, see C113. The connection that forked waits, and so do writers that need the locks the copy takes.)*

## 13. M2d design: `AS OF`

Measured first (`scripts/measure_asof.sql`, a scratch database, PostgreSQL 16): a table of 100,000 rows, then 70,000 later changes (50,000 updates, 10,000 deletes, 10,000 inserts), each stamped with an order number; a function
`cdb.asof(null::t, n)` answers `t` as of order `n` from the table and the deltas alone, with the index `(sch, tbl, ord)` on `cdb.delta`. **243 to 279 ms for the 100,000 rows; 0 differences** from a copy of the table made at that point (both ways of `except`),
and **0 differences at the latest order** from the live table. Section 3.4's 550 ms is replaced by this figure, for this shape: a table of three columns and one key, the later deltas all in one commit. A scan of the table and of the later deltas of that table is the cost; a bigger history costs more, linearly.

* **D27. Syntax.** `from t as of '<64 hex digits>'` and the same after a joined table; an alias may follow (`from t as of '...' x`). `AS` followed by the word `OF` and then a string literal is the clause; `AS` and a name is an alias as before (`of` is an ordinary word otherwise), so no statement that parsed before parses differently. The lexer needs no new token; the parser and `stmt` grow one node. The literal is 64 hex digits, else `as-of-bad-commit` (0A000). **A statement that writes** (`UPDATE`/`DELETE` of an `AS OF` table, an `INSERT` selecting from one if that ever lowers, any statement with an effect other than a read) is refused `as-of-write`: history is read-only.
* **D28. Which commits.** A commit of **the connection's own branch's chain**: the whole chain of the first branch; for a forked one, its fork commit (the copy as it was made, which is "everything since rewound") and every commit after it. A commit of another branch, or one that is not in the log, is `as-of-unknown-commit` (22023), and so is one from before the fork (Q6). ~~A read is a commit too, and may be named: its tables are as of its place in the chain.~~ *(Corrected in M2d-3: only a commit that wrote, changed the schema or called a function can be named, since those are the commits the proxy prepares and marks (D30); a read changed nothing, so name the commit before it. A read's id is `as-of-unknown-commit`.)*
* **D29. The IR says it.** The table's `Name` in the statement is `t@<hex>`, in `from` and in every `Col` that refers to it, so that the statement's id hashes the commit that was read and L2 sees `read t@<hex>` and `read t@<hex>.c`: **a token that allows `read orders` does not allow `read orders@...`** (Q5), and a token written `read orders@*` does. `Name` is opaque bytes to all three verifiers and the spec only forbids `.` in it, so nothing in them changes but their vectors (M2d-1: vectors with such names, accepted by Python, cancho and Go, and refused when the recorded effects drop the `@`). The lowering resolves the name by cutting the suffix off.
* **D30. The order, `ord`.** `cdb.delta` gets `ord bigint`: the commit's **index in the log** (0 for the first record of the whole log), written in the same `update` that stamps `commit_id`, in the prepared transaction. ~~The proxy keeps, next to the ids it already keeps, one byte per commit: its branch's index, so `as of C` is answered by the position of `C` in the ids, its branch, and `ord`.~~ *(Corrected in M2d-3: the place is found in SQL and the proxy keeps nothing new. The same statement that stamps the delta rows inserts a row in `cdb.mark(commit_id, sch, ord)`, in the prepared transaction; `cdb.ord('<hex>')` finds it among the marks of the schema first on the search path, which is the connection's branch.)* Deltas later than `C` on the branch are `sch = <the branch's schema> and ord > ord(C)`. *Rows interleaved by open transactions are ordered by commit, not by `seq`*, which is why `seq` is not the order. **Old rows:** deltas stamped before this slice have no `ord`; if there are any, `AS OF` is refused `as-of-unavailable` (the history from before it is not ordered), checked at start.
* **D31. The rendering.** `from t as of '<hex>' x` becomes `from cdb.asof(null::"t", cdb.ord('<hex>')) as "x"` (the alias is `t` if none; `t` resolves through the connection's search path, as in the original statement), by `src/asof.cho` on the guard's rendering: the function of the measurement, dynamic SQL over the table's key from the catalog: the current rows whose key no later delta touched, plus the old image of the **earliest** later delta of each key that touched it, unless that delta is an insert. PostgreSQL plans it. **Limit, stated:** a column added, dropped or retyped after `C` is not reflected (the old image is the old row's `jsonb`, read into today's type: a column added since is null, one dropped since is missing, and an incompatible change is PostgreSQL's cast error); a table made after `C` reads as empty. The proxy refuses nothing for these; a claim is that the data is right where the schema is the same.
* **D32. Tests.** Cases by hand for the parser and `stmt` (the differential suites do not apply, D9: PostgreSQL rejects the clause); lowering cases with the hand-written IR; and **the oracle of D9**: a test makes a copy of the table after each commit of a random session of inserts, updates and deletes (the test is the only writer, so the copy is the table as it was) and then asks for the table `as of` each commit through the proxy and compares it, row for row, with the copy: 300 commits over an integer, a composite and a text key, as in `capture_check`. Mutants on each rule.
* **D33. Slices.** **M2d-1:** `docs/spec/ir.md` gets the convention (section 6) and `tools/gen_ir.py` its vectors; the three verifiers accept them. **M2d-2:** the parser, `stmt`, the lowering and the guard (the rules `as-of-bad-commit`, `as-of-write`), with cases, still no proxy. **M2d-3:** `cdb.asof`, `ord` and the per-commit branch byte, the proxy's translation (`as-of-unknown-commit`, `as-of-unavailable`), the oracle test, the cost reported, claims.

**Not in M2d:** an `AS OF` on a branch other than the connection's, `AS OF` a timestamp, a snapshot to bound the cost (M3), and the reflection of schema changes (D31).

## 14. M2d as built

`select ... from t as of '<commit id>'` works, on the first branch and on a fork, through the proxy. Differences from section 13 are corrected there, in place; what was built:

* **The clause** (M2d-2): `AS OF` and a string literal of 64 lower-case hex digits after a table in `FROM` (any table of a join; an alias may follow); the table node carries the literal; the lowering writes the table's name as `t@<hex>` in `from` and in every column that refers to it; `as-of-bad-commit` for a literal that is not an id; `as-of-write` for the clause on the table of an `UPDATE`, a `DELETE` or an `INSERT`. `as of` without a literal is still an alias named `of`. The guard checks the token against the names as written (D29).
* **The rewrite** (`src/asof.cho`, run by the guard on its rendering): `"t" as of '<hex>' [as "x"]` becomes `cdb.asof(null::"t", cdb.ord('<hex>')) as "x"`, leaving alone whatever is inside a string constant or a quoted name.
* **The answer** (`sql/capture.sql`): `cdb.mark`, the column `cdb.delta.ord` and the index on `(sch, tbl, ord)`; `cdb.ord(hex)` (22023 `as-of-unknown-commit` for an id that is not a commit that wrote on this branch, 55000 `as-of-unavailable` if delta rows of the branch were stamped before `ord` existed); `cdb.asof(null::t, n)`, the function of section 13's measurement, with the deltas of the asking transaction counted as later than every commit (its own writes are not in the past).
* **The stamp** (`commitpath.conclude`): one statement, `with m as (insert into cdb.mark ...) update cdb.delta set commit_id = ..., ord = ...`, in the transaction that is prepared: **a write is no slower within what was measured** (`scripts/measure_p2e.py`, 200 inserts, two runs: medians 5.8 and 6.9 ms, against 5.4 and 6.7 before; the spread of one run is larger than the difference). The fork commit is marked in the new branch's schema.
* **Limits, stated:** a read cannot be named (it wrote nothing); a column added, dropped or retyped after the commit is not reflected, and a table made after it reads as empty (D31); history stamped before `ord` existed is refused rather than guessed; the cost of a history read is that of section 13 (a scan of the table and of its later deltas: 242 to 279 ms for 100,000 rows and 70,000 later changes, measured in PostgreSQL directly and not through the proxy), so a long history is slow, and a snapshot to bound it is M3.

## 15. M2e design: `cancho_merge`

Measured first (`scripts/measure_merge.sql`, a scratch database): a table of 100,000 rows, forked; the target then changes 9,500 rows and the source 9,500, of which 500 the same way and 500 differently (conflicts) plus 9,000 of its own. A three-way merge **by key and by state** written in SQL (the base is `cdb.asof` at the base commit's place, section 14) found **exactly the 500 conflicts and the 9,000 rows to take from the source** (1.2 s, a dry run), and with the conflicts removed applied them in **1.5 s**: the target kept its 9,000 changes, took the source's 9,000, the 500 changed identically stayed as they were, and **the merging transaction's net facts were exactly the 9,000 rows applied**, because the capture triggers see the merge as any other writes. The cost is that of three scans of the table and the base's history (linear in the table, not in the changes). This is one table shape, one machine, the conflicts removed by hand: the correctness claim is for the slice that builds it (an oracle, D41).

* **D34. A merge is a three-way merge of states, key by key** (this replaces D10's reading of the facts since the base): for every table, the **base** state (the table `AS OF` the merge base), the **target** (the connection's branch, live) and the **source** (live) are compared on the primary key's images. Source unchanged from the base: the target's row stays. Target unchanged, source changed (updated, deleted, inserted): the source's version is applied to the target. Both changed to the **same** image: nothing. Both changed to **different** images, or one deleted and the other changed: a **conflict**. A key change is a delete and an insert, and is merged as two.
* **D35. The merge base** is the nearest common ancestor of the two tips in the commit graph. The proxy builds the graph while it reads the log at start: each commit has its branch and its parents' indices, found among the (at most 64) tips at that moment, since a parent is always a tip when its child is made. The base's place for `AS OF` is that of the nearest commit at or before it on its own branch that wrote (`select max(ord) from cdb.mark where sch = <its schema> and ord <= <its index>`). No common ancestor, or a base that has no marked commit at or before it: `merge-no-base`. A source whose tip is an ancestor of the target's (already merged) is a commit with two parents and no facts.
* **D36. Conflicts abort, and so does anything else that goes wrong** (Q2 as recommended): all tables are checked for conflicts **before** anything is applied, and one conflict anywhere aborts the whole merge: the transaction rolls back, nothing is in the log, the client gets `merge-conflict` naming up to ten keys with their tables. Applying a source row that PostgreSQL refuses (a unique, foreign-key or check violation) is `merge-constraint` and also aborts. A table in the target that the source does not have, or with other columns, is `merge-schema-differs`; the merge does not carry schema changes. Applying is in foreign-key order: inserts and updates parents first, then deletes children first.
* **D37. It is a statement, a function and one commit.** `select cancho_merge('<source>')` (the form and the rules of the fork's, D23: lowered to the IR `Call`, one statement, outside a transaction block, an existing branch that is not the connection's) is rewritten by the proxy to `select cdb.merge(...)` with the schemas and the base's place, run in the connection's own transaction. The commit is on the **target**, its **two parents** are the target's tip and the source's tip, in that order, its `state` is the chain over **both** parents' states and its `changes` (docs/spec/state.md section 4 has the case), its `statements` the IR hash of the call, its `effects` `call cancho_merge`. The two tips are noted when the merge begins and checked at the commit, as the fork's source is: a commit on either since is `merge-raced` (40001), rolled back.
* **D38. What the token must allow.** The `branch` pattern must allow the connection's branch (it is the target) and `call cancho_merge` must be granted. **The proxy also refuses (`merge-denied`, 42501) unless the token allows `write` on every table of the target.** The commit cannot record those writes as effects: L2 with the statement store compares the recorded effects to what the IR of the call infers, and the call infers only `call cancho_merge`. So **L2 cannot check, from the log, that the token could write the tables a merge changed; L3a, which replays the facts, can show what was written** (Q7).
* **D39. Not in M2e:** resolution policies, merging schema changes, merging sequences, a merge into a branch other than the connection's, more than two parents.
* **D40. Cost and locks, stated.** Linear in the table sizes (section above); the merge holds the locks of its writes until the commit, and the connection that merges waits for it. The proxy does not wait: it relays the merge as it relays the fork.
* **D41. Tests.** An **oracle**: a Python reference of D34 over random sessions on two branches (copies of the base, the target and the source made with `create table ... as`, the test being the only writer), compared with the database's result on the target, every key; conflicts: the reference says which keys, the database's error must name them and leave the target unchanged and the log without a commit; the commit's two parents, its `state` over both, verified by the three verifiers at L1 and L2 (a commit with two parents is the first the log holds); crash windows as the fork's; the race; mutants on each rule of D34 to D38.
* **D42. Slices.** **M2e-1:** `cdb.merge` in `sql/capture.sql` with the Python reference and the oracle at the SQL level in `tests/capture_check.py`, mutants. **M2e-2:** the commit graph in `store.open_log`, the statement in the lowering of `Call` (already done for the fork), the proxy's decision and rewrite, the two-parent commit in `commitpath.conclude`, the end-to-end oracle, the verifiers, the cost reported.

## 16. M2e-1 as built: `cdb.merge`

The SQL half of the merge (D34 to D36), in `sql/capture.sql`, checked against a Python reference (`tests/merge_check.py`). The proxy does not use it yet (M2e-2).

* **`cdb.merge(tsch, ssch, bsch, bord)`** merges the tables of schema `ssch` into those of `tsch`, with the base the tables of `bsch` as of place `bord`. It looks at **every** table before it applies anything: the three states' images by key in one pass (`cdb.asof` for the base), the conflicts counted, the rows to take from the source kept in variables. A conflict anywhere raises `merge-conflict` (40001) naming up to ten tables and keys; tables that differ, or a table the base did not have, raise `merge-schema-differs` (55000). It applies deletes children first, then updates and inserts parents first, by ordinary statements, so that the capture records the merge as the net facts of the transaction; a row PostgreSQL refuses raises `merge-constraint`. **It makes no temporary table**: the prototype of section 15 did, and a transaction that has used one cannot be prepared, which every commit that writes is.
* **Order is a limit, stated.** All deletes come before all updates and inserts, so a result that is consistent but cannot be reached in that order (the source deletes a parent while repointing its only child elsewhere) is `merge-constraint`; a result that breaks a foreign key is refused for the same reason it should be.
* **The oracle** (`tests/merge_check.py`): 60 random trials and 5 pinned scenarios, each a fresh base, a fork, random statements on each side (those PostgreSQL refuses are skipped), then the reference of D34 over copies of the three states, and the foreign key checked on its result. 13 trials were conflicts, 3 foreign-key breaks (the pinned ones), 48 merges (7 changing nothing): the database refuses exactly where the reference does, leaves the target as it was and no delta row, and where it merges the target equals the reference's result row for row and **the merging transaction's facts are those of a diff of the target before and after**.
* **A bug of M2b-1 found by the oracle's first run, and fixed:** in `to_jsonb(x)` a bare `x` is **the column x** when the table has one, not the row, so the capture (whose row aliases were `n` and `o`) recorded a column's value as the row's image for a table with a column called `n`, `o` or the like; the oracle's own first dump (alias `x`, a table with a column `x`) had the same flaw and compared only that column. The capture's and the merge's aliases are now chosen per table so that no column has the name (`cdb.free_alias`, computed by `cdb.track` and passed to the trigger; `ALTER TABLE` re-tracks), and `tests/capture_check.py` has a table with columns `n`, `o`, `x` and `cdb_o` (the alias itself) among its scenarios. Claim C120.

## 17. M2e as built: `cancho_merge` through the proxy

`select cancho_merge('<source>')` merges the source branch into the connection's branch, as D34 to D42 say, with `cdb.merge` (section 16) doing the work upstream. What was built:

* **The commit graph** (`store.open_log` at start, `commitpath.conclude` as commits are made): for each commit its branch's index and its two parents' indices (`Store.cbr`, `Store.cg`), and for each branch the index of its last commit (`Store.tx`). A parent is found among the branches' tips at that moment, or by looking back through the ids; a merge commit has two. 17 MB for a log of the most commits the proxy accepts.
* **The base** (`forkpath.merge_base`): one walk down the indices from the higher tip, carrying two marks to the parents; the first commit that has both is the common ancestor of the highest index. It is passed to SQL as a commit index and the branch it is on; its place for `AS OF` is that of the nearest marked commit at or before it on that branch.
* **The decision** (`forkpath.start_merge`, as the fork's): one statement, outside a transaction block, an existing branch that is not the connection's, both branches with a commit, a base found; the token must allow `write` on every table of the branch (`merge-denied`: D38, which the commit cannot record); the two tips are noted. The proxy then sends `select cdb.merge(...)` in place of the guard's rendering. Simple protocol only (`merge-extended-protocol`).
* **The commit** (`commitpath.conclude`): on the target, the next seq, **parents `[target tip, source tip]`**, `state` over **both** parents' states and the changes, effect `call cancho_merge`; at commit time the two tips are checked against the noted ones and a commit on either since is `merge-raced` (40001), rolled back. `changes` is the root over the net facts the merge applied, from the same delta rows as any commit.
* **Rules and tags:** `merge-conflict` (from the database, naming tables and keys), `merge-constraint`, `merge-schema-differs` (from the database); `merge-malformed`, `merge-bad-name`, `merge-unknown-branch` (3D000), `merge-same-branch`, `merge-in-transaction`, `merge-denied` (42501), `merge-no-history`, `merge-no-base`, `merge-raced`, `merge-extended-protocol` (from the proxy).
* **Corrected in this slice:** the proxy's rendering of the merge puts the base's *place* in SQL (`select coalesce(max(ord), -1) from cdb.mark where sch = ... and ord <= <index>`), so the proxy needs only the base's index and branch, not a lookup of marks.
* **Limits, stated:** a source whose name is not `[a-z0-9_]{1,40}` (the first branch may be called anything) cannot be named in the statement; the commit cannot record the writes a merge makes (D38, Q7), so L2 cannot check from the log that the token could write the tables, and L3a, which replays the facts, can show what was written; a merge holds its locks until its commit and blocks writers of the same rows; a merge is all or nothing (no resolution policy); the walk and the graph are O(commits).

## 18. M2f design: the replay verifier (L3a)

What L3a adds to L1 and L2, from `docs/spec/state.md` section 5: that the **data is the history of the facts**, and that `changes` and `state` are what the facts give. This section is the design; the spec (`docs/spec/l3a.md`) is M2f-1.

* **D43. L3a needs no database to replay (corrects D12).** D12 said the facts are applied "to a scratch PostgreSQL". They need not be: a fact is a key and two images, and L3a never reads an image's contents, only its bytes and its hash, so replay is a map from `(branch, table, key)` to an image hash, applied in log order. **A PostgreSQL is needed only to read the tables the replay is compared with** (D46), and a verifier that is given a dump instead needs none. The verifier is then SHA-256 and a reader for two flat files, like the other three.
* **D44. Inputs.** (1) The **log** (read as L1 reads it) and the signing key's public half are not needed beyond that. (2) The **delta store**: the rows of `cdb.delta` that carry a commit's id (`tools/export_deltas`, a `psql` query to a tab-separated file: `seq`, commit id, schema, table, key, old hash, new hash, old image, new image, each hex or empty, one row per line; the images as hex so that the file has no escapes). (3) Optionally a **base snapshot** (Q8) of rows in the same form. (4) Optionally the **live tables** (D46).
* **D45. What it checks, in this order, each with a rule tag** (the first failure is the verdict, with the commit's index, as in L1 and L2):
  1. `store-malformed`: the file is not what D44 says; `store-foreign-row`: a delta row names a commit that is not in the log, or a schema that is not the commit's branch's (`public` for the first branch, `cdb_b_<name>` for another); a commit in the log with delta rows that is neither a write nor a call is `store-foreign-row`;
  2. `facts-image`: the hash of an image is not the hash stated for it (`SHA-256("cancho-db/row/v1" || 0x00 || image)`), or an image is absent where a hash is present;
  3. the facts of each commit, **netted from its rows by the rule of `cdb.facts`** (the first image before, the last after, per key, by `seq`; a row inserted and deleted, or changed and changed back, is no fact), must make **`changes`** by `state.md` section 3: `changes-mismatch`; and **`state`** from the parents' states by section 4, with a merge's two parents in the order the commit lists them: `state-mismatch`;
  4. `replay-precondition`: applying the facts in log order, an update or a delete whose old hash is not the hash of the row at that point (an insert of a key that is there, or a delete of one that is not, are the same) is refused with the commit and the key;
  5. `replay-final` (only with D46): the live tables are not what the replay holds.
* **D46. The final comparison** is what makes L3a worth having: the **content of every table of every branch**, read as `jsonb` text, hashed row by row and compared with the replay's map (a key the replay lacks, a key the tables lack, an image that differs). It proves **the tables hold exactly the history of facts the log commits to**; it does not prove that the history is what the statements meant (that is L3b, D12, not built).
* **D47. Branches and merges.** The replay holds one map per branch. A **fork** commit copies its source's map as it was at the fork (the commit has no facts: the copy is a base, section 12). A **merge** commit applies the facts it recorded, to the target's map; the verifier does not redo the merge (and so does not trust it: the facts are checked by 3 and 4, the data by 5). A commit with a parent on another branch uses that branch's `state` for section 4.
* **D48. What it cannot see, stated.** Data that was in the tables before the capture was installed and was never inserted by a fact is invisible without a base (Q8); a delta store the operator edited together with the log is a log the operator re-signed, which L1 refuses; the statements and their values are not replayed (Q3: L3b stays unbuilt); a commit's facts and its **effects** are not tied, so a commit whose recorded effects say a read but whose rows say a write is two verifiers' business (L2 over the statements, and this one over the rows) and no third check relates them (a later rule could: a commit with facts needs a `write` or `ddl` or `call` effect).
* **D49. Two implementations and vectors.** A Python verifier (`tools/l3a.py`, M2f-1) and one in cancho (`src/l3a.cho`, M2f-2) that must agree on every vector (golden logs with their delta stores and the verdict, written by hand from the spec: valid chains, one tampered, malformed or refused case for each rule of D45, forks, merges, a base); and a **third reading by a separate session from the spec and the vectors alone** (Q9, M2f-3): D13's "second verifier" rule, which the same-author pair does not meet. Mutants on both.
* **D50. Slices.** **M2f-1:** `docs/spec/l3a.md`, `tools/export_deltas`, `tools/l3a.py`, the generator of vectors and their runner, the end-to-end test over the logs of `fork_e2e`, `asof_e2e` and `merge_e2e` (they must verify, and each tamper of the delta store, the log or a live row must be refused with its tag). **M2f-2:** `src/l3a.cho` against the same vectors. **M2f-3:** the separate reading, and the claims.
* **D51. Cost.** Linear in the delta rows and, for D46, the table sizes, and **not measured**: M2f-1 reports it with the implementation.

