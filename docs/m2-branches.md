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
* **D2. A fork copies (3.1).** `cancho_fork('new', 'from')` creates the schema, `create table ... (like ... including all)` and `insert ... select` for every table of the
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
| **M2d** | `AS OF` | the lexer, parser and renderer cases; results equal the copy-at-the-time oracle (D9); `AS OF` write refused; mutants |
| **M2e** | `cancho_merge` | the exit criterion: two agents on separate branches merge; a conflict, a delete-vs-update and a constraint violation each abort with their tag; the merge commit verifies (two parents) |
| **M2f** | L3a verifier (cancho and Python) | replay reproduces the state root on the M2b to M2e sessions; a flipped delta, a dropped fact and a tampered row are each rejected |

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

## 9. M2b-2: how the proxy uses the capture (M2b-2a built; M2b-2b is design)

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
* **D17. *Open.* A transaction may carry facts up to a bound; beyond it the commit is refused.** The bound is the size of the facts text the proxy reads: 256 KB, about 1,700 ordinary facts. The refusal is the
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

