# M2: branches, `AS OF`, checked merge, row deltas and replay

**Status: design, with the measurements it rests on (section 3). Nothing here is built.** M1's last slice is merged ([`m1-extended.md`](m1-extended.md)
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
* **D7. `state` is a chain of the changes, not a hash of the contents:** `state_n = SHA-256("cancho-db/state/v1" || state_{n-1} || changes_n)`, `state_0` the
  empty root, a merge commit folding both parents' states in order. It is O(1) a commit and a function of history. **What it does and does not prove:** that two
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
| **M2a** | `docs/spec/state.md` (fact leaf, Merkle root, state chain, empty root), golden vectors, the fact/state code in cancho and Python | both agree on every vector; tampered fact lists are rejected; L1 and L2 vectors unchanged |
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
