# M3, the engine: design

Status: **design, nothing built.** Written before any engine code, as `docs/design.md` requires. Claims are measured where they can be (section 4) and say what they leave out. Open questions are answered at a
recommended default so the work can start; each is the owner's to overturn (section 8).

M3 in [`design.md`](design.md): *cancho storage (single writer, WAL, B-tree or LSM) and an executor for the SQL subset, behind per-feature flags. Exit: the differential suite passes on the declared subset; crash
and fsync-fault tests pass.* M1 is the demand test and the owner has said to go on.

## 1. What changes and what does not

A statement passes six layers (`design.md`). Today layer 4 (the executor) and layer 6 (storage) are **PostgreSQL**: the proxy lowers a statement to the IR, checks it against the token, and sends PostgreSQL the
guard's rendering; the capture triggers produce the row changes; the commit is two-phase (PREPARE, log, COMMIT PREPARED).

M3 replaces layers 4 and 6 with code in this repository. **Unchanged:** the protocol front, the lexer, parser and lowering, the guard and the token check, the commit builder, the log directory, all three verifiers
and the L3a replay verifier. The commit's `changes` and `state` are still defined by `state.md`; the engine is simply the *producer* instead of the triggers.

M3 does **not** remove PostgreSQL from the stack: catalog emulation for the client list (`pg_catalog`, `information_schema`, what the drivers ask at connect) is M4. Until then the engine serves a database
that PostgreSQL is not needed for **only when a client does not need the catalog**; the default stays PostgreSQL, and the engine is switched on per database (section 7).

What the engine has to run is exactly the IR (`spec/ir.md`): `Select2` (distinct, items, from, joins, where, group by, having, order by, limit, offset), `Insert`, `Update`, `Delete`, the four DDL kinds, and
expressions (operators, `Unary`, `In`, `Case`, `Cast`, calls). The lowering already refuses what is outside; the engine's *declared subset* is that, minus what a flag has not yet switched on.

## 2. What the language gives, and what it does not

Read from the compiler's own docs (`docs/file-writes.md` in the cancho repository) and builtins, not assumed:

* **Files:** `file_pwrite` and `file_pread` at an offset, `file_sync` (`fsync(2)`), `file_truncate`, `file_size`, `file_lock` (`flock`, released when the process ends), `dir_rename` (atomic `renameat` in one
  directory), `dir_sync` (so a rename is durable), `dir_open_new`, `dir_remove`. There is **no `fdatasync`**, and an append handle's `pwrite` still appends.
* **fsync failure is fatal.** After `EIO` the kernel may have dropped the dirty pages and cleared the error, so a second `fsync` can say `Ok` for data that is gone (PostgreSQL's 2018 "fsyncgate"). The engine
  treats any failed sync as the end of the process and recovers from the log on restart; it never retries.
* **Linux only for durability.** On macOS `fsync` does not flush the drive's cache; the file-writes document promises nothing there, and so does this one: *the engine's durability claims are for Linux.*
* **No ordered container.** `std.map` is a hash map; there is no sorted map, B-tree or sort in the standard library. The engine brings its own pages and tree. (Sorting for `ORDER BY` is the engine's too.)
* **Memory** is regions of 64 KiB and heap boxes (`box_slice`); a page cache is a heap box of fixed-size slots, written once at start.

## 3. Decisions

**D-M3-1. The current state of a branch is a copy-on-write B+tree.** Fixed 4 KiB pages with a CRC-32 (`std/crc`), keys and values as bytes, single writer. A write never changes a page that a root still
names: it writes new pages along the path and a new root. A **branch is a root pointer**, so `cancho_fork` is O(1) instead of the copy of 2.5 s per million rows measured for PostgreSQL (`m2-branches.md`), and two
branches share every page they have not written. The alternative, an LSM, is rejected for now: it makes a consistent branch cheap only with a manifest as complicated as the tree it saves, and the point reads
the IR is made of (`where key = ...`) are what a B+tree is good at.

**D-M3-2. History is a delta store, not old pages.** `AS OF`, replay and the verifiers need every past row version; keeping old page versions would keep every erased row inside them. So the tree holds
**only the current state** and the history is the append-only **delta segments**, one record per row change with the images and salts, exactly the shape of `cdb.delta` today (`spec/l3a.md` section 9) and the
shape `erasure` already scrubs (`m2g-erasure.md`). `AS OF c` is the branch's tip tree with the deltas after `c` applied backwards, as now (243 to 279 ms to rebuild 100,000 rows from 70,000 later deltas, `m2-branches.md` section 3.4 as corrected); signed
snapshots (M4) bound that. **A page no root names any more is overwritten with zeros** (it may hold an erased row's old image), which erasure needs and which costs one write per freed page.

**D-M3-3. The log is the commit authority; the root swap is the commit point of the data.** The order of one commit, each step synced before the next, is:
1. the delta records are appended to the delta segment and synced;
2. the new tree pages are written to unused pages and synced;
3. the commit record is appended to the log and synced (as today, `store.append`);
4. the new root is written to the **superblock** slot that is not current (two slots, alternating, each with a CRC and a sequence number) and synced.

At start the engine reads both superblocks, takes the valid one with the larger sequence, and compares its sequence with the log's tip: **a log that is ahead of the superblock is rolled forward** (steps 1 and 2
completed before step 3, so the pages are there: the superblock is written from the log record), **a superblock that is ahead of the log is a bug** and the engine refuses to start. So nothing is ever acknowledged
that the log does not hold, and nothing the log holds can be lost to a torn superblock. No separate WAL is needed: the delta segment and the log are the write-ahead record.

**D-M3-4. The executor interprets the IR.** One tree-walking interpreter over the bytes `ir.lift` and the guard already produce; no second parser. A feature (section 6) is switched on only when its differential
tests pass; a statement that needs an off feature is refused with a rule tag (`engine-feature-off`) before anything runs, so a flag can never change an answer, only whether there is one.

**D-M3-5. Types are what the IR carries.** Values are null, 64-bit integers and bytes (`ir.md`); `bigint`, `integer`, `smallint`, `boolean`, `text`, `varchar` and `bytea` map onto them. Others (`numeric`,
`timestamp`, `uuid`, `jsonb`) are not in the first subset and are refused at `create table`. **Text compares as bytes** (the `C` collation): the differential database is made with `LC_COLLATE=C`, and the page says
the engine does not claim PostgreSQL's default locale ordering. NULL follows PostgreSQL's three-valued logic and sorts last ascending.

**D-M3-6. The row image is the one the capture makes.** `to_jsonb(row)::text` of the supported types is simple enough to reproduce byte for byte, and the image is what the facts hash (`state.md`). Keeping it
means the engine's `changes` and `state` for a statement can be compared with the capture's **byte for byte** in shadow mode (section 7): the strongest oracle available, and it needs no new verifier.

**D-M3-7. Everything below the executor goes through one small file module**, `store`-style, with a numbered *crash point* before and after each write and sync of D-M3-3. A test build kills the process (or
fails the call) at point *n*; that is how the crash and fsync-fault tests of section 5 are made without a fault-injecting kernel.

## 4. What was measured

`scripts/measure_fsync.py` (kernel calls from Python on this machine, an ext4 virtual disk in the sandbox, 300 repeats; two runs agree):

| what | median |
|---|---|
| `pwrite` of 4 KiB, no sync | 0.5 µs |
| `pwrite` of 4 KiB and `fsync` | 107 to 115 µs |
| the commit of D-M3-3 (deltas, 3 pages and the superblock, three fsyncs) | **530 to 580 µs** (95th percentile 0.8 to 1.0 ms) |
| the same without the superblock (two fsyncs) | 230 to 310 µs |

An engine commit is therefore **about 0.6 ms of file writes**, against **3.77 ms for one Ed25519 signature** (`m1-commit-path.md` section 5.11, measured by the compiler's own benchmark) and the 6.2 ms a point
statement costs through the proxy today. **The signature, not storage, is the bottleneck**, so M3 is not a speed project: its gain is that a statement no longer makes PostgreSQL round trips and a two-phase
commit, and that fork and `AS OF` become cheap. Claimed: that. Not claimed: any throughput number for the engine, which does not exist yet. These timings are for **this disk**: a virtual disk may not honour a
flush, a real SSD with a volatile write cache can be slower or faster, and a spinning disk is two orders of magnitude slower. The test that matters is the crash test, not this table.

## 5. Gates (written before the code)

1. **Model test of the tree.** Random operations (put, delete, get, range, fork, drop a branch) on the B+tree against a Python model (a sorted dict per branch), with restarts, tens of thousands of cases; the
   tree after every restart equals the model; a flipped bit in any page is caught by its CRC and refused.
2. **Crash points.** For every crash point *n* of D-M3-3 and every commit of a scripted session: kill at *n*, restart, then (a) the engine starts, (b) its state equals the model after exactly the commits the log
   holds (all or none of the interrupted one, never part of it), (c) the three verifiers accept the log and L3a accepts the log with the delta segments. Torn writes are made by truncating the last page or
   superblock to every length.
3. **fsync faults.** A sync that fails at each point: the process stops (no retry, no acknowledgement of the commit), and the restart passes gate 2.
4. **Differential against PostgreSQL** (`LC_COLLATE=C`), per feature: the statements of `tests/lower_diff.py` and `tests/parse_diff.py` (and the expression differentials they share), as it applies, the `sqllogictest` corpus, answered by both, compared as sets (as ordered lists where there is an `ORDER BY`); and the **`changes` root** of every write against the capture's.
5. **Shadow run** (section 7) over the existing end-to-end suites with no divergence.
6. **A feature is on only when its row of the table in section 6 is green**; the table is the engine's declared subset, in the repository, with the test for each row.

## 6. Slices

| Slice | Delivers | Gate |
|---|---|---|
| **M3a** (built, below) | the page file, superblocks, the COW B+tree (bytes to bytes), fork (a slot made the same tree) | gates 1 and 2 on the tree alone, with the crash-point module; gate 3 and the page cache are not in it |
| **M3b** (the sweep built, 6c; the delta tree comes with the rows in M3c/M3d) | the zeroing and reuse of freed pages; the delta store as a tree; recovery from a log ahead of the superblock | gate 2 with the log; `AS OF`-style reconstruction equals the model |
| **M3c** (built, 6d and 6h) | tables, the row encoding and image (D-M3-6), the catalog of tables inside the engine, `create table` and `drop table` | the image equals `to_jsonb` for every supported type, on the corpus |
| **M3d** (built, 6f to 6h; the delta tree is not) | the executor for `insert`, `update`, `delete` and `select ... where <key> = <constant>`, and the engine's `changes` | gate 4 for these; `changes` equals the capture's |
| **M3e** (built, 6h) | predicates on any column, range scans on the key, `order by`, `limit`, `offset`, `distinct`, `in`, `case`, `cast`, `like` | gate 4 |
| **M3f** (built, 6i and 6j: `count`, `sum`, `min`, `max`) | aggregates and `group by`, `having` | gate 4 |
| **M3g** (built, 6k and 6l: nested loop; inner and left) | joins (nested loop first) | gate 4 |
| **M3h** (built, 6q and 6r: `add column`; an index is a recorded name, no tree is built) | `alter table`, `create index` (an index is a second tree) | gate 4 on the catalog after each |
| **M3i** (6n and 6o: the history, `AS OF`, a fork and an erase are built in the engine and its harness; merge and the proxy's functions are not) | native `cancho_fork`, `AS OF`, `cancho_merge`, `cancho_erase` on the engine | the existing fork, as-of, merge and erase end-to-end suites pass on it |
| **M3j** (designed as seven slices, 6s; not built) | the shadow run, then a database option to serve from the engine | gate 5, then the full gate on the engine for one database |

## 6b. M3a, built

`src/pager.cho` (4 KiB pages, a CRC-32 each, read and written by number, the crash hook), `src/btree.cho` (the copy-on-write B+tree: get, put, delete, and `next_after` for ordered scans; no recursion, a fixed scratch
buffer), `src/pstore.cho` (the superblocks, the catalog page and the commit), `proxy/btcheck.cho` (a command-line harness over all three), `tests/btree_check.py`, `tests/pstore_check.py`, 28 mutants.

**What differs from section 3, corrected in place.**
* **The superblocks are pages 1 and 2 of the page file, not a separate `super` file** (Q7 said a directory with `pages` and `super`). One file means one handle and one `fsync` target, and the superblock is
  protected the same way as every page, by its CRC, and not by a sector's atomicity: a superblock write that tears leaves a page whose CRC does not match, so the other superblock is current. The first page
  handed out is 3.
* **A page write that reaches the last non-zero byte of a superblock is a whole one**, because the rest of a superblock is zeros: a torn write of 100 bytes makes the commit visible and one of 1 byte does not; the
  test says so.
* **The catalog is 16 roots** (slots), not named branches; names come with M3i.
* **A crashed creation is refused, not repaired.** A file that is not empty and holds no valid superblock is refused (`err 102`) rather than read as an empty database, so a flipped bit in the only
  superblock cannot lose a database silently; the catalog page being written and the superblock not leaves exactly such a file, and the operator makes the engine directory again (there is no data in it).
* **The tree does not merge thin pages** and **does not reuse pages**: a delete that empties a leaf drops it, nothing else is rebalanced, and a page no root names is garbage until M3b zeroes and reuses it. The page
  cache is not built (every read is a `pread`).

**What the tests found.** The first versions of both tests passed mutants they should have killed: a tree of 5-byte keys never had an internal split (a page holds 400 of them), and deleting in random order never emptied
a subtree one page at a time. The tests now build a tree of 40,000 100-byte keys (three levels, internal splits) and delete it in key order and in reverse. One mutant is equivalent and is left out, with the reason in
`tests/mutants.py`; another (a short read accepted) is equivalent because the CRC still refuses the page.

## 6c. M3b, built: the sweep; and the delta store moves into the tree (a correction)

**Built:** `pstore.sweep` and the pager's free list. A page is *named* if it is reached from the trees as they are now (committed or not) or from the catalog of **either** superblock on disk (the one before the current is the
fallback for a damaged current one, so its pages stay). Every other page is overwritten with zeros, goes on a free list and is handed out again before the file grows; the sweep ends with an `fsync`. So **what a delete
removed is gone from the file two commits and a sweep later, not before**, which is the rule erasure on the engine (M3i) will follow. A crash in the middle of a sweep leaves pages that nothing names, zeroed or
not: nothing to repair, and the crash test of 6b now runs through sweeps. The sweep reads every page of every tree (it is a mark and sweep, not reference counts): simple, and its cost is the size of the data; it
is run when asked, not at every commit. Checked by `tests/pstore_check.py` (a deleted value's bytes before and after; five 700-byte values filling a page; a file rewritten for 60 commits stays 5 times smaller;
uncommitted work survives; the fallback superblock still works; random scripts against the model; the `fsync` seen with `strace`) and nine more mutants.

**Corrected: the delta store is a tree, not append-only segment files** (D-M3-2 and step 1 of D-M3-3 said segments, synced before the pages). A second file would need its own torn-tail repair and its own order against the
superblock, and erasure would have to rewrite it as the proxy rewrites the statement store today. Kept as one more tree in the page file (keyed by the order number), the deltas are committed by the same
superblock as the data they describe, atomically, with no extra `fsync`; erasure is a put of the scrubbed record and the sweep above. What it costs: a row image must fit a tree value (800 bytes) until overflow
pages exist, which Q9 already says; and history shares the page file with the current state, so "move old segments to cold storage" (design.md) becomes a snapshot question for M4, not a file move. The commit
order is therefore: pages (data and deltas) and catalog, `fsync`, the log record, `fsync` (as today), the superblock, `fsync`; recovery compares the superblock's sequence with the log's tip as D-M3-3 says.

## 6d. M3c, part 1, built: the row, its image and its keys

`src/row.cho`: a table definition (columns, types, key places), the stored row, and the three things made from it: the **image** (`to_jsonb(row)::text`, byte for byte: jsonb's key order of shorter names
first, its `", "` and `": "`, its string escapes, `\\x` hex for `bytea`), the **plain key** (`jsonb_build_array(<key columns>)::text`) and the **stored key** (integers big-endian with the sign bit flipped,
text with a terminator, so that stored keys sort as the key columns do). `tests/row_check.py` puts 1,051 random rows of 40 random tables into PostgreSQL and compares all three; 17 mutants.
Not built yet of M3c: the catalog of tables in a tree and `create table` (the IR's `Ddl` carries only the kind and the table's name, so the column definitions have to come from the parsed statement, not from the
IR: the executor of DDL reads the parser's tree). Stated limits: text is taken as bytes (that it is valid UTF-8 with no NUL is for the executor to check before a row is stored); a row or key that does not fit
its buffer is refused.

## 6e. A correction to D-M3-4, found before the executor is written: the IR is not enough to execute

D-M3-4 says the executor interprets the IR and nothing else. Reading the lowering (`src/lower.cho`) shows three things the IR does not carry, because it was made for effect inference and inference does not need them:

* **The kind of a literal.** `true`, `false`, a number that is not an integer (`1.5`) and a string are all written `Const bytes`: the boolean `true` and the string `'true'` are the same IR, as are `1.5` and
  `'1.5'`. PostgreSQL types them differently (`select 'true' = true` is a boolean comparison because of the other side; `select 1.5 || 'x'` and `select '1.5' || 'x'` differ in how they resolve).
* **A table's columns.** `Ddl` is a kind and a table name. The columns, types, `not null`, `primary key` and `default` of a `create table` are only in the parser's tree.
* **The names of a select's output columns**, which a client is sent before any row.

So the executor takes, beside the IR, **what the lowering knew and did not write**: for each `Const`, in order, its kind (integer, other number, string, `true`, `false`, `null`); for a `create table`, the column
definitions read from the tree; for a select, the output names. They are produced by the same walk that writes the IR (one more output array of the lowering), so the IR stays what the log commits to and the three
verifiers are untouched; the executor refuses a statement whose side information does not match its IR one for one. What this costs: L3b (replaying statements from the log) will need the same information
recorded, or a later IR version that carries literal kinds; that is noted for when bound values are recorded, not solved here.

## 6f. M3d, part 1, built: the expression evaluator, against PostgreSQL

`src/eval.cho` evaluates one IR expression over bound rows to a typed value: comparisons, `AND`/`OR`/`NOT` in three-valued logic, integer arithmetic at the width PostgreSQL uses (`smallint`, `integer`,
`bigint`, with its out-of-range and division-by-zero errors), `LIKE`/`ILIKE` and their negations, `||` on text, `IS [NOT] NULL`, `IN`, `CASE`, `CAST` between integers, booleans and text. The lowering now
notes the kind of each literal beside the IR (6e), and the row format carries the integer width.

**The rule that makes it safe to be incomplete:** the evaluator may *refuse* (`unsupported`), and when it answers, the answer is PostgreSQL's. `tests/eval_check.py` runs random expressions (most well typed, some
not) as `select <e> from t` on both, over twelve rows with nulls and the limits of each integer type, and compares `pg_typeof`, every row's value, or the SQLSTATE. Six seeds of 4,000: **no disagreement**; of the
expressions PostgreSQL answers with values the engine refuses about 9 %. Refused on purpose: numbers that are not integers, `varchar` as a cast target, `LIKE` on `bytea`, a literal beside a non-integer in
arithmetic (PostgreSQL has other operators of those names), `IN` over mixed types or with a failing member, parameters, calls, and **any error computed from constants alone**.

**What the differential found** (each was a wrong answer or a wrong error before it was fixed; none was guessed in advance):
* PostgreSQL reports the **leftmost** type error of an expression, and `CASE`, `AND` and `OR` check that a condition is a boolean before they read what follows it;
* an operator given a **constant NULL** is folded to NULL when the statement is planned, so the other side's division by zero or overflow never happens; a constant `false` decides an `AND` the same way, and a `CASE`
  whose conditions are constants is simplified before any row is read;
* **`- 2147483648` is an `integer`**: the minus sign joins the literal before the literal has a type;
* `x IN (...)` is an array of the members that name no column at one common type, plus separate comparisons of the others, so mixed types change the answer;
* `varchar` is `character varying`, a type of its own; `LIKE` exists on `bytea`; `null - text` resolves to an operator on another type.

## 6g. M3d, part 2, and M3e: the statements (design, written before the code)

**D-M3-8. A branch is one tree.** A key of the tree is a table's number (`u32`) and then the row's stored key (6d); table number 0 is the catalog of tables, whose keys are table names and whose values are a
table's number, its definition (6d), and for each column whether it is `not null` and its default. So a branch is still one root, a fork is still one copied slot, and the sweep (6c) needs to know nothing about
tables. *What this costs:* `drop table` deletes the table's rows one by one (a path of pages written for each), where a tree per table would drop a pointer; a tree per table needs the sweep to follow roots held
inside values, which is not built. A stored key is at most 196 bytes and a stored row at most 800 (the tree's limits): a longer one is refused (`engine-too-big`), never cut.

**A statement is a new root, or nothing.** A statement reads the tree it was given and writes into a copy-on-write descendant; if it fails, its root is dropped and the pages it wrote are garbage for the next
sweep. So an `update` reads the rows as they were before it began (no row is seen twice), and a failed statement changes nothing, with no undo code.

**Which error.** PostgreSQL reports the first error it meets, and what it meets first depends on the order it reads rows in and on how it orders the conditions of a `where` (by estimated cost), neither of which
the engine reproduces. So the engine does not stop at its first error: it finds **every error the statement could raise**, and
* if they all have one SQLSTATE, that is the answer (it is PostgreSQL's whatever its order);
* if they have several, the statement is refused (`engine-ambiguous-error`): PostgreSQL fails too, with one of them.

Three places where whether there is an error at all depends on the order, each refused (`engine-order-dependent`) rather than guessed:
* **a `where` whose conditions are joined by `AND`**: the engine computes every top-level condition for a row. No error: the row is kept if all are true. An error in one and every other one true: an error.
  An error in one and another false or null: PostgreSQL raises or not according to which it computed first;
* **an `update` that changes a key** to the key that another row of the same statement is moving away from (`set id = id + 1`): PostgreSQL fails or not according to which row it writes first. A new key that
  meets a row that stays, or two rows that take one new key, are a certain `23505`;
* **a `limit` or `offset`** on a statement in which some row raises an error: PostgreSQL may stop before reaching it.

An `insert` has an order of its own (its rows as written, each stored before the next is checked), so its first error is exact; errors of its constants come before any row is stored, as PostgreSQL finds them
when it plans.

**Assignment.** A value stored in a column is converted as PostgreSQL's assignment does: a string literal is read as the column's type, an integer into another integer type with a range check (`22003`),
anything into `text`; any other pair is `42804`. Text that is not valid UTF-8 or holds a zero byte is refused.

**`changes`.** Each statement lists what it changed: the table, the plain key, the image before and the image after (6d), a row whose image did not change left out, a changed key as a delete and an insert:
what the capture records for the same statement (`m1-commit-path.md`). The oracle in the tests is PostgreSQL itself, the table read before and after the statement.

**Order.** `order by` compares integers as numbers, booleans false first, text as bytes (D-M3-5), nulls last ascending and first descending unless said. Rows that compare equal come in key order, where
PostgreSQL's order for them is whatever its plan gives: the tests compare such results as sets.

Not in this slice, refused with `engine-unsupported`: aggregates, `group by`, `having`, joins, a table with no primary key or with a `unique` column, `alter table`, indexes, and types outside D-M3-5.

## 6h. M3d, part 2, and M3e, built: what the differential found, and what it costs

`src/tables.cho` (the catalog inside the tree), `src/exec.cho` (what the statements share, and SELECT with `where`, `order by`, `limit`, `offset`, `distinct`), `src/execw.cho` (INSERT, UPDATE, DELETE,
CREATE TABLE, DROP TABLE), `proxy/enginecheck.cho` (the harness: statements on standard input over a page file) and `tests/engine_check.py`.

**The test.** A random history (create and drop table, insert, update, delete, select; many statements wrong on purpose) is run by the engine in two processes with a commit and a sweep between, then by
PostgreSQL 16 statement by statement; a statement the engine refuses is rolled back in PostgreSQL so the two stay in step. Compared: the SQLSTATE of an error; the column types and rows of a select (in
order where the `order by` decides it); the row count of a write and its `changes` against the table read from PostgreSQL before and after. **20 seeds of 2,000 statements: no disagreement**; of the 28,114 statements
PostgreSQL answers the engine refuses 312 (1.1 %). Beside it: 63 fixed statements the engine must *answer* (so that a change which only refuses more cannot pass as "never wrong"), 6 statements whose outcome
in PostgreSQL does depend on its order, each refused as such (below), and the page file read as bytes after a delete and after a drop. 70 mutants of the three files and of the assignment in `src/eval.cho`
are all killed; three more were equivalent and are not listed (a sort that is not stable: equal rows have no order to keep; the assignment calling the conversion as an explicit cast: `assignable` has already
left only the pairs where the two agree; `<>` taken as a bound of a scan: it sets neither end).

**What the differential found** (not guessed in advance):
* **An output column without an alias has a name, and `order by` binds to it first.** `select cast(k as text) from t order by k` orders by the *text*: PostgreSQL names a cast after what is cast and a CASE
  after its ELSE (if that is a column or a call; else after the type, or `case`), and a bare name in `order by` is an output column before it is a table's. The lowering took only written aliases, so the
  engine ordered by the integer; with two output columns of that name PostgreSQL says the name is ambiguous. Fixed in `src/lower.cho` (which changes the IR of such a statement: it now names the expression
  that is ordered by), with 11 hand-written cases and 6 mutants.
* **`null / 0` is null**: a division's error needs both operands, which the evaluator had right and one of the fixed cases had wrong.

**The order dependence is real, and is PostgreSQL's cost model, not the text's order.** With rows stored 3, 2, 1: `where k > 2 and 10 / (k - 2) > 0` and the same conditions written the other way round both
answer without an error (the cheaper condition is computed first wherever it is written); `select 10 / (k - 2) from t order by k limit 1` answers (the limit is reached first); `update t set k = k + 1`
succeeds and `update t set k = k - 1` fails with `23505`. A sixth, `where k = 3 and 10 / (k - 2) > 0`, PostgreSQL answers by looking the key up and never reading the row that would divide by zero. The engine refuses all six, and the test holds PostgreSQL to
exactly these outcomes, so a planner that changes them is noticed.

**Measured** (one process, no `fsync` between statements, a table of an integer key, an integer and a short text; `enginecheck` on this machine):

| | |
|---|---|
| 20,000 inserts, one a statement | 4.1 s (4,900 a second) |
| the page file after them | 192 MiB: 9.8 KiB a row |
| a select with a predicate over the 20,000 rows | 0.67 s (30,000 rows a second) |
| `where k = 77`, and an update of that row, among the 20,000 | 0.2 ms each (a scan before the lookup by key was built: 0.7 s) |
| `where k >= 100 and k < 110` | 0.8 ms |
| an update of every row | 2.7 s; the file grows by 234 MiB |
| a sweep after it | 0.8 s, 108,517 pages (424 MiB) freed |

These are the costs of what is *not built*, and they are large: **every statement copies the path of pages from the root for each row it writes and nothing is reused before a sweep** (so the file is fifty
times the data until one runs); a scan goes down from the root for every row and checks the CRC of each page on the way, with no page cache. They
are M3b's page reuse within a transaction and the page cache of gate 3. Neither changes an answer.

**The lookup and the range scan by key** (`bounds` in `src/exec.cho`). When the key is one column of integers or text and a top-level condition compares it with a constant, a `select`, `update` or
`delete` reads only the keys that condition allows. *This is only done when no condition of the `where` can raise an error* (each is made of columns, constants, comparisons, `AND`, `OR`, `NOT`, `IS NULL`
and `IN`): a row that is not read is a row whose error is not found, and the rule of 6g is that every error is found. So `where k = 77 and a / b > 1` is still a full scan, and says so here rather than
answering by luck; every row that is read is still judged by the whole `where`.

**Not built yet, as before:** the engine's delta tree and the `AS OF` reads over it, transactions over several statements (a statement is its own), the output column names a client is sent, and
everything listed above as refused.

## 6i. M3f: aggregates, `group by`, `having` (design, written before the code)

**What is answered.** `count(*)`, `count(x)`, `sum(x)` over `smallint` and `integer` (a `bigint`), `min(x)` and `max(x)` over the integer types and `text`; `group by` expressions (an integer constant is the
place of an item, as in `order by`); `having`; and `order by`, `distinct`, `limit` over the groups. Refused (`engine-unsupported`): `sum` over `bigint` and `avg` (PostgreSQL's answer is a `numeric`, a type
the engine does not have), any other function, an aggregate inside an aggregate, in a `where` or in a `group by` (errors in PostgreSQL, with rules of their own), `distinct` inside an aggregate.

**How.** The row phase reads the rows the `where` lets through and computes, for each, the `group by` expressions and every aggregate's argument. With no `group by` the aggregates are accumulated as the rows
are read; with one, the rows' group values and arguments are kept, sorted by group, and accumulated run by run (so a grouped query is bounded by what the engine can hold: 262,144 rows, refused beyond). The
group phase then computes `having`, the items and the `order by` expressions once a group, **with no row bound at all**: the evaluator is given *slots*, a value for the expression that starts at a given
place, and each aggregate and each occurrence of a `group by` expression is one. So nothing in the group phase can read a column that is not grouped, by construction.

**The check PostgreSQL makes (`42803`).** Every column an item, the `having` or an `order by` names must be inside an aggregate or inside an expression that is one of the `group by` expressions. The engine
compares expressions as bytes of the IR. A column that is not covered is `42803`, except when the table's key is among the `group by` expressions: PostgreSQL then allows every column (they depend on the
key), and the engine refuses rather than reproduce that rule.

**Errors.** As 6g: every error is found (a row's group expression or aggregate argument is computed for every row the `where` lets through, `having` for every group, the items for every group `having`
keeps), one SQLSTATE is the answer, several are refused, and any error under a `limit` is order-dependent. A `sum` whose running total could leave the `bigint` range in some order of the rows is
order-dependent too (it cannot happen below four thousand million rows of `integer`, and is not tested).

## 6j. M3f, built: what the differential found

The grouped path is in `src/execs.cho` (SELECT moved there from `src/exec.cho`); the evaluator's slots are in `src/eval.cho`. `tests/engine_check.py` now writes grouped selects too (aggregates over
columns and expressions, wrong types, columns that are not grouped, `having`, `order by` places and aggregates, `limit`). **40 seeds of 2,000 statements: no disagreement; of the 53,982 statements PostgreSQL
answers the engine refuses 1,144 (2.1 %).** 88 fixed statements must be answered and are; 10 whose outcome depends on PostgreSQL's order and 9 the engine refuses on purpose are pinned with what PostgreSQL
16 does for each. 105 mutants of the engine, 35 of them of the grouped path and the slots.

**What the differential found** (each a wrong answer, or a claim of an error PostgreSQL does not raise, before it was fixed):
* **A `having` condition with no aggregate in it is not a condition on groups.** PostgreSQL moves it into the `where` and applies it to rows before they are grouped; a `having false` means nothing is read
  at all, not even the `where`. So `select k, sum(10 / (k - 2)) from t group by k having k > 2` never divides by zero, and `select count(*) from t where 10 / (k - 2) > 0 having false` answers no rows. The
  engine, which had computed every row first, said `22012`. It now refuses (`engine-order-dependent`) whenever a row or a group raises an error in a query that has such a condition; with no error the
  answer is the same either way.
* **`select distinct` over items that cannot differ is a `limit 1`.** `select distinct 'x' from t where 10 / (k - 2) > 0` stops at the first row and never reaches the division. An error under `distinct`
  is now order-dependent, as under `limit`.
* **A cast to the column's own type is nothing.** With `k` a `smallint`, `group by cast(k as smallint)` groups by `k`, so `select k ...` is legal (and, `k` being the key, so is every other column).
  The engine compared the bytes of the IR, found `k` outside every `group by` expression and said `42803`. A column under a cast in the `group by` now makes an ungrouped column a refusal, not an error.
* **`group by - 1` is a place** (`42P10`), like `order by - 1`: the minus joins the literal before PostgreSQL asks what it is. Refused.
* And one false alarm, which was the test's: an item can be *named* `k` by a cast or a CASE (6h), and then `order by k` is that item and does not break ties; the generator now writes the table's name
  before the key.

**Two PostgreSQL versions, found by CI.** The gate's first run of the evaluator's differential on GitHub's runner disagreed on one expression, `cast(y as integer)` with `y` a `bytea`: PostgreSQL 16.15
(this machine) has no such cast (`42846`), the runner's newer PostgreSQL has one. The tests said "PostgreSQL 16" and were being run on two versions without saying so. Now each prints the server's version;
a cast between `bytea` and an integer is refused; and what a refused statement does in PostgreSQL (the pinned outcomes above) is held to on version 16 and printed as a note on any other. **The engine
answers only where the versions it is tested on agree**, which is two, not every one.

**Limits of this slice.** A grouped query with a `group by` keeps a record for every row the `where` lets through and sorts them (262,144 rows or 16 MiB, refused beyond); without `group by` the rows are
only counted through. `sum` over `bigint`, `avg`, and every function that is not one of the four aggregates are refused. The overflow of a `sum` is not tested (it needs more rows than the test makes).

## 6k. M3g: joins (design, written before the code)

**What is answered.** `from a, b`, `a join b on ...` and `a left join b on ...`, any number of tables up to eight, each table once (a table joined to itself is refused: the IR names a column by its
table's real name, so two uses of one table cannot be told apart by the engine). Everything a one-table select has (items, `where`, `order by`, `distinct`, `limit`, aggregates, `group by`, `having`) works
over the joined rows.

**How.** A nested loop in the order the tables are written: the first table is read from the tree as before, the others are read once into memory, and each `on` is computed as soon as its table is bound; a
`left join` whose `on` is true for no row of its table binds that table to a row of nulls once. This is the simplest thing that is right; a join of two tables of *n* rows computes *n²* conditions, which
is the cost of having no hash join, and is said here rather than found by a user.

**Errors, and why conditions must be quiet.** PostgreSQL pushes a condition down to the table it speaks of, picks the join order and the join method, and so may compute a condition for a row that joins
with nothing, or never compute it for one that does. Whether a condition that *can* raise an error *does* is therefore the planner's business more than ever. So in a statement with a join **every
condition of the `where` and of every `on` must be one that cannot raise an error** (columns, constants, comparisons, `AND`, `OR`, `NOT`, `IS NULL`, `IN`: the rule of the lookup by key, 6h); any other is
refused (`engine-unsupported`) before a row is read. With quiet conditions the set of joined rows is the same for every plan, and the items are computed for exactly those rows, so their errors are found as
for one table.

**Not in this slice:** `right` and `full` joins, a table joined to itself, `using` and `natural`, the lookup by key under a join, and any join method but the nested loop.

## 6l. M3g, built: what PostgreSQL showed about joins

`rows_next` and `join_load` in `src/execs.cho`, `bind_join` in `src/exec.cho`. The random history now writes selects over two and three tables (commas, `join`, `left join`, conditions between
columns of different tables, grouped and not). **30 seeds of 2,000 statements, with everything since 6h in them: no disagreement; of the 39,686 statements PostgreSQL answers the engine refuses 912
(2.3 %).** 109 fixed statements must be answered; 10 depend on PostgreSQL's order and 16 are refused on purpose, each pinned with PostgreSQL 16's outcome. 120 mutants of the engine, 13 of them of the join.

**The rule of quiet conditions is not caution, it is needed.** With `fw` holding the rows (1, 5) and (9, 0) and `fz` the keys 1 to 3:
* `select fz.k from fz, fw where fz.k = fw.wk and 10 / fw.m > 0` is a **division by zero** in PostgreSQL, and so is the same written with `join ... on ... where`: the condition on `fw` alone is pushed down
  to `fw`, and computed for (9, 0), a row that joins with nothing. A nested loop that asked the `where` of joined rows would have answered `1`;
* `select fz.k from fz join fw on fz.k = fw.wk and 10 / fw.m > fz.k` answers `1`: that condition speaks of both tables, so it is computed for rows that join only.
The engine refuses all three (`engine-unsupported`): which conditions PostgreSQL pushes where is its planner's, and the engine does not model it.

**What the differential found:**
* **An `on` sees only the tables of its own join.** `a join b on c.x = ... join c on ...` and `a, b join c on a.x = ...` are errors in PostgreSQL (`42P01`: the table is joined later, or stands before the
  comma, which binds looser than `join`). The lowering resolved the name against every table of the statement, and the engine joined on a row that was not bound yet. Fixed in `src/lower.cho`: while an
  `on` is lowered the scope is its own join's tables (4 hand-written cases, 3 mutants).
* **Minus signs fold into a constant as PostgreSQL reads it**, so `order by - - 1` is the first item and `group by - - 9` a place that does not exist. A constant under any number of minus signs is now
  refused in both.
* Grouping by the key of a joined table frees that table's columns (the rule of 6i, now for any column in a join: refused rather than decided).

**Cost, said plainly.** A join of tables of *n* and *m* rows computes *n × m* conditions; the tables after the first are held in memory (16 MiB, 262,144 rows, refused beyond); there is no hash join
and no lookup by key under a join. Not built: `right` and `full` joins, a table joined to itself, `using`, `natural`.

## 6m. Gate 2 with statements: a crash at every durable step

M3a's crash test (6b) stops the tree alone. `tests/engine_crash.py` does it to the engine with statements: a history of six commits (creates, multi-row inserts, updates that change keys, deletes, a
dropped table, three sweeps) takes 534 page writes and `fsync`s; it is run 1,068 times, stopped at each step with the write torn at 0 and at 100 bytes, and a new process then reads every table. What it
finds is **always the tables of a commit, and exactly the commit expected**: the last one whose superblock was written whole before the step (each of the seven states is found after some crash). After
every restart a table is created, committed and read back by a third process, and the other tables are unchanged: the file a crash leaves is one that takes writes.

Two things it showed that the page could have got wrong by assertion:
* **A torn write can be a whole write.** A superblock is a few bytes at the head of a page of zeros, so a write of it cut at 100 bytes leaves exactly the page a whole write would: the commit is
  there. The test first held that a torn superblock write always falls back to the commit before, which was false for this layout; it now allows either answer for that one step and no other.
* **A crash while a new file's two superblocks are first written leaves a file that is refused** (3 of the 8 cases: the file is not empty and holds no valid superblock, which must not read as an
  empty database, 6b). It holds nothing, and has to be deleted by hand. That is a rough edge of making a database, not of running one, and it is not smoothed over here.

What this is not: a power failure (a stopped process leaves what it wrote; a machine may lose what was not synced, which is what the order of D-M3-3 is for and what only gate 3's failing `fsync` and a
real power test would show), nor a test of several branches or of the delta tree, which do not exist yet.

## 6n. The history inside the tree (design, written before the code; it settles what 6c left open)

6c moved the delta store into the page file "as a tree". This says which tree, and what a record is.

**D-M3-9. The history is undo entries in the branch's own tree.** Beside the tables (table numbers from 0, D-M3-8) the tree holds, under the number `0xFFFFFFFF`:

    0xFFFFFFFF, then (2^63 - 1 - t) as 8 bytes, then a key K of the tree   ->   what K held before transaction t first wrote it: `0` (nothing), or `1` and the value

where *t* counts the branch's transactions from 1. Every write of a key outside the history (a row, a table's entry in the catalog, the counter of table numbers) first records this, unless transaction
*t* already has an entry for K (the first value is the one before the transaction). What follows from it, each a reason for the choice:

* **`AS OF t` is the tip with the entries after *t* applied**, newest first, which is the order the keys sort in (hence the inverted number): a `put` of the old value or a `del`, onto a root that is
  thrown away afterwards. It is an ordinary tree, so every statement of the engine reads it unchanged, tables that were dropped since included (the catalog is undone like any row);
* **a fork carries its history**: the entries are in the tree a fork copies the root of, shared page for page, at no cost;
* **a commit is atomic with its history**: one root holds the rows and what they were;
* **`changes` is in the tree**, not only in memory: the entries of transaction *t* name every key it wrote and the value before; the value after is the tip's (or the next entry's);
* **erasing a row is deleting its entries** and the row, then the sweep of 6c: no second store to scrub in step with the first.

*What this costs.* A write is three more descents of the tree (is there an entry, what is the old value, store the entry), which roughly doubles the work of a write that is already the slow part
(6h); the history is never trimmed (a retention rule is M4's signed snapshots); an entry's value is the old row plus a byte and its key the row's key plus twelve, so the limits of D-M3-8 fall to **184
bytes for a stored key and 780 for a stored row**; `AS OF` far back writes a page path for every entry it undoes (garbage until the next sweep), where a persistent structure would share: correct first.

**What a transaction is, for now:** each statement that writes is one (the harness numbers them); transactions of several statements, and which transaction a commit of the log is, belong to the proxy's
use of the engine (M3j). Nothing in the entries depends on that.

**Gate.** At random points of the random history of 6h the tables are read; later, `AS OF` each of those points must read the same bytes, also from a new process after a commit, after a sweep, and on
a fork. Erasure and merge are M3i and are not claimed by this.

## 6o. The history, built: AS OF, a fork, an erase; and what the test corrected

`remember`, `put_key`, `del_key`, `as_of`, `last_txn` and `mark_txn` in `src/exec.cho`; `erase` in `src/execw.cho`; `!txn`, `!asof`, `!fork`, `!branch` and `!erase` in the harness.

**AS OF.** A random history of some 300 writes (inserts, updates that move keys, deletes, tables dropped and made again under the same name) is cut at 11 points where every table is read. Later each
point is read again with `!asof`: by another process after a commit; after a sweep and more writes; on a fork that has since been written to (12 points, the fork's own included); and on the branch the
fork was made from, which is byte for byte as it was. All equal, on 16 seeds. A statement that writes while the past is being read is refused (`engine-as-of-write`).

**A fork is a copied root** (`!fork` copies a slot of the catalog): its cost is nothing and its history is the branch's, because the history is in the tree (D-M3-9).

**An erase** (`!erase delete from T where KEY = CONSTANT`) removes the row, with no entry made for its removal, and every entry of its key. Checked on the file's bytes and on what is read: a row that was
updated and a row that was deleted are both still in the file after two commits and a sweep (their past is history, and `AS OF` reads it); after their keys are erased and two commits and a sweep, no
byte of either is in the file, `AS OF` any earlier transaction they are not there, and a third row that was not erased still has its past. An erase with any other `where` is refused.

**This corrects 6h and claim C152**, which said a deleted row is gone from the file two commits and a sweep later. That was true of an engine with no history; with one, *a `delete` is not an erasure*,
which is the product's point and also what the capture does in front of PostgreSQL (`m2g-erasure.md`). The test that held the old claim failed the moment the history was switched on, and now holds the
new one.

**What the erase test found in the design:** the number of a branch's last transaction was read off its newest history entry. Erasing the newest entries made the next statement take a number that had
been used, and `AS OF` that number then read the wrong state. The number is now kept in the tree by itself (under the history's prefix alone, before every entry) and never derived.

**Measured, with the history on** (as 6h: one process, no `fsync` between statements; 6h's own numbers are from before it):

| | before (6h) | with the history |
|---|---|---|
| 20,000 inserts, one a statement | 4.1 s (4,900 a second) | 11.1 s (1,800 a second) |
| the page file after them | 192 MiB | 633 MiB: 32 KiB a row |
| an update of every row | 2.7 s | 6.7 s |
| a sweep after it | 0.8 s | 2.2 s, 281,162 pages (1.1 GiB) freed |
| the tables AS OF 10,000 transactions back, twice | | 7.4 s |

So the history costs what 6n said and more: a single-row insert now writes three paths of pages (the entry, the row, the number) where it wrote one, and none is reused before a sweep. **The engine is
correct and wasteful**; the remedy is the one 6h names (a page written by the statement in progress can be written again in place, since no root names it yet), built next (6p).

**Not built, and not claimed:** transactions of several statements (a statement is one; the rule that a transaction's first value of a key is the one kept is written and has no test, since no statement
writes a key twice); merge; erasing the past of a table that was dropped (the erase finds a table by its name: erase the keys first); a retention rule (the history only grows); the log's commit ids
in place of the harness's transaction numbers (M3j).

## 6p. A statement writes its own pages again in place (built)

6h and 6o measured the waste: every write copied the path of pages from the root, and nothing was reused before a sweep. The remedy, as designed there:

**D-M3-10. A page handed out since the statement began is no root's yet, so it may be written again where it is.** The pager marks the pages it hands out inside a *window* (`pager.begin`, which the
caller opens for each statement); when the tree replaces a page that carries the mark, it writes the new page over it instead of taking another (`new_page` in `src/btree.cho`, which now knows which page
of the path each new page replaces). A page from before the window is never touched: that is still what makes a statement a new root or nothing (6g), `AS OF` a throwaway tree, and a fork free.

*The bargain the caller keeps:* within a window, of the trees it builds from one tree it uses only the newest. The engine's statements already did (each is a chain of roots); `btcheck`, which forks and
reads old roots at will, opens no window and so runs exactly as before, with all its tests.

**Measured** (as 6o; before and after this change, the history on in both):

| | before | now |
|---|---|---|
| 20,000 inserts, one a statement: the file | 633 MiB | 324 MiB (16 KiB a row) |
| the same rows, 100 a statement: the file | | 69 MiB (3.4 KiB a row), 3,800 rows a second |
| an update of every row, one statement: the file grows by | about 470 MiB | 3.7 MiB |
| the crash test's history: page writes and syncs | 1,762 | 928 |

Time is unchanged for single-row statements (1,900 a second): it goes to walking down the tree and checking each page's CRC three times a row, which is the page cache that is still not built. What a
single-row statement still wastes is one path of pages per statement, each superseded by the next statement's: reclaiming those without a sweep means freeing a page as soon as the root that named it is
replaced *and* no committed root names it, which is bookkeeping this slice does not have.

**Beside PostgreSQL, on the same machine and the same statements** (20,000 rows of an integer key, an integer and a short text; PostgreSQL 16.15 over a socket, the engine through its harness with no
`fsync` between statements, which flatters the engine):

| | PostgreSQL | the engine | |
|---|---|---|---|
| 20,000 inserts, one a statement | 1.6 s (12,900 a second) | 9.7 s (2,100 a second) | 6 times slower |
| a select with a predicate on a column that is not the key | 3.5 ms | 645 ms | 180 times slower |
| `count(*), sum(a)` over the table | 1.4 to 20 ms | 632 ms | 30 to 450 times slower |
| an update of every row | 0.09 s | 5.4 s | 60 times slower |
| a row by its key | 0.08 ms | 0.1 to 0.2 ms | about the same |

**So no: the performance problem is not solved** (as measured here; 6t is what was then done about it). What 6p solved is the size of the file. Reading is slow because every row is found by walking down from the root and every page on the way is read
from the file and its CRC checked again: there is no page cache and no cursor that stays on a leaf. Writing is slow for the same reason three times a row (6o). Both are known work (a cache of checked
pages, a scan that moves along the leaves), neither is built, and nothing here should be served to anyone who counts milliseconds until they are.

**Tests.** Everything that ran before runs through it: the random history against PostgreSQL (12 seeds), `AS OF` and the fork (whose untouched branch is exactly the property at risk), and the crash at
every step (928 steps, 1,856 crashes). Four mutants: writing over a page a root names, and keeping the marks of an earlier statement, are each killed by a wrong answer within twenty statements; two
that write a page over the wrong one of the path are killed too. Switching the reuse off is not a wrong answer, so no differential sees it: `tests/engine_crash.py` holds the step count under 1,200 for
that (a version that forgot the leaf's number took 1,422).

## 6t. Speed: a cache of checked pages, a scan that stays on a leaf, a statement's pages written once (built)

6p's table beside PostgreSQL said the engine was 6 to 450 times slower and why. Four changes, each measured, none changing an answer:

1. **A cache of pages in the pager** (8,192 slots, a slot a page number): a page is read from the file and its CRC checked once, then served from memory; a page that is written, zeroed or (by the test
   hook) damaged is dropped from it first.
2. **A scan that stays on a leaf** (`btree.scan_step`): the next row of a scan is the next entry of the leaf already in hand, and the tree is walked from the root only when a leaf is used up.
   (`next_after` is now that function with a leaf it forgets, so there is one account of the walk.)
3. **A statement's own pages are written once.** A page of the open window (D-M3-10: no root names it) is kept in the cache and goes to the file when the window closes or at a `sync`, however many
   times the statement wrote it; if another page wants its slot it is written first. The order of a commit (D-M3-3) is unchanged: everything is in the file before the `fsync` that precedes the superblock.
4. **Nothing above a page written in place is written again**, and the walk down looks at the pages above the leaf where they are in the cache instead of copying them.

**Beside PostgreSQL 16.15 again, same machine, same statements** (the engine still with no `fsync` between statements):

| | PostgreSQL | the engine before (6p) | the engine now |
|---|---|---|---|
| 20,000 inserts, one a statement | 1.6 s | 9.7 s | 3.7 s (5,400 a second): 2.3 times slower |
| the same rows, 100 a statement | | | 1.3 s (15,000 rows a second) |
| a select with a predicate on a column that is not the key | 3.5 ms | 645 ms | 6 ms |
| `count(*), sum(a)` over the table | 1.4 to 20 ms | 632 ms | 7 ms |
| an update of every row | 0.09 s | 5.4 s | 0.97 s: 11 times slower |
| a row by its key | 0.08 ms | 0.1 to 0.2 ms | 0.03 ms |

**So: reading is where PostgreSQL is; writing is not.** A write still walks the tree four times a row (is there a history entry, what is the old value, store the entry, store the row), and each walk copies the
leaf it changes. An update of every row is the worst case of that, and PostgreSQL does it eleven times faster. The file is no smaller than in 6p (a single-row statement still leaves a path of pages
for the sweep). The comparison is also kinder to the engine than it looks: PostgreSQL was durable at every statement and spoke over a socket; the engine did neither.

**Tests.** The random history against PostgreSQL, `AS OF`, the fork, and the tree's own model and crash tests all run through the cache. `tests/engine_crash.py`: the same six commits are now 94 writes
and syncs (they were 928: most pages are written once), each still stopped at and checked. `tests/engine_big.py` is new and is the test of point 3: 30,000 rows rewritten five times after two sweeps
have scattered the free pages, so that pages of one statement compete for slots; the sums a model predicts are read back, now and from a new process and `AS OF` the first load (a cache that dropped
the unwritten page instead of writing it answers `engine-damaged` there, tried by hand). The fixed statements gained a table of several leaves, without which a scan that read one entry past a leaf's
end passed every test. 7 mutants.

## 6u. What PostgreSQL does on a write, read in its source, and what was taken from it (built)

After 6t the engine read as fast as PostgreSQL and wrote 2 to 11 times slower. Instead of guessing further, PostgreSQL's own write path was read (a shallow clone of `postgres/postgres`) and the
engine's was profiled (`valgrind --tool=callgrind`, an update of every row).

**The profile.** About 500,000 instructions a row, 90 % of them in five loops that each walk a whole page: some twelve passes over 4 KiB for every row written (the leaf copied out of the cache, built
again entry by entry, its tail zeroed, copied back; twice, for the row and for its history entry; and two lookups that copied a leaf each).

**PostgreSQL, for the same write** (files in its tree):

| PostgreSQL | the engine after 6t |
|---|---|
| changes the page where it is in the buffer pool: pin, change, `MarkBufferDirty` (`heapam.c`, `heap_insert`; `bufmgr.c`) | copied the leaf out, rebuilt it, copied it back |
| a page is slotted: an insert moves a few line pointers and appends the tuple (`bufpage.c`, `PageAddItemExtended`) | rebuilt every entry of the leaf |
| looks a key up by binary search over the line pointers (`nbtsearch.c`, `_bt_binsrch`) | walks the entries, which have no index |
| remembers the last leaf and skips the walk down when the next key belongs there (`nbtinsert.c`, `_bt_search_insert`) | walked from the root four times a row |
| the old version of a row stays on its page (`README.HOT`); nothing else is touched and nothing is looked up | looked up whether it had an entry, looked up the old value, and inserted an entry elsewhere in the tree |
| is durable by a record of the change in a log written in order; pages are written later (`xlog.c`) | writes whole pages at every commit |

**Taken from it:**
1. **A leaf that is the statement's own is changed where it is in the cache** (`put_in_place`, `del_in_place` in `src/btree.cho`; `pager.own`): the entries after the one written are moved, and nothing else.
   It is open only for a page of the open window that is already marked to be written (D-M3-10), so no page a root names is ever touched; anything else, and an entry that does not fit, takes the way
   that was there before.
2. **What is known is not looked up.** An update and a delete have the old row in hand, and an insert has just found the key absent: the history entry is written from that (`remember_known`), without
   the two walks. This rests on a transaction being one statement in which no key is written twice; a transaction of several statements takes the old way (`set_once`), which is the tested one for
   the catalog and for rows that change key.
3. **A lookup reads the leaf where it is** (`leaf_get`), copying only the value.

**Measured**, as before, PostgreSQL 16.15 beside it:

| | PostgreSQL | after 6t | now |
|---|---|---|---|
| an update of every row (20,000) | 0.09 s | 0.97 s | 0.14 s |
| a delete of half the rows | | | 0.12 s |
| 20,000 inserts, one a statement | 1.6 s | 3.7 s | 2.4 s (8,200 a second) |
| the same rows, 100 a statement | | 1.3 s | 0.73 s (27,000 rows a second) |

**So a statement that writes many rows is now within a factor of two of PostgreSQL; a statement that writes one row is not**, and its cost is no longer in the tree: each such statement copies a path of
pages once (it owns none when it starts) and writes them all at the end. That is the last row of the table above, and it is a decision of this design (D-M3-3: the tree is the durable state, there is
no log of changes), not something a faster loop removes.

**Not taken, and why.** *Slotted pages and binary search:* a change of the page format; the profile no longer points there first. *The last leaf remembered:* worth doing for loads in key order.
*A log of changes with pages written later:* the one thing that would make a single-row commit cost a hundred bytes instead of sixteen thousand, and shrink the file; it turns D-M3-3 round and
touches every crash test, so it is to be designed on this page before any code, not slipped in as a speed-up.

**Tests.** The same as 6t, all through the new paths (the random history on 10 seeds, the crash at every step, statements larger than the cache, the tree's model). 8 mutants of the three changes are
killed. Two were not and are not listed, each because the code allows less than the mutant tests: `pager.own` asks that the page is of the open window, and a page marked to be written always is;
and a first version of `own` marked a clean page itself, a branch no test reached (it needs sixteen thousand pages written by one statement), so that branch was removed rather than left untested.

## 6q. M3h: `alter table ... add column`, `create index`, `drop index` (design, written before the code)

The parser's closed DDL is `create table`, `alter table T add [column] <column>`, `drop table`, `create [unique] index N on T (columns)` and `drop index N` (`src/stmt.cho`). What the engine does with
the three it does not yet run:

**`alter table T add column C ...`.** The table's definition gains the column and **every row is written again with the column's default, or null** (a path of pages a row, less since 6p). PostgreSQL
does not rewrite (it remembers the default beside the definition); the answers are the same, the cost is not, and the cost is said. As PostgreSQL: a column that is `not null` with no default is an error
(`23502`) if the table has a row and is taken if it has none; a default is checked as for `create table`; a name the table has is `42701`; `primary key` on the new column is `42P16` for a table that
has a key, which every table of the engine does. The history keeps each row's old form and the old definition, so `AS OF` before the statement reads the table as it was, columns and all.

**`create index`.** An index that is not `unique` changes no answer: the engine records its name (so that `drop index` and a second `create index` of the same name answer as PostgreSQL does: `42P07`)
and builds nothing. That is honest only because the engine claims no speed: when it has indexes to read by, this is where they are built. **A `unique` index is refused** (`engine-unsupported`): it is a
constraint, and holding it needs the index that is not built.

**`drop index N`.** Removes the name; a name that is not an index is refused by the lowering (the snapshot it reads lists the indexes: `index N on T`), as now in front of PostgreSQL.

**Where the names go.** The catalog (table number 0) gains keys of the form `0x00000000, 0x01, <index name>` whose value is the table's name: a table's name cannot begin with the byte 1, so the two
kinds of key do not collide, and `drop table` removes its table's indexes with it (as PostgreSQL does).

**Gate.** The random history of 6h gains these statements; answers and the tables afterwards equal PostgreSQL's; `AS OF` across an `add column` reads the old shape.

## 6r. M3h, built

`alter_add`, `create_index` and `drop_index` in `src/execw.cho` (the column definitions of `create table` and of `add column` are read by one function); index names in the catalog
(`tables.index_key`), listed for the lowering as `index N on T`. The random history writes them (columns added with and without defaults, taken or refused; indexes made, made twice, dropped). **8
seeds of 3,000 statements with everything since 6h: no disagreement**; 132 fixed statements answered; `AS OF` before an `add column` reads the table in its old shape (the history test adds columns
too); 14 mutants, the engine's group now 152.

As designed in 6q, with nothing found to correct: an `add column` writes every row again; an index that is not `unique` is a name and nothing more, and a `unique` one is refused. What PostgreSQL does
and the engine now matches: a `not null` column with no default (or a default of null) is `23502` on a table with rows and taken on an empty one; a second primary key is `42P16`; an index and a table
share one space of names (`42P07` either way); `drop table` takes the table's indexes with it.

## 6s. M3j: what stands between this engine and a client (design; none of it is built)

Everything above is the engine and a harness that reads statements from a pipe. Nothing a client connects to uses it. This section is the path from one to the other, written as slices with the gate
of each, so that what is missing is a list and not an impression.

**J1. The answer as a client sees it.** A select's answer has column *names* (PostgreSQL's rules for a column without an alias, of which the lowering knows the `order by` part, 6h), type identifiers,
and values as text (`t`/`f`, digits, bytes as they are; the wire's binary format is refused). An error is a SQLSTATE *and* a message; the engine has the first. A command has a tag (`INSERT 0 3`).
*Gate:* the bytes after the proxy's framing equal PostgreSQL's for the random history, names and tags included; messages are compared by SQLSTATE only, and the page says so.
*Built of it: the names.* `lower.output_names` writes, for a select, the name of each output column: an alias, or the one PostgreSQL makes up (a column's, a function's, a cast's type as the catalog
spells it, `case`, `?column?`), a `*` giving its tables' columns. `tests/engine_check.py` now compares them with the names in PostgreSQL's row description for every select of the random history (8 seeds
of 3,000 statements, aliases included: no disagreement; 6 mutants). The values as text and the tags followed (6v); the messages are not built.

**J2. Transactions.** `begin`, `commit`, `rollback`: a transaction is a root of its own that the statements of one connection build on, published or dropped at the end. The history's rule for a key
written twice in a transaction (6n) is then exercised for the first time. One writer at a time: a second connection's write waits or is refused; which, and what a reader sees meanwhile (the last
published root: snapshot isolation for free), is decided there. *Gate:* the random history cut into transactions of random length, with rollbacks, against PostgreSQL at `read committed` run one
connection at a time; interleavings are a separate test with its own model.

**J3. Parameters and the extended protocol.** `Parse`/`Bind`/`Execute` with `$n`: the evaluator refuses a parameter today. The types PostgreSQL infers for parameters are a rule of their own.
*Gate:* `tests/ext_e2e.py`'s statements, against the engine.

**J4. The facts of a commit.** The log's `changes` and `state` are hashes over facts: the table, the key, the salted hash of the image before and after, a salted commitment to the key
(`spec/state.md`, `spec/l3a.md` section 9). The engine has the images (the history's entries and the tip); it has no salts. They go beside the values they blind: one for a key, one for each version of a
row, made when the row is written, **erased with it** (which is the point of them, `m2g-erasure.md`). The engine's `changes` for a transaction is then computed from its entries.
*Gate:* the three L3a verifiers accept a log whose facts the engine made, with `--delta` exported from the engine's history; and for the same statements the engine's facts equal the capture's but
for the salts (the images are already equal, C150).

**J5. The shadow run.** The proxy, serving from PostgreSQL as now, also gives each statement to the engine and compares: the answer (J1) and, at commit, the facts' images. A statement the engine
refuses ends the comparison for that database (PostgreSQL ran a write the engine did not), and the proxy says so and goes on. Nothing the engine does can change what a client is sent.
*Gate 5 of section 5:* a workload runs for long enough to matter with no disagreement; the measure is how much of it the engine answered.

**J6. Serving.** A database option: statements are answered by the engine, PostgreSQL is not there. Needs J1 to J4, `cancho_fork`, `cancho_merge` and `cancho_erase` as functions of SQL over the engine's
own fork, history and erase (6o), and a merge, which does not exist. *Gate:* the proxy's end-to-end suites (`proxy_e2e`, `fork_e2e`, `asof_e2e`, `merge_e2e`, `erase_e2e`, `l3a_e2e`) with the engine in
PostgreSQL's place, for the statements the engine takes.

**J7. What clients ask beside their statements** (M4's "catalog emulation"): drivers read `pg_catalog` at connect, set session parameters, and ask for the server's version. None of it is in the
subset. Until it is, only clients that send what `psql -c` sends can be served.

*An honest size:* J1 and J2 are each about what a slice above was; J3 and J4 more; J5 and J6 are integration, where the tests get slow and the surprises are in the proxy, not the engine; J7 is open-ended.
M3's exit ("the differential suite passes on the declared subset; crash and fsync-fault tests pass") is met for the engine as a library but for the failing `fsync`; it is not met for anything a client
can reach, and M4's ("one cancho product runs on it in daily use") cannot be met from inside this repository at all.

## 6v. J1 and J2, built: the answer as a client is sent it, and transactions

**J1.** `src/answer.cho`: a column's type as PostgreSQL's identifier, a value as PostgreSQL's text (`t` and `f`, digits with a sign, text as it is, `\x` and hexadecimal for `bytea`, nothing for a null), and
a command's tag (`INSERT 0 3`, `SELECT 2`, `CREATE TABLE`). The harness prints those and `tests/engine_check.py` compares them with **the bytes of PostgreSQL's own messages**: the tag with its
`CommandComplete`, the identifiers and names with its `RowDescription`, each value with its `DataRow`. The test used to turn the engine's values into PostgreSQL's text itself; that translation is now the
engine's and is what is tested. An error is still a SQLSTATE without a message.

**J2.** `begin`, `commit`, `rollback`. A transaction is a tree of its own that its statements build on, one after another; `commit` makes it the branch's and gives the whole transaction one number in
the history, `rollback` drops it. What PostgreSQL does and the engine now matches, each found or confirmed by the differential:
* a statement that fails, fails the transaction: every statement after it is `25P02` until the transaction is ended, and its `commit` answers `ROLLBACK`;
* `begin` inside a transaction is taken (PostgreSQL warns), **but in a transaction that has failed it is `25P02` like anything else** (the first version answered `BEGIN`; the differential found it);
* `commit` and `rollback` outside a transaction are taken;
* DDL is part of a transaction: a table made in one that is rolled back was never made.
After every statement the state PostgreSQL reports to a client (`I`, `T`, `E`) is compared with the engine's.

**A refusal inside a transaction fails the transaction**, as an error does. There is nothing else it could honestly do: the statement did not run, and the statements after it were written for a state
in which it had. (The test then fails PostgreSQL's transaction too, so the two stay in step.)

**The history's rule for a key written twice** (6n: what a key held *before the transaction* is its one record) was written and untested while a transaction was one statement. It is exercised now:
the history test writes transactions of several statements on the same rows, some rolled back, and `AS OF` before each reads what was there. Inside a transaction the writer no longer trusts what it
knows about a key (6u, point 2) and looks, as designed.

**20 seeds of 3,000 statements with transactions in them: no disagreement** (the engine refuses 880 of the 37,627 statements PostgreSQL answers, 2.3 %); 172 fixed statements answered, 28 of them a
script of transactions; 179 mutants of the engine, 10 of them new (the text of a value, the tags, the identifiers, the two history rules).

**Not built:** one writer at a time is all there is (two connections with transactions open at once do not exist in the harness: that is the proxy's to arrange, J5); isolation levels and savepoints
are refused by the parser; an error's message.

## 6w. The first user: `cancho-hooks`, and what it asks for

All the `cancho-*` repositories were read for what they store in PostgreSQL. Four talk to it at all; one fits. `cancho-hooks` (the webhook delivery service) keeps three tables and sixteen
queries (`sql/schema.sql`, `sql/queries.sql` there), **every column of which is a type the engine has** (`bigint`, `integer`, `smallint`, `text`, `boolean`; its times are integers), its database is optional
and is not its source of truth (its log files are), and it is a product somebody runs, which is what M4's exit asks for. The others: `cancho-ota` (seventeen migrations: `timestamptz`, regular
expressions in checks, foreign keys that cascade), `cancho-web` (an example with a `json` column), `cancho-sheets` (a browser *of* PostgreSQL).

So the order of work from here is hooks' sixteen queries, and the measure is how many of them the engine answers as PostgreSQL does. What they need that was not built when this was written:

| | queries that need it |
|---|---|
| parameters (`$1`, `$1::bigint`) | all 16 |
| `returning` | 6 |
| `coalesce`, `greatest` | 4 |
| a subquery (a scalar one, a `count(*)` guard, `ctid in (select ...)`) | 3 |
| `on conflict do nothing` | 2 |
| sequences (`nextval`, `setval`), an identity column | 2, and one table |
| a `with` whose body is a `delete ... returning` | 1 |
| a primary key of several columns; `check`; `if not exists`; a partial index | the schema |

**Parameters first (design).** A parameter is, to PostgreSQL's analysis, what a string literal is: a value of no type yet, which takes its type from what it meets (the other side of a comparison, a
cast, the column it is stored in), and whose text is then read as that type. So the evaluator gives a `Param` node the text bound to it as a literal of unknown type, or a null, and everything already
built for literals applies: `$1::bigint`, `where k = $1`, `values ($1, $2)`, `limit $1`. A parameter also makes the lookup by key (6h) possible, since `k = $1` compares the key with a constant.
*The oracle:* PostgreSQL's extended protocol (`Parse` with no types given, `Bind` with text values), which is what `cancho-pg` sends.

**Built, and where the design was wrong.** "What a string literal is" was false in three ways, each found by the differential within its first 2,500 statements and each now a refusal:

1. *A parameter has one type in a statement, a literal has one at each place it is written.* PostgreSQL gives a parameter the type of its first use and reads the later uses as that type
   (`n > $1 or s = $1` is an error where two literals would not be). The engine reads each use alone, so it answers only where that cannot differ: a parameter used once, or one whose every use
   carries the same cast (`$1::bigint`, which is how hooks writes all of its repeated ones). `$1 between a and b` is two uses (it is `$1 >= a and $1 <= b`), and so is `$1 in (...)`.
2. *A parameter that meets no type is an error (42P18), where a literal is read as text*: `$1 is null`. The evaluator marks a parameter's value until something gives it a type (a comparison
   with a typed value, a cast, the column it is stored in, `||` beside text, `limit`) and refuses a node that leaves one unmet. This refuses more than PostgreSQL does (`$1 = $2`, which
   PostgreSQL reads as two texts).
3. *The statement must name every parameter that is bound, and no other*, and a statement that is not a query takes none.

One rule of literals was wrong too and is corrected with it: in `x in (...)` a string (or a parameter) among integers of several widths is read by PostgreSQL at a width the engine did not
reproduce (out of range at one, in range at another); that is refused now.

An error in reading a parameter's text (`'abc'` bound where an integer is stored) is answered as the error it is, as for a literal.

**Measured.** 20 seeds of 3,000 statements against PostgreSQL 16.15, three in ten of the queries with some of their literals made parameters (bare or cast, now and then one used twice, a null,
text that is no number), sent by the extended protocol: no disagreement; of 13,355 statements with parameters the engine answers 7,140 (rows, changes or the error). 29 fixed statements with
parameters must be answered, 9 are pinned as refused with PostgreSQL's own outcome beside them. 13 mutants, all killed (one survived until a grouped query with text parameters was added: the
arena's start); the engine's group is 192.

**The checklist** (`tests/hooks_check.py`; `tests/hooks/` holds hooks' own `schema.sql` and `queries.sql`). The schema, then 54 calls of the sixteen queries with values, on PostgreSQL and on
the engine; after each call the answers are compared and so is every table. When this was written: **0 of 15 schema statements, 0 of 16 queries**. Six queries are refused only because their
table is not there (`attempts_of`, `endpoints_all`, `schedule_by_id`, `schedules_all`, `schedules_due`, `advance_schedule`), so the schema comes next, before `returning`: a key of several
columns, `if not exists`, `check`, an identity column, a sequence, an index with a condition, and `alter column ... type` to the type it has.

## 6x. The schema of hooks (built; the identity column is 6y, the sequence is not built)

Fifteen statements (`tests/hooks/schema.sql`), none answered when 6w was written, and six of the sixteen queries wait only for their tables. What the statements need, and what each is in the engine:

| in the schema | in the engine | refused |
|---|---|---|
| `create table if not exists`, `create index if not exists`, `add column if not exists` | if the name is there, nothing changes and the answer is the statement's own tag (PostgreSQL adds a notice, which is not an answer) | - (*corrected:* the design refused a definition that would have raised an error had the name not been there. PostgreSQL's source says when it looks: for a table and a column, never, the name is tested first; for an index, the condition and the columns are read first and their errors raised, `src/backend/commands/indexcmds.c`. The engine does the same, and the differential found the index's order before the source was read) |
| `primary key (endpoint, event, replay, attempt)` | the place of each column in the key, which the stored definition and the stored key have had since M3c (src/row.cho): only the statement was missing | - |
| `check (id between 0 and 999999)` on a column | a range: two integers kept with the column's marks in the catalog; a row written with a value outside it (a null is inside) is error 23514 | every other check: not a `between` of the column itself and two integer literals, or a column that is not an integer |
| `alter table attempts alter column endpoint type bigint` | nothing, if that is the column's type | any change of type |
| `create index schedules_due on schedules (next_fire) where enabled` | an index is a name (6l); the condition is taken if it is a boolean column of the table | any other condition |
| `bigint generated always as identity`, `create sequence` | *the next slice*: a counter that a failed statement and a rollback do not take back, which is not what the tree does with anything else | - |

**Not for the proxy.** The guard (src/guard.cho) reads statements with the same parser, and what it lets through goes to PostgreSQL with the proxy's promises about it. None of these forms was
examined for that (an identity column makes an insert's row something the statement does not say). So the parser marks a statement that uses any of them (`st[12]`), and the guard refuses it as
before (`unsupported-statement`); only the engine's harness reads past the mark. *Test:* the guard's own tests, and one case for each form.

**Errors.** 23514 joins the errors of a row (not null 23502, the key 23505): several different ones in a statement are `engine-ambiguous-error`, as everywhere.

**Tests.** The random history gets tables with a key of two or three columns, columns with a range, and the `if not exists` forms (so that the skip and the create are both met); the fixed
statements pin each form; the checklist's schema count goes from 0 to 14 (the sequence stays), and the six queries that waited for tables are answered if parameters (6w) were enough for them.

**Built.** The grammar is in src/stmt.cho, the catalog's marks carry the range (src/tables.cho), a row is tested where its nulls are (src/execw.cho). `tests/hooks_check.py`: **12 of the 15
schema statements** (what is left: the identity column of `schedules`, the sequence, and the index on the table that was not made) and **2 of the 16 queries** (`attempts_of`, `endpoints_all`;
the four others that waited for a table wait for `schedules`). The test's floors are now those numbers.

*Measured:* 20 seeds of 3,000 statements against PostgreSQL 16.15 with three tables in ten keyed by two columns (in either order, the key written for the table), ranges on integer columns,
the `if not exists` forms on names that are and are not there, indexes with a condition, changes of type: no disagreement. 61 fixed statements pin the forms, 8 are refused on purpose with
PostgreSQL's outcome beside them. The guard refuses each form (9 cases). 27 mutants (20 of the engine, 7 of the mark and the guard), all killed; 13 older mutants were moved to the code as it
is now.

*Found on the way, and not new:* `insert into t values (...)` with fewer values than the table has columns is refused as `syntax`, where PostgreSQL fills the rest with defaults. It is a
refusal, so it is safe; the tag is wrong and the statement is common. Not fixed here.

## 6y. An identity column: the one thing a rollback does not take back

`id bigint generated always as identity` is how `schedules` gets its ids, and four of hooks' queries waited for that table.

**What PostgreSQL does.** An identity column is a sequence. Each row an insert reaches draws the next value, before the row is tested: a row that fails its constraints has drawn, and so has
every row before it; the rows after it have not. A value drawn is drawn for good: the statement failing does not give it back, and neither does the transaction being rolled back. A value
cannot be given to the column, in an insert or an update (428C9).

**Why that is a problem here, and the design.** Everything else in the engine is in the tree, and a statement that fails, or a transaction that is rolled back, leaves the tree it started
from (that is the whole of their implementation). A counter kept in the tree would be given back. So:

- the counter is in the tree (the catalog: `0x00000000 0x02` and the table's number, the last value drawn), where a commit keeps it, a fork copies it and a crash leaves it as of a commit;
- every draw is *also* noted outside the tree (`exec.seq_note`), and whoever drives the statements writes the notes into the tree that stays when the tree that has them is thrown away
  (`exec.seq_replay`: after a statement that failed, at a rollback), or drops them (`seq_forget`) when it is the one that stays;
- an insert that fails before any row is stored (an error of a constant, which PostgreSQL raises when it plans) has drawn nothing; one that fails at row r has drawn r + 1 values;
- the counter is no part of the history: `AS OF` reads, and never draws.

*Refused:* a value given to the column (428C9 is not reproduced), an identity column added to a table (each row there would draw), a second one in a table, one that is not an integer.
*A limit of the fork:* a branch has its own counter from the fork on, so two branches give the same ids; a merge of such rows is M4's.

**Built and measured.** 20 seeds of 3,000 statements against PostgreSQL 16.15, three tables in ten with an identity column (whose values show what every insert drew, the failed and the
rolled-back ones too): no disagreement. 41 fixed statements (failures at the first, a middle and no row; rollbacks; a table made and rolled back and made again). In the test a statement
the engine refuses is run by PostgreSQL and taken back *with its sequences set back* (`take_back`), since PostgreSQL would otherwise have drawn where the engine did nothing. 11 mutants.
`tests/hooks_check.py`: **14 of 15 schema statements** (the sequence is left) and **6 of 16 queries**.

## 6z. `on conflict do nothing`; and a wrong answer the new values found

**`insert ... on conflict do nothing`** (no target; hooks writes it on both its inserts, so that a repeat is harmless). A row whose key is there, or was stored by an earlier row of the same
statement, is left out and is no error; its nulls and its ranges are tested first all the same, as PostgreSQL tests them before it looks for the conflict; a row that is left out has still
drawn from an identity column. The tag counts the rows stored. A conflict with a target (`on conflict (k) do ...`) and `do update` are refused by the parser, as before. One of the engine's
forms: the guard refuses it. 13 fixed statements; two in ten of the random inserts carry it; 20 seeds, no disagreement; 3 mutants. `tests/hooks_check.py`: **8 of 16 queries**.

**A wrong answer, there since M3d.** With more kinds of text in the tables (the parameters' values, 6w) the differential met `cast(b as integer)` where `b` is `'3000000000 7abc'`: the engine
said 22P02 (not a number), PostgreSQL 22003 (out of range). PostgreSQL reads the digits first and stops with "out of range" as soon as they pass what the type holds, before it sees what
follows them. The evaluator read the whole text and then judged it. *Corrected by refusing:* digits and then something else is answered (22P02) only when the digits are fewer than five, which
is in range of every integer type; for more it depends on the type and on how PostgreSQL's reader is written, and nothing is answered. Pinned both ways (3 refused with PostgreSQL's outcome
beside them, 5 fixed), 2 mutants. The claim that was false for these texts was C149 ("when the evaluator answers, its answer is PostgreSQL's"): its twelve test rows held no such text. It is true again by saying less, and says so.

## 6aa. `returning`

Six of hooks' queries end in `returning id` (or a list of columns): it is how the service learns that an update or a delete found its row.

**Design.** The items of a `returning` are a select list over the statement's table, read for each row the statement stored (insert, update: the row as it now is, whether or not the update
changed it) or removed (delete). So the parser builds, beside the statement, a `select <items> from <the table>` (the same nodes a SELECT has), and the engine runs that SELECT:

1. *before the statement, over no rows*: its types, its column names, and what is wrong with them. A wrong item is PostgreSQL's error before anything is written or drawn from a counter;
2. the statement, which keeps each row it stores or removes (`exec.ret_row`);
3. *after it, over the rows it kept* instead of over the table.

Nothing of the SELECT was written again for this: the row source is the only thing that differs (`exec.scan_next`).

*Refused:* an item that can raise an error for a row (arithmetic, a cast, `||`): PostgreSQL raises it at that row, with the rows before it written and their identity values drawn, and
here the statement has run whole by then. The items must be "quiet" in the sense of 6k (columns, constants, comparisons, `and`/`or`/`not`, `is null`, `in`). An aggregate is refused too.
*Order:* PostgreSQL returns the rows in the order it wrote them, which for an update or a delete is the order it found them; nobody is promised that order, and the test compares the rows
as a set.

**The guard's tags.** A statement of the proxy that has a `returning` or an `on conflict` was refused with those words as its tag. The mark of 6x would have made both
`unsupported-statement`; the mark now carries the refusal the guard gives (`engine_form` in src/stmt.cho: the first form's, which is what the parser said before it could read on), so the
proxy answers these exactly as it did. `proxy/stmtcheck.cho` and `proxy/lowercheck.cho`, which test the proxy's grammar, refuse the engine's forms the same way.

**Built and measured.** 20 seeds of 3,000 statements against PostgreSQL 16.15 with `returning` on two in ten of the random inserts, updates and deletes: no disagreement on the rows returned
(as a set), their names and their types, nor on the changes. 26 fixed statements (with identity columns, `on conflict`, parameters, a key that an update moves), 4 pinned refusals; 5 mutants
of the engine and 2 of the mark (a sixth, of the refusal of an aggregate, was of a test the test before it already made: removed with the test). `tests/hooks_check.py`: **10 of 16 queries** (`patch_address`, `delete_schedule`).

**What is left of the sixteen**, and what each needs: `patch_endpoint`, `patch_schedule` (`coalesce`, `greatest`, and a `case` over parameters); `prune_attempts` (`ctid in (select ...
limit)`: a row's place has no meaning here, and this one is better rewritten in hooks by key); `create_endpoint`, `create_schedule` (`insert ... select` with a scalar subquery);
`delete_endpoint` (a `with` whose body is a `delete ... returning`); and the sequence (`nextval`, `setval`) that two of those use.

## 6ab. `coalesce`, `greatest`, `least`

Hooks' two patch queries are `set c = coalesce($n::type, c)` throughout: "change this column if a value was given". The three are reserved words that PostgreSQL's grammar reads as
expressions of their own, not as functions; the parser refused them as reserved words.

**Design.** The parser reads the three as calls when a `(` follows (a column of such a name stays refused). They are no engine-only form: they have no effect of their own, the lowering
writes them as the `Call` it writes for any function, and the proxy lets them through as it does `upper(x)`. The evaluator computes them:

- the type is the one type of the arguments, as for the branches of a `case` (integers widen, a literal or a parameter takes it, all literals are text);
- `coalesce`: the first argument that is not null, and PostgreSQL does not compute the ones after it, so an error in a later argument is no error (the evaluator computes every node and
  carries an error as a value, which is how `case` already skips what PostgreSQL skips);
- `greatest`, `least`: every argument is computed in order, nulls are left out, the answer is null only if all are;
- *refused:* a constant argument that is an error (`coalesce(c, 1 / 0)`, `coalesce(c, 'abc')` for an integer): PostgreSQL raises it when it plans, or does not reach it, depending on
  what stands before it. (Nothing was written for this: the evaluator already refuses a constant that is an error wherever it is made. Two tests written for it here tested nothing,
  as their mutants showed, and were removed; the refusals are pinned.)

In a grouped select the three are ordinary nodes over the aggregates' values (`coalesce(max(a), 0)`), not aggregates.

**Built, and what the differential corrected.** Two rules were missing from the design, and each was a wrong answer until the random history met it:

1. *`coalesce` of a constant is that constant, to the planner.* PostgreSQL drops the constant nulls and, if what is then first is a constant, takes it as the whole expression and never
   looks at the rest: `coalesce(null, 3000000000, x)` is `3000000000`, and `x = - coalesce(...)` into a smaller column is error 22003 when the statement is planned, whatever the rows
   (the engine answered `UPDATE 0`). A parameter is a constant in the same way. The evaluator now marks the result a constant by that rule.
2. *An aggregate under an operator that folds to null is never computed.* `max(1 % c) - $1` with a null parameter is null to the planner (the operator is strict), so the aggregate is
   gone and its division by zero with it; the engine computed it and answered the error. This was there since the grouped select was written (6i) and needed a null constant beside an
   aggregate to show. Refused now: a grouped expression that comes out a constant and has an aggregate in it.

*Measured:* the evaluator's differential on four seeds of 4,000 expressions with the three functions in them, no disagreement; 20 seeds of 3,000 statements, no disagreement; 22 fixed
statements, 7 pinned refusals; 7 mutants (5 of the functions, 1 of the folded aggregate, 1 of the parser). `tests/hooks_check.py`: **12 of 16 queries** (`patch_endpoint`, `patch_schedule`).

**For the proxy** the three are new statements it lets through (they were refused as reserved words): the hand-written parser cases pin them, and `nullif`, which is not built, stays refused.

## 6ac. A scalar subquery, and `insert ... select` with no table

`create_schedule` in hooks is `insert into schedules (...) select $1::text, ... where (select count(*) from schedules) < 64 returning ...`: one row, if there are fewer than 64.

**The subquery (design).** `(select ...)` where a value is expected, with nothing of the statement around it in it, is computed once by PostgreSQL and is then a value. The engine does
the same *before* the statement, and in the statement's text: the driver finds the subquery, runs it as the SELECT it is, and puts a parameter with a cast in its place
(`($3::bigint) < 64`), bound to the value's text. Nothing of the parser, the lowering or the IR changes, and the proxy refuses a subquery as before.

- The value is no constant to PostgreSQL's planner (it is known when the statement runs, not when it is planned), so the evaluator does not treat such a parameter as one: an error made
  of it is an error of a row, not of the statement.
- PostgreSQL computes the subquery only if it is reached; the engine always. So a subquery that raises an error, or is refused, or has more than one row, refuses the statement.
- A subquery that names a column of the statement around it is not this (it is computed for each row): its SELECT does not lower alone, and the statement is refused.

**`insert ... select` with no `from` (design).** It is one row of expressions with a condition: the parser reads it as the `values` row it is, and keeps the condition beside the
statement as a SELECT of it (as `returning` keeps its items, 6aa); the engine computes the condition first, over nothing, and stores the row or no row. An engine form (the proxy keeps
its `insert-select` refusal). `insert ... select ... from` stays refused.

**Built, and what the differential corrected.**

1. *A subquery in a list of output columns gives its column its name*, and not only when it is the whole item: under a cast (`cast((select count(*) ...) as text)` is named `count`) and
   as the `else` of a `case`. The parameter in its place would name it otherwise. Refused: any subquery among the items of a SELECT that is the statement, or of a `returning`.
2. *What is wrong with the condition comes before what is wrong with the row*: PostgreSQL reads the SELECT, its `where` included, before it fits the items to the table's columns. The
   condition is computed first.
3. *"No constant" was half right.* An error made of a subquery's value in an assignment is a row's (`update ... set n = cast((select ...) as bigint) where` no row: no error; pinned).
   But a condition with no column in it is computed once before any row, so there the error is raised whatever the rows. The engine refuses that case as it refuses every error whose
   moment it does not know (`engine-order-dependent`); pinned with PostgreSQL's 22P02 beside it.

*Where the code is, and what that means:* finding the subqueries and writing the statement again is done by the program that drives the engine (`prepare` in proxy/enginecheck.cho), as
transactions are (6v). It is tested by everything below and has **no mutants of its own**: the mutant runner changes src/ only. It moves into src/ with the serving of clients (J6).
(*No longer so: it is `src/drive.cho`, with 13 mutants, 6ae.*)

*Measured:* 20 seeds of 3,000 statements with scalar subqueries among the integer operands (of this table or another, some with several rows, some of a column of the statement around
them) and a quarter of the one-row inserts written as `insert ... select` with a condition: no disagreement. 22 fixed statements, 16 pinned refusals; 6 mutants (4 of the engine, 2 of
the parser), 5 statement cases and 4 guard cases. `tests/hooks_check.py`: **13 of 16 queries** (`create_schedule`), and the four `schedules` queries that were answered over an empty
table are now answered over the rows it makes.

## 6ad. A sequence, where its value is drawn once for certain

`create_endpoint` in hooks takes its id from `greatest(nextval('endpoint_ids'), coalesce((select max(id) from endpoints), -1) + 1)`: a sequence, so that an id is never given twice,
and the largest id there is, so that one somebody inserted by hand is skipped.

**Design.** A sequence is the counter of 6y under a name of its own: `create sequence [if not exists] name [minvalue n] [start [with] n]` (a name among the tables' and the indexes';
a number from the tables' numbers; the counter holds the value given next, which is never below 0; no other option, no negative number, no `drop`). A value drawn is drawn for good,
by the same notes.

`nextval` is a function with an effect, and the evaluator computes an expression more than once (before the rows, for its types, and for each row). So it is not the evaluator that
draws. The driver puts the value the sequence gives next in the place of `nextval('name')` in the statement's text (a parameter, as for a subquery, 6ac), and the insert whose row holds
it makes the draw the sequence's at the moment an identity column's is: when the row is reached. That is right only where PostgreSQL computes the `nextval` once for certain, so it is
answered only there: **in an insert, once, in its first row, as the first thing after `select`, `values (`, `greatest(` or `least(`, with no `case` in the statement and no condition
on the row.** (*Changed in 6ae: anywhere in the first row, with nothing before it that may leave it uncomputed.*) Everywhere else it is refused, as before (`nondeterministic`).

`setval`, `currval`, `drop sequence`, and a sequence's other options are not built.

**Built, and what the differential corrected.** The first 20 seeds had six that disagreed, all one mistake: a `nextval` in a later row of a `values` was taken, and PostgreSQL never
reaches that row if an earlier one fails (the engine had drawn, PostgreSQL had not). Two rules came of it: the first row only; and an error that is raised before any row is stored,
in a statement that draws, is not answered (PostgreSQL raises it before the draw if it is a constant's, after it if it is made of the value drawn, and the engine does not tell
the two apart there). The second rule holds for an identity column beside a subquery's value too, where it had been wrong since 6ac.

*Measured:* 40 seeds of 3,000 statements with sequences made (with and without `minvalue`, `start`, `if not exists`, under names that are taken) and drawn from in the random
inserts: no disagreement; every value equals PostgreSQL's, through rows that fail and transactions that are rolled back. 32 fixed statements, 13 pinned refusals; 12 mutants (11 of
the engine, 1 of the parser's mark), 5 statement cases, 2 guard cases. As for a subquery, the part that finds `nextval` in the text is in the test's driver and has no mutants
(*until 6ae*).
`tests/hooks_check.py`: **the whole schema, 15 of 15, and 14 of 16 queries** (`create_endpoint`).

**The two that are left, and why they are not built.**

- `delete_endpoint` is `with gone as (delete ... returning id) select id, setval('endpoint_ids', greatest(nextval('endpoint_ids'), id), true) from gone`: it moves the sequence past
  the id that was deleted, so that the id is not given again. It needs a `with` over a statement that writes, and `setval`. Since `create_endpoint` already takes the larger of the
  sequence and the largest id there is, the only id this protects is the largest one, deleted. On the engine an id is never given twice if the sequence is simply never set back,
  and `delete from endpoints where id = $1 returning id` is answered today.
- `prune_attempts` is `delete from attempts where ctid in (select ctid from attempts where at_ms < $1 limit $2)`: "delete some `$2` of the old rows". Which rows is PostgreSQL's
  choice (the order they lie in its file), and `ctid` is a place in that file. The engine has no such place and will not invent one. By key it can be said without either:
  the oldest `$2` rows, `order by at_ms, endpoint, event, replay, attempt limit $2`, which needs a subquery of several columns and rows.

Both are for hooks to decide (a different statement each), not for the engine to imitate.

## 6ae. The text pass is the engine's, and tested as it is

6ac and 6ad left a part of the engine in the program that tests it: finding a subquery or a `nextval` in a statement's text and writing the statement again. It answered statements, so a
mistake in it is a wrong answer, and no mutant could reach it. It is now `src/drive.cho` (`prepare`), built into the test program as every other module is, and its rules have mutants.

Writing the mutants changed the rules, which is what they are for:

- **A rule that tested nothing.** `nextval` was taken only as the first thing after `select`, `values (`, `greatest(` or `least(`. Its mutant lived: the other rules already refuse
  every case it was written for. It is gone, and a `nextval` anywhere in the first row is answered (an error raised before the row is stored is refused, 6ad, so its place among the
  row's items cannot matter).
- **A rule that was missing.** `coalesce(56, greatest(nextval('s'), 1))` passed the rule above and PostgreSQL never computes that `nextval`; the engine would have drawn. No test met
  it. Now: nothing before the `nextval` that may leave what follows uncomputed (`case`, `coalesce`, `and`, `or`, `in`).
- **A rule that was double.** A subquery that is a whole item after a comma was refused twice; once is kept (a subquery among output columns, 6ac).

13 mutants: of a subquery with several rows, with several columns, one that fails, one after `in`, one among output columns, one of no row; of a `nextval` in a later row, under a
`case`, after a `coalesce`, a second one, one outside an insert, the value drawn; and of the parameters a statement must name. 40 seeds of 3,000 statements, no disagreement; 8 more
pinned refusals.

*What is still the test program's:* transactions (which tree a statement runs on, 6v) and the writing back of counters after a failure (6y). They are a dozen lines each and go to
src/ with the session that will hold them (J6).

## 6af. J4, first part: the facts of a commit, from the engine

A commit in the log says what it changed as `changes`, a hash over its **facts** (`docs/spec/state.md`): for each row the commit changed, net, the table, the key, and the hash of
the row's image before and after, in the order of `(table, key)`. Behind PostgreSQL a trigger collects them. The engine has to make them itself, and this is the first of it.

**Design.** A statement already keeps, for each row it writes, the table, the plain key and the two images (they are what `tests/engine_check.py` compares with PostgreSQL's
rows, C150). At the end of a statement that succeeded the driver folds them into the facts of the transaction (`exec.facts_take`): a tree of its own in the page file, keyed by the
table, a zero byte and the plain key, which is the order the facts are in, holding for each row the hash of its image *when the transaction first touched it* and *as it is now*. A row
touched again keeps the first and takes the new second; one that ends as it began (inserted and deleted; updated back) is no fact. At commit `exec.facts_changes` walks the tree and
computes `changes` exactly as the specification says, with src/state.cho, the code the proxy and the verifiers use.

**This is version 1 of the facts**: the key as it is, and the row's hash without a salt. The log's second version (salted hashes and a commitment to the key, so that a row can be
erased and the log still verify, `docs/spec/l3a.md` section 9) needs a salt kept beside each version of a row and destroyed with it. That is a change to what the tree stores and is
the second part; nothing here decides it.

**Test.** `tools/state.py` and `tools/l3a.py` are the project's own second implementation of facts, their netting and `changes`, written for the verifiers. The differential feeds them
what **PostgreSQL's** tables show each statement changed (the key and the images before and after, read from PostgreSQL), netted over each transaction, and holds the hash against the
one the engine prints at each commit. So the engine's `changes` is checked against rows it did not produce and code it does not share.

*Not in this part:* a commit (its parents, its `state`, its signature; 6ah), the store the verifiers read, DDL in a transaction with writes (the test skips those commits), a key over
183 bytes with its table's name (the facts are then refused, and the commit says so: `F -`).

**Built.** `exec.facts_take` and `exec.facts_changes` (src/exec.cho); the test program prints `F <count> <changes>` for each commit that changed rows. 20 seeds of 3,000 statements:
the engine's `changes` equals the reference's for every commit compared, statements of their own and transactions of several. 30 fixed statements for the netting (a row inserted
and updated, updated and put back, inserted and deleted, deleted and inserted again, a key of two columns, two tables in one transaction, a rollback). 7 mutants.

*What the test program still did itself:* it decided when a transaction's facts begin and end (as it decided which tree a transaction runs on, 6v). Those lines had no mutants *(they are `src/session.cho` since 6aj, with mutants)*.

## 6ag. J4, second part: salts, so that what is erased cannot be guessed back

The facts of 6af commit to a row by the hash of its image and to its key in clear. A row that is erased leaves those in every commit it was part of, and an image that can be
guessed (a name from a list, a PIN) is then found by hashing guesses (`docs/m2g-erasure.md`, C135). The log's second version blinds both: a row's hash is over a 16-byte **salt**
and the image, the fact's key is a **commitment** over the key's own salt and the key, and erasing destroys the salts with the row (`docs/spec/l3a.md` section 9).

**Design.** The salts live where the row lives, so that whatever removes the row removes them:

- a row's value in its table's tree is `key salt (16) || row salt (16) || row`. The key's salt is made when the row is inserted and stays while the row is there; the row's salt is
  made anew by every write that changes the row. A row put back under a key that was deleted is a new row with a new key salt, as in the capture (`sql/capture.sql`);
- the history keeps the value a key held, salts included, so `AS OF` and a fork carry them, and `erase` (6o), which removes the row and every entry of its history, removes every
  salt it ever had. Nothing else holds one;
- an update that leaves the row as it was writes nothing and makes no salt (it is no fact); one that moves a row to another key is a delete and an insert;
- the facts of a transaction (6af) are keyed by the table and the **commitment**, and hash each image with its salt.

*Where salts come from.* cancho has no source of randomness, and a salt that could be computed again would not be destroyed by erasing it. The driver reads 32 bytes from the
system (`/dev/urandom`) when it starts and gives them to the engine, which makes each salt as the first 16 bytes of `SHA-256(seed || counter)`. The seed is never stored; it is gone
with the process. A statement that writes with no seed given is refused (`engine-no-entropy`).

*The cost.* 32 bytes a row, so the longest row is 748 bytes where it was 780. **A page file written before this change is not readable after it** (a row's first 32 bytes would be
taken for salts): nothing was promised about page files, and none exists outside a test.

*Not decided here (decided in 6ai, which corrects this: the rewrite did leave the log unable to verify, and a column added now gives each row a new salt and a fact):* `alter table ... add column` rewrites every row with its salts as they were and no fact, which is what PostgreSQL's capture does too (no trigger fires), and
leaves the next fact of each row starting from an image the log never committed to. That is a question for the log (what a change of definition is, there), not for the salts.

**Test.** For every change the engine reports the three salts beside the key and the images. The differential (a) already holds the key and the images against PostgreSQL's; (b) now
computes the commitment and the two hashes from those and the salts **in Python, from the formulas of the specification**, nets them by commitment and holds the engine's `changes`
against `tools/state.py`'s; (c) follows every row through the whole history: the salt a write says the row had must be the one the write before it gave, a key's salt must stay
while the row is there, and no salt is ever given twice. (c) runs across the two processes of the test, so it is the stored salts that are followed.

**Built.** src/exec.cho (`row_put`, `row_del`, the salts read in `scan_next`), src/facts.cho (the commitment and the salted hashes), the joins' own reading of rows (src/execs.cho,
which the first run of the test found: every join was `engine-damaged`). 20 seeds of 3,000 statements: (a), (b) and (c) hold for every change and every commit compared. The
erasure test now follows the salts into the page file: after a key is erased, two commits and a sweep, **none of the salts it ever had (its key's, each version's) is in the file**,
and those of the row beside it are. With no seed a statement that writes a row is refused, and one that reads, deletes or leaves a row as it is is not. 12 mutants.

*A rule of 6af that salts made empty:* "a row that ends as it began is no fact". Every change gives the row a new salt, so within a transaction its two hashes never agree; the
test for it could not be made to fail and is gone with its mutant. (A row inserted and deleted in one transaction is still no fact.) The reference nets the same way, by commitment.

*Version 1 of the facts (6af) is replaced, not kept beside:* the engine makes the salted form only.

## 6ah. J4, third part: a commit from the engine, read by the verifiers

6af and 6ag give a commit's facts. A commit is more: its parent, its number, its `state`, its effects, a signature (`docs/spec/commit.md`). This part makes the record, so that the
verifiers that were written for the proxy's log read one the engine made.

**Design.**

- *The head of the log lives in the branch's tree.* The catalog key `0x00000000 0x04` holds the number of the branch's last commit, its id and its `state`. `facts.seal` reads it,
  makes the next commit and writes the new head into the same tree the transaction's rows are in, so the page file's commit (`pstore.commit`) makes both durable or neither, and a
  process that starts later goes on from where the file is. No commit yet: the first has number 0 and no parent.
- *The commit is made of what the engine already has, with the code the proxy uses* (`build.encode`, `build.id`, `build.sign`, `state.state`): `changes` from the facts (6af),
  `state` from the parent's `state` and `changes`, one **write** effect for each table the transaction wrote. A transaction whose changes net to nothing (a row inserted and
  deleted) still wrote: `facts.take` notes each table it sees under the key of the table alone, and the effects are made of those notes, not of the facts. *(Changed in 6au: a commit's
  effects are those of its statements, and the notes are gone.)*
- *What the record does not say yet is said as nothing*, not invented: the schema hash, the token and the principal are zeros, there are no statement ids, the time is 0, the
  branch is always `main`. Each is a field the proxy fills from things the engine's driver does not have yet (a login, the lowered statements kept, a clock).
- *The signing key* is given to the test program on a line (`!log` and the seed in hex). Where a server keeps its key is not decided here.

**Test** (`tests/engine_log.py`; no PostgreSQL). The engine runs fixed statements and a random history in two processes over one page file and prints a record for each commit
that changed rows, and for each statement what it changed (as since 6af). The test only moves bytes: the records into a log; each change into a line of the version-2 delta store
under the commit whose record came next (the commitment and the two hashes of a line computed in Python from the specification's formulas; the engine prints none of them); every
row of every table at the end, with its salts, into a live dump. Then `tools/verify.py` must accept the log (chain, numbers, signatures) and **the three L3a verifiers**
(`tools/l3a.py`, `build/l3averify`, `tests/third/l3a_third.py`) must each say `ok ... final`: every commit's `changes` is the hash of the facts of its lines, every `state`
follows, and replaying the facts from nothing gives exactly the rows the engine holds. And what must not pass: a line of the store removed (`changes-mismatch`), an image changed
(`facts-image`), a row missing from the dump or changed in it (`replay-final`), a record cut out of the log.

*Not in this part, and pinned by the test as the refusals they are:*

- *(corrected in 6ai)* as first built, **a column added** rewrote every row's image with no fact, so the next change of such a row was `replay-precondition`, and **a table
  dropped** took its rows with no fact, so the end was `replay-final`; the test pinned both refusals. 6ai makes each a change of rows, and the pins are gone;
- commits on a fork (no record is made off the first branch), the erasure of a row from the store (the store here is the test's, made of what the engine printed), statements
  that change no row (DDL, a sequence's value) which are in no commit;
- **the log is not written by the engine.** The test program prints records and the test keeps them. A crash after a record was given out and before the page file's commit
  leaves a record the file does not know; a server has to write the log and the page file in an order, and recover to the file's head. Not designed here.

**Built.** `facts.seal`, the table notes in `facts.take`, `tables.head_key`; `!log` and `!rows` in the test program. Measured: 12 seeds of 2,000 random statements (885 to 1,039
commits and 3,018 to 4,332 changes each) and the fixed history: the log and all three verifiers `ok ... final`, every tampered file refused with its rule. 12 mutants, each
killed by a verifier's own rule (`seq-gap`, `parent-count`, `bad-signature`, `state-mismatch`, `store-foreign-row`) or by a record the engine could no longer make.

*Found after this was pushed, and corrected:* `tests/engine_crash.py` failed in about half its runs (6 of 12 here). It learns from one whole run at which durable step each commit
ends and then stops other runs at every step; with the table notes in the facts' tree, a commit's facts no longer fit one page for its larger statements, and the tree, keyed
by commitments, takes its pages in an order the salts decide. Two runs with different seeds wrote different pages at the same step number. The property the test checks (the
tables after a crash are those of the last commit) was never violated; its bookkeeping was. The test program takes a seed on a line (`!seed`) and the crash test gives every run
the same one: 12 of 12 runs pass.

## 6ai. A column added and a table dropped are changes of rows

6ah found that a log of the engine did not verify once a table had a column added (every row's image changes, and no fact said so) or was dropped (its rows are gone, and no
fact said so). PostgreSQL's capture has the same hole: no row trigger fires for either. The engine does not need to inherit it.

**Design.** Both are what they do to rows:

- `alter table ... add column` writes every row of the table again with the new column's value. That is an update of each row: its key salt stays, **its row salt is new**,
  and the statement reports the change from the image under the old definition to the image under the new one (`exec.change_def`), which is a fact of the commit. (6ag kept the
  salts as they were; that is corrected there.) A consequence: with no seed to make salts of, a column added to a table that has rows is refused (`engine-no-entropy`);
- `drop table` reports each row it removes as a row deleted.

A table made again under a dropped one's name has other rows: new key salts, so other commitments. Nothing changes for a table with no rows, for `add column if not exists` of
a column that is there, or for an index.

*The cost* is the one an update of every row has: a fact a row, the 16 MiB a statement's changes may take (beyond it the statement is refused, as an update is).

*Not in this part:* the definition itself. The log now tells every change of every row, so a replay ends at the rows there are; it does not say that a column was added or what
its type is (a commit's schema hash is still zeros, 6ah).

**Test.** The differential (`tests/engine_check.py`) treats both statements as writes: PostgreSQL's table is read before and after (`to_jsonb` of each row; after a drop, no
rows), and the engine's reported changes must be exactly the difference, with the salts following each row's history and the commit's `changes` equal to the reference's over
them, inside transactions too (a transaction with DDL in it was skipped by the facts' comparison before; it is not any more). `tests/engine_log.py` has both in its fixed
history and its random one (a column added to the random table, the table dropped and made again), and the three verifiers must still say `ok ... final`.

## 6aj. The session is the engine's, and tested as it is

Since 6v the test program decided which tree a statement runs on and when a transaction's tree becomes the branch's; since 6af when the facts of a commit begin and end; since
6ah when a commit is sealed. Each of those sections ended with the same sentence: *those lines have no mutants*. They were about 130 lines of the test program, and a server
would have had to write them again.

**Design.** `src/session.cho` holds a session's state (idle, in a transaction, in one that has failed; the transaction's tree; its facts) and two functions the driver calls
around every statement:

- `open`: the tree the statement runs on (the branch's, or the open transaction's), the number its writes take, whether a key written twice keeps its first record (6n);
- `close`: given what running the statement gave (a tree, or that it was `begin`, `commit` or `rollback`) and whether it failed. Outside a transaction a statement that wrote
  is a commit: its facts are taken, its number marked, the commit sealed. Inside one the statement's tree becomes the transaction's and its facts are folded into the
  transaction's; `commit` marks, seals and hands the tree to the branch; `rollback`, or the `commit` of a transaction that failed, gives back what was drawn from counters (6y)
  and nothing else. It leaves what the driver answers with: the command, the facts to show, the record.

The driver keeps what is its own: reading a statement, running it (`run_sql`), writing answers. The test program is that driver, and is 102 lines shorter.

*Not moved:* a branch other than the first, `AS OF` a point, and erasing are still chosen by the test program's own commands; the seed of the salts and the signing key are
still handed over by it. A server will have to decide where each comes from.

**Test.** Nothing new is claimed: every test that ran through the test program's lines runs through `session` (the differential's transactions, C165; the facts, C175; the
log, C177). What is new is that a fault in those decisions is now caught: 20 mutants in `src/session.cho` judged by the differential and 1 by the log's verifiers.

## 6ak. Running a statement is the engine's too

After 6ae (the text pass) and 6aj (the session), what the test program still did itself was the middle: read a statement, lower it, decide which of the engine's functions runs
it (a SELECT, a write, a write with RETURNING and its two reads, a table made or dropped, a sequence, an erase), and turn what came back into "answered", "an error with this
code" or "refused with this tag". 250 lines, none with a mutant, and all of it what a server does for every message.

**Design.** `drive.run` (`src/drive.cho`) does that for one statement over one tree and leaves how it went in a `Run`: the outcome (answered; refused where it was read, where
it was lowered, or by the engine, each with its tag; an error with its SQLSTATE; or `begin`, `commit`, `rollback`, which are the session's to answer), the statement's kind,
whether the answer has rows, and the names of its columns. The rows and the changes stay where they were (`exec`). The driver's part is what is left: the bytes in and the
bytes out. The test program writes the answer as lines for a test to read; a server will write PostgreSQL's messages from the same `Run` (`src/answer.cho`, C164).

*One check was found dead and removed.* The test program refused a statement that is not a query if it had parameters bound. With the check gone, every such statement is
still refused: a parameter in a default or in a sequence's start is refused where the statement is lowered or read (`unknown-construct`, `syntax`), one in an index's
condition by the index (`engine-unsupported`), one bound and not named by `params_fit`. The test now pins those tags, so the day a form of DDL takes a parameter it is seen.

**Test.** As for 6aj, nothing new is claimed and every test runs through the moved code. 13 mutants in `drive.run`; they needed two new cases: a sequence made on a tree
read `AS OF` (refused), and the exact tag of a refusal at each stage (the lexer's, the parser's, the lowering's, the engine's).

*The test program is now 874 lines where it was 1,155 before 6aj.* What it still decides: which branch, which point `AS OF`, when to commit the page file, and the lines
of its own protocol.

## 6al. A server: PostgreSQL's protocol in front of the engine, first part

Until here the engine was reached by a test program that reads lines. This is the first program a PostgreSQL client can connect to with no PostgreSQL behind it.

**Scope of this part, deliberately small:** one connection at a time, the simple query protocol, no authentication, no log written. Each of the four is its own later part and
is listed below as what it is.

**Design.** `build/engine PAGEFILE PORT` (`proxy/engine.cho`) listens on a port and serves one connection to its end, then the next.

- *Who may connect.* A client from this machine (the loopback addresses), as for the proxy; any other is closed unread. **There is no login**: a startup message is answered
  `AuthenticationOk` whatever user it names. The proxy's token login (`src/login.cho`) is the next part; until then the server is for a test and a developer's own machine.
- *Startup.* An `SSLRequest` or `GSSENCRequest` is answered `N` (no TLS: loopback only). A startup of protocol 3.0 is answered `AuthenticationOk`, the parameters a client
  reads (`server_version`, `server_encoding` and `client_encoding` `UTF8`, `DateStyle`, `integer_datetimes`, `standard_conforming_strings`), `BackendKeyData` and
  `ReadyForQuery`. A cancel request is closed: nothing runs long enough to cancel.
- *A query* (`Q`) is one statement. The server does what the test program does and nothing else: `session.open`, `drive.prepare`, `drive.run`, `session.close` (6ae, 6aj,
  6ak). The answer is written from the `Run` and the rows where they are: `RowDescription` (each column's name and type; no table or column number, the engine has none to
  give that a client could use), a `DataRow` per row in text, `CommandComplete` with the tag (C164); or `ErrorResponse` with the SQLSTATE the engine gave; then
  `ReadyForQuery` with the session's state (`I`, `T`, `E`). An empty query is `EmptyQueryResponse`.
- *A refusal is an error a client can tell from PostgreSQL's:* SQLSTATE `0A000` (feature not supported) and the message `cancho-db: refused <tag>`, the tag being the rule
  that refused. In a transaction it fails the transaction, as any error does (6v).
- *Durable before acknowledged.* When a statement left a commit (a statement of its own that wrote, or `commit`), the page file is committed (`pstore.commit`: the write and
  the `fsync` of the superblock) **before** `CommandComplete` is sent. If that fails the client is told `58030` and the server stops; it does not go on over a file it could
  not write.
- *A connection that ends inside a transaction* rolls it back.
- *The extended protocol* (`Parse`, `Bind`, ...) is refused, properly: one `ErrorResponse` (`0A000`, `extended-protocol`), everything up to `Sync` skipped, `ReadyForQuery`
  at `Sync`. `Terminate` ends the connection. Any other message type, a length under 4 or over 16 MiB ends the connection with an error: there is no way to find the next
  message after it. *(Corrected in 6aq: a message is at most 1 MiB, and a longer one is refused and read past; only a length under 4 and an unknown type end the connection.)*

`src/wire.cho` holds the messages (pure: bytes into a buffer), so that they have mutants; the program holds the socket.

*Not in this part:* **the extended protocol**, which is what `cancho-pg` and so `cancho-hooks` speak for every statement with a parameter (the engine already runs those,
6w; the server cannot be sent them yet). **The log**: the server commits the page file and writes no log, so nothing it does can be verified yet (6ah made the records; where
they are written, and in what order with the page file, is not designed). **Authentication. More than one connection** (a second client waits until the first is gone).
`AS OF`, forks and erasure, which the test program reaches by its own commands and SQL has no form for yet.

**Test** (`tests/engine_wire.py`; no PostgreSQL). The oracle is the test program, whose answers are held against PostgreSQL's for the same statements (C150, C164): a history
from the differential's own generator is run through the test program and, over a socket, through the server; for every statement the two must agree on the outcome (the
tag and count, or the SQLSTATE, or the refusal's tag), the column names and type oids, every row's text, and the transaction's state. Then the server is stopped and the
test program opens **the server's page file**: every table must hold what the test program's own file holds. And: the server is killed (`SIGKILL`) after an acknowledged
commit and the rows are there on restart; a connection dropped inside a transaction leaves nothing of it; `psql` (a client this project did not write) runs a script
against it and against PostgreSQL and must print the same (skipped, and said so, where no PostgreSQL is at hand; the gate has one); the extended protocol is refused and
the connection goes on; garbage (random bytes, a huge length, a half message and a close) never stops the server.

**Built.** `src/wire.cho` (the messages), `src/serve.cho` (one connection: startup, a statement at a time, the commit before the answer, the rollback at the end),
`proxy/engine.cho` (the listener and the page file; 192 lines). Measured, 3 seeds: 2,031 statements each (570 fixed, 1,461 random) answered by the server as by the test
program (for seed 1: 722 commands, 555 answers with rows, 449 errors, 305 refusals), and the server's page file read by the test program as its own, 20 tables. A run takes
17 to 22 s here, every write committed to the disk before its answer (500 single-row inserts: about 0.5 s on this machine's disk, which is a sandbox's). `psql` 16 prints the same 54 lines for a script of 15 statements against the server and against
PostgreSQL 16.15. 54 kinds of garbage; the server answers the next connection after each.

*Found while testing, and corrected:*

- the design said a client that sends more than its startup before it is answered is closed. It was closed without a word, and nothing is wrong with such a client: what
  follows the startup is now kept and read as the messages it is;
- a connection that ended inside a transaction was rolled back twice over (the session was also reset when the next connection began), and the reset hid that the rollback
  could fail unseen. The reset is gone; a rollback that cannot be done stops the server rather than hand one client's transaction to the next;
- **a select of one row took 44 ms.** The first version wrote the row's description to the socket, then the row, then the end: three small writes, and the second waits
  for the client to acknowledge the first (500 selects: 22 s; 500 inserts, whose answer is one message: 0.5 s). The differential did not see it, because it asks nothing
  about time. An answer is now written in as few writes as the buffer allows (500 selects: 0.07 s; an answer of 30,000 rows and 2.4 MB, larger than the buffer, arrives whole
  in 0.05 s), and the test has both the large answer and a floor for the speed. Turning off the socket's delay as well changed nothing measurable, so it is not done;
- what the test did not see until a mutant survived: a message arriving in two pieces, a value drawn from a counter in a transaction the connection took with it (it stays
  drawn), the server closing its side at `Terminate`, a second refused batch of the extended protocol, and that the server says why (`08P01`) before it closes on a message
  it cannot read past.

31 mutants (16 of the messages, 15 of the connection), each built into a server of its own and judged by this test.

*What the test cannot reach:* the page file failing under the server (`58030` and the stop): there is no way to make it fail from outside. The crash test (C156) covers the
page file's own behaviour at every step; the server's two lines around it are read, not run.

## 6am. The server, second part: the extended protocol, as `cancho-pg` speaks it

`cancho-pg` (`src/pg.cho`, read at its commit of this date) sends four shapes, and `cancho-hooks` reaches the database through three of them:

| | what is sent | what PostgreSQL answers |
|---|---|---|
| a statement with values (`execute`) | `Parse` (unnamed, no types), `Bind` (text), `Describe` the portal, `Execute`, `Sync` | `1 2 T D.. C Z`, or `1 2 n C Z` with no rows |
| prepare under a name (`parse_named`) | `Parse` (named), `Sync` | `1 Z` |
| run a prepared one (`bind_named`) | `Bind` (text), `Execute`, `Sync` | `2 D.. C Z` |
| ask what a statement takes and gives (`describe`) | `Parse`, `Describe` the statement, `Sync` | `1 t T Z` |

The engine already runs a statement with values bound as text and no types given (6w, C166): that is exactly what the first and third send. So this part is the protocol
around it, not the engine.

**Design.**

- *`Parse`* keeps the statement's text under its name (the unnamed one is replaced by the next; a name twice is `42P05`) and reads none of it: **what PostgreSQL finds at
  `Parse`** (a syntax error, a table that is not there, a type that does not fit) **the engine finds when it runs the statement, and says then.** A client that prepares
  its statements when it connects, to learn early that one is wrong, learns it at the first use instead. (The text pass of 6ae rewrites some statements before they are
  read, with the values in hand; reading the text at `Parse` would refuse statements the engine runs.) Parameter types given by the client are refused unless they are all
  0 ("infer"), which is what `cancho-pg` sends.
- *`Bind`* keeps the values (text only: a binary format is refused; at most 64 values and 64 KiB, the engine's limit of 6w) for the unnamed portal (a named portal is
  refused). A statement that was never prepared is `26000`.
- *`Describe` of the portal* sends nothing yet: the columns are known when the statement has run. *`Execute`* runs it, through the same code a simple query goes through
  (`session`, `drive`), and then sends the description if one was asked for (`RowDescription`, or `NoData` for a command with no rows), the rows, and `CommandComplete`.
  **For a statement that succeeds the bytes are in PostgreSQL's order** (the description and the rows are next to each other either way). For one that fails at run
  time, PostgreSQL has already sent the description and the engine has not; a client that reads to `ReadyForQuery`, as `cancho-pg` does, sees the error either way. A client
  that asks for the description and waits for it before `Execute` (a `Flush` between them) would wait for ever, so that `Flush` is refused (`describe-before-execute`).
- *One `Execute` to a `Sync` outside a transaction.* PostgreSQL runs everything up to a `Sync` as one transaction; the engine commits each statement. So a second
  `Execute` before the `Sync` is refused (`pipeline`) unless a transaction is open, rather than answered with a different meaning.
- *`Execute` with a row limit* is refused (`row-limit`: a portal is not kept half read). *`Describe` of a statement* is refused (`describe-statement`): the types of the
  parameters are not known before values are bound (6w). That is the fourth shape, which `cancho-pg`'s generator of typed code uses at build time; it needs a PostgreSQL.
- *`Close`* forgets a statement or the portal. *`Sync`* answers `ReadyForQuery` and ends what an error started: after any error everything up to the `Sync` is skipped, as
  the protocol says.
- A simple query drops the unnamed statement and the portal, as in PostgreSQL.
- *Answers leave when the server next waits for the client*, not message by message: the five answers to a batch are one write (6al found what three writes cost).

A connection holds at most 64 named statements and 1 MiB of their text *(3 MiB as first built; 6aq gives each of 16 connections its own)*, and a statement prepared is at
most 1 MiB; more is refused (`53200`, `54000`), not truncated.

**Test** (`tests/engine_wire.py`). The differential now sends the generator's statements with parameters (about a third of the writes and reads) by the first shape, and
holds the answer against the test program's for the same statement and values, and the order of the messages against the table above. Then: statements prepared by name
and run by name several times with other values, against the test program; a name twice, a name never prepared, a statement closed and prepared again; each refusal above
with its tag; an error in a batch skips to the `Sync` and the next batch is answered; a transaction opened by a simple `begin` and written to by prepared statements.
And **`cancho-pg` itself**: a program written with it (its own example, built from its repository beside this one) logs in to the server, creates a table, writes and reads
with parameters, and prints what it prints against PostgreSQL. That step needs the repository and is skipped, and says so, where it is not there.

**Built.** The handlers in `src/serve.cho` (`parse_message`, `bind_message`, `describe_message`, `execute_message`, `close_message`; `answer` is the one path a simple query
and an `Execute` both take), four readers in `src/wire.cho`. Measured, 3 seeds: 2,070 statements each, 360 to 369 of them with parameters by the extended protocol, answered
by the server as by the test program, the messages in the order of the table above. `cancho-pg`'s example client (`examples/psql.cho` at its commit `2068e4e`, built here)
prints the same 34 lines for 13 statements (inserts, selects, an update and a delete with values bound, `returning`, a null, a value with a quote and a semicolon in it, a
duplicate key) against the server and against PostgreSQL 16.15, an error compared by its SQLSTATE. **The gate does not have `cancho-pg`'s repository, so that step is
measured here and skipped there.**

29 mutants added to the group `wire` (60 now: 18 of the messages, 42 of the connection), all killed; they needed five more cases (an error at an `Execute` followed by
another, the unnamed statement and the portal closed, a portal whose statement was replaced, a closed statement's place taken again).

*Found while building:* a closed statement's place was not used again, so a client that prepares and closes would have been refused at its 65th statement whatever it had
closed; places are reused now (the text is not: 1 MiB of statements ever prepared on a connection, 3 MiB before 6aq, then `53200`).

*Not in this part:* `Describe` of a statement (so `cancho-pg`'s code generator cannot be pointed at the engine); binary values; named portals and row limits; more than one
`Execute` to a `Sync` outside a transaction. Each is refused with a tag, and the test pins each. **`cancho-hooks` itself has not been run against the server**: its queries
are answered by the engine (14 of 16, C167) and its driver's messages are served, but a program is more than its queries (what it does at connect, in what order, under
what timeouts), and that is the next thing to measure, not to assume.

## 6an. `cancho-hooks`, the program, on the engine: a first measurement

6w made `cancho-hooks` the first user and counted how many of its statements the engine answers. 6am ended on the sentence that a program is more than its queries. This
section is the measurement, made as soon as there was a server to make it against, and nothing is built in it.

**What was run** (`tests/hooks_server.py`). `cancho-hooks` at its commit `40b2ce0`, built from its repository with its own script (`scripts/build.sh --pure`, with this
compiler rather than the one it pins), started with `--pg-host` at `build/engine` and nothing else changed. Its schema applied with `psql`, one endpoint in its table, a
receiver for it to deliver to, 12 events posted.

**What happened.** The service read its endpoint from the engine and said it was ready; delivered the 12 events; wrote 12 rows of its attempt history through the engine
(`hooks_history_rows_total{result="written"} 12`, none failed, none dropped); answered `GET /events/:id/attempts` for each from the engine; and after it was stopped the 12
rows were read from the engine with `psql`. **No PostgreSQL was running.**

**What it also showed, which is the point of measuring:**

- **"1 of 2 connections live."** The service opens two connections; the server takes one at a time (6al), so the second waited for the whole run. The service went on
  with one, as it is built to. Anything that needs the second (a request while the first is busy) was not exercised;
- **hooks' own test of this feature does not run.** `tests/history_test.py` of its repository, pointed at the engine, stops at its first step: it empties its table with
  `truncate attempts`, which the engine refuses (`unsupported-statement`). Past that it reads the tables with `psql` *while the service is connected*, which one
  connection at a time cannot serve. So: `truncate`, then more than one connection, then whatever the 11 scenarios of that test find. Its scenarios (a database that goes
  away, that never answers, that answers with an error) are about the service, but each needs the server to behave as PostgreSQL does when cut off or slow, and none of
  that has been tried;
- the two queries the engine does not answer (C167: deleting an endpoint, pruning old attempts) were not reached by 12 deliveries. The service prepares them when it
  connects, and the server says nothing at `Parse` (6am); it will refuse them the first time they are run.

*So the honest state is:* a `cancho-hooks` that only delivers and records runs on the engine today, on one connection, with nothing it does verifiable (no log, 6al) and
no login. It is a demonstration, not a deployment. The order of work this measurement gives: more than one connection, `truncate`, hooks' own tests as the gate for
"hooks runs on the engine", then the log and the login.

*The gate skips this test:* it needs a `cancho-hooks` binary (`HOOKS_BIN`), and the gate does not build one. It is measured on a developer's machine, as C180's step
with `cancho-pg`'s client is.

## 6ao. `truncate`

The first thing `cancho-hooks`' own test asks of its database (6an). Small, and the engine had everything for it.

**Design.** `truncate [table] NAME`, one table, none of the options (several tables, `restart identity`, `cascade`: refused, `unsupported-statement`). Every row of the
table is removed and is a row deleted: a change the statement reports and a fact of the commit, as for a table dropped (6ai). The table stays, with its indexes and its
definition, and **its counter goes on from where it was**, which is PostgreSQL's default (`continue identity`). In a transaction it is taken back by a rollback like any
write. Behind PostgreSQL's capture a `truncate` fires no row trigger and tells the log nothing; here it does.

It is one of the engine's own forms (no IR; the guard refuses it behind PostgreSQL, as it refuses `create sequence`), refused on a tree read `AS OF` and with parameters.

**Test.** The differential's generator truncates a table now and then, and the fixed statements have it alone, with `table`, on a table that is not there (`42P01`), in a
transaction rolled back and in one committed, and before an insert that must draw the next value of the counter, not the first. As for a table dropped, the rows the
engine reports are held against PostgreSQL's table read before and after, and the commit's `changes` against the reference's. The three options are pinned as refused.
`tests/engine_log.py` has it in both histories. 20 seeds of 3,000 statements; 6 mutants; 6 cases of the statement test.

## 6ap. An insert with fewer values than the table has columns

The second thing `cancho-hooks`' own test asks (6an): `insert into endpoints values (0, '127.0.0.1', 9100, '...')` into a table of more columns. The lowering refused it
(`syntax`): with no columns listed it wanted a value for every column. That was a limit of the lowering since M2, written down and never lifted, and it held for the proxy
too: a statement PostgreSQL accepts was refused before it reached PostgreSQL.

**Design.** With no columns listed, the values of a row are for the table's first columns, as many as the row has; the others take their defaults, exactly as if those
first columns had been listed (the IR says so: it lists them). More values than the table has columns, and rows of different lengths, stay refused (`syntax`; PostgreSQL:
`42601`). Nothing else changes: a column with no value and no default that takes no null is `23502`, as it is when columns are listed.

**Test.** The differential's fixed statements have it with one value fewer, with only the key, with every value, with `returning` and with `on conflict`, and the two
refusals pinned against PostgreSQL's `42601`. The lowering's hand-written cases have the IR of two such statements byte for byte (one was the pinned refusal). 2 mutants.

## 6aq. The server, third part: more than one connection

6an measured it: `cancho-hooks` opens two connections and got one, and its own test reads the tables with `psql` while the service is connected. One connection at a time
(6al) was the scope of a first part, not a design.

**Design.** Still one process and one thread: the engine runs one statement at a time, and nothing here changes that. What changes is that the server no longer waits on one
client. It waits on all of them (a poller over the listener and every connection), reads what each has sent as it comes, and runs a statement when its message is whole.

- *Up to 16 connections*, each with its own buffer for what it sends (1 MiB), its own session (6aj) and its own prepared statements (6am). The 17th is told `53300` and
  closed. A message longer than the buffer is not the end of a connection any more: it is read past and refused (`54000`, `statement-too-long`), which is what the first
  part could not do. *(The first part took a message of 16 MiB. The engine never ran a statement near that: the longest row is 748 bytes and a statement's values 64 KiB
  with parameters. 1 MiB a connection is what 16 connections can be given without the server holding a quarter of a gigabyte for buffers nobody fills.)*
- *Statements outside a transaction* run in the order their last byte arrives, each its own commit, each on the disk before its answer (6al). Two clients never see half
  of one.
- **A transaction has the database to itself.** A transaction's statements build on a tree of their own that becomes the branch's at `commit` (6v). Two of them open at
  once would each start from the same tree, and the second to commit would undo the first: a lost update, silently. The engine has no row locks and no way to merge two
  trees, so the server does the one thing that is certainly right: while a connection is in a transaction, **what the other connections send waits** (unread past its
  buffer, unanswered) until that transaction ends. Every history the server produces is then one a single client could have produced, which is also one PostgreSQL could
  have produced; what PostgreSQL would have run side by side runs one after the other.
  - The cost is the obvious one, and it is stated as a limit: a client that says `begin` and goes quiet stops everyone. So a transaction that has been idle for 30 s while
    another connection waits is ended by the server: its connection is told `25P03` (PostgreSQL's code for exactly this, `idle_in_transaction_session_timeout`) and
    closed, its transaction rolled back. With nobody waiting, a transaction may idle as long as it likes.
  - Reads by the others wait too. They could be answered from the branch's tree as it stands (it is what is committed), and are not, yet: one rule first.
- *Fairness:* each pass over the connections runs at most one statement of each, in turn, starting after the one that was first the pass before.
- *Writing an answer* is the one place the server still waits on a single client: an answer is written to its connection before the next statement of anyone runs, and a
  client that does not take it stops the others while it does not. After 10 s of a client taking nothing, its connection is closed. An answer of any size to a client
  that reads costs the others only the time it takes to send.
- A connection that ends, however it ends, gives back what it held: its transaction is rolled back (6al), the wait of the others ends, its place is free.

*Not in this part:* more than one statement at a time (there is one engine, one page file, one thread; this part is about not making clients queue for a connection, not
about speed); reads beside a transaction; a limit on what one address may open; the log, the login.

**Test** (`tests/engine_wire.py`). Everything the first two parts test, unchanged, on the new loop. Then, with several clients: statements of two connections interleaved,
each answered and all of it there at the end; a second client served while the first sits idle (the thing 6al could not do); a client in a transaction and another that
writes: the second's answer comes only after the first commits, and both writes are there, in that order; the same with a rollback; the same when the first disconnects
instead; a transaction idle for the limit while another waits is ended with `25P03` and the waiter is served, and one idle with nobody waiting is not; a 17th connection
is told `53300` and the 16 go on; a message over 1 MiB is refused and the connection goes on; a client that sends a query and never reads is dropped after the limit and
the others are served; many clients at once, each with its own table, against the test program's answers for the same statements. And `cancho-hooks` again (6an): both of
its connections live.

**Built.** `serve.run` (the loop), `step` (a connection's next unit of work), `accept_all`, `receive`, `finish`, `push` (`src/serve.cho`); the program allocates what 16
connections hold (about 52 MiB) and takes the two limits as arguments, so that a test does not wait 30 s. The handlers of 6al and 6am are unchanged but for where their
bytes go. Measured: the differential of 6al and 6am (3 seeds, 2,070 statements each) unchanged on the new loop; the cases above, with limits of 1.5 s: a waiting statement
is answered 1.5 s after the transaction it waits for went idle and the idle connection reads `25P03`; a client that reads none of a 10 MB answer is dropped after 1.5 s
having been sent 2.8 MB, and the other client is answered then; 8 clients at once, 161 statements each, answered as the test program answers each alone.

**And `cancho-hooks` (6an), which is why this was built.** The service now says `2 of 2 connections live`. Its own test of the feature, `tests/history_test.py` of its
repository, run against the engine unchanged (with `truncate`, 6ao, and the short insert, 6ap): **scenarios 1 to 7 pass, 22 checks** (every attempt a row; the reasons
that are not a status; a replay's rows; a database not there at start; one that never answers; one cut in the middle; none named). It stops at scenario 8, which renames
the table away (`alter table attempts rename to ...`) to see what the service does when its table is gone; the engine has no rename. *(6ar adds it, and measures the
rest.)*

*What changed from the first part and is corrected there:* a message of 16 MiB was read and one longer ended the connection; a message is now at most 1 MiB and a longer
one is refused and read past. The named statements of a connection may hold 1 MiB of text, not 3.

13 mutants added to the group `wire` (72 now: 16 of the messages, 56 of the connection); all killed. Three that survived at first were of code the new loop had
made dead (the old function that found a message's end; a length check the smaller buffer made impossible to fail), which is removed.

*Not tested, and said:* that a connection whose buffer is full is not read from (so that the loop sleeps rather than spins while it waits) is in the code and no test can
see it, since a loop that spins gives the same answers. Fairness between connections is by construction (the pass starts one place later each time) and is not measured.

## 6ar. A table renamed, and `cancho-hooks`' own test of its history, in full

Scenario 8 of hooks' test (6aq) takes the service's table away by renaming it and brings it back. The engine had no rename.

**Design.** `alter table NAME rename to NEW`. The table keeps its number, so its rows stay where they are in the tree; its entry in the catalog moves to the new name (the
old name is free, and stays in the history as a dropped table's does), and its indexes become indexes of the table under its new name. The new name must be free of
tables, indexes and sequences (`42P07`), the old one a table (`42P01`).

*For the log a row is a row of the table named.* A fact is (table, key, before, after), so the same rows under another name are other facts. Each row **leaves the table of
the old name and enters the table of the new one**, with new salts (it is another row to the log, and no salt is given twice, 6ag): two facts a row, and a replay of the
log ends at the rows there are, under the names they have. PostgreSQL's capture tells its log nothing of a rename. The cost is a write of every row, as for a column added
(6ai). Renaming a column or a constraint is not this and is refused.

**Test.** Fixed statements against PostgreSQL: the rename, onto a table's name, an index's name, of a table that is not there; reads and writes under the new name; the
counter going on; an index that goes with the table when it is dropped under its new name; in a transaction rolled back and in one committed. The rows the engine reports
are held against PostgreSQL's two tables (the old name gone, the new one read). In the log's test a table is renamed, written to and renamed back, and the three verifiers
say `ok ... final`. 9 mutants; one survived until the test dropped a table under its new name.

**`cancho-hooks`' own test, measured** (`tests/hooks_server.py` with `HOOKS_REPO`; hooks at its commit `40b2ce0`, its test `tests/history_test.py`, 11 scenarios):

- **unchanged, it passes 24 checks and stops at scenario 9**, which makes a PostgreSQL role (`create role hooks login`, grants) and looks for the service's connections in
  `pg_stat_activity`. That is the administration of a PostgreSQL. The engine has no roles and no login at all yet (6al); when it has one, it will be its own.
- **with those lines cut from a copy** (seven statements and one check; nothing else touched) **it passes all it has left: 43 checks, scenarios 1 to 11.** A database that
  is not there at start, that never answers, that is cut in the middle, that answers with an error, a table renamed away and back, the history read back through the
  service's API while the database is slow, gone or wrong.

*Run three times.* Twice all 43 passed. Once, while this machine was also running two mutant groups and the gate, one check of scenario 11 failed (a request that should
have waited and timed out was refused at once: `503`). The scenario is about the service's own waiting slots while a proxy in front of the database stalls; whether the
service, its test or the engine's server under load was late is **not known**. It is written here so that it is not forgotten, not because it is understood.

*What this is and is not.* It is the first time a program this project did not write for the purpose has had its own test of a database feature pass against the engine.
It is one test of one feature of one service, on one machine; the gate cannot run it (no hooks binary there). The two queries of C167 the engine refuses are not in this
test. Nothing the server does is logged or verifiable yet, and anyone on the machine may connect.

## 6as. The log is in the page file

6ah made a commit's record and gave it to the test program to print; 6al's server commits and writes no log. 6ah left open where a server writes the log and in what
order with the page file, across a crash. This part answers it by not having the question.

**Design.** The record of a commit, and the facts it commits to, are written **into the branch's tree**, in the same tree and the same page-file commit as the rows the
transaction wrote and the head of the log (6ah):

- `0xFFFFFFFE 0x05`, the commit's number, a part number: the record as the log holds it (`build.log_record`), in parts of at most 700 bytes (a value of the tree is at most
  800);
- `0xFFFFFFFE 0x06`, the commit's number, then the table, a zero byte and the key's commitment: for each fact of the commit, the two hashes (was, is), each after a byte
  that says whether it is there. This is what `facts.seal` already walks to compute `changes`; it is copied, not recomputed.

So a commit, its record and its facts are durable together or not at all: a crash cannot leave a record without its rows or rows without their record, and the crash test
of the page file (C156) covers the log with nothing added. The log file a verifier reads is an **export**: the header and the records in order, read back from the tree.

*The store has no images.* The delta store a verifier reads (`docs/spec/l3a.md` section 9) has for each change the hashes and, where they have not been erased, the key,
the images and the salts. What is kept here is the hashes only, which is the form of a line that has been erased, for every line. The verifiers check exactly what they
check for an erased line: that the facts hash to the commit's `changes`, that each `state` follows, that a replay of the facts ends at the rows there are (whose keys,
images and salts the live dump gives). They do not check that an image hashes to its fact, since no image is given; the engine's history holds the old rows with their
salts for as long as they are not erased (6n), and showing them is a matter of reading the history, not of a second copy. **Erasure therefore has nothing to do in the
store:** what it destroys (rows, salts) was never there, and what is there (salted hashes, commitments) says nothing once the salts are gone (6ag).

*The cost:* a write to the tree for each fact, beside the row's own. Measured below.

*The server* takes the seed of its signing key from a file named on its command line and logs every commit of the first branch that changed rows. With no key file it
logs nothing, as before, and says so when it starts. How a key is kept, rotated or put in hardware is not this part.

*Not in this part:* the log as a file the server appends to and ships (it is read out of the page file on request, by the test program's commands; a tool of its own for
an operator is not written); commits that change no row (a table made, a sequence drawn) are in no record, as before; the schema hash, token, principal, statements and
time of a record are still zeros (6ah); branches other than the first.

**Test.** `tests/engine_log.py`: after the history, **a process that did not write it** reads the records and the facts out of the page file, and those are what goes to
`tools/verify.py` and the three L3a verifiers, with the live dump; they must be byte for byte what the writing process printed at each commit. Then a row is erased
(`!erase`), the file swept, and the export verified again: the same log, the same store, the row gone from the dump and its facts still accounted for.
`tests/engine_wire.py`: the server is started with a key; after the differential's history (2,070 statements over a socket, a third by the extended protocol) it is
stopped, the log is read out of its page file and verified. That is the first log of a client's session through the server that a verifier has read.

**Built.** `facts.seal` writes the record and the facts with the head; `facts.header`, `facts.record`, `facts.next_fact` read them back; `!records` and `!store` in the
test program; the server's key file. Measured:

- `tests/engine_log.py`, 3 seeds of 2,000 statements (933 to 1,025 commits): the log and the facts read out of the page file by another process are the ones printed,
  record for record; `tools/verify.py` and the three L3a verifiers say `ok ... final` on them (every line of the store counted as erased, since none has an image); a fact
  removed and a hash changed are each `changes-mismatch`; after a delete, an erase and a sweep, one commit more and still `ok ... final`; a record of 40 tables is kept in
  two parts and read back whole.
- `tests/engine_wire.py`: **the log of a session of 929 statements over a socket** (the differential's fixed statements and 300 random ones, a third of the parametrised
  by the extended protocol; 225 commits, 1,859 facts), read out of the server's page file after it stopped, verifies with `tools/verify.py` and the three L3a verifiers,
  the replay ending at the 69 rows the file holds; at the gate's size, 2,129 statements, 328 and 333 commits for seeds 1 and 2. The same for the server that 8 clients wrote to at once, with transactions that waited, one that was ended and
  connections that were dropped.
- **One key signs a log:** a commit signed with another key is refused, and (which was not so as the session was first written in 6ah and 6aj: a commit whose
  record failed was made without one) **a commit that cannot be recorded is not made**: the statement is an error and its rows are not there. The server stops on it rather than go on unrecorded.

*The cost, measured on this machine while it was busy with other work, the two servers side by side:* 300 commits of one row take 1.57 s with no key and 4.46 s with
one, 2.8 times as long (9.6 ms a commit more); one update of 1,200 rows 0.028 s and 0.044 s; the page file after both, 22 MB and 45 MB. What of the 9.6 ms is the
signature and what the writes is not measured. C162's numbers are without a log.

*Found while building, and corrected:*

- the log was first put in the catalog (`0x00000000 0x05`, `0x06`). **Every statement reads the catalog from end to end** to know the tables, so every statement read
  the whole log: after 30,000 facts a select of one row took 200 ms. The floor of 6al's test (500 selects under 5 s) failed, which is what it is for. The log is under a
  number of its own, and the 500 selects take 0.04 s again;
- a test that fails did not stop its server. Two servers built with a mutant that loops had been running for 38 minutes on every processor of this machine when that
  was noticed, during which a check of hooks' test failed once (6ar) and several timings in this document were taken. The test now kills what it started however it
  ends. **The timings of 6al and 6am were taken before those servers existed; those of 6aq and the cost above were not, and are marked so.** The hooks failure of 6ar may
  have been this load; it has not been seen since, in 2 runs, which proves nothing.

*Still not there:* the log covers the rows and nothing else. A commit says no schema, no principal, no statement, no time; a table made or dropped leaves no record
unless it had rows; nobody is authenticated, so "who" is not a question the log could answer yet. It is the L3a half of what the proxy's log says.

## 6at. A login, what a token allows, and who and when in the log

After 6as the server records what changed. It does not know who asked: any client on the machine is served as anyone (6al), every commit's token and principal are
zeros and its time is 0 (6ah). The proxy has had all of this since M1: a capability token as the password, checked against a root key; each statement's effects held
against the token; the token's id, its principal and the time in every commit, so that a verifier with the root key can ask of a log *was each commit allowed* (L2,
`docs/spec/token.md`). This part gives the engine's server the same, with the proxy's code.

**Design.**

- *Login.* The server is started with the root's public key in a file. A startup is then answered with a request for a password, and the password is what it is for the
  proxy: `base64url(token || seed of the token's last key)`. `login.check` (the proxy's) decides: the chain of signatures from the root, the proof that the client holds
  the last key, the expiry against the server's clock, the branch (the database named must be `main`, the one branch the server has), one principal at most. A refusal
  is `FATAL` with the proxy's SQLSTATE and rule, and the connection is closed; nothing is served before. The token stays with the connection.
  **With no root key file the server has no login, as before, and says so when it starts.**
- *What a statement may do.* Before a statement runs, its effects are inferred from its IR by the verifier's own function (`ir.infer`: the tables and columns it reads,
  the tables it writes, what it defines) and each is held against every block of the token (`token.effect_denied`). One that is not allowed is refused
  (`42501`, `effect-denied`) and nothing of the statement runs; in a transaction that fails the transaction, as any error does. The engine's forms that have no IR are
  given their effects here: `create sequence` defines its name, `truncate` writes its table, a rename defines both names. A statement with `returning` is held to the
  effects of its hidden select as well. This is what the proxy's guard does, on the same two functions; the guard itself is not used because it refuses the engine's
  own forms outright (6x), which behind PostgreSQL is right and here would refuse half of what the engine does.
- *Who and when.* A commit's record carries the id of the connection's token, its principal (zeros if the token names none) and the server's clock in milliseconds.
  The token itself is kept in the page file under its id, in the commit that first uses it, so that a verifier can be given the tokens with the log.
- *What a verifier can then ask:* `tools/verify.py LOG --root KEY --tokens FILE`, L2: every commit names a token in the file, the token's chain verifies under the
  root, it was not expired at the commit's time, its principal and branch fit, and **every effect the commit records is one the token allows**. The commit's effects
  are still the writes only (a write for each table written, 6ah): L2 over this log says nobody wrote where they were not allowed to. That nobody *read* what they were
  not allowed to is enforced by the server when the statement arrives, and is not in the log.

*Not in this part:* **the statements** (a commit names none, so a verifier cannot recompute its effects from what was run: `--stmts` has nothing to read, and "what" is
still the rows, not the SQL); revocation (the server reads no list of revoked tokens; a verifier can be given one); the schema hash; a commit for a statement that
changes no row; TLS (the password travels in clear, on the loopback only).

**Built.** `password_step` and the token's place with a connection (`src/serve.cho`); `permitted`, `permitted_name` and the outcome `o_denied` (`src/drive.cho`); `who`
in `facts.seal`, the token kept under `0xFFFFFFFE 0x07`, `facts.next_token`; the root's key file as the server's fourth argument; `!tokens` in the test program.
Measured (`tests/engine_wire.py`, `logins`):

- **not let in**, each asked for a password, told why with the proxy's SQLSTATE and rule, and closed with nothing served: a query in place of the password (`08P01`); a
  password that is no token, a token another root signed, one without the seed of its last key, one that has expired (`28P01`); a token for another branch, a database
  that is not `main` (`3D000`);
- **a token that may only read** reads, and an insert, an update, a delete, a truncate, a table made, dropped, renamed or given a column, a sequence and an index are
  each `42501 effect-denied`; **a token for one table** writes and reads it, with `returning` too, and no other; **one that may write a table and not read it** inserts,
  and is refused what the insert would return and an update that must read to find its rows;
- a statement not allowed fails its transaction and nothing of it stays; by the extended protocol it is the same refusal;
- **every record names its token and its time**: the commits of that session are under three tokens (the read-only one made none), each kept in the file once, each
  time within the test's own clock and none before the one before;
- **L2:** `tools/verify.py --root --tokens` says `ok ... level=2` on the log and the tokens read out of the server's page file; under another root's key
  `token-bad-signature`, and without the tokens a rejection. The three L3a verifiers still say `ok ... final`;
- 600 random statements under a login with a token that allows everything are answered as the test program answers them (it is asked nothing about who), and that
  log verifies at L2 too.

**`cancho-hooks` with a login**, tried by hand and not yet a test: started with `--pg-database main --pg-password <token>` it logs in (its driver answers a request
for a cleartext password as it does PostgreSQL's), has both connections live, and the attempt it records is a commit under its own token, kept in the file beside the
administrator's. One thing found: **hooks takes a password of at most 255 characters**, and a token is long: one with three grants (`r:*,w:*,c:*`) is exactly 255 as
`mint.py` makes it, one with five is 266 and hooks refuses the setting. A token attenuated by a second block would not fit. That is a limit in hooks to raise, or a
reason for a shorter presentation of a token; nothing is changed here.

*What this does not give, said again where it is measured:* the token is a bearer's (whoever has the password is the principal, and it crosses the loopback in clear);
a commit's effects are its writes, so L2 over the log is about writes; and a statement that changes no row (a table made by a token that may define it, a read) is
in no record at all. "Who read what" is enforced and not recorded.

**`cancho-log`, looked at for this** (its commit `43c492c`). It is a durable append-only log with a crash-swept recovery of a torn tail, and a "trail" mode that
hash-chains events and checks a file against an anchor held elsewhere. It is not what this part needs: who may connect and what a record says are the token's and the
commit format's, both already this project's. Nor would it replace 6as: the engine's log is in the page file precisely so that a commit and its record cannot come
apart, and a second file would bring back the order-of-two-writes question 6as removed. **Where it would earn its place is the copy of the log that leaves the machine**
(the next item after this one: a log an operator can rewrite proves nothing until a copy is somewhere they cannot reach). That copy is an append-only file with a
recovery story, which is exactly `log.append`, `log.flush` and `log.recover`; and its anchor (`count`, head id) is the shape of what a third party would hold. Two
things to settle then, not now: it writes one segment and does not roll yet, and its trail ids are lex-trail's hash of an event, where this log's records already carry
their own chain and a signature, so trail mode would be a second chain over the first rather than a replacement.

## 6au. What ran: the statements in the log

After 6at a commit says who and when and which rows. It names no statement, so a verifier cannot ask the last question L2 has: *were the commit's effects what its
statements do, and was each allowed?* The proxy answers it since M1 with a statement store beside the log (`docs/spec/ir.md` sections 4 and 8).

**Design.**

- *What is recorded.* Every statement that ran to an answer in a transaction that commits, in the order they ran, reads among them: a commit's `statements` are their
  ids. A statement outside a transaction that changes no row is still no commit and in no record.
- *As what.* As the IR the engine lowered it to, in the store's third form: the **shape** (the statement with each constant replaced by a hole of its type) and a salted
  hash of the constants. A statement with `returning` is two statements, the write and the select of what it returns. The engine's forms that have no IR are told as
  the IR that says what they did: a `truncate` is a `Delete` with no condition, a renaming is a definition (`Ddl`, alter) of each of the two names, `create sequence` a
  definition of its name. `on conflict do nothing` is the `Insert` it is; the IR has no word for the clause.
- **The constants are never written.** The third form allows a record whose constants have been erased: the shape, the hash, and nothing else. Every record is
  written in that form from the start. So the log says *what kind of thing was done to which tables and columns*, the verifier can infer the effects of every statement,
  and a value a client sent is in no byte of the page file because of the log. An erasure (6o) has nothing to find here, as it has nothing to find in the store of
  facts (6as). What is given up is said plainly: **the log cannot show the values a statement carried**, erased or not; the rows' history can, while it is not erased.
- *A commit's effects are its statements'.* Until now a commit recorded one write for each table written (6ah), noted table by table as the transaction went. Now its
  effects are **exactly** the union of what `ir.infer` gives for its statements: reads of tables and columns, writes, definitions, calls. That is what the
  specification asks (equality, not containment), it is what the server already held against the token (6at), and the table notes of 6ah are gone.
- *Where.* A statement's record is kept in the page file under its id (`0xFFFFFFFE 0x08`), written by the commit that names it, in the same page-file commit as
  everything else.
- *A limit that is a refusal:* a commit names at most 500 statements and 8 KiB of effects. A transaction of more is refused **when it commits**
  (`54000`, `commit-too-large`) and rolled back; it is not committed with a record that says less than it did.

*Not in this part:* the values bound to parameters (the IR has `Param`, the store has no place for what was bound); the SQL text (the IR is what the verifier reads,
and what the engine ran); the schema hash; statements that commit nothing.

**Test.** `tests/engine_log.py` runs its histories under a token and gives the log, the tokens and the statements, all read out of the page file by another process, to
`tools/verify.py --root --tokens --stmts` and to the two other verifiers of L2 the gate builds (`build/verify`, in cancho, and `build/verify-go`): each must say
`level=2+ir`, and refuse a store with one statement taken out (`stmt-missing`) or a table's name changed in one. A row whose values came in three statements (an
insert, a condition, an update) is deleted and erased: no byte of the page file holds the value, and the log still verifies with the statements. A transaction of 501
statements is refused at its commit. `tests/engine_wire.py`: the same check on the log of a session over a socket, under a login.

**Built.** `exec.stmt_add` (the IR of each statement that ran, kept while the transaction is open), `drive.run` and `keep_named` (the forms with no IR), `facts.say` (at the
commit: `ir.lift`, a salt, `build.stmt3` with the constants left out, `ir.infer`), `facts.seal` (the ids and the effects in the record, the statements' records under
`0xFFFFFFFE 0x08`), `session.close` (`commit-too-large`); `!stmts` in the test program. Measured:

- 3 seeds of 2,000 random statements after the fixed history, in two processes on one page file: 1,268 statements in 1,029 commits, 1,191 in 937, 1,235 in 972; the
  count of each commit is exactly the statements that ran in its transaction (a `returning` counted twice, a renaming twice). The log, the tokens and the statements
  read out by another process verify at `level=2+ir` with `tools/verify.py`, `build/verify` and `build/verify-go`, before and after an erase; each refuses a store
  with a statement taken out (`stmt-missing`) and one with a table's name changed. The three L3a verifiers still say `ok ... final`.
- A renaming's commit has for effects the definition of both names and nothing else; a truncate's, the write of its table.
- The value of the erased row, which came in an insert, in a condition and in an update, is in no byte of the page file; the log verifies after.
- A transaction of 501 statements: `commit-too-large` at its commit, nothing of it there, the next commit made.
- Over a socket, under a login (`tests/engine_wire.py`, 3 seeds): the log of a session verifies at `level=2+ir` with the tokens and the statements the file kept.
- 20 seeds of 3,000 statements against PostgreSQL, the crash test, the big-table test and hooks' tests: as before.
- Cost, 300 one-row commits by the test program with a key and a token: 1.75 s with the statements, 1.78 s at the commit before (no difference measured); the page
  file is 9.57 MB against 8.33 MB, 15% more (a record of a statement is a page of the tree written again at each commit).
- 18 mutants (`stmts:`), all killed. Four survived the first run and each said something true: the cap on statements was checked twice (`facts.say` and `facts.seal`;
  the first is removed); the test counted a commit's statements between `n` and `2n` (now exactly); and no test looked at what a truncate's or a renaming's commit
  says its effects are (now one does).

*Limits.* The constants of a statement are in no record, by design: the log shows a statement's shape, not its values. What was bound to a parameter is not kept. A
statement outside a transaction that changes no row leaves no record, so **reads outside a writing transaction are still enforced and not recorded**. The schema hash
is still zeros. The 500-statement limit is a refusal at the commit, after the work was done.

## 6av. The log out of the page file, for someone else to keep

The log is in the page file (6as), and the page file is the operator's. A log its keeper can rewrite proves nothing to anyone else until a copy, or at least the id
of its head, is somewhere the keeper cannot reach. Until now the only way out of the page file was the test program's commands (C186's limit: *no tool for an
operator*). This part is the tool; what carries its output off the machine stays the operator's (a copy command, a mail), and is not built.

**What was already there (a read, `docs/spec/commit.md` section 6, `tools/verify.py` line 157).** The check that a log still holds a commit someone was given
earlier exists in all three verifiers since M1: `--expect ID`, verdict `expected-missing`. So an *anchor* needs no new rule: it is a commit's number and id, and
whoever holds one runs any verifier with `--expect` on a later copy of the log.

**Design.**

- *A program that can only read.* `build/logexport PAGEFILE WHAT [UPTO]` writes one thing to its standard output and nothing anywhere else. `WHAT` is `anchor`,
  `log`, `facts`, `tokens`, `stmts` or `live`. Its authority is a fact to check: it opens one file to read, and has no word for writing a file, the network or the
  clock (`cancho authority`).
- *The files are the ones the verifiers read*, byte for byte what `tests/engine_log.py` assembled until now from the test program's output: `log` is `CHODBLG1`, the
  key, and each record; `facts` a version-2 delta store with the hashes only (6as); `tokens` `CHODBTK1`; `stmts` `CHODBST3`; `live` a version-2 dump of every row of
  every table, the tables found in the catalog and not named by the caller.
- *`anchor`* prints `anchor N ID`: the number of commits and the id of the last (`anchor 0 -` for a log with none).
- *One log, several runs.* The five things are five runs, and commits may be made between them. `UPTO` (a count of commits, from `anchor`) makes `log` and `facts`
  stop there, so the two agree with each other and with the anchor. `tokens` and `stmts` are stores looked into by id: more than the log names does no harm. `live`
  is the rows now: it can be compared (L3a's `final`) only with a log taken at the same head, so with `UPTO` it refuses if the head is not there.
- *Beside a server that is running.* The tool does not stop the server or lock the file. A page it reads may have been freed and written again by commits made
  while it read. So at its end it reads the file's superblock again, and if a commit was made since it began, its output is not to be believed: it says
  `refused export-raced` and ends with status 1. The caller runs it again. Every other way of failing is a refusal with a tag too: `export-usage` (2),
  `export-no-file`, `export-no-database`, `export-no-log` (a page file with no log has nothing to export but `live`), `export-damaged`, `export-behind` (`UPTO` is
  more commits than there are, or `live` asked at a head that is gone).

*Not in this part:* carrying the output anywhere; an export that picks up where the last one ended (each run writes the whole log; measured below); the server
giving an anchor to a client (`cancho_last_commit()` is the proxy's) *(corrected in 6ax: it is not; the specification names it and nothing had built it. 6ax does, in the engine)*; `cancho-log` (6at saw it as the file a copy could be appended to: with whole exports there is
no file to append to yet, so it has no place in this part).

**Test.** `tests/engine_log.py`: after its history, the tool's five outputs are byte for byte what the test assembles from the test program's commands; the
verifiers are given the tool's files. An anchor taken in the middle of the history: `--expect` of its id on the log at the end is `ok`, and on the log of another
history made with the same key `expected-missing`; `log N` is exactly the first `N` records and verifies. `tests/engine_wire.py`: the tool run again and again
beside a server that 4 clients write to; every run either ends 0 with a log that verifies or says `export-raced`, and at least one of each happens. Every refusal
is reached. `tests/authority.sh`: the tool's authority.

**Built.** `proxy/logexport.cho` (one file; it uses `facts.header`, `record`, `next_fact` and `next_kept` as the test program does, and writes no page). Measured:

- 3 seeds of 2,000 statements (944 to 1,036 commits, 2,325 to 2,821 facts, 1,200 to 1,277 statements): the tool's log, facts, tokens and statements are byte for
  byte what the test assembles; its live dump has the same lines (the tables in the catalog's order, not the caller's); the three L3a verifiers say `ok ... final`
  on its files.
- An anchor taken when the first process ended: all three L2 verifiers say `ok ... level=2+ir` with `--expect` of its id on the log at the end and on the log cut at
  the anchor (`log N`), and `expected-missing` on the cut log asked for the last commit and on the log of another history made with the same key and token.
- Beside a server 4 clients write 480 rows to (3 runs): 55 to 57 runs of the tool whole, each log verifying and each log with its facts (16 to 19 pairs) having every
  commit's changes; 46 to 73 runs `export-raced`; no other outcome. With the writers done, everything taken at one anchor (481 commits) verifies to `final`.
- Every refusal reached, 20 cases: `export-behind`, `export-damaged` (a file of noise; a record's length changed where it lies in the page file),
  `export-no-database`, `export-no-file`, `export-no-log`, `export-usage`.
- Authority (`tests/authority.sh`): `args err_write file_read fs_read("") heap io_write`; never the network, signals, other programs, foreign code. No `file_write`.
- Cost, a log of 1,000 commits (a page file of 37.5 MB): `anchor` 9 ms, `log` 14 ms (344 KB), `facts` 20 ms, `stmts` 17 ms, `live` 26 ms. A whole export each time
  is not yet a cost worth an incremental one.
- 17 mutants (group `export`), all killed. One survived the first run: a record that cannot be read ended the log quietly at the commit before, status 0, and what
  was written verified. No test had a damaged record; now one does.

*Found while testing.* `create table` changes no row, so it makes no commit (6ah): a server that has only made tables has no log, and the tool says `export-no-log`
of it. That is the rule of 6ah showing, not a fault of the tool; it is one more reason the schema hash matters (still zeros).

*Limits.* Nothing here takes the output off the machine or gives the anchor to a third party: until someone else holds an anchor, the log is as rewritable as before.
`export-raced` is detected by the superblock's number at the two ends of a run, on the argument that a page of the tree read is written again only by a commit after
the next; the argument is tested by the runs beside a server, not proved. Under writers that never pause, a run long enough may never be whole (not met: 14 ms
against a commit's 7). The tool reads the first branch only. A reader of the page file can read every row: the tool's authority bounds what it can *do*, not what it
can see.

## 6aw. The server takes back the pages its commits leave behind

**Found (measured while timing 6av).** Every commit writes new pages and leaves the old ones (the tree is copied on write), and the pages nothing names any more are
found and made free only by `pstore.sweep` (D-M3-2), which until now nothing but the test program's `!sweep` called. The server never called it. A table of two
columns, 2,000 inserts and 1,000 updates, each its own commit, through `build/engine`: the page file is **147 MB** with the log on and 57.6 MB without; a sweep of
that file frees 97% of its pages. A server under steady writes filled its disk.

**Design.**

- *When.* After a commit is durable, and only then: the connection is in no transaction, so no tree exists that the page file's roots do not name (a transaction
  has the database to itself, 6aq). The sweep runs if the pages the last sweep freed are used up **and** the file has reached a size set by that sweep: twice the
  pages then in use, and 8 MiB (2,048 pages), or the size the file had if that is more. So the file is held near twice what is in use, and a sweep, whose cost is
  the size of the file, is paid for by at least as many pages written since the last.
- *At a start.* The free pages are not kept in the file (a sweep finds them again), so a server that starts knows none: the first commit after a start sweeps.
  *(Corrected while building: as first written a start set the mark at the file's size and 8 MiB, like a first sweep. Measured with a server killed and restarted
  5 times in 3,000 commits: 46.4 MiB against 14.5, each start having cost its 8 MiB again.)*
- *What stays.* What a tree names: the rows, the indexes, the history of the rows (6n) until it is erased, the log with its facts, tokens and statements. And
  the trees of the superblock before the current one, which `pstore.sweep` keeps for a damaged current one to fall back to. So the reader of 6av that loaded one
  state still reads whole pages until the commit after the next, and its check at the end (any commit: `export-raced`) covers it as before.
- *A sweep that fails* is the page file not readable or writable: the server stops, as for a commit that fails (`58030`).
- *Erasure.* A page freed is zeroed (D-M3-2). With the server sweeping, what an erase removed is gone from the file without anyone asking, at the latest when the
  file has doubled; when exactly is not promised.

*Not in this part:* giving the file's space back to the system (freed pages are reused, the file does not shrink); a sweep that does not stop the server while it
runs; the free pages kept across a start.

**Test.** `tests/engine_wire.py` (`reclaiming`): the 3,000 commits above through the server, killed with `SIGKILL` and restarted at 5 points of the run; the file
stays under 20 MiB at every 500th commit, every acknowledged row is there at the end, and the log out of the file verifies with the L3a verifiers (a page zeroed
that a tree named would fail one of the three). The differential, the 8 clients and the export beside a writing server (6av) all now run with sweeps among their
commits.

**Built.** `serve.reclaim`, called where the commit is made durable. Measured:

- The 3,000 commits and 5 kills: the file ends at 14.4 to 14.5 MiB and is never larger (140.7 MiB with the sweep taken out, by the mutant); 2,000 rows, the 50
  updated ones with their last value; the log's 3,000 commits verify to `final`. The slowest answer of the run 0.04 to 0.09 s.
- Without a log the same history ends at 9.3 MB (57.6 before).
- What a sweep costs: a file of 159 MiB (60,000 rows, 36,294 of its 40,676 pages free) is swept in 0.33 s, 0.23 s when the free pages are zeros already.
- `tests/engine_wire.py` on 3 seeds, the crash test and the 500-insert floor: as before (3.6 to 3.8 s for 500 commits; 3.6 to 4.5 before).
- 2 mutants (`reclaim:`, group `wire`), both killed: never sweeping (140.7 MiB), and sweeping once a start (32.7 MiB).

*Limits.* **The server answers nobody while it sweeps**: about 0.3 s for 160 MiB here, so seconds for gigabytes, at a moment the clients do not choose. The file
never shrinks. What is "in use" includes every old version of every row (the history is kept until erased) and the whole log: 14.5 MiB for 2,000 small rows after
3,000 commits is mostly those, and they grow with every commit; nothing here bounds them. A failed sweep was not provoked (no test makes the disk fail). The free
list holds 65,536 pages (256 MiB); more than that freed at once waits for the next sweep.

## 6ax. The head of the log, given to a client

6av ends on its limit: no one but the operator holds an anchor. `docs/spec/commit.md` section 5 has said since M1 how a reader would hold one: *a reader that holds a
commit id it was given earlier (`cancho_last_commit()`) can pass it as the expected id*. **A read, and a correction:** nothing answers that call. Not the proxy
(`grep cancho_last_commit src proxy`: no line), not the engine, where it lowers to the IR's `Call` and is refused `engine-unsupported`. 6av said it was "the
proxy's"; that was written without looking.

**Design.**

- `select cancho_last_commit()` is answered by the engine with one row of two columns: `commits`, an integer, the number of commits in the log, and `id`, text,
  the id of the last in 64 hex digits; `0` and null when there is no commit. It is what `logexport ... anchor` prints, from the same key of the tree.
- *It is the head of the log, not "my last commit".* Any commit a client's own commit comes before will do as its anchor: a log that holds the head holds all
  before it. Asked right after its commit is acknowledged, the head is that commit or a later one.
- *In a transaction* it is the head the transaction began on (its own commit is not made yet), and it is a statement of that transaction like another: the commit
  names it, and its effect, `call cancho_last_commit`, is among the commit's.
- *Authority.* The IR is the statement `Call`, whose effect is `call cancho_last_commit` (`docs/spec/ir.md` section 3); the server holds it against the token as
  any effect (6at). A token must allow that call by name or all calls; one that may only read tables may not ask. That is a choice, and a strict one: the head's id
  says nothing of any row, but an effect the token does not list is not run.
- Only that name, in lower case as the lexer makes an unquoted name, with no argument. Everything else that is a call stays `engine-unsupported`.

*Not in this part:* the same call in the proxy; a head per branch; the id of the commit a statement made, returned with its answer.

**Test.** `tests/engine_log.py`: the call three times in the history (alone, in a transaction that commits, after it); each answer is the number of records made
so far and the id of the last; the commit of the transaction names it and the log still verifies at L2. With no log: `0`, null. Another name of the same length,
an argument, the name quoted: refused. `tests/engine_wire.py`: a client takes the head after the first commit of a run of 481; the log the export tool writes at the
end is accepted with `--expect` of it and refused with an id never given; the server's answer at the end is the tool's anchor. Under a login: a token for
`c:cancho_last_commit` is answered by both protocols and may read no table; a token for `r:*` is `42501`.

**Built.** `facts.last`, `drive.is_last_commit`. Measured: all of the test above, on 3 seeds of each; the 63 steps of the gate before the mutants; 5 mutants
(group `engine`, `log:`), all killed.

*Limits.* A client that never asks holds nothing: the anchor is taken, not pushed. The id is given over the same clear connection as everything else. It is the
engine's server only; a deployment still behind the proxy has no such call. Whoever holds an anchor still needs a copy of the log to check, which 6av writes and
nothing carries.

## 7. Taking over, safely

The risk table of `design.md` says the largest risk is losing data, and the mitigation is staying on PostgreSQL storage until the crash tests pass. So:

* **The default is PostgreSQL** until gates 1 to 5 pass; the engine is built behind a **per-database option**, off.
* **Shadow mode** runs each statement on the engine as well as on PostgreSQL and compares the answer and the `changes` root; a difference is an error in the log (`engine-divergence`), and the PostgreSQL answer is the one served. It is the differential suite run on real workloads, for as long as it takes.
* **Serving from the engine** is a second option, on only for a database whose shadow run has been clean, and the log says which engine made each commit through the commit's `code` field (the hash of the code that ran, `spec/commit.md`), not through a new commit format.

## 8. Open questions, answered at a default (the owner's to overturn)

* **Q1. B+tree or LSM?** *COW B+tree* (D-M3-1). An LSM is reconsidered only if the write amplification of the tree is measured to matter, which it cannot be while the signature costs 6 times the storage.
* **Q2. History as deltas or as page versions?** *Deltas* (D-M3-2): it is what erasure and replay already expect.
* **Q3. Which types first?** *bigint, integer, smallint, boolean, text, varchar, bytea* (D-M3-5); the rest when a client on the list needs them.
* **Q4. Collation.** *C*, byte order, stated (D-M3-5). PostgreSQL's locale ordering is not claimed.
* **Q5. Row image.** *The capture's `to_jsonb` text*, so shadow mode compares hashes (D-M3-6).
* **Q6. Platforms.** *Durability claims for Linux only*, as the language's own documents say.
* **Q7. Directory layout.** *One directory* beside the log directory: `pages`, `super`, `deltas/`; opened and locked as the log directory is (`flock` on `super`).
* **Q8. Can PostgreSQL and the engine run together?** *Yes, in shadow mode* (section 7); that is how the engine is trusted.
* **Q9. A page size.** *4 KiB*; a row or key that does not fit one page is refused (`engine-row-too-large`) until overflow pages are designed, which is not in M3.

## 9. What this page does not show

* **No engine exists.** Every number above is a measurement of the disk or of the proxy, not of the engine.
* The 0.6 ms is for one disk in a sandbox. It is not a claim about production hardware.
* Section 5's gates are a plan. A gate that is not run is not a claim.
* That the declared subset is *enough* for any client is M4's question; M3 only makes the subset real and checked.
