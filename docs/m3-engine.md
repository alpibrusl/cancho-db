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

*Corrected (6bo, slice 2).* "A constant" above did not include a parameter, though PostgreSQL's planner takes one for a constant and the engine had
already refused, before any row, one that cannot be read as the column's type. So `where k = $1`, which is what a driver sends, read the whole table:
76 ms a lookup on 100,000 rows where the same lookup with the number written in the statement took under 0.1 ms. A parameter the client bound is now a
constant here (one the engine binds itself for a subquery's value is not), and a string or a parameter compared with an integer key is read as that
integer: 0.11 ms. The first measure is the binary before the change and the second after, 200 lookups each, by hand.

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
- *Startup.* An `SSLRequest` or `GSSENCRequest` is answered `N` (no TLS: loopback only; *since 6bq* a server given a certificate answers `S`). A startup of protocol 3.0 is answered `AuthenticationOk`, the parameters a client
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
  - Reads by the others wait too (*no longer: 6bs answers them*). They could be answered from the branch's tree as it stands (it is what is committed), and are not, yet: one rule first.
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
changes no row; TLS (the password travels in clear, on the loopback only; *built since, 6bq*).

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

*(Corrected in 6az: the rule below, any commit, made the tool useless beside a busy server; what disturbs a reader is a sweep, and the server now says when one
is coming. And each run no longer reads the whole log.)*

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
- *At a start.* The free pages are not kept in the file (a sweep finds them again), so a server that starts knows none: the first commit after a start sweeps. *(Corrected in 6ay: the server sweeps before it serves; a first commit on a full disk could not be made to get to its sweep.)*
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

## 6ay. A disk that fills under the server

What the server does when the page file cannot be written was designed (section 2: a failed write or sync ends the process; 6al: `58030`) and never met: no test
made a write fail under `build/engine`. The crash tests stop the process at every durable step, which is the disk's state after a failure, not the server's conduct
during one.

**How a write is made to fail, without a hook in the server.** The test starts the server with the kernel's limit on the size of a file it may write
(`RLIMIT_FSIZE`), the signal that comes with it ignored. A write that would take the page file past the limit is cut short or refused (`EFBIG`), which is what a
full disk does: writes inside the file still succeed, the file cannot grow, and the last page may be written in part. It is a real failure of a real `write`, at a
size the test chooses. What it does not make is a failing `fsync`, or a write that fails inside the file.

**What must hold.** The commit that meets the limit is not acknowledged: the client is answered `58030` and the server stops (status 7). Every commit acknowledged
before is in the file. Started again, the server has exactly those rows, and the log verifies.

**Found.** All of that held as built. What did not: **started again on the same full disk, the server never served a write again.** The file was mostly pages
nothing named, and 6aw's sweep would have freed them, but it came after the first commit, which needed new pages first. Measured at a limit of 9 MiB: 660 commits,
stop; then 0 commits in each of three further lives.

**Changed.** The server sweeps before it serves: `serve.reclaim` at the start, in place of 6aw's "the first commit after a start sweeps" *(6aw corrected by this)*.
A start costs a pass over the file (0.3 s for 160 MiB, 6aw).

**Test.** `tests/engine_wire.py` (`disk_full`), at four limits (two on a page's edge, two inside a page): a client inserts until it is refused; three lives under
the same limit, then one with room.

**Measured.** At 3 MiB, 3 MiB and 1,500 bytes, 5 MiB and 7 pages and 100 bytes, 9 MiB: every life ends with `58030` on the commit that met the limit and status 7,
the file never over the limit; commits in the three lives 95+80+77, 97+80+76, 153+134+128, 665+186+180 (0 in the second and third before the change); with room,
the rows are exactly the acknowledged ones, the next insert is made, `cancho_last_commit()` counts them, and the log verifies to `final` with the L3a verifiers.
2 mutants (`disk:`, group `wire`), both killed: a refused commit acknowledged, and a server that goes on. The sweep at the start has no mutant (it is in
`proxy/engine.cho`, which the group does not mutate); it is held by the test's "each life serves", which failed before the change.

*Limits.* **A full disk still stops the server**; someone has to start it again, and it then has only what its own file can give back. A server whose disk is
smaller than twice its data and 8 MiB (6aw's mark) stops at intervals rather than sweeping when it is short: the sweep is tied to the file's size, not to the room
left, which the server does not ask about. A failing `fsync` and a write failing inside the file were not provoked. The clients connected when it stops are cut
off; only the one whose commit failed is told why.

## 6az. The server under load for a while, and what it found

Nothing had run for longer than a test. `tests/engine_soak.py` holds the server to what must be true in any order of several clients: money moved between 200
accounts in transactions is never made or lost (two readers ask for the sum throughout); a journal has one row for every transfer acknowledged and no other; the
export tool keeps a copy of the log beside the running server; a client takes the head of the log (6ax) and the copy must come to hold it; the server is killed
every 20 to 40 seconds and started again; at the end everything exported at one anchor verifies to `final`.

**Found in the first minute: the export tool was of no use beside a busy server.** 6av's rule was that any commit made while the tool read made its output
unbelievable. Measured with 4 writers (a commit every 10 to 15 ms): 8 runs whole against 110 `export-raced` in 45 seconds, and fewer as the log grew, because a
run read the whole log again (9 ms for 1,000 commits, 6av) and so took longer than the time between two commits. 6av's own measure, "55 to 57 runs whole, 46 to
73 raced", was of a log of 481 commits; its limit said a run "may never be whole" under writers that never pause, "not met". It is met at once.
*(C189 and 6av corrected in place.)*

**Changed, three things.**

- *The anchor is one key.* `anchor` reads the head of the log (`tables.head_key`, as `cancho_last_commit()` does) and no record.
- *A copy is kept up in parts.* `log UPTO FROM` and `facts UPTO FROM` write what a copy that has `FROM` commits lacks, with no header. For the parts of the
  store to be numbered as the whole, a line's number is now its commit's number times 10,000,000 and its place in the commit (the specification asks only that
  it be unique in the file and order a commit's lines).
- *What disturbs a reader is a sweep, not a commit.* **A read (`src/pager.cho`, `src/pstore.cho`):** a page is written again only if it is on the pager's free
  list, and only `pstore.sweep` puts pages there. A commit writes new pages and leaves the old; so a reader that loaded one state reads that state's pages whole
  however many commits follow, until a sweep frees some of them. *(Amended in 6be: a statement that reads the past also gives back the pages it built its view of. Those were made in its own window and no root
  named them, so a reader of a committed state never had them to read.)* So the server now **says in the tree that a sweep is coming**: a number under the log's space
  (`tables.sweeps_key`) that the commit before a sweep raises, and the first commit of every run (for the sweep made at the start, 6ay, which has no commit of its
  own). The tool reads the number when it begins and, from the state the file is in when it ends, again: if it is not the same, `export-raced`. `logexport
  PAGEFILE sweeps` prints it.

*What that argument leaves.* (1) A reader that began before the server was stopped, where the server has started again (its sweep zeroing pages) and made no
commit yet: the number is the same, and the reader may meet a zeroed page. A zeroed page does not pass its checksum, so the reader says `export-damaged` of a file
that is not damaged; it does not believe a wrong page. (2) The second reading of the number is itself a read of the file, three pages; two sweeps would have to
fall inside it for it to be wrong. Neither was provoked.

**Test.** `tests/engine_wire.py` (`raced`), made certain and not left to chance: the tool is held in the middle of a log of 1,500 commits by its output not
being taken (a pipe holds 64 KiB; the log is 500). While it is held: 20 commits and no sweep, and its log must be whole and verify; then commits until `sweeps`
changes and 300 more to write over the freed pages, and it must say `export-raced`. `tests/engine_log.py`: the log and the store written in 5 parts are the
whole, byte for byte. `tests/engine_soak.py` for 60 seconds is a step of the gate; the long runs are by hand, below.

**Built.** `tests/engine_soak.py`; `tables.sweeps_key`, `sweeps`, `sweeps_raise`; `serve.sweep_due`, `announce`; in `proxy/logexport.cho` `count` (the head),
`FROM`, `sweeps`, the check at the end. Measured:

- **Ten minutes** (4 writers, 2 readers, the exporter, a kill every 20 to 40 s; seed 2): 52,292 commits through 18 kills. The sum read 26,490 times, always
  200,000. The journal has the 52,287 transfers acknowledged and 1 of the 15 whose commit was sent and never answered, and no other; 290 transfers would have
  overdrawn and were rolled back by their client. The exporter: 413 runs whole, 1 raced (before the change, 8 against 110 in 45 seconds); 206 parts appended,
  206 times the copy came to hold a head a client had taken; the copy (51,595 commits) is the beginning of what is exported whole at the end, byte for byte. At
  the end the log, the facts and the rows verify to `final` (5 s).
- *Throughput did not fall:* 2,870 commits in the first 30 seconds, 2,758 in the last 34.
- **The page file grows without bound, as 6aw's limit said, and this is its measure:** 23 MiB at 30 s, 143 at 282 s, 283 at the end; 5.5 KiB a commit, a straight
  line. Nearly all of it is in use by 6aw's count: the old versions of 200 rows changed 100,000 times, and the log. At this load that is 1.7 GB an hour. Nothing
  takes it back; what may be dropped, and when, is the next part.
- The race made certain (`raced`): held through 20 commits, whole and verifying; held through a sweep, `export-raced`; held through a kill, a start and 5
  commits, `export-raced`, the number one more.
- The parts: 5 parts of the log and of the store are the whole, byte for byte; a part of nothing is empty.
- Mutants: the export tool's 23 (6 new, 7 rewritten for the new code), 1 new of the server (`sweep:`), and those of 6aw and 6ay again: all killed. One written
  and taken out: *a sweep made though the commit before it did not say so* survived, because the only way to it is the page of the catalog that the commit itself
  writes crossing the mark, which no test reaches; the code asks the question once, before the commit, so that it cannot happen, and nothing holds that but
  reading it.

*Limits.* Ten minutes is not days. One machine, one disk, a loopback socket. The load is one shape (short transactions on two tables). The exporter and the
server are on one machine: nothing was carried anywhere. What the argument about readers leaves is said above and was not provoked. The growth is unbounded.

## 6ba. What the page file grows by, and the log's oldest part taken out of it

6az measured the growth (5.5 KiB a commit, without bound) and guessed at its parts. This measures them and takes out the largest.

**Measured first** (`logexport PAGEFILE usage`, new: the entries and the bytes of keys and values under each kind of key; 5,000 transfers of 6az's load in one
process, swept):

| what | bytes a commit | share |
|---|---|---|
| the log's records | 497 | 31% |
| the statements' records (6au) | 500 | 31% |
| the facts (6as) | 355 | 22% |
| the history of the rows (6n) | 176 | 11% |
| the rows (the journal's, which is data) | 82 | 5% |

1,610 bytes of keys and values a commit, 2,849 of pages in use; between two sweeps up to twice that is on the disk. **The log is 84% of it; the history of the
rows, which is what I had proposed to trim, 11%.** That proposal was made before measuring and would have done little.

**Design. The log's place is the copy, not the page file.** The page file holds the log so that a commit and its record cannot come apart (6as). Once a part of
it has been written out by the export tool and is kept elsewhere, the page file's copy of that part is a second copy. So:

- `select cancho_log_archive(N)` takes out of the tree the record, the facts and the statements' records of every commit before `N` that it still has, and
  writes under the log's space the number of the first commit it still has (the **floor**). It answers `floor` and `commits`. The head of the log stays: the next
  commit chains to it as before, and `cancho_last_commit()` answers as before.
- *It is the caller's word that the copy exists.* The engine cannot know. So it is a call a token must name (`call cancho_log_archive`), nothing does it
  unasked, and what it takes out is gone from this file. **Nothing is dropped automatically.**
- *At most 128 commits a call* (`facts.archive_step`): the others wait while a statement runs; the caller calls again until the floor is where it asked.
- *More commits than the log has* is refused, `archive-ahead`. Less than the floor changes nothing.
- *The tool knows the floor.* `logexport PAGEFILE floor`; `log`, `facts` and `stmts` from before it are refused `export-archived`. And since the statements'
  store was written whole or not at all, `stmts UPTO FROM` now writes those the commits `FROM` to `UPTO` name, so that the copy has them before they are taken
  out.
- *It makes no commit of the log* (it changes no row, as a table made does not, 6ah): the log does not say that it was archived, or by whom. The floor in the
  tree says where; who, nothing.

*Not in this part:* the history of the rows (11%, and no statement of the server reads it: `AS OF` is the test program's alone); a verifier that reads a log
that begins after its first commit (the copy is whole, so none is needed); a floor per branch.

**Found while building, by hand before any test:** the call was sealed as a commit of the log carrying the facts of the statement *before* it. A commit is made
when a statement "changed rows", read from a count the statement leaves in the work area, and the new call left the last statement's count there. It now clears
it, the test runs a row-changing statement first in the same process, and a mutant puts the fault back.

**Test.** `tests/engine_log.py` (`archiving`): a copy of the first five sixths of the log is taken; the call is refused for one commit too many and for what is
not a number; the commits go out 128 a call; `usage` after shows the facts and the statements of the commits left and of no other, and every row; the tool
writes the rest from the floor and is refused from before it; the copy and the rest are the log, the facts and the statements as they were; a commit made after
continues the copy, which verifies at `level=2+ir` with the three L2 verifiers and to `final` with the L3a ones against the rows the file holds.
`tests/engine_wire.py`: through the server, who may call it, both protocols, and the floor after a kill. `tests/engine_soak.py ... archive`: the exporter has the
server take out what the copy has, through the load.

**Built.** `facts.archive`, `forget`, `floor`; `tables.floor_key`; `drive.archive_upto`; in the tool `usage`, `floor`, `put_stmts`, `export-archived`.
Measured:

- 3 seeds of 2,000 statements (944 to 1,036 commits): all of the test above.
- **Ten minutes of 6az's load with the exporter archiving** (seed 2, 18 kills): 65,542 commits (52,292 without: the tree is smaller and the server a quarter
  faster). The page file **79.4 MiB against 283**, 1.2 KiB a commit against 5.5. The floor at the end is 64,587, where the copy ended. Money, the journal, the
  copy's 188 parts and the replay to `final`: as in 6az.
- What that file holds at the end: rows 5.3 MB (the journal: data), history 11.5 MB, and of the log what the copy had not yet taken, 1.3 MB. So what still grows
  without bound is **the history of the rows, 175 bytes a commit, two thirds of what is left**, and the data itself.
- 12 mutants (8 of the engine, 4 of the tool), all killed. One written and taken out: *a count below zero is archived to* is the same program, the number being
  refused as negative a line later.

*Limits.* **Whoever calls it without a copy has lost that part of the log**, and the engine cannot tell. The call leaves no record of itself in the log. The
history of the rows still grows without bound and nothing reads it in the server. The file does not shrink (6aw): the space is used again, not given back. A
copy is now the only place the old log is: how it is kept, and that it is, is not this repository's.

## 6bb. What the rows were before, taken out of the page file

After 6ba what still grew without bound was the history of the rows (6n): for every key a transaction writes, what it held before, 176 bytes a commit of 6az's
load and two thirds of what was left in the file. **A read (`src/serve.cho`, `src/drive.cho`):** nothing the server runs reads it. `AS OF` is a command of the test
program; the server has no statement for it. A commit's facts are made from the entries of the transaction that is committing, and from no older one
(`facts.take`); an erase deletes a row's entries and needs none to be there.

**Design.**

- `select cancho_history_trim()` takes out of the tree every entry of the history up to the tree's last transaction, at most 256 a call (`facts.trim_step`),
  and answers `removed` (0: there are no more) and `transaction`. A token must name the call. **Nothing does it unasked.**
- *The entries of a transaction that is open stay.* They are of the next number, which the call does not reach: the transaction's commit finds them and makes
  its facts as before.
- *What is trimmed cannot be read again, and says so.* The tree keeps the number of the last transaction trimmed (`tables.trim_key`); `exec.as_of` for a
  transaction before it is refused, `history-trimmed`, where it would otherwise have answered with the rows as they are now and called them the past.
- It makes no commit of the log (6ba), and it is a transaction of the tree: the number goes on by one.

*Not in this part:* a trim up to a chosen transaction (nothing gives a client a transaction's number; when `AS OF` is a statement of the server, this is where it
gets its bound); a trim per branch.

**Test.** `tests/engine_log.py` (`trimming`): the tree is read as of its first transaction; then, inside a transaction that has written a row, the call until it
finds nothing; the transaction writes again and commits. Every entry of the transactions ended is gone and the open one's are there; as of the first transaction
is now `history-trimmed`; the commit continues the copy of 6ba at `level=2+ir` and the replay ends at the rows the file holds. `tests/engine_wire.py`: who may
call it. `tests/engine_soak.py ... archive`: the exporter trims after it archives.

**Built.** `facts.trim`, `tables.trim_key`, the refusal in `exec.as_of`. Measured:

- 3 seeds of 2,000 statements: 2,489 to 2,962 entries (the tree's count of its transactions among them) out in 11 to 13 calls, 3 left (the open transaction's), all of the test.
- **Ten minutes of 6az's load, the exporter archiving and trimming** (seed 2, 16 kills): 67,652 commits; the page file **48.1 MiB** (79.4 with the archive alone,
  283 with neither), 0.7 KiB a commit. 200,175 entries of the history taken out, 2,974 there at the end. Money, the journal and the replay to `final` as before.
- What that file holds: the rows 5.4 MB (67,848 of them: the journal, which is the data), the log not yet copied 2.5 MB, the history 0.2 MB. **What grows now is
  what was put in.**
- 6 mutants, all killed. One survived the first run: the bound of a call was 1,024 entries and the test's small history had 551, so a call with no bound did the
  same. The bound is 256 and the test asks that some call meets it.

*Limits.* What a row was before is gone for good, for anyone: an operator who wants `AS OF` later must not call this. The server still has no `AS OF`, so today
the history it keeps until trimmed is of use to nobody; whether to write it at all when nothing will read it is a question this does not answer. The call leaves
no record in the log. The file does not shrink.

## 6bc. The schema a commit began with, definitions as commits, and what an erase had left behind

**What was missing.** A commit's `schema` field was zeros (6ah), and a statement that made, changed or dropped a table, an index or a sequence was no commit
unless it also changed rows: the log could not say that the schema had changed, and a server that had only made tables had no log (6av found that).

**Design.**

- *`schema` is what the proxy's is* (`docs/m1-proxy.md`: "the hash of the snapshot read before the transaction's first statement"): SHA-256 of the text the
  lowering reads (`exec.schema`), taken of the tree the transaction began on. It is computed when the commit is made, from that tree, which the transaction did
  not change.
- *A definition is a commit.* A statement whose IR is a `Ddl` (and the engine's forms told as one: a renaming, a sequence made, 6au) makes a commit though it
  changes no row: its statements, its effects (`define`), who and when, and no fact. In a transaction, a definition makes the transaction one that commits to the
  log. A definition rolled back, a select, a transaction that only reads: none, as before. With no key there is no log and nothing changes.
- So two commits one after the other with different `schema` say that a definition lies between them, and the commit between says which names and who.

*What the hash is of, said plainly.* The snapshot is the names: each table with its columns, and each index with its table. **A column's type is not in it**, nor
a default, nor a key. That is the proxy's snapshot (it is what the lowering needs), not a description of the schema. A sequence is not in it at all: making one
is a commit that changes no `schema`.

**Test.** `tests/engine_log.py`: the schema is asked for (`!schema`, new in the test program) before every statement outside a transaction and before every
`begin`; each commit's `schema` is the hash of the last one asked before it. `definitions`: a table made, a transaction of two definitions, a sequence, a
renaming and a table dropped are five commits with exactly their definitions for effects; a reading transaction, a select and a definition rolled back are none;
the log of the five verifies.

**Found by this, and nothing to do with schemas: an erase left the key of the row in the file.** The new commits moved where pages of the tree were split, and
the test that erases one row and searches the file for it (6au's needle) failed: the row's key was in the file, in an internal page of the tree. **A read
(`src/btree.cho`, the header):** an internal page's key is "the least key that can be in" a child. It is copied from a leaf when a page is split, and when that
entry is deleted the copy stays, a bound as good as before. So the key of a row that was deleted and erased, and the keys of its history entries (which hold the
row's key), could remain. The older tests erased one row or three, and passed by where the splits fell. C158 said "no byte" of them is in the file; that was
measured for its three rows and is false in general.

- *Measured first, with a test that does not leave it to chance* (`tests/engine_erase.py`: 600 rows with text keys in each of two tables, one with an index on a
  text column, a third updated, half erased, some after an ordinary delete; two commits and a sweep; the whole file searched for each erased row's key, value,
  later value and indexed value, whole and their first 12 bytes): **26 to 32 of 300 erased keys were still in the file**, every one in an internal page, on each
  of 3 seeds.
- *Fixed* (`btree.scrub`, called by `execw.erase` for the row's key and for each history entry's): on the path to where the key was, an internal page's key
  equal to it is replaced by the first bytes (as many, or fewer) of the least key the child now holds. That is a bound as good, and no longer, so the page needs
  no room. If the least key there begins with the erased one, it stays: the file has those bytes in a row that is there. After the fix: none found, on 5 seeds,
  and the rows not erased are read whole by key and by the index.

**Built.** `session.schema_hash`, `exec.stmts_define`, the `schema` given to `facts.seal`; `btree.scrub`, `least`; `!schema`. Measured: 3 seeds of 2,000
statements, every commit's `schema` the one before its transaction (dozens of different schemas a history); `definitions`; the erase test on 3 seeds in the gate;
the server's tests with every table made now a commit (a load of 480 rows in 4 tables is 485 commits). 9 mutants (5 of the log, 4 of the scrub), all killed.

*Limits.* The hash is of names, not of types. **An erase is still the test program's command**: the server has no statement for it, so no client could have been
told a row was erased that was not; what was false was the claim. The scrub covers the path to the key in the tree as it is when the erase runs: a tree of
another branch that shares the page (a fork) keeps the page until it is swept, as it keeps the row. An ordinary delete still leaves its key in an internal page,
as it leaves the row in the history: only an erase promises otherwise. A key cut short may still show the first bytes of a neighbour's key, which is a row
that is there.

## 6bd. The root's list of revoked tokens, read by the server

A token is a bearer's: whoever has it is let in until it expires (6at), and the server read no list of the ones the root has taken back. The list exists since M1
(`docs/spec/token.md` section 3: `CHODBRV1`, then entries of a token's id, a time `since`, and the root's signature over both) and the verifiers read it; only
the server did not. So a commit the server made under a revoked token was one a verifier would refuse afterwards, and nothing stopped it being made.

**Design.**

- *The server is given the file* (`engine ... IDLE_MS WRITE_MS REVOKEDFILE`, with a root key). It reads it when it starts and again whenever the file's size is
  not what it was, looked at on every turn of its loop, which is at least once a second. The specification's list is added to and never rewritten, so its size
  says whether it changed.
- *Every entry is checked under the root's key.* **A list that does not check is no list to go by**: a file cut short, another magic, an entry the root did
  not sign, more than 256 entries. Until it checks again nobody is let in (`login-revocations-unreadable`) and who is in runs nothing more
  (`revocations-unreadable`). The other choice, to go on with the last list that checked, lets whoever can damage the file undo a revocation.
- *A token is revoked if it, or any token it was made from, is on the list* with a `since` that has come (each prefix of its blocks: the specification's rule,
  and the verifier's).
- *At the login:* refused, `28P01 login-revoked`. *After it:* the next message of a connection whose token has been revoked since is answered
  `28P01 token-revoked` and the connection is ended; a transaction it had open is rolled back, as for any connection that ends.
- The list is kept among the server's own numbers (ten for an entry), so every place that judges a statement has it without being handed it.

*Not in this part:* TLS (the token still travels in clear: it is to be ended in front of the server (*corrected, 6bq: the server ends it itself*), and until it is, a token read off the wire can be revoked
but not kept secret); a way to tell the server to look now (it looks within a second); a list larger than 256; the proxy, which still reads none.

**Test.** `tests/engine_wire.py` (`revocations`), with `tools/mint.py revoke` (new) making entries. An empty list lets everyone in. A token made from one that
is then revoked runs nothing more and is not let in again, and the others go on. A revocation from a time not yet come changes nothing. A token revoked while its
transaction is open: the commit is refused, the connection ended, the row not there. `tools/verify.py --revoked` with the same list accepts the server's log.
An entry signed by another root: nobody is let in, and who is in runs nothing more.

**Built.** `src/revoke.cho` (`load`, `hit`), `serve.revocations`, `standing`; the eighth word of the server's command line. Measured: all of the test; the
revocation takes effect at the token's next message, within the 1.3 s the test waits. 7 mutants (`revoke:`, group `wire`), all killed.

*Found while testing.* A revocation dated before commits the token had already made makes the verifier refuse those commits, which is the specification's
meaning of `since` and not a fault: the root can say "from then on this token was not to be trusted". The server cannot undo what it let through before it was
told; the test dates its revocations at the moment they are written.

*Limits.* The token is still sent in clear. Between a revocation being written and the server's next turn (a second at most) a statement can still run. A
damaged list stops everyone, by design: whoever can write the file can stop the server's clients, as they could by deleting the page file. 256 entries. The
clock is the server's.

## 6be. A table read as it was at a commit, through the server

The engine has kept what every row was before each transaction since 6n, and could put a tree back to any of them (`exec.as_of`, by the tree's own count of its
transactions). Only the test program could ask. The server had no statement for it, so the history it wrote was read by nobody (6bb said so). The statement has
existed since M2: `select ... from t as of '<commit id>'`, the proxy's (`docs/m2-branches.md` D8), which the lexer, the parser and the lowering accept and the
engine refused when it came to run it.

**Design.**

- *The commit is the client's handle.* A client has a commit's id from `cancho_last_commit()` (6ax). The tree counts transactions, not commits (a statement
  that fails, a trim, an archive are transactions and no commits), so each commit now writes, under its id, which transaction it was (`tables.asof_key`), and
  `AS OF` a commit is `exec.as_of` that transaction.
- *One tree a statement.* The engine runs a statement over one tree. So every table of the statement is read as of the same commit: one table as it was beside
  one as it is, or two commits, is refused `engine-unsupported`. The proxy can do those, table by table; the engine cannot yet.
- *The names are found in the tree as it was.* The schema the statement is lowered against is the one of that commit: a table since dropped is there, a column
  since added is not.
- *Two lowerings.* The IR that is kept (for the token, for the log if the statement is in a transaction that commits) names each table `t@<commit>`, as the
  specification asks (`docs/spec/ir.md` section 6.1); the one that is run names it `t`, over the tree as it was. The lowering writes either, by a flag.
- *What a token needs is the specification's:* a pattern matches the name as written, so `r:t` does not reach the past and `r:t@*` does not reach the present.
- *Nothing of it is the branch's.* The tree read is forgotten when the statement ends and the branch is as it was; in a transaction the past is the past,
  whatever the transaction has done.
- *What is refused and how:* a commit the tree has no record of, `asof-unknown-commit` (nobody made it, or its record was archived, 6ba: the archive takes the
  handle with it); a past that was trimmed, `history-trimmed` (6bb); a write `AS OF`, by the lowering as before.

**Found while building: reading the past made the file grow.** Putting a tree back writes pages (the tree is copied on write), and they were given back only by
a sweep, which runs after a commit. Measured: 300 reads of a table as it was 2,000 transactions ago, with no write, grew the page file from 13.4 MB to 24.4 MB.
Now the pages a statement built its view of are given back when it ends (`pager.recycle`): after, the same 300 reads leave the file at 13.4 MB. This is a second
way for a page to be written again besides a sweep (6az's argument for the export tool said there was one): the pages given back were made in the statement's own
window and no root ever named them, so no reader of a committed state had them to read. 6az's argument stands for that reason and is amended there.

*Not in this part:* one statement over two times; a self-join (refused by the engine with or without `AS OF`); `AS OF` a time rather than a commit; branches.

**Test.** `tests/engine_log.py` (`as_of`): four commits' ids taken as a history goes; a table read as of each is the table as it was (rows since changed or
deleted, a column not yet added, a table since dropped, two tables joined as of one commit); refused: two commits, one table as it was beside one as it is, a
commit nobody made, a write; in a transaction the past is not what the transaction did, and its commit, which names the read, verifies at `level=2+ir` with the
three L2 verifiers; after a trim `history-trimmed`, after the archive `asof-unknown-commit`. `tests/engine_wire.py` (`history`): through the server by both
protocols; a token for the past and one for the present, each refused the other; 300 reads and the file not a page larger.

**Built.** `drive.as_of_view`, `select_as_of`; `facts.txn_of` and the key written by `facts.seal`; `lower`'s flag for plain names; `pager.recycle`. Measured:
all of the test, on 3 seeds of the log's test; a read of 200 rows as they were 2,000 transactions ago takes 10.6 ms through the server (the cost is the
transactions since: each one's entries are applied to get back); 800 such reads leave the page file exactly the size it was. 9 mutants (8 of the engine, 1 of the
server), all killed. Two written and taken out as the same program: an archive that throws away the tree its deletion answered (the tree deletes in place within
a statement), and a page given back that keeps its mark.

*Limits.* **A read of the past costs the whole of what happened since**, and holds the server while it runs: far back in a long history is slow, and nothing
bounds it. One commit a statement, every table of it. No self-join. The handle is the commit's id, which a client must have kept: there is no way to ask for
"an hour ago". A commit's handle goes with its record when the log is archived, though the rows' past may still be there. The past of a row that was erased is
not there, which is what an erase is for.

## 6bf. A row erased, through the server

The engine has been able to erase a row and its past since 6n, and only the test program could ask (`!erase`). The proxy's clients have had a statement for it
since M2g: `select cancho_erase('<table>', '<key>')` (`docs/m2g-erasure.md` 6d). This is that statement, answered by the engine.

**Design.**

- *The statement.* `select cancho_erase('<table>', '<key>')` and nothing else: the key a JSON array of one value, a whole number or a string, for a table whose
  key is one column of that kind. Anything else that is the call is refused, `erase-malformed`: a key of the other kind, of two values, a table that is not
  there, a table keyed by two columns (the engine erases by one, 6n). A statement of its own, outside a transaction (`25001 erase-in-transaction`), with no
  parameters.
- *What a token needs:* the call `cancho_erase`, and what the DELETE of that row needs (to write the table and read its key). Either missing is `42501`.
- *The row is deleted first, as a DELETE deletes it.* The test program's erase removes a row that is there with no fact for the log, which is what it was made
  for (a row already deleted) and would leave a log whose replay still has the row. So the server runs the DELETE, with its fact, and then the erase of the key:
  the row's history entries, and its key wherever the tree kept it (6bc).
- *The log.* The commit names one statement, the call, its two constants left out like every statement's (6au), and its effect is `call cancho_erase`: the
  specification does not open a call into what it did, and the fact says a row left the table. So the log says **that** an erase was done, by whom and when, and
  that a row left that table; not which key. An erase that removed only a past (the row deleted before) is a commit too. One that found nothing changes nothing
  and is none.
- *Gone when the client is answered.* Erased pages are zeroed by a sweep, and a sweep keeps what either of the file's two last states names. Left to 6aw's rule
  the row would stay in the file until the file had next grown enough. So an erase commits, **commits again**, so that both states are the one without the row,
  and sweeps, before it answers.
- *The answer:* `row` (1 if the row was there) and `past` (how many entries of its history went).

*Not in this part:* erase by a key of several columns; by a condition; of a table that was dropped; of the statements that named the subject (the engine's
records never held their constants, 6au, so there is nothing of the subject in them to erase); a branch.

**Test.** `tests/engine_wire.py` (`erasing`): 40 people in two tables (a text key, one with a quote in it; a number key; an index on a text column), each
updated; five erased from each, one of them deleted first. When the last erase is answered, with the server running, the file is searched for each erased key,
value, earlier value and indexed value, whole and their first 10 bytes. The rows not erased are whole; the table as of a commit before the erases has the
others and not the erased. The refusals. After a kill the file still has nothing of them; each erase that removed something is a commit whose only effect is the
call; the log verifies with the tokens and the statements, and the replay ends at the rows the file holds.

**Built.** `drive.erase_text` (the statement read, the DELETE written, the call as the log is told it), `may_erase`, `keep_erase`; the server's mode of an
erase in `drive.run` (the DELETE, then `execw.erase`); in `serve.answer` the refusals, the second commit and the sweep; `exec.stmts_define` takes the call for
a statement that commits. Measured: all of the test. 10 mutants (`erasing:`, group `wire`), all killed; one survived the first run, a table keyed by two columns
erased by one of them, which no test had: with it the DELETE written names one column and would have deleted every row with that value.

*Found while building.* Erased through the server, the row was first still in the file after the answer: zeroed only by a sweep, and a sweep was not due. The
second commit and the sweep at once are for that. And a token whose effects are listed out of order is no token (`login-bad-token`): the specification's order,
which the test's first token did not have; nothing of the server's.

*Limits.* **An erase costs a pass over the whole file** (the sweep: 0.3 s for 160 MiB, 6aw) and the server answers nobody meanwhile: it is for the request of
a person, not for a batch. One column of key. The log does not say which key was erased; whoever must show that a given person's row was erased has the
commit, its time and its token, and the absence of the row. What is erased is erased in this file: a copy of the page file made before, a backup, the disk
under the file system, are not this program's. The log's copy elsewhere (6ba) holds the row's facts as hashes, with salts that are gone.

## 6bg. What was built one at a time, held together under load

Since the soak of 6az the server has learnt to take the oldest of its log out of the file (6ba), to trim the rows' past (6bb), to make definitions commits
(6bc), to read a table as of a commit (6be) and to erase a row (6bf). Each has a test of its own, with one client and nothing beside it. What this month's
faults had in common is that they were between two things: a sweep and the export tool, a read of the past and the file's size, an erase and the page a
sweep had not reached. So the soak gets the new things as clients of their own, beside the transfers, the readers, the export tool and the kills it had.

**Design.** `tests/engine_soak.py ... SECONDS SEED mixed` (and `archive,mixed`). Nothing in the engine changes for it: it is a test. Three clients more:

- *A definer.* Over and over: a table made, 40 rows, a column added, an index made, 8 rows updated by the indexed column, read back by it (count and sum),
  the table dropped. Every statement's answer is what it must be, or the connection was lost to a kill. Seven commits a round, six of them definitions, so
  the transfers' transactions begin under a schema hash that keeps moving.
- *People.* A person inserted with a secret (their number and 80 random bits), the secret changed, and one person in three erased. The client keeps what
  was acknowledged. At the end, with the server stopped: **the file has no byte of either secret of any person whose erase was answered** (whole, or the
  first 14 bytes, which hold the person's number and so are no one else's), and every person not erased is there with the secret last acknowledged. A
  person under a statement when the server was killed is set aside: nothing is claimed of them. After every fifth erase the file is searched at once, the
  server running: 6bf says gone when the answer comes, and the end of the run cannot tell (see below).
- *The past.* A mark only this client writes is set to the next number and the head of the log taken (`cancho_last_commit()`): as of that head the mark is
  that number, whatever was committed between, and as of a head taken earlier (one of the last 40, at random) it is still the number written then. Then
  `sum(cents), count(*)` of the accounts as of the head: **the first sum, at every commit**, since no commit makes or loses money. The journal as of it read twice, 0.3 s apart: the same both times, and no more rows than the journal has now. Without
  `archive` no reading may be refused. With it a reading may be refused `history-trimmed` or `asof-unknown-commit`, and for no other reason.

What stays held from 6az: the sum at every reading of the present, the journal against the acknowledgements, the copy kept up by the export tool and
verified, and at the end the replay of the whole log ending at the rows the file holds, now through definitions, deletes and erases.

**The checks were made to fail, and two of the first could not.** Each was run against an engine built with one of the mutants of `tests/mutants.py`
(40 s, `mixed`):

- *An erase that does not sweep the file* (`erasing: the file is not swept when a row is erased`) **passed the soak as first written.** The file was
  searched only at the end, after the server had been started once more, and a server sweeps when it starts. The search after an answer is what was added;
  with it this engine and the one that commits an erase once fail on the first erase looked at. An erase that keeps the row's past fails by its answer.
- *A past that is the present* (`history: a known old value is recorded as nothing`) **passed too**: every commit has the same sum, and the journal read
  twice as of a commit is the same wrong thing twice. The mark is what was added; with it this engine fails. Two engines whose past is damaged were refused
  by the first checks already (`engine-damaged` is not an answer the soak allows).
- *A past one commit too early* (`history: AS OF t undoes t as well`) **still passes, and that is a limit of this test**: it shows only as of the mark's
  own commit, and under this load the head a client takes is never its own commit (0 of 135 tries with the statements sent together: the server takes its
  clients in turn). One client alone sees it at the first read, and `tests/engine_wire.py` fails on that engine.

*What it does not hold.* That an erased person is out of the *copy*: the copy is the export tool's, outside the file, and has the facts of the insert (6bf's
limit, unchanged). That two definers at once agree: there is one. How long a client waits while an erase sweeps: not measured here.

**Measured** (by hand; the gate runs `60 1 archive,mixed`).

| run | commits | kills | people erased (searched at once) | tables made and dropped | the past read (mark) | page file at the end | commits a second, first and last minute |
|---|---|---|---|---|---|---|---|
| 30 min, `mixed`, the first checks | 53,647 | 54 | 803 (none) | 1,273 | 985 (none) | 193.0 MiB | 110, 20 |
| 60 min, `archive,mixed`, the checks as they are | 291,097 | 81 | 4,364 (873) | 6,918 | 2,161 (3,577) | 71.5 MiB | 100, 55 |

In both every check passed: the sum at every reading (20,071 and 108,781), the journal against the acknowledgements (40,032 and 214,527 transfers), the
copy verifying beside the load, and at the end the whole log replayed to the rows the file holds, through the definitions, the deletes and the erases (7 s
and 28 s). In the hour 1,965 readings of the past were refused, all as trimmed or archived; 1,590,919 history entries were trimmed and 288,152 commits
archived as the load went. No fault of the engine was found by either run.

*What the runs did show.*

- **An erase costs the whole file, and under load that is the server's throughput.** Without the archive the file grew to 193 MiB and commits fell from
  110 a second to 20: an erase about every second, each sweeping every page while every client waits (6bf's limit, with its number under load). With the
  archive the file stayed under 72 MiB and the fall was to 55. *(Corrected by 6bh: the sweep was a third of it. An erase also reads every history entry
  the file has to find the row's own, and in this run, with nothing trimmed, that was the larger part Corrected again by 6bj: commits a second in the soak measure the soak's load, whose own questions grow with what it has written; they are not the engine's throughput.)*
- **The test's own search was slower than its load.** One search of the file for each secret took 12 minutes after the hour, with 4,364 people erased. It is
  one pass now: every secret begins with its person's number, so whatever in the file begins as a secret does is looked up once.
- The 30 minutes were run before the search at once and the mark were added; the hour has both.


## 6bh. An erase that costs what was written since the last one, not the file

6bf's limit, with 6bg's number: an erase sweeps the whole file while every client waits, and under load that was the server's throughput (110 commits a
second to 20 at 193 MiB). The sweep is the engine's only way to find the pages nothing names: it walks every tree from its root and zeroes the rest.

**What does not work** (and was first proposed): to zero only the pages the erase itself replaced. A page is copied when it is changed, and the copy before
stays in the file until a sweep. A row erased today is in the copies that last week's commits left behind, and nothing says where those are.

**Design.** The pager remembers which pages it has handed out since a point where the file was known clean (the *base*: a tree, and nothing else in the file
but zeroed pages). At an erase the garbage is then worked out from two trees and that list, with no walk of what did not change:

- *Born.* Every page handed out since the base, a mark for each and a list of them (`pager.alloc`). A page that was not born since the base and is in the
  tree now was in the tree at the base: pages are never changed in place once a root names them, so the whole of what is under such a page is as it was.
- *Live and new.* From the root as it is now, down through born pages only. A page reached that was not born is *kept*: it and all under it are the base's
  and still in use, and it is not read.
- *Dead and old.* From the base's root down, stopping at kept pages. Whatever else is reached was in the base's tree and is in no kept part of it: no
  root names it now. A tree has one way to each page, so a page under a kept page is never reached another way.
- *Garbage* is the dead and old, and the born that are not live and new: pages of statements that failed or were rolled back, pages one statement of a
  transaction wrote and the next replaced, the catalog pages of commits since. Except the two catalog pages the two superblocks name now.
- The garbage is zeroed and made free, the file synced, and the tree as it is now is the new base. A crash in the middle leaves pages zeroed that nothing
  names, as for a sweep.

*Why not a list of pages as they are replaced* (the second proposal): what a statement replaced is still in use if the statement fails, if the transaction
is rolled back, or if the tree was built only to be read (6be). Each such path would have to take its entries back, and one path missed zeroes a page in
use. This design asks nothing of those paths: it reads what the trees are, not how they came to be.

*When it may be used* (otherwise the erase sweeps as it does today, and that sweep makes a base):

- There is a base. A sweep makes one if, when it ran, both superblocks named the tree it was given: otherwise the state before the last commit is in the
  file and in neither tree. An erase's own sweep qualifies (the commit is made twice, 6bf); the sweep at start and the sweeps for size usually do not, so
  the first erase after one of those sweeps the file.
- Both superblocks name the tree as it is now, and it is the only tree (the test program's branches share pages between trees; the server has one).
- The list of born pages did not overflow (262,144 pages, 1 GiB written since the base).

*Pages given back by a read of the past* (`pager.recycle`, 6be) were free and not zeroed: nothing needed them zeroed before the next sweep. Now an erase
may come before it. They are marked, stay free, and are zeroed by the next erase. A page of them that was handed out again in between is an ordinary
born page.

*The test program checks every use.* `!purge` in the test program runs the same code and then the old one beside it: every tree walked from its root as
the sweep does, and (a) **no page the erase would zero is one the walk reaches** (else `purge-unsafe`: it would have destroyed a page in use), (b) **every
page the walk does not reach, and the erase would not zero, is zeros already** (else `purge-incomplete`: something erased could be left). Both are refusals
before a byte is written. The server does not run the walk: that is the cost this section removes.

**Test** (written first; `tests/engine_erase.py`, a second part). A workload of the seed: rows inserted, updated and deleted in two tables, alone and in
transactions, some rolled back, some statements that fail half-way (a duplicate key in the last row of an insert of many), reads as of an earlier
transaction, erases; and after every few statements two commits and `!purge`. Every `!purge` after the first sweep must use the list (not fall back),
and pass both checks; at the end no erased key or value is in the file and every other row is read whole. Then the cases that must fall back, each
shown to: no sweep yet, one commit only, a second branch, a sweep that did not leave a base. Through the server: `tests/engine_wire.py` (`erasing`) and
the soak (6bg) as they are, which hold an erase to "gone when answered" and the file to "every row readable", whichever way the garbage was found.

**Built.** `pager.alloc` marks and lists what it hands out; `pager.rebase` starts a base; `pager.recycle` marks what it gives back. `pstore.purge` is the
design above; `pstore.sweep` leaves a base when both superblocks named the one tree it was given (the walk it shares with the check is `mark_all`). The
server (`serve.answer`) tries `purge` after an erase's two commits and sweeps if it answers `no_base()` or a sweep for size is due anyway. The test program
has `!purge`, always checked; the server checks when its command line ends with `check-purge`, which every test's server does.

**Measured.**

- *The check* (`tests/engine_erase.py`, three seeds): 126 purges each, after 92 to 109 erases, 34 to 36 transactions, 29 to 51 rollbacks, 53 to 62 statements
  that failed half-way and 40 to 52 reads of the past; about 6,200 pages zeroed a run; never unsafe, never incomplete, never a fall back after the first
  sweep. No erased key or value in the file, every other row read whole. The five cases that must fall back do.
- *Through the server*: `tests/engine_wire.py` passes with every erase checked. A part of it is new (`erasing_after_the_past`): 1,500 rows; three times 150 of
  them are updated, the table is read as it was before (most of its leaves are written again into pages that are then given back) and 5 of the rows are
  erased, the file searched after each; then 1,200 updates and every row read back. The first form of it, with 60 rows, **could not fail**: the erase took
  the few pages the read had given back off the free list and wrote over them. With 1,500 an engine that does not zero those pages leaves the secret in
  the file, and one that makes them free twice hands a page out twice and the log's replay no longer ends at the rows.
- *Mutants*: 10 of the purge (`scrub: purge:`, judged by `tests/engine_erase.py`), 2 of the pages a read of the past gives back (`erasing:`, by
  `tests/engine_wire.py`), all killed; the 6 older mutants of the sweep's walk moved with the code and are killed as before (the page store's 40 of 40).
- *The time of an erase* (one client, a file of 110 MiB, 40 erases, each after an update; the server without the check):

  | | before | after |
  |---|---|---|
  | the first erase after a start | 368 ms | 424 ms (it sweeps: the base) |
  | the next 39, median | 323 ms | **15 ms** |
  | the next 39, the slowest | 400 ms | 17 ms |

**Found by measuring, and not what this section set out to fix.** Those numbers are with the history trimmed (6bb). With the history of the 400,000
rows that filled the file still in it, an erase took 1,373 ms before and 1,104 ms after: **an erase reads every history entry in the file.** The history
is kept by transaction and then by key, so the entries of one row are found by reading all of them (`execw.erase`, since 6n). In the test program, on
that file: the erase itself 1.05 s, a sweep 0.43 s. 6bg put the whole fall in throughput down to the sweep; it was a third of it (corrected there and in
C200, C201). What this section built removes the sweep's part. The scan's part is as it was, and is the next thing: it needs the history findable by key.

*What it will not do.* A sweep for size still walks the file and holds the server (6aw): this is for erases. The first erase after a start or after a
sweep for size still sweeps. Nothing a client sees says which way an erase went; the measure is the time.

## 6bi. The history of one row, found without reading everyone's

6bh's finding: an erase reads every history entry in the file to find one row's (1.05 s for 400,000). The history is kept under the transaction's number
and then the key, newest first, because that is the order a read of the past undoes it in (6n). Nothing finds an entry by its key.

**Design.**

- *A second entry, by key.* Wherever a history entry is written (`exec.remember`, `exec.remember_known`) one more key is: the log space, kind 13, the tree
  key, and the transaction's number as the history has it (so newest first). One byte for a value. The entries of one key are next to each other.
- *An erase* reads the entries that begin as the row's key does and are exactly that much longer, and for each removes the history entry of that transaction and key, and the entry itself; the keys are scrubbed from the internal pages as before (6bc), the
  new entries' too, since they hold the row's key.
- *A trim* (6bb) removes the by-key entry with each history entry it removes.
- *A read of the past* does not use them and does not see them: it undoes the history, which is where it was.

*Files written before this.* Their history has no such entries, and an erase that trusted the new ones would leave a row's past in the file. So the
tree says whether its history is all findable by key: a mark (kind 14) written with the first transaction of a new tree, or by a trim that finds no
history left to take (from then every entry is one written since). **Without the mark an erase reads all of the history, as it did.** An old file is
brought over by trimming its history.

*The cost*, measured on a prototype before this was designed (the soak of 6az, 60 s, twice each): 4,920 and 4,716 commits without, 4,860 and 4,535
with; 7.1 and 7.2 KiB a commit without, 7.3 and 7.5 with. A few percent at most of either, inside what two runs of the same binary differ by.

**Test** (first). `tests/engine_erase.py`: the search of the whole file after the erases already holds an erase to every value a row ever had, so an
entry the new way misses is found there; it gains (a) the count each erase answers, held to the number of times the row was written, (b) a file with no
mark (the test program removes the mark and the by-key entries: `!unindex`), where erases must do as much, and after a trim to the end must have the mark
again (`!indexed`), (c) a row whose key begins another's. `tests/engine_log.py` (`trimming`): after a trim to the end no by-key entry is left (the tool's
`usage` counts them). The time: the 110 MiB file of 6bh with its history not trimmed.

**Built.** `tables.past_key`, `past_prefix`, `indexed_key`; `exec.by_key` (called where `remember` and `remember_known` write an entry) and the mark in
`exec.mark_txn` at a tree's first transaction; `execw.erase` goes by the entries when the tree has its mark and reads all of the history when it has
not (and there removes an entry by key that it meets, since a file being brought over has some); `facts.trim` removes each with the entry it found, and
gives the mark when it finds no history left. The test program: `!indexed`, `!unindex`. The export tool's `usage` counts them (`by-key`).

**Measured.**

- *The time of an erase*, the 104 MiB file of 6bh with the history of its 400,000 rows not trimmed, 40 erases, one client, the server without the check:

  | | before 6bh | with 6bh | with this |
  |---|---|---|---|
  | the first erase after a start (it sweeps) | 1.3 s | 1.3 s | 343 ms |
  | the next 39, median | 1,373 ms | 1,104 ms | **9.5 ms** |
  | the next 39, the slowest | 1,838 ms | 1,526 ms | 15 ms |

- *Under load* (the soak of 6bg, `1800 3 mixed`, the same seed and length as its first run; the server without the check): 86,571 commits through 51
  kills where there were 53,647, 1,527 people erased where there were 803, every check passing. The file ended at 332 MiB (193 then: more was
  written). Commits a second in the last minute: 35, at 332 MiB, where there were 20 at 193. *It still falls as the file grows*, and an erase is no
  longer why: what is left that costs the whole file is the sweep when the server starts (51 kills in this run), the sweeps for size, and a read of the
  past that undoes more the more there is. Not taken apart here. *(Taken apart in 6bj: most of the fall is the soak's own questions, which grow with what
  it has written.)*
- *What an erase answers* (`tests/engine_erase.py`, three seeds): each of about 100 erases among transactions, rollbacks and statements that fail answers
  the row and one entry for every transaction that wrote it, no more and no fewer; and the search of the file finds nothing of them.
- *A file from before* (the same test, `by_key`): with the mark and the entries taken out, 30 rows written by 4 transactions each answer 5, all of their
  history; `!indexed` says no; one trim that takes 256 entries and leaves others does not give the mark; a trim to the end does, and 30 rows updated and
  erased after it answer 2.
- *A trim* (`tests/engine_log.py`): before and after it there is one entry by key for each history entry.
- *Mutants*: 9 (`scrub: by key:`, and one of the trim under `log:`), all killed. Two were wrong first and are worth the note. One was a mutant of
  nothing: "an erase takes the entries of a key that only begins as the row's" cannot be killed because no key begins another (a text ends with a
  terminator, a number is 8 bytes, `row.cho`); the check of the length stays, and the test's rows with a key one letter longer are there for a
  format that might change. The other, "a trim leaves the entries", survived by ignoring what `btree.del` answered: a page the statement itself wrote is
  changed in place, so the entry went anyway. The mutant now does not call it.

**Found by CI, and then by the test it asked for.** Three older mutants survived the first push: they change the reading of all the history, which
the tests now reached only for a file from before. So the erase test of 6bc runs that way on its even seeds (`!unindex` first), and the mutants of that
way are judged by it. Making `!unindex` right (it left the keys it removed as bounds in internal pages, which a file from before never had) raised the
question of what else removes such keys without looking there. **A trim does** (6bb, since it was built): it removes history entries, whose keys hold
rows' keys, and an internal page may keep one as the bound of a child. A row erased afterwards has no entry left for the erase to know that key by.
Measured before the fix (600 rows with text keys, a trim of 256 or 768 entries that leaves the rest, 300 rows erased, three seeds): **1 to 9 of the 300
erased keys still in the file** with this section's entries, and 1 of 300 on one seed of three with the engine as it was before them. A trim to the
end left none, which is why the soak and 6bb's test did not see it: with no history left there are no internal pages of it. `facts.trim` now takes
each key it removes out of the internal pages (`btree.scrub`), the history's and the by-key entry's. `tests/engine_erase.py` (`after_a_trim`) is that
measurement, held to none; two mutants, one for each scrub. C195 and C197 said more than was so and are corrected.

**And a second one, which is 6bc's own.** The second push failed in CI on a check that passed here: a key one letter longer than an erased one, erased
after it, was in the file. It failed here too once in nine runs of the same seed. *(What differed between the runs, found since: the salts of the facts are the
system's unless a test seeds them; a commit's id is made of them; and since 6be the tree keeps a key under each commit's id. So two runs of one input
wrote different trees, 25.3 and 25.1 MiB for the same 600 statements. With `!seed` three runs are the same file byte for byte, and
`tests/engine_erase.py` now seeds every run it makes: a failure of it comes again.)* The bytes were in an internal page, and were **the beginning of the key and not all of it**. When `btree.scrub` takes a key out of an internal
page it puts in its place the beginning of the least key the child now holds, cut to the length of the key that went. That is a piece of a
*neighbour's* key, and shorter than it when the neighbour's key is longer. The erase of the neighbour looked for a bound that was all of its key, and
left the piece. The test of 6bc could not see it: every key in it is of one length, so a piece was never shorter than its key.

- *Measured, with the engine as it was before this section* (`tests/engine_erase.py`, `lengths`: 500 rows with keys of 14 to 65 bytes, 450 erased in an
  order of the seed, the file searched for the first 14 bytes of each): **12, 14 and 15 of the 450 erased keys in the file**, on each of three seeds.
- *The fix*: `btree.scrub` takes out every bound on the path that the key *begins with*, not only one that is all of it (it stays if the child's least
  key begins with it too: those bytes are in a row that is there). The page that holds such a piece is on the path of the key it was cut from, because
  a bound and the child it bounds stay side by side whatever is split above them. With it: none, on the three seeds.
- Two mutants of it (a bound that is all of the key only; after the first bound of a page the others not looked at). C197 is corrected a second time.

**What else removes keys, looked at after the two.** `tests/engine_erase.py` (`beside_an_index`): 500 rows with an index on a column, names and
values of 14 to 65 bytes, half updated in the indexed column, a third deleted by an ordinary statement before the erase, 450 erased; the file searched
for the first 14 bytes of every name, value and earlier value. None, on three seeds (the engine as it was before this section leaves 14 names in the
same test: it can see what it looks for). What the look found about each way:

- *An index* holds nothing: `CREATE INDEX` records a name and builds no entries (6q), so there is no indexed value in the tree to be left. That is also
  why the indexed values of 6bc's test were never found, by an engine with the fault or without.
- *An ordinary DELETE, and an UPDATE*, leave the key as a bound; the erase that follows takes it out, as 6bc says, and now the pieces of it too.
- *The archive of the log* (6ba) removes records, facts and statements: their keys are numbers and commit ids, and hold nothing of a row.
- *DROP TABLE and TRUNCATE* remove a table's rows and take nothing out of the internal pages, and no erase can follow: the rows are not there to name.
  **A dropped table's keys may be in the file until those pages are written again.** Nothing has claimed otherwise; it is said here so that it is.

*What it will not do.* A file written by this engine and then by an older one has history the mark does not know of: an older engine is not to be run on
it (nothing in the file stops it). An erase is still by one key column (6bf).

## 6bj. Why the soak slows as it runs, each thing measured by itself

6bi left the soak at 35 commits a second after 30 minutes where it began near 100, and said what might be left without measuring it. This is the
measurement: one client, nothing beside it (`tests/engine_grow.py`, run by hand; nothing in the engine changes).

| the file | transfers a second | 200 rows as of about 250 commits back | the start after a kill |
|---|---|---|---|
| 48 MiB | 87 | 12.5 ms | 142 ms |
| 137 MiB | 77 | 8.0 ms | 416 ms |
| 286 MiB | 80 | 8.7 ms | 927 ms |
| 469 MiB | 68 | 11.8 ms | 1,413 ms |

| one row as of | 0 commits back | 100 | 500 | 2,000 | 7,900 |
|---|---|---|---|---|---|
| | 0.2 ms | 1.7 ms | 6.8 ms | 13.4 ms | 51.6 ms |

| a count and a sum over | 5,000 rows | 20,000 | 60,000 |
|---|---|---|---|
| now | 3.3 ms | 12.6 ms | 45.0 ms |
| as of the head | 3.3 ms | 12.6 ms | 47.2 ms |

**What it says.**

- *Commits by themselves fall little*: 87 to 68 transfers a second over a file ten times the size. The tree is deeper and less of it is in the server's
  memory (32 MiB of pages).
- *A read of the past costs what it undoes*, about 7 microseconds an entry, whatever the size of the file: 52 ms for 7,900 commits back.
- *A scan costs its rows*: 45 ms for 60,000.
- *The start after a kill costs the file*: 3 ms a MiB, the sweep before the server serves (6ay). At 10 GiB that would be about half a minute. This is
  the one cost here that is the engine's and grows with the file whatever the clients ask.

**The soak, then.** Its client of the past (6bg) asks, each round: the journal counted and summed as of the head, twice, and once now; and a mark as of
one of its last 40 heads. After 30 minutes the journal has 60,000 rows and 40 rounds are some thousands of commits: about 130 ms of scans and up to
50 ms of undoing in a round of about a second, on a server that answers one statement at a time. With a second of sweep at each of its kills (one in
30 s) and the fall of the commits themselves, that is the soak's fall. **Most of it is the test's own questions growing with what the test has
written**, not a cost the engine puts on every client. 6bg and 6bi read the soak's commits a second as the engine's throughput; they are a measure of
that load, and are corrected to say so where they said more.

*Not done.* The soak is not changed: its questions are the checks, and a soak that asked less would hold less. A bound on them (the journal of the last
minute, say) would make its numbers comparable from run to run; it is left for when a number of it is next needed. The start after a kill is not
changed either: whether a server may serve before it has swept is a question of what a full disk then does (6ay), and wants its own design.

## 6bk. Who took the log's oldest part out, and who trimmed the history: commits of the log

An erase is a commit of the log: who asked and when (6bf). The two other calls that take something out of the page file are not. `cancho_log_archive(n)`
removes records, facts and statements (6ba) and `cancho_history_trim()` removes what the rows were before (6bb); each changes the tree, the page file's
commit makes that durable, and the log has no record that it was done. A reader of the log sees that it starts at a floor and cannot see who put it
there.

**Design.** A call of either that changed the tree is a commit of the log, as an erase is and by the same rule (`exec.stmts_define`: the statement is one
that makes a commit though it changes no row). Its record has no changes; its one statement is the call, with its constant left out as every statement's
is; its effect is the call's name, which is what a token needs to make it (6at). A call that changed nothing (an archive that is already there, a trim
with nothing to take and the tree's mark already set) is no commit, as a statement that wrote nothing is none.

*What follows from it, and is meant.*

- The log grows by a record for each call that did something: an archive of 128 commits a call adds one record for 128 taken, a trim one for 256 entries.
- An archive's own record is after what it took, so it is not taken by that call; a later archive takes it like any record.
- *How much* a call took is not in its record (the constant is left out, and a trim has none): the floor is in the tree, and a copy of the log that was
  kept up has the records before it. What the record adds is who and when.

**Test** (first). `tests/engine_log.py`: after the archive and after the trim the log has, for each call that removed something, a record whose only
effect is that call, by the token that made it, and the verifiers accept the log with them; the call that found nothing left none. `tests/engine_wire.py`
and the soak count commits around these calls and are brought to the new count where they did.

**Built.** `exec.stmts_define` names the two calls beside the erase. Nothing else: a statement that changed the tree and is one of these was already a
commit by `session.close`, with the effects of its statements.

**Measured.**

- `tests/engine_log.py`: 187 commits archived by two calls that took something: the log's next two records have the call `cancho_log_archive` for
  their only effect, the second call answers one commit more than the first, and a third call with nothing to take adds none. A trim by itself that
  takes something: a record whose only effect is `cancho_history_trim`; the one after it, which finds nothing, none. A trim made in a transaction: the
  call is among that commit's effects. The verifiers accept the log with these records (`level=2+ir`, and the replay ends at the rows).
- `tests/engine_wire.py`: through the server, two archive calls by a token that names the call move the head two commits on.
- The soak (`60 1 archive,mixed`): 5,761 commits, 4,321 of them archived and 27,175 history entries trimmed as the load went, every check passing.
- Two mutants (the archive is no commit; the trim is none), both killed.

*What changed for a reader of the log.* The head is no longer what it was after an archive or a trim: a client that took the head before one and
holds a later log to it still can (the head it took is in that log), but "the head stays" is not so, and one test said it.

## 6bl. The schema a commit began with: the types and the keys too

A commit says the hash of the schema its transaction began with (6bc). The schema hashed was the snapshot the lowering reads: the names of the tables,
of their columns and of the indexes. So a table dropped and made again with the same names and other types, or another key, was the same schema to
the log: two commits that wrote to tables a reader would not call the same said the same `schema`.

**Design.** What is hashed is the snapshot with, after each column's name, its type and its place in the key (`/T/K`: the type's number in the tree's
definition, 0 for a column that is not of the key, else which column of the key it is). `tables.schema_text` writes either form; the lowering still
reads the one of names, which is all it needs and is what the proxy's lowering reads. The specification puts no rule on the field (`docs/spec/commit.md`),
so no verifier changes; the engine's hash and the proxy's for the same tables were not the same bytes before either, and are not meant to be.

*What it still does not say.* ~~Whether a column may be null, and its default: the tree's definition of a table keeps them as the statement that made it,
not as fields.~~ **That was false, and was written without looking**: the table's entry marks each column (it may not be null; it has a default, kept
as a stored value; a range; an identity: `tables.not_null`, `tables.default_at`). Found while reading the catalog for the indexes. The text hashed now
has the marks and the default too, `/T/K/M` and `=` with the default's bytes: `v/3/0/3=03000178` is a text column, not of the key, not null, with the
default `x`. A sequence is in no snapshot (6bc).

**Test** (first). `tests/engine_log.py`: the schema the test program prints before each statement (`!schema`) is the text hashed, and the test of 6bc
holds every commit's field to the hash of it, so the record and the text cannot differ without that test failing. Added (`definitions`): a table dropped
and made again with a column of another type, and again with another key, is a different schema each time, and the names alone are the same.

**Built.** `tables.schema_text` takes `typed`; `session.schema_hash` and the test program's `!schema` ask for it, `exec.schema` (the lowering's) does not.

**Measured.** `tests/engine_log.py`: every commit of the history says the hash of the typed text printed before its statement (the check of 6bc, now of
this text); a table made with `v text`, then `v integer`, then keyed by `v`: three schemas, and the third made again is the third. Three mutants (the
commit hashes the names alone; the type left out; the key left out), all killed. `t: k/5/1 v/3/0` is a line of it.

## 6bm. A sync that fails, provoked

Section 1 says a failed `fsync` is the end of the process and is never tried again: after `EIO` the kernel may have dropped the pages and cleared the
error, and a second `fsync` can say all is well for data that is gone. The test program's crash hook makes the pager stop at a step (6b); nothing made
the kernel's own call fail under the server. This does.

**Design** (a test; nothing in the engine changes unless it finds something). `tests/shim/fsync_fail.c`, loaded into the server with `LD_PRELOAD`:
the n-th `fsync` of the process answers -1 with `EIO`, and **every call after it succeeds**, so a server that tried again would be told all is well. It
writes how many calls were made to a file the test reads. `tests/engine_wire.py` (`sync_failing`) runs a server for each n from 1 until a run is not
reached by the failure, with a client that makes a table, inserts five rows, erases one and inserts another, and holds:

- *No sync after the one that failed*: the count of calls is n, exactly.
- *The statement under which it failed is refused* (`58030`), the connection ended, the server gone with status 7; if it failed before the server
  served, the server did not start (status 5).
- *After a start without the fault*: every row acknowledged is there, and no row but those and the one in flight; the log verifies and its replay ends
  at the rows.

**Measured** (first, by hand, before the test was written; n from 1 to 13):

- The server made no call after the failing one, at every n, and stopped as designed.
- A commit syncs twice (the pages and the catalog, then the superblock). **When the second failed, the client was told the commit failed and the row
  was there after the start**: the superblock was written, and whether it reached the disk is what the failed call did not say. This is the rule of
  a kill (a commit not acknowledged may be there or not), but here the client has an error in hand and not silence: `58030` does not mean "not done".
- **A new file whose first sync failed is not a database afterwards**: the catalog page is in it and no superblock, and the server refuses it at every
  start (status 5) rather than take it for an empty one (the rule of `pstore.load`: a file that is not empty and has no valid superblock is refused). It
  never held a commit; it has to be removed by hand. A failure at the second or third sync of a new file leaves one that starts.

**The test, as it runs in the gate.** 22 places: the syncs of a new file, of the start, of each of the commits, of the erase (its two commits and
what it zeroes) and of the insert after it. At each: no call after the failing one; `58030` and status 7 (or no start, status 5); the rows after a
start are those acknowledged, or those and the one in flight (10 of the 22: the second sync of a commit, which the client was told had failed); the
verifiers accept the log and its replay ends at the rows wherever there are commits enough for them. One mutant (a failed sync is taken for done):
killed, the server going on to sync again.

*Not done.* The shim fails a call; it does not lose the pages, so "the data is gone and a retry would not know" is the kernel's behaviour as documented,
not something this test shows. A failing `pwrite` is 6ay's. A new file left unusable by its first sync is not repaired here.

## 6bn. A copy of the page file that can be started from, taken while the server runs

Nothing so far says how this database is backed up. Two things were assumed and neither holds.

- *The log is not a backup.* What `logexport` writes proves what was committed and by whom; its facts are salted hashes of the rows (6ag), so that what
  was erased cannot be guessed back. Nothing can be rebuilt from it, by design. **A backup is a copy of the page file.**
- *A copy made with `cp` while the server runs is not one either.* Measured first (three writers and an erase every 50 ms, a copy every half second,
  each copy opened and its tables counted): of 116 copies of an 18 MiB file, 115 were whole and **1 was refused as damaged** when opened. A commit writes
  pages and then the superblock that names them; a copy that read the superblock late and the pages early has a superblock naming pages the copy does
  not have, and after a sweep or an erase a page the copy's superblock names may have been zeroed or written again.

**Design.** `logexport PAGEFILE pages` writes the whole page file to its output, in an order that makes the copy one state of the database, and says if
it could not:

- *The two superblocks are read first*, before anything else, and are what the copy has for its pages 1 and 2. Every page a superblock names was
  written and synced before the superblock was (6b), so every page those two name is in the file from that moment on.
- *Then the program loads the database as it does for any export, and reads the two superblocks again.* If they are not byte for byte what it read
  first, a commit came between: it stops, `export-raced`, and the caller runs it again. Otherwise the state it loaded is the state it will write.
- *Then every other page, to the end of the file as it is by then.* Pages the two superblocks do not name may be in it, whole or half written: the
  server that starts on the copy sweeps them before it serves (6ay).
- *At the end, the count of sweeps the tree says were announced* (6az) is read again from the file as it is then, as for every export. If it is not
  what the loaded state said, a page the copy has may have been zeroed or written again since: `export-raced`, and the output is not to be kept.

It writes to its output and nowhere else, and opens the page file to read: its authority is what it was (C189).

*To restore* is to put the copy where a page file is wanted and start the server on it. There is no other step, and so nothing else to get wrong.

**Test** (first). `tests/engine_wire.py` (`copying`): under writers, a client that erases and one that reads the past, the tool is run over and over.
Every copy it says is whole is started as a server of its own: every table is counted and summed against what must hold whatever the moment (the sum of
the accounts; each writer's journal without a gap), every transfer acknowledged before the copy was begun is in it, the log exports and verifies and
its replay ends at the rows. No copy it says is whole may fail any of that. How many it refuses as raced is counted and reported: an erase announces a
sweep, so under erases a copy of a large file may seldom get through, and that is a number this section owes.

**Built.** `pager.raw` (a page as the file has it, unchecked); `pages` in `proxy/logexport.cho`, with the two superblocks read in `main` before the load.

**Measured.**

- *`cp`, to know what is being replaced* (a 202 MiB file, three writers that also rewrite rows all over it, an erase every 50 ms, a copy every half
  second, each opened and counted): **32 of 82 copies were not a database** (39%). The engine refused 28 of them as damaged when it opened or read
  them; the other 4 answered the first question and failed a later one.
- *The tool, the same load*: 55 of 55 runs refused `export-raced`; a run took 1.1 s, and a sweep was announced twenty times a second. **Nothing wrong
  was handed out, and nothing was handed out.**
- *The tool, an erase every 3 s* (274 MiB by the end): 37 of 49 runs gave a copy, 12 were raced; **every one of the 37 was whole** by every count.
- *In the gate* (`copying`, a 24 MiB file): under an erase every 20 ms, 7 of 8 runs raced and the one copy was whole; under an erase a second, 4 of 6
  gave a copy. Each copy was started as a server and had the accounts' sum, the untouched table's rows, each writer's journal without a gap and every
  transfer acknowledged before the copy began; the log of one verified and its replay ended at its rows.
- Three mutants (the superblocks are not those of the moment it began; the copy stops before the end of the file; a copy is given though a sweep was
  announced), all killed.

*What this does not do, and it matters.*

- **Under steady erases no copy gets through.** A copy is refused whenever a sweep was announced while it was read, and every erase announces one. The
  caller runs it again; how long that takes depends on the load, and under an erase every 50 ms it is never. A way for a copy to hold the sweeps off, or
  to survive one, is not designed.
- A copy takes 1.1 s for 200 MiB: the tool writes its output a byte at a time.
- Two refusals are designed and not shown to refuse: a commit landing between the first read of the superblocks and the load (no test makes one land
  there), and a superblock torn while it is read.
- A restore is a start: the copy's server sweeps before it serves (6ay), which costs the file (6bj).
- What the copy is *of* is the commit the superblocks named when the tool began; later commits are not in it, and the tool does not say which commit
  that was (`logexport COPY anchor` does, from the copy).

**Corrected: a copy the tool called whole that no server would start on.** Found by the gate, once, on seed 3 of the server's test, weeks of runs
after this section was written: of 8 copies under an erase every 20 ms, one was said to be whole and the server stopped on it at start (status 5).
Kept from a later run (1 in about 150 attempts) and looked at: its tables read, the sums were right, and the start's sweep failed in it.

- *Why.* The copy had both superblocks as they were when it began: the state it copied and the state before. An erase commits twice, one after
  the other, and then zeroes the pages that only the state before the erase named (6bh). A copy begun *between those two commits* has the erase's
  first commit as its state and, as its older superblock, the state before the erase, whose pages are zeroed and used again while the copy is read.
  The number of sweeps was already raised by the first commit, so the tool saw nothing change. The state copied was whole. The superblock beside it
  named pages that were another state's by then, and a server's start sweeps what *either* superblock names.
- *What this section said that was not so*: "every page the two name was in the file before they were", taken to mean that both states were
  kept. Only the one loaded is.
- *The repair.* A copy has one superblock, the loaded state's, and zeros where the other is: a file as it is after one commit, which a server
  starts on. The tool run on the copy that was kept gives a copy a server starts on. The test now holds every copy to that shape (one superblock, one
  page of zeros), since the moment itself is a few milliseconds wide and is not provoked; a mutant that writes both is killed by it.
- *What it means for a copy taken before this*: it is its state, and a server refuses it at start if it was begun in that moment. Copying it again
  with this tool repairs it.

## 6bo. Indexes that are built: the plan, and its first slice

`create index` records a name and builds nothing (6q): "honest only because the engine claims no speed". Every read that is not by the key reads the
whole table, 45 ms for 60,000 rows (6bj), and a `unique` index is refused because there is nothing to hold it with. This is the plan for building
them, in slices that each leave the gate green, and the design of the first.

**What an index is, in the tree.**

- *Its entry in the catalog* has been the index's name and the table's name. It gains: a number of its own (from the counter tables take theirs
  from, so no table has it), the columns it is on, in order, and the boolean column of its condition if it is a partial one (6x). An entry without
  those is an index from before: a name, as now, and it stays one (it is not built behind anyone's back; it can be dropped and made again).
- *Its entries* are keys under its number: for each of its columns one byte (0: null; 1: a value) and the value as a key stores it (the encoding of
  `row.cho`: it sorts as the values do), then the row's own key. One byte for a value (since slice 2 that byte says where in the entry the row's key begins). An entry leads to its row by the key at its end.
- *They are written with the row*, in the same statement and the same tree: an insert writes them, a delete removes them, an update that changes an
  indexed column or the condition's removes the old and writes the new. `truncate` and `drop table` remove them with the rows, `drop index` removes
  them alone, and `create index` on a table that has rows writes one for each.

**Two decisions, with their reasons.**

- *An index entry has no history.* A row's past is kept so that the table can be read as it was (6n). An index is not read as it was: **a statement
  that reads the past reads no index**, it reads the table, as every statement does today. So the entries are written and removed plainly, a rollback
  drops the tree they were in as it drops the rows, and nothing of them is in the history or its by-key entries. A read of the past builds its tree
  by undoing the rows' history, which leaves the index entries of the present in that tree; nothing reads them there.
- *An erase has to know them.* An entry holds the indexed values of a row. The erase removes the entries the row has now and takes their keys out of
  the internal pages (6bc), and for each earlier form of the row that its history holds, works out the entries that form had and takes those keys out
  too: an update removed those entries plainly, and a key removed plainly may still bound a child. That is the one place the two decisions meet, and
  the test of it is the erase test with an index on a column of many lengths, searched for every value the row ever had (which holds today only because
  an index holds nothing).

**The slices.**

1. *Built and kept, and read by nothing* (this one). Answers cannot change: no statement reads an index. What it has to show is that the entries are
   exactly what the rows say, through every statement, a crash, a rollback and an erase.
2. *A read by an indexed column's value* (`where c = constant`) goes by the index. The differential against PostgreSQL holds the answers; the time is
   the claim.
3. *`unique`*: the constraint held by looking the value up before a row is written.
4. *Ranges and order* (`where c > x`, `order by c`), if the first three say they are worth it.

**Slice 1: the test, written first.** The test program gets `!indexes`: for every built index of the tree, the entries it has and the entries its
table's rows say it should have, and whether they are the same set (`indexes N ok`, or the first difference). It is asked:

- at the end of every seed of the random history against PostgreSQL (`tests/engine_check.py`), whose statements gain `create index` on tables with
  rows, partial ones, and `drop index` (they have them already, building nothing);
- after every crash point of the crash test (6m), on the state the file comes back to;
- after rollbacks and failed statements (the erase test's workload of 6bh, with an index);
- and in the erase test with an indexed column of 14 to 65 bytes: after the erases no value an erased row ever had is in the file.

*What slice 1 will cost* is a number it owes: every write to an indexed table writes more pages. It is measured before slice 2 is begun, with the
soak's transfers on a table with one index and with three. (*What was measured is not that*: single-row statements through the test program, below. The
soak has no table with three indexes and its time is mostly its syncs.)

**Slice 1, built.** `src/index.cho` (what an index is in the catalog, the entry of a row, `apply`, `clear`, `load`); `row.index_part` (a value as an entry has
it). `exec.bind_table` loads the bound table's indexes and `exec.row_put` and `exec.row_del`, the two places a row is written or removed, keep their
entries: that covers insert, update, delete, `truncate`, `drop table` and a table renamed. `execw.create_index` gives the index a number, writes its
catalog entry with its columns and builds an entry for each row; `drop_index` removes them (`index.clear`). `execw.erase` (`unindexed`). To make room,
`as_of` and `mark_txn` moved from `exec.cho` to `facts.cho` unchanged (nothing in `exec.cho` called them and the file was at 1,985 lines).

*Two things about the entries that the plan did not say.*

- *A text is in an entry by its first 24 bytes.* A key of the tree is at most 200 bytes, and an entry ends with the row's own key. So two rows whose
  texts begin the same have entries that differ only in that key, and a reader by value (slice 2) has to look at the row. An entry that would still be
  too long refuses the statement that writes the row.
- *An index from before stays a name.* Its catalog value has no number; nothing is built behind it.

**What the test found, the first time it ran.**

- **An update that changes the key did not keep the indexes.** On two of the first three seeds of the random history an index had the right number of
  entries and some of the wrong ones. `update ta set k = k + 30` moves every row to another key through a path of its own (the rows leave their keys,
  then take the new ones, so that no row meets another's old key), and that path writes with `exec.put_key`, not `row_put`. It keeps the entries now.
  Found by `!indexes` asked after every statement (`INDEX_EVERY=1`), which named the statement.
- **The erase test failed with indexes, as this section said it would**: the indexed values of an erased row were in the file, in the entries the erase
  had not been told of. It passes with `unindexed`.
- **The check itself had a hole.** It held each index the catalog names to its table, and so could not see the entries of an index that had been
  dropped and not cleared: nobody's, and an erase would never find them. `!indexes` now also holds every number that has keys in the tree to the tables
  and indexes there are (`indexes bad nobody N`).

**Measured.** What keeping them costs a write, by hand with the test program (no server, no sync): a table of four columns, 4,000 inserts, 4,000
updates of one indexed column by key, 2,000 deletes by key, each its own commit, twice.

| indexes | ms a statement | page file written |
|---|---|---|
| 0 | 0.22, 0.23 | 257 MiB |
| 1 | 0.30, 0.29 | 312 MiB |
| 3 | 0.40, 0.42 | 396 MiB |

About a third more time for the first index and a quarter of that again for each further one; the pages are those a commit copies and a sweep takes
back (the test program does not sweep). `!indexes` said `ok` after each run.

**Slice 2: a read by an indexed column's value.** A `select` of one table whose `where` has, among its top-level conditions, `column = constant`
with the column the first of a built index, reads that index's entries for the value and each entry's row, not the table (`src/via.cho`: `choose`
before the rows, `start`, `next`).

- *Every row read is still judged by the whole `where`.* So the index may give rows the condition is not true for (a text is in an entry by its first
  24 bytes) and what matters is that it gives every row it is true for. The rows come in the order of their keys, as a read of the table gives them.
- *When it is not done.* When a condition of the `where` can raise an error (the rule of the lookup by key, 6b: a row not read is a row whose error
  is not found); when a condition already bounds the scan by the key; under a join (there the engine does not ask whether the `where` can raise); for a read of the past (**the entries in the tree a past read is
  given are the present's**: an index has no history); for a partial index (it has not every row); when the constant is a null (`= null` is true of
  nothing, and the table says so); when the column is a boolean or a bytea; and when the constant has a minus sign, which is not counted as a
  constant because it can overflow. That last one is a limit worth removing: `where a = -5` reads the table. (*Removed since*, for a minus sign
  over an integer written in the statement: see below.)
- *The constant.* A number for an integer column; a string for a text column; a parameter or a string for an integer column is read as the integer
  the column's type makes of it (one that is no integer was refused before any row).
- *An entry says where its row's key begins* (its one byte of value), so that the reader need not know the columns' lengths. This changed the entries
  slice 1 wrote, before any file but a test's had one.
- *`update` and `delete` do not read an index yet.* They read the table, or the key's bounds.

*The test, written with it.* `tests/engine_check.py` runs 64 selects on a table with five indexes (one partial, one of two columns), a table with a
key of two columns and one with 400 rows of a value, each marked with whether it has to be read by an index, between writes, a rollback, a key moved, an index dropped and made again, a
table renamed and a `truncate`. PostgreSQL holds every answer, and the test program counts the statements it read by an index (`!via`): the count has
to be exactly the 45 marked. So an index read where it may not be fails, and one not read where it is there fails too. A read of the past by value is
held to what the table had then, with a count of 0 (`past_by_value`), and through the server's `as of` in `tests/engine_log.py`.

**Measured** (by hand, the test program, 600 selects by value, half on an integer column with 10 rows a value and half on a text column):

| rows | no index | by the index |
|---|---|---|
| 10,000 | 5.8 ms a select | 0.09 ms |
| 100,000 | 68 ms | 0.16 ms |

The same 3,341 rows answered either way on the larger table. The two indexes made the file 14 % larger (60.0 MiB for 52.4) and the load 40 % longer.

**A number with a minus sign is a constant (after slice 2).** `where a = -5` read the table: a minus is not counted among what cannot raise (it
overflows on the least bigint), and so neither the key's bounds (6b) nor an index was used for the commonest way of writing a negative number. A minus
over an integer written in the statement cannot overflow: the integer is not negative, and its negation is a bigint. So that one form, a minus sign
directly over an integer literal, is now a condition that cannot raise and a constant a key or an indexed column may be compared with. A minus over
anything else (a column, a parameter, a string, another minus) is as before: the table is read.
*Tested* in the list of slice 2, which is now 69 selects of which 49 have to be read by an index: four with a negative number, and three with a minus
over something else that may not be. 3 mutants. That the key's bounds take a negative number too is, like the parameter there, not counted by a test.

**Slice 3: `create unique index`, the design.** A unique index is an index (slices 1 and 2: built, kept, read) whose catalog entry says so, and a
row may not be written while another row has the same values in its columns. As in PostgreSQL a null is equal to nothing, so a row with a null in one
of the columns conflicts with none, and a partial unique index holds only the rows its condition is true for.

- *Looking a value up.* The entries of the value (slice 2's read), and for each the row it leads to, compared with the new row column by column:
  an entry has only the first 24 bytes of a text, so two entries that begin alike are not yet two equal values.
- *`insert`.* Each row, after its own key is found free, is looked up in every unique index against the tree as the statement has made it so far (so
  two rows of one statement conflict as they do in PostgreSQL). A conflict is `23505`, or with `on conflict do nothing` the row is left out.
- *`create unique index` on a table with rows* builds the entries and is `23505` if two rows have the same values; nothing is made then.
- *`update`* is where the order matters. PostgreSQL checks each row as it writes it, in the order it happens to visit them, against rows of which
  some are already changed and some not. The engine does not know that order, so it answers only what does not depend on it:
  - the new value of a row is held by a row the statement does not change, or by one it changes that keeps or takes the same value: `23505`,
    whatever the order;
  - the new value of a row is the *old* value of another row the statement changes to something else (`set u = u + 1`): PostgreSQL fails or not by
    the order it visits them. **Refused, `engine-order-dependent`**, as the same thing is for the key (6g);
  - no row's new value is any other row's old or new value: the update is made.

  How it is decided while reading the table once: a row's new value is looked up in the tree as the statement has made it so far. A row that holds
  it there is remembered. If that row is read later and gives the value up, the statement is order-dependent; if it is still remembered when the
  statement ends, it kept the value or took it in this statement, which is the error. If no row holds it there, it is looked up in the tree as it
  was before the statement: a row that held it then has given it up since, and the statement is order-dependent.
  (*As first written* this told a holder already read from one not yet read, by the order of the keys, and one that had the value before the
  statement from one that took it. Neither changes an answer: a holder that will not be read again stays remembered, and that is the error either
  way. The mutants of those two tests could not be killed, and the tests are gone.)
- *An update that changes the key* of a table with a unique index is refused (`engine-unsupported`) in this slice: it goes by another path (the rows
  leave their keys and then take the new ones) and the reasoning above is not made for it.
  *Since:* **a row that takes another key and keeps its values in every unique index is moved**, and only one whose values there change too is
  refused. A row's values are not another's because its key is, so nothing has to be looked up: PostgreSQL finds, for the new entry, only the row's
  own old version. The entries follow the row to its new key (slice 1). `update t set k = k + 10` on a table with a unique column is answered.
  *Tested*: 8 more statements in the list (120), two among those refused on purpose (the key and the indexed value both changed: one PostgreSQL
  answers, one it fails), 3 mutants.
- *A column or table `unique` constraint* in `create table` stays refused: it needs the index's name to be the constraint's, and `drop index` on it
  to be an error. `create unique index` is the whole of this slice.
- *The schema.* Whether an index is unique is part of what the schema hash is made of (6bl): it is a constraint, not a way of reading.

*The test, first.* A list of statements in `tests/engine_check.py` (72), each held to PostgreSQL's answer and none refused: inserts
that conflict (one row, two rows of one statement, with nulls, on a text longer than an entry keeps, under a partial index, on two columns), `on
conflict do nothing`, `create unique index` over duplicates, updates of the kinds above that have an answer, a delete that frees a value, a rollback,
and `!indexes` at the end. The updates whose outcome depends on the order are in the list of those (`DEP`), each with what PostgreSQL 16 does: one
that fails there, one that succeeds there, and two rows that change places, which fails in either order and is refused all the same. The random
history against PostgreSQL makes a unique index now and then, as it did when they were refused.

**Slice 3, built.** `index.holder` (a row that has a row's values in a unique index: the entries of the value, and each one's row compared),
`src/uniq.cho` (`taken` for an insert, `changed` for an update), `execd.create_index` (the flag, and the check as the entries are made). The schema
text a commit's hash is of says `unique` after such an index.

*What writing the mutants found.* **An update from one long text to another that begins with the same 24 bytes was not checked.** The update asked
whether the row's entry changed, and the two entries are the same bytes. So `update t set s = '<24 bytes>-2' where k = 4` took a value another row
held, with a unique index on `s`, and the list of statements above had not caught it because an earlier statement of the list had changed that other
row. It now asks whether the values changed (`index.stays`), and the list has the case, both ways.

**Slice 4, first part: a read by a range of an indexed column.** `where c > x`, `c >= x`, `c < x`, `c <= x`, alone or two of them (which is
what `between` is), on the first column of a built index, reads the entries from the lower bound to the upper and each one's row. Slice 2's rules
hold: when it is done (no condition that can raise, no bound by the key, one table, not the past, no partial index), what a constant is, and that
every row read is still judged by the whole `where`.

- *The bounds are wide, never narrow.* `>` is read as `>=` and `<` as `<=`, and a text bound is cut to the 24 bytes an entry keeps: an entry's value
  is not after its text's, so cutting a bound can only let more in. The `where` takes out what is over.
- *A null is in no range*: its entries come before every value's, and the read begins after them.
- *An equality is preferred* to a range when the `where` has both for indexed columns.
- *The rows come in the order of the indexed values*, not of their keys as slice 2's do. No answer depends on it: a `select` without `order by`
  has no order to PostgreSQL either, and the test holds such answers as sets.
- *What it costs when the range is most of the table* is the number to measure before this is kept as it is: a read by the index takes a lookup by
  key for every row, which a read of the table does not.

**Measured, and what it changed.** 100,000 rows, an integer column of as many values, `select count(*) ... where a >= x and a < y`, by hand with
the test program:

| the range is | reading the table | every range by the index | as built |
|---|---|---|---|
| 0.1 % of the table | 83 ms | 1.3 ms | 1.5 ms |
| 1 % | 84 ms | 3.9 ms | 5.2 ms |
| 10 % | 88 ms | 32 ms | 35 ms |
| 50 % | 86 ms | 151 ms | 101 ms (the table) |
| all of it (`a >= 0`) | 65 ms | 253 ms | 75 ms (the table) |

Read by the index whatever its size, a range of half the table took nearly twice the table's time and one of all of it four times: the two reads
cost the same at about 28 % of the table. The engine keeps no statistics, so **it counts** (`via.worth`): at the first row, the entries of the range
(an entry is a few bytes of a leaf already in hand, where a row is a lookup), then the index's other entries until there are three times as many.
If there are, the range is a quarter of the index or less and is read by it; if not, the table is read, as before. The count is the third column's
price: up to a third more on a small range that is read by the index all the same, 15 % on a wide one that is not.

- *Which index is asked.* The first, by name, that has a bound on its first column. If its range is too wide the table is read, though another
  index might have had a narrow one: `where b > 'v01' and b < 'v02' and a < 300` reads the table when `a`'s index is met first.
- *An equality is not counted.* A value that half the rows have is read by its index, slower than the table would be. Slice 2's, unchanged.
- *A text bound cut to 24 bytes can make the range all of the index* (every text beginning alike): counted as that, and the table is read.

*Tested.* A table of 410 rows with three indexes in the list of slice 2: 26 ranges that have to be read by an index (each bound, both, `between`,
a parameter, a negative number, the constant first, an empty range, one of exactly a quarter) and 12 that may not be (one row more than a quarter,
one-sided and wide, texts beginning alike, the key bounding the scan, an `or`, what can raise), PostgreSQL holding every answer and the count of
reads by an index exact. 14 mutants.

**Slice 4, second part: `order by` an indexed column with a `limit`, the design.** `select ... from t order by c limit n` reads the whole table and
sorts it to give `n` rows. With an index on `c` the first `n` entries are the answer.

- *The tree is read backwards for `desc`.* `btree.prev_before`: the last entry before a key, as `next_after` is the first after one. It walks from
  the root each time (no leaf is kept): a read of this kind is a few rows. Held, like `next_after`, to a model in `tests/btree_check.py`.
- *When.* A `select` of one table, not grouped, not `distinct`, with no `where`, ordered by one item that is a column, the first of a built index
  that is not partial, of an integer type, `asc` or `desc` with the nulls where PostgreSQL puts them by default (last for `asc`, first for `desc`),
  and a `limit` (an `offset` may come with it). Then the rows are read by the index in that order, and the read ends when `offset + limit` rows are
  had. They are sorted like any answer afterwards, which changes nothing: they come sorted.
- *Not a text column*: an entry has only a text's first 24 bytes, and texts that begin alike are in the order of their keys, not their own.
- *Not when an item of the select list can raise an error.* A row that is not read is a row whose error is not found (6g); PostgreSQL may compute
  the list before it sorts, and the engine already refuses `select 10 / (k - 2) ... order by k limit 1` as depending on that order. So the list has
  to be columns, constants and what cannot raise.
- *Not with a `where`*, in this part: the rows that pass may be few and far along the index, and reading most of a table by an index costs four
  times what reading the table does (the first part's measure). Without a count of what passes there is nothing to decide by.
- *Rows that tie.* Where rows have the same value in `c`, which of them are within the limit is not said by the statement; PostgreSQL gives
  whichever its plan meets. For `asc` the index gives those with the least keys, as the sort of the whole table did. **For `desc` it gives those with
  the greatest keys, where the sort gave the least**: an answer PostgreSQL may give as well, and another than this engine gave before. The test
  holds such answers by their number of rows, as it always has.
- *At most 1,024 rows* (`offset + limit`). A row by the index is a lookup, and a `limit` as large as the table would read all of it that way, at
  four times the table's cost. A thousand lookups are a few milliseconds whatever the table.

**Built.** `btree.prev_before`; in `src/via.cho`, `ordered` (called by the plain `select` once it knows its `limit` and `offset`), and `step`, the
one place the read moves, forwards or backwards. The read has two parts, the values and the nulls, in the order the direction asks.

*What the mutants of `prev_before` showed*: it was written with a second way of walking, "the last leaf under the page to the left", for when a
leaf has nothing before the key. Both mutants of it lived, and rightly: everything under that page is before the key, so the walk as it already was
ends at the last entry there. The second way is gone.

**Measured** (100,000 rows, by hand with the test program, each of 20 runs):

| | sorting the table | by the index |
|---|---|---|
| `order by a limit 10` | 115 ms | 0.06 ms |
| `order by a desc limit 10` | 114 ms | 0.12 ms |
| `order by a desc limit 100 offset 900` | 91 ms | 9.1 ms |
| `order by a limit 1025` (over the bound) | 99 ms | 98 ms (the table, as before) |

Backwards costs about twice forwards a row: each step walks from the root.

*Tested.* In the list of slice 2: 17 ordered reads that have to go by an index (both directions, an offset, past the values into the nulls and
the other way, a limit of 0 and of 1,024, parameters, after writes and inside a transaction that is rolled back) and 11 that may not (1,025 rows, no
limit, a text column, two items, an expression, `distinct`, a `where`, a partial index, an item that can raise). PostgreSQL holds the answers: in
order where the order is total, by their number where rows tie at the edge. `first_rows` holds the number of rows the index gave to the number
asked for, which no answer shows. The past is read without it (`past_by_value`). 19 mutants, and 5 of `prev_before` with the tree's model.

**`update` and `delete` by an index (after slice 4).** They read the table, or the key's bounds, and so `delete from t where a = 5` cost what a
read of every row costs. They now find their rows as a `select` does: `via.choose` after the `where` is read, and the rows by the index's entries
of the value, or of the range if it is a quarter of the index or less (the first part's count). Nothing else about them changes.

- *The rows are read in the tree as it was before the statement*, as they always were, and written into the tree it is making: an `update` that
  changes the indexed column does not meet its own rows again.
- *The order they are read in is the index's*, not the key's. What an `update` decides about a unique index (slice 3) and about keys that move
  does not depend on the order rows are read in: that was why the mutants of the order tests could not be killed.
- *The same rules for when* as a `select`: no condition of the `where` that can raise, no bound by the key, not a partial index.

*Measured* (100,000 rows, 10 rows a value, by hand with the test program, 30 statements each with its commit): `update ... where a = N` 53 ms
with no index and 2.2 ms with one; `delete ... where a = N` 54 ms and 1.7 ms.

*Tested.* In the list of slice 2: 17 updates and deletes that have to be read by an index (a value, a small range, a parameter, a key moved, with
`returning`, inside a transaction rolled back) and 5 that may not be, the tables held to PostgreSQL's after each. `first_rows` holds the rows an
`update` and a `delete` are given by the index to the rows of the value or range. 4 mutants.

**`unique` on a column of `create table` (after slice 3).** PostgreSQL makes of it a constraint named `<table>_<column>_key`, held by a unique index
of that name. Here it is that index and a mark on it:

- `create table t (k integer primary key, u integer unique)` makes the table and, in the same statement, a unique index `t_u_key` on `u`, marked in
  the catalog as a constraint's. Everything slice 3 does for a unique index it does for this one. The name is taken as any index's is.
- *`drop index t_u_key` is refused* (`engine-unsupported`): PostgreSQL's answer is an error of its own (`2BP01`, the constraint needs it), and the
  way to drop it there is `alter table ... drop constraint`, which the engine has not.
- *Refused, and said:* when the name `<table>_<column>_key` is already a table's, an index's or a sequence's (PostgreSQL then tries the name with a
  number after it), or is longer than 63 bytes (PostgreSQL cuts it); `alter table ... add column ... unique`; and a `unique (a, b)` written as a
  constraint of the table, which the parser does not read. More than eight unique columns in one table.

*`unique (a, b)` as a constraint of the table (after that).* Read by the parser as the table's `primary key (...)` is, and made as the column's
is: a unique index on those columns, named `<table>_<a>_<b>_key`, marked as a constraint's. A column of the list that the table has not is
PostgreSQL's error (`42703`). Refused: such a constraint written before a column definition (the engine reads the columns first, and they are then
not where it looks for them), a column named twice in one list, and `constraint <name> unique (...)`, whose name is the user's.
*Tested*: 17 more statements in the list (112) and three more among those refused on purpose; 7 more mutants. *Corrected*: the paragraph above says
a `unique (a, b)` of the table is refused because the parser does not read it. It reads it now.

*Built and tested.* `uniq.constraints`, called by `create table` once the table is made; the mark is a bit of the index's flags, which `drop index`
reads. The list of slice 3 has 23 more statements (95): a table with three unique columns, the conflicts of each, a default that conflicts, the
constraint's name taken by an index, a table and a sequence, the table dropped and made again, and renamed. Five statements are in the list of those
refused on purpose, each beside what PostgreSQL 16 does. 11 mutants.

*A limit of the check, said plainly (slice 1's; slice 2 narrows it).* Since slice 2 a fault in `index.entry` that loses a row from a read is seen by
PostgreSQL's answer. One that only makes entries longer than they need be is still on both sides.

*As it was written with slice 1:* `!indexes` works out what entry a row should have with the function the engine writes it with (`index.entry`). A
fault in that function is on both sides and is not seen. It will be seen in slice 2, where a read by an index is held to PostgreSQL's answer.

*Not in the plan.* An index on an expression; `include`; any index but the tree's own order; a planner that chooses between two indexes by anything
but "the first that fits"; statistics.

## 6bp. Times: `timestamp` and `timestamptz`

The engine has integers, text and booleans. A table of anything that happens has a time in it, and today that column has to be a number or a text,
which sorts and compares as the application means only if the application is careful. This is the plan for the two types, in slices as 6bo was.

**What a time is here.**

- *Two types*, as in PostgreSQL: `timestamp` (a date and a time of day, of no zone) and `timestamptz` (a moment). Both are the number of
  microseconds since 2000-01-01 00:00:00, PostgreSQL's own measure, stored as an integer is stored. So a time is a key, an indexed value and an
  ordered value with nothing new: it sorts as its number does.
- *The zone of the session is UTC, and cannot be set.* PostgreSQL writes a `timestamptz` in the session's zone and reads one without an offset
  in it; a client that sets the zone gets other text for the same moment. Here `set time zone` stays refused, a `timestamptz` is written with
  `+00`, and one read without an offset is UTC. The differential runs PostgreSQL with `TimeZone = UTC` and `DateStyle = ISO`.
- *What is read.* ISO 8601 as PostgreSQL writes it and as drivers send it: `YYYY-MM-DD`, then optionally a space or `T` and `HH:MM`, `:SS`, a
  fraction of up to six digits, and an offset (`Z`, `+HH`, `+HH:MM`, `+HHMM`). For a `timestamp` an offset is read and dropped, as PostgreSQL
  does. A year from 0001 to 9999. **Anything else PostgreSQL would read (`Nov 27 2026`, `infinity`, `now`, a time of `24:00`, a second of `60`,
  `BC`, a named zone) is refused, `engine-unsupported`: not an error, because PostgreSQL has an answer.** A text of the form with a field out of
  range (month 13, 30 February, hour 25) is PostgreSQL's error, `22008`; a text that is no date at all is `22007`.
- *What is written.* `2026-11-27 10:00:00`, a fraction if there is one with its trailing zeros dropped, and `+00` for a `timestamptz`. In the row
  image the log's facts are made of (`to_jsonb`): `"2026-11-27T10:00:00"` and `"2026-11-27T10:00:00+00:00"`. To a client the types are
  PostgreSQL's (1114 and 1184), in text.

**What can be done with one, in the first slice.** A column of either type, also in the key and in an index; a literal or a parameter where a
time is expected; `=`, `<>`, `<`, `<=`, `>`, `>=`, `between`, `in`, `is null`, between two times or a time and such a text; `order by`,
`distinct`, `group by`, `min`, `max`, `count`; `cast` between the two types, from text and to text. A `timestamp` beside a `timestamptz` is read
as that moment in UTC, which is what PostgreSQL does in a session whose zone is UTC.

**Refused in the first slice, and said:** `now()` and `current_timestamp` (the second slice: the time is the transaction's, which the log
already records, so a statement that asks for it is still one the log can hold); arithmetic (`+ interval`, a difference); `extract`,
`date_trunc`, `to_char`; `date`, `time` and `interval` as types; a precision (`timestamp(3)`); `at time zone`.

**Slice 2: `now()`, the design.**

- *What it is.* The time the transaction began, a `timestamptz`, as in PostgreSQL: the same for every statement of a transaction, and for a
  statement outside one the time it began. From the server's clock, which counts milliseconds: a `now()` has no finer part.
- *Where the clock is.* The server sets it before a statement when no transaction is open (`exec.clock`), so `begin` takes it and the statements
  after it keep it. The test program has no clock of its own: `!clock MICROSECONDS` sets one, and without it `now()` is refused as before.
- *`default now()`* on a column of either type of time: a mark of the column, and the time is taken when a row is inserted that gives the column
  no value. Not a value kept in the entry: that would be the time the table was made.
- *What it is not.* A constant for a key's bounds or an index (a `where` with `now()` reads the table); `current_timestamp`, which the parser
  does not read as an expression; `clock_timestamp()` and `statement_timestamp()`, which differ within a transaction; a default of a column added
  to a table that has rows.
- *The log.* The statement's IR already says `nondet now` (docs/spec/ir.md): the log holds the statement, and the rows it wrote hold the time.
  Nothing replays a statement to find its values.
- *The test cannot be the differential alone*: PostgreSQL's clock is not the engine's. With the test program's clock set, the answers are held
  to what that clock says; the statements whose answers no clock changes (`now() = now()`, a row inserted by default equal to `now()` within one
  transaction, the type a client is told) are held to PostgreSQL's too; and through the server, to the test's own clock within a few seconds.

**Slice 2, built.** `exec.clock` and a place for it beside the evaluator's parameters; `eval`'s answer to the IR's `nondet now`; a mark of the
column (16) in the table's entry for `default now()`, read by the insert; the server reads its clock before a statement when no transaction is
open; `!clock` in the test program.

*Tested.* `clocked` in `tests/engine_check.py`: with the clock set, 22 answers held to what the clock says (no clock: refused; the same time
through a transaction; another after the clock moves; `update` and `delete` by it; a default on a column that is no time, on a column added
later, and a call that is not `now()`, each refused), and 13 statements whose answers no clock changes held to PostgreSQL's. `clock` in
`tests/engine_wire.py`: through the server, the test's own time within 5 s, one time for statements of a transaction 1.1 s apart and for the rows
they insert, a later one after it. `clocked` in `tests/engine_log.py`: the log of such commits verifies with each verifier. 8 mutants and 3 of
the server.

*Found on the way*: `select now()` with no table is refused, as every `select` without a `from` is. A client that asks the time that way gets
no answer; `select now() from <a table of one row>` does.

**The slices.**

1. *The types, stored and compared* (this one), with the test first: a list of statements over a table of both types, each held to PostgreSQL's
   answer, the texts read and refused among them; the random history's tables get columns of the two types.
2. *`now()`*, as the transaction's time.
3. *Arithmetic with intervals*, if the first two say an application needs it here rather than in its own code.

**Slice 1, built.** `src/time.cho` (a text read as a time, a time written: held to Python's `datetime` by `tests/time_check.py`, on their own);
types 7 and 8 in `src/row.cho`, stored with the integers' tag, and the row image writing them as `to_jsonb` does; `src/eval.cho`: a text or a
parameter beside a time is read as one, the two types compare as one number, the casts, and a refusal wherever a time meets arithmetic or a
choice between the two types; `execw.column_defs`; `src/answer.cho` (what a client is told and sent, which now takes the column's type: a stored
time does not say it is one); the constant of a key's bounds and of an index. `exec.bounds` moved to `via.cho` unchanged to make room.

*Nothing else had to learn the types.* The three verifiers of the log read a row's image as bytes; the log of a run with times in it verifies
with all three (`tests/engine_log.py`), and the server's test passes with them (`tests/engine_wire.py`).

*What the first run by hand showed*: a time was stored as an empty text. The one place a value is written into a row (`exec.enc`) knew the
integers by their three types and took everything else but a boolean for text. The row then failed its own check, and every read of the table was
refused `engine-damaged`: nothing wrong was answered, and nothing was readable.

*Tested.* 78 statements on three tables (`TIMEFIXED`), none refused, each answer PostgreSQL's in UTC: every way a time is written, the fields no
date has (`22008`), a time where another type is wanted and the other way (`42804`, `42883`), each comparison, a parameter, `order by`, `group
by`, `distinct`, `min` and `max`, the casts, `coalesce`, `case`, `greatest`, a time as a key and as half of one, an index and a unique index on
one. 18 statements PostgreSQL answers and the engine refuses on purpose, each beside what PostgreSQL 16 does. 10 more in the list of reads by an
index. **The random history's tables have columns of both types** (2 in 9), in keys too, with texts of times among their values and conditions:
3 seeds of 3,000 statements agree. 21 mutants of `time.cho` judged by `time_check.py`, 17 of the rest judged by the differential.

**What the first slice had to change**, as it was read from the code before (kept: it was right but for `exec.enc`): the closed list of types in `src/row.cho` and what
a stored value of each is; `src/eval.cho` (a text read as a time, a time written, the comparison, the casts, what unifies with what);
`execw.column_defs` (the parser already knows the two names: the proxy passes them to PostgreSQL); `src/answer.cho` (the type a client is told and
the text it is sent); the row image in `src/row.cho`; the key's bounds and the index's constant (`exec.bounds`, `via.part`), which take an
integer constant and now have to take a time's; the schema text a commit's hash is of. The IR does not change: a `cast` carries its type's name
already, and a column's type is not in it.

## 6bq. TLS: the server ends it itself

*Design, written before the code, then corrected by building it (the corrections are marked). Each statement here is a choice, a read (with
the file), or measured with its command.*

**What is missing.** The server answers `SSLRequest` with `N` (6al), so a password, a token and every row travel in clear, and the server
serves this machine only for that reason (`from_here`). 6bd said TLS "is to be ended in front of the server". *Choice, overturning that:* the
server ends TLS itself. A proxy in front would see the token and every row in clear, and it would be a second program to run and to trust.

**What there is to build on (read: `packages/tls` of the compiler's repository, at the revision `cancho.toml` names).** A TLS 1.3 server
written in cancho: `tls.open_server`, `tls.add_identity(chain_pem, key_pem, names, now)`, `tls.serve(slot, now)`, and then bytes in and out
(`feed`, `take`, `send`, `recv`, `finish`, `drop`). It holds no socket and no capability: the program moves the bytes. Its own documents
(`docs/tls-server.md` there) say what it is checked against (OpenSSL, Go, wolfSSL, browsers; a lying client; a fuzzer; its mutants), and say
**it has not been reviewed by anyone outside** (its issue 209). This server inherits that: TLS here is not a claim that the cryptography was
reviewed. TLS 1.3 only; the key is ECDSA P-256 only (`tls-server-key-type` for any other).

**The command line (choice).** One more word, `tls=<directory>`, last or before `check-purge`: the directory holds `chain.pem` (the
certificates, the server's first) and `key.pem` (PKCS#8 or SEC 1, not encrypted). A directory named whose files cannot be read, or that the
package refuses (a key that is not the certificate's, an expired certificate, an RSA key), is a refusal to start (status 2, and the package's
tag on the error stream), not a server without TLS. The files are read once, at start: a renewed certificate needs a restart (*not in this
part:* a reload; *built since, 6bu*).

**The protocol (read: PostgreSQL's `protocol-flow`, "SSL Session Encryption").** A client sends `SSLRequest` in clear; the server answers one
byte, `S` or `N`; after `S` the client begins the TLS handshake, and the startup message comes inside.

- With no `tls=`, `N`, as before. With it, `S`, and the connection is TLS from the next byte.
- **Bytes that came with the `SSLRequest` are a refusal** (the connection is ended): what a client sent before the handshake is not to be
  read as if it had come inside it (PostgreSQL's CVE-2021-23214 is this).
- An `SSLRequest` inside TLS ends the connection. `GSSENCRequest` is answered `N` as before.
- A handshake that fails ends the connection; the package's alert is sent first when it has one.
- *Choice:* a connection may still begin in clear when `tls=` is given. The server serves this machine only, as before, and a client on it
  chooses (`sslmode`). **Clients from other machines are the next part**, and there a startup in clear will be ended.
- *Not in this part:* client certificates; ALPN (`postgresql`, which PostgreSQL 17's direct TLS needs); direct TLS without `SSLRequest`;
  channel binding (there is no SCRAM here: the login is a token, 6at).

**How the bytes move.** The server reads a connection in one place (`receive`) and writes in one (`push`). Both go through a new module,
`src/tlsio.cho`:

- *Reading.* What the socket gives is kept in the connection's own room for ciphertext (17 KiB: one record and its header fit) and fed to
  the package; what the package then has in clear is moved into the connection's buffer, where a message is parsed as it always was. The
  package takes nothing when its own room is full, so what it has not taken stays in the connection's room, and the socket is not read until
  it is taken. Whatever the package wants sent (its flight, an alert, a key update) is written at once.
- *Writing.* `push` gives the answer to the package a piece at a time and writes what it makes, waiting for the socket as it does in clear,
  and for no longer (`g_write_ms`).
- *Ending.* `close_notify` is queued and written if the socket takes it at once; then the slot is dropped, which overwrites its keys.
- *As built:* the two pure pieces are `src/tlsio.cho` (`absorb`: the connection's ciphertext into the package, its clear bytes into the
  buffer); what touches the socket stayed in `src/serve.cho` (`receive_tls`, `flush`, `push`), beside the code in clear it stands for. A
  peer's `close_notify` is not a failure: what it sent before is still answered, as for a socket that ends. Each pass over the connections
  moves what the package and the connection's room still hold, since a socket with nothing more to read would never say so.
- A connection has the same slot in the package as in the server's table, so there is nothing to look up.

**The random bytes** the package needs (its DRBG's seed, 32) are read from `/dev/urandom` at start, beside the salts' seed (6ag), and are
not the same bytes.

**Cost, measured** (`python3 scripts/measure_tls.py build/engine build/enginecheck 2000`, medians, one server, the client on the same
machine; two runs):

| | in clear | through TLS |
|---|---|---|
| connect and startup, to `ReadyForQuery` | 0.05 to 0.06 ms | 1.07 to 1.10 ms |
| a select by key | 71 to 86 µs | 78 to 88 µs |
| an update, committed and synced | 540 to 624 µs | 571 to 660 µs |
| 1,000 rows | 3.1 ms | 2.0 ms |

A statement costs the same within the noise of the two runs; a connection costs a millisecond more. The server's binary is 1,267,200 bytes
(739,080 before the package was in it), and its resident memory 14.5 MB with a certificate loaded.

*Found by measuring:* the first run said 44 ms a connection. It was the test's client, not the server: Python's socket holds a small write
for the acknowledgement of the one before it (Nagle), and the server has nothing to send after a client's Finished, so its acknowledgement
waits 40 ms. libpq sets `TCP_NODELAY`, and now the test's client does. `TCP_NODELAY` on the server's side was tried and changed nothing
(0.95 against 0.85 ms), so it is not set.

*The build:* the package is 17 files of the compiler's repository, named on the command line of the one build that has the server in it
(`scripts/check.sh`, `tests/mutants.py`); that build takes 24 s where it took 12. The verifier's build of "all of `src`" leaves the server
out, and the test program never had it.

**Test.** `tests/engine_tls.py`, with a P-256 certificate made by `openssl` for the run:

- `psql "sslmode=verify-full sslrootcert=..."` runs statements and reports `TLSv1.3`; `sslmode=disable` still works; with no `tls=`,
  `sslmode=require` is refused by psql and `sslmode=prefer` goes on in clear.
- Python's `ssl` over the same socket: the differential of 6al (random statements against PostgreSQL) run through TLS, answers of more than
  one record (a large select), and many small messages in one record.
- Bytes after `SSLRequest` in the same packet: ended, nothing answered after `S`.
- A handshake that is garbage, one that stops half way, a client that closes without `close_notify`, a second `SSLRequest` inside TLS.
  *Corrected:* this said "the idle rules still end" a handshake that stops half way. There is no such rule: a client that connects and
  sends nothing holds one of the sixteen places until it goes, in clear as through TLS. What is tested is a client that stops and closes.
  **A time limit for a startup is not built.**
- A login by token through TLS (6at). *Not done:* a revoked token's connection ended through TLS (6bd is tested in clear; the code that
  ends it is the same `finish`).
- The start refused: no `key.pem`, a key that is another certificate's, an RSA key, an expired certificate.
- Mutants of `src/tlsio.cho` and of the server's new lines, each killed.

*As built, the test (three seeds in the gate):* the differential of 6al through TLS (929 statements at seed 1, the page file and the log
as in clear); psql 16 with `verify-full`, and refusing a server it does not trust; a row of 24,000 bytes; sixty queries in one record; a
query a byte a record; 26,964 writes sent while another connection's transaction makes them wait (a little more than the connection's
buffer; *corrected twice, below*); `close_notify` sent, answered, and after a query in
the same packet; a record that is no handshake; 24 handshakes of random bytes, cut short or with a byte changed; six certificates and keys
that stop the server from starting. **19 mutants, all killed** (`MUTANT_ONLY=tls python3 tests/mutants.py wire`). One line has none: a
failure the package would say only when read from, which no test reaches (it says it when fed). Nor has the rule that stops the socket
being asked while the connection's room is full: without it the server would spin, and answer the same.

*Found by CI:* the test read psql 16's sentence for `\conninfo` ("protocol: TLSv1.3"); CI's psql is newer and prints a table ("SSL
Protocol | TLSv1.3"), so the first run there failed on a connection that was TLS 1.3. The test reads either.

*Found by CI, a PR later, and then by slowing the client down:* the mutant "what waits in the package is read only when the socket has
more" was killed here and in one run of CI, and survived in the next two. Its tests, in order, and why each was a matter of speed:

1. 45,000 queries sent at once: it relied on the buffer filling, which depends on how fast the server empties it.
2. The statements made to wait (writes, beside another connection's transaction), half as much again as the buffer holds: with that
   much left over the socket has more to give, and reading it moves what waits, so the pass is not needed.
3. 3,020 bytes more than the buffer holds: killed here, but run with the client slowed by hand (16 KiB every half millisecond) the
   mutant answered everything. A slow client's last bytes arrive after the buffer is full, stay **in the socket**, and are read when the
   buffer empties.

What the pass is for is bytes left **in the package** with the socket empty. The test now sends the bytes that cross the buffer's end
as one record: the package opens it whole, the buffer takes 2,000 bytes of it, and 3,020 are left where only the pass reaches them. Run
by hand at five speeds of the client (all at once; 16 KiB, 4 KiB and 64 KiB at a time with pauses; 1,000 bytes at a time), the mutant
stops at statement 26,886 of 26,964 every time, and the server as it is answers all of them.

*Found by the gate:* the seventeenth connection, which is told `53300` before it has a place, went through the new `push`, which asks
whether its place is inside TLS: a place past the last, so the server stopped on an index out of range. `tests/engine_wire.py` (`several`)
failed on it. That one answer is written in clear, with `put`, and never asks.

**What this does not show.** That the package's cryptography is right: that is its own tests' claim and nobody outside has reviewed it.
That a server is safe to put on a network: it still serves this machine only. Certificates other than ECDSA P-256; a certificate renewed
without a restart; client certificates.

## 6br. Clients from other machines

*Design, written before the code. Choices are marked; what is measured has its command.*

**What there is.** The server takes a client from this machine and closes any other unread (`from_here`, 6al), because everything travelled
in clear. Since 6bq it can end TLS. A database only this machine can reach is not what TLS was built for.

**The rule (choice).** A client from another machine is given a place only by a server that has **both** a certificate (`tls=`, 6bq) and
a login (the root's key, 6at). With either missing it is closed unread, as before: a server with no login would serve anyone who can reach
its port, and one with no certificate would be handed tokens in clear.

- Its first packet must be the `SSLRequest`. A startup in clear is answered `28000`, `cancho-db: refused tls-required`, and the connection
  is ended **before a password is asked for**, so a client set to fall back to clear never sends its token.
- After the handshake it is a connection like any other: it logs in with its token and is held to it.
- A client from this machine is as before: it may come in clear.
- *Read (`src/login.cho`):* the listener binds every address (cancho's `tcp_listen` has no other form at this revision), so there is no
  "listen on this address only"; who is served is decided by the peer's address at `accept`.

**A time limit for the startup.** 6bq found that a client that connects and says nothing holds one of the sixteen places for as long as
it likes. From this machine that was a nuisance; from anywhere it is an attack one socket wide. *Choice:* a connection that has not
finished its startup (the TLS handshake, the startup packet and, with a login, the password) within `WRITE_MS` of being accepted is ended
unanswered. `WRITE_MS` is already "how long a client may keep the server waiting" (default 10 s); a second number was not worth a seventh
word on the command line. The server looks once a turn, which is at least once a second, so the limit is kept to within a second.

**What this does not do, said plainly.**

- **Sixteen places are still sixteen.** A client that cannot log in holds a place for at most the limit, but nothing stops it coming back,
  and there is no bound per address. Someone who can reach the port can keep others out. *Not built:* more places, or a bound per address.
- The certificate proves the server to the client; the token proves the client to the server. There are no client certificates.
- The TLS package is unreviewed by anyone outside (6bq). Putting the server on a network rests on it.

**Test** (`tests/engine_tls.py`, from this host's own address that is not loopback; skipped, and saying so, on a host that has none):
a client from there is closed unread by a server with no certificate, and by one with a certificate and no login; with both, a startup in
clear is answered `28000` and no password is asked for, a token through TLS is let in and held to what it allows, a wrong one refused. The
limit: a socket that says nothing, one that stops after the `SSLRequest`, and one that stops before its password are each ended at the
limit and not before; a connection that has logged in and then idles is not. Mutants, each killed.

*As built:* the place's mark is one int of the connection's (`st[18]`), set at `accept`; the limit is looked for once a turn, before the
idle transaction's. The test runs from 192.0.2.2 in the sandbox it was written in. **10 mutants, all killed**
(`MUTANT_ONLY="tls: far"` and `"tls: limit"`, `python3 tests/mutants.py wire`), and the older mutant that serves a client from anywhere is
still killed by `tests/engine_wire.py`. *Found while testing, and not a fault:* a token of `r:*` is refused `select count(*)`; a call
is an effect of its own (kind 3, `c:` in `tools/mint.py`; `docs/spec/ir.md`), so the token needs `c:count` too.

## 6bs. Reads beside a transaction

*Design, written before the code. The first part of more than one session at work at a time; the second (two transactions that write) is
sketched at the end and is not built here.*

**What there is (6aq).** While a connection is in a transaction, everything the others send waits, reads too. 6aq said why reads could be
answered and were not: "one rule first". A dashboard that reads while a batch job holds a transaction for a minute waits a minute.

**Why a read can be answered.** The tree is copy-on-write (D-M3-1): a transaction builds a tree of its own and the branch's root does not
move until its `commit`. So the branch's tree, read while a transaction is open, is exactly what is committed: a read on it sees none of
the transaction's writes, never half of them, and is the read PostgreSQL would give at `read committed` for a statement that began before
the commit.

**The rule.** While another connection is in a transaction, a connection that is in none has its statement run on the branch's tree if
the statement **only reads**; any other statement waits, as before. A statement only reads when all of this holds, decided from its tokens
before it runs (`drive.reads_only`):

- its first word is `select`, and it is one statement (no `;` before its end);
- it has none of the words `nextval`, `setval`, `into`, and no word that begins `cancho_` (the engine's own functions: an erase, a trim
  of the history). A sequence is drawn from, and written, by a `select`; so those wait.

Everything else waits: `insert`, `update`, `delete`, any definition, `begin` (a second transaction beside the first is the second part).
The rule errs on the side of waiting: a `select` over a column named `into_x` reads, one with a string `'nextval'` reads (a string is not
a word), and a `select` with the word `into` waits though PostgreSQL's `select ... into` is refused by the engine anyway.

**A net under the rule.** If a statement that the rule let through turns out to have written (the tree it leaves is not the tree it was
given), it is not committed: what it did is discarded as a failed statement's is, and the client is told `0A000`,
`cancho-db: refused read-beside-wrote`. No statement is known to reach it; it is there so that a hole in the rule is a refusal and not a
lost update.

**What the transaction must not notice** (read: `src/serve.cho`, `src/session.cho`, `src/exec.cho`). One thread still runs one statement
at a time; a read beside a transaction runs *between* two of the transaction's statements, and uses the same working memory.

- *The clock.* `now()` is the time a transaction began (6bp), kept in the working memory and set whenever a statement runs with no
  transaction open. A read beside would set it, and the transaction's next `now()` would move. So the clock becomes each connection's own
  (one more int of its state), set when it is in no transaction and given to the working memory before every statement.
- *The numbers a statement writes with* (`set_txn`, `set_once`, the draws) are set by `session.open` before every statement already.
- *The pages.* A statement's window (6p) is flushed when the next begins; a read hands back the pages it took (6be). The transaction's
  tree is in the file, named by its session.
- Whatever else there is, the test below is what finds it: a transaction interleaved with reads must answer and commit exactly as alone.

**What a reader sees, said plainly.** The committed state, statement by statement: two reads beside one transaction see the same rows; a
read after its commit sees all of it. A reader that needs two statements to agree with each other across someone else's commit has
`begin`, which waits.

*Not in this part:* a statement of the extended protocol that reads (it waits as before: the rule is applied to a simple query's text
first, and the Execute path has its own skipping rules; next. *Built since, below*); two transactions at once.

**Test** (`tests/engine_wire.py`, `beside_reads`). A history from the differential's generator is run by one connection in transactions
of a few statements each, some rolled back, while a second connection reads between every two statements. (1) The first connection's
answers, the page file at the end and the log are what the test program gives for the same history alone. (2) Every read of the second
connection inside a transaction's span equals the read it made just before the `begin`, and after a `commit` equals what the first
connection reads. (3) `now()` in a transaction is the same before and after a read beside it that comes a second later. (4) Beside a
transaction, each of these waits until it ends: an `insert`, a `select nextval(...)`, a `select cancho_...`, a `begin`, two statements in
one query. (5) The 30-second rule of 6aq is unchanged for those that wait. Mutants of the rule and of the clock, each killed.

**As built, and what building it found.** `drive.reads_only` (the rule), `reads` and the one condition in `step`, the connection's
clock (`st[20]`), `exec.seq_hold` (`src/serve.cho`, `src/drive.cho`, `src/exec.cho`).

- *Found by the test, on its first run:* the transaction did notice. Statement 416 of the history, a `rollback`, answered
  `engine-damaged`, and everything after it. The draws a transaction has made from counters are noted in the working memory until it ends
  (6y), and a statement that runs with no transaction open forgets them when it ends, or, **if it failed, writes them into the branch's
  tree**: a read of a table that is not there, beside a transaction that had drawn from a sequence, committed a tree beside the
  transaction's. The design's list had "the draws" as set before every statement; that was false. A statement beside a transaction now
  leaves the draws alone (`seq_hold`), and the net was widened: whatever its ending would write is not committed either.
- *The rule's `;`:* the lexer gives no token for a `;` that ends the text, so "no `;` before its end" is "no `;` token"; the mutant
  written for the difference survived, and the condition it stood on was removed.
- *Three older tests said reads wait* (`tests/engine_wire.py`, `several`): they used a `select` as the statement that waits. They use a
  write that changes nothing, and one now says a read is answered at once with what is committed.
- *The test, as run* (three seeds in the gate; at seed 1): 107 times the second connection read three tables inside a transaction of the
  first, each answered at once and equal to its read before the `begin`; 929 statements of the first answered as the test program, the
  page file and the log the same. Nine statements that wait, four that read. **12 mutants, all killed**
  (`MUTANT_ONLY=beside python3 tests/mutants.py wire`).
- *Not tested:* the net (`read-beside-wrote`): no statement is known to reach it, which is what it is for. That a read beside a
  transaction costs the transaction nothing in time is not measured.

**An Execute that reads** (*added after the first part; a driver that prepares its statements sends nothing else*). The rule is applied
to the text of the statement the portal was bound to (`reads_portal`): the unnamed statement's, or the named one's. The messages before
the Execute (Parse, Bind, Describe) never waited. An Execute with no portal is refused whenever it is let through (nothing runs); a
rule that made it wait first had a mutant that survived, and was removed. *Test:* the second connection of the interleaved history reads every other time by Parse, Bind, Describe,
Execute, Sync; a read with a parameter and one prepared under a name are answered beside a transaction; a write, a `select` that draws
from a sequence, and a write prepared under a name while the unnamed statement is a read, each sent by the extended protocol, wait.
Three more mutants.

**The second part, sketched: two transactions that write.** Each on a tree of its own from the root it began with. At `commit`, if the
branch has not moved, as now. If it has: the transaction's facts (6as: every row it wrote, with what the row held before) are held
against the facts committed since it began; if no row is in both, they are applied to the branch's tree as it is now, and if one is,
the commit is refused `40001` (PostgreSQL's serialization failure, which clients already retry). That is snapshot isolation with the
first committer winning. Open, and the owner's to decide before it is built: whether a unique index or a sequence makes two
transactions conflict, and whether `read committed` is to be claimed (it cannot be, as designed: a statement would see its own
transaction's snapshot, not each statement's).

## 6bt. More places, and a bound for an address

*Design, written before the code.*

**What there is.** Sixteen places (6aq), fixed in the source; and since 6br a client from anywhere may take one. 6br said it plainly:
"who can reach the port can keep others out by coming back". Two things are missing: a server that many clients use needs more than
sixteen, and one address should not be able to hold them all.

**Places (choice).** One more word on the command line, `places=N`, beside `tls=` and before `check-purge` (the three in any order after
the words that have a place): 1 to 128, 16 without it. A place costs what a connection may hold, allocated when the server starts:
its buffer (1 MiB), what the extended protocol keeps (2.07 MiB), its room for ciphertext (17 KiB), and the TLS package's slot. *To be
measured:* the server's memory at 16, 64 and 128 places. A number that is none of 1 to 128 is a refusal to start (status 2).

*Why not places that grow:* everything a connection holds is one allocation made at start, sliced by its number; the server never
allocates while it serves, which is why a client cannot make it run out of memory. That is kept.

**A bound for an address (choice).** A client that is not of this machine is given a place only while its address holds fewer than a
quarter of the places (at least one): with 16 places four, with 64 sixteen. One more is told `53300`,
`cancho-db: too many connections from this address`, in clear, and closed; nothing of it is read. The address is the peer's IPv4
address (*read, the compiler's `docs/conn-peer.md`: every cancho socket is IPv4 at this revision*; an IPv6 peer, when there is one, is
counted by its /64).

- Clients of this machine are not bounded: an application beside the server pools as many connections as it likes, as before.
- A place counts for its address from `accept` until the connection ends, whether or not it has logged in: a client that never logs in
  holds at most its quarter, each for at most the startup's limit (6br).

**What this does not do.** Someone with many addresses still fills the places a quarter at a time; clients behind one address (a NAT,
a proxy) share its quarter. A bound that an operator sets, and a list of addresses, are not built.

**Test** (`tests/engine_tls.py`): a server with `places=8` and both a certificate and a login: from this host's other address two
connections are given places and the third is told `53300 ... from this address` and closed, while six clients of this machine are
served; when one of the two ends, another from there is let in. A server with `places=40`: forty clients served at once, each
answering, and the forty-first told `53300`; without the word, the seventeenth (6aq's test, unchanged). `places=0`, `places=129` and
`places=x` do not start. Mutants, each killed.

*As built, and measured.* `places=N` and `tls=` are read in any order after the words that have a place (`proxy/engine.cho`); the bound
is at `accept` (`src/serve.cho`), with the address in two ints of the connection's state. The server's memory when it starts
(`/proc/<pid>/status`, one run each): 166 MB of address space and 3.6 MB resident at 16 places; 331 MB and 3.7 MB at 64; 550 MB and
3.4 MB at 128. So a place is 3.4 MB of address space, and of memory only what its connection comes to use: the buffers are allocated
zeroed and the kernel gives a page when it is first written. *The design said "allocated when the server starts"; that is the address
space, not the memory.* **5 mutants, all killed** (`MUTANT_ONLY="tls: places"`). *Not tested:* that two addresses are counted apart (the
host the test runs on has one address that is not loopback); the parsing of `places=` has a test and no mutant, since the mutants are
of `src/` and it is in `proxy/engine.cho`.

## 6bu. A certificate renewed while the server runs

*Written with the code, not before it: the design was three decisions, each said here with what was built and measured.*

**What was missing (6bq).** The certificate was read once, at start. A certificate lasts ninety days or less; a restart for each renewal
ends every connection.

**How the server learns of a renewal (choice): it looks.** Every two seconds it reads `chain.pem` and `key.pem` again, hashes each, and
if either differs from what it last took, gives the pair to the package in place of the one it has (`tls.replace_identity`). Considered
and not chosen: a signal (the server has no signals, and its authority report says so: `tests/authority.sh`); the files' times (a
renewal replaces two files, and one can be seen changed before the other).

**Half a renewal is not a problem, because the package refuses it.** A new key beside the old certificate is a key that is not the
certificate's: `tls-server-key-mismatch`, and the identity there is stays (*read: `packages/tls/tls.cho`, `replace_identity`: "refused
as `add_identity` is, and then the identity is as it was"*). Two seconds later the certificate is there too and the pair is taken. The
same for anything else the package refuses (an RSA key, an expired certificate): the old one is served, and the server says why on
standard error, **once** for each reason and not every two seconds. When a pair is taken it says so.

**The server holds no path for it.** The directory is opened once, at start (`open_dir`), and everything after is read beneath the
handle (`src/tlsid.cho`: `dir_read`, `file_read`): the loop that faces the network can read that directory and name no other file. The
cost, as the compiler's own TLS example found: **a symbolic link in the directory is refused.** certbot's `live/` is links into
`archive/`; a deployment copies the two files in (a deploy hook does). With no `tls=` the handle is the directory the server was started
in, never read: a handle has to be passed, and a server with no certificate has no other directory.

- Connections made before a renewal go on with the keys they have; the next handshake uses the new certificate.
- The key is read into memory every two seconds and overwritten after, as at start.

**Measured.** A renewed pair is served 1.5 s after the second file is moved into place (one run; at most the two seconds and a turn).
The files are some 800 bytes together; reading and hashing them every two seconds is not measured against anything, and is not claimed
to cost nothing.

**Test** (`tests/engine_tls.py`, `renewed`): three certificates, each trusted by a client that trusts no other. The first is served and
the second is not; the second's key alone is moved in, and after 4.5 s the first is still served; its certificate is moved in, and the
second is served within eight seconds and the first no longer, while a connection made at the start still writes; an RSA pair is moved
in and the second goes on being served; the third is moved in and served. The server's standard error has "not taken:
tls-server-key-type" once, "not taken: tls-server-key-mismatch" at least once, and "read again" twice. A directory that cannot be
opened, and one with no `chain.pem`, do not start. **6 mutants, all killed** (`MUTANT_ONLY="tls: renew"`).

*Not built:* a chain that changes its names (the identity keeps the one name it was given); more than one certificate (SNI).

## 6bv. Transactions side by side: the first part

*Design, written before the code. The owner chose "concurrent" over one writer at a time (27 Nov 2026) and left the particulars; each
is marked a choice here, and is the owner's to overturn.*

**What there is.** A transaction has the database to itself (6aq): what the others send waits, but for reads (6bs). A job that holds a
transaction for a minute stops every writer for a minute.

**Who asks for it (choice): a transaction that names its isolation level.** `begin isolation level serializable` (or `repeatable read`;
`start transaction ...` and `begin transaction ...` too) begins a transaction **beside** the others. A plain `begin` is as before:
it has the database to itself, waits for nobody's permission to commit, and is never refused for what another connection did. So a
client that was written for the server as it is sees nothing change, and a client that asks for one of these levels is one PostgreSQL
already tells to be ready for `40001` and to run its transaction again. (`read committed` and `read uncommitted` named in a `begin` are
refused as every option was: a plain `begin` is the server's default, and is stronger than both.)

**What a transaction beside the others is.** It runs on the tree that was the branch's when it began (its *snapshot*), and builds a
tree of its own from it, as every transaction does (6v). It sees its own writes and nothing anyone commits after it began. Nobody waits
for it, and it waits for nobody, until it ends.

**The rule at its end (choice): first committer wins, the whole database being one thing.**

- A transaction that **wrote nothing** commits, whatever happened meanwhile: its reads were all of one committed state.
- A transaction that wrote commits **if the branch has not moved since it began**: its tree becomes the branch's, exactly as a
  transaction's does today.
- If the branch has moved, it is refused: `40001`, `cancho-db: refused serialization-failure`, and what it did is rolled back.

That is serializable, not only snapshot isolation: a transaction that commits having written saw the state its commit is made on, so it
is as if it ran whole at that moment; one that only read is as if it ran whole when it began. No two transactions' reads and writes
can cross (write skew), because of two that wrote and overlapped only one commits. The price is plain: **of two transactions that
write at the same time one is refused even if they touch different rows.** Applying the second's rows to the first's tree when no row
is in both (snapshot isolation, for `repeatable read`) is the second part, and is not built here.

**How it lives with the others.**

- A plain transaction still has the database to itself: while one is open, a transaction beside it goes on reading and writing its own
  tree (it touches nothing of the branch), but its `commit` or `rollback` waits for the plain one to end, like any write.
- A statement outside a transaction beside an open one runs and commits at once, as if the open one were not there; if that one has
  written, it has then lost.
- A read beside is as 6bs.

**What they must not notice of each other** (6bs found one such thing by testing; this part has more of them at once).

- *The draws from counters* (6y) are noted in the working memory until a transaction ends. With two transactions open they are two
  lists. They become each connection's own, put into the working memory before its statement and taken out after; 6bs's `seq_hold` goes.
  A counter drawn from in a transaction stays drawn if it is rolled back or refused (6y), written to the branch as it then is.
  *Corrected by the test (below): that is not enough. A draw has to count as a write.*
- *The clock* is each connection's already (6bs).
- *The numbers a statement writes with* come from the transaction's snapshot, not from the branch as it is now. *Corrected: they need not.
  The code that gave a statement its transaction's first tree for this had a mutant that changed nothing, and was removed: a statement
  takes the numbers after the branch's last, and those are the right ones whenever its transaction commits at all, since it commits only
  if the branch has not moved.*
- *The pages.* **A sweep frees the pages no committed tree names (6aw), and an open transaction's tree is such pages.** Today no commit
  happens while a transaction is open, so no sweep does. Now one can. So: no sweep, and no purge after an erase, while a transaction
  beside the others is open; an erase asked for then is refused, `25001`, `cancho-db: refused erase-beside-transaction`. A transaction
  that stays open keeps the file from being swept; one that has been idle for the idle limit (30 s) while a sweep is due is ended,
  `25P03`, as an idle plain transaction is when someone waits for it.
- Whatever else there is, the test finds or it is not known.

**The log** is unchanged: a transaction that commits beside the others commits on the tree it began with, so its commit is the one a
plain transaction would have made.

*Not in this part:* the second part above; a transaction that is `read only` or `deferrable`; savepoints; `set transaction`;
PostgreSQL's own rule for `serializable` (it refuses fewer transactions than this does: it looks at what each read).

**Test** (`tests/engine_sidebyside.py`). The oracle is the server itself, one client at a time: *every history must be one a single
client could have produced.*

1. Several connections each run random transactions beside the others (statements from the differential's generator over shared
   tables, with counters), with plain statements and plain transactions among them, interleaved by a seeded schedule. Then the
   transactions that committed, in the order they committed (those that wrote nothing where they began), are run again by one
   connection on a fresh server: every statement must get the answer it got, and the tables at the end must be the same. Of two that
   wrote and overlapped at most one committed; every refusal is `40001`.
2. Fixed cases: two that write different rows (one is refused: the price above, asserted so that the second part must change the
   test); one that only reads commits after others wrote, and read one state throughout; a plain transaction is never refused and makes
   one beside it wait at its `commit`; a counter drawn from in a refused transaction stays drawn; `now()` is each one's own.
3. A sweep that is due while one is open does not happen until it ends (the file is read afterwards by the test program, whole); an
   erase then is refused; one idle past the limit while a sweep is due is ended.
4. The log of the whole run verifies (L1 to L3a).

**As built, and what building it found.** `drive.side_begin` and `drive.ends_txn` (what a statement is, from its words), the rule in
`answer` (`lost`, `nothing`), `aside` in `step` (who waits), a count of the open ones (`g_sides`), the connection's own draws
(`exec.seq_give`, `seq_take`) and the tree it began on (`st[23]`) (`src/serve.cho`, `src/drive.cho`, `src/exec.cho`,
`src/session.cho`). The parser is not touched: a `begin` with a level is read by the server and run as `begin`, so the proxy and the
test program refuse it as they did.

- **Counters are not PostgreSQL's.** A transaction beside the others draws from the counter as it was when the transaction began, so
  two of them can draw the same number (101 and 101, in the test). No number ends with two holders, because **a draw is a write**: the
  counter is in the tree, a transaction that drew has a tree of its own, and it commits only if nobody committed since it began; the
  other is refused and its number is void, as everything a refused transaction was told is. In PostgreSQL a counter is outside every
  transaction and two never draw the same number, even if both are rolled back. *Corrected twice here.* The design said "stays drawn"
  and no more. Then a rule was added that counted a connection's noted draws as a write, on the argument that one that only drew
  "wrote nothing"; its mutant survived, because it never wrote nothing: the draw had changed its tree. The rule was removed, and so was
  half of `session.wrote` (a transaction with facts and its first tree does not exist). *Read (`src/drive.cho`): `select nextval(...)`
  is refused by the engine (`nondeterministic`), so a draw is in a statement that writes or would have (`insert ... on conflict do
  nothing`).*
- *What a rolled-back one drew stays drawn* (6y), with other connections' statements in between: tested, since two mutants of the
  connection's own draws (`seq_give`, `seq_take`) survived until it was.
- *The test, as run* (`python3 tests/engine_sidebyside.py build/engine build/enginecheck 300 1`; three seeds in the gate): 300
  transactions and statements of four connections; 26 committed having written, 36 having only read, 42 refused, 18 rolled back, 73
  failed (a statement of theirs met an error), 105 statements outside any; run again by one client, each of the 683 statements got the
  answer it had got and the tables ended the same; the log verified with 72 commits. The fixed cases are in the test's own words.
- *The pages:* with a transaction beside the others holding a thousand rows of its own while another connection rewrote 2,000 rows
  twelve times, its rows were whole; the mutant that lets the sweep run then is among those below.
- **Mutants: 15** (`MUTANT_ONLY="side: " python3 tests/mutants.py wire`, which runs the 15 of `beside` with them), and eleven older ones
  whose lines these changes moved. Three written at first were of code that was then removed (above).

**What this does not show.** That it is fast: nothing here is measured for speed, and the rule refuses one of every two that overlap
and write. That four connections and 300 transactions meet every interleaving: the schedule is random and seeded, not exhaustive.
Transactions beside the others with definitions in them (`create table` inside one) are not in the random history. A connection that
ends inside one while a plain transaction is open loses what it drew from counters (said in the code; not tested).

## 6bw. Transactions side by side: the second part, rows

*Design, written before the code. The owner chose it (27 Nov 2026: "go with row level"), with `serializable` keeping the first part's rule
and `repeatable read` taking this one. Who uses what was read first, at the owner's asking: neither sibling that speaks to a database
names an isolation level (`cancho-hooks` at 40b2ce0, `src/roster.cho`: `begin`, `commit`; `cancho-ota` at feb14de, `src/store.cho`:
`begin`, `commit`, and `select nextval('design_ids')` on its own), and neither handles `40001`. So nothing here changes what they see,
and counters stay as 6bv left them.*

**What is missing (6bv).** Of two transactions beside each other that write, one is refused, even if they touch different rows: the
whole database is one thing. A transaction is refused for what it could not have been harmed by.

**The rule, for `begin isolation level repeatable read`.** At its commit, if the branch has moved since it began:

1. **A row it wrote that someone else wrote since** is a conflict: for each key the transaction wrote (stored, changed or removed), what
   the branch holds at that key now must be exactly what it held when the transaction began. If not: `40001`, as before.
2. **A counter it drew from that someone else drew from since** is a conflict (the same test, on the counter). Otherwise two
   transactions that both commit could hold one number.
3. **A definition** made by the transaction, or by anyone since it began (the schema's text differs, 6bc), is a conflict: tables are not
   merged.
4. Otherwise **its rows are put on the branch as it is now**, and that tree is what it commits. A row whose values are already in a
   unique index of the branch (someone took them since) is a conflict too: `40001`, and when the transaction is run again the
   statement itself says `23505`.

That is snapshot isolation with the first writer of a row winning, which is what PostgreSQL calls `repeatable read`. It is **not**
serializable: two transactions that each read what the other writes, and write different rows, both commit (write skew).
`begin isolation level serializable` keeps the first part's rule, which refuses one of them.

**How the rows are put.** Not by running the statements again: they were answered from the snapshot, and run now they might write
other rows. And not from the facts (6af): those are hashes. So:

- *Which rows.* While a transaction beside the others runs, every key a statement stores or removes is noted in a tree of the
  transaction's own (the table's name and the key; `exec.row_put` and `exec.row_del` are the two places a row is written).
  *Corrected: they are not the only two.* An `update` that moves rows to other keys writes them with `put_key` and `del_key`
  (`execw.settle`). What every write of a key with a history goes through is `exec.remember`, and that is where a key is noted. The
  transaction's tree holds what each of those keys holds at its end.
- *The same bytes.* A stored row is its two salts and the row (6ag). The bytes are copied from the transaction's tree to the branch's,
  salts and all. So the transaction's facts stay true without being made again: for each key, "what it held when the transaction first
  touched it" is what the branch holds now (rule 1 says they are the same bytes), and "what it holds at the end" is the bytes copied.
- *What a write does besides.* Each copy does what `row_put` does around the bytes: the record of what the key held before (6n), and
  the entries of the table's indexes (6bo), taken out for the old row and put in for the new.
- *The order* is the keys' order. A unique value handed from one row to another inside the transaction may be seen taken while the
  rows are put, and the transaction refused though it need not be. Said, not solved.
- *The counters* it drew from are written to the new tree (6y's replay), which rule 2 has shown nobody else moved.
- Then the commit is an ordinary one: the tree made this way is the transaction's tree, and `session.close` does the rest (its number,
  its record in the log with the schema it began with, its facts).

**What the log says.** One commit, with the facts of the rows the transaction changed and the statements it ran. A verifier that
replays the changes (L3a) reaches the state the file holds; nothing in a record says the transaction began on an older state, and
nothing needs to: a commit's facts are against the commit before it, and they are.

**The cost,** to be measured: a commit that finds the branch moved reads each key it wrote in two trees and writes it in one. A
transaction that wrote ten thousand rows pays for ten thousand at its commit; one that finds the branch as it left it pays nothing new.

*Not in this part:* a transaction that writes a table with an identity column and finds the branch moved is refused as in the first
part, unless the test shows its counter is covered by rule 2; `serializable` by anything finer than the first part's rule
(PostgreSQL's looks at what each transaction read); savepoints; `select ... for update`.

**Test** (`tests/engine_sidebyside.py`, extended). The first part's oracle was "one client, in the right order". Snapshot isolation is
not that: a transaction's reads are of when it began and its writes land when it commits. So the single client is made to do exactly
that, on a fresh server kept in step with the first:

1. In the order things happened: where a transaction **began**, the client begins one, runs its statements and checks each answer
   against the answer it got, then reads the tables whole, **rolls back**, and keeps what changed (the transaction's effects: rows
   stored, changed, removed). Where it **committed**, the client applies those effects with plain statements. Statements outside any
   transaction are run where they ran.
2. The tables at the end must be the same. So must the rule: a transaction of `repeatable read` that committed having written is one
   whose keys nobody else changed while it was open, and one that was refused is one for which somebody did; for `serializable`, as
   in the first part. Both are computed from the single client's own record, not asked of the server under test.
3. Fixed cases: two that write different rows both commit, and both rows are there (the line 6bv said this part must change); the
   same row, one is refused; write skew commits at `repeatable read` and is refused at `serializable`; a unique value taken meanwhile;
   a counter both drew from; a definition on either side; indexes after a merge answer as a scan does; the history of a merged row
   (`AS OF`) is what it was (*not done: nothing reads the past of a merged row in the test; the log's replay, L3a, is what holds the
   records of the rows to what they were*); a large transaction merged whole.
4. The log of the run verifies (L1 to L3a), with merged commits in it.

**As built.** `src/merge.cho` (`onto`: the counters, then every key held to the rule, then every key put), `exec.track` and the note
in `exec.remember`, `session.schema_same` and `retree`, and in `answer` the one place a `repeatable read` that has "lost" is tried
(`src/serve.cho`); a connection's state has the tree of its keys and its level. The rule for the level is read with the `begin`
(`drive.side_begin` answers 1 or 2).

- *It ran the first time,* and the oracle agreed on three seeds (`python3 tests/engine_sidebyside.py build/engine build/enginecheck
  300 <seed>`). At seed 1: 300 transactions and statements; at `repeatable read` 29 committed having written and 5 were refused; at
  `serializable` 16 and 22; 683 answers the same, the tables the same, and nobody refused or let through against the rule of its
  level. The log verified with 82 commits, the merged ones among them.
- *Identity columns* needed nothing of their own (*read, `src/execw.cho`, `insert`: a table's counter is noted with `exec.seq_note`
  under the table's number, as a sequence's draw is*), so rule 2 holds it. *Not tested by name: the fixed cases use a sequence.*
- *Measured:* a transaction of 3,000 rows (with an index) put on a branch that had moved commits in 136 ms (one run, the server
  with a key file, so the commit is signed and synced as any is).
- **17 mutants, all killed** (`MUTANT_ONLY="side: rows" python3 tests/mutants.py wire`).

**What this does not show.** Write skew is allowed at `repeatable read`, and the test shows it happening. A transaction refused for a
unique value that it handed from one of its own rows to another (the order the rows are put in) is said and not tested. A row
rewritten by someone else with the values it had is a conflict (its bytes differ); the oracle allows that and does not require it.
Nothing is measured against the first part's rule for how many transactions it saves under a real load: the random history has 24
keys on purpose, so that they meet.

## 6bx. What a sibling's own SQL asks of the engine: the measure, and the order

*A plan, measured before anything is built. The owner asked for "what ota needs" (27 Nov 2026). `cancho-ota` is the one sibling that
uses PostgreSQL broadly; its repository is private, so nothing of its SQL is quoted here: only counts, by the engine's own refusal.*

**The measure** (`python3 scripts/measure_client.py build/engine build/enginecheck <its migrations> <its store's source>`, at its commit
feb14de, the engine at a92ea11 with 6bw): its 17 migration files are 49 statements, and its store sends 134 distinct statements.

| | run | refused |
|---|---|---|
| migrations, as they are | **2 of 49** | 17 for a table an earlier refusal did not make, 13 `syntax`, 6 `unsupported-operator`, 5 `unknown-type`, 3 `reserved-word`, 2 `engine-unsupported`, 1 `unsupported-statement` |
| queries, on that schema | 2 of 134 | 71 for a table that is not there |
| migrations, with CHECK and REFERENCES taken out and `bigserial` written as an identity column | **45 of 49** | 2 `reserved-word`, 1 `syntax`, 1 `unsupported-statement` |
| queries, on that schema | **64 of 134** | 30 `engine-unsupported`, 12 `syntax`, 10 `subquery`, 7 `reserved-word`, 4 for the one table still missing, 2 `on-conflict`, 2 `unsupported-statement`, and one each of `cannot-lower`, `nondeterministic`, `insert-select` |

Taking the three out one at a time (the same script's `soften`, each alone and in pairs): none alone gets past 13 of 49, any two
at most 34, all three 45. **They are needed together.** What they are, counted in the migrations:

- **50 `check` constraints.** The engine has a range on an integer column (6x) and no other check. 17 of the 50 use `~` with a
  pattern, of ten distinct patterns: every one has a character class, seven are anchored at both ends, seven have `{m,n}`, three have
  `+` or `*`, one has an escape; none has a group or an alternation. 12 use `length(...)`, 6 `in (...)`.
- **19 `references`**, two kinds of `on delete` among them (`cascade`, `set null`).
- **5 `bigserial` columns.**

**The order (choice).**

1. *The schema applies.* `bigserial`; then `check` as an expression held to every row stored (with the pattern operator, of the subset
   above, and `length`, `in`); then `references`, with the two `on delete` forms. Then the four that remain: a generated column, a
   constraint added and dropped by `alter table`, and two words the parser keeps for itself.
2. *The queries.* Measured again on the real schema, since the 64 of 134 is on a softened one. By the count now: what
   `engine-unsupported` hides (30: to be split by reading), a subquery where a table or a value stands (10), `on conflict ... do
   update`, a statement with `with` that writes, `select` with no table (three of the single ones are that), `insert ... select`.
3. *Then it is run:* its own tests against the engine's server, which is the measure that counts. Until then "N of 134 run" says a
   statement was answered, not that the answer is PostgreSQL's; each feature is held to PostgreSQL by the differential as it is built.

**Built so far.**

- *`bigserial`, `serial`, `smallserial`* (`src/stmt.cho`, `coldef`): an integer of that size with the table's counter, which is the
  engine's identity column (6x). Held to PostgreSQL by the differential (`tests/engine_check.py`: three tables, a rollback between
  draws). **Where it departs, by refusing:** PostgreSQL takes a value given to a serial column and a table may have several; the engine
  refuses both (`engine-unsupported`), and the test says so (`UNSUP`). Three mutants of the parser. *Measured after it:* still 2 of
  49, as the table above said it would be: the tables it unlocks have checks and references too.

- *The pattern operators and the lengths* (6by) and *a check that is an expression* (6bz). *Measured after them:* **18 of 49** as the
  migrations are written (from 2), and none of the 50 checks is refused; what is left is 15 `syntax` (the references), 13 for a table one
  of those did not make, 2 `reserved-word`, 1 `unsupported-statement`. 25 of the 134 queries run on that schema.

- *A column that references another table's key* (6ca, the first piece). *Measured after it:* **45 of 49** as the migrations are
  written: the softened measure's number, on the real schema. 55 of the 134 queries run and 9 more are answered with an error of a
  check or a reference (the measure sends `1` for every parameter); the refusals are the list above, to be read next.

*What is not planned:* its advisory lock is one statement; the engine has no lock to give, and a plain transaction already has the
database to itself, so what it is for is to be read before anything is built.

## 6by. The pattern operators and the lengths of a text

*The first piece of the checks of 6bx: 17 of the sibling's 50 use `~` and 12 a length, so a check cannot be an expression until an
expression can say these.*

**What is added.** `a ~ b` and `a !~ b` (text and a pattern: whether the text has a match, and not), and `length(t)`,
`char_length(t)` (characters) and `octet_length(t)` (bytes) of a text. A null on either side is null.

**The pattern is a subset of PostgreSQL's, and what is outside it is refused, never read some other way (choice).**

| in | out (`engine-unsupported`) |
|---|---|
| a character; `.`; `\` before a character that is no letter or digit | `\` before a letter or a digit (`\d`, `\w`, `\m`, a back reference) |
| a bracket expression: characters, ranges, `^` for all but, `\` as outside | `[.x.]`, `[=x=]`, a class by a name not on the list |
| the classes `alpha digit alnum upper lower space punct xdigit cntrl blank` | `print`, `graph` |
| `*`, `+`, `?`, `{m}`, `{m,}`, `{m,n}` (to 255, as PostgreSQL) after one of the above | a quantifier after a quantifier (`a+?` is PostgreSQL's non-greedy), a group, an alternation |
| `^` first, `$` last | an anchor anywhere else; `(?i)` and the other openings |

Why this and no more: it is what the sibling's patterns are (measured below), and with no group and no alternation a pattern is a
row of atoms, each a set of characters and how many times it may come. That has a match without any search. The classes are
ASCII's because the engine's collation is C (D-M3-5), and a database of PostgreSQL made with `lc_ctype 'C'` agrees; `cntrl` is the one
class PostgreSQL does not ask the locale for (it is U+0000 to U+001F and U+007F to U+009F), and it is the same here.

**How a match is found (`src/regex.cho`).** `compile` reads the pattern once into at most 64 atoms (more: refused) and is also
what says a pattern is outside the subset. `matches` keeps, for the atoms read so far, the places of the text (in characters) where
a match of them may end. An atom that may come `lo` to `hi` times moves a place on to every place from `lo` characters further to
`hi`, or to as far as the characters it takes run: a stretch, so all the places are moved in one pass over the text. The cost is
atoms by characters whatever the pattern; there is no step limit to run out and no pattern that is slow. *(Corrected in place: the
first matcher written for this section tried and gave back, with a memo; a text of 500 `a` and `^a*a*a*a*b$` ran out of its four
million steps and was refused. It was replaced before it was merged; the measure that found it is the one below.)*

**Where it is in the pipeline.** The parser has two operators more, at the level of `||` (PostgreSQL's "any other operator"); the
IR's operator codes are a closed list (0 to 17, which the verifiers hold it to), so the lowering writes them as calls,
`textregexeq(a, b)` and `textregexne(a, b)`, which are PostgreSQL's own names for them, and the evaluator computes those two and the
three lengths. A pattern that is a constant and outside the subset refuses the statement whatever the rows; one from a column
refuses it at the first row whose pattern is.

**Measured.**

- *Against PostgreSQL 16* (`tests/regex_check.py`, a database with `lc_collate 'C' lc_ctype 'C'`): 56 fixed patterns and 400 random
  ones of the subset, each with `~` and `!~` over 53 texts (ASCII of every kind, control characters, letters beyond ASCII, the empty
  text, a null): the rows chosen are PostgreSQL's, for seeds 1 to 5 (4,479 to 5,875 rows chosen by `~`, by seed). The three lengths
  of every text are PostgreSQL's. 32 patterns outside the subset, of every kind in the table above: each refused.
- *The sibling's patterns:* 14 distinct, 14 read (13 before `cntrl` was a class: the measure is what added it).
- *The cost:* a text of 500 characters against `a*a*a*a*a*a*a*a*b`, which fails only after every way of sharing the text among eight
  atoms is ruled out: 51 microseconds a statement, the statement's own cost included (200 in a row through `build/enginecheck`); 39 for
  `^[a-z0-9_-]{1,40}$`.

**What is not here.** `~*`, `!~*`, `similar to`, `regexp_replace` and the rest of the family: refused, as before. The lengths of a
`bytea`. And a pattern with a group or an alternation, which is most patterns written anywhere: when a client has one, it is a
different matcher, and this section says so now.

## 6bz. A check that is an expression

*The largest of the three that 6bx found: 50 checks in the sibling's schema, 48 written on a column and 2 on the table, one of them
named; 9 of the 48 name other columns than their own. Their operators are the comparisons, `and or not`, `in`, `between`, `is null`,
`%`, the pattern operators and the lengths (6by). A range of an integer column (6x) is all the engine had.*

**What PostgreSQL does** (read from `src/backend/catalog/heap.c`, `AddRelationNewConstraints`, and `executor/execMain.c`,
`ExecRelCheck`, version 16; each line below is held to it by the differential).

- A check written on a column and one written on the table are the same thing: an expression over the columns of the row, which
  must be a boolean. A row is taken if it is true *or null*.
- A check with no name is given one: the table's name, the name of the column if the expression names exactly one column
  (wherever the check was written), and `check`, joined by `_`; if that is taken, the same with 1, 2, ... after it. Names are
  given in the order the checks are written.
- A row is tested for its nulls first (23502), then against the checks **in the order of their names**, and the first that is
  false is the error (23514). An expression that raises (a division by zero) is that error, when its turn comes. Only then is the
  row's key looked at (23505).
- The expression may not have a subquery, an aggregate, a parameter, or a column of another table.

**Design.**

- *Where a check is kept.* Under the catalog, `0x00000000 0x09`, the table's number, the check's name: so a table's checks are
  read in one walk, in the order of their names, which is the order they are tested in. The value is the expression as the engine
  runs every expression: its IR (`docs/spec/ir.md`, an `Expr`), with what the IR does not say about its constants beside it (the
  notes of 6e). Not its text: the text would be parsed and lowered again at every statement that writes.
- *What is hashed.* The schema a commit says (6bl) gets a line for each check: the table's number, the name, and the SHA-256 of
  the value. A table with no such check has the lines it had, so no commit made before this says another schema.
- *When it is tested.* A row an `insert` is about to store and the row an `update` would leave, after the nulls and the range and
  before the key: the checks of the table, loaded once for the statement, each evaluated with the row bound. `on conflict do
  nothing` tests them before it looks at the key, as it does the nulls (6z).
- *What is refused when the table is made* (`engine-unsupported` unless said): an expression the evaluator does not compute; one
  with a parameter, `now()` or a subquery (the parser's and the lowering's own refusals); one whose type is not known to be a
  boolean before any row (PostgreSQL's 42804 for the ones it also rejects); a name longer than 63 bytes, which PostgreSQL cuts; a
  name given twice, or given after PostgreSQL made it for an earlier check (its 42710, which is not an error the engine has). A
  column that is not the table's is 42703.
- *The range of 6x stays what it is*: a check that is `c between lo and hi` of an integer column and two literals is still two
  integers beside the column, tested without the evaluator, and it takes the name PostgreSQL would give it, so that the names of the
  others are PostgreSQL's. It has no place in the order of names, so a row that is outside a range *and* makes a check raise
  another error than 23514 is `engine-ambiguous-error`, as two different errors are everywhere (6x).
- *What a table with such a check cannot do yet:* be renamed (the expression names its table; refused), or get a column with such
  a check by `alter table add column` (each row there would have to be tested; refused, as before). `drop table` takes its checks
  with it. `alter table ... add constraint / drop constraint` is the next piece and is why the names are PostgreSQL's from the start.

**Test (first).** `tests/engine_check.py`: the random history makes tables with checks of several columns, named and not, on
the column and on the table, with patterns, lengths and arithmetic that can raise, and writes rows that pass, fail and raise; the
fixed statements pin each rule above (the null that passes, the order of names by an error that depends on it, the name given
twice, what is refused). The log's test (`tests/engine_log.py`) holds the schema line. Mutants for each rule.

**Built.** The parser takes `[constraint name] check (...)` on a column, any number of them, and on the table (`src/stmt.cho`: the checks of
a statement are a chain off its root, in the order written; the first unnamed one of a column is still also the column's own, which
is what 6x read). `src/checks.cho` is the rest: `prepare` (lowered by `lower.check` over the one table, typed with no row bound,
named), `store`, `load`, `hold`. `tables.schema_text` writes the lines. `insert` and `update` load the table's checks and hold each
row (`src/execw.cho`); `drop table` removes them; `rename` and `add column` refuse as designed.

**Measured.**

- *Against PostgreSQL 16.15* (`tests/engine_check.py`): 36 seeds of 3,000 statements, three tables in ten with one to three checks
  drawn from 37 forms (on a column or the table, named or not, joined by `and`/`or`; one in 25 is one PostgreSQL refuses): no
  disagreement. 92 fixed statements pin the rules: the null that passes, the check before the key, the order of the names in both
  directions (by an error that depends on it), the name made of the column the expression names, the numbers after a name, a name
  given, a range beside a check. 23 statements refused on purpose, PostgreSQL's outcome beside each.
- *The schema* (`tests/engine_log.py`): a table with no check or with a range has no line; a check is a line by its name; another
  expression is another hash, the same one the same; a table dropped takes its lines.
- *38 mutants* (29 of the rules, 5 of the schema's lines, 3 of the parser's mark, 1 of the export tool), all killed. **What they
  found:** a condition that refused a constant that raises, which the evaluator had refused already; a row bound again after its
  checks, which nothing read; and two older mutants that had passed only because the engine refused `not between` and a range of
  another column, which are now checks: each has its fixed statements. One mutant was dropped as no change of behaviour (a row
  that failed its check being stored in a tree the statement's error throws away).
- *Found on the way, older than this:* `truncate` and `rename` of a name that is a sequence's or an index's said 42P01; PostgreSQL
  says 42809 or does it. Seen once a table could fail to be made for its check and leave its name to something else. Refused now.
- *The sibling's schema:* none of its 50 checks is refused (6bx).

## 6ca. A column that references another table's key

*The last of the three of 6bx: 19 references in the sibling's schema. Every one is written on a column and names one column, which is
the whole primary key of the other table; 11 say `on delete cascade`, 1 `on delete set null`, 7 nothing; 6 of the columns are their
own table's key. None is of two columns, none names its own table, none says `on update`.*

**What PostgreSQL does** (each line run on PostgreSQL 16.15 before it was written here; held by the differential).

- When the table is made: the other table must be there (42P01), the column must be its (42703) and be all of a key or of a unique
  constraint (42830), and the two types must compare (42804; `bigint` to `integer` does). With no column named, it is the primary key.
- A row stored with a value in the column must find a row of the other table with that key, **at the end of the statement**: a null
  finds nothing and passes; a statement whose second row has a key that is taken is 23505 even if its first row's reference is to
  nothing. Missing: 23503.
- A row of the other table that is deleted, or whose key changes, while rows reference it: 23503 with no `on delete`; with `cascade`
  those rows are deleted (and what references them in turn); with `set null` their column is made null. All of it is one statement:
  if anything in it is refused, nothing was done. `delete` of every row is 23503 if one reference says nothing, whatever the others say.
- The table referenced cannot be dropped (2BP01) or truncated (0A000) while it is referenced.

**Design.**

- *Kept* under the catalog twice, so each side finds it in one walk: by the referencing table (`0x0a`, its number, the column:
  the table referenced, by number and by name, and what `on delete` says) and by the table referenced (`0x0b`, its number, the
  referencing table's number, the column: the referencing table's name). A line of the schema that is hashed for each of the first.
- *The row that references.* The table referenced is another table, which the statement does not write, so whether the key is
  there is the same when the row is stored as at the end of the statement: it is looked up when the row is stored (one `get` by
  key), and only the **error** waits: 23503 is the statement's error if nothing else was. So the 23505 of a later row comes first, as
  in PostgreSQL.
- *The row that is referenced.* After a `delete`, or an `update` that changed a key, of a table that is referenced: each
  referencing table is walked, and a row whose reference finds no key in the tree the statement leaves is the violation. One
  walk a referencing table a statement, however many rows went. *(A cost stated, not hidden: the walk is of the whole referencing
  table. An index on the referencing column would make it a lookup for each row that went; that is the second piece's.)* With a
  reference that says nothing: 23503. With `cascade` or `set null`: done, by the second piece below. *(Corrected in place: the
  first piece refused these; the second does them.)*
- *Side by side* (6bw): a transaction that stores a reference has counted on a row it did not write, and one that takes a row out
  of a table that is referenced has taken what others may count on. Either is held to the rule of `serializable` whatever its
  level: put on the branch only if nobody committed meanwhile, else 40001. *(Corrected in place: the design first had the row
  referenced noted as a key the transaction wrote. That catches the deletion committed first; committed second it does not, since
  the row is the same bytes on the branch as when the transaction began. A key of no table among the keys noted says "alone"
  instead, `src/merge.cho`.)* It refuses more than PostgreSQL, whose lock is on the one row: two transactions that reference the
  same row, or any commit beside one that stores a reference. Stated.
- *Second piece:* `cascade` and `set null` done: the rows of the other tables are changes of the same statement (a change says its
  table, so the log has nothing new to learn), found table by table with a list in place of recursion: a table rows went from is
  walked for the tables that reference it, and a table that lost rows is put on the list in its turn. A row made null for `set
  null` is held to its nulls and its checks (23502, 23514). After the list, each table on it is walked once more, and a row that
  references nothing with a reference that says nothing is 23503. *A row held by one of its references and taken by another*
  (PostgreSQL's answer is by the order it comes to them, which is no order it promises): **refused**.
- *Refused:* a reference of several columns; one to a column that is not the whole primary key (PostgreSQL also takes a unique
  one); one to the table itself; a second reference on a column; `on update` other than nothing; types that are not the same
  (PostgreSQL takes what compares); a reference on a column added to a table; renaming either table; `drop table` and `truncate` of
  a table that is referenced (PostgreSQL's 2BP01 and 0A000).

**Built.** The parser reads `references` on a column (`src/stmt.cho`; a node in the chain the checks are in).
`src/refs.cho`: `prepare` and `store` when the table is made, `load`, `row_stored` and `failed` for the rows that reference, `gone`
for the rows referenced (with `child_pass` for `cascade` and `set null`, and `scan` for what is left), `forget` and `any` for `drop`, `truncate`, `rename` and the erase. Two keys of the catalog a reference
(`tables.ref_key`, `tables.refd_key`) and a line of the schema. 23503 is an error the engine has.

**Measured.**

- *Against PostgreSQL 16.15* (`tests/engine_check.py`): 63 fixed statements: the errors of the definition; a reference that finds
  its key, finds none, is null; the key that is taken coming first whichever row it is; `on conflict do nothing`; updates of the
  column; a row and a key that are referenced, and are not; inside a transaction; the tables dropped in the order that is allowed. No
  disagreement. 16 statements refused on purpose, PostgreSQL's outcome beside each (a unique column that is not the key, two types
  that compare, a table that references itself, `on update cascade`, a row held by one reference and taken by another, `drop` and
  `truncate` of a table that is referenced, the renamings, an erase).
- *`cascade` and `set null`* (the second piece; `tests/engine_check.py`, 46 more fixed statements, and the test now compares the
  changes of every table a statement may write, not only its own): a delete takes the rows that reference it and the rows that
  reference those; a column is made null; a row made null that fails its check, a key, a column that may not be null, a unique
  column; a delete still held by a reference that says nothing; inside a transaction rolled back; a delete of every row. No
  disagreement.
- *Side by side* (`tests/engine_sidebyside.py`): a reference stored while the row it references is deleted beside it: the second
  to commit is 40001, in either order, and no row is left that references nothing.
- *The schema* (`tests/engine_log.py`): a line for a reference, another when it says `cascade`, none once the table is dropped.
- *43 mutants* (37 of the rules, 3 of the rule side by side, 2 of the parser's mark, 1 of the schema's line), all killed.
- *The sibling's schema:* **45 of 49** statements as its migrations are written (6bx), from 18: every reference is taken. What is
  left is the four of 6bx's list.
- *Not measured:* the walk's cost on a large referencing table, and a random history with references (the fixed statements are all
  there is; the generator's tables do not reference each other).

*Found on the way:* the fixed statements of the differential are held to a table whose name a pattern reads from the statement;
names it did not read (`fc10` and on, of 6bz) were held to another table's rows, so their changes were compared with nothing. The
pattern reads them now, and they agree.

*Two mutants that cannot be told:* a delete that takes rows of other tables leaves its tree in `w.root`, and the statement takes it;
not taking it, or binding the statement's own table again after, changes nothing anyone sees, because the rows of a statement are
written in place on the pages it already wrote. They are not in the list; the code keeps the tree it means.

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
