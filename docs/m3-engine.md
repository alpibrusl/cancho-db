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
| **M3c** | tables, the row encoding and image (D-M3-6), the catalog of tables inside the engine, `create table` and `drop table` | the image equals `to_jsonb` for every supported type, on the corpus |
| **M3d** | the executor for `insert`, `update`, `delete` and `select ... where <key> = <constant>`, and the engine's `changes` | gate 4 for these; `changes` equals the capture's |
| **M3e** | predicates on any column, range scans on the key, `order by`, `limit`, `offset`, `distinct`, `in`, `case`, `cast`, `like` | gate 4 |
| **M3f** | aggregates and `group by`, `having` | gate 4 |
| **M3g** | joins (nested loop first) | gate 4 |
| **M3h** | `alter table`, `create index` (an index is a second tree) | gate 4 on the catalog after each |
| **M3i** | native `cancho_fork`, `AS OF`, `cancho_merge`, `cancho_erase` on the engine | the existing fork, as-of, merge and erase end-to-end suites pass on it |
| **M3j** | the shadow run, then a database option to serve from the engine | gate 5, then the full gate on the engine for one database |

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
