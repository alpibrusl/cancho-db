# M2g: erasure

`design.md` says erasure "must be designed before any data is stored", and gives the decision: *value payloads are encrypted per subject and stored outside the chain; erasure destroys the key; hashes stay and the chain
still verifies.* This page tests that decision against what is built (M2: row deltas, L3a), finds a defect in it, and proposes the slices. Nothing here is built yet but the measurement of section 2.

## 1. What erasure has to mean here

After an erasure of a data subject, **no one holding the log, the delta store, the snapshots and every verifier's inputs can recover the subject's data**, and **everything that did not belong to the subject still verifies**
(L1, L2, and L3a over the rest). What may stay: that a commit happened, who signed it, under which token, the table and the kind of change (insert, update, delete), counts, and hashes that commit to nothing guessable.

Today the data is in three places: the **database tables** (erasure there is a `DELETE`, which is itself a commit); the **delta store** (`cdb.delta`: `old_image`, `new_image`, and `pk`, the row as it was and is, and the key, in clear, for every
version of every row); and the **log**, which holds only hashes (`changes` is a Merkle root over facts, a fact is `kind, table, pk, old_hash, new_hash`). L1 and L2 never see a value. L3a needs the delta store.

## 2. The finding: a hash of a guessable row is the row

A row's hash is `SHA-256("cancho-db/row/v1" || 0x00 || image)`, with no salt (`state.md`). The log holds `changes`, a Merkle root, so the hashes are not in the log itself; but the delta store holds them beside the images
(`old_hash`, `new_hash`), and L3a exports and shares that store with whoever verifies. **Once the image is erased and the hash stays, the hash is a test for a guess.**
`scripts/measure_hash_leak.py` (one core, Python, 280,000 guesses a second, nothing else done):

| What the attacker knows | What is guessed | Guesses | Time |
|---|---|---|---|
| the id of the row | a four-digit PIN | 4,822 | 0.017 s |
| the id | a name from 100,000 candidates | 100,000 | 0.30 s |
| the id | a date of birth, any day in 100 years | 23,907 | 0.075 s |

A nine-digit number (a phone, a national id) is 10^9 guesses: an hour on this core, seconds on a GPU. So **"erasure destroys the key; hashes stay" is false for any value a person could guess or a list could hold**: the hash
that stays gives the data back. `design.md`'s row for erasure is corrected in place to say so (section 5). The same holds for the key: the `pk` in the delta store (an email address, a national id) is in clear and in every fact's leaf.

## 2b. A second finding: the statement store holds constants, and the log holds their hashes

Found while building `cancho_erase` (the call has to name the key it erases). The **statement IR** (`ir.md` section 2) holds `Const Value` for every literal in a statement, and `--stmts` L2 needs the statement store to check that a commit's recorded effects are what its statements do. So the **statement store** (`log/stmts`, one record per distinct statement) holds, in clear, every constant a client wrote as a literal: `insert into people values ('ana@example.org', 'Ana Quintero', '600111222')` is stored with all three values, and `where email = 'ana@example.org'` with the e-mail. (The project's own vectors show it: `vectors/ir2_*.stmts` contain the string `secret` in clear, and `ir_*` stores the table name `orders`.) Two consequences:

* **The statement store is a payload store that erasure has not reached.** Erasing the delta rows leaves the statements that carried the same values. Erasing a statement record makes `--stmts` L2 refuse the commit that cites it (`stmt-missing`), unless the verifier is told which statements were erased (as L3a is told which rows).
* **The statement id in the log is a test for a guess**, exactly as section 2's row hash was: a commit carries the SHA-256 of each statement's IR (`commit.md`, field `stmts`), unsalted, constants included. A guessable constant (a PIN, a name from a list) is recovered from the log alone by guessing and hashing the statement it was in, when the rest of the statement is known (the table, the other columns). Statements sent with bind parameters (the extended protocol, `$1`) hold `Param`, not the value, and do not leak; statements sent with literals do.

And `cancho_erase('people', '["ana@example.org"]')` is itself a statement with the key as a literal: run as it is, **the erasure writes the key it erases into the statement store**.

**D-E7 (proposed). Constants are payloads of their statement, and the statement id commits to them with a salt.** A statement record keeps its *shape* (the IR with each `Const` replaced by a placeholder that keeps its type) and, beside it, the constants and a random 16-byte salt; the id in the log is `SHA-256(shape || SHA-256(salt || constants))`. Effect inference, which sees names and not values, works on the shape (`Call` arguments never decide an effect), so L2 with statements is unchanged in what it proves; erasing a statement means destroying its constants and its salt. This is `ir.md` version 3 and a change to the three verifiers, and it is **a precondition of an erasure that leaves nothing**, so it comes before `cancho_erase` goes through the proxy.

**Q14. Take D-E7?** *Recommended:* yes. *Alternative:* document that literals in a statement are not erasable and tell clients to use bind parameters for personal data (the extended protocol already keeps them out of the IR); cheaper, and a client that forgets leaks.

## 3. Decisions proposed

* **D-E1. Salted commitments.** A row version carries a random 16-byte **salt**; its hash is `SHA-256("cancho-db/row/v2" || 0x00 || salt || image)`. The salt is stored beside the image in the delta store and is **never** in the log. Erasing
  a row version destroys its image *and* its salt: what stays is a commitment to nothing that can be tested (2^128 salts per guess). **This needs no change to `state.md`**: it fixes only that a hash stands for one image, and leaves how a row image is hashed to the producer (`state.md` section 2, last paragraph); the definition is in `l3a.md` section 1, which version 2 of the delta store changes (L3a section 9). A verifier that is given the salt checks the hash.
* **D-E2. The key is a payload too.** `pk` is stored in the delta store beside a per-key salt and committed in the fact's leaf as `H(salt_k || pk)` rather than in clear; the order of a commit's facts (state.md section 3 sorts by table, then pk)
  is then by the *commitment*, not the key. Recommended default: **yes**, since primary keys are often personal (emails). It changes nothing in `state.md` either: a fact's `pk` is "the producer's canonical encoding", and a 32-byte commitment is one. It changes the capture SQL and the delta store (L3a section 9). **Decided: yes (Q10).**
* **D-E3. The erasure is a commit.** `select cancho_erase('<subject>')` runs as one commit with a new effect kind, `erase`, which needs its own token capability; its recorded effects name the *table and the count*, and the commit
  lists the **leaves** (32-byte hashes) of the facts whose payloads were destroyed, never a key or a value. The log then says that, when and by whom, and L2 checks the authority like any other write.
* **D-E4. L3a over a store with erased rows.** An erased delta row keeps `seq`, `commit`, `schema`, `table`, the key **commitment** (which *is* the fact's `pk`) and the two (salted) hashes, and loses the images, the salts and the plain key. So the leaf, `changes`, `state` and the whole replay
  (which works on hashes and the commitment) are checked exactly as before; only the checks that need what is gone (image against hash, plain key against commitment) are *skipped, not failed*, and the verifier says so: `ok ... erased=N`. The correction to the first draft of this page: it kept the leaf in an erased row; the commitment makes that unnecessary.
* **D-E5. Snapshots (M4) are payload stores, and are erased the same way.** A snapshot holds rows; erasing a subject rewrites the snapshot (a new signed snapshot), and the old one is destroyed with the others.
  **Out of scope until snapshots exist.**
* **D-E6. What an erasure does not reach, stated:** a copy the operator made outside the system; PostgreSQL's own WAL and dead tuples until `VACUUM FULL` and a WAL recycle (the commit says the delete was made; wiping the
  storage is the operator's step, and the proxy cannot see it); a branch that was forked before the erasure holds its own copy of the rows, so **an erasure runs on every branch** or says which it did not reach.

## 4. Slices

| Slice | Delivers | Gate |
|---|---|---|
| **E1** (this page) | the finding, measured; `design.md` corrected; the decisions above, with the open questions | the measurement reproduces; the claim is corrected where it was made |
| **E2** | `l3a.md` section 9 (delta store version 2: salted row hash, key commitment, erased rows), golden vectors, the Python and cancho verifiers and a fresh third reading (`state.md` and the L1/L2 vectors do not change) | v1 vectors unchanged; v2 vectors agree in three verifiers; a tampered salt, a wrong commitment, a changed hash in an erased row each refused with a tag |
| **E3** | the capture SQL makes salts, the delta store has `salt` and the key commitment; the proxy's commits carry v2 `changes` | the Python root of the delta table equals the log's `changes`; write cost reported |
| **E3a** (built) | `cdb.erase(sch, tbl, key)` in SQL: deletes the row by its plain key and destroys the images, salts and plain keys of every delta row of the key in that schema, and reports the schemas that still hold the key | `tests/erase_check.py`: a scan of every table the capture keeps for planted values, before and after; a composite key; a rolled-back erasure; a branch made before holds its copy and is named. It also shows that erasure is by key: another table's column that names the subject (`notes.owner`) is for the caller to erase |
| **E3b** (D-E7, Q14) | `ir.md` version 3: statement records keep the shape and put the constants and a salt beside it; the statement id commits to both; the three verifiers | v2 vectors unchanged; v3 vectors agree; a statement with its constants erased still verifies at L2 |
| **E4** | `cancho_erase` through the proxy: the `call cancho_erase` capability (a `call` effect, granted explicitly, never implied by `write`), the token's `write` on the table, the erase commit; the call's key is a constant that D-E7 makes erasable | after an erase no stored byte, the statement store and the log included, equals the subject's value; the rest still verifies |
| **E5** | the L3a verifier over erased stores in both languages | the E2 vectors with erased rows; mutants |

## 5. Questions for the owner

Recommended answer first; none blocks E1.

* **Q10. Commit to the key as well (D-E2)?** **Decided 2026-11-19: as recommended**, yes, with no change to `state.md` (the delta store is version 2, L3a section 9; existing vectors and logs stay valid). *Alternative, not taken:* keep `pk` in clear and say in the docs that personal data
  must not be a primary key; erasure then cannot hide the key of a deleted row.
* **Q11. Who may erase?** **Decided as recommended:** a dedicated capability, `erase`, never implied by `write`, granted to a token an operator holds, not to agents.
* **Q12. Is an erasure of a subject the deletion of rows (by key list) or by a subject id column?** **Decided as recommended:** by key list in v1 (the caller names the table and the keys); a subject column needs a schema convention.
* **Q13. Is version 2 only for new logs?** **Decided as recommended:** yes. The commit format does not change; what a log's facts commit to is fixed by how its hashes were made, so a log whose hashes were unsalted verifies as it is (delta store version 1) and its guessable hashes cannot be un-leaked.

## 6. E2 as built

* **`docs/spec/l3a.md` section 9** is the specification of delta store version 2: the salted `rowhash`, the key commitment (the fact's `pk`), erased rows, the rule `facts-key`, `erased=E`, and the version 2 base and dump. `state.md`, `commit.md` and the L1 and L2 vectors do not change.
* **Three verifiers, 114 golden cases (42 of them new for version 2 and its edges), one answer:** `tools/l3a.py`, `src/l3a.cho` and `tests/third/l3a_third.py`, the last extended to version 2 by a fresh agent session from the spec text and the vectors alone: it passed all 105 then-existing cases on the first run, disagreed with the spec nowhere, and listed ten points the text left open, now settled in section 9.
* **What an erased store still proves.** With the images, salts and plain keys of every row erased (`v2_ok_erased_everything_and_the_tables_still_match`) a store still gives the log's `changes` and `state`, still replays (an update that starts from another hash is refused: `v2_erased_rows_are_still_replayed`), and still matches the tables. A hash changed in an erased row is `changes-mismatch` (`v2_erased_row_with_another_hash`). What it no longer proves is that a hash is the hash of some image: that is what erasure gives up, and the answer says how many rows are in that state.
* **Mutants:** 16 more on the Python verifier and 18 more on the cancho one (all killed); they found five checks no case reached (a salt of the wrong length in a base line, a dump line or a delta row, and a store magic of a later version), each with a case now.
* **Not built:** the capture SQL that makes the salts and commitments (E3), `cancho_erase` (E4), the erased-row cases through a real session (E5).

## 6b. E3b as built: the statement store, version 3

* **`docs/spec/ir.md` section 8** is normative: store magic `CHODBST3`; a record is `shape chash payload`, the shape being the v2 statement with a `Hole` (tag 11, the type of the constant) wherever a `Const` was, `chash = SHA-256("cancho-db/consts/v1" || 0 || salt || u32(n) || the n values)`, the payload either erased (`0x00`) or the salt and the values; the statement's id is `SHA-256("cancho-db/stmt/v3" || 0 || shape || chash)`, so it does not change when the payload is erased. A new rule, `stmt-consts-mismatch`, for a payload that is not what the record committed to. (The draft of the previous slice put `Hole` at tag 6, which v2 uses for `Star`: corrected to 11 when it was made normative.)
* **Three verifiers, 467 vectors** (`tools/gen_ir3.py`: 31 new `ir3_*`): `tools/verify.py`, `src/ir.cho` and `verifiers/go/ir.go` agree on every one of them and on 9,000 fuzzed inputs (the fuzz reaches `stmt-consts-mismatch`). L2 with statements over an **erased** store still proves that the recorded effects are what the shapes infer.
* **Mutants:** 12 on the Python verifier and 14 on the cancho one (all killed); one survived until a vector put a whole payload under a bad tag (`ir3_bad_payload_tag_2_over_a_whole_payload`).
* **Not built:** the proxy writing version 3 records (it still writes version 2, so its statement store is not erasable), and `cancho_erase` through the proxy (E4).

## 6c. E3c, the proxy writes version 3 (built)

Built as designed: `ir.lift`, `build.stmt3`, salts from `cdb.rnd()` through the client accumulator, store magic `CHODBST3`. Checked by `tests/lift_check.py` (118 version 2 statements: 87 lift, every lifted record accepted by the Python verifier with the same effects, the 31 refused ones refused by both), `tests/stmts_v3_e2e.py` (a real session: planted values only in payloads; `tools/erase_stmts.py` removes them; both verifiers accept the same log with the erased store) and the existing proxy, extension, driver, changes, fork, as-of, merge and L3a e2e runs against the new proxy. The lift bug found on the way (`mv < 3` treated every constant as a hole-less type) is the reason `proxy/liftcheck.cho` exists.

* **Where.** `commitpath.add` already takes, for each statement the guard allowed, its id and its IR record and keeps them in the client's transaction until the commit. In E3c `add` turns each record into a version 3 record at that moment: `ir.lift` walks the statement (the same walk as inference, in a mode that records where each `Const` starts and ends), copies it with each constant replaced by a `Hole` of its type, and keeps the constants in order; the record is `shape || chash || payload` with a fresh 16-byte salt, and the statement's id becomes the version 3 id. The commit's `statements` field then names version 3 ids, and the statement store is opened with the magic `CHODBST3`.
* **Entropy.** cancho's standard library has no random source and the proxy must not derive salts from its signing key (a salt that can be recomputed is not destroyed by erasing it). It takes them from the upstream database, as the capture does for its own salts: a 1 KiB buffer fetched with one query at start and refilled when it runs low (`select encode(string_agg(cdb.rnd(), ''::bytea), 'hex') from generate_series(1, 64)`), each salt using 16 bytes that are never used again. One round trip in about 64 statements with constants.
* **One id for each occurrence.** Two executions of the same statement now have two ids (two salts), so the statement store grows with the statements run and no longer deduplicates them; that is the price of the salt, and it is measured when this is built.
* **A log directory is one version.** The statement store's magic is fixed when the directory is made: a directory whose store is `CHODBST2` is refused by a proxy that writes version 3 (`r_bad_magic`), as a version 1 database is refused by the version 2 capture. Existing logs verify as they are.
* **Tests to change:** `tests/build_check.py` (the builder's records and ids against an independent encoder), the `--stmts` checks of `proxy_e2e`, `ext_e2e`, `drivers_e2e` and `l3a_e2e` (the verifiers already read version 3), and a new check that no statement store byte equals a planted constant.

## 6d. E4, `cancho_erase` through the proxy (design; not built)

What E1-E3c leave: `cdb.erase` destroys what the capture keeps for a key; the statement store holds constants as erasable payloads. E4 joins them behind one call a client can make, and answers three things the earlier slices left open.

* **The call.** `select cancho_erase('people', '["ana@example.org"]')` (table, key as a JSON array, Q12 erase by key list). The guard recognises the call by name, as it does `AS OF`, and lowers it to one `Call` effect on `cancho_erase` plus a `write` on the table named. A token needs both: the explicit `call cancho_erase` capability (Q11; never implied by `write:*`) and `write` on that table. A token that has only `write` is refused with the usual denied-effect tag.
* **The proxy runs the erasure, not the client's connection.** The proxy sends `select cdb.erase('<sch>', 'people', '<key>')` on the upstream connection of the client's branch schema, inside the client's own transaction, so the delete and the scrub commit or roll back together with the commit that records them (E3a: a rolled-back erasure leaves everything). The answer line (rows deleted, delta rows scrubbed, other schemas that still hold the key) goes back to the client as the result of its `select`.
* **The commit.** The erase is a commit like any other: its `changes` carry the delete as a fact with the key's commitment as `pk` (the capture already makes it), its effects are the call and the write, and its statement record is written **already erased** (payload tag 0): the key never reaches the store. The commit does not list leaves (D-E3's first draft); the facts it already carries are the leaves.
* **Erasing the earlier statements that hold the key (the open point).** The statement store is append-only and its records are length-prefixed, so erasing a payload changes a record's length. E4 therefore **rewrites the store**: the proxy, still holding the log directory's lock, writes `stmts.new` with every record whose payload contains the subject's plain key bytes replaced by its erased form (the shape and the hash of the constants stay, so every id in the log stays valid), syncs it, and renames it over `stmts` (one atomic step), before it answers the client. A crash before the rename leaves the old store, whose records still verify; the proxy re-checks at start and redoes the erasure only if the client retries (the call is idempotent: the second run finds nothing). The match is on the plain key as it appears in the constants (an e-mail as the text value); a statement that holds the subject in another form (a name in an `insert`, a phone) is **not found by the key** and stays, which `tools/erase_stmts.py --containing` can do offline: the commit says what was matched, and `claims.md` says what is not.
* **What the commit may not say.** The recorded call has the table name and no key; the erased record has the shape `select cancho_erase(?, ?)` and no constants; the answer line is not logged.
* **Tests (E4 gate).** A real session writes rows for two subjects as literals, erases one through the proxy; then a scan of the whole log directory and of the upstream tables the capture keeps finds none of the subject's key bytes and all of the other's; all verifiers accept the log at L2 with statements and L3a over the delta store reports `erased=N`; a token with `write` and no `call cancho_erase` is refused; a rolled-back erasure changes no byte; a kill between the two steps leaves a log that verifies.
* **Not in E4:** the other columns of the subject in earlier statements (named above), PostgreSQL's own storage until `VACUUM FULL`, other branches (the answer line names them), and E5's cases of erased rows through a real session.

## 7. Claims

C135 (the unsalted hash leaks; measured), C136 (an erased store still verifies) and C137 (the statement store holds constants) and C138 (an erased statement store still verifies), in [`claims.md`](claims.md).
