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

## 3. Decisions proposed

* **D-E1. Salted commitments.** A row version carries a random 16-byte **salt**; its hash is `SHA-256("cancho-db/row/v2" || 0x00 || salt || image)`. The salt is stored beside the image in the delta store and is **never** in the log. Erasing
  a row version destroys its image *and* its salt: what stays is a commitment to nothing that can be tested (2^128 salts per guess). This is `state.md` version 2 of the row hash, and a verifier that is given the salt checks it (L3a).
* **D-E2. The key is a payload too.** `pk` is stored in the delta store beside a per-key salt and committed in the fact's leaf as `H(salt_k || pk)` rather than in clear; the order of a commit's facts (state.md section 3 sorts by table, then pk)
  is then by the *commitment*, not the key. Recommended default: **yes**, since primary keys are often personal (emails). It changes the fact encoding (`state.md` version 2), and the capture SQL. **Open (Q10).**
* **D-E3. The erasure is a commit.** `select cancho_erase('<subject>')` runs as one commit with a new effect kind, `erase`, which needs its own token capability; its recorded effects name the *table and the count*, and the commit
  lists the **leaves** (32-byte hashes) of the facts whose payloads were destroyed, never a key or a value. The log then says that, when and by whom, and L2 checks the authority like any other write.
* **D-E4. L3a over a store with erased rows.** An erased delta row keeps `seq`, `commit`, `schema`, `table`, the two (salted) hashes and the **leaf**, and loses `key`, images and salts. Checks that need what is gone are
  *skipped, not failed*, and the verifier says so: `ok ... erased=N`. `changes` is recomputed from the leaves (an erased fact contributes its stored leaf, at its stored rank); a replay map entry whose key is erased is
  tracked by its key commitment, which is enough to check the chain of hashes through the key's life (an update must start from the hash the last version left).
* **D-E5. Snapshots (M4) are payload stores, and are erased the same way.** A snapshot holds rows; erasing a subject rewrites the snapshot (a new signed snapshot), and the old one is destroyed with the others.
  **Out of scope until snapshots exist.**
* **D-E6. What an erasure does not reach, stated:** a copy the operator made outside the system; PostgreSQL's own WAL and dead tuples until `VACUUM FULL` and a WAL recycle (the commit says the delete was made; wiping the
  storage is the operator's step, and the proxy cannot see it); a branch that was forked before the erasure holds its own copy of the rows, so **an erasure runs on every branch** or says which it did not reach.

## 4. Slices

| Slice | Delivers | Gate |
|---|---|---|
| **E1** (this page) | the finding, measured; `design.md` corrected; the decisions above, with the open questions | the measurement reproduces; the claim is corrected where it was made |
| **E2** | `state.md` and `l3a.md` version 2 (salted row hash, key commitment, erased rows), golden vectors, the Python and cancho code, three verifiers where there are three | v1 vectors unchanged; v2 vectors agree; a tampered salt, a missing leaf, a wrong rank each refused with a tag |
| **E3** | the capture SQL makes salts, the delta store has `salt` and the key commitment; the proxy's commits carry v2 `changes` | the Python root of the delta table equals the log's `changes`; write cost reported |
| **E4** | `cancho_erase`: the `erase` effect and capability, the erase commit, the scrub of the delta store (and the rows, on every branch) | after an erase no stored byte equals the subject's value (a scan of the data directory and the log for the planted values: it must find none); the rest still verifies |
| **E5** | the L3a verifier over erased stores in both languages | the E2 vectors with erased rows; mutants |

## 5. Questions for the owner

Recommended answer first; none blocks E1.

* **Q10. Commit to the key as well (D-E2)?** *Recommended:* yes, with `state.md` version 2 (a version bump: the existing vectors and logs stay valid under version 1). *Alternative:* keep `pk` in clear and say in the docs that personal data
  must not be a primary key; erasure then cannot hide the key of a deleted row.
* **Q11. Who may erase?** *Recommended:* a dedicated capability, `erase`, never implied by `write`, granted to a token an operator holds, not to agents.
* **Q12. Is an erasure of a subject the deletion of rows (by key list) or by a subject id column?** *Recommended:* by key list in v1 (the caller names the table and the keys); a subject column needs a schema convention.
* **Q13. Is version 2 only for new logs?** *Recommended:* yes; a log is one version from its first commit (the commit's `version` already carries it), so v1 logs verify as they are and cannot be erased.

## 6. Claims

C135 (the unsalted hash leaks; measured), in [`claims.md`](claims.md).
