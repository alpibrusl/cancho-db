# Cancho DB: L3a, delta replay (v1)

This extends [`commit.md`](commit.md), [`token.md`](token.md) and [`state.md`](state.md) with the third level of verification for the part the first two cannot see: **is the data the history of the facts the log commits
to?** L1 asks whether the log is intact, L2 whether each commit was allowed; L3a asks whether `changes` and `state` are what the stored row changes give, whether those row changes fit together
(each one starts from what the one before left), and, if the tables are given, whether they hold exactly what the row changes say. A verifier needs this page, `commit.md` and `state.md`, and SHA-256. The design is
[`../m2-branches.md`](../m2-branches.md) section 18.

**What L3a does not do**, so that nobody takes it for more: it does not re-run statements (that needs their bound values, which a commit does not carry: L3b, not built); it does not check that a commit that changed rows
was *allowed* to (L2's business, over the statements); and it cannot see data that was in the tables before the capture was installed and was never inserted by a fact, unless it is given that data as a base (section 3).

## 1. Notation

As in `commit.md` and `state.md`. `hex` is lower-case hexadecimal, two digits a byte. A **row image** is the bytes of PostgreSQL's `jsonb` text of the row; its hash is
`SHA-256( "cancho-db/row/v1" || 0x00 || image )` (`state.md` section 2). A **key** is the bytes of the `jsonb` text of the array of the primary key's values (`state.md`, the producer's definitions of M2b). L3a never reads an image
or a key, only hashes and compares them as bytes.

## 2. The delta store

A text file of lines, **each ending `\n`, the last too**. The first line is exactly `CHODBDL1`. Every other line is one **delta row** of nine fields separated by one tab (0x09), in this order; a field that is "absent" is empty:

```
seq        decimal, no sign, no leading zero (except 0), unique in the file
commit     64 hex digits: the id of the commit the row belongs to
schema     the name of the schema the row was written in: `public` for the log's first branch, `cdb_b_<branch>` for any other (the text has no tab or newline)
table      hex of the table's name
key        hex of the key
old_hash   64 hex digits, or absent: the hash of the row's image before this change
new_hash   64 hex digits, or absent: the hash of the image after
old_image  hex of the image, or absent
new_image  hex of the image, or absent
```

Rows may come in any order; `seq` orders the changes of one commit (a change with a lower `seq` happened first). **`store-malformed`**: a file whose last byte is not `\n` (an empty file included); a blank line; a first line that is not `CHODBDL1`; a line without nine fields; a field that is not what is
said above (an odd or non-hex digit, a hash that is not 32 bytes, a `seq` repeated, an empty `commit`, `schema`, `table` or `key`); a row with neither hash.

A row is **well formed as to images** if `old_hash` is absent exactly when `old_image` is, `new_hash` exactly when `new_image`, and a present hash is the hash of the present image: otherwise **`facts-image`**.

## 3. The base

An optional file: the first line `CHODBBS1`, then one row per line of three tab-separated hex fields `table`, `key`, `image`: the rows of the log's first branch's tables before its first commit. Without one the base is empty. A line that does not
have three well-formed fields, or a `(table, key)` that appears twice, is `store-malformed`; so is a file that does not end with `\n`.

## 3b. The live dump

An optional file, the **rows the database holds**: the first line `CHODBLV1`, then one row per line of four tab-separated fields: `schema` (as in section 2), `table` (hex), `key` (hex), `image` (hex of the row's image as the database
gives it: `to_jsonb(row)::text`). The rows of every table of every branch's schema, and only those. `tools/export_live.py` writes it from a database; a verifier that is given a database connection instead (`tools/l3a.py --live`) builds the same
rows itself. A line without four well-formed fields, an empty `schema`, `table`, `key` or `image`, or a first line that is not `CHODBLV1`, is `store-malformed`.

## 4. The facts of a commit

The rows that carry a commit's id are its **raw changes**. Its **facts** are the raw changes **netted** by `(table, key)`: the `old_hash` of the change with the lowest `seq`, and the `new_hash` of the one with the highest; if the two are equal (both
absent, or the same hash) there is no fact; otherwise the kind is `0` insert (old absent), `2` delete (new absent), `1` update. This is the rule of `state.md` section 2 and of the database's `cdb.facts`. The facts are ordered as
`state.md` section 3 orders them, and `changes` is that section's root over them; the empty list gives the empty `changes` (`state.md` section 6).

## 5. What a verifier checks

The log is read as `commit.md` says; **L3a presupposes that the log passes L1**, and a log that does not is not L3a's to judge (a verifier may refuse it as `log-malformed`). The first branch is the branch of the first commit unless the caller
names another. The commits are visited **in log order**; for each, in this order, the first failure being the verdict (with the commit's index; `-1` where it belongs to no commit):

1. **`store-foreign-row`**: before any commit is visited, a delta row whose `commit` is not the id of a commit of the log. During the visit: a row of this commit whose `schema` is not the schema of its branch; or rows on a commit none of whose
   recorded effects is a write (`1`), a DDL (`2`) or a call (`3`) (a commit that only read changed nothing).
2. **`facts-image`**: a row of this commit that is not well formed as to images (section 2).
3. **`changes-mismatch`**: the `changes` of section 4 over this commit's facts is not the commit's `changes`.
4. **`state-mismatch`**: `state.md` section 4 over the `state` fields of the commit's parents (in the order it lists them) and the commit's `changes` is not the commit's `state`. A parent that is not a commit of the log is `state-mismatch`.
5. **`replay-precondition`**: the facts, applied in order to the **map of the commit's branch**, are not consistent with it. The map is, per `(table, key)`, the hash of the row's image now. An insert needs the key to be absent; an update or a
   delete needs it present with a hash equal to the fact's `old_hash`. An insert and an update set the hash to `new_hash`; a delete removes the key.
6. **`replay-unsupported`**: the commit starts a branch (no earlier commit is on it) and its first parent is not the last commit visited on another branch, so that the map it must copy is not known.

**Order of 5 and 6.** Step 6 is judged *before* step 5 for the same commit (a commit that starts a branch is refused as `replay-unsupported` before its facts are tried against a map that does not exist); the numbers
name the rules, not the order of the two.

**Branches.** There is one map for each branch. The first branch's map starts as the base. **A branch's first commit** takes a **copy of the map of the branch its first parent is on**, as it is now (the first parent is that branch's last commit visited:
step 6), and then applies its own facts, of which a fork has none; with no parent it starts from an empty map (the first branch's, from the base). **A merge commit applies the facts it recorded to its own branch's map**; L3a does not redo the merge, whose result is what the facts say and which steps 3 to 5 check.

When the commits have all been visited, and only if the **live tables** were given:

7. **`replay-final`**: for every branch, the rows of the live dump (or of the database) that carry the branch's schema, each as `(table, key)` and the hash of its image, are not exactly the entries of the branch's map: a key the map lacks, a key the
   dump lacks, a hash that differs, a key twice in the dump, or a row whose schema is no branch's. (A table with no rows has no line.) The verdict has `record=-1`.

A log that passes is `ok commits=N facts=M branches=B`, with ` final` appended if step 7 ran.

## 6. Rule order and the output

The order above is the order of checking, within one commit and across commits (commit 0 completely before commit 1). The line a verifier writes is the same as L1's and L2's: `ok ...` or `reject rule=<tag> record=<index>`; exit status `0` for ok, `1` for a
rejection, `2` for a usage error or a file that cannot be read.

## 7. Vectors

`tests/l3a/` holds the golden cases, written by `tools/gen_l3a.py` and never edited by hand: for each case `NAME.log`, `NAME.deltas`, optionally `NAME.base` and `NAME.live`, `NAME.expect` (the line a verifier must write) and `NAME.args` (the extra arguments:
`--base` and `--live-dump` stand for the files of the case, `--first-branch NAME`). `tests/l3a_check.py` runs a verifier over all of them.

## 8. Points settled by the third reading

A separate agent session wrote a verifier from this page and the vectors alone (`tests/third/l3a_third.py`, M2f-3); it passed all 63 vectors then existing on its first run and listed what the page leaves open. These are settled here, and the vectors that test them are `bad_store_no_final_newline`, `bad_store_blank_line`, `bad_store_header_without_newline`, `bad_base_no_final_newline`, `bad_base_key_twice`, `bad_base_key_twice_other_image`, `bad_live_no_final_newline`, `store_schema_not_utf8`, `live_schema_not_utf8`.

* **Every line ends with a newline**, the last too (sections 2, 3, 3b); an empty file, a file without a final newline and a blank line are `store-malformed`. A file of only its first line and `\n` is valid (no rows).
* **A key twice in the base** is `store-malformed` (it was "the later line wins" in the first two verifiers).
* **Hex is lower-case** (section 1): a capital digit is `store-malformed`. An empty image field is an absent image.
* **The order of whole-file checks:** the log, then the delta store, the base and the live dump, each completely; `store-malformed` and `log-malformed` come before any commit is visited and carry `record=-1` where they belong to no commit. Then the rows of no commit (`store-foreign-row`, `-1`), then the commits.
* **`facts=M` and `branches=B`** in the answer: M is the number of facts (section 4) over all commits, not of delta rows; B is the number of distinct branches of the log.
* **A log L1 would refuse** is not judged: a verifier may answer `log-malformed` (with any record) or follow the rules as far as they go. Parents are earlier commits in a log that passes L1; for one that does not, what a parent that comes later does is not defined here. A first branch named with `--first-branch` that is not in the log is not defined either (the first two verifiers read it as a branch that exists in no commit, so no branch is the first branch).
* **Sizes:** a `seq` is a decimal number of any length (compared as a number, without a limit); a table over 255 bytes or a key over 65,535 (state.md) makes the facts unencodable and the commit `changes-mismatch`; a hash of 32 zero bytes is not special to L3a (it is not the hash of any image, so a row with an image is `facts-image`).
* **The files are bytes.** A schema name is any bytes without a tab or a newline and is compared as bytes (a verifier that decodes the files as UTF-8 text refuses a store that the others read: the third reading did, and was amended).
* **Branch names and schemas:** a branch is the first branch's schema `public` or `cdb_b_<name>`; the name is the bytes of the log's branch field compared with the bytes of the schema text. A branch named `public` that is not first has the schema `cdb_b_public`.
* **Command line:** the log, `--deltas` (required), and optionally `--base`, `--live-dump`, `--first-branch`, each given once; anything else, or a file that cannot be read, is a usage error: exit `2`, a message on standard error and no verdict.

## 9. Version 2: salted commitments and erased rows

The delta store, the base and the live dump each come in a second version whose first line is `CHODBDL2`, `CHODBBS2` and `CHODBLV2`. **All the files given to one verification are of one version**; a store of one version with a base or a dump of the
other is `store-malformed`. Version 1 is as above, unchanged. Version 2 exists so that a row can be **erased** (the design is [`../m2g-erasure.md`](../m2g-erasure.md)): its image, salt and key are destroyed and everything that was committed to
still verifies. Nothing in `commit.md` or `state.md` changes.

**Two new hashes.** A row image is hashed with a 16-byte salt: `rowhash = SHA-256("cancho-db/row/v2" || 0x00 || salt || image)`. A key is committed to with its own 16-byte salt: `key = SHA-256("cancho-db/key/v1" || 0x00 || key_salt || key_plain)`, where
`key_plain` is the bytes of the key as in section 1. **The fact's `pk` (`state.md` section 2) is that 32-byte commitment**, so `(table, key)` in sections 4 and 5 is `(table, commitment)`, and the facts are ordered by the commitment.

**The delta store, version 2.** Thirteen tab-separated fields, the nine of section 2 and four more, in this order:

```
seq commit schema table key old_hash new_hash old_image new_image | old_salt new_salt key_plain key_salt
```

`key` is the commitment: exactly 64 hex digits. `old_salt` and `new_salt` are 32 hex digits or absent; `key_salt` is 32 hex digits or absent; `key_plain` is hex, not empty, or absent. A field that is not so is `store-malformed`, as are the rules of section 2 for the other nine
(the hashes, the images, `seq`, and a row with neither hash).

**A row version is erased** when its hash is present and its image and salt are both absent; **a key is erased** when `key_plain` and `key_salt` are both absent. Step 2 for version 2 is two checks, in this order, the first failure being the verdict (with the commit's index):

* **`facts-image`**, for each of the old and the new side: with the hash absent, the image and the salt must be absent; with the hash present, either the image and the salt are both absent (erased: nothing to check), or both present and the hash is the `rowhash` of the salt and the image. Anything else (an image without a salt,
  a salt without an image, an image or a salt without a hash, a hash that is not that `rowhash`) is `facts-image`.
* **`facts-key`** (new): `key_plain` and `key_salt` are both absent (erased), or both present and `key` is the commitment to them; anything else is `facts-key`.

Everything after step 2 is as in section 5: `changes` is recomputed from the **stored** hashes and commitments (they are what the leaves hash), so an erased row verifies exactly as an intact one, and a hash or commitment that was changed after the fact is `changes-mismatch`;
`state` and the replay work on hashes and commitments alone. **Erasing never makes a check fail; it makes the checks that need what is gone not run**, and the verdict says how many: the answer for a version 2 store is `ok commits=N facts=M branches=B erased=E` (then ` final` if step 7 ran),
where `E` is the number of delta rows with an erased row version or an erased key.

**The base, version 2** (`CHODBBS2`): five tab-separated hex fields, `table`, `key_plain`, `key_salt` (16 bytes), `image`, `salt` (16 bytes), none empty; the base map holds `(table, commitment)` and the version 2 `rowhash`. A key twice (the same table and commitment) is `store-malformed`.

**The live dump, version 2** (`CHODBLV2`): six tab-separated fields, `schema` (as in section 2), `table`, `key_plain`, `key_salt`, `image`, `salt` (hex, none empty). The verifier computes the commitment and the version 2 `rowhash` and compares them as step 7 compares version 1's. (The salts of the rows a database holds are what the producer stores beside them; section 4 of the design says where.)

**Settled by the third reading of this section** (it passed every vector, and listed what the text leaves to the reader): the checks of step 2 run over **all the rows of a commit** for `facts-image`, and only then over all of them for `facts-key` (`v2_images_are_judged_before_keys` has a bad key in an earlier row and a bad image in a later one); `erased=E` counts a delta row **once**, however many of its parts are erased,
and an absent hash is not an erased row version; a salt (of a row version, of a key, in a delta row, a base line or a dump line) that is not 16 bytes of hex is `store-malformed`, not `facts-image`; the version of the whole verification is the delta store's, and a base or dump with the other magic is `store-malformed`; the live comparison (step 7) compares the map's hash with the dump's recomputed hash, so
a key whose last version was erased is still compared; `key_plain` is never read as a key (a plain key that matches its commitment passes, whatever it says); and the only size limit that can apply to a fact in version 2 is the table's (the commitment is 32 bytes).

**Vectors.** `tests/l3a/v2_*` are the cases of this version; `NAME.args` names the files as before.

