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

A text file of lines ending `\n`. The first line is exactly `CHODBDL1`. Every other line is one **delta row** of nine fields separated by one tab (0x09), in this order; a field that is "absent" is empty:

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

Rows may come in any order; `seq` orders the changes of one commit (a change with a lower `seq` happened first). **`store-malformed`**: a first line that is not `CHODBDL1`; a line without nine fields; a field that is not what is
said above (an odd or non-hex digit, a hash that is not 32 bytes, a `seq` repeated, an empty `commit`, `schema`, `table` or `key`); a row with neither hash.

A row is **well formed as to images** if `old_hash` is absent exactly when `old_image` is, `new_hash` exactly when `new_image`, and a present hash is the hash of the present image: otherwise **`facts-image`**.

## 3. The base

An optional file: the first line `CHODBBS1`, then one row per line of three tab-separated hex fields `table`, `key`, `image`: the rows of the log's first branch's tables before its first commit. Without one the base is empty. A line that does not
have three well-formed fields is `store-malformed`.

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
