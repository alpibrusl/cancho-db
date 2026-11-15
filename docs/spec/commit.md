# Commit and log format, version 1 (L1)

This is the language-neutral definition of what a Cancho DB log is and what it takes for it to verify at **L1
(integrity)**. A verifier needs this page, SHA-256 and Ed25519 (RFC 8032), and nothing else. A signature check MUST reject a
signature whose `S` is not below the group order, and a key (or `R`) that does not decode; it answers "invalid", it does
not fail. What an implementation does with small-order or non-canonical-but-decodable keys and `R` values is **not
specified in v1** and no vector exercises it: implementations are known to differ there, and a log's signer is trusted
not to produce them. It does not need cancho,
and `tools/verify.py` is meant to be written from this page (and `token.md`) alone. *Corrected:* it was written from them
by the same author who wrote the cancho verifier and after it, so it is not yet the independent second verifier the design
asks for ([`../claims.md`](../claims.md)).

L2 (tokens and effects) is [`token.md`](token.md); L3 (replay) is in the design ([`../design.md`](../design.md)) and not
yet specified. A log that verifies at L1 says the history was not altered or reordered by anyone without the server key, and
nothing about whether each commit was allowed.

The words MUST and MUST NOT are used as in RFC 2119.

## 1. Notation

- All integers are **big-endian** and fixed width: `u8`, `u16`, `u32`, `u64`; `i64` is two's complement.
- `Hash` is 32 bytes (SHA-256 output). `PublicKey` is 32 bytes (Ed25519). `Signature` is 64 bytes.
- `bytes16` is a `u16` length followed by that many bytes. `bytes32` is a `u32` length followed by that many bytes.
  Neither is required to be UTF-8; a verifier MUST NOT interpret or validate the contents.
- `[T]` is a `u32` count followed by that many `T`. Every `T` is at least one byte, so a count larger than the bytes
  remaining in the record is malformed (rule `bad-encoding`); a verifier MUST NOT allocate from a count before checking
  this.
- Every value has **exactly one** byte representation. A decoder MUST reject anything an encoder would not have produced
  (rule `bad-encoding` unless a more specific rule is named below).

## 2. Commit

A commit is the concatenation, in this order and with no padding, of:

| # | Field | Encoding | Constraint |
|---|---|---|---|
| 1 | `version` | `u16` | MUST be `1` (`bad-version`) |
| 2 | `parents` | `[Hash]` | at most 2 entries (`parent-count`) |
| 3 | `branch` | `bytes16` | length 0 is `branch-empty`; length over 255 is `bad-encoding` |
| 4 | `seq` | `u64` | |
| 5 | `schema` | `Hash` | |
| 6 | `statements` | `[Hash]` | |
| 7 | `effects` | `[Effect]` | strictly ascending (`effects-unordered`) |
| 8 | `token` | `Hash` | |
| 9 | `principal` | `PublicKey` | |
| 10 | `code` | `[Hash]` | |
| 11 | `nondet` | `[Value]` | |
| 12 | `changes` | `Hash` | |
| 13 | `state` | `Hash` | |
| 14 | `checks` | `[Check]` | |
| 15 | `time` | `u64` | milliseconds since the Unix epoch; informational, never checked |

`Effect` is `kind: u8` then `target: bytes16`. `kind` is `0` read, `1` write, `2` ddl, `3` call, `4` nondet; any other
value is `bad-encoding`. The list MUST be strictly ascending by `(kind, target)`, comparing `kind` as a number and
`target` as an unsigned lexicographic byte string (a prefix sorts first). Strictly means no duplicates: the set has one
encoding.

`Value` is `tag: u8` then: tag `0` null, nothing more; tag `1` int, an `i64`; tag `2` bytes, a `bytes32`. Any other tag
is `bad-encoding`.

`Check` is `name: bytes16` then `ok: u8`, which MUST be `0` or `1`.

The encoding of a commit MUST end exactly where the record says it does: bytes left over are `bad-encoding`, and so is a
field that would read past the end.

## 3. Identity and signature

```
id        = SHA-256( "cancho-db/commit/v1" || 0x00 || encoding(commit) )
signature = Ed25519-Sign(server_key, id)        // the 32 id bytes are the message
```

The prefix (the 19 ASCII bytes `cancho-db/commit/v1` and one `0x00`: 20 bytes) is a domain separator: a hash of a commit can never be mistaken for a hash of anything else the system
hashes. The signature is over the id, so it covers every field.

## 4. Log file

```
log     = magic server_key record*
magic   = "CHODBLG1"                 (8 bytes, ASCII)
record  = length encoding signature
length  = u32                        (size of `encoding` in bytes)
```

- `server_key` is the Ed25519 public key every signature in this log MUST verify under. v1 has no key rotation; a log
  with a new key is a new log.
- A record is at most 16 MiB (`length` > 16,777,216 is `record-too-large`).
- A log with no records is valid.

Framing is read in this order, and the first failure is the verdict:

1. fewer than 8 bytes in the file: `truncated`;
2. the 8 bytes are not `magic`: `bad-magic`;
3. fewer than 40 bytes in the file: `truncated`;
4. then, for each record while any byte remains: fewer than 4 bytes left for `length`: `truncated`; `length` over
   16 MiB: `record-too-large` (judged before whether the bytes are there, so a lying length is refused, not waited
   for); fewer than `length + 64` bytes left: `truncated`.

## 5. What L1 checks

Records are checked **in file order**, one at a time, each judged completely when it is reached (framing included: a
record that fails to decode is the verdict even if a later record is truncated); for each record the checks run in this
order; the first that fails is the verdict, so that two verifiers agree on the rule and not only on the refusal:

1. **Framing**: `bad-magic`, `truncated`, `record-too-large`.
2. **Decoding** (§2): `bad-version`, `bad-encoding`, `branch-empty`, `effects-unordered`, `parent-count`. Fields are read in
   the order of §2 and **the first violation met is the verdict**: a rule is judged when its field has been read, not at
   the end. In particular a `parents` count is first checked against the bytes left (`bad-encoding` if `count * 32`
   does not fit) and only then against 2, so three parents with fewer than 96 bytes behind them are `bad-encoding`,
   and with all 96 `parent-count`; and an out-of-order `effects` list is `effects-unordered` even if a later field is
   malformed.
3. **Duplicate**: the id was already seen in this log: `duplicate-commit`.
4. **Signature**: `bad-signature`. (Before the chain rules: an unsigned record claims nothing, so nothing it says can be
   wrong.)
5. **Sequence**: for a branch with *n* commits already seen, `seq` MUST equal *n* (`seq-gap`, which also names a repeat
   or a start that is not zero).
6. **Parents**:
   - `seq = 0`: `parents` has 0 entries (a root) or 1 (a fork point, which MUST be the id of a commit earlier in the
     log, else `parent-unknown`). Two parents is `parent-count`.
   - `seq > 0`: `parents` has 1 or 2 entries (else `parent-count`). `parents[0]` MUST equal the id of the branch's
     previous commit (`parent-mismatch`). If there is a second parent it MUST differ from the first (`parent-count`) and
     MUST be the id of a commit earlier in the log (`parent-unknown`).

The verdict is `ok` only if every record passes.

**What this does and does not catch.** Altering any byte of a record changes its id, so the signature fails; dropping or
reordering records breaks `seq` or the parents; splicing in a record signed by another key fails the signature. It does
**not** catch the **removal of the end of the log**: a prefix of a valid log is a valid log. A reader that holds a commit
id it was given earlier (`cancho_last_commit()`) can pass it as the **expected id**, and the verdict is
`expected-missing` unless that id occurs in the log. That check runs after every record has passed.

## 6. Verifier interface

Both verifiers (`src/verify.cho`, `tools/verify.py`) take the log path, and optionally `--expect <64 hex digits>` (before
or after the path; upper or lower case), and write exactly one line to standard output:

```
ok commits=<N> branches=<B>
reject rule=<tag> record=<i>
```

Any repeated option, extra positional argument, option without its value, or hex value that is not exactly 64 hex digits
(either case) is a usage error, exit 2 and no verdict.

`<i>` is the zero-based index of the record that failed, or `-1` when the failure is in the header or is
`expected-missing`. Exit status is 0 for `ok`, 1 for `reject`, 2 for a usage error or an unreadable file (no verdict).
Neither verifier may panic or write anything else for any input.

## 7. Golden vectors

`vectors/` holds, for each `NAME`: `NAME.log` (the input), `NAME.expect` (the exact line both verifiers MUST write) and,
where the case needs one, `NAME.args` (extra arguments). `tools/gen_vectors.py` writes them; a vector is never edited by
hand. The names say what each case is: valid chains (a root, a branch with a fork, a merge) and one tampered or malformed
case for each rule in §5 and each way a field can be wrong in §2.
