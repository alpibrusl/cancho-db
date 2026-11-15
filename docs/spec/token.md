# Capability tokens and L2 (authority), version 1

This extends [`commit.md`](commit.md) (notation, §1, is the same) with the token format and the **L2** check: *was each
commit allowed by the token it presented?* A verifier needs this page, `commit.md`, SHA-256 and Ed25519.

L2 is checked **on top of L1**: a log that fails L1 has the L1 verdict, and L2 is not reached.

## 1. What a token is

A token is a chain of **blocks**. The first (the *authority block*) is signed by the **root key**, the authority that
issues tokens. Each block names the key that must sign the next one, so whoever holds the private key of the last block
can append a block, offline, and nobody else can. A block can only **narrow**: a commit is allowed by a token only if it is
allowed by **every** block, so adding a block never widens what the token permits (§5).

```
Token = [Block]                      // u32 count (at least 1), then the blocks
Block = payload next_key signature
payload   = principal branch effects expiry
principal = PublicKey                // 32 zero bytes: any principal
branch    = bytes16                  // a pattern (§2)
effects   = [Effect]                 // as in commit.md §2: strictly ascending; each target is a pattern (§2)
expiry    = u64                      // ms since the Unix epoch; 2^64-1 means none
next_key  = PublicKey                // the key that signs the next block (unused after the last)
signature = Signature
```

`signature` of block *i* is Ed25519 by key *i* over

```
"cancho-db/token-block/v1" || 0x00 || payload || next_key
```

where key 0 is the root key and key *i* (*i* > 0) is `next_key` of block *i*-1. A block moved, dropped or inserted breaks
the chain: its signature no longer verifies under the key the chain expects there.

**Token ids.** For a token of blocks *b0..bn-1*, the id of its **prefix of k blocks** is

```
SHA-256( "cancho-db/token/v1" || 0x00 || u32(k) || b0 || ... || bk-1 )
```

The id of the whole token (*k* = *n*) is what a commit records in `token`. The ids of the shorter prefixes exist so that
revoking a token revokes every token attenuated from it (§4).

A block's `branch` pattern may be empty (it then matches only the empty branch name, which no commit has) and a pattern
has no length limit but its `u16` length; there are no further constraints on a block than those written here.

**Decoding** is as strict as in `commit.md` §1: one byte representation per value, a count larger than the bytes left is
malformed, effects strictly ascending (`token-bad-encoding`), a token with no blocks is malformed, bytes left over after
the last block of a token are malformed. A `kind` above 4 is malformed.

**Not specified here: presentation.** A client that presents a token to a server also proves it holds the private key of
the last block (otherwise anyone could strip trailing blocks from a token they saw and use a wider one). That proof is part
of the connection protocol (M1) and is not part of the token as stored and logged, which is what the commit's `token`
hashes. L2 over a log therefore checks the chain of signatures and the grants, not who presented it.

## 2. Patterns

A pattern is bytes. If its last byte is `*` (0x2A), it matches every value that starts with the pattern **without** that
last byte; so `*` alone matches everything, and `agent-7/*` matches `agent-7/` and `agent-7/x` but not `agent-70`. Any other
pattern matches only an equal value. There is no other wildcard, and no escape: a name that ends in `*` can only be
matched by a pattern that ends in `*`, a sharp edge worth knowing and not one to build on.

A block's `branch` pattern is matched against the commit's `branch`. An `Effect` in a block **permits** a commit effect when
the kinds are equal and the block's target pattern matches the commit's target. `orders.*` permits `read orders.total` and
does not permit `read orders`.

## 3. The stores

L2 needs two files besides the log.

```
tokens   = "CHODBTK1" ( u32 length  Token )*
revoked  = "CHODBRV1" ( token_id  since:u64  signature )*        // 104 bytes each
```

`tokens` is a set: a token listed twice is the same token. A token no commit presents is never looked at beyond decoding.
`revoked` entries are signed by the root key, so a list that anyone could extend cannot lock the system:

```
signature = Ed25519-Sign(root_key, "cancho-db/revoke/v1" || 0x00 || token_id || since)
```

`since` is a time in ms: the token (or any token with that id as a prefix id) is refused for commits whose `time` is
`since` or later, and not for earlier ones. An id listed more than once is revoked from the **earliest** of its `since`
values (a commit is refused if any entry for the id has `since` at or before its `time`).

The verifier is given the **root public key** and both files. Which root key is trusted is the reader's decision, as the
`--expect` id is (`commit.md` §5).

## 4. What L2 checks

After L1 has passed for the whole log:

**Stores** (in this order; `record` is the index of the entry in that file, or `-1` for a failure in the header):

1. `tokens`: fewer than 8 bytes: `tokens-truncated`; magic differs: `tokens-bad-magic`; for each entry, fewer than 4 bytes
   left for the length or fewer than `length` bytes left: `tokens-truncated`; the token does not decode:
   `token-bad-encoding`.
2. `revoked`: fewer than 8 bytes: `revocations-truncated`; magic differs: `revocations-bad-magic`; a final entry shorter than
   104 bytes: `revocations-truncated`; a signature that does not verify under the root key:
   `revocation-bad-signature`.

**Commits**, in log order, each checked in this order, the first failure being the verdict (`record` is the commit's index
in the log):

1. `token-missing`: the commit's `token` is not the id of any token in `tokens`.
2. `token-bad-signature`: some block's signature does not verify under the key the chain expects (§1).
3. `token-revoked`: the id of any prefix of the token (including the whole) is in `revoked` with `since` ≤ the commit's
   `time`.
4. `token-expired`: for some block, `expiry` is not 2^64-1 and the commit's `time` is greater than it.
5. `principal-denied`: for some block, `principal` is not all zeros and differs from the commit's `principal`.
6. `branch-denied`: for some block, its `branch` pattern does not match the commit's `branch`.
7. `effect-denied`: for some block, some effect of the commit is not permitted by any effect of that block.

Times are unsigned 64-bit and compared as such; a verifier that keeps them in a signed integer must not mistake 2^63 or more
for a negative.

The verdict is `ok` at **level 2** if every commit passes.

**`time` is the server's claim.** It is signed with the rest of the commit but the server chose it, so expiry and revocation
bind a server that keeps an honest clock, and no one else. L2 does not make the clock honest.

## 5. Why attenuation cannot widen

A commit is allowed only if every block allows it (checks 4 to 7 each quantify over all blocks), and each block's
permission depends only on that block. So the set of commits a token allows is the intersection of the sets its blocks
allow, and appending a block can only shrink an intersection. The signatures make sure the blocks are the ones the root's
chain produced, in order. The property tests (`tests/properties.py`) check it by construction: for random tokens, random
appended blocks and random commits, a commit allowed by the longer token is allowed by every prefix of it.

## 6. Verifier interface

Both verifiers take, besides `commit.md` §6's arguments:

```
--root <64 hex digits>      the root public key: turns L2 on
--tokens <file>             required with --root
--revoked <file>            optional with --root (absent means none)
```

`--tokens` or `--revoked` without `--root`, `--root` without `--tokens`, or a file that cannot be read, is a usage error
(exit 2, no verdict). With L2 on, the success line is

```
ok commits=<N> branches=<B> level=2
```

and a rejection is `reject rule=<tag> record=<i>` as before, with the L2 tags of §4. Without `--root` nothing changes: the
line, the tags and the exit statuses are those of `commit.md`.

## 7. Vectors

L2 vectors are `NAME.log` with `NAME.tokens`, optionally `NAME.revoked`, and an `NAME.args` that points at them (`{dir}` is
the vectors directory). `tools/gen_l2.py` writes them next to the L1 ones, and the same rules hold: the expected line of each
is written by hand.
