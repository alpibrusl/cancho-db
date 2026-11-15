# Claims

Every security statement the README makes, next to the test that enforces it. **A claim with no test is removed from
the README** (design, "Verification strategy"). A test is only listed if it was shown to fail when the claim is false:
`tests/mutants.py` breaks each verifier one rule at a time, and the row says which mutant makes the test fail.
C1 to C9 are L1 ([`spec/commit.md`](spec/commit.md)).

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C1 | Altering any byte of a commit makes the log fail. | `body_flipped_*`, `sig_*` vectors; mutants "signature unchecked", "sig over wrong domain" | the signature covers the id, the id covers every field |
| C2 | Dropping, repeating, reordering or skipping commits makes the log fail. | `record_dropped`, `records_reordered`, `seq_*` vectors; mutants "seq may skip ahead", "seq may repeat", "seq global not per branch", "seq high half ignored" | `seq` is gapless per branch, a u64 compared whole |
| C3 | A commit's parents are checked: the first is the branch's previous commit, a second or a fork point is a commit already in the log, and the two differ. | `parent_*`, `fork_*`, `merge_*`, `root_two_parents` vectors; the six `parent` mutants | each parent rule has a vector that only it refuses |
| C4 | A commit signed by any key but the log's is refused, and the signature is judged before the chain rules. | `signed_by_other_key`, `log_key_is_other`, `signature_before_seq`, `first_failure_wins`; mutant "signature after chain rules" | an unsigned record claims nothing |
| C5 | A log cut short is refused, and **a log with its end removed is detected only against a commit id the reader already holds** (`--expect`). | `truncated_*`, `record_too_large*`, `truncated_tail_ok_alone`, `truncated_tail_pinned`, `expected_*` | a prefix of a valid log is a valid log (spec §5); the vectors state both halves |
| C6 | Every byte sequence has one reading: anything an encoder would not produce is refused (trailing bytes, unsorted or repeated effects, a bad tag, a count the record cannot back). | `bad-encoding`, `effects_*`, `*_overrun`, `count_*` vectors; the decode mutants | spec §1: exactly one byte representation per value |
| C7 | The cancho verifier reaches the log and the console and nothing else: no network, no signals, no other program, no foreign code. | `tests/authority.sh` | `cancho authority` lists what the program performs; the test pins the list |
| C8 | No input makes either verifier crash or print anything but its one line. | `tests/fuzz.py` (differential, damaged vectors), `tests/cli_test.py` | a trap, a signal, a stray stderr line, or a disagreement between the two verifiers fails the run |
| C9 | The two verifiers give the same answer on every vector. | `tests/run_vectors.py`, run on each | each vector holds the line a verifier must print; the lines are written by hand in `tools/gen_vectors.py`, not taken from either verifier |

### L2: tokens ([`spec/token.md`](spec/token.md))

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C10 | A token is accepted only if every block is signed by the key the previous block names, the root key first. Blocks cannot be altered, reordered, dropped from the middle, or added by anyone without the last key. | `l2_sig_*`, `l2_block*`, `l2_first_block_*`, `l2_next_key_is_not_a_point`, `l2_wrong_root_given`; mutants "chain unchecked", "only the first block's signature", "block signature ignores next_key" | the chain is the only thing tying a block to the root |
| C11 | **Attenuation never widens**: a commit is allowed only if every block allows it, so appending a block can only narrow. | `*_cannot_be_widened`, `l2_expired_attenuation_cannot_extend`, `*_by_attenuation` vectors; `tests/properties.py` (20,000 random tokens: allowed by the whole token implies allowed by every prefix); the "only the first block's ..." mutants of both verifiers; the property test itself fails against a verifier that counts only the last block | a verifier that read only one block would accept a widening block |
| C12 | A commit is refused unless its token's every block allows its branch, its principal, each of its effects, and its time, and the first rule broken is the one reported, in a fixed order. | `l2_branch_denied_*`, `l2_effect_denied_*`, `l2_principal_*`, `l2_expired*`, `l2_order_*`, `l2_first_failing_commit_wins`; the L2 mutants, including the ones that swap two checks | each rule has a vector only it refuses |
| C13 | Times are unsigned 64-bit: a time or expiry at or above 2^63, or across the 2^32 boundary, is compared correctly. | `*_high_bit`, `*_above_signed_range`, `*_across_32_bit_carry`, `l2_expired_time_max`; the "low half only" and "high half only" mutants | cancho's int is signed and splits u64 in two halves; one half alone gets these backwards |
| C14 | Revocations bind only if signed by the root; revoking a token revokes every token attenuated from it and none it was attenuated from; a commit before `since` stays valid; the earliest `since` of an id wins. | `l2_revoked_*`, `l2_ok_revoked_*`, `l2_ok_revoking_child_leaves_parent`; the revocation mutants | an unsigned list could lock the system out |
| C15 | A malformed token store or revocation list is refused with a tag and the entry it names, before any commit is judged; L1 is judged before L2. | `l2_tokens_*`, `l2_token_*`, `l2_revoked_bad_*`, `l2_revoked_truncated_*`, `l2_l1_failure_*`, `l2_stores_checked_before_commits` | the order is part of the spec, so two verifiers cannot disagree |
| C16 | Neither verifier crashes or prints anything but its line on damaged L2 inputs, and they agree. | `tests/fuzz.py` (damages log, token store and revocation list), `tests/cli_test.py` | as C8 |

## What is *not* claimed

- **L3.** Nothing here replays statements. And **L2 here checks the commit's *recorded* effect set against its token,
  not that the recorded set is what the statements do.** The design's L2 "needs tokens and statement IR", and the IR is
  not specified yet, so a server that records a smaller effect set than it executed passes this check. Closing that is
  M1's effect inference plus the IR format; until then the claim is "the log is consistent with the tokens", not "the
  statements were within the tokens".
- **The server key and the root key are trusted.** A holder of the server key can write a valid log of anything, and of
  the root key can mint any token. L1 and L2 detect tampering and overreach by everyone else.
- **`time` is the server's claim** (`token.md` §4). Expiry and revocation bind a server with an honest clock.
- **A token can be cut short undetectably.** A prefix of a token is a valid, wider token (`l2_ok_token_prefix_is_a_token`).
  What stops a thief using it is proof of the last private key when a token is *presented*, which is the connection
  protocol of M1 and not something a log can show.
- **Patterns are crude on purpose.** One wildcard, a trailing `*` meaning prefix; `o*` matches `orders` and `orders_archive`
  (`l2_ok_star_is_a_prefix_sharp_edge`). Row-level predicates are later (design, open question 7).
- **The second verifier is not yet independent in the way the design asks.** The design wants it written from the spec
  alone by a session with no access to the engine source. Here one author wrote the spec, the vectors, the cancho
  verifier and the Python verifier, in one sitting, and the Python one was written after the cancho one existed. What
  independence there is: a different language, and a different Ed25519 (cancho's own against OpenSSL's, via
  `cryptography`). M0's exit criterion is **not met** until a verifier is written from `docs/spec/commit.md` by someone
  who has not seen `src/` or `tools/verify.py`, and agrees on every vector.
- **Mutants are the ones listed.** `tests/mutants.py` shows the vectors fail for those changes, not for every possible
  fault. It found real gaps while this was written, each now covered by a vector: a `seq` above 2^32
  (`seq_2_pow_32*`); and for L2 a commit whose second effect is the denied one (`l2_effect_denied_second_effect`), an
  empty pattern (`*_empty_pattern`), duplicate revocations listed latest first
  (`l2_revoked_twice_earliest_wins_later_first`) and u64 compares across the 32-bit boundary
  (`*_across_32_bit_carry`).
- **The L2 fuzzing is shallow in the finest rules.** Damaging a token changes its id, so most damaged inputs end in
  `token-missing` or `token-bad-encoding`; the fuzzer shows agreement and no crashes, and the vectors (not the fuzzer) are
  what pin the individual denial rules.
- **Hash and signature choice is provisional** (design, open question 3). `version` is in the commit so a change is a new
  version, not a rewrite.
