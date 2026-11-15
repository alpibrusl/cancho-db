# Claims

Every security statement the README makes, next to the test that enforces it. **A claim with no test is removed from
the README** (design, "Verification strategy"). A test is only listed if it was shown to fail when the claim is false:
`tests/mutants.py` breaks each verifier one rule at a time, and the row says which mutant makes the test fail.

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

## What is *not* claimed

- **L2 and L3.** Nothing here checks tokens, effects, or replay. A log that verifies says the history was not altered
  by anyone without the server key, not that each commit was allowed. The token spec is the next piece of M0.
- **The server key is trusted.** A holder of it can write a valid log of anything. L1 detects tampering by everyone else.
- **The second verifier is not yet independent in the way the design asks.** The design wants it written from the spec
  alone by a session with no access to the engine source. Here one author wrote the spec, the vectors, the cancho
  verifier and the Python verifier, in one sitting, and the Python one was written after the cancho one existed. What
  independence there is: a different language, and a different Ed25519 (cancho's own against OpenSSL's, via
  `cryptography`). M0's exit criterion is **not met** until a verifier is written from `docs/spec/commit.md` by someone
  who has not seen `src/` or `tools/verify.py`, and agrees on every vector.
- **Mutants are the ones listed.** `tests/mutants.py` shows the vectors fail for those changes, not for every possible
  fault. It found one real gap while this was written (a `seq` above 2^32), now covered by `seq_2_pow_32*`.
- **Hash and signature choice is provisional** (design, open question 3). `version` is in the commit so a change is a new
  version, not a rewrite.
