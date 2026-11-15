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
| C8 | No input makes any verifier crash or print anything but its one line. | `tests/fuzz.py` (differential, damaged vectors), `tests/cli_test.py` | a trap, a signal, a stray stderr line, or a disagreement between the verifiers fails the run |
| C9 | The three verifiers give the same answer on every vector. | `tests/run_vectors.py`, run on each | each vector holds the line a verifier must print; the lines are written by hand in `tools/gen_vectors.py`, not taken from either verifier |

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

### Statement IR and effect inference ([`spec/ir.md`](spec/ir.md))

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C17 | A statement has one reading: names, operands, counts and tags that an encoder would not produce are refused, expressions in prefix order are well formed exactly when no operand is owed or left over, and `.` cannot appear in a table or column name. | `ir_bad_*` vectors (39); the IR decode mutants of both verifiers | a name with a dot would make `read a.b` ambiguous; an operand miscount would let two readings share bytes |
| C18 | Each kind of statement yields exactly the effects of `ir.md` §3: a select reads each `from` table and each column it names, a write records the table, a call records the function, a `now()` or sequence records a nondet. | `ir_ok_*` vectors, whose recorded effect sets are written out by hand, never computed; the "forgets ..." mutants | the expected set of every vector is a literal |
| C19 | **A commit's recorded effects must equal the inferred effects of its statements**, a hidden effect and an invented one alike, and every statement it names must be in the store. A server that records less than it ran passes L2 alone and is refused with `--stmts`. | `ir_mismatch_*`, `ir_stmt_missing_*`, **`ir_gap_hidden_write_passes_l2_alone`** and **`ir_gap_hidden_write_is_refused_with_statements`** (the same log, with and without the store); the "recorded may be smaller / larger" and "only the first statement" mutants | equality is checked in both directions |
| C20 | With statements, `effect-denied` is judged on the effect set shown to be real, after `stmt-missing` and `effects-mismatch`. | `ir_effect_denied_on_the_true_effects`, `ir_order_*`; the "effects judged before the statements" mutants of both verifiers | a lying recorded set must not be what the token is judged against |
| C21 | A malformed statement store is refused with a tag and the entry it names, before any commit is judged, after the token store and the revocation list; an unused bad entry is still an error. | `ir_stmts_*`, `ir_bad_entry_unused_is_still_an_error`, `ir_order_*_before_stmts` | as C15 |

### The SQL lexer, P1a ([`m1-lowering.md`](m1-lowering.md) section 3)

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C33 | **The lexer finds the same statements PostgreSQL runs**, for everything it accepts: a `;` inside a string, a comment (nested or not) or a quoted identifier separates nothing; a backslash in a string is a backslash. | `tests/lex_diff.py`: SQL strings from a grammar of valid lists and from a fuzzer over hostile fragments are sent to a real PostgreSQL, whose `CommandComplete` count must equal the lexer's. 12,000 strings, 6,247 comparable (4,505 with 2 or more statements): 0 disagreements. A lexer with non-nesting comments is caught (20 in 3,000) | a lexer that found fewer statements than PostgreSQL runs would let one through unchecked |
| C34 | Operators end where PostgreSQL ends them, including its rule that only an operator holding one of `~ ! @ # % ^ & | ` ?` may end in `+` or `-`. | `tests/lex_diff.py` reads PostgreSQL's own error message for 3,000 random operator strings (0 disagreements); 26 hand cases (each special character with each sign, plus the trimming and comment cases); the mutants "~ is not special", "@ is not special", "never trims", "always trims" | the rule was missed by my first cases and found by mutation |
| C35 | **Everything not understood is refused with a tag**: `E''`, `U&''`, bit and hex strings, `$$` and `$tag$`, `$1`, non-ASCII outside strings and comments, NUL, form feed, vertical tab, unknown characters, a number followed by identifier characters (`1abc`, `1_000`, `0x1F`), an unterminated string, comment or identifier. | 54 refusal cases with their exact tags; 35 mutants of the lexer, none surviving | the default is refusal, so a form not named is an error |
| C36 | An identifier over 63 bytes is refused: PostgreSQL truncates it silently, so two different long names would be one. | measured on PostgreSQL (a `NOTICE`, then `column ... specified more than once`); cases at 63 and 64 bytes, quoted, unquoted and with doubled quotes | a name checked as one thing would run as another |

### The expression parser, P1b-1 ([`m1-lowering.md`](m1-lowering.md) section 3.2)

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C37 | **The rendering means what the original means**: PostgreSQL's plan for `SELECT <original> FROM t` and for `SELECT <rendering> FROM t` are identical, or both are errors with the same SQLSTATE. | `tests/parse_diff.py`: 12,000 expressions over three seeds (a typed grammar with random parentheses, spacing, case and comments; operator chains with no parentheses; a token fuzzer), 0 disagreements. Its teeth: parsers with AND binding like OR, `\|\|` above `+`, unary minus loosened, comparisons made associative are each caught (2, 8, 26 and 44 disagreements in 1,200 to 3,000 cases) | the proxy forwards the rendering, so a parse that differs from PostgreSQL's is a different statement run |
| C38 | **The parser accepts nothing PostgreSQL calls a syntax error.** | the same run: an accepted expression whose original is `42601` is a failure; none occurred | a statement nobody could have run would run |
| C39 | PostgreSQL's operator precedence and non-associativity are what the parser implements: `OR < AND < NOT < IS < comparisons < BETWEEN IN LIKE ILIKE < \|\| < + - < * / % < unary minus`, with `a < b < c` refused. | 265 hand-written cases from the documented table (each pair that matters, in both orders); 56 parser mutants killed | the differential covers it too, but a hand case says *why* an answer is right |
| C40 | **Everything outside the subset is refused with a tag**: other operators (`^ @> ~ ->`), unary `+`, `IS TRUE/DISTINCT FROM`, row constructors, sub-selects (`subquery`), `ESCAPE`, `SIMILAR TO`, array syntax, a third name part, a quoted function name, every PostgreSQL reserved, function-name or column-name keyword as a bare name, any type outside the closed list. | 123 refusal cases with exact tags; the reserved-word list is PostgreSQL's `pg_get_keywords()` | a word PostgreSQL rejects must not be quietly quoted into one it accepts |
| C41 | **A limit is a refusal, never a trap**: operator and value stack depth, node and child arenas, the rendering stack and the output buffer each have a case at the limit and one under it. | the `limits` cases; one found a real trap (the renderer wrote at index -1 into a full buffer) | an input must never reach a panic |

### The SELECT parser, P1b-2a ([`m1-lowering.md`](m1-lowering.md) section 3.3)

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C42 | **A SELECT's rendering means what the original means**: PostgreSQL's plan for the statement and for its rendering are identical (or both errors with one SQLSTATE), and nothing accepted is a syntax error to PostgreSQL's parser. | `tests/stmt_diff.py`: 12,000 statements over three seeds, 0 disagreements; seven rendering breakages each caught | the proxy runs the rendering |
| C43 | Every clause, alias, join kind and direction the subset reads is pinned by hand: 146 cases (83 refusals with exact tags), each accepted statement a fixed point of parse-then-render; 34 mutants of the statement parser and its half of the renderer killed. | `tests/stmt_test.cho`, `tools/gen_stmt.py --check`, `tests/mutants.py stmt` | the differential cannot see what a plan does not show (aliases) |
| C44 | Words PostgreSQL treats specially are not taken for names: `nulls first`, the eleven non-bare-label words as a label without `AS`, `ROLLUP` and `CUBE` in `GROUP BY`. | cases for each, and the differential that found the first two | a statement PostgreSQL would reject, or read differently, would run |

### INSERT, UPDATE and DELETE, P1b-2b ([`m1-lowering.md`](m1-lowering.md) section 3.3)

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C45 | **A DML statement's rendering means what the original means**: PostgreSQL's `EXPLAIN` plan for INSERT, UPDATE and DELETE (which plans, never runs) is identical for the original and the rendering, and nothing accepted is a syntax error to PostgreSQL. | `tests/stmt_diff.py` with DML in 30% of the statements, 12,000 statements over three seeds, 0 disagreements | the proxy runs the rendering |
| C46 | The forms outside the subset carry their own tag: `insert-select`, `returning`, `on-conflict`; the rest are refused as `syntax`, `reserved-word` or `unknown-construct`. 226 hand cases in all (143 refusals); 60 mutants of the statement parser and renderer, none surviving (four survived at first: a skipped `VALUES`, `SET` or `FROM`, a row without its parenthesis; each had a gap in the cases). | `tests/stmt_test.cho`, `tests/mutants.py stmt` | a guard that only skips a token is invisible to cases that fail anyway |

### The closed DDL, P1b-2c ([`m1-lowering.md`](m1-lowering.md) section 3.4)

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C47 | **The rendering of a DDL statement does what the original does**: run in a rolled-back transaction, both leave the same columns, constraints and indexes, or fail with the same SQLSTATE; nothing accepted is a syntax error to PostgreSQL. | `tests/ddl_diff.py`, 5,000 cases over two seeds, 0 disagreements; four rendering breakages each caught | the proxy runs the rendering, and a renderer that drops `PRIMARY KEY` would run a different schema change |
| C48 | The DDL grammar is closed and everything else is refused: 320 hand cases in all (211 refusals); 84 statement mutants, none surviving (one survived at first: `DEFAULT -'x'`). | `tests/stmt_test.cho`, `tests/mutants.py stmt` | the IR's `Ddl` names only the table, so what is accepted must be fully reproduced |

### The lowering, P1c ([`m1-lowering.md`](m1-lowering.md) sections 4.1 and 4.2)

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C49 | **The lowering produces the IR a person would write for the statement**: aliases resolved to base tables, unqualified columns to the one table that has them, `*` expanded in order, `BETWEEN` and a simple `CASE` written with `Op`, `now()` as `Nondet`. | `tests/lower_check.py`: 42 statements whose IR bytes are built by hand with the test's own encoder and compared byte for byte | the IR's id and effects come from these bytes |
| C50 | **The effects of the lowered statement are the hand-written ones**, as the verifier sees them: a commit recording exactly the hand-written set verifies (`level=2+ir`), one with an effect fewer or one more is refused `effects-mismatch`. | the same 42 cases, run through `build/verify --stmts`; 126 refusals of the altered sets | a lowering that read a column it did not record, or the reverse, is the whole point of the IR |
| C51 | **A name the lowering resolves, PostgreSQL resolves the same way**, and one it refuses is one PostgreSQL does not accept: unknown tables, unknown and ambiguous columns, `ORDER BY` output names. | `tests/lower_diff.py`: 20,000 generated statements against PostgreSQL's `42P01`, `42703`, `42702`, 0 disagreements | the IR would name something other than what runs |
| C52 | **What the log could not reproduce is refused**: `random`, `clock_timestamp`, `nextval`, `gen_random_uuid`, `setseed`, `txid_current`, `timeofday`, `statement_timestamp`, `transaction_timestamp`, `currval`, `lastval` (`nondeterministic`); `now()` is recorded as `Nondet now`. | refusal cases; the mutants that allow `random()` or `nextval()`, and that make `now()` a plain call | a value the server chose, not in the log |
| C53 | 73 cases, @LM@ mutants of the lowering killed, none surviving. | `tests/lower_check.py`, `tests/mutants.py lower` | |

### IR version 2 ([`spec/ir.md`](spec/ir.md) section 6)

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C29 | **A column named in any clause is a read**: `ORDER BY`, `GROUP BY`, `HAVING`, `LIMIT`/`OFFSET`, a join's `ON`, a `CASE`, an `IN` list, under `NOT`. A recorded set that leaves one out is `effects-mismatch`. | `ir2_ok_*` (effects written by hand) and `ir2_mismatch_*` vectors; the "reads nothing" mutants (one per clause) in the Python verifier; all three verifiers agree | each clause has a vector whose only read of some column is in that clause |
| C30 | A cast is not a call, a type name is not an effect, and `count(*)` reads no column: `Cast` and `Star` add nothing; an aggregate is `call count`. | `ir2_ok_cast_is_not_a_call`, `ir2_ok_star_reads_no_column`, `ir2_mismatch_cast_recorded_as_a_call`; the "a Cast is a call" mutant | a token that granted no `call` would otherwise refuse every cast |
| C31 | v2 is a strict superset of v1, selected by the store's magic: a v1 statement keeps its id in a v2 store; a v1 store refuses every v2 construct; any other magic is refused. | `ir2_ok_a_v1_select_in_a_v2_store`, `ir2_ok_v1_and_v2_statements_in_one_commit`, the nine `ir2_v1_store_refuses_*` vectors, `ir2_a_store_with_another_magic_is_refused`; the "accepted in a v1 store" mutants of both verifiers | moving a store from v1 to v2 must not change a commit's `statements` hashes |
| C32 | A malformed v2 statement is refused for **its own** fault: each of the 30 `ir2_bad_*` vectors carries one fault only. | the mutants of each rule in both verifiers (150 Python, 139 cancho, none surviving) | two vectors carried a second fault that masked the first (a `Case` else flag of 2, a join kind of 3); the mutants found them and they were fixed |

### The proxy, P0 ([`m1-proxy.md`](m1-proxy.md))

| # | Claim | Enforced by | Fails when the claim is false because |
|---|---|---|---|
| C22 | A client gets in only with a capability token that decodes, is signed from the root key, whose holder has the last block's key, that is unexpired, and that allows the one branch served; a different branch name is refused. Each refusal is a rule tag with its SQLSTATE. | `tests/login_test.cho` (31 login cases with real signatures, 25 base64url, 26 startup, the exact tag and state of each refusal); the 40 `login:` mutants; `tests/proxy_e2e.py` (each refusal through real psql, and the SQLSTATE read off the wire) | the cases are minted by an independent Ed25519 with hand-written answers |
| C23 | **A refused login never reaches PostgreSQL.** | `tests/proxy_e2e.py` counts the startup messages PostgreSQL receives through a wire tee: none for the six refused logins and none for any malformed packet; the mutant "a refused login still opens the upstream" | the tee sees every connection the proxy makes upstream |
| C24 | Only loopback clients are served: any other peer is closed without a byte being read. | `login.is_loopback` at the boundary of every range (18 addresses, 8 mutants); `tests/proxy_e2e.py` with a client from the host's other address (a reset, not an answer); mutant "non-loopback clients are served" | cancho's `tcp_listen` binds every address, so this is the only thing standing between the token and the network |
| C25 | After login the proxy forwards every message untouched, in both directions: 200,000 rows (7.9 MB) come back byte for byte as direct; errors, transactions and rollbacks are the server's own; 24 clients at once each get their own answer. | `tests/proxy_e2e.py`; mutant "forwarded bytes lose the last one" | the comparison is against psql talking to PostgreSQL directly |
| C26 | A silent client, a silent upstream and a dead upstream each cost one client a refusal, not the loop: closed after about 10 s, `upstream-timeout` after about 5 s, `upstream-unavailable` at once. | `tests/proxy_e2e.py` with real timings; mutants "a silent client is never closed", "a silent upstream is waited for a minute" | the first draft of the proxy waited on PostgreSQL's login forever and one silent upstream froze every client: seen, fixed, now tested |
| C28 | The proxy test can fail: ten mutants of `proxy/proxy.cho` (serve non-loopback clients, skip the token check, never close a silent client, wait a minute for a silent upstream, lose a forwarded byte, answer `S` to SSLRequest, drop application_name, use the client's role upstream, open the upstream after a refusal, skip the protocol-version check) are each caught by `tests/proxy_e2e.py`. | `PG_E2E_PORT=... python3 tests/mutants.py proxy cancho`: 10 mutants, 0 not killed. Not in `scripts/check.sh`: it takes about 20 minutes | each mutant is a real rule removed |
| C27 | The proxy never touches the filesystem, signals, other programs or foreign code; its network authority is unbounded. | `tests/authority.sh` pins both lists | a change in either list is a decision, not a drift |

## What is *not* claimed

- **P0 understands no SQL.** The proxy checks who may connect, not what they run: there is no effect check, no log and
  no commit yet, so a valid token can run anything the upstream role can. That is P1 and P2.
- **P0's stated limits.** Opening the connection to PostgreSQL (`tcp_connect`) blocks, so a black-holed upstream would stall
  the loop (a down or silent one is handled); while one client's upstream login waits (up to 5 s) the others wait. The
  upstream must use trust login. `CancelRequest` is closed, not forwarded. The token and its key travel in clear, so only
  loopback is served. The network authority is unbounded in the report (a compiler revision limit, `m1-proxy.md` section 3).
  Concurrency was tested at 24 clients, not more.
- **L3.** Nothing here replays statements.
- **Without `--stmts`, L2 judges only the recorded effect set against the token**, and a server that records less than it
  ran passes (`ir_gap_hidden_write_passes_l2_alone` is that case, kept on purpose). With `--stmts` the recorded set is
  shown to be exactly what the statement store infers. What that does **not** show: that the store holds the statements
  the server actually executed (the log commits to their hashes; whether the server ran that IR is its honesty again, and
  L3 is what checks execution); that the server lowered the client's SQL to that IR faithfully (an alias resolved to the
  wrong table gives an IR consistent with its own effects and wrong about the SQL; differential testing against Postgres
  at M1 is what covers that); and anything the v1 IR cannot express (subqueries, `RETURNING`, CTEs), which a server cannot
  run until a new IR version.
- **Two stated gaps in the effect model.** `call fn` is recorded but not expanded into what the stored function does
  (that needs the function's declared effects, M1). An `Update` or `Delete` does not record `read table` for its row
  count, the writer already holding `write table`.
- **The server key and the root key are trusted.** A holder of the server key can write a valid log of anything, and of
  the root key can mint any token. L1 and L2 detect tampering and overreach by everyone else.
- **`time` is the server's claim** (`token.md` §4). Expiry and revocation bind a server with an honest clock.
- **A token can be cut short undetectably.** A prefix of a token is a valid, wider token (`l2_ok_token_prefix_is_a_token`).
  What stops a thief using it is proof of the last private key when a token is *presented*, which is the connection
  protocol of M1 and not something a log can show.
- **Patterns are crude on purpose.** One wildcard, a trailing `*` meaning prefix; `o*` matches `orders` and `orders_archive`
  (`l2_ok_star_is_a_prefix_sharp_edge`). Row-level predicates are later (design, open question 7).
- **How independent the verifiers are.** The cancho and Python verifiers were written by the author of the specs and the
  vectors, the Python one after the cancho one. The third, in Go (`verifiers/go/`), was written from `commit.md` and
  `token.md` alone by a separate agent session handed a directory with only those files, the vectors and the runner. That
  isolation was by instruction, not a sandbox; the agent's tool-call log was read afterwards and shows it read the two specs,
  wrote the file and ran the vectors. It is the same model family as the author, so a misreading the family shares would be
  shared. What it did show: one bug of its own on the first run (66 of 209 vectors, a missing `next_key` in a signed message
  that the spec states plainly), and seven places where the spec left a careful implementer to decide, now written into the
  specs. It was later extended to the statement IR the same way (the IR spec and the new vectors only; all 121 IR vectors
  passed without a fix; eight open points reported and now written into `ir.md`). Three implementations use three different Ed25519 code bases (cancho's own, OpenSSL's, Go's). **The M0 exit
  criterion** (every verifier agrees on every vector and rejects every tampered chain) **is met for L1, L2 and the IR** by
  these three, on the strength of that caveat.
- **What the three-way fuzz found.** Fuzzing all three verifiers against each other found one disagreement the vectors and
  the independent reading had both missed: whether `effects-unordered` or `bad-encoding` wins when an out-of-order effect is
  followed by a malformed one. The spec said "judged when its field has been read" and did not say whether a list is the
  field or each element. That was a spec ambiguity, not a bug in any verifier: it is now decided (per element, in order,
  `commit.md` §5), five vectors pin it, and the Go verifier was changed by the agent that wrote it, from the clarified
  text. The agent was then asked to look for the same ambiguity elsewhere by reading; it named three more (the order
  of entries inside the token, revocation and statement stores), now written into `token.md` §4 and `ir.md` §4 and pinned by
  three vectors. A spec sentence is not counted as settled until a vector separates the two readings.
- **IR v2 independence:** the Go verifier was extended to v2 by the same separate agent, from the spec and the vectors only,
  and passed all 428 without a fix; I re-ran its code and its tool-call log shows no read outside its directory. Same
  caveats as before (instruction-enforced, same model family). Its six open points are written into `ir.md` section 6.
- **The lowering is not the proxy.** The parser reads expressions, SELECT, INSERT, UPDATE, DELETE and the closed DDL, and
  `src/lower.cho` turns them into IR; the proxy calls neither, so no query is checked against a token yet (P1d). A `SELECT`
  with no `FROM` cannot be lowered, the schema snapshot is written by hand (nothing reads `information_schema` yet), and the
  lowering does not type-check.
- **The statement parser's differentials are as good as their generators.** The plan comparison for SELECT and DML runs over three
  small tables, and plans show joins and clauses, not every alias or name. The statement-count differential of the lexer cannot
  see a lexing error that keeps statement boundaries (for example, a doubled quote ending a string preserves quote parity); the
  unit cases cover that, and each check is claimed for what it covers. The fuzzers' alphabets are finite.
- **The expression differential is as good as its generator.** Expressions are type-correct by construction in the grammar
  half and mostly not in the fuzzer half; a case where both sides fail with the same SQLSTATE is counted as agreeing, so a wrong
  parse that also fails to type-check is invisible there (the hand cases cover precedence either way). The planner folds constant
  subtrees, so a mistake confined to constants (`1 + 2 * 3`) can be hidden; the columns `a b c d` keep most trees unfolded.
  About 0.6% of valid expressions are refused (one deliberate class is `BETWEEN` bounds holding comparisons); that is counted in
  every run, not hidden. Only PostgreSQL 16 was compared.
- **No SQL is lowered to v2 yet.** The IR can say what a psql user types; nothing produces it from SQL (P1, `m1-lowering.md`).
- **Ed25519 edge cases are unspecified.** Small-order and non-canonical-but-decodable keys and `R` values are
  implementation-defined in v1 and no vector exercises them (`commit.md` header).
- **Mutants are the ones listed.** `tests/mutants.py` shows the vectors fail for those changes, not for every possible
  fault. It found real gaps while this was written, each now covered by a vector: a `seq` above 2^32
  (`seq_2_pow_32*`); and for L2 a commit whose second effect is the denied one (`l2_effect_denied_second_effect`), an
  empty pattern (`*_empty_pattern`), duplicate revocations listed latest first
  (`l2_revoked_twice_earliest_wins_later_first`) and u64 compares across the 32-bit boundary
  (`*_across_32_bit_carry`).
- **The IR mutants found one gap** while this was written: a row whose declared count differs from the number of columns
  was only ever caught by a truncation or trailing bytes, never by its own rule
  (`ir_bad_insert_row_count_*`). Two mutants are not listed because their change is not observable in a verdict: the
  check that a count fits the bytes left (every read is bounds-checked anyway, so only the allocation is unbounded) and
  `size <= ne` for `size == ne` in the cancho set comparison (with every recorded effect required to be inferred, they are
  the same test).
- **The L2 fuzzing is shallow in the finest rules.** Damaging a token changes its id, so most damaged inputs end in
  `token-missing` or `token-bad-encoding`; the fuzzer shows agreement and no crashes, and the vectors (not the fuzzer) are
  what pin the individual denial rules.
- **Hash and signature choice is provisional** (design, open question 3). `version` is in the commit so a change is a new
  version, not a rewrite.
