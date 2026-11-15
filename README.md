# cancho-db

A Postgres-compatible database whose commit path is verifiable: every write becomes a signed, hash-chained commit that
records who wrote, under which capability, and running which code. *The database you can let agents write to.*
Working name. The design is [`docs/design.md`](docs/design.md).

## Status

**M0 (spec and verifier).** Built:

- [`docs/spec/commit.md`](docs/spec/commit.md): the byte-level commit and log format and **L1 (integrity)**
  verification, written so a verifier needs only SHA-256 and Ed25519.
- [`docs/spec/token.md`](docs/spec/token.md): capability tokens (a chain of signed blocks that can only narrow) and
  **L2 (authority)**: was each commit allowed by the token it presented?
- [`docs/spec/ir.md`](docs/spec/ir.md): the **statement IR** (the bound form of a small SQL subset) and effect inference,
  so that L2 can check that a commit's recorded effects are *what its statements do*, not only what the server says.
- [`vectors/`](vectors): 341 golden vectors, valid chains and one tampered, malformed or denied case for each rule.
- Three verifiers that must agree on every one: [`src/`](src) in cancho (no C, no foreign call),
  [`tools/verify.py`](tools/verify.py) in Python, and [`verifiers/go/`](verifiers/go) in Go, written from the specs alone
  by a separate agent session (see its README and [`docs/claims.md`](docs/claims.md) for what that does and does not show).

**Designed, not built:** M1, the proxy in front of PostgreSQL with psql first ([`docs/m1-proxy.md`](docs/m1-proxy.md)).
**Not built:** L3 replay, SQL-to-IR lowering, and M2 onward (branches, the engine). Without `--stmts`, L2
checks only the commit's *recorded* effect set against its token; with it, the recorded set is shown to equal what the
statements infer. That the store holds what was actually executed is L3's (see [`docs/claims.md`](docs/claims.md)). That file says what is claimed, what each claim rests on, and what is *not*
claimed.

## Use

```console
$ cancho build --std src/commit.cho src/verify.cho -o verify
$ ./verify vectors/ok_chain3.log
ok commits=3 branches=1
$ ./verify vectors/seq_skips.log
reject rule=seq-gap record=1
$ ./verify vectors/truncated_tail_pinned.log --expect eace04f4...671d   # the last id you were given
reject rule=expected-missing record=-1
```

Exit status 0 for `ok`, 1 for `reject`, 2 for a usage error or a file that cannot be read. `python3 tools/verify.py`
takes the same arguments and prints the same lines. A log is *not* shown to be complete by verifying: pass `--expect`
the last commit id you were given, or a removed tail goes unnoticed ([spec §5](docs/spec/commit.md)).

L2 is switched on by naming the root key and the token store (and, optionally, the signed revocation list and, for the
statement IR, `--stmts`):

```console
$ ./verify vectors/l2_ok_basic.log --root $ROOT --tokens vectors/l2_ok_basic.tokens
ok commits=3 branches=1 level=2
$ ./verify vectors/l2_effect_denied_ddl.log --root $ROOT --tokens vectors/l2_effect_denied_ddl.tokens
reject rule=effect-denied record=0
```

(`$ROOT` is the key in the vector's `.args` file; the vectors' keys are derived from fixed strings, for testing only.)

With the statement store, a server that hides what it did is refused (`ir_gap_*` is this case, with and without it):

```console
$ ./verify vectors/ir_gap_hidden_write_passes_l2_alone.log --root $ROOT --tokens vectors/ir_gap_hidden_write_passes_l2_alone.tokens
ok commits=1 branches=1 level=2
$ ./verify vectors/ir_gap_hidden_write_is_refused_with_statements.log --root $ROOT \
    --tokens vectors/ir_gap_hidden_write_is_refused_with_statements.tokens --stmts vectors/ir_gap_hidden_write_is_refused_with_statements.stmts
reject rule=effects-mismatch record=0
```

## Test

```console
$ CANCHO=/path/to/cancho sh scripts/check.sh
```

Runs what CI runs: formatting, vectors regenerate byte for byte, all three verifiers on every vector, the command lines,
the authority report, the attenuation property over thousands of random tokens, 4,500 differentially fuzzed inputs (the
verifiers agree and none crashes), and the mutants of both verifiers (every one must make a vector fail). Needs `python3` with `cryptography`, and the cancho
compiler at the revision in [`cancho.toml`](cancho.toml), and `go`.

## Licence

European Union Public Licence v. 1.2 (EUPL-1.2), [`LICENSE`](LICENSE), as the other cancho repositories. Copyright
Alpibru S.L. ([`NOTICE`](NOTICE)).
