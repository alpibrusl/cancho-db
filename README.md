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
- [`vectors/`](vectors): 209 golden vectors, valid chains and one tampered, malformed or denied case for each rule.
- Two verifiers that must agree on every one: [`src/`](src) in cancho (no C, no foreign call) and
  [`tools/verify.py`](tools/verify.py) in Python.

**Not built:** L3 replay, the statement IR, and M1 onward (the proxy, branches, the engine). L2 checks the commit's
*recorded* effect set against its token; that the recorded set is what the statements do needs the IR (see
[`docs/claims.md`](docs/claims.md)). That file says what is claimed, what each claim rests on, and what is *not*
claimed. In particular the M0 exit criterion is **not yet met**: the second verifier was not written independently of
the first.

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

L2 is switched on by naming the root key and the token store (and, optionally, the signed revocation list):

```console
$ ./verify vectors/l2_ok_basic.log --root $ROOT --tokens vectors/l2_ok_basic.tokens
ok commits=3 branches=1 level=2
$ ./verify vectors/l2_effect_denied_ddl.log --root $ROOT --tokens vectors/l2_effect_denied_ddl.tokens
reject rule=effect-denied record=0
```

(`$ROOT` is the key in the vector's `.args` file; the vectors' keys are derived from fixed strings, for testing only.)

## Test

```console
$ CANCHO=/path/to/cancho sh scripts/check.sh
```

Runs what CI runs: formatting, vectors regenerate byte for byte, both verifiers on every vector, the command lines,
the authority report, the attenuation property over thousands of random tokens, 4,500 differentially fuzzed inputs (the
two verifiers agree and neither crashes), and the mutants of both verifiers (every one must make a vector fail). Needs `python3` with `cryptography`, and the cancho
compiler at the revision in [`cancho.toml`](cancho.toml).

## Licence

European Union Public Licence v. 1.2 (EUPL-1.2), [`LICENSE`](LICENSE), as the other cancho repositories. Copyright
Alpibru S.L. ([`NOTICE`](NOTICE)).
