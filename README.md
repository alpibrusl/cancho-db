# cancho-db

A Postgres-compatible database whose commit path is verifiable: every write becomes a signed, hash-chained commit that
records who wrote, under which capability, and running which code. *The database you can let agents write to.*
Working name. The design is [`docs/design.md`](docs/design.md).

## Status

**M0 (spec and verifier), first half.** Built:

- [`docs/spec/commit.md`](docs/spec/commit.md): the byte-level commit and log format and **L1 (integrity)**
  verification, written so a verifier needs only SHA-256 and Ed25519.
- [`vectors/`](vectors): 90 golden vectors, valid chains and one tampered or malformed case for each rule.
- Two verifiers that must agree on every one: [`src/`](src) in cancho (no C, no foreign call) and
  [`tools/verify.py`](tools/verify.py) in Python.

**Not built:** the token spec and L2, L3 replay, and M1 onward (the proxy, branches, the engine). See
[`docs/claims.md`](docs/claims.md) for what is claimed, what each claim rests on, and what is *not* claimed. In
particular the M0 exit criterion is **not yet met**: the second verifier was not written independently of the first.

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

## Test

```console
$ CANCHO=/path/to/cancho sh scripts/check.sh
```

Runs what CI runs: formatting, vectors regenerate byte for byte, both verifiers on every vector, the command lines,
the authority report, 3,000 differentially fuzzed inputs (the two verifiers agree and neither crashes), and the
mutants of both verifiers (every one must make a vector fail). Needs `python3` with `cryptography`, and the cancho
compiler at the revision in [`cancho.toml`](cancho.toml).

## Licence

Not chosen: it is an open question in the design. Until it is, no licence is granted.
