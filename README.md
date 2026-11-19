# cancho-db

A Postgres-compatible database whose commit path is verifiable: every write becomes a signed, hash-chained commit that
records who wrote, under which capability, and running which code. *The database you can let agents write to.*
Working name. The design is [`docs/design.md`](docs/design.md).

## Status

**M0 (spec and verifier): built.**

- [`docs/spec/commit.md`](docs/spec/commit.md): the byte-level commit and log format and **L1 (integrity)**
  verification, written so a verifier needs only SHA-256 and Ed25519.
- [`docs/spec/token.md`](docs/spec/token.md): capability tokens (a chain of signed blocks that can only narrow) and
  **L2 (authority)**: was each commit allowed by the token it presented?
- [`docs/spec/ir.md`](docs/spec/ir.md): the **statement IR** (the bound form of a SQL subset) and effect inference,
  so that L2 can check that a commit's recorded effects are *what its statements do*, not only what the server says.
- [`docs/spec/state.md`](docs/spec/state.md): the facts a commit changed, `changes` (a Merkle root over them) and `state` (a chain of changes).
- [`vectors/`](vectors): 436 golden vectors, valid chains and one tampered, malformed or denied case for each rule.
- Three verifiers that must agree on every one: [`src/`](src) in cancho (no C, no foreign call),
  [`tools/verify.py`](tools/verify.py) in Python, and [`verifiers/go/`](verifiers/go) in Go, written from the specs alone
  by a separate agent session (see its README and [`docs/claims.md`](docs/claims.md) for what that does and does not show).

**M1 (the proxy in front of PostgreSQL): built** ([`docs/m1-proxy.md`](docs/m1-proxy.md), [`docs/m1-commit-path.md`](docs/m1-commit-path.md)).
psql, psycopg 2 and 3, pg8000, asyncpg and node-postgres connect with a capability token as the password. Every statement is parsed,
lowered to the IR and its effects checked against the token before PostgreSQL sees it; a refusal has a rule tag and never reaches the database. Every
transaction is one signed, hash-chained commit, made durable before PostgreSQL commits (a two-phase commit, settled by recovery after a crash). Simple and extended protocol; only loopback clients are served.
The SQL is a subset (no subqueries, CTEs, set operations or window functions; a closed set of DDL): [`docs/claims.md`](docs/claims.md) lists what is refused.

**M2 (row changes, branches, `AS OF`, merge, the replay verifier L3a): built** ([`docs/m2-branches.md`](docs/m2-branches.md)).
Built: **row-delta capture** (triggers installed by the proxy; every commit carries the real `changes` and `state`), and **branches**:
`select cancho_fork('name')` copies the data into a schema of its own and starts a new chain in the log; a connection chooses its branch by the database name.
**`AS OF`**: `select ... from t as of '<commit id>'` reads a table as a commit left it (on any branch; the commit is named in the statement, so the log records which past was read, and a token must grant it).
**`cancho_merge`**: `select cancho_merge('<source>')` merges a branch into the connection's branch (a three-way merge by key against the common ancestor read `AS OF`): one commit with two parents, or nothing if there is a conflict.
**L3a (delta replay)** ([`docs/spec/l3a.md`](docs/spec/l3a.md)): given the delta store the database keeps, a verifier checks that each commit's `changes` and `state` are what the stored row changes give, that the changes fit together, and (given a dump of the tables) that the tables hold exactly what they say; in cancho (`proxy/l3averify.cho`), in Python (`tools/l3a.py`) and as a third reading by a separate agent session (`tests/third/`), on 72 golden cases.
Not built: recording of bound values (L3b), snapshots and erasure. Without `--stmts`, L2
checks only the commit's *recorded* effect set against its token; with it, the recorded set is shown to equal what the
statements infer. That the store holds what was actually executed is L3's (see [`docs/claims.md`](docs/claims.md)), which says what is claimed, what each claim rests on, and what is *not*
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

## The proxy

```console
$ cancho build --std proxy/proxy.cho src/commit.cho src/token.cho src/login.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/ir.cho src/guard.cho src/snapshot.cho src/build.cho src/store.cho src/l1.cho src/upstream.cho src/shared.cho src/commitpath.cho src/catalog.cho src/extended.cho src/capture_sql.cho src/state.cho src/fork.cho src/forkpath.cho src/asof.cho -o proxy
$ proxy 5440 127.0.0.1 5432 main $ROOT postgres postgres ./log ./signing.key   # listen port, upstream host and port, first branch, root key, upstream role, database, log directory, signing key (32 bytes)
$ PGPASSWORD=$(python3 tools/mint.py password) psql -h 127.0.0.1 -p 5440 -U agent -d main -c 'select 1'
$ PGPASSWORD=... psql -h 127.0.0.1 -p 5440 -U agent -d main -c "select cancho_fork('feature')"
$ PGPASSWORD=... psql -h 127.0.0.1 -p 5440 -U agent -d feature      # the database name is the branch
```

The password is `base64url(token ‖ the last key's seed)`; `tools/mint.py` makes one for the test keys. The upstream role must be allowed to create triggers and event
triggers (the row-change capture is installed at start), and every table needs a primary key. The log directory holds the log, the tokens and the statements, which the verifiers read:
`build/verify log --root $ROOT --tokens ./log/tokens --stmts ./log/stmts`. The gates are `tests/proxy_e2e.py`, `tests/ext_e2e.py`, `tests/drivers_e2e.py`, `tests/changes_e2e.py` and
`tests/fork_e2e.py`, `tests/asof_e2e.py` and `tests/merge_e2e.py`, against a real PostgreSQL and the stock clients.

## Test

```console
$ CANCHO=/path/to/cancho sh scripts/check.sh
```

Runs what CI runs: formatting, vectors regenerate byte for byte, all three verifiers on every vector, the command lines,
the authority report, the attenuation property over thousands of random tokens, 4,500 differentially fuzzed inputs (the
verifiers agree and none crashes), the parser, lowering and row-capture differentials against PostgreSQL, the proxy and fork end to end, and about 700 mutants (every one must make a check fail; the proxy
ones take about an hour). Needs `python3` with `cryptography`, the cancho compiler at the revision in [`cancho.toml`](cancho.toml), `go`, `strace`, `psql` and a PostgreSQL 16 server (the script starts a throwaway one).

## Landing page

`site/index.html`, published by `.github/workflows/pages.yml` on a push to `main` (Settings > Pages > Source must be "GitHub Actions").

## Licence

European Union Public Licence v. 1.2 (EUPL-1.2), [`LICENSE`](LICENSE), as the other cancho repositories. Copyright
Alpibru S.L. ([`NOTICE`](NOTICE)).
