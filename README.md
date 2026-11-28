# cancho-db

A database that speaks PostgreSQL's protocol and whose every write is checkable: each transaction is a signed, hash-chained
commit that records who wrote, under which capability, and what the statements did, and independent verifiers re-check the
log, the authority and the rows. *The database you can let agents write to.* Working name. The design is
[`docs/design.md`](docs/design.md); what is claimed, what each claim rests on and what it does not show is
[`docs/claims.md`](docs/claims.md).

It comes in two forms that write the same log:

- **The engine** (M3): its own storage and SQL executor, served over PostgreSQL's wire protocol with no PostgreSQL anywhere.
  This is where the work is now.
- **The proxy** (M1, M2): a guard in front of a stock PostgreSQL, which still stores the data.

## Status

| Milestone | State |
|---|---|
| M0 Spec and verifier | **Built.** Four specs, 467 golden vectors, three verifiers (cancho, Python, Go) that agree on every one. |
| M1 The proxy | **Built.** psql and five drivers connect with a capability token as the password; every statement is checked before PostgreSQL sees it. |
| M2 Branches and replay | **Built.** Row-change capture, branches, `AS OF`, a checked merge, the replay verifier (L3a), erasure. |
| M3 The engine | **Mostly built and served.** What is not: the shadow run that moves an existing PostgreSQL database onto it, and merge on the engine. |
| M4 PostgreSQL removed | **Started, client by client.** One sibling project runs on the engine; a second is being measured. |

### The engine

A page file holding a copy-on-write B+tree and two superblocks, crash-tested at every durable step, with a provoked failing
`fsync` (the server refuses and ends; what it acknowledged is there after a restart). Its server speaks PostgreSQL's
protocol, simple and extended, to psql and to `cancho-pg`'s client:

- **The log is in the page file.** Every commit that changed rows is signed and chained with what it wrote, and the
  three verifiers read it through `logexport`, the export tool. A client logs in with a capability token, and the log
  records who wrote and which statements ran.
- **SQL**, each statement answered as PostgreSQL answers it (16 here, 18 in CI) or refused with a rule tag:
  - `create table`, `insert`, `update`, `delete`, `select` with joins, aggregates, `group by`, `having`, `order by`,
    `limit`, `distinct`, `case`, `cast`, `like`, `in`, a scalar subquery;
  - `returning`, `on conflict do nothing`, `truncate`, `alter table add column` and `rename`;
  - indexes, unique ones too, used by `select`, `update` and `delete`;
  - identity columns, `serial` and sequences;
  - `timestamp`, `timestamptz` and `now()`;
  - `check` constraints of any expression it computes, including `~`, `!~` and `length`;
  - references to another table's key, with `on delete cascade` and `set null`.
- **History**: `AS OF` a commit, a fork, and an erase that removes a row and every past version of it from the file,
  while the log still verifies.
- **Connections**: up to 128 at once. Clients from other machines are served through TLS (the server ends it itself)
  with a login. Reads go on beside a transaction. Transactions can run side by side at `serializable` or `repeatable
  read`, a loser is refused `40001`.
- **Operations**: a copy of the page file taken while the server runs, the log's oldest part archived out of the file, a
  soak of ten minutes under kills (52,292 commits through 18 kills, its invariants held throughout).

How it is held to that: a differential against PostgreSQL (random histories of 3,000 statements on several seeds, over a
thousand fixed statements, and a list of what is refused on purpose with PostgreSQL's answer beside it), the crash and
fault tests, and about 1,900 mutants. Each mutant is a deliberate fault that some test must catch.

**Its clients.** [`cancho-hooks`](https://github.com/alpibrusl/cancho-hooks) runs on it: its own history test passes 43
checks across its 11 scenarios. Seven statements that make PostgreSQL roles were cut from a copy of the test; nothing else
was changed. `cancho-ota` is being measured ([`docs/m3-engine.md`](docs/m3-engine.md) 6bx):

- its 49 migration statements: 45 run as written;
- its 134 queries: 55 run on that schema, which says a statement was answered, not yet that its answer is right.

Running its own test suite against the engine is the next measure.

**What the engine does not do yet:**
- subqueries in `from` or `exists`, CTEs, set operations, window functions;
- `on conflict do update`, a statement with `with` that writes;
- a reference of several columns, `on update` actions;
- merge;
- taking over a database PostgreSQL holds (the shadow run, M3j).

It is not a speed project: a commit's file writes cost about 0.6 ms on the test disk, its signature 3.8 ms.

### The proxy

psql, psycopg 2 and 3, pg8000, asyncpg and node-postgres connect with a capability token as the password. Every statement
is parsed, lowered to the statement IR and its effects checked against the token before PostgreSQL sees it; a refusal has a
rule tag and never reaches the database. Every transaction is one commit, made durable before PostgreSQL commits (a
two-phase commit, settled by recovery after a crash). Triggers capture every row change, so each commit carries its real
`changes` and `state`. Branches are `cancho_fork`, `AS OF` reads a table as a commit left it, `cancho_merge` is a three-way
merge by key (nothing if there is a conflict), and `cancho_erase` removes a person's rows, the capture's copies and the
statements that name them while the log still verifies. Loopback clients only, one commit at a time, the same SQL subset.

### The specs and the verifiers

- [`docs/spec/commit.md`](docs/spec/commit.md): the commit and log format and **L1 (integrity)**, needing only SHA-256 and Ed25519.
- [`docs/spec/token.md`](docs/spec/token.md): capability tokens (signed blocks that can only narrow) and **L2 (authority)**.
- [`docs/spec/ir.md`](docs/spec/ir.md): the **statement IR** and effect inference, so L2 checks that a commit's effects are what its statements do.
- [`docs/spec/state.md`](docs/spec/state.md) and [`docs/spec/l3a.md`](docs/spec/l3a.md): the facts a commit changed, and **L3a**, the replay of them against the tables.
- Three verifiers that must agree on every vector:
  - [`src/`](src) in cancho;
  - [`tools/verify.py`](tools/verify.py) in Python;
  - [`verifiers/go/`](verifiers/go) in Go, written from the specs alone by a separate agent session.

Not built: recording of the values a client binds (L3b), and snapshots.

## Run the engine

`sh scripts/check.sh checks` builds it as `build/engine`, with the export tool as `build/logexport` (the build lines are in
the script; the server needs the compiler's TLS package). Then:

```console
$ build/engine pages 5450 signing.key root.pub        # page file, port, the log's signing seed, the root that signs tokens (hex files)
listening
$ PGPASSWORD=$(python3 tools/mint.py password --effects 'r:*,w:*,d:*,c:*,n:*') psql -h 127.0.0.1 -p 5450 -U agent -d main
```

Trailing options: `tls=DIRECTORY` (a `chain.pem` and `key.pem`), `places=N` (connections at once). Without a root file
there is no login; without a signing key nothing is recorded. The rest are in [`proxy/engine.cho`](proxy/engine.cho).

The log, read out of the page file and verified:

```console
$ build/logexport pages log > log; build/logexport pages tokens > tokens; build/logexport pages stmts > stmts
$ python3 tools/verify.py log --root $(cat root.pub) --tokens tokens --stmts stmts
ok commits=5 branches=1 level=2+ir
```

`tools/mint.py` makes tokens for the test keys only: their keys are derived from fixed strings.

## Verify a log

```console
$ cancho build --std src/commit.cho src/verify.cho -o verify
$ ./verify vectors/ok_chain3.log
ok commits=3 branches=1
$ ./verify vectors/seq_skips.log
reject rule=seq-gap record=1
$ ./verify vectors/truncated_tail_pinned.log --expect eace04f4...671d   # the last id you were given
reject rule=expected-missing record=-1
```

The exit status is 0 for `ok`, 1 for `reject`, and 2 for a usage error or a file that cannot be read. `python3
tools/verify.py` takes the same arguments.

A log is *not* shown to be complete by verifying it. Pass `--expect` with the last commit id you were given, or a removed
tail goes unnoticed ([spec §5](docs/spec/commit.md)). L2 needs `--root` and `--tokens`. With `--stmts`, the recorded
effects are shown to be what the statements do: a server that hides a write passes without it and is refused with it
(`vectors/ir_gap_*`).

## The proxy, by hand

```console
$ proxy 5440 127.0.0.1 5432 main $ROOT postgres postgres ./log ./signing.key   # listen port, upstream, first branch, root key, role, database, log directory, signing key
$ PGPASSWORD=$(python3 tools/mint.py password) psql -h 127.0.0.1 -p 5440 -U agent -d main -c 'select 1'
$ PGPASSWORD=... psql -h 127.0.0.1 -p 5440 -U agent -d main -c "select cancho_fork('feature')"   # the database name is the branch
```

The upstream role must be allowed to create triggers and event triggers, and every table needs a primary key. The build
line is in `scripts/check.sh`. Its documents are [`docs/m1-proxy.md`](docs/m1-proxy.md),
[`docs/m1-commit-path.md`](docs/m1-commit-path.md) and [`docs/m2-branches.md`](docs/m2-branches.md).

## Test

```console
$ CANCHO=/path/to/cancho sh scripts/check.sh
```

This runs what CI runs:

- formatting, and the vectors regenerated byte for byte;
- the three verifiers on every vector, and fuzzed inputs that none may crash on;
- the differentials of the parser, the lowering, the evaluator and the engine against PostgreSQL;
- the crash, fault, wire, TLS, side-by-side and soak tests;
- the end-to-end tests of the proxy;
- every mutant.

It needs:
- `python3` with `cryptography`;
- the cancho compiler at the revision in [`cancho.toml`](cancho.toml), and its repository, for the TLS package;
- `go`, `strace` and `psql`;
- a PostgreSQL server (16 here; CI runs 18). The script starts a throwaway one.

`checks` runs everything but the mutants; `mutants-a` to `mutants-f` run a shard of them each. CI runs the seven at once.

## Landing page

`docs/index.html`, one self-contained page, served by GitHub Pages from branch `main`, folder `/docs`. Its counts (vectors,
mutants, claims) are written by `python3 scripts/site.py` and checked by `scripts/check.sh`. The replayed session in it is a
recording of a real run of the engine, trimmed; it is not generated.

## Licence

European Union Public Licence v. 1.2 (EUPL-1.2), [`LICENSE`](LICENSE), as the other cancho repositories. Copyright
Alpibru S.L. ([`NOTICE`](NOTICE)).
