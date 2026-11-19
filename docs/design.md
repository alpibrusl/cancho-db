# Cancho DB: design

> Source of truth for the design. Copied from the design doc "Cancho DB: design doc" (2026-11-15) and kept here so
> that a claim that turns out false is corrected **in place**, in the document that made it. Status of each milestone is
> in [Build status](#build-status).

Cancho DB (working name) is a Postgres-compatible database whose commit path is verifiable. Every write becomes a
signed, hash-chained commit recording who wrote, under which capability, and running which code. The pitch: the
database you can let agents write to.

- **Canonical form:** an append-only, content-addressed log. Tables, indexes, and SQL results are projections of it.
- **Edge:** the Postgres wire protocol, so existing drivers, ORMs, and BI tools connect unmodified.
- **Implementation:** cancho. Trust rests on a language-neutral spec and an independent verifier, not on the cancho
  compiler.
- **Build order:** proxy first. The commit path ships in front of stock Postgres before the storage engine exists, then
  the engine replaces Postgres behind the same protocol.

The design applies [Trust Without Comprehension](https://alpibru.com/manifesto) to data: verification over
comprehension, content-addressed units, attested chains, and readable views as projections.

## Goals and non-goals

**Goals**

1. Unmodified Postgres clients on a named list work against it.
2. Every commit can be verified offline, from the log alone, by code that shares nothing with the engine.
3. Authority is scoped per agent with attenuable tokens. The effects of every statement are inferred and checked before
   execution.
4. Each agent works on its own branch, and merge is a checked operation.
5. By the last milestone the whole stack is cancho, with no Postgres underneath.

**Non-goals for v1**

- Replication, consensus, or any distributed deployment.
- Multi-writer concurrency control. One writer per branch, serializable.
- PL/pgSQL, Postgres extensions, LISTEN/NOTIFY, logical replication.
- A cost-based optimiser or analytical performance.
- The full Postgres dialect. The subset grows only when a client on the list needs it.

## Architecture

A statement passes six layers, and the capability check sits before the executor so an out-of-scope statement never
runs.

```
client ── 1 protocol ── 2 parser/IR ── 3 effect check ── 4 executor ── 5 commit builder ── 6 storage
                                            │                              │
                                       token (L2)                     commit log ──► verifier
```

The protocol, parser, effect check, and commit builder are the same code in every milestone. Only the storage layer
changes: Postgres at first, the cancho engine later. The verifier shares no code with the server and needs only the log.

## Commit format

Everything that can change state sits under the commit hash: statements, schema, token, and every nondeterministic
value. Nothing mutable lives outside the chain.

```
Commit {
  version:     u16
  parents:     [Hash]         // one normally, two for a merge
  branch:      BranchId
  seq:         u64            // per branch, gapless
  schema:      Hash           // schema version the commit is valid against
  statements:  [Hash]         // IR hashes, in execution order
  effects:     EffectSet      // inferred: read[..], write[..], ddl[..], call[..]
  token:       Hash           // capability token presented
  principal:   PublicKey      // agent or user identity
  code:        [Hash]         // stored cancho functions invoked
  nondet:      [Value]        // recorded now(), random(), sequence values
  changes:     Hash           // Merkle root of the fact delta
  state:       Hash           // Merkle root of the branch after apply
  checks:      [CheckResult]  // constraints and contracts evaluated
  time:        Timestamp      // server clock, informational only
}

id        = H(canonical_encoding(Commit))
signature = Sign(server_key, id)     // optional client co-signature
```

**Rules**

- **Encoding:** one fixed binary encoding with exactly one byte representation per value. Not JSON.
- **Primitives:** SHA-256 and Ed25519 as the starting proposal, chosen so a verifier is easy to write in any language.
- **Facts:** a fact is a row version keyed by table and primary key, either asserted or retracted. UPDATE retracts and
  asserts; DELETE retracts.
- **Payloads:** the chain holds hashes of values. The values are stored beside it, which is what makes erasure possible
  later.
- **Only committed transactions enter the log.** Rolled-back work and savepoints leave no trace.

**Verification levels**

| Level | What the verifier checks | Cost |
|---|---|---|
| L1 Integrity | Chain linkage, gapless sequence, signatures | Linear scan, no data needed |
| L2 Authority | Token is valid and unrevoked; inferred effects are within its grants | Needs tokens and statement IR |
| L3 Replay | Re-executing statements with the recorded `nondet` reproduces `changes` and `state` | Needs full data and an executor |

The byte-level definition of the format is [`spec/commit.md`](spec/commit.md); tokens and L2 are
[`spec/token.md`](spec/token.md).

## Query path

A statement is rejected before execution if its effects exceed the token. The path for every statement:

1. Parse SQL to an AST. Native clients may send IR directly.
2. Lower to the typed IR and hash it. The hash is the statement's identity in the commit.
3. Infer the effect set: `read[table.cols]`, `write[table]`, `ddl`, `nondet`, `call[fn]`.
4. Check that the effects are within the token's grants on this branch.
5. Execute, then evaluate constraints and contracts.
6. Build, sign, and append the commit. Update projections.

**Effect inference**

- Bind parameters cannot change which tables a statement touches, so inference runs once per prepared statement.
- Stored functions are cancho. Their effects are declared in the signature and checked by the compiler, so `call[fn]`
  expands to a known set.
- Granularity in v1: tables for writes, columns for reads. Row-level predicates come later.

**Capability tokens**

- Biscuit-style: signed, and attenuable offline. A holder can narrow a token for a sub-agent but never widen it.
- A grant names a branch, an effect set, and an expiry.
- The token travels as the Postgres password, so no client changes.
- The token hash goes into the commit. Revocation is a list of token ids checked at L2.

## Postgres compatibility

Compatibility is defined by a client list that must pass unmodified, not by dialect coverage. The proposed list:

| Client | What it exercises |
|---|---|
| psql | Simple query protocol, catalog queries behind `\d` |
| One driver per language (libpq, pgx, node-postgres, psycopg, JDBC) | Extended protocol, prepared statements, type OIDs, binary formats |
| SQLAlchemy | Introspection, transactions, savepoints |
| Prisma | Schema introspection and migration DDL |
| Metabase | `information_schema` and JDBC metadata |

**Layers of compatibility**

- **Wire protocol v3:** in scope, and cheap.
- **SQL subset compiled to IR:** in scope, grown on demand.
- **`pg_catalog` and `information_schema` emulation:** in scope, and the long tail of the work.
- **Extensions and PL/pgSQL:** out of scope permanently.

**Ledger features through knobs clients already have**

| Feature | How a client reaches it |
|---|---|
| Branch | Database name in the connection string |
| Capability token | Password |
| History | `AS OF <commit>` on a query |
| Last commit id | `SELECT cancho_last_commit()` |
| Merge | `SELECT cancho_merge('<branch>')` |

## Where the models clash

An append-only ledger and Postgres semantics disagree in six places, and erasure is the one that must be designed before
any data is stored.

| Issue | Postgres behaviour | Cancho DB decision |
|---|---|---|
| Erasure (GDPR) | DELETE plus VACUUM removes data | Value payloads are encrypted per subject and stored outside the chain. Erasure destroys the key; hashes stay and the chain still verifies at L1 and L2. |
| DDL | Arbitrary `ALTER TABLE` | DDL becomes a typed migration commit. A migration that cannot be expressed as a total function over existing rows is rejected. |
| Nondeterminism | `now()`, `random()`, sequences evaluated freely | Values are recorded in `nondet` so replay is exact. |
| Isolation | MVCC, several levels | Single writer per branch, serializable. Concurrency comes from branches, not from interleaving. |
| Rollback and savepoints | Supported | Supported in the session; only the committed result reaches the log. |
| Storage growth | Old versions vacuumed | History is kept. Periodic signed snapshots let old segments move to cold storage without breaking verification. |

## Verification strategy

Every trust claim the project makes must map to a test that fails when the claim is false. Four mechanisms carry that:

- **Spec before code.** The commit format and token rules are written as a language-neutral spec with golden test
  vectors, including tampered chains that must be rejected.
- **Two verifiers.** One in cancho, one in Rust or TypeScript, the second written from the spec alone by a session with
  no access to the engine source. Disagreement between them is a spec bug.
- **Postgres as the oracle.** The same statements run against real Postgres and against the engine, and results are
  diffed. Sources: the sqllogictest corpus and a subset of the Postgres regression suite. A SQL feature is switched on
  only when its tests pass.
- **Property and fault tests.** Replaying a log reproduces the state root. An attenuated token never grants more than
  its parent. Killing the process mid-commit never yields a chain that verifies with missing data.

A claims table in the repository lists each security statement in the README next to the test that enforces it. A claim
with no test is removed from the README. ([`claims.md`](claims.md))

## Milestones

Five milestones, each gated by a test rather than a date. M1 is the demand test: if nobody wants the proxy, stop before
building an engine.

| Milestone | Delivers | Exit criteria |
|---|---|---|
| M0 Spec and verifier | Commit and token spec, golden vectors, two standalone verifiers | Both verifiers agree on every vector and reject every tampered chain |
| M1 Proxy | Cancho proxy in front of stock Postgres: wire protocol, SQL parser, effect inference, tokens, attested log | Client list passes unmodified. Log verifies at L1 and L2. A statement outside a narrowed token is rejected before reaching Postgres. |
| M2 Branches and replay | Branch per connection, `AS OF`, checked merge, row deltas captured for `changes` and `state` | Two agents on separate branches merge, with a conflict detected. L3 replay reproduces the state root. |
| M3 Engine | Cancho storage (single writer, WAL, B-tree or LSM) and executor for the SQL subset, behind per-feature flags | Differential suite passes on the declared subset. Crash and fsync-fault tests pass. |
| M4 Postgres removed | Catalog emulation for the client list, erasure, snapshots | Client list passes with no Postgres in the stack. One cancho product runs on it in daily use. |

No durations are given. They depend on what the cancho compiler and standard library support today, which is the first
open question below.

## Risks and open questions

The largest risk is losing data, and the mitigation is staying on Postgres storage until the crash tests pass.

| Risk | Mitigation |
|---|---|
| Durability bugs in a new engine | Postgres holds the data through M2. The engine takes over feature by feature, only behind passing fault tests. |
| Cancho compiler immaturity | M0 and M1 are network, parsing, and hashing code. Trust rests on the spec and the second verifier, not the compiler. |
| Catalog emulation long tail | Scope fixed by the client list. A client is added only with a reason. |
| Demand unproven | M1 is usable alone and cheap to try. Treat its uptake as the go or no-go for M3. |
| Scope creep toward full Postgres | Non-goals are permanent unless a listed client needs the feature. |
| Prior art overlap (Dolt, Datomic, XTDB, immudb, TerminusDB) | Position on the combination none of them has: effect-checked statements plus attested commits behind the Postgres protocol. |

**Open questions**

- [x] Does cancho already have sockets, TLS, fsync, SHA-256, and Ed25519, or do M0 and M1 start by building them?
  **Answered 2026-11-15, by reading the tree at `0da6d1c`:** SHA-256 and SHA-512 (`std/crypto.cho`), Ed25519
  (`std/ed25519.cho`, `sign` and `verify`), TLS (`packages/tls`), sockets (`packages/net-sockets`) and a Postgres wire
  client (`cancho-pg`, including SCRAM) exist. M0 needs none of them built. *fsync was not checked*; it matters at M3,
  not before.
- [ ] Final name.
- [ ] Hash and signature primitives: confirm SHA-256 and Ed25519, or pick BLAKE3 for speed. (M0 is built on SHA-256 and
  Ed25519, the starting proposal; the spec carries a `version` so a change is a new version, not a rewrite.)
- [ ] Are read-only statements logged as signed receipts, or only writes?
- [ ] Fact granularity: row versions as proposed, or attribute-level facts.
- [ ] Merge semantics: three-way by primary key with constraint re-check is the proposal; what is the conflict policy?
- [ ] Row-level capabilities in v1 or later.
- [ ] Which product goes on it first: cancho-sheets or cancho-forge.
- [x] Licence. **Decided 2026-11-15: EUPL-1.2**, as the other cancho repositories (`LICENSE`).

## Build status

| Milestone | Status |
|---|---|
| M0 Spec and verifier | **L1, L2 and the statement IR built**: three specs (the IR in two versions), 428 vectors, three verifiers ([`README.md`](../README.md)). With the statement store L2 checks that the recorded effect set is what the statements infer; without it, only against the token. Not built: SQL lowering, `call` expansion, subqueries. Three verifiers agree on every vector, the third (Go) written from the specs alone by a separate agent session, so the exit criterion is met for L1, L2 and the IR with the caveats in [`claims.md`](claims.md). |
| M1 | **Built** (P0 to P3, the extended protocol included; [`m1-extended.md`](m1-extended.md); [`m1-proxy.md`](m1-proxy.md), [`m1-lowering.md`](m1-lowering.md), [`m1-commit-path.md`](m1-commit-path.md)): the proxy in front of PostgreSQL logs in with a capability token, checks every statement (lexer, parser, lowering to the IR, inferred effects) against it before PostgreSQL sees it, and logs every transaction as a signed, hash-chained commit (two-phase for writes, recovered after a crash, `now()` recorded) that the three verifiers accept at L1, L2 and the IR. A statement outside a narrowed token is refused. **Criterion not met: the client list.** Only `psql` and psycopg2 (simple protocol) work; the other drivers need the extended protocol: [`m1-extended.md`](m1-extended.md) (designed, not built). Cost, measured: about 6 ms a statement through the proxy against 0.06 direct, mostly the Ed25519 signature (`m1-commit-path.md` section 5.11). |
| M2 | **Designed; M2a, M2b-1, M2b-2a, M2b-2b, M2c-1, M2c-2 and M2d built** (the facts spec and code; the capture SQL; the proxy installs the capture, refuses a table it cannot track, and puts real `changes` and `state` in every commit; branches, `AS OF`, merge and L3 replay are not built; M2c, branches, is designed in `m2-branches.md` section 10 and built, sections 11 and 12: the branch table, and `select cancho_fork('<name>')`; `AS OF` is built, sections 13 and 14) (the facts, `changes` and `state` spec and code, [`spec/state.md`](spec/state.md)) ([`m2-branches.md`](m2-branches.md)): branches as schemas, row deltas by triggers, `AS OF` from the deltas, checked merge, L3a delta replay; fork, capture and `AS OF` cost measured (2.5 s per million rows to fork by copy; +6 microseconds per single-row statement and 11 times on a bulk update to capture; 550 ms to rebuild 100,000 rows from 70,000 deltas). Four questions for the owner (state root, conflict policy, recording values, fork by copy). |
| M3 to M4 | Not started. |
