#!/bin/sh
# Everything CI runs, locally. CANCHO is the compiler (default: `cancho` on PATH); needs python3 with `cryptography`.
set -eu
cd "$(dirname "$0")/.."
CANCHO=${CANCHO:-cancho}
export CANCHO
mkdir -p build

# run a command, keep ITS exit status (a pipe into tail would hide it in sh), and show its last N lines; on failure show all.
quiet() {
    n=$1
    shift
    if out=$("$@" 2>&1); then
        printf '%s\n' "$out" | tail -n "$n"
    else
        printf '%s\n' "$out"
        echo "FAILED: $*" >&2
        exit 1
    fi
}

echo "== formatting";                "$CANCHO" fmt --check src
echo "== vectors are reproducible";  rm -rf build/vectors && python3 tools/gen_vectors.py build/vectors >/dev/null && diff -r vectors build/vectors
echo "== the landing page (docs/index.html, served by Pages from branch main, folder /docs): its counts are current"; python3 scripts/site.py --check
echo "== the capture SQL module is reproducible"; python3 tools/gen_capture.py --check
echo "== login cases are reproducible"; python3 tools/gen_login.py --check
echo "== login tests (the proxy's front door, from bytes)"; quiet 2 "$CANCHO" test tests/login_test.cho tests/login_cases.cho src/commit.cho src/token.cho src/login.cho --std
echo "== lexer cases are reproducible"; python3 tools/gen_lex.py --check
echo "== lexer tests (from bytes)"; quiet 2 "$CANCHO" test tests/lex_test.cho tests/lex_cases.cho src/lex.cho --std
echo "== parser cases are reproducible"; python3 tools/gen_parse.py --check
echo "== parser tests (from bytes)"; quiet 2 "$CANCHO" test tests/parse_test.cho tests/parse_cases.cho src/lex.cho src/parse.cho --std
echo "== statement cases are reproducible"; python3 tools/gen_stmt.py --check
echo "== statement tests (from bytes)"; quiet 2 "$CANCHO" test tests/stmt_test.cho tests/stmt_cases.cho src/lex.cho src/parse.cho src/stmt.cho --std
echo "== build";                     "$CANCHO" build --std src/*.cho -o build/verify
echo "== go verifier";               (cd verifiers/go && gofmt -l . | (! grep .) && go vet ./... && go build -o ../../build/verify-go .)
export FUZZ_EXTRA="build/verify-go"
echo "== authority";                 sh tests/authority.sh
echo "== vectors, python verifier";  python3 tests/run_vectors.py vectors -- python3 tools/verify.py
echo "== vectors, cancho verifier";  python3 tests/run_vectors.py vectors -- build/verify
echo "== vectors, go verifier";      python3 tests/run_vectors.py vectors -- build/verify-go
echo "== the proxy builds";          "$CANCHO" build --std proxy/proxy.cho src/commit.cho src/token.cho src/login.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/ir.cho src/guard.cho src/snapshot.cho src/build.cho src/store.cho src/l1.cho src/upstream.cho src/shared.cho src/commitpath.cho src/catalog.cho src/extended.cho src/capture_sql.cho src/state.cho src/fork.cho src/forkpath.cho src/erase.cho src/asof.cho -o build/proxy
echo "== the proxy end to end (psql, a real PostgreSQL)"
sh scripts/pg_throwaway.sh start 5593
trap 'sh scripts/pg_throwaway.sh stop 5593' EXIT
export PG_E2E_PORT=5593
E2E_VERIFIERS="build/verify build/verify-go" quiet 3 python3 tests/proxy_e2e.py build/proxy
echo "== cancho_erase through the proxy: the token checks, the erase commit, the erased record, a log that verifies"
E2E_VERIFIERS="build/verify build/verify-go" quiet 3 python3 tests/erase_e2e.py build/proxy
echo "== the capture install at start retries a deadlock (a CI run died on one)"
quiet 3 python3 tests/install_retry_e2e.py build/proxy
echo "== cancho_erase on a branch, and the extended protocol's refusal"
E2E_VERIFIERS="build/verify build/verify-go" quiet 3 python3 tests/erase_branch_e2e.py build/proxy
echo "== the engine's rows against PostgreSQL (docs/m3-engine.md, M3c): the image is to_jsonb's, the plain key jsonb_build_array's, the stored keys in key order"
"$CANCHO" build --std proxy/rowcheck.cho src/row.cho src/state.cho src/commit.cho src/build.cho -o build/rowcheck
quiet 2 python3 tests/row_check.py build/rowcheck
echo "== the engine's expression evaluator against PostgreSQL (docs/m3-engine.md, M3d): it may refuse; when it answers, the type, every row's value or the SQLSTATE are PostgreSQL's"
"$CANCHO" build --std proxy/evalcheck.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/state.cho src/commit.cho src/build.cho src/row.cho src/eval.cho -o build/evalcheck
quiet 4 python3 tests/eval_check.py build/evalcheck 4000 1
quiet 4 python3 tests/eval_check.py build/evalcheck 4000 2
echo "== the engine's statements against PostgreSQL (docs/m3-engine.md 6g, 6h): create, insert, update, delete, select; the changes; what must be answered, what must be refused, what must be gone from the file"
"$CANCHO" build --std proxy/enginecheck.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/state.cho src/commit.cho src/build.cho src/row.cho src/eval.cho src/pager.cho src/btree.cho src/pstore.cho src/tables.cho src/exec.cho src/execs.cho src/execw.cho src/answer.cho src/drive.cho src/facts.cho src/session.cho -o build/enginecheck
quiet 4 python3 tests/engine_check.py build/enginecheck 3000 1
quiet 4 python3 tests/engine_check.py build/enginecheck 3000 2
quiet 4 python3 tests/engine_check.py build/enginecheck 3000 3
echo "== the first user's schema and queries on the engine (docs/m3-engine.md 6w): how many of cancho-hooks' statements are answered, and none differently from PostgreSQL"
quiet 20 python3 tests/hooks_check.py build/enginecheck
echo "== the engine's statements across a crash at every durable step (gate 2 at the level of SQL): the tables after a restart are those of a commit, and the file takes writes again"
quiet 3 python3 tests/engine_crash.py build/enginecheck
echo "== statements larger than the pager's cache: 30,000 rows rewritten five times, read back as a model says"
quiet 2 python3 tests/engine_big.py build/enginecheck
echo "== the statement store of a real session is version 3, and erasing one subject's constants leaves a log that verifies"
E2E_VERIFIERS="build/verify build/verify-go" quiet 3 python3 tests/stmts_v3_e2e.py build/proxy
echo "== the extended protocol through the proxy (raw messages, a real PostgreSQL)"
E2E_VERIFIERS="build/verify" quiet 3 python3 tests/ext_e2e.py build/proxy
echo "== real drivers through the proxy (psycopg 3, psycopg2, pg8000, asyncpg, node-postgres)"
sh scripts/drivers_setup.sh
E2E_VERIFIERS="build/verify" quiet 3 python3 tests/drivers_e2e.py build/proxy
echo "== row-delta capture (sql/capture.sql) against a snapshot diff, in a real PostgreSQL"
quiet 3 python3 tests/capture_check.py
echo "== changes and state in the commits (M2b-2b): recomputed from the database's delta rows, the chain, the bound, a restart"
E2E_VERIFIERS="build/verify build/verify-go" quiet 3 python3 tests/changes_e2e.py build/proxy
echo "== cdb.merge (M2e-1): 60 random trials and the pinned scenarios against a reference of the three-way merge"
quiet 3 python3 tests/merge_check.py
echo "== cancho_merge (M2e-2): the two-parent commit, the base, refusals, the race, the crash windows"
E2E_VERIFIERS="build/verify build/verify-go" quiet 3 python3 tests/merge_e2e.py build/proxy
echo "== the fork (M2c-2): the schema per branch, the commit on the new branch, refusals, the race, the crash windows"
E2E_VERIFIERS="build/verify build/verify-go" quiet 3 python3 tests/fork_e2e.py build/proxy
echo "== AS OF (M2d): every commit of a random session read back against a copy made then, on two branches"
E2E_VERIFIERS="build/verify build/verify-go" quiet 3 python3 tests/asof_e2e.py build/proxy
echo "== L3a, delta replay (M2f-1): the golden cases are reproducible, and the verifier agrees with them"
python3 tools/gen_l3a.py --check
quiet 2 python3 tests/l3a_check.py "python3 tools/l3a.py"
echo "== L3a verifier in cancho"; "$CANCHO" build --std proxy/l3averify.cho src/l3a.cho src/commit.cho src/build.cho src/state.cho -o build/l3averify
quiet 2 python3 tests/l3a_check.py build/l3averify
echo "== L3a, the third reading"; quiet 2 python3 tests/l3a_check.py "python3 tests/third/l3a_third.py"
quiet 2 python3 tests/l3a_fuzz.py "python3 tests/third/l3a_third.py" build/l3averify 300 7
quiet 2 python3 tests/l3a_fuzz.py "python3 tools/l3a.py" build/l3averify 500 1
quiet 3 python3 tests/l3a_scale.py "python3 tools/l3a.py" build/l3averify 300
echo "== L3a over a real session: the live tables compared, and the ways to cheat refused"
quiet 3 python3 tests/l3a_e2e.py build/proxy "python3 tools/l3a.py" build/l3averify
echo "== L3a over a session in which a subject is erased through the proxy (docs/m2g-erasure.md E5)"
quiet 3 python3 tests/erase_l3a_e2e.py build/proxy "python3 tools/l3a.py" build/l3averify
echo "== a log the engine made, read by the three L3a verifiers (docs/m3-engine.md 6ah): 3 seeds of 2,000 statements over two processes, and what must not pass"
for seed in 1 2 3; do quiet 2 python3 tests/engine_log.py build/enginecheck 2000 $seed "python3 tools/l3a.py" build/l3averify "python3 tests/third/l3a_third.py"; done
echo "== the engine's server (docs/m3-engine.md 6al): PostgreSQL's protocol over a socket, held against the test program; kill, dropped connections, garbage, psql"
"$CANCHO" build --std proxy/engine.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/state.cho src/commit.cho src/build.cho src/row.cho src/eval.cho src/pager.cho src/btree.cho src/pstore.cho src/tables.cho src/exec.cho src/execs.cho src/execw.cho src/answer.cho src/drive.cho src/facts.cho src/session.cho src/wire.cho src/serve.cho src/login.cho src/token.cho -o build/engine
for seed in 1 2 3; do quiet 2 python3 tests/engine_wire.py build/engine build/enginecheck 1500 $seed; done
echo "== cancho-hooks, the program, on the engine's server (docs/m3-engine.md 6an): skipped unless HOOKS_BIN names a hooks binary"
quiet 2 python3 tests/hooks_server.py build/engine
echo "== the commit path's cost: a smoke run of the measurement (it must run; the numbers are in docs/m1-commit-path.md section 5.11)"
PG_PORT=5593 N=40 quiet 2 python3 scripts/measure_p2e.py build/proxy
echo "== the lexer against PostgreSQL (statement counts, operator tokens)"
"$CANCHO" build --std proxy/lexcheck.cho src/lex.cho -o build/lexcheck
quiet 4 python3 tests/lex_diff.py build/lexcheck 4000 1
echo "== the expression parser against PostgreSQL (the plan of the original and of the rendering)"
"$CANCHO" build --std proxy/exprcheck.cho src/lex.cho src/parse.cho -o build/exprcheck
quiet 2 python3 tests/parse_diff.py build/exprcheck 4000 1
quiet 2 python3 tests/parse_diff.py build/exprcheck 4000 2
echo "== the SELECT parser against PostgreSQL (the plan of the original and of the rendering)"
"$CANCHO" build --std proxy/stmtcheck.cho src/lex.cho src/parse.cho src/stmt.cho -o build/stmtcheck
quiet 2 python3 tests/stmt_diff.py build/stmtcheck 4000 1
quiet 2 python3 tests/stmt_diff.py build/stmtcheck 4000 2
echo "== the DDL parser against PostgreSQL (what the original and the rendering leave in the catalog)"
quiet 2 python3 tests/ddl_diff.py build/stmtcheck 3000 1
echo "== the lowering: hand-written IR bytes, effects through the verifier, refusals"
"$CANCHO" build --std proxy/lowercheck.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho -o build/lowercheck
quiet 2 python3 tests/lower_check.py build/lowercheck build/verify
echo "== name resolution in the lowering against PostgreSQL (42P01, 42703, 42702)"
quiet 2 python3 tests/lower_diff.py build/lowercheck 4000 1
quiet 2 python3 tests/lower_diff.py build/lowercheck 4000 2
echo "== the query guard: hand-written verdicts over tokens minted outside src/"
"$CANCHO" build --std proxy/guardcheck.cho src/commit.cho src/token.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/ir.cho src/guard.cho src/build.cho src/asof.cho -o build/guardcheck
quiet 2 python3 tests/guard_check.py build/guardcheck
echo "== the commit builder: bytes, ids and signatures against an independent encoder; the three verifiers accept its log"
"$CANCHO" build --std proxy/buildcheck.cho src/build.cho src/commit.cho -o build/buildcheck
quiet 2 python3 tests/build_check.py build/buildcheck build/verify build/verify-go
echo "== lifting constants out of statements (ir.md section 8): ir.lift against the Python verifier"
"$CANCHO" build --std proxy/liftcheck.cho src/lex.cho src/state.cho src/ir.cho src/build.cho src/commit.cho -o build/liftcheck
quiet 2 python3 tests/lift_check.py build/liftcheck
echo "== facts, changes and state (docs/spec/state.md): the cancho implementation against tools/state.py, the golden cases and values worked by hand"
"$CANCHO" build --std proxy/statecheck.cho src/state.cho src/build.cho src/commit.cho -o build/statecheck
quiet 2 python3 tests/state_check.py build/statecheck
echo "== the log directory: restart, torn tails at every byte, the lock, the order of durable writes (strace)"
"$CANCHO" build --std proxy/storecheck.cho src/store.cho src/build.cho src/commit.cho src/l1.cho src/ir.cho -o build/storecheck
quiet 2 python3 tests/store_check.py build/storecheck build/verify build/verify-go
echo "== the statement store rewrite (docs/m2g-erasure.md 6d): the cancho code against tools/erase_stmts.py, and the crash points"
"$CANCHO" build --std proxy/erasecheck.cho src/store.cho src/build.cho src/commit.cho src/l1.cho src/ir.cho -o build/erasecheck
quiet 2 python3 tests/erase_store_check.py build/erasecheck
echo "== the engine's page file and B+tree (docs/m3-engine.md, M3a): against a model, a bit flipped in every page; a crash at every durable step with torn writes; the order of the calls"
"$CANCHO" build --std proxy/btcheck.cho src/btree.cho src/pager.cho src/pstore.cho src/commit.cho src/build.cho -o build/btcheck
quiet 2 python3 tests/btree_check.py build/btcheck
quiet 2 python3 tests/pstore_check.py build/btcheck
echo "== command lines";             python3 tests/cli_test.py vectors build/verify
echo "== attenuation property";       python3 tests/properties.py 4000 1
echo "== fuzz (three verifiers, no crash)"; python3 tests/fuzz.py vectors build/verify 3000 1
echo "== mutants, python";           quiet 1 python3 tests/mutants.py py
echo "== mutants, cancho";           quiet 1 python3 tests/mutants.py cho "$CANCHO"
echo "== mutants, login";            quiet 1 python3 tests/mutants.py login "$CANCHO"
echo "== mutants, lexer";            quiet 1 python3 tests/mutants.py lex "$CANCHO"
echo "== mutants, parser";          quiet 1 python3 tests/mutants.py parse "$CANCHO"
echo "== mutants, statements";      quiet 1 python3 tests/mutants.py stmt "$CANCHO"
echo "== mutants, lowering";        quiet 1 python3 tests/mutants.py lower "$CANCHO"
echo "== mutants, facts and state"; quiet 1 python3 tests/mutants.py state "$CANCHO"
echo "== mutants, guard";           quiet 1 python3 tests/mutants.py guard "$CANCHO"
echo "== mutants, commit builder"; quiet 1 python3 tests/mutants.py build "$CANCHO"
echo "== mutants, log directory"; quiet 1 python3 tests/mutants.py store "$CANCHO"
echo "== mutants, B+tree, pages and superblocks"; quiet 1 python3 tests/mutants.py btree "$CANCHO"
echo "== mutants, the engine's rows"; quiet 1 python3 tests/mutants.py row "$CANCHO"
echo "== mutants, the engine's expression evaluator"; quiet 1 python3 tests/mutants.py eval "$CANCHO"
echo "== mutants, the engine's statements"; quiet 1 python3 tests/mutants.py engine "$CANCHO"
echo "== mutants, the engine's server"; quiet 1 python3 tests/mutants.py wire "$CANCHO"
echo "== mutants, capture SQL and cdb.fork"; quiet 1 python3 tests/mutants.py sql "$CANCHO"
echo "== mutants, L3a verifier"; quiet 1 python3 tests/mutants.py l3a "$CANCHO"
echo "== mutants, L3a verifier in cancho"; quiet 1 python3 tests/mutants.py l3a-cho "$CANCHO"
echo "== mutants, proxy (end to end, four at once)"; quiet 1 python3 tests/mutants.py proxy "$CANCHO"
echo "all green"
