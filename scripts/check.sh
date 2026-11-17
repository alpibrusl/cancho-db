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
echo "== the proxy builds";          "$CANCHO" build --std proxy/proxy.cho src/commit.cho src/token.cho src/login.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/ir.cho src/guard.cho -o build/proxy
echo "== the proxy end to end (psql, a real PostgreSQL)"
sh scripts/pg_throwaway.sh start 5593
trap 'sh scripts/pg_throwaway.sh stop 5593' EXIT
export PG_E2E_PORT=5593
quiet 3 python3 tests/proxy_e2e.py build/proxy
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
"$CANCHO" build --std proxy/guardcheck.cho src/commit.cho src/token.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/ir.cho src/guard.cho -o build/guardcheck
quiet 2 python3 tests/guard_check.py build/guardcheck
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
echo "== mutants, guard";           quiet 1 python3 tests/mutants.py guard "$CANCHO"
echo "== mutants, proxy (end to end, four at once)"; quiet 1 python3 tests/mutants.py proxy "$CANCHO"
echo "all green"
