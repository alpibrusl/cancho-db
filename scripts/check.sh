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
echo "== build";                     "$CANCHO" build --std src/*.cho -o build/verify
echo "== go verifier";               (cd verifiers/go && gofmt -l . | (! grep .) && go vet ./... && go build -o ../../build/verify-go .)
export FUZZ_EXTRA="build/verify-go"
echo "== authority";                 sh tests/authority.sh
echo "== vectors, python verifier";  python3 tests/run_vectors.py vectors -- python3 tools/verify.py
echo "== vectors, cancho verifier";  python3 tests/run_vectors.py vectors -- build/verify
echo "== vectors, go verifier";      python3 tests/run_vectors.py vectors -- build/verify-go
echo "== the proxy builds";          "$CANCHO" build --std proxy/proxy.cho src/commit.cho src/token.cho src/login.cho -o build/proxy
echo "== the proxy end to end (psql, a real PostgreSQL)"
sh scripts/pg_throwaway.sh start 5593
trap 'sh scripts/pg_throwaway.sh stop 5593' EXIT
export PG_E2E_PORT=5593
quiet 3 python3 tests/proxy_e2e.py build/proxy
echo "== command lines";             python3 tests/cli_test.py vectors build/verify
echo "== attenuation property";       python3 tests/properties.py 4000 1
echo "== fuzz (three verifiers, no crash)"; python3 tests/fuzz.py vectors build/verify 3000 1
echo "== mutants, python";           quiet 1 python3 tests/mutants.py py
echo "== mutants, cancho";           quiet 1 python3 tests/mutants.py cho "$CANCHO"
echo "== mutants, login";            quiet 1 python3 tests/mutants.py login "$CANCHO"
echo "all green"
