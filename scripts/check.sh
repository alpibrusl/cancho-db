#!/bin/sh
# Everything CI runs, locally. CANCHO is the compiler (default: `cancho` on PATH); needs python3 with `cryptography`.
set -eu
cd "$(dirname "$0")/.."
CANCHO=${CANCHO:-cancho}
export CANCHO
mkdir -p build

echo "== formatting";                "$CANCHO" fmt --check src
echo "== vectors are reproducible";  rm -rf build/vectors && python3 tools/gen_vectors.py build/vectors >/dev/null && diff -r vectors build/vectors
echo "== login cases are reproducible"; python3 tools/gen_login.py --check
echo "== login tests (the proxy's front door, from bytes)"; "$CANCHO" test tests/login_test.cho tests/login_cases.cho src/commit.cho src/token.cho src/login.cho --std | tail -2
echo "== build";                     "$CANCHO" build --std src/*.cho -o build/verify
echo "== go verifier";               (cd verifiers/go && gofmt -l . | (! grep .) && go vet ./... && go build -o ../../build/verify-go .)
export FUZZ_EXTRA="build/verify-go"
echo "== authority";                 sh tests/authority.sh
echo "== vectors, python verifier";  python3 tests/run_vectors.py vectors -- python3 tools/verify.py
echo "== vectors, cancho verifier";  python3 tests/run_vectors.py vectors -- build/verify
echo "== vectors, go verifier";      python3 tests/run_vectors.py vectors -- build/verify-go
echo "== command lines";             python3 tests/cli_test.py vectors build/verify
echo "== attenuation property";       python3 tests/properties.py 4000 1
echo "== fuzz (three verifiers, no crash)"; python3 tests/fuzz.py vectors build/verify 3000 1
echo "== mutants, python";           python3 tests/mutants.py py | tail -1
echo "== mutants, cancho";           python3 tests/mutants.py cho "$CANCHO" | tail -1
echo "== mutants, login";            python3 tests/mutants.py login "$CANCHO" | tail -1
echo "all green"
