#!/bin/sh
# The client drivers tests/drivers_e2e.py runs through the proxy: a Python venv (psycopg 3, psycopg2, pg8000, asyncpg) and node-postgres,
# both under build/. Idempotent; needs network the first time.
set -eu
cd "$(dirname "$0")/.."
if [ ! -x build/venv/bin/python ]; then
    python3 -m venv build/venv
fi
build/venv/bin/python -c "import psycopg, psycopg2, pg8000, asyncpg" 2>/dev/null ||
    build/venv/bin/pip install -q "psycopg[binary]" psycopg2-binary pg8000 asyncpg
if [ ! -d build/node/node_modules/pg ]; then
    mkdir -p build/node
    (cd build/node && { [ -f package.json ] || echo '{"name":"drivers","private":true}' > package.json; } && npm install --silent pg)
fi
