#!/bin/sh
# What each program can reach, pinned (README claim C7, docs/m1-proxy.md section 3). `cancho authority` lists what a program
# performs and what it never touches; this fails if either list changes, so a wider authority is a decision and not a drift.
set -eu
CANCHO=${CANCHO:-cancho}

performs_of() { printf '%s\n' "$1" | sed -n '/^performs/,/^never touches/p' | sed '1d;$d' | sed 's/^ *//; s/ *<- unbounded$//' | sort | tr '\n' ' '; }
never_in() { printf '%s\n' "$1" | sed -n '/^never touches/,/^provably/p' | grep -q "^ *$2\$"; }

# the verifier: the log and the console, and nothing else
out=$("$CANCHO" authority $(ls src/*.cho | grep -v -e /serve.cho -e /tlsio.cho) --std)
got=$(performs_of "$out")
want='args err_write file_read fs_read("") heap io_write '
[ "$got" = "$want" ] || { echo "verifier authority changed: performs [$got], expected [$want]" >&2; exit 1; }
for never in "the network" "signals" "other programs" "foreign code"; do
    never_in "$out" "$never" || { echo "verifier: no longer says it never touches $never" >&2; exit 1; }
done
echo "verifier authority ok: $got"

# the L3a verifier: the files named on its command line and the console, and nothing else
out=$("$CANCHO" authority proxy/l3averify.cho src/l3a.cho src/commit.cho src/build.cho src/state.cho --std)
got=$(performs_of "$out")
want='args err_write file_read fs_read("") heap io_write '
[ "$got" = "$want" ] || { echo "L3a verifier authority changed: performs [$got], expected [$want]" >&2; exit 1; }
for never in "the network" "signals" "other programs" "foreign code"; do
    never_in "$out" "$never" || { echo "L3a verifier: no longer says it never touches $never" >&2; exit 1; }
done
echo "L3a verifier authority ok: $got"

# the export tool (docs/m3-engine.md 6av): the page file it is named, to read, and the console; it can write no file, and has no clock
out=$("$CANCHO" authority proxy/logexport.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/state.cho src/commit.cho src/build.cho src/time.cho src/row.cho src/eval.cho src/pager.cho src/btree.cho src/pstore.cho src/tables.cho src/index.cho src/exec.cho src/via.cho src/uniq.cho src/execs.cho src/execw.cho src/execd.cho src/facts.cho src/token.cho src/ir.cho --std)
got=$(performs_of "$out")
want='args err_write file_read fs_read("") heap io_write '
[ "$got" = "$want" ] || { echo "export tool authority changed: performs [$got], expected [$want]" >&2; exit 1; }
for never in "the network" "signals" "other programs" "foreign code"; do
    never_in "$out" "$never" || { echo "export tool: no longer says it never touches $never" >&2; exit 1; }
done
echo "export tool authority ok: $got"

# the proxy: the network (unbounded: this compiler revision has one Net per program, so a program that listens and dials
# cannot carry a narrowed one, docs/net-bounds.md section 1), the clock, the console, the filesystem (since P2c: the key file and the
# log directory, nothing else is named, and the report does not narrow `fs_read("")`), and no signal, program or foreign code. When the report can bound the network this must change on purpose.
out=$("$CANCHO" authority proxy/proxy.cho src/commit.cho src/token.cho src/login.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/ir.cho src/guard.cho src/snapshot.cho src/build.cho src/store.cho src/l1.cho src/upstream.cho src/shared.cho src/commitpath.cho src/catalog.cho src/extended.cho src/capture_sql.cho src/state.cho src/fork.cho src/forkpath.cho src/erase.cho src/asof.cho --std)
got=$(performs_of "$out")
want='args clock conn_accept conn_read conn_write dir_read dir_write err_write file_read file_write fs_read("") heap io_write net_in("") net_out("") poll '
[ "$got" = "$want" ] || { echo "proxy authority changed: performs [$got], expected [$want]" >&2; exit 1; }
for never in "signals" "other programs" "foreign code"; do
    never_in "$out" "$never" || { echo "proxy: no longer says it never touches $never" >&2; exit 1; }
done
printf '%s\n' "$out" | sed -n '/^unbounded by/,/^provably/p' | grep -q 'net_out("")' ||
    { echo "proxy: the network is no longer reported unbounded: update docs/m1-proxy.md and this test" >&2; exit 1; }
echo "proxy authority ok: $got (network unbounded)"

# the engine's server (docs/m3-engine.md 6al, 6bq): it listens and never dials, reads and writes the files it is named, and has the clock; with the TLS package in it
# (TLS_PKG: its files, from scripts/check.sh) it still runs no foreign code and no other program. Skipped when the package's files are not named.
if [ -n "${TLS_PKG:-}" ]; then
    out=$("$CANCHO" authority --std proxy/engine.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/state.cho src/commit.cho src/build.cho src/time.cho src/row.cho src/eval.cho src/pager.cho src/btree.cho src/pstore.cho src/tables.cho src/index.cho src/exec.cho src/via.cho src/uniq.cho src/execs.cho src/execw.cho src/execd.cho src/answer.cho src/drive.cho src/facts.cho src/session.cho src/wire.cho src/serve.cho src/login.cho src/token.cho src/revoke.cho src/ir.cho src/tlsio.cho $TLS_PKG)
    got=$(performs_of "$out")
    want='args clock conn_accept conn_read conn_write err_write file_read file_write fs_read("") fs_write("") heap net_in("") poll '
    [ "$got" = "$want" ] || { echo "server authority changed: performs [$got], expected [$want]" >&2; exit 1; }
    for never in "signals" "other programs" "foreign code"; do
        never_in "$out" "$never" || { echo "server: no longer says it never touches $never" >&2; exit 1; }
    done
    echo "server authority ok: $got"
fi
