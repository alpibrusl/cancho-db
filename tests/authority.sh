#!/bin/sh
# What each program can reach, pinned (README claim C7, docs/m1-proxy.md section 3). `cancho authority` lists what a program
# performs and what it never touches; this fails if either list changes, so a wider authority is a decision and not a drift.
set -eu
CANCHO=${CANCHO:-cancho}

performs_of() { printf '%s\n' "$1" | sed -n '/^performs/,/^never touches/p' | sed '1d;$d' | sed 's/^ *//; s/ *<- unbounded$//' | sort | tr '\n' ' '; }
never_in() { printf '%s\n' "$1" | sed -n '/^never touches/,/^provably/p' | grep -q "^ *$2\$"; }

# the verifier: the log and the console, and nothing else
out=$("$CANCHO" authority src/*.cho --std)
got=$(performs_of "$out")
want='args err_write file_read fs_read("") heap io_write '
[ "$got" = "$want" ] || { echo "verifier authority changed: performs [$got], expected [$want]" >&2; exit 1; }
for never in "the network" "signals" "other programs" "foreign code"; do
    never_in "$out" "$never" || { echo "verifier: no longer says it never touches $never" >&2; exit 1; }
done
echo "verifier authority ok: $got"

# the proxy: the network (unbounded: this compiler revision has one Net per program, so a program that listens and dials
# cannot carry a narrowed one, docs/net-bounds.md section 1), the clock, the console, the filesystem (since P2c: the key file and the
# log directory, nothing else is named, and the report does not narrow `fs_read("")`), and no signal, program or foreign code. When the report can bound the network this must change on purpose.
out=$("$CANCHO" authority proxy/proxy.cho src/commit.cho src/token.cho src/login.cho src/lex.cho src/parse.cho src/stmt.cho src/lower.cho src/ir.cho src/guard.cho src/snapshot.cho src/build.cho src/store.cho src/l1.cho src/upstream.cho src/shared.cho src/commitpath.cho src/catalog.cho src/extended.cho --std)
got=$(performs_of "$out")
want='args clock conn_accept conn_read conn_write dir_read dir_write err_write file_read file_write fs_read("") heap io_write net_in("") net_out("") poll '
[ "$got" = "$want" ] || { echo "proxy authority changed: performs [$got], expected [$want]" >&2; exit 1; }
for never in "signals" "other programs" "foreign code"; do
    never_in "$out" "$never" || { echo "proxy: no longer says it never touches $never" >&2; exit 1; }
done
printf '%s\n' "$out" | sed -n '/^unbounded by/,/^provably/p' | grep -q 'net_out("")' ||
    { echo "proxy: the network is no longer reported unbounded: update docs/m1-proxy.md and this test" >&2; exit 1; }
echo "proxy authority ok: $got (network unbounded)"
