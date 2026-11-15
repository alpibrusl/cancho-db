#!/bin/sh
# The cancho verifier reaches the log and the console and nothing else (README claim C7). `cancho authority` lists what a
# program performs and what it never touches; this fails if the list grows or a "never touches" line goes away.
set -eu
CANCHO=${CANCHO:-cancho}
out=$("$CANCHO" authority src/commit.cho src/verify.cho --std)
performs=$(printf '%s\n' "$out" | sed -n '/^performs/,/^never touches/p' | sed '1d;$d' | sed 's/^ *//' | sort | tr '\n' ' ')
want='args err_write file_read fs_read("") heap io_write '
if [ "$performs" != "$want" ]; then
    echo "authority changed: performs [$performs], expected [$want]" >&2
    exit 1
fi
for never in "the network" "signals" "other programs" "foreign code"; do
    printf '%s\n' "$out" | sed -n '/^never touches/,/^provably/p' | grep -q "^ *$never\$" || {
        echo "authority: no longer says it never touches $never" >&2
        exit 1
    }
done
echo "authority ok: $performs"
