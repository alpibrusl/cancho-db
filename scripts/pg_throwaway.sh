#!/bin/sh
# A throwaway PostgreSQL for tests/proxy_e2e.py: trust login on 127.0.0.1, its own data directory, removed on `stop`.
#
#   sh scripts/pg_throwaway.sh start PORT    # prints nothing; the data directory is build/pg-throwaway-PORT
#   sh scripts/pg_throwaway.sh stop PORT
#
# Finds the server binaries under /usr/lib/postgresql/*/bin (Debian and Ubuntu packages), or installs them with apt-get.
# As root it runs the server as the `postgres` user, from a directory that user can reach (/var/lib/postgresql), since a
# server refuses to run as root.
set -eu
action=${1:?start or stop}
port=${2:?port}
bin=$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)
if [ -z "$bin" ] && [ "$action" = start ]; then
    (sudo -n true 2>/dev/null && sudo apt-get install -y -q postgresql) >&2 || apt-get install -y -q postgresql >&2
    bin=$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)
fi
if [ "$(id -u)" = 0 ]; then
    dir=/var/lib/postgresql/cancho-db-e2e-$port
    as="runuser -u postgres --"
else
    dir=$(pwd)/build/pg-throwaway-$port
    as=""
fi
case $action in
start)
    rm -rf "$dir"
    mkdir -p "$(dirname "$dir")"
    [ -z "$as" ] || { mkdir -p "$dir" && chown postgres "$dir"; }
    $as "$bin/initdb" -D "$dir" -A trust -U postgres >/dev/null
    $as "$bin/pg_ctl" -D "$dir" -o "-p $port -c listen_addresses=127.0.0.1 -c unix_socket_directories=$dir -c max_prepared_transactions=20 -c fsync=off" -l "$dir/server.log" -w start >/dev/null
    ;;
stop)
    $as "$bin/pg_ctl" -D "$dir" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$dir"
    ;;
*) echo "usage: pg_throwaway.sh start|stop PORT" >&2; exit 2 ;;
esac
