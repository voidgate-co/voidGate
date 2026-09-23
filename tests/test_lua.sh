#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run Lua control tests against a daemon in private namespaces.
set -euo pipefail

. "$(dirname "$0")/create_env.sh"

conf=$work/voidgate.conf

cleanup() {
    local result=$?
    trap - EXIT
    if [[ -e $work/voidgate.pid ]]; then
        "$root/voidgate" -s stop -c "$conf" 2>/dev/null || true
    fi
    exit "$result"
}
trap cleanup EXIT

cp "$root/tests/idle.conf" "$conf"
printf 'log_file = %s\n' "$work/daemon.log" >> "$conf"
printf 'pid_file = %s\n' "$work/voidgate.pid" >> "$conf"

timeout --kill-after=2 10 "$root/voidgate" -d -c "$conf"

cd "$root"
timeout --kill-after=5 30 lua tests/test_lua.lua \
    /run/voidgate.sock "$conf"
