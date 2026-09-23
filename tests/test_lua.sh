#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run Lua control tests against a daemon in private namespaces.
set -euo pipefail

if [[ ${1:-} != --isolated ]]; then
    read -r -a lua <<< "${1:-lua}"
    "${lua[@]}" -e 'require("socket.unix")'
    exec sudo unshare --mount --net --pid --fork --kill-child \
        --propagation private bash "$0" --isolated \
        "$(readlink /proc/self/ns/mnt)" "${1:-lua}"
fi
if [[ -z ${2:-} || $(readlink /proc/self/ns/mnt) == "$2" ||
      $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
    echo "refusing to run without mount isolation" >&2
    exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
read -r -a lua <<< "${3:-lua}"
mount -t proc proc /proc
mount -t tmpfs -o mode=755 tmpfs /run
directory=$(mktemp -d /tmp/voidgate-lua-XXXXXX)
conf=$directory/voidgate.conf

cleanup() {
    local result=$?
    trap - EXIT
    if [[ -e /run/voidgate.pid ]]; then
        "$root/voidgate" -s stop -c "$conf" 2>/dev/null || true
    fi
    rm -rf -- "$directory"
    exit "$result"
}
trap cleanup EXIT

cd "$root"
ip link add test0 type veth peer name peer0
for interface in lo test0 peer0; do
    ip link set "$interface" up
done

cp "$root/tests/idle.conf" "$conf"
printf 'log_file = %s\n' "$directory/daemon.log" >> "$conf"

timeout --kill-after=2 10 "$root/voidgate" -d -c "$conf"
timeout --kill-after=5 30 "${lua[@]}" tests/test_lua.lua \
    /run/voidgate.sock "$conf"
