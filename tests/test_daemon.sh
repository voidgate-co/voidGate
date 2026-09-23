#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Exercise real daemon startup in disposable mount, network and PID namespaces.
set -euo pipefail

if [[ ${1:-} != --isolated ]]; then
    exec sudo unshare --mount --net --pid --fork --kill-child \
        --propagation private bash "$0" --isolated \
        "$(readlink /proc/self/ns/mnt)"
fi
if [[ -z ${2:-} || $(readlink /proc/self/ns/mnt) == "$2" ||
      $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
    echo "refusing to run without mount isolation" >&2
    exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
mount -t proc proc /proc
mount -t tmpfs -o mode=755 tmpfs /run
mount -t tmpfs -o mode=755 tmpfs /var/log
directory=$(mktemp -d /tmp/voidgate-daemon-XXXXXX)
pid=

cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n $pid ]]; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
    if (( result != 0 )); then
        cat "$directory"/*.log "$directory"/*.err >&2 2>/dev/null || true
    fi
    cd /
    rm -rf -- "$directory"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ip link add test0 type veth peer name peer0
for interface in lo test0 peer0; do
    ip link set "$interface" up
done
cd "$directory"
umask 022
cat > base.conf <<'CONF'
interface = test0
xdp_mode = skb
wake_pps = 1000000000
wake_mbps = 1000000000
metrics_port = 0
remote_map_size = 64
drop_map_size = 64
local_networks = 198.51.100.10/32,2001:db8:1::10/128
CONF

status() {
    [[ $(timeout 2 "$root/voidgatectl" status) == state=idle* ]]
}

start_daemon() {
    timeout --kill-after=2 10 "$root/voidgate" -d "$@" \
        > launch.out 2> launch.err
    [[ ! -s launch.out ]]
    local message
    message=$(cat launch.err)
    [[ $message =~ ^voidgate\ daemon\ started\ \(pid\ ([0-9]+)\)$ ]]
    pid=${BASH_REMATCH[1]}
    kill -0 "$pid"
    [[ $(< /run/voidgate.pid) == "$pid" ]]
    status
    [[ $(readlink "/proc/$pid/fd/0") == /dev/null ]]
    [[ $(readlink "/proc/$pid/fd/1") == /dev/null ]]
    [[ $(readlink "/proc/$pid/cwd") == "$directory" ]]
    # Double fork leaves the daemon outside the caller's session, and not
    # a session leader. Linux stat: pid, comm, state, ppid, pgrp, session.
    local process comm state parent group session rest
    read -r process comm state parent group session rest < "/proc/$pid/stat"
    [[ $session != "$pid" ]]
    read -r process comm state parent group rest < /proc/self/stat
    [[ $group != "$session" ]]
}

stop_daemon() {
    "$root/voidgate" -s stop -c base.conf
    [[ ! -e /run/voidgate.sock ]]
    [[ ! -e /run/voidgate.pid ]]
    # An XDP program must no longer be attached after socket removal.
    [[ $(ip -details link show test0) != *prog/xdp* ]]
    pid=
}

expect_failure() {
    local result=0
    timeout --kill-after=2 10 "$@" > failure.out 2> failure.err || result=$?
    [[ $result == 1 ]]
    [[ ! -e /run/voidgate.sock ]]
    [[ $(ip -details link show test0) != *prog/xdp* ]]
}

expect_failure "$root/voidgate" -s stop -c base.conf

# Default daemon log, permissions and append across restarts.
start_daemon -c base.conf
[[ $(readlink "/proc/$pid/fd/2") == /var/log/voidgate.log ]]
[[ $(stat -c %a /var/log/voidgate.log) == 640 ]]
stop_daemon
printf 'append marker\n' >> /var/log/voidgate.log
start_daemon -c base.conf
grep -q 'append marker' /var/log/voidgate.log
stop_daemon

# Configured relative destination, verbosity and relative config reload.
cp base.conf run.conf
printf 'log_file = config.log\n' >> run.conf
start_daemon -c run.conf -vv
[[ $(readlink "/proc/$pid/fd/2") == "$directory/config.log" ]]
grep -q 'active configuration' config.log
printf 'log_file = changed.log\n' >> run.conf
[[ $("$root/voidgatectl" reload) == ok ]]
[[ ! -e changed.log ]]
grep -q 'reloaded run.conf' config.log
stop_daemon

# Append mode preserves existing contents.
cp base.conf append.conf
printf 'log_file = append.log\n' >> append.conf
printf 'append marker\n' > append.log
start_daemon -c append.conf
[[ $(readlink "/proc/$pid/fd/2") == "$directory/append.log" ]]
grep -q 'append marker' append.log
stop_daemon

# Closed inherited standard streams must not collide with the startup pipe.
cp base.conf closed.conf
printf 'log_file = closed.log\n' >> closed.conf
timeout --kill-after=2 10 bash -c 'exec 0<&- 1>&- 2>&-; exec "$@"' _ \
    "$root/voidgate" -d -c closed.conf
status
for entry in /proc/[0-9]*/stat; do
    if read -r process comm state rest < "$entry"; then
        if [[ $comm == '(voidgate)' && $state != Z ]]; then
            pid=$process
        fi
    fi
done
[[ -n $pid ]]
grep -q 'idle on test0' closed.log
stop_daemon

# Foreground remains attached to the launched PID, with default or file log.
for mode in default config; do
    cp base.conf foreground.conf
    if [[ $mode == config ]]; then
        printf 'log_file = foreground-config.log\n' >> foreground.conf
    fi
    "$root/voidgate" -c foreground.conf 2> foreground.err &
    pid=$!
    for attempt in {1..100}; do
        if status 2>/dev/null; then
            break
        fi
        sleep 0.05
    done
    status
    [[ ! -s foreground.err ]]
    if [[ $mode == default ]]; then
        grep -q 'idle on test0' /var/log/voidgate.log
    else
        grep -q 'idle on test0' "foreground-$mode.log"
    fi
    stop_daemon
done

# Fail before forking for bad config and unusable/invalid log paths.
cp base.conf invalid.conf
printf 'wake_pps = invalid\n' >> invalid.conf
expect_failure "$root/voidgate" -d -c invalid.conf
cp base.conf missing.conf
printf 'log_file = missing/daemon.log\n' >> missing.conf
expect_failure "$root/voidgate" -d -c missing.conf
printf -v oversized '%0256d' 0
cp base.conf invalid.conf
printf 'log_file = %s\n' "$oversized" >> invalid.conf
expect_failure "$root/voidgate" -d -c invalid.conf

# Fail after forking: no capabilities means BPF initialization must fail.
cp base.conf bpf.conf
printf 'log_file = bpf-failure.log\n' >> bpf.conf
expect_failure setpriv --bounding-set=-all "$root/voidgate" \
    -d -c bpf.conf
grep -q 'daemon startup failed' failure.err
grep -q 'failed to load BPF object' bpf-failure.log

# No live daemon may remain after any failure (allow exited zombies).
for entry in /proc/[0-9]*/stat; do
    if read -r process comm state rest < "$entry"; then
        [[ $comm != '(voidgate)' || $state == Z ]]
    fi
done
echo "Daemon integration tests passed"
