#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Exercise real daemon startup in disposable mount, network and PID namespaces.
set -euo pipefail
. "$(dirname "$0")/create_env.sh"

directory=$(mktemp -d /tmp/voidgate-XXXXXX)
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

cd "$directory"
umask 022
cp "$root/tests/idle.conf" base.conf
mkdir "$work/log"
printf 'log_file = %s\n' "$work/log/voidgate.log" >> base.conf

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
    # Single fork + setsid: session leader, not the caller's session.
    # Linux stat: pid, comm, state, ppid, pgrp, session.
    local process comm state parent group session rest
    read -r process comm state parent group session rest < "/proc/$pid/stat"
    [[ $session == "$pid" ]]
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
[[ $(readlink "/proc/$pid/fd/2") == "$work/log/voidgate.log" ]]
[[ $(stat -c %a "$work/log/voidgate.log") == 644 ]]
stop_daemon
printf 'append marker\n' >> "$work/log/voidgate.log"
start_daemon -c base.conf
grep -q 'append marker' "$work/log/voidgate.log"
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
        grep -q 'idle on test0' "$work/log/voidgate.log"
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
