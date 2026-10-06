#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run contrib/logban against a real daemon in private namespaces. Replay:
# rule, watch, cluster and honey bans become timed drops, a browser is
# left alone, and a drop the daemon refuses is asked once, not every
# step. Follow: bans that fail while the daemon is down are retried until
# it is back.
set -euo pipefail

. "$(dirname "$0")/../bin/create_env.sh"

conf=$work/voidgate.conf
lbconf=$work/logban.conf
logban=$root/contrib/logban/logban.py
follow_pid=
writer_pid=

if ! command -v python3 > /dev/null; then
    echo "skip: no python3" >&2
    exit 0
fi

# refute <cmd...>: fail if cmd succeeds. Not "! cmd": set -e ignores a
# negated command, so "! grep ..." can never fail the script.
refute() {
    if "$@"; then
        echo "${0##*/}: unexpectedly true: $*" >&2
        return 1
    fi
}

cleanup() {
    local result=$?
    trap - EXIT
    for p in $writer_pid $follow_pid; do
        kill "$p" 2>/dev/null || true
    done
    if [[ $result != 0 ]]; then
        tail -n 30 "$work"/*.out "$work/daemon.log" >&2 2>/dev/null || true
    fi
    if [[ -e $work/voidgate.pid ]]; then
        "$root/voidgate" -s stop -c "$conf" 2>/dev/null || true
    fi
    exit "$result"
}
trap cleanup EXIT

start_daemon() {
    timeout --kill-after=2 10 "$root/voidgate" -d -v -c "$conf" 2> /dev/null
}

# wait_for <seconds> <cmd...>: poll until cmd succeeds.
wait_for() {
    local i tries=$(( $1 * 10 ))
    shift
    for (( i = 0; i < tries; i++ )); do
        "$@" && return 0
        sleep 0.1
    done
    echo "${0##*/}: timed out waiting for: $*" >&2
    return 1
}

# idle.conf protects local_networks 198.51.100.10/32: a drop of it is
# refused.
cp "$root/t/conf/idle.conf" "$conf"
printf 'log_file = %s\n' "$work/daemon.log" >> "$conf"
printf 'pid_file = %s\n' "$work/voidgate.pid" >> "$conf"
start_daemon

cat > "$lbconf" <<'EOF'
costly = ^/search
honey = ^/\.env
watch scan = status:404
scan.max = 50
cluster_min_addresses = 10
cluster_min_costly = 100
ttl = 600
EOF

# --- replay -----------------------------------------------------------

python3 - "$work/access.log" <<'EOF'
import sys
from datetime import datetime, timedelta, timezone

t0 = datetime(2026, 10, 3, 10, 0, tzinfo=timezone.utc)
out = []

def emit(ip, sec, path, status=200, ua="test"):
    stamp = (t0 + timedelta(seconds=sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    out.append((sec, '%s - - [%s] "GET %s HTTP/1.1" %d 512 "-" "%s"'
                     ' rt=0.1 urt=0.1\n' % (ip, stamp, path, status, ua)))

for i in range(150):
    emit("203.0.113.7", i * 0.2, "/search?q=%d" % i)
    emit("2001:db8::bad", i * 0.2, "/search?q=%d" % i)
# 5 minutes from the protected address: 30 steps over threshold
for i in range(1500):
    emit("198.51.100.10", i * 0.2, "/search")
# a browser: searches, but mostly cheap pages
for i in range(200):
    emit("198.51.100.20", i * 0.2, "/search" if i % 4 == 0 else "/")
# the honey probe as a JSON line (log_format escape=json), in the same file
out.append((12, '{"time_local":"%s","remote_addr":"198.18.0.5",'
                '"request":"GET /.env HTTP/1.1","status":404}\n'
                % (t0 + timedelta(seconds=12)).strftime(
                    "%d/%b/%Y:%H:%M:%S +0000")))
# a wide botnet: 12 addresses, 10 searches each, one user agent
for k in range(12):
    for i in range(10):
        emit("198.18.1.%d" % (k + 1), i * 4 + k * 0.1, "/search", ua="wide")
# a path scanner: 60 misses
for i in range(60):
    emit("198.18.0.6", i * 0.3, "/scan%d.php" % i, 404)

out.sort(key=lambda x: x[0])
open(sys.argv[1], "w").writelines(line for _, line in out)
EOF

python3 -B "$logban" -c "$lbconf" "$work/access.log" > "$work/replay.out"
cat "$work/replay.out"

drops=$("$root/voidgatectl" drops)
echo "$drops"
grep -Eq '^203\.0\.113\.7/32 reason=4 ' <<< "$drops"
grep -Eq '^2001:db8::bad/128 reason=4 ' <<< "$drops"
grep -Eq '^198\.18\.0\.5/32 reason=4 ' <<< "$drops"
grep -Eq '^198\.18\.0\.6/32 reason=4 ' <<< "$drops"
[[ $(grep -Ec '^198\.18\.1\.[0-9]+/32 reason=4 ' <<< "$drops") == 12 ]]
refute grep -q '198\.51\.100\.10' <<< "$drops"
refute grep -q '198\.51\.100\.20' <<< "$drops"

grep -q ' ban 198\.18\.0\.5 ttl=900 .*rule=honey path=/\.env$' \
    "$work/replay.out"
grep -Eq ' ban 198\.18\.0\.6 ttl=600 .*rule=scan hits=[0-9]+$' \
    "$work/replay.out"
grep -q ' ban 198\.18\.1\.1 .*rule=cluster cluster=12 ua="wide"$' \
    "$work/replay.out"
# refused once, held for its ttl: one line from logban, one in the daemon
[[ $(grep -c ' ban 198\.51\.100\.10 ' "$work/replay.out") == 1 ]]
grep -q ' ban 198\.51\.100\.10 .* error="error: refused or map update'\
' failed" retry_after=600s$' "$work/replay.out"
[[ $(grep -c 'refuse drop 198\.51\.100\.10/32' "$work/daemon.log") == 1 ]]

# --- follow, daemon down, then back -----------------------------------

"$root/voidgate" -s stop -c "$conf"
refute test -S /run/voidgate.sock

cat >> "$lbconf" <<'EOF'
window = 10
step = 1
EOF
: > "$work/live.log"
python3 -B "$logban" -f -c "$lbconf" "$work/live.log" \
    > "$work/follow.out" 2>&1 &
follow_pid=$!
sleep 0.5       # follow starts at the end of the file

# a live flood: 20 costly requests a second, stamped now
python3 - "$work/live.log" <<'EOF' &
import sys, time

with open(sys.argv[1], "a") as f:
    for i in range(20 * 30):
        stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
        f.write('198.18.0.40 - - [%s] "GET /search HTTP/1.1" 200 512 "-"'
                ' "test" rt=0.1 urt=0.1\n' % stamp)
        f.flush()
        time.sleep(0.05)
EOF
writer_pid=$!

# no socket: the ban fails, and is retried every step
banned_with_error() {
    [[ $(grep -c ' ban 198\.18\.0\.40 .* error=' "$work/follow.out") -ge 2 ]]
}
wait_for 20 banned_with_error
refute grep -q 'retry_after' "$work/follow.out"

start_daemon

dropped() {
    "$root/voidgatectl" drops | grep -Eq '^198\.18\.0\.40/32 reason=4 '
}
wait_for 10 dropped
grep -Eq ' ban 198\.18\.0\.40 ttl=600 offense=1 .*rule=ratio$' \
    "$work/follow.out"

echo "logban integration tests passed"
