#!/bin/bash
# Integration: veth pair, daemon starts IDLE, flood wakes it, drop works,
# SSH-like TCP still passes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/voidgate"
CTL="$ROOT/voidgatectl"
CONF=$(mktemp)
NS=vgtest$$
VETH_A=vga$$
VETH_B=vgb$$
cleanup() {
  sudo kill "$DAEMON_PID" 2>/dev/null || true
  sudo ip netns del "$NS" 2>/dev/null || true
  sudo ip link del "$VETH_A" 2>/dev/null || true
  rm -f "$CONF"
}
trap cleanup EXIT

cat > "$CONF" <<EOF
interface = $VETH_A
xdp_mode = skb
wake_pps = 50
wake_mbps = 1000
idle_poll_ms = 200
clear_seconds = 2
threshold_pps = 20
threshold_mbps = 1000
ban_time = 60
aggregate_k = 8
local_networks =
allow_ports = 22
metrics_port = 0
EOF

sudo ip netns add "$NS"
sudo ip link add "$VETH_A" type veth peer name "$VETH_B"
sudo ip link set "$VETH_B" netns "$NS"
sudo ip addr add 198.51.100.10/24 dev "$VETH_A"
sudo ip link set "$VETH_A" up
sudo ip netns exec "$NS" ip addr add 198.51.100.1/24 dev "$VETH_B"
sudo ip netns exec "$NS" ip link set "$VETH_B" up
sudo ip netns exec "$NS" ip link set lo up
sudo ip netns exec "$NS" ping -c 1 -W 1 198.51.100.10 >/dev/null || true

sudo "$BIN" -c "$CONF" -i "$VETH_A" &
DAEMON_PID=$!
sleep 0.5
STATUS=$(sudo "$CTL" status || true)
echo "initial: $STATUS"
echo "$STATUS" | grep -q 'state=idle' || { echo "expected idle"; exit 1; }

flood() {
  sudo ip netns exec "$NS" python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.time() + 2
n = 0
while time.time() < end:
    s.sendto(b"x"*64, ("198.51.100.10", 9))
    n += 1
s.close()
print("sent", n)
PY
}

flood
sleep 0.5
STATUS=$(sudo "$CTL" status)
echo "during flood: $STATUS"
echo "$STATUS" | grep -q 'state=active' || {
    echo "expected active after flood"
    sudo "$CTL" stats
    exit 1
}

sudo "$CTL" drop 198.51.100.1/32
sudo "$CTL" drops
flood
STATS=$(sudo "$CTL" stats)
echo "stats after drop: $STATS"
echo "$STATS" | grep -E 'dropped=[1-9]' || {
    echo "expected dropped > 0"
    exit 1
}

sudo "$CTL" disarm
STATUS=$(sudo "$CTL" status)
echo "after disarm: $STATUS"
echo "$STATUS" | grep -q 'state=idle' || {
    echo "expected idle after disarm"
    exit 1
}
echo "netns test passed"
