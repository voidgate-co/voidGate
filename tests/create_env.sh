# SPDX-License-Identifier: Apache-2.0
# Source from a test script. Re-execs the caller in private namespaces.

if [[ ${1:-} != --isolated ]]; then
    exec sudo unshare --mount --net --pid --fork --kill-child \
        --propagation private bash "$0" --isolated \
        "$(readlink /proc/self/ns/mnt)" "$@"
fi
if [[ -z ${2:-} || $(readlink /proc/self/ns/mnt) == "$2" ||
      $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
    echo "refusing to run without mount isolation" >&2
    exit 1
fi
shift 2

root=$(cd "$(dirname "$0")/.." && pwd)
work=/tmp/voidgate

mount -t proc proc /proc
mount -t tmpfs -o mode=755 tmpfs /run
mount -t tmpfs -o mode=755 tmpfs /tmp
mkdir "$work"

ip link add test0 type veth peer name peer0

for interface in lo test0 peer0; do
    ip link set "$interface" up
done
