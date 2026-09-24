# voidGate

Multi-layer XDP shield for a single Linux VM. Silent unless the instance
is under attack.

Website: [https://lynch1981.github.io/VoidGate/](https://lynch1981.github.io/VoidGate/).
Source is [`docs/`](docs/). Enable once in the GitHub UI: Settings → Pages →
Deploy from a branch → `main` / `/docs`.

Watch the NIC idle, keep the VM reachable, cut attacker hosts, then
widen to `/24` or `/64` when the cluster is dense. There is no NetFlow,
sFlow, AF_PACKET, or AF_XDP. Packets are not redirected to userspace.
The XDP program either `XDP_PASS` or `XDP_DROP`. Userspace is the
control plane: it watches coarse rx rates, and only when the NIC is
flooded does it arm the gate, count sources, and install CIDRs into a
BPF LPM drop tree.

```
IDLE  ── wake_pps / wake_mbps ──► ACTIVE ── quiet clear_seconds ──► IDLE
         cfg.armed = 0                 cfg.armed = 1
         parse: no                     parse + LPM drop + counters
```

## Requirements

- Linux 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- clang, llvm, libbpf, bpftool, libelf
- `CAP_BPF` + `CAP_NET_ADMIN` (root is fine)

On Ubuntu 24.04:

```
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev \
    linux-tools-generic make gcc
make
sudo ./tests/test_xdp
```

## Run

```
sudo ./voidgate -c configs/voidgate.conf -i eth0
sudo ./voidgatectl status
sudo ./voidgatectl drop 203.0.113.0/24
sudo ./voidgatectl disarm
```

Prometheus: `http://127.0.0.1:9105/metrics`

Use `-d` to detach and run in the background:

```sh
sudo ./voidgate -d -c configs/voidgate.conf
sudo ./voidgate -s stop
```

The command waits for startup before returning success and printing the daemon
PID to stderr. Startup failures return nonzero; after detachment, diagnostic
details are in the log file. SIGTERM shuts down the daemon and detaches XDP.
The supplied systemd service continues running in the foreground.

`log_file` in the configuration selects the append-only log. Omit the key for
`/var/log/voidgate.log`. Files are created with mode `0644` subject to
the process umask; parent directories must already exist. `pid_file` is
`/run/voidgate.pid` when omitted; `-s stop` reads it. Relative log, pid, and
config paths use the launch directory, which the daemon retains for
configuration reloads. `-v` and `-vv` retain their usual verbosity. Restart
voidgate after rotating the log file or changing its destination; configuration
reload does not reopen logs or move the pid file.

Run `sudo bash tests/test_daemon.sh` to test daemon startup and logging in
isolated mount, network and PID namespaces (requires sudo and BPF support).

Edit `interface` in the config to the VM's public NIC. Do not point this
at a shared management-only interface you cannot afford to XDP-attach;
the idle path is `XDP_PASS`, but attach still requires driver/SKB XDP.

## Lua integration

The `lua/voidgate.lua` module talks directly to the daemon's Unix socket.
It supports Lua 5.1–5.4 and LuaJIT with LuaSocket's `socket.unix` module.
On Ubuntu, install the optional Lua dependencies and module with:

```sh
sudo apt install lua5.4 lua-socket
sudo make install-lua LUA_VERSION=5.4
```

Set `LUA_VERSION=5.1` for Lua 5.1/LuaJIT, or override `LUA_DIR` for an
embedded application's module directory. To use the source checkout without
installing, set `LUA_PATH='./lua/?.lua;;'`.

```lua
local vg = require("voidgate")

local status, err = vg.status()
if not status then
    error(err)
end
print(status.state, status.armed, status.rx_pps)

local ok, err = vg.drop("203.0.113.0/24")
if not ok then
    error(err)
end
assert(vg.undrop("203.0.113.0/24"))

-- Optional settings; each method opens and closes its own connection.
local client = assert(vg.new({ path = "/run/voidgate.sock", timeout = 1 }))
local stats = assert(client:stats())
print(stats.rx_pkts) -- Decimal string: preserves all 64 bits.
```

| Method | Successful return |
| --- | --- |
| `status()` | Table: `state`, boolean `armed`, numeric `rx_pps`, `rx_bps`, `prefixes`, string `iface` |
| `stats()` | Table: counters as decimal strings; numeric rates and prefix count; string `state` |
| `drops()` | Array of `{ cidr, reason, age }` entries; empty array when there are no drops |
| `arm()`, `disarm()`, `reload()` | `true` |
| `drop(cidr)`, `undrop(cidr)` | `true` |

Operations return `nil, error` on connection, timeout, or daemon errors.
CIDR validity is checked by the daemon; the client only rejects a CIDR
that contains whitespace. `stats()` keeps `rx_pkts`,
`rx_bytes`, `passed`, `dropped`, `non_ip`, `map_full`, and `parse_err` as
strings to avoid precision loss. Drop `reason` and `age` (seconds) are
numbers.

The calling process needs permission to access `/run/voidgate.sock` (mode
`0660`). Calls block, with a default one-second timeout per socket operation;
this client is intended for standard Lua hosts, not an OpenResty request loop.
The daemon currently has an 8192-byte response buffer, so large `drops()` lists
may be truncated by the daemon.

The protocol is one newline-terminated command per connection, followed by a
text response and connection close. Commands are limited to 254 bytes before
the newline. The server also accepts a command terminated by a write-side EOF.

Run the Lua control tests against an isolated real daemon (requires sudo,
BPF support, Bash, coreutils, iproute2, util-linux, Lua, and LuaSocket):

```sh
sudo bash tests/test_lua.sh
```

The Bash runner creates private network and mount namespaces, a temporary
veth pair, and a private `/run/voidgate.sock`. It stops the daemon and removes
temporary files after the test. Build `voidgate` and `voidgatectl` first.
The runner uses `lua` from `PATH`.

## How it decides

- **IDLE**: XDP increments `rx_pkts` / `rx_bytes` and passes. Userspace
  polls those counters. No drop tree, no per-source maps written.
- **ACTIVE**: XDP parses IPv4/IPv6, hard-passes NDP/SSH/DHCP, drops
  prefixes in `drop_v4`/`drop_v6`, counts local hosts and remote sources.
- Control plane inserts attacker `/32`/`/128` (and aggregates to
  `/24`/`/64` when dense). It will not install a prefix that covers the
  VM itself or the allow list.
- When the flood is gone for `clear_seconds` and the drop tree is empty,
  it disarms. Remote LRU maps are **not** wiped (no cheap BPF clear);
  rates are re-baselined on the next arm.

## Layout

```
src/bpf/voidgate.bpf.c   XDP program
src/bpf/voidgate.h       shared map/packet structs
src/voidgate.c           daemon
src/voidgatectl.c        voidgatectl
lua/voidgate.lua         Lua control client
src/policy.c             IDLE/ACTIVE policy
src/maps.c               libbpf attach + LPM helpers
```
