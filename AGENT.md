# AGENT.md — voidGate

Instructions for humans and coding agents working in this repo.

## What this is

voidGate is an **inline XDP DDoS gate for one Linux VM**. It is not
FastNetMon and must not grow FastNetMon’s capture backends.

- Data plane: `src/bpf/voidgate.bpf.c` — `XDP_PASS` or `XDP_DROP` only.
- Control plane: `src/voidgate.c` + `src/policy.c` — decides CIDRs,
  writes LPM maps.
- No AF_XDP, no packet redirect to userspace, no
  NetFlow/sFlow/pcap/AF_PACKET, no BGP.

The gate is **silent unless the VM is under attack**. Idle path is one
`cfg.armed` load plus coarse rx counters.

## Layout

```
src/bpf/voidgate.h       shared structs (BPF + userspace). No libc.
src/bpf/voidgate.bpf.c   XDP program (GPL-2.0-only)
src/voidgate.c           daemon
src/voidgatectl.c        voidgatectl (unix socket client)
src/policy.c             IDLE/ACTIVE policy
src/maps.c               libbpf load/attach, LPM helpers
src/config.c             key=value config
src/ipaddr.c             CIDR parse / overlap
configs/voidgate.conf
tests/test_xdp.c         bpf_prog_test_run (needs root)
tests/test_netns.sh      veth flood (needs root)
```

Generated, do not edit or commit: `src/bpf/voidgate.skel.h`, `*.o`,
binaries.

## Invariants (do not break)

1. **Idle datapath stays cheap.** If `cfg.armed == 0`, XDP must not parse
   Ethernet, must not LPM, must not touch host/remote maps. Only
   `metrics.rx_*` then `XDP_PASS`.
2. **XDP stays attached in IDLE.** Arming is a map write
   (`cfg.armed = 1`), not attach/detach. Detach only on process exit.
3. **Control plane decides drops; XDP only looks them up.** No
   thresholds in BPF.
4. **Whitelist / NDP / SSH before drop.** Never drop IPv6 NDP (types
   133–137), `fe80::/10`, `ff02::/16`, TCP `allow_ports` when the
   **local** side is that port (`dport` + dest in `local_*`, or `sport` +
   src in `local_*`), DHCP UDP 67/68 (and DHCPv6 546/547). A remote
   source port of 22 is not a whitelist. Userspace must refuse a drop
   CIDR that covers `local_*` or `allow_*`.
5. **Do not blackhole the VM.** Drop attacker prefixes, not the local
   interface CIDR.
6. **Do not clear `remote_*` on disarm.** BPF has no cheap hash flush.
   Flush `drop_*` only. On the next arm, re-baseline userspace rate
   snapshots so leftover counters are not treated as a new flood.
7. **Shared NIC.** Default verdict is `XDP_PASS`. This is not a SPAN
   tap. No promiscuous mode in v1.
8. **IPv4 and IPv6 together.** Dual LPM, dual host maps, dual remote
   maps. Do not ship v4-only changes.
9. **Do not copy FastNetMon sources** (`/home/ubuntu/fastnetmon` is
   GPLv2). Reuse ideas, not code.

## State machine

Userspace owns state. XDP only reads `cfg.armed`.

```
IDLE  -- wake_pps / wake_mbps or `voidgatectl arm` -->  ACTIVE
ACTIVE -- quiet for clear_seconds AND drop tree empty --> IDLE
`voidgatectl drop <cidr>` forces ACTIVE
`voidgatectl disarm` flushes drops and returns IDLE
```

- `wake_*`: NIC is on fire, turn the gate on.
- `threshold_*`: this remote is part of the attack, install a drop.
- Policy (ACTIVE, 1s): top remotes over threshold → `/32` or `/128`;
  dense clusters → `/24` or `/64`. Manual drops are not auto-expired.

## Maps

| Map | Type | Written when | Notes |
|-----|------|----------------|-------|
| `cfg` | ARRAY[1] | userspace | `armed`, allow_ports |
| `metrics` | PERCPU_ARRAY[1] | always (rx); armed (dropped, …) | |
| `drop_v4/v6` | LPM_TRIE | ACTIVE | empty in IDLE after disarm |
| `allow_v4/v6` | LPM_TRIE | start/reload | |
| `local_v4/v6` | LPM_TRIE | start/reload | this VM’s CIDRs |
| `host_v4/v6` | PERCPU_HASH | armed | local IPs |
| `remote_v4/v6` | LRU_PERCPU_HASH | armed | attack sources; not flushed |

LPM lookup key prefixlen is 32/128 for a host query. LPM_TRIE maps need
`BPF_F_NO_PREALLOC`.

## Build and test

```
make
./tests/test_policy
sudo ./tests/test_xdp
sudo tests/test_netns.sh
sudo bash tests/test_daemon.sh
sudo bash tests/test_lua.sh
```

Needs clang, llvm, libbpf, bpftool, libelf, root (or `CAP_BPF` +
`CAP_NET_ADMIN`). Kernel 5.8+ with BTF.

Attach: native (`XDP_FLAGS_DRV_MODE`) then SKB fallback. Tests use SKB /
`bpf_prog_test_run` and do not require a real NIC.

`voidgatectl` talks to `/run/voidgate.sock`. Prometheus (if
`metrics_port` > 0): `127.0.0.1:9105/metrics`.

## Coding rules

- C, no extra libraries beyond libbpf/libelf/zlib. `-Wall -Wextra`.
- Formatting: [`code_style.md`](code_style.md) (nginx-based).
- `src/bpf/voidgate.h` is included by BPF and userspace: keep types
  packed/`__u*`, no `stdio`, no pointers to userspace objects.
- BPF file is **GPL-2.0-only** (kernel helpers). Userspace is
  **Apache-2.0**.
- Commit messages: `type: summary` (types: `feature`, `bugfix`, `doc`,
  `tests`, `optimize`, `style`). Wrap every line at 80 characters.
  Example: `style: 4-space indent and braced if/else`.
- Verifier first: bounded unrolls (`VG_MAX_VLANS`, `VG_MAX_ALLOW_PORTS`),
  `data_end` checks before every packet deref. If a BPF change compiles
  but `test_xdp` cannot load the object, the verifier rejected it — fix
  the program, do not weaken tests.
- After changing `voidgate.bpf.c` or map layouts in `voidgate.h`, rebuild
  the skeleton (`make` does this) and run `sudo ./tests/test_xdp`. If
  you change drop/allow/idle behavior, extend that test; if you change
  wake/arm, run `tests/test_netns.sh`.
- Unix ctl protocol is one line in, text out: `status`, `stats`,
  `drops`, `arm`, `disarm`, `drop <cidr>`, `undrop <cidr>`, `reload`.
- `reload` re-reads the config file and replaces allow/local maps +
  ports. It does not change the attached interface, XDP mode, or map
  sizes.

## Out of scope until someone explicitly asks

AF_XDP, detaching XDP every idle cycle, 5-tuple conntrack, GRE/GTP/MPLS,
Kafka/ClickHouse, BGP, copying FastNetMon plugins.
