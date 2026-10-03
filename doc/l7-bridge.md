# Design: Layer 7 → Layer 3 ban bridge

Let OpenResty, or a gateway built on it (Kong, APISIX), decide which client
is abusive and push that address down to XDP with a drop that expires by
itself. voidGate stays a gate, not a WAF.

Contents:

1. [Problem](#1-problem)
2. [Scope](#2-scope)
3. [Architecture](#3-architecture)
4. [Control protocol](#4-control-protocol)
5. [Timed drops](#5-timed-drops)
6. [The drop list](#6-the-drop-list)
7. [Logging](#7-logging)
8. [State machine](#8-state-machine)
9. [Client: `resty.voidgate`](#9-client-restyvoidgate)
10. [Socket access](#10-socket-access)
11. [Security](#11-security)
12. [Failure modes](#12-failure-modes)
13. [Behaviour changes](#13-behaviour-changes)
14. [Alternatives considered](#14-alternatives-considered)
15. [Future work](#15-future-work)
16. [Tests](#16-tests)

## 1. Problem

voidGate drops floods at XDP based on packet and byte rates. It cannot see
HTTP, so it cannot tell a credential stuffer, a scraper or a slow request
flood from a real user. The web tier can: OpenResty's `limit_req`, failed
logins, bot rules.

But once the web tier has decided, its own enforcement is expensive: every
banned request still costs an accept, a TLS handshake and the HTTP parser
before nginx returns 403. XDP sits in front of all of that, and voidGate
already keeps a drop tree there.

**Goal:** let the gateway push "drop this address for N seconds" into
voidGate's drop tree, without blocking request handling, and keep the
daemon fast when bans arrive by the thousand.

## 2. Scope

In scope:

- **OpenResty**, and gateways built on it such as Kong and APISIX. They run
  the same nginx Lua module, so one client covers them all.
- A drop that **expires by itself**, so a crashed or reloaded gateway never
  leaves bans behind.
- Gateway workers reach the control socket **without running as root**.
- A drop list that stays cheap at its maximum size.

Out of scope:

- **No WAF.** voidGate does not parse HTTP, match signatures or rate-limit
  requests. The gateway detects; voidGate enforces.
- No other deciders yet (fail2ban, HAProxy, ...). Anything that can run
  `voidgatectl drop <ip> ttl=<sec>` works, but nothing else ships (§15).
- No persistence and no per-caller permissions (§11).

The `AGENT.md` invariants still hold:

- no BPF change: a timed drop is an ordinary `drop_v4` / `drop_v6` entry;
- protected prefixes (`local_*`, `allow_*`) are still refused;
- the control plane still decides what is dropped.

## 3. Architecture

```
 ┌─────────────────────────────────────┐         ┌──────────────────────────────┐
 │ OpenResty / Kong / APISIX worker    │         │ voidgate daemon              │
 │                                     │  unix   │                              │
 │  limit_req → 429                    │  socket │  ctl_server.c                │
 │  log phase: resty.voidgate.ban()    │         │    drop <cidr> ttl=N         │
 │    ├─ shared dict: once per window  │         │  policy.c                    │
 │    └─ ngx.timer.at → cosocket ──────┼────────▶│    drop_add()    merge rules │
 │                                     │         │    drop list     pool+lists  │
 └─────────────────────────────────────┘         │    expire_drops() each tick  │
                                                 └──────────────┬───────────────┘
                                                                │ LPM map write
                                                 ┌──────────────▼───────────────┐
                                                 │ XDP: drop LPM → XDP_DROP     │
                                                 │ (unchanged)                  │
                                                 └──────────────────────────────┘
```

Only the control plane knows a drop is timed. XDP just looks it up.

## 4. Control protocol

One new form of an existing command:

```
drop <cidr> ttl=<seconds>
```

The dispatcher strips `drop `; `ctl_drop` sees `<cidr>` or
`<cidr> ttl=<seconds>`. **The first word is always the CIDR** and is judged
first, parsed in place with `vg_parse_cidr_len` (no second copy, and a NUL
inside the word is rejected). Only the text after the first space is
options. After `ttl=` only decimal digits are accepted, checked against the
bound digit by digit, so the value cannot overflow.

| Input | Reply |
|---|---|
| `drop 203.0.113.7 ttl=600` | `ok`. A bare address is a `/32` or `/128`, as before. |
| `drop 203.0.113.7 ttl=0060` | `ok`, 60 s: leading zeros are still decimal |
| a bad CIDR, whatever follows: `drop ttl=60 <ip>`, `drop  <ip>` (two spaces), an over-long word | `error: bad cidr` |
| ttl outside 1 … 31536000 (one year), empty, sign, space, hex, trailing text, a number past `uint32`, or any option other than `ttl=` | `error: bad ttl` |
| covers `local_*` or `allow_*`, the drop list is full, or the map write failed | `error: refused or map update failed` |
| `undrop <cidr>` whose kernel delete fails | `error: map update failed` (was a silent `ok`) |

Compatibility:

- `drop <cidr>` without a ttl behaves as before.
- The `drops` line format is unchanged (`<cidr> reason=N age=N`); timed
  drops show `reason=4`. The remaining ttl is deliberately left out, because
  clients and tests anchor on that exact line. Lines are now oldest first.
- `voidgatectl` exits 1 when the reply starts with `error`, or when the
  daemon closes without replying. It used to exit 0 for everything.

## 5. Timed drops

### 5.1 Reasons

| Reason | Name | Installed by | Lifted by |
|---|---|---|---|
| 1 | manual | `drop <cidr>` | `undrop`, `disarm`, a reload that makes it cover a protected prefix |
| 2 | policy | per-remote threshold | `ban_time` after insert |
| 3 | aggregate | `aggregate_k` hosts in one `/24` or `/64` | `ban_time` after insert |
| **4** | **timed** | `drop <cidr> ttl=N` | **its own `expires`**, plus everything that lifts a manual drop |

### 5.2 Dropping a prefix that is already listed

All drops go through `drop_add()` in `src/policy.c`:

| Existing ↓ / new → | manual | timed | policy / aggregate |
|---|---|---|---|
| **manual** | refresh insert time | no change: **manual wins** | no change |
| **timed** | becomes manual (permanent) | `expires = max(old, now + ttl)` | no change |
| **policy / aggregate** | becomes manual | becomes timed, `expires = max(inserted + ban_time, now + ttl)` | no change |

- **Manual wins.** An operator's permanent drop is never shortened by an
  automated ban.
- **A ttl only ever extends.** Re-banning a banned address never shortens
  the ban.
- **A timed drop on a policy drop keeps the longer of the two.** The flood
  detector's decision is never cut short.

### 5.3 Expiry

`expire_drops()` runs on every ACTIVE tick (`idle_poll_ms`, 1 s by
default) and lifts a timed drop once `now >= expires`, using wall-clock
`time()` as `ban_time` does. Expiry only runs while ACTIVE, which is
enough: any drop forces ACTIVE, and the gate cannot disarm while drops
remain.

### 5.4 No aggregation

`maybe_aggregate()` drops a whole `/24` or `/64` once `aggregate_k` listed
drops fall inside it. **Timed drops are not counted.** Web clients cluster
behind carrier CGNAT and corporate egress addresses: a few web bans in one
`/24` plus one flood source must not drop the whole prefix. Manual drops
still count, as before.

## 6. The drop list

### 6.1 Why it changed

The list was an array that grew with `realloc`, and every `drop`, `undrop`
and expiry searched it linearly; expiry searched again for each record it
lifted. A burst of bans made that O(n²):

| 65,536 drops (logging stubbed) | before | after |
|---|---|---|
| add all | ~27 s | ~30 ms |
| expire half in one tick | ~7 s | ~1 ms |
| tick with nothing due (full scan) | 0.3 ms | 0.7 ms |

At ~0.9 ms per ban near the limit, the old list blocked the single event
loop that also runs the tick and the control socket.

### 6.2 Structure

```
drop_pool[2 x drop_map_size]       records, allocated once, never moved
  drop_used                        high-water mark: pool records ever handed out
drop_free   (vg_list)              lifted records, reused first
drop_all    (vg_list)              every listed drop, oldest first   → walks
drop_heads[] (vg_hlist_head)       bucket per prefix hash            → lookups

struct vg_drop_rec {
    cidr, reason, inserted, expires;
    struct vg_hlist_node hash;     /* bucket chain: next, **pprev */
    struct vg_list       all;      /* drop_all, or drop_free when unused */
};
```

- **Pool size** is `2 × drop_map_size`: `drop_v4` and `drop_v6` each hold
  up to `drop_map_size` entries, and `reload` cannot grow them, so the list
  can never need more. A drop past the pool is refused (`drop list full`),
  the same bound the kernel maps already had.
- **Records never move**, so list nodes stay valid while linked, and a
  record stays readable after it is lifted until the next allocation.
- **Memory:** new records come from the high-water mark, not a pre-linked
  free list, so `calloc` pages are only touched as drops are used.
- **Buckets:** the next power of two ≥ the pool size, so chains stay near
  one entry. The hash is FNV-1a over family, prefix length and address;
  the prefix length is part of the key (`/32` and `/24` on the same address
  are separate drops).
- **`src/list.h`** is our own `vg_list` / `vg_hlist`. The kernel's
  `list.h` is GPL-2.0 and voidGate's userspace is Apache-2.0, so the idea
  is reused, not the code.

### 6.3 Operations

| Operation | How | Cost |
|---|---|---|
| find | hash the prefix, walk its bucket | O(1) average |
| add | take a record (free list, else pool), map write, `hlist_add_head`, `list_add_tail` | O(1) |
| remove | **kernel map → hash → list**: map delete, `hlist_del`, `list_del`, onto `drop_free` | O(1) worst case |
| walk (expiry, reload prune, aggregation, `drops`) | safe iteration of `drop_all` | O(n) |
| disarm | flush the maps, then reset heads, lists and `drop_used` | O(buckets) |

**Remove order matters.** The kernel delete comes first: if it fails, the
record stays listed and the next expiry pass retries it. The old code
dropped the record first, so a failed delete left a map entry dropping
traffic that nothing tracked.

**Why not a min-heap for expiry.** The scan of a full list costs ~0.7 ms
per tick, about 0.07 % of a core. A heap would add O(log n) to every insert
and re-ban, plus a heap position per record kept in sync with the lists, to
save that. Not worth it unless a profile says otherwise.

## 7. Logging

A burst of bans used to write one timestamped line per drop and per
expiry. On a VM whose clock source is HPET, each timestamp is a system
call, and logging was over 90 % of the cost of a ban burst.

| Event | Default | With `-v` |
|---|---|---|
| drops added since the last tick | one line per tick: `dropped 9800 prefixes (manual 0, policy 70, aggregate 3, timed 9727), 41 again, 9812 listed` | plus `drop <cidr> reason N`, and `(again)` for a re-drop |
| drops expired this tick | one line per tick: `expired 9873 drops (policy 70, aggregate 3, timed 9800), 12 left` | plus `expire <cidr> reason N` |
| `undrop` from the socket | `undrop <cidr>` | same |
| reload lifting a protected drop | `reload: undrop <cidr> (now covers local/allow)` | same |
| refusal, full list, map failure | one line each | same |

Refusals and failures stay per prefix: they are rare, and a refusal is
exactly what someone debugging a missing ban looks for. The added-drops
summary is written at the start of the next tick, so drops lifted by a
`disarm` in between are still reported. To see which addresses are banned,
use `voidgatectl drops`.

## 8. State machine

- A timed drop arms the gate, like a manual one.
- ACTIVE → IDLE still needs an empty drop list, so **the gate stays armed
  while any web ban is live**. ACTIVE parses every packet and updates the
  host and remote maps: more than the idle path, far less than letting the
  request reach nginx. A site that bans steadily will be armed most of the
  time, which weakens "silent unless under attack". Accepted (§14).
- `disarm`, and a daemon restart, forget every timed drop. Nothing is
  persisted.
- `reload` lifts a timed drop that now covers `local_*` or `allow_*`, as it
  does every other drop.

## 9. Client: `resty.voidgate`

`lua/resty/voidgate.lua` is the only Lua client: methods, response parsing
and `ban()` in one module that needs nothing beyond lua-nginx-module. It
follows the OpenResty `resty.*` naming convention.

```lua
local vg = require("resty.voidgate")
vg.status() / vg.stats() / vg.drops() / vg.drop(cidr [, ttl]) / ...
vg.ban(ip, ttl, { dict = "voidgate_ban", window = 10, client = c })
vg.new({ path = "/run/voidgate.sock", timeout = 1 })   -- seconds
```

**Transport.** `ngx.socket.tcp()` connects to `unix:<path>`, sends one line
and reads with `receive("*a")` until the daemon closes. No keepalive pool:
the protocol is one command per connection.

**Phases.** Cosockets yield, so the methods run only in `rewrite`,
`access`, `content` and timer context. `ban()` covers every other phase: it
validates its input, queues `ngx.timer.at(0, ...)` to make the call from
timer context, and returns `true` at once. The daemon's answer goes to the
nginx error log, never to the request. Kong and APISIX plugins call it the
same way from their `log` handler.

**Why the log phase.** By then the status is known (429 from `limit_req`,
401 from auth) and the client has already been answered, so the ban adds
no latency.

**Deduplication.** Until the XDP drop lands, one client can send hundreds
of requests, each of which would queue a timer and a socket round trip.
With `opt.dict`, `ban()` first does `dict:add(cidr, true, window)` on a
`lua_shared_dict`, which every worker sees; if the key exists it returns
`true` without sending. The window is 10 s, not the ban's ttl:

- once XDP drops the client, its requests stop reaching nginx anyway;
- a short window self-heals a ban lost to `disarm` or a daemon restart.

**Input.** `ip` must be a bare address: a `/` or whitespace is rejected,
and `/32` or `/128` is appended depending on whether it contains `:`. The
ttl is checked locally (an integer, 1 s to one year); the daemon does the
final CIDR validation.

**Install.** `make install-lua` copies the file to
`/usr/local/openresty/site/lualib/resty/`. For Kong or APISIX, set
`LUA_DIR` to a directory on the gateway's Lua path (Kong:
`lua_package_path`; APISIX: `apisix.extra_lua_path`).

## 10. Socket access

The socket is created `0660 root:root`. The `ctl_socket_group` config key
`chown`s it to a named group after `bind`, so gateway workers can connect.

| Gateway | Common worker group | Set by |
|---|---|---|
| OpenResty | `nogroup` (Debian/Ubuntu), `nobody` (RHEL) | `user` in `nginx.conf` |
| Kong | `kong` | `nginx_user` in `kong.conf` |
| APISIX | `nogroup` or `nobody`; `apisix` in its Docker image | `nginx_config.user` in `config.yaml` |

Check the real group with `ps -eo user,group,args | grep 'worker process'`.
In a container with the socket bind-mounted, the worker's numeric gid must
match the host group's.

- An unknown group, or a failed chown, logs a warning and leaves the
  socket root-only. It never stops the gate from starting.
- Applied at startup only; `reload` keeps the old value.
- The systemd unit's capability bounding set gains `CAP_CHOWN`.

## 11. Security

**Trust.** Group members get the whole protocol: `disarm`, `reload`, and
`drop` of any unprotected prefix. A code-execution bug in the gateway can
therefore turn off the gate or drop arbitrary prefixes. Accepted for now:

- the gateway already terminates all traffic, so compromising it is
  already fatal for availability;
- `local_*` and `allow_*` still cannot be dropped, so the VM cannot
  blackhole itself or its management ranges.

**Spoofed addresses.** Behind a CDN or load balancer, a ban keyed on an
unchecked `X-Forwarded-For` lets an attacker ban any address, including the
proxy itself. Two things are required:

- `set_real_ip_from` limited to trusted proxies;
- the proxy ranges listed in `allow_networks`, so the daemon refuses to
  drop them even if a forged header slips through.

## 12. Failure modes

| Failure | Effect |
|---|---|
| daemon down | `ban()` logs a connect error; requests are unaffected |
| daemon restart, or `disarm` | bans are forgotten; the next offending request after the dedup window bans again |
| gateway reload or crash | bans already sent stay until their ttl; nothing to clean up |
| drop list full (`2 × drop_map_size`) | `drop <cidr> refused: drop list full`; the client gets `error: refused or map update failed` |
| kernel map write fails | the record goes back to the pool; `error: refused or map update failed` |
| kernel map delete fails | the record stays listed and expiry retries it next tick; `undrop` answers `error: map update failed` |
| `lua_max_pending_timers` reached | `ngx.timer.at` fails; `ban()` returns `nil, err` |
| daemon slow | the cosocket times out after `timeout`; only the timer waits, never a request |

## 13. Behaviour changes

For anyone upgrading:

- **`lua/voidgate.lua` (LuaSocket) is removed**, with
  `t/integration/lua.sh`; `resty.voidgate` replaces it. `make install-lua`
  now targets OpenResty's site lualib and `LUA_VERSION` is gone.
- **`voidgatectl` exits 1** on an `error:` reply.
- **`undrop`** answers `error: map update failed` when the kernel refuses
  the delete.
- **`voidgatectl drops`** lists oldest first.
- **Logs:** per-drop `drop` / `undrop` lines from drops and expiry become
  per-tick summaries; use `-v` for the old detail.
- **`drop <cidr> <junk>`** answers `error: bad ttl`; a misplaced or empty
  CIDR answers `error: bad cidr`.

## 14. Alternatives considered

- **Keeping the ttl in OpenResty** (a shared dict plus a timer that calls
  `undrop`). Rejected: the state is lost on nginx restart, it is
  per-instance, and a crash leaves permanent drops behind.
- **A separate `ban` command.** Rejected: a `ttl=` option on `drop` keeps
  one code path, one refusal rule and one listing.
- **The remaining ttl in the `drops` line.** Rejected for compatibility
  (§4).
- **Enforcing drops while IDLE** (one LPM lookup without arming). Rejected
  for now: it breaks invariant 1 (the idle path does no LPM) and needs a
  BPF change. Revisit if web bans keeping the gate armed costs measurably.
- **A generic Lua client plus an OpenResty wrapper.** Rejected: two modules
  and a pluggable transport add surface for hosts we do not target.
- **fail2ban.** Deferred. Its most common jail (sshd) would do nothing:
  invariant 4 passes TCP to local `allow_ports` before the drop lookup. It
  bans at low rates that `nftables` already handles cheaply, and correct
  multi-jail unban needs per-drop ownership tags (§15).
- **A min-heap or index-chained hash for the drop list.** See §6.3: the
  heap saves under a millisecond per tick; the index-chained array needed
  relinking on every swap-remove, which the pool and lists avoid.

## 15. Future work

- A restricted second socket that accepts only `drop <host> ttl=` and
  `status`, so the gateway never gets `disarm` or `reload`.
- Tagging each drop with who installed it, so one decider's unban cannot
  lift another's ban (needed before fail2ban support).
- Persisting timed drops across daemon restarts.

## 16. Tests

| Test | Covers |
|---|---|
| `t/unit/policy.c` `test_ttl` | arm on a timed drop, extend-only merge, manual wins both ways, policy → timed keeps `ban_time`, expiry (v4 and v6), no aggregation, `disarm` flush |
| `t/unit/policy.c` `test_drop_index` | 20,000 random adds, re-drops, undrops and expiries; after each, both lists and every `prev` / `pprev` link agree, and lookups match a shadow set |
| `t/unit/policy.c` `test_pool` | full pool refused, lifted record reused, failed map write returns its record, oldest-first order, `disarm` empties the pool |
| `t/unit/policy.c` `test_del_fail` | a failed kernel delete keeps the record and does not spin the expiry loop |
| `t/unit/policy.c` `test_expire_log`, `test_drop_log` | one summary line per tick, per-prefix lines only with `-v`, refusals still per line |
| `t/unit/cidr.c` | `vg_parse_cidr_len`: a word of a longer line, NUL inside the length, over-long input |
| `t/drop-ttl.t` | protocol parsing: v4 and v6, refusal, ttl bounds and digits-only, CIDR-first errors |
| `t/drop-ttl-xdp.t` | a timed drop really drops at XDP; SSH still passes |
| `t/integration/daemon.sh` | `ctl_socket_group` chown, kept on reload, unknown group only warns; `voidgatectl` exits 1 on error |
| `t/integration/resty.sh` + `resty.lua` | real nginx with workers as `nobody:nogroup`: every method against a real daemon, ttl validation, reload; `ban()` from the log phase; 50 requests send exactly one ban |

`resty.sh` needs OpenResty, or nginx with `lua-nginx-module`
(Ubuntu: `nginx-core libnginx-mod-http-lua`), and skips otherwise.
