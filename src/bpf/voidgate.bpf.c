// SPDX-License-Identifier: GPL-2.0-only
/* voidGate XDP data plane.
 *
 * IDLE  (cfg.armed == 0): bump rx counters, XDP_PASS. No parse, no LPM, no LRU.
 * ACTIVE (cfg.armed == 1): whitelist → drop LPM → count → PASS|DROP.
 *
 * Control plane decides prefixes; this program only enforces them.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "voidgate.h"


static __always_inline struct vg_metrics *get_metrics(void);
static __always_inline struct vg_cfg *get_cfg(void);
static __always_inline int port_allowed(const struct vg_cfg *c, __u16 port);
static __always_inline int v4_in_lpm(void *map, __be32 ip);
static __always_inline int v6_in_lpm(void *map, const __u8 addr[16]);
static __always_inline int v6_is_linklocal(const __u8 addr[16]);
static __always_inline int v6_is_mcast_link(const __u8 addr[16]);
static __always_inline void acc_in(struct host_counters *c, __u64 bytes);
static __always_inline int dhcp_ports(__u16 sport, __u16 dport);
static __always_inline int v4_tcp_allowed(const struct vg_cfg *c,
    __be32 saddr, __be32 daddr, __u16 sport, __u16 dport);
static __always_inline int v6_tcp_allowed(const struct vg_cfg *c,
    const __u8 saddr[16], const __u8 daddr[16], __u16 sport, __u16 dport);
static __always_inline int parse_l4(void *l4, void *data_end, __u8 proto,
    __u16 *sport, __u16 *dport, __u8 *icmp6_type);
static __always_inline int v6_walk_ext(void *data_end, void **l4p,
    __u8 *protop);
static __always_inline int pass(struct vg_metrics *m);
static __always_inline int parse_fail(struct vg_metrics *m);

/* Userspace ARRAY[1]: armed and allow_ports. XDP reads. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vg_cfg);
} cfg SEC(".maps");


/* Per-CPU ARRAY[1]: rx_* always; drop/pass and the rest only when armed. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vg_metrics);
} metrics SEC(".maps");


/* LPM of IPv4 prefixes to XDP_DROP. ACTIVE write; flushed on disarm. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_DROP_MAP_MAX);
    __type(key, struct vg_lpm_v4);
    __type(value, struct drop_entry);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} drop_v4 SEC(".maps");


/* LPM of IPv6 prefixes to XDP_DROP. ACTIVE write; flushed on disarm. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_DROP_MAP_MAX);
    __type(key, struct vg_lpm_v6);
    __type(value, struct drop_entry);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} drop_v6 SEC(".maps");


/* LPM of IPv4 never-drop CIDRs. Userspace at start/reload. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_LPM_MAP_MAX);
    __type(key, struct vg_lpm_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v4 SEC(".maps");


/* LPM of IPv6 never-drop CIDRs. Userspace at start/reload. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_LPM_MAP_MAX);
    __type(key, struct vg_lpm_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v6 SEC(".maps");


/* LPM of this VM's IPv4 CIDRs; dest/src-local and TCP allow-port. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_LPM_MAP_MAX);
    __type(key, struct vg_lpm_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} local_v4 SEC(".maps");


/* LPM of this VM's IPv6 CIDRs; dest/src-local and TCP allow-port. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, VG_LPM_MAP_MAX);
    __type(key, struct vg_lpm_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} local_v6 SEC(".maps");


/* Per-CPU hash of local IPv4 dests; inbound volume when dest is local. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, VG_HOST_MAP_MAX);
    __type(key, __be32);
    __type(value, struct host_counters);
} host_v4 SEC(".maps");


/* Per-CPU hash of local IPv6 dests; inbound volume when dest is local. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, VG_HOST_MAP_MAX);
    __type(key, struct vg_ip6);
    __type(value, struct host_counters);
} host_v6 SEC(".maps");


/* LRU per-CPU hash of dest-local IPv4 sources; not flushed on disarm. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, VG_REMOTE_MAP_MAX);
    __type(key, __be32);
    __type(value, struct host_counters);
} remote_v4 SEC(".maps");


/* LRU per-CPU hash of dest-local IPv6 sources; not flushed on disarm. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, VG_REMOTE_MAP_MAX);
    __type(key, struct vg_ip6);
    __type(value, struct host_counters);
} remote_v6 SEC(".maps");


static __always_inline struct vg_metrics *
get_metrics(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&metrics, &key);
}


static __always_inline struct vg_cfg *
get_cfg(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&cfg, &key);
}


static __always_inline int
port_allowed(const struct vg_cfg *c, __u16 port)
{
    int i;

    if (c == NULL) {
        return 0;
    }

#pragma unroll
    for (i = 0; i < VG_MAX_ALLOW_PORTS; i++) {
        if (i >= c->allow_port_count) {
            break;
        }

        if (c->allow_ports[i] == port) {
            return 1;
        }
    }

    return 0;
}


static __always_inline int
v4_in_lpm(void *map, __be32 ip)
{
    struct vg_lpm_v4 key = {};

    key.prefixlen = 32;
    __builtin_memcpy(key.data, &ip, 4);
    return bpf_map_lookup_elem(map, &key) != NULL;
}


static __always_inline int
v6_in_lpm(void *map, const __u8 addr[16])
{
    struct vg_lpm_v6 key = {};

    key.prefixlen = 128;
    __builtin_memcpy(key.data, addr, 16);
    return bpf_map_lookup_elem(map, &key) != NULL;
}


static __always_inline int
v6_is_linklocal(const __u8 addr[16])
{
    return addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80;
}


static __always_inline int
v6_is_mcast_link(const __u8 addr[16])
{
    return addr[0] == 0xff && addr[1] == 0x02;
}

#define VG_HASH_GET(map, keyp, m) \
    ({ \
        struct host_counters *_c; \
        struct host_counters _zero = {}; \
        _c = bpf_map_lookup_elem(&(map), (keyp)); \
        \
        if (_c == NULL) { \
            bpf_map_update_elem(&(map), (keyp), &_zero, BPF_NOEXIST); \
            _c = bpf_map_lookup_elem(&(map), (keyp)); \
            \
            if (_c == NULL && (m) != NULL) { \
                (m)->map_full++; \
            } \
        } \
        \
        _c; \
    })

static __always_inline void
acc_in(struct host_counters *c, __u64 bytes)
{
    if (c == NULL) {
        return;
    }

    c->in_pkts++;
    c->in_bytes += bytes;
}


static __always_inline int
dhcp_ports(__u16 sport, __u16 dport)
{
    return dport == 67 || dport == 68 || sport == 67 || sport == 68
           || dport == 546 || dport == 547 || sport == 546 || sport == 547;
}


/* Allow TCP only when the local side is the configured service port.
 * Inbound SSH: dport 22 and dest is this VM. Replies we originated that
 * appear on ingress: sport 22 and src is local. A remote sport=22 flood
 * is not a whitelist hit.
 */
static __always_inline int
v4_tcp_allowed(const struct vg_cfg *c,
    __be32 saddr, __be32 daddr,
    __u16 sport, __u16 dport)
{
    if (port_allowed(c, dport) && v4_in_lpm(&local_v4, daddr)) {
        return 1;
    }

    if (port_allowed(c, sport) && v4_in_lpm(&local_v4, saddr)) {
        return 1;
    }

    return 0;
}


static __always_inline int
v6_tcp_allowed(const struct vg_cfg *c,
    const __u8 saddr[16],
    const __u8 daddr[16], __u16 sport,
    __u16 dport)
{
    if (port_allowed(c, dport) && v6_in_lpm(&local_v6, daddr)) {
        return 1;
    }

    if (port_allowed(c, sport) && v6_in_lpm(&local_v6, saddr)) {
        return 1;
    }

    return 0;
}


static __always_inline int
parse_l4(void *l4, void *data_end, __u8 proto,
    __u16 *sport, __u16 *dport,
    __u8 *icmp6_type)
{
    *sport = 0;
    *dport = 0;

    if (icmp6_type != NULL) {
        *icmp6_type = 0;
    }

    if (proto == VG_IPPROTO_TCP) {
        struct vg_tcphdr *th = l4;

        if ((void *) (th + 1) > data_end) {
            return -1;
        }

        *sport = bpf_ntohs(th->source);
        *dport = bpf_ntohs(th->dest);
        return 0;
    }

    if (proto == VG_IPPROTO_UDP) {
        struct vg_udphdr *uh = l4;

        if ((void *) (uh + 1) > data_end) {
            return -1;
        }

        *sport = bpf_ntohs(uh->source);
        *dport = bpf_ntohs(uh->dest);
        return 0;
    }

    if (proto == VG_IPPROTO_ICMPV6 && icmp6_type) {
        struct vg_icmpv6hdr *ih = l4;

        if ((void *) (ih + 1) > data_end) {
            return -1;
        }

        *icmp6_type = ih->type;
        return 0;
    }

    return 0;
}


/* 1: try L4 at *l4p. 0: no L4 (non-first fragment). -1: truncated extension.
 * Never takes a verdict — caller still runs allow/drop with whatever
 * ports it has.
 */
static __always_inline int
v6_walk_ext(void *data_end, void **l4p, __u8 *protop)
{
    void *l4 = *l4p;
    __u8 proto = *protop;
    int i;

#pragma unroll
    for (i = 0; i < VG_MAX_IPV6_EXT; i++) {
        __u8 *ext = l4;
        __u32 len;

        if (proto == VG_IPPROTO_FRAGMENT) {
            struct vg_ip6_frag *fh = l4;

            if ((void *) (fh + 1) > data_end) {
                return -1;
            }

            proto = fh->nexthdr;
            l4 = (void *) (fh + 1);

            if (bpf_ntohs(fh->frag_off) & 0xfff8) {
                *l4p = l4;
                *protop = proto;
                return 0;
            }

            continue;
        }

        if (proto != VG_IPPROTO_HOPOPTS && proto != VG_IPPROTO_ROUTING
            && proto != VG_IPPROTO_DSTOPTS && proto != VG_IPPROTO_AH)
        {
            break;
        }

        if ((void *) (ext + 2) > data_end) {
            return -1;
        }

        len = proto == VG_IPPROTO_AH ? ((__u32) ext[1] + 2) * 4
              : ((__u32) ext[1] + 1) * 8;

        if ((void *) (ext + len) > data_end) {
            return -1;
        }

        proto = ext[0];
        l4 = ext + len;
    }

    *l4p = l4;
    *protop = proto;
    return 1;
}


static __always_inline int
pass(struct vg_metrics *m)
{
    if (m != NULL) {
        m->passed++;
    }

    return XDP_PASS;
}


static __always_inline int
parse_fail(struct vg_metrics *m)
{
    if (m != NULL) {
        m->parse_err++;
    }

    return XDP_PASS;
}


SEC("xdp")
int
voidgate_xdp(struct xdp_md *ctx)
{
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct vg_metrics *m = get_metrics();
    struct vg_cfg *c;
    struct vg_eth *eth;
    void *nh;
    __u16 eth_proto;
    __u64 pkt_len;
    int i;

    pkt_len = (__u64) ((__u8 *) data_end - (__u8 *) data);

    if (m != NULL) {
        m->rx_pkts++;
        m->rx_bytes += pkt_len;
    }

    c = get_cfg();

    if (c == NULL || c->armed == 0) {
        return pass(m);
    }

    if ((void *) data + sizeof(*eth) > data_end) {
        return parse_fail(m);
    }

    eth = data;
    eth_proto = bpf_ntohs(eth->proto);
    nh = (void *) (eth + 1);

#pragma unroll
    for (i = 0; i < VG_MAX_VLANS; i++) {
        if (eth_proto != VG_ETH_P_8021Q && eth_proto != VG_ETH_P_8021AD) {
            break;
        }

        if (nh + sizeof(struct vg_vlan) > data_end) {
            return parse_fail(m);
        }

        {
            struct vg_vlan *vh = nh;

            eth_proto = bpf_ntohs(vh->proto);
            nh = (void *) (vh + 1);
        }
    }

    if (eth_proto == VG_ETH_P_IP) {
        struct vg_iphdr *ip = nh;
        __u32 ihl;
        void *l4;
        __be32 saddr, daddr;
        __u8 proto;
        __u16 sport = 0, dport = 0;
        int first_frag;

        if ((void *) (ip + 1) > data_end) {
            return parse_fail(m);
        }

        ihl = ip->ver_ihl & 0x0f;

        if (ihl < 5) {
            return parse_fail(m);
        }

        l4 = (void *) ip + (ihl << 2);

        if (l4 > data_end) {
            return parse_fail(m);
        }

        saddr = ip->saddr;
        daddr = ip->daddr;
        proto = ip->protocol;
        first_frag = (bpf_ntohs(ip->frag_off) & 0x1fff) == 0;

        if (first_frag
            && parse_l4(l4, data_end, proto, &sport, &dport, NULL) < 0)
        {
            if (m != NULL) {
                m->parse_err++;
            }
        }

        if (v4_in_lpm(&allow_v4, saddr) || v4_in_lpm(&allow_v4, daddr)) {
            goto v4_count;
        }

        if (proto == VG_IPPROTO_TCP
            && v4_tcp_allowed(c, saddr, daddr, sport, dport))
        {
            goto v4_count;
        }

        if (proto == VG_IPPROTO_UDP && dhcp_ports(sport, dport)) {
            goto v4_count;
        }

        if (v4_in_lpm(&drop_v4, saddr) || v4_in_lpm(&drop_v4, daddr)) {
            if (m != NULL) {
                m->dropped++;
            }

            return XDP_DROP;
        }


        v4_count:

        if (v4_in_lpm(&local_v4, daddr)) {
            acc_in(VG_HASH_GET(host_v4, &daddr, m), pkt_len);
            acc_in(VG_HASH_GET(remote_v4, &saddr, m), pkt_len);
        }

        return pass(m);
    }

    if (eth_proto == VG_ETH_P_IPV6) {
        struct vg_ipv6hdr *ip6 = nh;
        void *l4;
        __u8 proto;
        __u16 sport = 0, dport = 0;
        __u8 icmp6_type = 0;
        struct vg_ip6 saddr = {}, daddr = {};

        if ((void *) (ip6 + 1) > data_end) {
            return parse_fail(m);
        }

        proto = ip6->nexthdr;
        l4 = (void *) (ip6 + 1);
        __builtin_memcpy(saddr.addr, ip6->saddr, 16);
        __builtin_memcpy(daddr.addr, ip6->daddr, 16);

        {
            int ext_rc = v6_walk_ext(data_end, &l4, &proto);

            if (ext_rc < 0) {
                if (m != NULL) {
                    m->parse_err++;
                }

            } else if (ext_rc > 0
                    && parse_l4(l4, data_end, proto, &sport, &dport,
                                &icmp6_type) < 0)
            {
                if (m != NULL) {
                    m->parse_err++;
                }
            }
        }

        if (v6_is_linklocal(saddr.addr) || v6_is_linklocal(daddr.addr)
            || v6_is_mcast_link(saddr.addr) || v6_is_mcast_link(daddr.addr))
        {
            goto v6_count;
        }

        if (icmp6_type >= VG_NDISC_RS && icmp6_type <= VG_NDISC_REDIRECT) {
            goto v6_count;
        }

        if (v6_in_lpm(&allow_v6, saddr.addr)
            || v6_in_lpm(&allow_v6, daddr.addr))
        {
            goto v6_count;
        }

        if (proto == VG_IPPROTO_TCP
            && v6_tcp_allowed(c, saddr.addr, daddr.addr, sport, dport))
        {
            goto v6_count;
        }

        if (proto == VG_IPPROTO_UDP && dhcp_ports(sport, dport)) {
            goto v6_count;
        }

        if (v6_in_lpm(&drop_v6, saddr.addr)
            || v6_in_lpm(&drop_v6, daddr.addr))
        {
            if (m != NULL) {
                m->dropped++;
            }

            return XDP_DROP;
        }


        v6_count:

        if (v6_in_lpm(&local_v6, daddr.addr)) {
            acc_in(VG_HASH_GET(host_v6, &daddr, m), pkt_len);
            acc_in(VG_HASH_GET(remote_v6, &saddr, m), pkt_len);
        }

        return pass(m);
    }

    if (m != NULL) {
        m->non_ip++;
    }

    return pass(m);
}


char LICENSE[] SEC("license") = "GPL";
