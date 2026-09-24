
/* SPDX-License-Identifier: Apache-2.0 */

#include "bpf/voidgate.h"
#include "bpf/voidgate.skel.h"
#include "config.h"
#include "ipaddr.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>


static void expect(int cond, const char *msg);
static void bump_memlock(void);
static void put_mac(uint8_t *p, uint8_t last);
static uint16_t ip_cksum(const void *data, int len);
static int craft_v4_tcp(uint8_t *buf, size_t cap, const char *src,
    const char *dst, uint16_t sport, uint16_t dport);
static int craft_v4_udp(uint8_t *buf, size_t cap, const char *src,
    const char *dst, uint16_t sport, uint16_t dport);
static int craft_ndp(uint8_t *buf, size_t cap);
static int craft_v4_udp_vlan(uint8_t *buf, size_t cap, const char *src,
    const char *dst, uint16_t sport, uint16_t dport);
static int craft_v4_frag(uint8_t *buf, size_t cap, const char *src,
    const char *dst);
static int craft_v6_tcp(uint8_t *buf, size_t cap, const char *src,
    const char *dst, uint16_t sport, uint16_t dport);
static int craft_v6_udp(uint8_t *buf, size_t cap, const char *src,
    const char *dst);
static int prepend_ext(uint8_t *pkt, int len, uint8_t type, size_t cap);
static int run_pkt(struct voidgate_bpf *skel, uint8_t *pkt, int len,
    int *retval);
static int set_armed(struct voidgate_bpf *skel, uint32_t armed);
static int add_lpm_v4(int fd, const char *cidr, uint8_t val);
static int add_drop_v4(struct voidgate_bpf *skel, const char *cidr);
static int add_drop_v6(struct voidgate_bpf *skel, const char *cidr);
static int add_lpm_v6(int fd, const char *cidr, uint8_t val);
static struct vg_metrics read_metrics(struct voidgate_bpf *skel);
static void test_prefixes(void);
static void test_v6_extensions(struct voidgate_bpf *skel);

static int g_fail;

static void
expect(int cond, const char *msg)
{
    if (cond) {
        printf("  ok  %s\n", msg);

    } else {
        printf("  FAIL %s\n", msg);
        g_fail++;
    }
}


static void
bump_memlock(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

    setrlimit(RLIMIT_MEMLOCK, &r);
}


static void
put_mac(uint8_t *p, uint8_t last)
{
    p[0] = 0x02;
    p[1] = 0x00;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = last;
}


static uint16_t
ip_cksum(const void *data, int len)
{
    const uint16_t *w = data;
    uint32_t s = 0;

    while (len > 1) {
        s += *w++;
        len -= 2;
    }

    if (len) {
        s += *(const uint8_t *) w;
    }

    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (uint16_t) ~s;
}


static int
craft_v4_tcp(uint8_t *buf, size_t cap, const char *src,
    const char *dst, uint16_t sport, uint16_t dport)
{
    struct vg_eth *eth = (struct vg_eth *) buf;
    struct vg_iphdr *ip;
    struct vg_tcphdr *th;
    struct in_addr a, b;

    if (cap < 54) {
        return -1;
    }

    memset(buf, 0, 54);
    put_mac(eth->dst, 1);
    put_mac(eth->src, 2);
    eth->proto = htons(VG_ETH_P_IP);
    ip = (struct vg_iphdr *) (buf + 14);
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->protocol = VG_IPPROTO_TCP;
    ip->tot_len = htons(40);
    inet_pton(AF_INET, src, &a);
    inet_pton(AF_INET, dst, &b);
    ip->saddr = a.s_addr;
    ip->daddr = b.s_addr;
    ip->check = ip_cksum(ip, 20);
    th = (struct vg_tcphdr *) (buf + 34);
    th->source = htons(sport);
    th->dest = htons(dport);
    th->doff_res = 5 << 4;
    th->flags = 0x02; /* SYN */
    return 54;
}


static int
craft_v4_udp(uint8_t *buf, size_t cap, const char *src,
    const char *dst, uint16_t sport, uint16_t dport)
{
    struct vg_eth *eth = (struct vg_eth *) buf;
    struct vg_iphdr *ip;
    struct vg_udphdr *uh;
    struct in_addr a, b;

    if (cap < 42) {
        return -1;
    }

    memset(buf, 0, 42);
    put_mac(eth->dst, 1);
    put_mac(eth->src, 2);
    eth->proto = htons(VG_ETH_P_IP);
    ip = (struct vg_iphdr *) (buf + 14);
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->protocol = VG_IPPROTO_UDP;
    ip->tot_len = htons(28);
    inet_pton(AF_INET, src, &a);
    inet_pton(AF_INET, dst, &b);
    ip->saddr = a.s_addr;
    ip->daddr = b.s_addr;
    ip->check = ip_cksum(ip, 20);
    uh = (struct vg_udphdr *) (buf + 34);
    uh->source = htons(sport);
    uh->dest = htons(dport);
    uh->len = htons(8);
    return 42;
}


static int
craft_ndp(uint8_t *buf, size_t cap)
{
    struct vg_eth *eth = (struct vg_eth *) buf;
    struct vg_ipv6hdr *ip6;
    struct vg_icmpv6hdr *ih;

    if (cap < 62) {
        return -1;
    }

    memset(buf, 0, 62);
    put_mac(eth->dst, 1);
    put_mac(eth->src, 2);
    eth->proto = htons(VG_ETH_P_IPV6);
    ip6 = (struct vg_ipv6hdr *) (buf + 14);
    ip6->ver_tc = 0x60;
    ip6->payload_len = htons(8);
    ip6->nexthdr = VG_IPPROTO_ICMPV6;
    ip6->hop_limit = 255;
    ip6->saddr[0] = 0xfe;
    ip6->saddr[1] = 0x80;
    ip6->saddr[15] = 1;
    ip6->daddr[0] = 0xff;
    ip6->daddr[1] = 0x02;
    ip6->daddr[15] = 1;
    ih = (struct vg_icmpv6hdr *) (buf + 54);
    ih->type = VG_NDISC_NS;
    return 62;
}


static int
craft_v4_udp_vlan(uint8_t *buf, size_t cap, const char *src,
    const char *dst, uint16_t sport, uint16_t dport)
{
    struct vg_eth *eth = (struct vg_eth *) buf;
    struct vg_vlan *vh;
    struct vg_iphdr *ip;
    struct vg_udphdr *uh;
    struct in_addr a, b;

    if (cap < 46) {
        return -1;
    }

    memset(buf, 0, 46);
    put_mac(eth->dst, 1);
    put_mac(eth->src, 2);
    eth->proto = htons(VG_ETH_P_8021Q);
    vh = (struct vg_vlan *) (buf + 14);
    vh->tci = htons(1);
    vh->proto = htons(VG_ETH_P_IP);
    ip = (struct vg_iphdr *) (buf + 18);
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->protocol = VG_IPPROTO_UDP;
    ip->tot_len = htons(28);
    inet_pton(AF_INET, src, &a);
    inet_pton(AF_INET, dst, &b);
    ip->saddr = a.s_addr;
    ip->daddr = b.s_addr;
    ip->check = ip_cksum(ip, 20);
    uh = (struct vg_udphdr *) (buf + 38);
    uh->source = htons(sport);
    uh->dest = htons(dport);
    uh->len = htons(8);
    return 46;
}


static int
craft_v4_frag(uint8_t *buf, size_t cap, const char *src,
    const char *dst)
{
    struct vg_eth *eth = (struct vg_eth *) buf;
    struct vg_iphdr *ip;
    struct in_addr a, b;

    if (cap < 34) {
        return -1;
    }

    memset(buf, 0, 34);
    put_mac(eth->dst, 1);
    put_mac(eth->src, 2);
    eth->proto = htons(VG_ETH_P_IP);
    ip = (struct vg_iphdr *) (buf + 14);
    ip->ver_ihl = 0x45;
    ip->ttl = 64;
    ip->protocol = VG_IPPROTO_UDP;
    ip->tot_len = htons(28);
    ip->frag_off = htons(0x0008); /* offset 8, not first fragment */
    inet_pton(AF_INET, src, &a);
    inet_pton(AF_INET, dst, &b);
    ip->saddr = a.s_addr;
    ip->daddr = b.s_addr;
    ip->check = ip_cksum(ip, 20);
    return 34;
}


static int
craft_v6_tcp(uint8_t *buf, size_t cap, const char *src,
    const char *dst, uint16_t sport, uint16_t dport)
{
    struct vg_eth *eth = (struct vg_eth *) buf;
    struct vg_ipv6hdr *ip6;
    struct vg_tcphdr *th;
    struct in6_addr a, b;

    if (cap < 74) {
        return -1;
    }

    memset(buf, 0, 74);
    put_mac(eth->dst, 1);
    put_mac(eth->src, 2);
    eth->proto = htons(VG_ETH_P_IPV6);
    ip6 = (struct vg_ipv6hdr *) (buf + 14);
    ip6->ver_tc = 0x60;
    ip6->payload_len = htons(20);
    ip6->nexthdr = VG_IPPROTO_TCP;
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, src, &a);
    inet_pton(AF_INET6, dst, &b);
    memcpy(ip6->saddr, &a, 16);
    memcpy(ip6->daddr, &b, 16);
    th = (struct vg_tcphdr *) (buf + 54);
    th->source = htons(sport);
    th->dest = htons(dport);
    th->doff_res = 5 << 4;
    th->flags = 0x02;
    return 74;
}


static int
craft_v6_udp(uint8_t *buf, size_t cap, const char *src,
    const char *dst)
{
    struct vg_eth *eth = (struct vg_eth *) buf;
    struct vg_ipv6hdr *ip6;
    struct vg_udphdr *uh;
    struct in6_addr a, b;

    if (cap < 62) {
        return -1;
    }

    memset(buf, 0, 62);
    put_mac(eth->dst, 1);
    put_mac(eth->src, 2);
    eth->proto = htons(VG_ETH_P_IPV6);
    ip6 = (struct vg_ipv6hdr *) (buf + 14);
    ip6->ver_tc = 0x60;
    ip6->payload_len = htons(8);
    ip6->nexthdr = VG_IPPROTO_UDP;
    ip6->hop_limit = 64;
    inet_pton(AF_INET6, src, &a);
    inet_pton(AF_INET6, dst, &b);
    memcpy(ip6->saddr, &a, 16);
    memcpy(ip6->daddr, &b, 16);
    uh = (struct vg_udphdr *) (buf + 54);
    uh->source = htons(12345);
    uh->dest = htons(80);
    uh->len = htons(8);
    return 62;
}


/* Prepend one minimum-size extension to an existing IPv6 packet. */
static int
prepend_ext(uint8_t *pkt, int len, uint8_t type, size_t cap)
{
    struct vg_ipv6hdr *ip6 = (void *) (pkt + 14);
    uint8_t next = ip6->nexthdr;
    int size = type == VG_IPPROTO_AH ? 12 : 8;

    if (len < 54 || (size_t) len + (size_t) size > cap) {
        return -1;
    }

    memmove(pkt + 54 + size, pkt + 54, (size_t) len - 54);
    memset(pkt + 54, 0, (size_t) size);

    if (type == VG_IPPROTO_AH) {
        pkt[55] = 1;
    }

    pkt[54] = next;
    ip6->nexthdr = type;
    ip6->payload_len = htons(ntohs(ip6->payload_len) + size);
    return len + size;
}


static int
run_pkt(struct voidgate_bpf *skel, uint8_t *pkt, int len,
    int *retval)
{
    uint8_t out[2048];
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt,
                .data_size_in = (uint32_t) len, .data_out = out,
                .data_size_out = sizeof(out), .repeat = 1);
    int err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.voidgate_xdp),
                                     &opts);

    if (err) {
        printf("  test_run failed: %d\n", err);
        return err;
    }

    *retval = (int) opts.retval;
    return 0;
}


static int
set_armed(struct voidgate_bpf *skel, uint32_t armed)
{
    __u32 key = 0;
    struct vg_cfg cfg;

    memset(&cfg, 0, sizeof(cfg));
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.cfg), &key, &cfg);
    cfg.armed = armed;
    cfg.allow_ports[0] = 22;
    cfg.allow_port_count = 1;
    return bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &key, &cfg,
                               BPF_ANY);
}


static int
add_lpm_v4(int fd, const char *cidr, uint8_t val)
{
    struct vg_cidr p;
    struct vg_lpm_v4 k;

    if (vg_parse_cidr(cidr, &p) < 0) {
        return -1;
    }

    memset(&k, 0, sizeof(k));
    k.prefixlen = p.prefixlen;
    memcpy(k.data, p.addr, 4);
    return bpf_map_update_elem(fd, &k, &val, BPF_ANY);
}


static int
add_drop_v4(struct voidgate_bpf *skel, const char *cidr)
{
    struct vg_cidr p;
    struct vg_lpm_v4 k;
    struct drop_entry e = { .reason = VG_REASON_MANUAL, .insert_time = 1 };

    if (vg_parse_cidr(cidr, &p) < 0) {
        return -1;
    }

    memset(&k, 0, sizeof(k));
    k.prefixlen = p.prefixlen;
    memcpy(k.data, p.addr, 4);
    return bpf_map_update_elem(bpf_map__fd(skel->maps.drop_v4), &k, &e,
                               BPF_ANY);
}


static int
add_drop_v6(struct voidgate_bpf *skel, const char *cidr)
{
    struct vg_cidr p;
    struct vg_lpm_v6 k;
    struct drop_entry e = { .reason = VG_REASON_MANUAL, .insert_time = 1 };

    if (vg_parse_cidr(cidr, &p) < 0) {
        return -1;
    }

    memset(&k, 0, sizeof(k));
    k.prefixlen = p.prefixlen;
    memcpy(k.data, p.addr, 16);
    return bpf_map_update_elem(bpf_map__fd(skel->maps.drop_v6), &k, &e,
                               BPF_ANY);
}


static int
add_lpm_v6(int fd, const char *cidr, uint8_t val)
{
    struct vg_cidr p;
    struct vg_lpm_v6 k;

    if (vg_parse_cidr(cidr, &p) < 0) {
        return -1;
    }

    memset(&k, 0, sizeof(k));
    k.prefixlen = p.prefixlen;
    memcpy(k.data, p.addr, 16);
    return bpf_map_update_elem(fd, &k, &val, BPF_ANY);
}


static struct vg_metrics
read_metrics(struct voidgate_bpf *skel)
{
    __u32 key = 0;
    int ncpus = libbpf_num_possible_cpus();
    struct vg_metrics *arr;
    struct vg_metrics sum;
    int i, w;

    if (ncpus <= 0) {
        ncpus = 1;
    }

    arr = calloc((size_t) ncpus, sizeof(*arr));
    memset(&sum, 0, sizeof(sum));

    if (arr == NULL) {
        return sum;
    }

    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.metrics), &key, arr) < 0) {
        free(arr);
        return sum;
    }

    w = (int) (sizeof(sum) / sizeof(uint64_t));

    for (i = 0; i < ncpus; i++) {
        uint64_t *s = (uint64_t *) &arr[i];
        uint64_t *d = (uint64_t *) &sum;
        int j;

        for (j = 0; j < w; j++) {
            d[j] += s[j];
        }
    }

    free(arr);
    return sum;
}


static void
test_prefixes(void)
{
    struct vg_cidr p, n;
    struct vg_config cfg;

    printf("prefix / config tests\n");
    expect(vg_parse_cidr("10.1.2.3/24", &p) == 0 && p.addr[0] == 10
           && p.addr[1] == 1 && p.addr[2] == 2 && p.addr[3] == 0
           && p.prefixlen == 24, "v4 parse masks host bits");
    expect(vg_parse_cidr("2001:db8::1:2:3:4/64", &p) == 0 && p.prefixlen == 64
           && p.addr[8] == 0 && p.addr[15] == 0,
           "v6 parse masks host bits");
    expect(vg_parse_cidr("198.51.100.10/32", &p) == 0
           && vg_cidr_v4_slash24(&p, &n) == 0 && n.prefixlen == 24
           && n.addr[3] == 0, "v4 /24 aggregate masks");

    vg_config_defaults(&cfg);
    expect(vg_parse_cidr("169.254.169.254/32", &p) == 0
           && vg_cidr_is_protected(&cfg, &p), "metadata IP is protected");
    expect(vg_parse_cidr("203.0.113.1/32", &p) == 0
           && !vg_cidr_is_protected(&cfg, &p), "test-net is not protected");
    expect(vg_parse_cidr("127.0.0.1/32", &p) == 0
           && vg_cidr_is_protected(&cfg, &p), "localhost is protected");

    vg_config_defaults(&cfg);
    expect(vg_parse_cidr("192.168.64.9/32", &cfg.local_cidr[0]) == 0,
           "parse vm /32");
    cfg.local_cidr_count = 1;
    expect(vg_parse_cidr("192.168.64.9/32", &p) == 0
           && vg_cidr_is_protected(&cfg, &p), "vm address is local");
    expect(vg_parse_cidr("192.168.64.8/32", &p) == 0
           && !vg_cidr_is_protected(&cfg, &p),
           "on-link neighbor is not local");
    expect(vg_parse_cidr("192.168.64.0/24", &p) == 0
           && vg_cidr_is_protected(&cfg, &p),
           "lan /24 drop would cover the vm");
    expect(vg_parse_cidr("2001:db8::9/128", &cfg.local_cidr[0]) == 0,
           "parse vm /128");
    expect(vg_parse_cidr("2001:db8::9/128", &p) == 0
           && vg_cidr_is_protected(&cfg, &p), "vm v6 address is local");
    expect(vg_parse_cidr("2001:db8::8/128", &p) == 0
           && !vg_cidr_is_protected(&cfg, &p),
           "on-link v6 neighbor is not local");
}


static void
test_v6_extensions(struct voidgate_bpf *skel)
{
    const uint8_t types[] = {
        VG_IPPROTO_HOPOPTS, VG_IPPROTO_DSTOPTS, VG_IPPROTO_ROUTING,
            VG_IPPROTO_AH, VG_IPPROTO_FRAGMENT
    };
    uint8_t pkt[256];
    size_t i;
    int len, rc, rv;

    for (i = 0; i < sizeof(types); i++) {
        len = craft_v6_tcp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10",
                           40000, 22);
        len = prepend_ext(pkt, len, types[i], sizeof(pkt));
        rc = run_pkt(skel, pkt, len, &rv);
        expect(rc == 0 && rv == XDP_PASS,
               "IPv6 extension preserves SSH exemption");

        len = craft_v6_tcp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10",
                           22, 80);
        len = prepend_ext(pkt, len, types[i], sizeof(pkt));
        rc = run_pkt(skel, pkt, len, &rv);
        expect(rc == 0 && rv == XDP_DROP,
               "IPv6 extension does not exempt remote source port 22");
    }

    len = craft_v6_tcp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10", 40000,
                       22);

    for (i = 0; i < VG_MAX_IPV6_EXT; i++) {
        len = prepend_ext(pkt, len, VG_IPPROTO_DSTOPTS, sizeof(pkt));
    }

    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS,
           "IPv6 bounded extension chain reaches SSH");
    len = prepend_ext(pkt, len, VG_IPPROTO_HOPOPTS, sizeof(pkt));
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP,
           "overlong extension chain cannot supply exempt ports");

    len = craft_v6_tcp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10", 40000,
                       22);
    len = prepend_ext(pkt, len, VG_IPPROTO_FRAGMENT, sizeof(pkt));
    pkt[57] = 8; /* Nonzero fragment offset: payload is not a TCP header. */
    len = prepend_ext(pkt, len, VG_IPPROTO_HOPOPTS, sizeof(pkt));
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP,
           "extension before non-first fragment does not expose ports");

    len = craft_v6_udp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10");
    ((struct vg_udphdr *) (pkt + 54))->dest = htons(547);
    len = prepend_ext(pkt, len, VG_IPPROTO_DSTOPTS, sizeof(pkt));
    len = prepend_ext(pkt, len, VG_IPPROTO_HOPOPTS, sizeof(pkt));
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS,
           "IPv6 chained extensions preserve DHCPv6 exemption");

    len = craft_v6_udp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10");
    ((struct vg_ipv6hdr *) (pkt + 14))->nexthdr = VG_IPPROTO_ICMPV6;
    memset(pkt + 54, 0, 8);
    pkt[54] = VG_NDISC_NS;
    len = prepend_ext(pkt, len, VG_IPPROTO_DSTOPTS, sizeof(pkt));
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS,
           "IPv6 extension preserves global-address NDP exemption");
    pkt[55] = 255;
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP,
           "truncated IPv6 extension from dropped src is XDP_DROP");
}


int
main(void)
{
    struct voidgate_bpf *skel;
    uint8_t pkt[256];
    int len, rc, rv;
    struct vg_metrics before, after;
    uint8_t one = 1;

    test_prefixes();

    bump_memlock();
    skel = voidgate_bpf__open_and_load();

    if (skel == NULL) {
        fprintf(stderr, "failed to load BPF object (need root / CAP_BPF)\n");
        return 1;
    }

    printf("voidGate XDP tests\n");

    /* IDLE: always PASS, only coarse counters */
    set_armed(skel, 0);
    len = craft_v4_udp(pkt, sizeof(pkt), "203.0.113.1", "198.51.100.10", 12345,
                       80);
    before = read_metrics(skel);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS, "idle UDP is XDP_PASS");
    after = read_metrics(skel);
    expect(after.rx_pkts == before.rx_pkts + 1, "idle increments rx_pkts");
    expect(after.dropped == before.dropped, "idle does not drop");

    /* Populate local + allow */
    add_lpm_v4(bpf_map__fd(skel->maps.local_v4), "198.51.100.10/32", one);
    add_lpm_v6(bpf_map__fd(skel->maps.local_v6), "2001:db8::10/128", one);
    add_lpm_v4(bpf_map__fd(skel->maps.allow_v4), "192.0.2.99/32", one);

    set_armed(skel, 1);
    add_drop_v4(skel, "203.0.113.1/32");

    len = craft_v4_udp(pkt, sizeof(pkt), "203.0.113.1", "198.51.100.10", 12345,
                       80);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP, "armed + dropped src is XDP_DROP");

    len = craft_v4_tcp(pkt, sizeof(pkt), "203.0.113.1", "198.51.100.10", 40000,
                       22);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS,
           "SSH dport 22 passes even from dropped src");

    len = craft_v4_tcp(pkt, sizeof(pkt), "203.0.113.1", "198.51.100.10", 22,
                       80);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP,
           "TCP sport 22 from dropped src is not a whitelist");

    len = craft_v4_udp(pkt, sizeof(pkt), "203.0.113.1", "198.51.100.10", 12345,
                       67);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS, "DHCP UDP 67 passes from dropped src");

    len = craft_v4_udp_vlan(pkt, sizeof(pkt), "203.0.113.1", "198.51.100.10",
                            12345, 80);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP, "VLAN-tagged dropped src is XDP_DROP");

    len = craft_v4_frag(pkt, sizeof(pkt), "203.0.113.1", "198.51.100.10");
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP,
           "non-first fragment from dropped src is XDP_DROP");

    len = craft_v4_udp(pkt, sizeof(pkt), "192.0.2.99", "198.51.100.10", 12345,
                       80);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS, "allow_v4 prefix passes");

    len = craft_v4_udp(pkt, sizeof(pkt), "198.51.100.8", "198.51.100.10", 12345,
                       80);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS, "non-dropped src is XDP_PASS when armed");

    len = craft_ndp(pkt, sizeof(pkt));
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS, "IPv6 NDP always PASS");

    add_drop_v6(skel, "2001:db8::bad/128");
    len = craft_v6_udp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10");
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP, "armed + dropped IPv6 src is XDP_DROP");

    len = craft_v6_tcp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10", 40000,
                       22);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS,
           "IPv6 SSH dport 22 passes from dropped src");

    len = craft_v6_tcp(pkt, sizeof(pkt), "2001:db8::bad", "2001:db8::10", 22,
                       80);
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_DROP,
           "IPv6 TCP sport 22 from dropped src is not a whitelist");

    test_v6_extensions(skel);

    len = craft_v6_udp(pkt, sizeof(pkt), "2001:db8::1", "2001:db8::10");
    rc = run_pkt(skel, pkt, len, &rv);
    expect(rc == 0 && rv == XDP_PASS, "non-dropped IPv6 is XDP_PASS");

    voidgate_bpf__destroy(skel);
    printf("%s\n", g_fail ? "FAILED" : "all tests passed");
    return g_fail ? 1 : 0;
}
