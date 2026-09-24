
/* SPDX-License-Identifier: Apache-2.0 */

#include "maps.h"
#include "log.h"

#include "bpf/voidgate.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>


static void bump_memlock(void);
static int libbpf_print(enum libbpf_print_level level, const char *fmt,
    va_list args);
static size_t sum_scratch_need(int ncpus);
static int foreach_family(struct vg_maps *m, int fd, int family, size_t ksz,
    uint32_t budget, vg_remote_pt fn, void *ctx);
static int lpm_update(int fd, const struct vg_cidr *p, const void *val);
static int lpm_delete(int fd, const struct vg_cidr *p);
static int flush_lpm(int fd, int v6);

static void
bump_memlock(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

    if (setrlimit(RLIMIT_MEMLOCK, &r) < 0) {
        vg_warn("setrlimit(RLIMIT_MEMLOCK) failed: %s", strerror(errno));
    }
}


static int
libbpf_print(enum libbpf_print_level level, const char *fmt,
    va_list args)
{
    enum libbpf_print_level max_level =
        vg_verbose >= 2 ? LIBBPF_INFO : LIBBPF_WARN;

    if (level > max_level) {
        return 0;
    }

    return vfprintf(stderr, fmt, args);
}


static size_t
sum_scratch_need(int ncpus)
{
    size_t a = sizeof(struct host_counters);
    size_t b = sizeof(struct vg_metrics);

    return (size_t) ncpus * (a > b ? a : b);
}


int
vg_maps_open(struct vg_maps *m, struct vg_config *cfg)
{
    int err;

    memset(m, 0, sizeof(*m));

    m->ifindex = (int) if_nametoindex(cfg->interface);

    bump_memlock();
    libbpf_set_print(libbpf_print);

    m->ncpus = libbpf_num_possible_cpus();

    if (m->ncpus <= 0) {
        m->ncpus = 1;
    }

    /* Reuse one buffer sized for either counter type across all CPUs. */
    m->sum_scratch_size = sum_scratch_need(m->ncpus);
    m->sum_scratch = calloc(1, m->sum_scratch_size);

    if (m->sum_scratch == NULL) {
        vg_die("out of memory");
    }

    m->skel = voidgate_bpf__open();

    if (m->skel == NULL) {
        free(m->sum_scratch);
        m->sum_scratch = NULL;
        vg_die("failed to open BPF object");
    }

    if (cfg->remote_map_size) {
        bpf_map__set_max_entries(m->skel->maps.remote_v4, cfg->remote_map_size);
        bpf_map__set_max_entries(m->skel->maps.remote_v6, cfg->remote_map_size);
    }

    if (cfg->drop_map_size) {
        bpf_map__set_max_entries(m->skel->maps.drop_v4, cfg->drop_map_size);
        bpf_map__set_max_entries(m->skel->maps.drop_v6, cfg->drop_map_size);
    }

    err = voidgate_bpf__load(m->skel);

    if (err) {
        voidgate_bpf__destroy(m->skel);
        m->skel = NULL;
        free(m->sum_scratch);
        m->sum_scratch = NULL;
        vg_die("failed to load BPF object: %d", err);
    }

    return 0;
}


void
vg_maps_close(struct vg_maps *m)
{
    if (m == NULL) {
        return;
    }

    vg_xdp_detach(m);

    if (m->skel != NULL) {
        voidgate_bpf__destroy(m->skel);
        m->skel = NULL;
    }

    free(m->sum_scratch);
    m->sum_scratch = NULL;
}


int
vg_xdp_attach(struct vg_maps *m, const struct vg_config *cfg)
{
    int prog_fd;
    uint32_t flags;
    int err;

    if (m->skel == NULL) {
        vg_warn("XDP attach: BPF object not loaded");
        return -1;
    }

    prog_fd = bpf_program__fd(m->skel->progs.voidgate_xdp);

    if (prog_fd < 0) {
        vg_warn("XDP attach: missing program fd");
        return -1;
    }

    /* Replace any leftover program from a crashed daemon. */

    if (strcmp(cfg->xdp_mode, "skb") == 0) {
        flags = XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(m->ifindex, prog_fd, flags, NULL);

    } else if (strcmp(cfg->xdp_mode, "native") == 0) {
        flags = XDP_FLAGS_DRV_MODE;
        err = bpf_xdp_attach(m->ifindex, prog_fd, flags, NULL);

    } else {
        flags = XDP_FLAGS_DRV_MODE;
        err = bpf_xdp_attach(m->ifindex, prog_fd, flags, NULL);

        if (err) {
            vg_warn("native XDP attach failed (%s), falling back to skb",
                    strerror(-err));
            flags = XDP_FLAGS_SKB_MODE;
            err = bpf_xdp_attach(m->ifindex, prog_fd, flags, NULL);
        }
    }

    if (err) {
        vg_warn("XDP attach failed: %s", strerror(-err));
        return -1;
    }

    m->attach_flags = flags;
    m->attached = 1;
    vg_log("attached XDP on ifindex %d flags 0x%x (%s)", m->ifindex, flags,
           flags & XDP_FLAGS_DRV_MODE ? "native" : "skb");
    return 0;
}


void
vg_xdp_detach(struct vg_maps *m)
{
    if (m->attached == 0) {
        return;
    }

    bpf_xdp_detach(m->ifindex, m->attach_flags, NULL);
    m->attached = 0;
    vg_log("detached XDP from ifindex %d", m->ifindex);
}


int
vg_maps_metrics_fd(struct vg_maps *m)
{
    return bpf_map__fd(m->skel->maps.metrics);
}


int
vg_maps_remote_v4_fd(struct vg_maps *m)
{
    return bpf_map__fd(m->skel->maps.remote_v4);
}


int
vg_maps_remote_v6_fd(struct vg_maps *m)
{
    return bpf_map__fd(m->skel->maps.remote_v6);
}


static int
foreach_family(struct vg_maps *m, int fd, int family, size_t ksz,
    uint32_t budget, vg_remote_pt fn, void *ctx)
{
    uint8_t cur[16], next[16];
    int first = 1;
    uint32_t visited = 0;

    if (fd < 0) {
        return -1;
    }

    memset(cur, 0, sizeof(cur));
    memset(next, 0, sizeof(next));
    while (visited < budget
           && bpf_map_get_next_key(fd, first ? NULL : cur, next) == 0)
    {
        struct host_counters sum;

        first = 0;
        memcpy(cur, next, ksz);
        visited++;

        if (vg_sum_percpu(m, fd, cur, sizeof(sum), &sum) == 0) {
            fn(family, cur, &sum, ctx);
        }
    }

    if (visited < budget) {
        return 1;
    }

    if (bpf_map_get_next_key(fd, first ? NULL : cur, next) != 0) {
        return 1;
    }

    return 0;
}


int
vg_remote_foreach(struct vg_maps *m, uint32_t budget, vg_remote_pt fn,
    void *ctx)
{
    int c4, c6;

    if (m == NULL || fn == NULL) {
        return -1;
    }

    if (budget == 0) {
        budget = VG_REMOTE_MAP_MAX;
    }

    c4 = foreach_family(m, vg_maps_remote_v4_fd(m), AF_INET, 4, budget, fn,
                        ctx);
    c6 = foreach_family(m, vg_maps_remote_v6_fd(m), AF_INET6, 16, budget, fn,
                        ctx);

    if (c4 < 0 || c6 < 0) {
        return -1;
    }

    return c4 && c6;
}


int
vg_cfg_commit(struct vg_maps *m, uint32_t armed,
    const struct vg_config *cfg)
{
    __u32 key = 0;
    struct vg_cfg bc;
    int i, fd;

    memset(&bc, 0, sizeof(bc));
    bc.armed = armed;

    if (cfg != NULL) {
        bc.allow_port_count = (uint16_t) cfg->allow_port_count;

        if (bc.allow_port_count > VG_MAX_ALLOW_PORTS) {
            bc.allow_port_count = VG_MAX_ALLOW_PORTS;
        }

        for (i = 0; i < bc.allow_port_count; i++) {
            bc.allow_ports[i] = cfg->allow_ports[i];
        }
    }

    fd = bpf_map__fd(m->skel->maps.cfg);
    return bpf_map_update_elem(fd, &key, &bc, BPF_ANY);
}


int
vg_sum_percpu(struct vg_maps *m, int map_fd, const void *key,
    size_t val_size, void *out_sum)
{
    int ncpus = m->ncpus;
    uint8_t *buf;
    size_t need, i, words;
    int cpu;

    if (ncpus <= 0) {
        ncpus = 1;
    }

    need = (size_t) ncpus * val_size;

    if (m->sum_scratch == NULL || m->sum_scratch_size < need) {
        return -1;
    }

    buf = m->sum_scratch;
    memset(buf, 0, need);
    memset(out_sum, 0, val_size);

    if (bpf_map_lookup_elem(map_fd, key, buf) < 0) {
        return -1;
    }

    words = val_size / sizeof(uint64_t);

    for (cpu = 0; cpu < ncpus; cpu++) {
        uint64_t *src = (uint64_t *) (buf + (size_t) cpu * val_size);
        uint64_t *dst = out_sum;

        for (i = 0; i < words; i++) {
            dst[i] += src[i];
        }
    }

    return 0;
}


int
vg_metrics_read(struct vg_maps *m, struct vg_metrics *out)
{
    __u32 key = 0;

    return vg_sum_percpu(m, vg_maps_metrics_fd(m), &key, sizeof(*out), out);
}


static int
lpm_update(int fd, const struct vg_cidr *p, const void *val)
{
    if (p->family == AF_INET) {
        struct vg_lpm_v4 k = { .prefixlen = p->prefixlen };

        memcpy(k.data, p->addr, 4);
        return bpf_map_update_elem(fd, &k, val, BPF_ANY);
    }

    {
        struct vg_lpm_v6 k = { .prefixlen = p->prefixlen };

        memcpy(k.data, p->addr, 16);
        return bpf_map_update_elem(fd, &k, val, BPF_ANY);
    }
}


static int
lpm_delete(int fd, const struct vg_cidr *p)
{
    if (p->family == AF_INET) {
        struct vg_lpm_v4 k = { .prefixlen = p->prefixlen };

        memcpy(k.data, p->addr, 4);
        return bpf_map_delete_elem(fd, &k);
    }

    {
        struct vg_lpm_v6 k = { .prefixlen = p->prefixlen };

        memcpy(k.data, p->addr, 16);
        return bpf_map_delete_elem(fd, &k);
    }
}


int
vg_drop_add(struct vg_maps *m, const struct vg_cidr *p, uint32_t reason,
    uint32_t now)
{
    struct drop_entry e = { .reason = reason, .insert_time = now };
    int fd = p->family == AF_INET ? bpf_map__fd(m->skel->maps.drop_v4)
             : bpf_map__fd(m->skel->maps.drop_v6);

    return lpm_update(fd, p, &e);
}


int
vg_drop_del(struct vg_maps *m, const struct vg_cidr *p)
{
    int fd = p->family == AF_INET ? bpf_map__fd(m->skel->maps.drop_v4)
             : bpf_map__fd(m->skel->maps.drop_v6);

    return lpm_delete(fd, p);
}


static int
flush_lpm(int fd, int v6)
{
    int err;
    uint8_t key[sizeof(struct vg_lpm_v6)];
    uint8_t next[sizeof(struct vg_lpm_v6)];
    size_t ksz = v6 ? sizeof(struct vg_lpm_v6) : sizeof(struct vg_lpm_v4);

    memset(key, 0, sizeof(key));

    if (bpf_map_get_next_key(fd, NULL, next) < 0) {
        return 0;
    }

    memcpy(key, next, ksz);

    for ( ;; ) {
        err = bpf_map_get_next_key(fd, key, next);
        bpf_map_delete_elem(fd, key);

        if (err < 0) {
            break;
        }

        memcpy(key, next, ksz);
    }

    return 0;
}


int
vg_drop_flush(struct vg_maps *m)
{
    flush_lpm(bpf_map__fd(m->skel->maps.drop_v4), 0);
    flush_lpm(bpf_map__fd(m->skel->maps.drop_v6), 1);
    return 0;
}


int
vg_populate_local(struct vg_maps *m, const struct vg_config *cfg)
{
    int i, fd4, fd6;
    uint8_t one = 1;

    fd4 = bpf_map__fd(m->skel->maps.local_v4);
    fd6 = bpf_map__fd(m->skel->maps.local_v6);
    flush_lpm(fd4, 0);
    flush_lpm(fd6, 1);

    for (i = 0; i < cfg->local_cidr_count; i++) {
        char buf[80];
        int fd = cfg->local_cidr[i].family == AF_INET ? fd4 : fd6;

        vg_cidr_to_str(&cfg->local_cidr[i], buf, sizeof(buf));

        if (lpm_update(fd, &cfg->local_cidr[i], &one) < 0) {
            vg_warn("failed to add local %s: %s", buf, strerror(errno));

        } else {
            vg_log("local network %s", buf);
        }
    }

    return 0;
}


int
vg_populate_allow(struct vg_maps *m, const struct vg_config *cfg)
{
    int i, fd4, fd6;
    uint8_t one = 1;

    fd4 = bpf_map__fd(m->skel->maps.allow_v4);
    fd6 = bpf_map__fd(m->skel->maps.allow_v6);
    flush_lpm(fd4, 0);
    flush_lpm(fd6, 1);

    for (i = 0; i < cfg->allow_cidr_count; i++) {
        int fd = cfg->allow_cidr[i].family == AF_INET ? fd4 : fd6;

        if (lpm_update(fd, &cfg->allow_cidr[i], &one) < 0) {
            vg_warn("failed to add allow prefix");
        }
    }

    return 0;
}
