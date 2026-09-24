
/* SPDX-License-Identifier: Apache-2.0 */

#include "policy.h"
#include "ipaddr.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>


static void set_v4_item(int i, uint32_t id, uint64_t pkts);
static void force_dt(struct vg_ctrl *c);
static int tick(struct vg_ctrl *c);

#define FOREACH_MAX  64

static struct vg_cidr deleted;
static int complete_scan = 1;
static int nitems;
static struct {
    int                   family;
    uint8_t               addr[16];
    struct host_counters  c;
} items[FOREACH_MAX];

int
vg_drop_del(struct vg_maps *m, const struct vg_cidr *p)
{
    (void) m;
    deleted = *p;
    return 0;
}


int
vg_drop_add(struct vg_maps *m, const struct vg_cidr *p, uint32_t reason,
    uint32_t now)
{
    (void) m;
    (void) p;
    (void) reason;
    (void) now;
    return 0;
}


int
vg_cfg_commit(struct vg_maps *m, uint32_t armed,
    const struct vg_config *cfg)
{
    (void) m;
    (void) armed;
    (void) cfg;
    return 0;
}


int
vg_drop_flush(struct vg_maps *m)
{
    (void) m;
    return 0;
}


int
vg_populate_allow(struct vg_maps *m, const struct vg_config *cfg)
{
    (void) m;
    (void) cfg;
    return 0;
}


int
vg_populate_local(struct vg_maps *m, const struct vg_config *cfg)
{
    (void) m;
    (void) cfg;
    return 0;
}


int
vg_metrics_read(struct vg_maps *m, struct vg_metrics *out)
{
    (void) m;
    memset(out, 0, sizeof(*out));
    return 0;
}


int
vg_remote_foreach(struct vg_maps *m, uint32_t budget, vg_remote_pt fn,
    void *ctx)
{
    int i;

    (void) m;
    (void) budget;

    for (i = 0; i < nitems; i++) {
        fn(items[i].family, items[i].addr, &items[i].c, ctx);
    }

    return complete_scan;
}


static void
set_v4_item(int i, uint32_t id, uint64_t pkts)
{
    memset(&items[i], 0, sizeof(items[i]));
    items[i].family = AF_INET;
    memcpy(items[i].addr, &id, sizeof(id));
    items[i].c.in_pkts = pkts;
}


static void
force_dt(struct vg_ctrl *c)
{
    clock_gettime(CLOCK_MONOTONIC, &c->last_tick);
    c->last_tick.tv_sec -= 1;
    c->have_last_tick = 1;
    c->have_last_m = 1;
}


static int
tick(struct vg_ctrl *c)
{
    force_dt(c);
    return vg_ctrl_tick(c);
}


int
main(void)
{
    struct vg_config cfg;
    struct vg_ctrl c;
    struct vg_cidr expired, manual;
    int i, drops_before;

    vg_config_defaults(&cfg);
    cfg.remote_map_size = 16;
    assert(vg_ctrl_init(&c, &cfg, NULL, NULL, NULL) == 0);
    assert(c.snap_cap == 32);
    c.state = VG_ACTIVE;

    assert(vg_parse_cidr("203.0.113.1/32", &expired) == 0);
    assert(vg_parse_cidr("2001:db8::bad/128", &manual) == 0);
    c.drops[0] = (struct vg_drop_rec){ .cidr = expired,
                                       .reason = VG_REASON_POLICY };
    c.drops[1] = (struct vg_drop_rec){ .cidr = manual,
                                       .reason = VG_REASON_MANUAL };
    c.drop_count = 2;
    nitems = 0;
    complete_scan = 1;
    assert(tick(&c) == 0);
    assert(memcmp(&deleted, &expired, sizeof(expired)) == 0);
    assert(c.drop_count == 1 && c.drops[0].reason == VG_REASON_MANUAL);
    assert(memcmp(&c.drops[0].cidr, &manual, sizeof(manual)) == 0);

    /* Truncated walks must keep snapshots so a second look can compute a
     * rate. */
    complete_scan = 0;
    nitems = 1;
    set_v4_item(0, 10, 1000);
    drops_before = c.drop_count;
    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 1);
    assert(c.drop_count == drops_before);
    items[0].c.in_pkts = 1000 + cfg.threshold_pps + 1;
    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 1);
    assert(c.drop_count == drops_before + 1);

    /* A newly observed leftover counter is a baseline, not a flood. */
    nitems = 1;
    set_v4_item(0, 11, 1000000000);
    drops_before = c.drop_count;
    assert(tick(&c) == 0);
    assert(c.drop_count == drops_before);

    /* Truncated walk retains remotes that were not in this batch. */
    nitems = 8;

    for (i = 0; i < 8; i++) {
        set_v4_item(i, 100 + (uint32_t) i, 1);
    }

    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 8 + 2); /* ids 10, 11 plus 100..107 */
    nitems = 8;

    for (i = 0; i < 8; i++) {
        set_v4_item(i, 200 + (uint32_t) i, 1);
    }

    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 18);

    /* Complete scan prunes remotes that left the map. */
    complete_scan = 1;
    nitems = 3;
    set_v4_item(0, 200, 1);
    set_v4_item(1, 201, 1);
    set_v4_item(2, 202, 1);
    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 3);

    complete_scan = 1;
    nitems = 0;
    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 0);

    /* At cap, truncated walks keep existing entries and refuse new ones. */
    complete_scan = 0;
    nitems = 32;

    for (i = 0; i < 32; i++) {
        set_v4_item(i, 300 + (uint32_t) i, 1);
    }

    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 32);
    nitems = 32;

    for (i = 0; i < 32; i++) {
        set_v4_item(i, 400 + (uint32_t) i, 1);
    }

    assert(tick(&c) == 0);
    assert(vg_ctrl_snap_count(&c) == 32);

    vg_ctrl_free(&c);
    puts("control-plane regression tests passed");
    return 0;
}
