
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_POLICY_H_INCLUDED_
#define _VG_POLICY_H_INCLUDED_

#include "config.h"
#include "list.h"
#include "maps.h"

#include <stddef.h>
#include <time.h>

enum vg_state { VG_IDLE = 0, VG_ACTIVE = 1 };

#define VG_SNAP_BUCKETS  4096

/* One listed drop. Records live in drop_pool and never move, so the list
 * nodes below stay valid while linked.
 */
struct vg_drop_rec {
    struct vg_cidr          cidr;
    uint32_t                reason;
    time_t                  inserted;
    time_t                  expires;    /* VG_REASON_TIMED only */
    struct vg_hlist_node    hash;       /* drop_heads bucket chain */
    struct vg_list          all;        /* drop_all, or drop_free if unused */
};


struct vg_snap_ent;

struct vg_ctrl {
    enum vg_state           state;
    struct vg_config       *cfg;
    struct vg_maps         *maps;
    char                    cfg_path[VG_CFG_PATH_MAX];
    char                    iface_override[VG_MAX_IFACE];
    struct vg_metrics       last_m;
    int                     have_last_m;
    struct timespec         last_tick;
    int                     have_last_tick;
    double                  rx_pps;
    double                  rx_bps;
    time_t                  quiet_since;
    struct vg_drop_rec     *drop_pool;      /* 2 x drop_map_size (v4 + v6) */
    unsigned                drop_pool_cap;
    unsigned                drop_used;      /* pool records ever handed out */
    struct vg_list          drop_free;      /* lifted records, for reuse */
    struct vg_list          drop_all;       /* listed drops, oldest first */
    int                     drop_count;
    struct vg_hlist_head   *drop_heads;
    unsigned                drop_nbuckets;  /* power of two */
    int                     drops_new[VG_REASON_TIMED + 1]; /* this tick */
    int                     drops_again;    /* re-drops this tick */
    struct vg_snap_ent     *snap_pool;
    struct vg_snap_ent     *snap_free;
    struct vg_snap_ent     *snaps[VG_SNAP_BUCKETS];
    unsigned                snap_cap;
    uint32_t                snap_gen;
};


int vg_ctrl_init(struct vg_ctrl *c, struct vg_config *cfg,
    struct vg_maps *maps, const char *cfg_path,
    const char *iface_ov);
void vg_ctrl_free(struct vg_ctrl *c);
int vg_ctrl_arm(struct vg_ctrl *c, const char *why);
int vg_ctrl_disarm(struct vg_ctrl *c, const char *why);
int vg_ctrl_tick(struct vg_ctrl *c);
int vg_ctrl_drop(struct vg_ctrl *c, const struct vg_cidr *p, uint32_t reason);
int vg_ctrl_drop_ttl(struct vg_ctrl *c, const struct vg_cidr *p,
    uint32_t ttl);
int vg_ctrl_undrop(struct vg_ctrl *c, const struct vg_cidr *p);
int vg_ctrl_prune_protected(struct vg_ctrl *c);

#if (VG_CTRL_TEST)
unsigned vg_ctrl_snap_count(const struct vg_ctrl *c);
struct vg_drop_rec *vg_ctrl_drops_find(struct vg_ctrl *c,
    const struct vg_cidr *p);
int vg_ctrl_drops_check(struct vg_ctrl *c);
#endif /* VG_CTRL_TEST */

#endif /* _VG_POLICY_H_INCLUDED_ */
