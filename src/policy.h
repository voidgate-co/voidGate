
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_POLICY_H_INCLUDED_
#define _VG_POLICY_H_INCLUDED_

#include "config.h"
#include "maps.h"

#include <stddef.h>
#include <time.h>

enum vg_state { VG_IDLE = 0, VG_ACTIVE = 1 };

#define VG_SNAP_BUCKETS  4096

struct vg_drop_rec {
    struct vg_cidr    cidr;
    uint32_t          reason;
    time_t            inserted;
};


struct vg_snap_ent;

struct vg_ctrl {
    enum vg_state           state;
    struct vg_config_file  *cfg;
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
    struct vg_drop_rec     *drops;
    int                     drop_count;
    int                     drop_cap;
    struct vg_snap_ent     *snap_pool;
    struct vg_snap_ent     *snap_free;
    struct vg_snap_ent     *snaps[VG_SNAP_BUCKETS];
    unsigned                snap_cap;
    uint32_t                snap_gen;
};


int vg_ctrl_init(struct vg_ctrl *c, struct vg_config_file *cfg,
    struct vg_maps *maps, const char *cfg_path,
    const char *iface_ov);
void vg_ctrl_free(struct vg_ctrl *c);
int vg_ctrl_arm(struct vg_ctrl *c, const char *why);
int vg_ctrl_disarm(struct vg_ctrl *c, const char *why);
int vg_ctrl_tick(struct vg_ctrl *c);
int vg_ctrl_drop(struct vg_ctrl *c, const struct vg_cidr *p, uint32_t reason);
int vg_ctrl_undrop(struct vg_ctrl *c, const struct vg_cidr *p);

#if (VG_CTRL_TEST)
unsigned vg_ctrl_snap_count(const struct vg_ctrl *c);
#endif /* VG_CTRL_TEST */

#endif /* _VG_POLICY_H_INCLUDED_ */
