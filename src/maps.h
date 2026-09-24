
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_MAPS_H_INCLUDED_
#define _VG_MAPS_H_INCLUDED_

#include "bpf/voidgate.h"
#include "config.h"
#include "ipaddr.h"

#include <stddef.h>
#include <stdint.h>

struct voidgate_bpf;

struct vg_maps {
    struct voidgate_bpf  *skel;
    int                   ncpus;
    int                   ifindex;
    uint32_t              attach_flags;
    int                   attached;
    void                 *sum_scratch;
    size_t                sum_scratch_size;
};


int vg_maps_open(struct vg_maps *m, struct vg_config *cfg);
void vg_maps_close(struct vg_maps *m);
int vg_xdp_attach(struct vg_maps *m, const struct vg_config *cfg);
void vg_xdp_detach(struct vg_maps *m);

int vg_cfg_commit(struct vg_maps *m, uint32_t armed,
    const struct vg_config *cfg);

int vg_metrics_read(struct vg_maps *m, struct vg_metrics *out);
int vg_sum_percpu(struct vg_maps *m, int map_fd, const void *key,
    size_t val_size, void *out_sum);

typedef void (*vg_remote_pt)(int family, const uint8_t *addr,
    const struct host_counters *sum, void *ctx);

/* Walk remote_v4 then remote_v6, at most `budget` keys each.
 * Returns 1 if both maps reached EOF, 0 if either walk was truncated,
 * -1 on error.
 */
int vg_remote_foreach(struct vg_maps *m, uint32_t budget, vg_remote_pt fn,
    void *ctx);

int vg_drop_add(struct vg_maps *m, const struct vg_cidr *p, uint32_t reason,
    uint32_t now);
int vg_drop_del(struct vg_maps *m, const struct vg_cidr *p);
int vg_drop_flush(struct vg_maps *m);

int vg_populate_local(struct vg_maps *m, struct vg_config *cfg);
int vg_populate_allow(struct vg_maps *m, const struct vg_config *cfg);

int vg_maps_metrics_fd(struct vg_maps *m);
int vg_maps_remote_v4_fd(struct vg_maps *m);
int vg_maps_remote_v6_fd(struct vg_maps *m);

#endif /* _VG_MAPS_H_INCLUDED_ */
