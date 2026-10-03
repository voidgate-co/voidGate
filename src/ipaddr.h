
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_IPADDR_H_INCLUDED_
#define _VG_IPADDR_H_INCLUDED_

#include <stdint.h>
#include <netinet/in.h>

struct vg_cidr {
    int      family; /* AF_INET or AF_INET6 */
    uint8_t  addr[16];
    uint8_t  prefixlen;
};


int vg_parse_cidr(const char *s, struct vg_cidr *out);
int vg_parse_cidr_len(const char *s, size_t n, struct vg_cidr *out);
void vg_cidr_mask(struct vg_cidr *p);
int vg_cidr_contains(const struct vg_cidr *hay,
    const struct vg_cidr *needle);
int vg_cidr_covers_or_overlaps(const struct vg_cidr *a,
    const struct vg_cidr *b);
void vg_cidr_to_str(const struct vg_cidr *p, char *buf, size_t buflen);
int vg_cidr_v4_slash24(const struct vg_cidr *host, struct vg_cidr *net);
int vg_cidr_v6_slash64(const struct vg_cidr *host, struct vg_cidr *net);
int vg_netmask_to_prefixlen(int family, const void *mask);

#endif /* _VG_IPADDR_H_INCLUDED_ */
