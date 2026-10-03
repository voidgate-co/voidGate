
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_CTL_SERVER_H_INCLUDED_
#define _VG_CTL_SERVER_H_INCLUDED_

struct vg_ctrl;


/* 1 if a live daemon accepts connections on path, else 0. */
int vg_ctl_server_alive(const char *path);
int vg_ctl_server_listen(const char *path, const char *group);
/* The caller sets socket timeouts and closes fd after handling. */
void vg_ctl_server_handle(struct vg_ctrl *ctrl, int fd);

#endif /* _VG_CTL_SERVER_H_INCLUDED_ */
