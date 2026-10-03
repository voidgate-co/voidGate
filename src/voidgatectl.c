
/* SPDX-License-Identifier: Apache-2.0 */

#include "bpf/voidgate.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
    struct sockaddr_un addr;
    char cmd[256], buf[8192];
    int fd, i, failed = 0, replied = 0;
    ssize_t n;

    if (argc < 2) {
        fprintf(stderr, "usage: voidgatectl status|stats|drops|arm|"
                "disarm|drop <cidr> [ttl=<sec>]|undrop <cidr>|reload\n");
        return 1;
    }

    cmd[0] = 0;

    for (i = 1; i < argc; i++) {
        if (i > 1) {
            strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        }

        strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
    }

    strncat(cmd, "\n", sizeof(cmd) - strlen(cmd) - 1);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", VG_SOCK_PATH);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "voidgatectl: connect %s: %s\n", VG_SOCK_PATH,
                strerror(errno));
        close(fd);
        return 1;
    }

    if (write(fd, cmd, strlen(cmd)) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    shutdown(fd, SHUT_WR);
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = 0;

        /* Scripts need a refused command to fail. */
        if (!replied && strncmp(buf, "error", 5) == 0) {
            failed = 1;
        }

        replied = 1;
        fputs(buf, stdout);
    }
    close(fd);

    return failed || !replied;
}
