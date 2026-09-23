
/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
#include "ctl_server.h"
#include "http.h"
#include "policy.h"
#include "log.h"
#include "maps.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


static void on_signal(int sig);
static void sock_timeout(int fd);
static long elapsed_ms(const struct timespec *a, const struct timespec *b);
static void usage(const char *argv0);
static void redirect_log(int fd);
static int daemon_start(int log_fd);

static volatile sig_atomic_t g_stop;

static void
on_signal(int sig)
{
    (void) sig;
    g_stop = 1;
}


static void
sock_timeout(int fd)
{
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}


static long
elapsed_ms(const struct timespec *a, const struct timespec *b)
{
    return (a->tv_sec - b->tv_sec) * 1000L
           + (a->tv_nsec - b->tv_nsec) / 1000000L;
}


static void
usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-d] [-c config] [-i iface] [-v|-vv]\n",
            argv0);
}


static void
redirect_log(int fd)
{
    if (dup2(fd, STDERR_FILENO) < 0) {
        vg_die("redirect log: %s", strerror(errno));
    }

    if (fd != STDERR_FILENO) {
        close(fd);
    }
}


/* Return the readiness pipe in the daemon; the original parent exits. */
static int
daemon_start(int log_fd)
{
    int      fd, pipefd[2];
    pid_t    child, daemon_pid;
    ssize_t  n;

    /* Keep pipe descriptors above stderr even if the caller closed stdio. */
    for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
        if (fcntl(fd, F_GETFD) < 0) {
            if (errno != EBADF || open("/dev/null", O_RDWR) < 0) {
                vg_die("reserve standard streams: %s", strerror(errno));
            }
        }
    }

    if (pipe(pipefd) < 0) {
        vg_die("startup pipe: %s", strerror(errno));
    }

    fflush(NULL);
    child = fork();

    if (child < 0) {
        vg_die("fork: %s", strerror(errno));
    }

    if (child > 0) {
        close(pipefd[1]);
        close(log_fd);

        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) { /* void */ }

        do {
            n = read(pipefd[0], &daemon_pid, sizeof(daemon_pid));
        } while (n < 0 && errno == EINTR);

        close(pipefd[0]);

        if (n != sizeof(daemon_pid)) {
            vg_die("daemon startup failed; check the log file");
        }

        fprintf(stderr, "voidgate daemon started (pid %ld)\n",
                (long) daemon_pid);
        exit(0);
    }

    close(pipefd[0]);
    redirect_log(log_fd);

    if (setsid() < 0) {
        vg_die("setsid: %s", strerror(errno));
    }

    child = fork();

    if (child < 0) {
        vg_die("fork: %s", strerror(errno));
    }

    if (child > 0) {
        _exit(0);
    }

    fd = open("/dev/null", O_RDWR);

    if (fd < 0) {
        vg_die("open /dev/null: %s", strerror(errno));
    }

    if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0) {
        vg_die("redirect standard streams: %s", strerror(errno));
    }

    if (fd > STDERR_FILENO) {
        close(fd);
    }

    /* Keep cwd so relative config paths still work on reload. */
    return pipefd[1];
}


int
main(int argc, char **argv)
{
    struct vg_config_file cfg;
    struct vg_maps maps;
    struct vg_ctrl ctrl;
    const char *cfg_path = "/etc/voidgate/voidgate.conf";
    const char *iface_ov = NULL;
    int opt, ctl_fd = -1, http_fd = -1;
    int daemon_mode = 0, log_fd, ready_fd = -1, result = 0;
    struct sigaction sa;
    struct timespec last_tick;

    while ((opt = getopt(argc, argv, "c:i:dhv")) != -1) {
        switch (opt) {
        case 'c':
            cfg_path = optarg;
            break;
        case 'i':
            iface_ov = optarg;
            break;
        case 'v':
            if (vg_verbose < 2) {
                vg_verbose++;
            }
            break;
        case 'd':
            daemon_mode = 1;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (vg_config_load(cfg_path, &cfg) < 0) {
        vg_die("failed to load config %s", cfg_path);
    }

    if (iface_ov != NULL) {
        snprintf(cfg.interface, sizeof(cfg.interface), "%s", iface_ov);
    }

    if (if_nametoindex(cfg.interface) == 0) {
        vg_die("unknown interface %s", cfg.interface);
    }

    log_fd = open(cfg.log_file, O_WRONLY | O_CREAT | O_APPEND, 0640);

    if (log_fd < 0) {
        vg_die("open log %s: %s", cfg.log_file, strerror(errno));
    }

    if (daemon_mode) {
        ready_fd = daemon_start(log_fd);

    } else {
        redirect_log(log_fd);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (vg_maps_open(&maps, &cfg) < 0) {
        vg_die("BPF maps");
    }

    if (vg_populate_allow(&maps, &cfg) < 0
        || vg_populate_local(&maps, &cfg) < 0)
    {
        vg_maps_close(&maps);
        vg_die("failed to populate allow/local maps");
    }

    if (vg_cfg_commit(&maps, 0, &cfg) < 0) {
        vg_maps_close(&maps);
        vg_die("failed to commit cfg map");
    }

    if (vg_xdp_attach(&maps, &cfg) < 0) {
        vg_maps_close(&maps);
        vg_die("XDP attach failed");
    }

    if (vg_ctrl_init(&ctrl, &cfg, &maps, cfg_path, iface_ov) < 0) {
        vg_maps_close(&maps);
        vg_die("control plane init failed");
    }

    ctl_fd = vg_ctl_server_listen(VG_SOCK_PATH);

    if (ctl_fd < 0) {
        vg_warn("ctl socket %s failed: %s (voidgatectl disabled)",
                VG_SOCK_PATH, strerror(errno));

    } else {
        vg_log("ctl socket %s", VG_SOCK_PATH);
    }

    http_fd = vg_http_listen(cfg.metrics_port);

    if (http_fd >= 0) {
        vg_log("prometheus 127.0.0.1:%d/metrics", cfg.metrics_port);
    }

    vg_log_config(&cfg, maps.attach_flags);
    vg_log("idle on %s, wake_pps=%llu wake_mbps=%llu", cfg.interface,
           (unsigned long long)cfg.wake_pps,
           (unsigned long long)cfg.wake_mbps);

    if (ready_fd >= 0) {
        pid_t daemon_pid = getpid();

        if (write(ready_fd, &daemon_pid, sizeof(daemon_pid))
            != sizeof(daemon_pid))
        {
            vg_warn("failed to report daemon readiness");
            g_stop = 1;
            result = 1;
        }

        close(ready_fd);
    }

    clock_gettime(CLOCK_MONOTONIC, &last_tick);
    while (!g_stop) {
        struct pollfd pfd[2];
        int nfds = 0, pr, wait_ms;
        struct timespec now;
        long elapsed;

        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = elapsed_ms(&now, &last_tick);
        wait_ms = cfg.idle_poll_ms - (int) elapsed;

        if (wait_ms < 0) {
            wait_ms = 0;
        }

        if (ctl_fd >= 0) {
            pfd[nfds].fd = ctl_fd;
            pfd[nfds].events = POLLIN;
            nfds++;
        }

        if (http_fd >= 0) {
            pfd[nfds].fd = http_fd;
            pfd[nfds].events = POLLIN;
            nfds++;
        }

        pr = poll(pfd, (nfds_t) nfds, wait_ms);

        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }

            break;
        }

        if (pr > 0) {
            int i;

            for (i = 0; i < nfds; i++) {
                int cfd;

                if (!(pfd[i].revents & POLLIN)) {
                    continue;
                }

                cfd = accept(pfd[i].fd, NULL, NULL);

                if (cfd < 0) {
                    continue;
                }

                sock_timeout(cfd);

                if (pfd[i].fd == ctl_fd) {
                    vg_ctl_server_handle(&ctrl, cfd);

                } else {
                    vg_http_handle(&ctrl, cfd);
                }

                close(cfd);
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &now);

        if (pr <= 0 || elapsed_ms(&now, &last_tick) >= cfg.idle_poll_ms) {
            vg_ctrl_tick(&ctrl);
            last_tick = now;
        }
    }

    vg_ctrl_disarm(&ctrl, "shutdown");
    vg_ctrl_free(&ctrl);
    vg_maps_close(&maps);

    if (ctl_fd >= 0) {
        close(ctl_fd);
        unlink(VG_SOCK_PATH);
    }

    if (http_fd >= 0) {
        close(http_fd);
    }

    vg_log("exit");
    return result;
}
