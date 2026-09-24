
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _VG_LOG_H_INCLUDED_
#define _VG_LOG_H_INCLUDED_

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

extern int vg_verbose;

struct vg_config;


void vg_log_config_at(const char *file, int line,
    const struct vg_config *cfg, uint32_t attach_flags);

#define VG_SGR_DIM     "\033[2m"
#define VG_SGR_CYAN    "\033[36m"
#define VG_SGR_YELLOW  "\033[33m"
#define VG_SGR_RED     "\033[31m"
#define VG_SGR_RESET   "\033[0m"


static inline int vg_log_color(void);
static inline void vg_log_prefix(const char *level, const char *sgr);
static inline void vg_log_loc(const char *file, int line);


static inline int
vg_log_color(void)
{
    return isatty(fileno(stderr)) && getenv("NO_COLOR") == NULL;
}


static inline void
vg_log_prefix(const char *level, const char *sgr)
{
    struct timespec ts;
    struct tm tm;
    char tbuf[32];

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm);

    if (vg_log_color()) {
        fprintf(stderr, VG_SGR_DIM "%s" VG_SGR_RESET
                " voidGate %s[%s]" VG_SGR_RESET " ", tbuf, sgr, level);

    } else {
        fprintf(stderr, "%s voidGate [%s] ", tbuf, level);
    }
}


static inline void
vg_log_loc(const char *file, int line)
{
    if (vg_log_color()) {
        fprintf(stderr, " " VG_SGR_DIM "at %s:%d" VG_SGR_RESET "\n",
                file, line);

    } else {
        fprintf(stderr, " at %s:%d\n", file, line);
    }
}


__attribute__((format(printf, 3, 4)))
static inline void
vg_log_at(const char *file, int line, const char *fmt, ...)
{
    va_list ap;

    vg_log_prefix("INFO", VG_SGR_CYAN);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    vg_log_loc(file, line);
}


__attribute__((format(printf, 3, 4)))
static inline void
vg_warn_at(const char *file, int line, const char *fmt, ...)
{
    va_list ap;

    vg_log_prefix("WARN", VG_SGR_YELLOW);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    vg_log_loc(file, line);
}


__attribute__((noreturn, format(printf, 3, 4)))
static inline void
vg_die_at(const char *file, int line, const char *fmt, ...)
{
    va_list ap;

    vg_log_prefix("FATL", VG_SGR_RED);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    vg_log_loc(file, line);
    exit(1);
}


#define vg_log(...)  vg_log_at(__FILE__, __LINE__, __VA_ARGS__)
#define vg_warn(...) vg_warn_at(__FILE__, __LINE__, __VA_ARGS__)
#define vg_die(...)  vg_die_at(__FILE__, __LINE__, __VA_ARGS__)
#define vg_log_config(cfg, flags) \
    vg_log_config_at(__FILE__, __LINE__, (cfg), (flags))

#define vg_vlog(...) \
    do { \
        if (vg_verbose >= 1) { \
            vg_log(__VA_ARGS__); \
        } \
    } while (0)

#define vg_vvlog(...) \
    do { \
        if (vg_verbose >= 2) { \
            vg_log(__VA_ARGS__); \
        } \
    } while (0)

#endif /* _VG_LOG_H_INCLUDED_ */
