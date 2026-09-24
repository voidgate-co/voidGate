# voidGate C style

Formatting follows the nginx Code style chapter:

https://nginx.org/en/docs/dev/development_guide.html#code_style

This file is voidGate’s version: same rules, `vg_` / `VG_` names, and
the deviations in the last section. Product, BPF, and commit-message
rules stay in AGENT.md.

Hand-written C and H in `src/` and `tests/` follow this guide. Makefile
recipes stay tab-indented (required by make). Do not hand-edit
`src/bpf/voidgate.skel.h`.

Existing files may still lag some of these rules. New code should match
this document. Do not mix a partial restyle into an unrelated change.

## General rules

- Maximum text width is 80 characters.
- Indentation is 4 spaces.
- No tabs, no trailing spaces.
- List elements on the same line are separated with spaces.
- Hexadecimal literals are lowercase.
- File names, function and type names, and global variables have the
  `vg_` prefix, or a more specific one such as `vg_ctrl_`.

```c
static unsigned
snap_hash(int family, const uint8_t *addr)
{
    unsigned  h = (unsigned) family * 16777619u;
    int       n = family == AF_INET ? 4 : 16;
    int       i;

    for (i = 0; i < n; i++) {
        h = (h ^ addr[i]) * 16777619u;
    }

    return h % VG_SNAP_BUCKETS;
}
```

## Files

A typical source file may contain the following sections, separated by
two empty lines, except for the license spacing described below:

- SPDX license comment
- includes
- preprocessor definitions
- type definitions
- function prototypes
- variable definitions
- function definitions

Hand-written Apache-2.0 C sources and headers, including tests and the
shared BPF header, begin with one empty line, the opening license comment,
and one empty line. For a multi-line comment, place the trailing empty
line after its closing `*/`:

```c

/* SPDX-License-Identifier: Apache-2.0 */

```

`src/bpf/voidgate.bpf.c` is GPL-2.0-only. It may use the kernel SPDX
form on line 1; see [voidGate notes](#voidgate-notes).

Project headers come first, then system and library headers:

```c
#include "maps.h"
#include "log.h"

#include "bpf/voidgate.skel.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
```

Header files use include guards:

```c
#ifndef _VG_POLICY_H_INCLUDED_
#define _VG_POLICY_H_INCLUDED_
...
#endif /* _VG_POLICY_H_INCLUDED_ */
```

## Comments

- `//` comments are not used (exception: the BPF SPDX line).
- Text is written in English; American spelling is preferred.
- Multi-line comments are formatted like this:

```c
/*
 * IDLE  (cfg.armed == 0): bump rx counters, XDP_PASS.
 * ACTIVE (cfg.armed == 1): whitelist, drop LPM, count, PASS or DROP.
 */

/* refuse a drop CIDR that covers local_* or allow_* */
```

## Preprocessor

Macro names start with `vg_` or `VG_` (or a more specific prefix).
Constant macros are uppercase. Parameterized macros and initializer
macros are lowercase. The macro name and value are separated by at
least two spaces:

```c
#define VG_MAX_ALLOW_PORTS  8

#define vg_ncpus(m)  ((m)->ncpus)

#define vg_ipv4_host_key(k, addr)                                        \
    do {                                                                 \
        (k)->prefixlen = 32;                                             \
        memcpy((k)->data, (addr), 4);                                    \
    } while (0)
```

`#if` conditions are inside parentheses; negation is outside:

```c
#if (VG_CTRL_TEST)
...
#elif (defined(VG_HAVE_FOO) && !(VG_TEST_BUILD_FOO))
...
#else /* no VG_HAVE_FOO */
...
#endif /* VG_CTRL_TEST */
```

## Types

Type names end with the `_t` suffix. A defined type name is separated
by at least two spaces:

```c
typedef uint32_t  vg_reason_t;
```

Structure types are defined using `typedef`. Inside structures, member
types and names are aligned:

```c
typedef struct {
    int        family;
    uint8_t    addr[16];
    uint8_t    prefixlen;
} vg_cidr_t;
```

Keep alignment identical among different structures in the file. A
structure that points to itself has a name ending with `_s`. Adjacent
structure definitions are separated with two empty lines:

```c
typedef struct vg_snap_ent_s  vg_snap_ent_t;

struct vg_snap_ent_s {
    int              family;
    uint8_t          addr[16];
    uint64_t         in_pkts;
    uint64_t         in_bytes;
    uint32_t         gen;
    vg_snap_ent_t   *next;
};


typedef struct {
    vg_snap_ent_t   *snap_free;
    unsigned         snap_cap;
    uint32_t         snap_gen;
} vg_snap_pool_t;
```

Each structure member is declared on its own line.

Function pointers inside structures have defined types ending with
`_pt`:

```c
typedef int (*vg_ctrl_drop_pt)(struct vg_ctrl *c, const struct vg_cidr *p,
    uint32_t reason);

typedef struct {
    vg_ctrl_drop_pt    drop;
    vg_ctrl_drop_pt    undrop;
} vg_ctrl_ops_t;
```

Enumerations have types ending with `_e`:

```c
typedef enum {
    vg_state_idle = 0,
    vg_state_active
} vg_state_e;
```

`src/bpf/voidgate.h` is shared with BPF: packed `__u*` members, no
libc, no pointers to userspace objects. That header may keep
`struct vg_*` without a typedef when both sides already use that form.

## Variables

Variables are declared sorted by length of a base type, then
alphabetically. Type names and variable names are aligned. The type and
name columns are separated with two spaces. Large arrays are put at the
end of a declaration block:

```c
int                     i, n;
size_t                  len;
uint8_t                *p;
uint32_t                key;
struct vg_cfg           bc;
struct vg_cidr          cidr;
char                    tmp[128];
```

Static and global variables may be initialized on declaration:

```c
static const char  *vg_sock_path = VG_SOCK_PATH;

static uint32_t  vg_fnv_prime = 16777619u;
```

## Functions

All functions (even static ones) should have prototypes. Prototypes
include argument names. Long prototypes are wrapped with a single
indentation on continuation lines:

```c
static void bump_memlock(void);
static int libbpf_print(enum libbpf_print_level level, const char *fmt,
    va_list args);

int vg_maps_open(struct vg_maps *m, struct vg_config *cfg);
int vg_sum_percpu(struct vg_maps *m, int map_fd, const void *key,
    size_t val_size, void *out_sum);
```

The function name in a definition starts on a new line. The function
body opening and closing braces are on separate lines. The body is
indented. There are two empty lines between functions:

```c
static size_t
sum_scratch_need(int ncpus)
{
    size_t  a = sizeof(struct host_counters);
    size_t  b = sizeof(struct vg_metrics);

    return (size_t) ncpus * (a > b ? a : b);
}


int
vg_maps_open(struct vg_maps *m, struct vg_config *cfg)
{
    ...
}
```

There is no space after the function name and the opening parenthesis.
Long function calls are wrapped so continuation lines start from the
position of the first argument. If that is impossible, format the first
continuation line so it ends at position 79:

```c
    return bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &key, &cfg,
                               BPF_ANY);

    vg_log("setrlimit(RLIMIT_MEMLOCK) failed: %s",
           strerror(errno));

    m->sum_scratch = calloc((size_t) ncpus,
                                sizeof(struct host_counters) * (size_t) ncpus);
```

Prefer `static inline` in headers. Do not use a bare `inline` without
`static` in a header.

## Expressions

Binary operators except `.` and `->` are separated from their operands
by one space. Unary operators and subscripts are not:

```c
    bits = bits * 10 + (*fmt++ - '0');

    out->prefixlen = (uint8_t) (plen < 0 ? 128 : plen);

    p = &out->addr[i + 1];
```

Type casts are separated by one space from the cast expression. An
asterisk inside a type cast is separated with a space from the type
name:

```c
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
```

If an expression does not fit on a single line, wrap it. The preferred
point to break is a binary operator. Put that operator at the start of
the continuation line. Line the continuation up with the start of the
expression (the first token after `if (` or the `(` of a call), not a
fixed extra indent:

```c
        if (v6_in_lpm(&drop_v6, saddr.addr)
            || v6_in_lpm(&drop_v6, daddr.addr))
        {
            ...
        }

        msg = "failed to load BPF object "
              "or attach XDP";
```

As a last resort, wrap so the continuation line ends at position 79:

```c
    need = sizeof(struct vg_metrics)
                               + (size_t) ncpus * sizeof(struct host_counters);
```

The same rules apply to sub-expressions; each sub-expression has its
own indentation level:

```c
    if (((cfg->wake_pps > 0 && rx_pps >= cfg->wake_pps)
         || rx_bps >= cfg->wake_mbps * 1e6) && c->state == VG_IDLE
        && cfg->armed == 0)
    {
        ...
    }
```

Sometimes it is convenient to wrap after a cast. In that case the
continuation line is indented:

```c
    sin = (struct sockaddr_in *)
              ((uint8_t *) sa + offsetof(struct sockaddr_in, sin_addr));
```

Pointers are compared to `NULL` (not `0`):

```c
    if (ptr != NULL) {
        ...
    }
```

## Conditionals and loops

The `if` keyword is separated from the condition by one space. The
opening brace is on the same line, or on a dedicated line if the
condition takes several lines. The closing brace is on a dedicated
line, optionally followed by `else if` / `else`. Usually there is an
empty line before the `else if` / `else` part:

```c
    if (p->family == AF_INET) {
        plen = 32;
        family = AF_INET;

    } else if (p->family == AF_INET6) {
        plen = 128;
        family = AF_INET6;

    } else {
        return -1;
    }
```

Always put braces on `if` / `else` / `for` bodies, even one-liners.

When an `if` / `else if` / `while` / `for` condition wraps, put `{` on
the next line at the `if` indent. A one-line condition keeps `) {`.

Put a blank line before and after an `if` / `else` chain or a `for`
when it sits next to another statement. Do not insert that blank
against the enclosing `{` or `}`:

```c
    slash = strchr(tmp, '/');

    if (slash != NULL) {
        *slash = 0;
        plen = atoi(slash + 1);

    } else {
        plen = -1;
    }

    if (strchr(tmp, ':') != NULL) {
        out->family = AF_INET6;
        ...
    }
```

Similar formatting applies to `do` and `while`. A `while` whose body is
a single statement may omit braces:

```c
    while (p < last && *p == ' ') {
        p++;
    }

    while (p < last && *p == ' ')
        p++;

    do {
        n = read(fd, buf, sizeof(buf));
        p += n;
    } while (n > 0);
```

The `switch` keyword is separated from the condition by one space. The
opening brace is on the same line. `case` labels line up with `switch`:

```c
    switch (reason) {
    case VG_REASON_MANUAL:
        why = "manual";
        break;

    case VG_REASON_POLICY:
        why = "policy";
        break;

    default:
        why = "unknown";
        break;
    }
```

Most `for` loops are formatted like this:

```c
    for (i = 0; i < c->allow_port_count; i++) {
        ...
    }

    for (i = 0, p = c->drops;
         i < c->drop_count;
         i++, p++)
    {
        ...
    }
```

If some part of the `for` statement is omitted, mark it with
`/* void */`. A loop with an empty body uses the same comment, which
may sit on the same line:

```c
    for (i = 0; /* void */ ; i++) {
        ...
    }

    for (p = head; p->next != NULL; p = p->next) { /* void */ }
```

An endless loop looks like this:

```c
    for ( ;; ) {
        ...
    }
```

## Labels

Labels are surrounded with empty lines and are indented at the previous
level:

```c
    if (m->skel == NULL) {
        vg_log("failed to open BPF object");
        goto failed;
    }

    err = voidgate_bpf__load(m->skel);
    if (err != 0) {
        goto failed;
    }

    return 0;

failed:

    vg_maps_close(m);
    return -1;
```

## voidGate notes

These override nginx where they conflict.

- Always brace `if` / `else` / `for`, including one-liners. Leave
  `while` unbraced when the body is a single statement.
- Exported functions, types, and globals use the `vg_` / `VG_` prefix.
  File-local static helpers may omit it.
- Blank line before and after an `if` / `else` chain or `for` when it
  sits next to another statement (not against the enclosing `{` / `}`).
- Blank line before `} else {` and, usually, before `} else if`.
- SPDX instead of nginx `Copyright (C)` banners. Userspace is
  Apache-2.0. `src/bpf/voidgate.bpf.c` is GPL-2.0-only and may keep
  `// SPDX-License-Identifier: GPL-2.0-only` on line 1. No other `//`
  comments.
- `src/bpf/voidgate.h` stays shared: `__u*` / packed types, no libc.
  BPF verifier constraints (bounded unrolls, `data_end` checks) are in
  AGENT.md.
- Makefile recipes stay tab-indented. Hand-written C/H is 4-space.
- Commit messages (`type: summary`) are in AGENT.md, not here.
