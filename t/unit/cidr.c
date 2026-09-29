
/* SPDX-License-Identifier: Apache-2.0 */

/* vg_parse_cidr and the config CIDR lists. A malformed prefix length must
 * be rejected, never truncated or read as /0: in allow_networks that would
 * allow-list everything.
 */

#include "config.h"
#include "ipaddr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static int g_fail;


static void
expect_cidr(const char *in, const char *want)
{
    struct vg_cidr p;
    char got[80];
    int rc = vg_parse_cidr(in, &p);

    if (rc == 0) {
        vg_cidr_to_str(&p, got, sizeof(got));
    }

    if ((want == NULL && rc == 0)
        || (want != NULL && (rc != 0 || strcmp(got, want) != 0)))
    {
        printf("FAIL parse '%s': want %s, got %s\n", in,
               want != NULL ? want : "reject", rc == 0 ? got : "reject");
        g_fail++;
    }
}


static void
expect_config(const char *line, int want_rc)
{
    char path[] = "/tmp/vg-cidr-XXXXXX";
    struct vg_config cfg;
    FILE *fp;
    int fd, rc;

    fd = mkstemp(path);

    if (fd < 0 || (fp = fdopen(fd, "w")) == NULL) {
        perror("mkstemp");
        exit(1);
    }

    fprintf(fp, "%s\n", line);
    fclose(fp);
    rc = vg_config_load(path, &cfg);
    unlink(path);

    if (rc != want_rc) {
        printf("FAIL config '%s': want %d, got %d\n", line, want_rc, rc);
        g_fail++;
    }
}


int
main(void)
{
    char long_cidr[256];

    expect_cidr("10.1.2.3/24", "10.1.2.0/24");
    expect_cidr("10.0.0.1", "10.0.0.1/32");
    expect_cidr("0.0.0.0/0", "0.0.0.0/0");
    expect_cidr("10.0.0.0/08", "10.0.0.0/8");
    expect_cidr("2001:db8::1/64", "2001:db8::/64");
    expect_cidr("2001:db8::1", "2001:db8::1/128");
    expect_cidr("::/0", "::/0");

    expect_cidr("10.0.0.0/33", NULL);
    expect_cidr("10.0.0.0/280", NULL);
    expect_cidr("10.0.0.0/4294967320", NULL);
    expect_cidr("2001:db8::/129", NULL);
    expect_cidr("2001:db8::/300", NULL);
    expect_cidr("10.0.0.1/", NULL);
    expect_cidr("10.0.0.1/abc", NULL);
    expect_cidr("10.0.0.1/-8", NULL);
    expect_cidr("10.0.0.1/+24", NULL);
    expect_cidr("10.0.0.1/ 24", NULL);
    expect_cidr("10.0.0.1/24x", NULL);
    expect_cidr("10.0.0.1/24/8", NULL);
    expect_cidr("/24", NULL);
    expect_cidr("", NULL);

    /* Longer than the parser's buffer: reject, do not parse a prefix. */
    memset(long_cidr, '1', sizeof(long_cidr) - 1);
    long_cidr[sizeof(long_cidr) - 1] = '\0';
    memcpy(long_cidr, "10.0.0.0/8", 10);
    expect_cidr(long_cidr, NULL);

    expect_config("allow_networks = 192.0.2.0/24, 2001:db8::/32", 0);
    expect_config("allow_networks = 10.0.0.0/", -1);
    expect_config("allow_networks = 10.0.0.0/abc", -1);
    expect_config("local_networks = 198.51.100.0/280", -1);

    if (g_fail) {
        printf("%d cidr unit check(s) failed\n", g_fail);
        return 1;
    }

    puts("cidr unit tests passed");
    return 0;
}
