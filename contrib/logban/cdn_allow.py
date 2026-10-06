#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

"""Fetch a CDN's published egress ranges into a logban allow_file.

    cdn_allow.py cloudflare /etc/logban/cdn-allow.txt

The file is replaced only with a list that parsed, holds both IPv4 and
IPv6 ranges, and differs from what is there; it is written next to the
target and renamed over it, so a reader never sees half a file and a
failed fetch leaves the old list in place. Exit 0 when the file is
current (changed or not), 1 on any failure: safe to run from cron.
"""

import argparse
import ipaddress
import json
import os
import sys
import tempfile
import time
import urllib.request


def cloudflare(data):
    doc = json.loads(data)

    if not doc.get("success"):
        raise ValueError("success is not true: %s" % doc.get("errors"))

    r = doc["result"]
    return r["ipv4_cidrs"] + r["ipv6_cidrs"]


PROVIDERS = {
    "cloudflare": ("https://api.cloudflare.com/client/v4/ips", cloudflare),
}


def check(cidrs):
    """Normalized, sorted CIDR strings; refuse anything suspicious."""

    nets = set()

    for c in cidrs:
        if not isinstance(c, str):
            raise ValueError("not a string: %r" % (c,))

        net = ipaddress.ip_network(c, strict=False)

        # A CDN never announces something this wide; a bad list would
        # turn logban off for a large part of the internet.
        if net.prefixlen < (8 if net.version == 4 else 16):
            raise ValueError("too wide: %s" % c)

        nets.add(net)

    for version in (4, 6):
        if not any(n.version == version for n in nets):
            raise ValueError("no IPv%d ranges" % version)

    return [str(n) for n in sorted(nets, key=lambda n: (n.version, n))]


def current(path):
    """The CIDR lines of the existing file, or None."""

    try:
        with open(path) as f:
            return [ln.strip() for ln in f
                    if ln.strip() and not ln.startswith("#")]

    except FileNotFoundError:
        return None


def write(path, provider, url, cidrs):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".cdn-allow.")

    try:
        with os.fdopen(fd, "w") as f:
            f.write("# %s egress ranges from %s\n" % (provider, url))
            f.write("# fetched %s by cdn_allow.py; do not edit\n"
                    % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            f.write("".join(c + "\n" for c in cidrs))
            f.flush()
            os.fsync(f.fileno())

        os.chmod(tmp, 0o644)
        os.rename(tmp, path)

    except BaseException:
        os.unlink(tmp)
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Fetch a CDN's egress ranges into an allow_file.")
    ap.add_argument("provider", choices=sorted(PROVIDERS))
    ap.add_argument("output", help="allow_file to replace")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="print nothing unless it fails")
    args = ap.parse_args(argv)

    url, parse = PROVIDERS[args.provider]

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "voidgate-logban-cdn_allow"})

        with urllib.request.urlopen(req, timeout=20) as r:
            cidrs = check(parse(r.read()))

    except (OSError, ValueError, KeyError, TypeError) as e:
        sys.stderr.write("cdn_allow: %s: %s; %s left unchanged\n"
                         % (url, e, args.output))
        return 1

    if current(args.output) == cidrs:
        if not args.quiet:
            print("%s: unchanged, %d ranges" % (args.output, len(cidrs)))
        return 0

    try:
        write(args.output, args.provider, url, cidrs)

    except OSError as e:
        sys.stderr.write("cdn_allow: %s: %s\n" % (args.output, e))
        return 1

    if not args.quiet:
        print("%s: updated, %d ranges" % (args.output, len(cidrs)))

    return 0


if __name__ == "__main__":
    sys.exit(main())
