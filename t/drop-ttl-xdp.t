# SPDX-License-Identifier: Apache-2.0
# A ttl drop is enforced like a manual one, with the same whitelist.
# Fixture (t/conf/xdp.conf): local 198.51.100.10 / 2001:db8::10, port 22.

use VG::Test;

run_xdp_blocks();

__DATA__

=== TEST 1: v4 src under a ttl drop is XDP_DROP
--- setup: drop 203.0.113.1/32 ttl=60
--- packets: ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80
--- verdict: XDP_DROP
--- counters: rx_pkts=1 dropped=1



=== TEST 2: v6 src under a ttl drop is XDP_DROP
--- setup: drop 2001:db8::bad/128 ttl=60
--- packets: ipv6 udp [2001:db8::bad]:12345 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 3: SSH dport 22 passes from a ttl-dropped src
--- setup: drop 203.0.113.1/32 ttl=60
--- packets: ipv4 tcp 203.0.113.1:40000 > 198.51.100.10:22
--- verdict: XDP_PASS
