# SPDX-License-Identifier: Apache-2.0
# ARMED IPv6: NDP / SSH / DHCPv6 whitelist before the drop LPM.
# Fixture (t/conf/xdp.conf): local 2001:db8::10, allow_ports 22.

use VG::Test;

run_xdp_blocks();

__DATA__

=== TEST 1: IPv6 NDP always PASS
--- packets: ipv6 icmpv6 fe80::1 > ff02::1 type=135 hop=255
--- verdict: XDP_PASS



=== TEST 2: armed + dropped IPv6 src is XDP_DROP
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:12345 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 3: IPv6 SSH dport 22 passes from dropped src
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:40000 > [2001:db8::10]:22
--- verdict: XDP_PASS



=== TEST 4: IPv6 TCP sport 22 from dropped src is not a whitelist
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 tcp [2001:db8::bad]:22 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 5: DHCPv6 server reply 547->546 to local passes from dropped src
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:547 > [2001:db8::10]:546
--- verdict: XDP_PASS



=== TEST 6: UDP sport 547 from dropped IPv6 src is not a whitelist
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:547 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 7: UDP sport 546 from dropped IPv6 src is not a whitelist
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::bad]:546 > [2001:db8::10]:80
--- verdict: XDP_DROP



=== TEST 8: non-dropped IPv6 is XDP_PASS
--- setup: drop 2001:db8::bad/128
--- packets: ipv6 udp [2001:db8::1]:12345 > [2001:db8::10]:80
--- verdict: XDP_PASS
