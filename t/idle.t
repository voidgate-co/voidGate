# SPDX-License-Identifier: Apache-2.0
# IDLE: armed == 0 passes everything and only bumps the rx counters.
use VG::Test;

run_xdp_blocks();

__DATA__

=== TEST 1: idle UDP is XDP_PASS
--- idle
--- packets: ipv4 udp 203.0.113.1:12345 > 198.51.100.10:80
--- verdict: XDP_PASS
--- counters: rx_pkts=1 dropped=0
