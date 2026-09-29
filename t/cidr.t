# SPDX-License-Identifier: Apache-2.0
# CIDR parsing and the local/allow guard, through `voidgatectl drop`.
# Fixture (t/conf/xdp.conf): local 198.51.100.10/32 and 2001:db8::10/128,
# allow = built-in defaults + 192.0.2.99/32.

use VG::Test;

run_ctl_blocks();

__DATA__

=== TEST 1: v4 parse masks host bits
--- input: drop 10.1.2.3/24
--- expected: ok
--- drops: 10.1.2.0/24



=== TEST 2: v6 parse masks host bits
--- input: drop 2001:db8:5::1:2:3:4/64
--- expected: ok
--- drops: 2001:db8:5::/64



=== TEST 3: v4 /24 masks the host octet
--- input: drop 203.0.113.77/24
--- expected: ok
--- drops: 203.0.113.0/24



=== TEST 4: metadata IP is protected
--- input: drop 169.254.169.254/32
--- expected: error: refused or map update failed
--- drops:



=== TEST 5: test-net is not protected
--- input: drop 203.0.113.1/32
--- expected: ok
--- drops: 203.0.113.1/32



=== TEST 6: localhost is protected
--- input: drop 127.0.0.1/32
--- expected: error: refused or map update failed



=== TEST 7: extra allow_networks entry is protected
--- input: drop 192.0.2.0/24
--- expected: error: refused or map update failed



=== TEST 8: vm address is local
--- input: drop 198.51.100.10/32
--- expected: error: refused or map update failed



=== TEST 9: on-link neighbor is not local
--- input: drop 198.51.100.8/32
--- expected: ok
--- drops: 198.51.100.8/32



=== TEST 10: lan /24 drop would cover the vm
--- input: drop 198.51.100.0/24
--- expected: error: refused or map update failed



=== TEST 11: vm v6 address is local
--- input: drop 2001:db8::10/128
--- expected: error: refused or map update failed



=== TEST 12: on-link v6 neighbor is not local
--- input: drop 2001:db8::8/128
--- expected: ok
--- drops: 2001:db8::8/128



=== TEST 13: bad cidr is rejected
--- input: drop 10.0.0.1/33
--- expected: error: bad cidr
