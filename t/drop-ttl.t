# SPDX-License-Identifier: Apache-2.0
# drop <cidr> ttl=<seconds>: a timed drop (reason 4) for OpenResty
# bans. Expiry itself is covered by t/unit/policy.

use VG::Test;

run_ctl_blocks();

__DATA__

=== TEST 1: v4 ttl drop is ok and listed
--- input: drop 203.0.113.1/32 ttl=60
--- expected: ok
--- drops: 203.0.113.1/32



=== TEST 2: v6 ttl drop is ok and listed
--- input: drop 2001:db8::bad/128 ttl=60
--- expected: ok
--- drops: 2001:db8::bad/128



=== TEST 3: ttl drop of a protected prefix is refused
--- input: drop 169.254.169.254/32 ttl=60
--- expected: error: refused or map update failed
--- drops:



=== TEST 4: ttl 0 is a bad ttl
--- input: drop 203.0.113.1/32 ttl=0
--- expected: error: bad ttl
--- drops:



=== TEST 5: ttl over one year is a bad ttl
--- input: drop 203.0.113.1/32 ttl=31536001
--- expected: error: bad ttl



=== TEST 6: one year is the largest ttl
--- input: drop 203.0.113.1/32 ttl=31536000
--- expected: ok



=== TEST 7: ttl with trailing junk is a bad ttl
--- input: drop 203.0.113.1/32 ttl=60s
--- expected: error: bad ttl



=== TEST 8: unknown option is a bad ttl
--- input: drop 203.0.113.1/32 for=60
--- expected: error: bad ttl



=== TEST 9: negative ttl is a bad ttl
--- input: drop 203.0.113.1/32 ttl=-1
--- expected: error: bad ttl



=== TEST 10: bad cidr with a good ttl is a bad cidr
--- input: drop 203.0.113.1/33 ttl=60
--- expected: error: bad cidr



=== TEST 11: an empty first word is a bad cidr, not a bad ttl
--- input: drop  203.0.113.1/32
--- expected: error: bad cidr



=== TEST 12: ttl before the cidr is a bad cidr
--- input: drop ttl=60 203.0.113.1/32
--- expected: error: bad cidr



=== TEST 13: an over-long cidr with a ttl is a bad cidr
--- input: drop 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 ttl=60
--- expected: error: bad cidr



=== TEST 14: the cidr is judged before the ttl
--- input: drop 203.0.113.1/33 ttl=0
--- expected: error: bad cidr



=== TEST 15: empty ttl is a bad ttl
--- input: drop 203.0.113.1/32 ttl=
--- expected: error: bad ttl



=== TEST 16: space after ttl= is a bad ttl
--- input: drop 203.0.113.1/32 ttl= 60
--- expected: error: bad ttl



=== TEST 17: plus sign is a bad ttl
--- input: drop 203.0.113.1/32 ttl=+60
--- expected: error: bad ttl



=== TEST 18: space inside the number is a bad ttl
--- input: drop 203.0.113.1/32 ttl=6 0
--- expected: error: bad ttl



=== TEST 19: hex is a bad ttl
--- input: drop 203.0.113.1/32 ttl=0x10
--- expected: error: bad ttl



=== TEST 20: a number past uint32 is a bad ttl, not a wrapped one
--- input: drop 203.0.113.1/32 ttl=4294967356
--- expected: error: bad ttl



=== TEST 21: leading zeros are still decimal
--- input: drop 203.0.113.1/32 ttl=0060
--- expected: ok
--- drops: 203.0.113.1/32
