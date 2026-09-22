-- SPDX-License-Identifier: Apache-2.0

package.path = "./lua/?.lua;" .. package.path
local vg = require("voidgate")
local conn = assert(vg.new({ path = assert(arg[1]), timeout = 0.5 }))

local status = assert(conn:status())
assert(status.state == "idle" and status.armed == false
    and status.iface == "test0")
assert(type(status.rx_pps) == "number" and status.prefixes == 0)
assert(conn:arm())
assert(conn:status().armed == true)
assert(conn:disarm())
assert(conn:status().armed == false)
local stats = assert(conn:stats())
assert(type(stats.rx_pkts) == "string" and stats.rx_pkts:match("^%d+$"))
assert(stats.dropped == "0" and stats.prefixes == 0)
assert(#assert(conn:drops()) == 0)
assert(conn:drop("203.0.113.0/24"))
local drops = assert(conn:drops())
assert(#drops == 1 and drops[1].cidr == "203.0.113.0/24")
assert(type(drops[1].reason) == "number" and drops[1].age >= 0)
assert(conn:undrop("203.0.113.0/24"))
assert(#assert(conn:drops()) == 0)
assert(conn:drop("2001:db8::/64"))
assert(conn:drops()[1].cidr == "2001:db8::/64")
assert(conn:undrop("2001:db8::/64"))
local ok, err = conn:drop("bad-cidr")
assert(ok == nil and err == "error: bad cidr")
-- Disarm must clear actual map entries and controller tracking.
assert(conn:drop("203.0.113.0/24"))
assert(conn:drop("2001:db8::/64"))
assert(conn:disarm())
assert(#assert(conn:drops()) == 0)
assert(conn:status().armed == false)

local config_path = assert(arg[2])
local file = assert(io.open(config_path, "r"))
local config = file:read("*a")
file:close()
local function write_config(contents)
    local output = assert(io.open(config_path, "w"))
    assert(output:write(contents))
    assert(output:close())
end
write_config(config .. "allow_networks = 203.0.113.0/24,2001:db8::/64\n")
assert(conn:reload())
for _, cidr in ipairs({ "203.0.113.1/32", "2001:db8::1/128" }) do
    ok, err = conn:drop(cidr)
    assert(ok == nil and err == "error: refused or map update failed")
end
write_config(config .. "wake_pps = invalid\n")
ok, err = conn:reload()
assert(ok == nil and err == "error: reload failed")
write_config(config)
assert(conn:reload())
assert(conn:drop("203.0.113.1/32"))
assert(conn:drop("2001:db8::1/128"))
assert(conn:disarm())
local missing = vg.new({ path = arg[1] .. ".missing" })
ok, err = missing:status()
assert(ok == nil and type(err) == "string")

local created, closed = 0, 0
local failure, response, receive_error
local sent, path
package.loaded["socket.unix"] = {
    stream = function()
        if failure == "create" then
            return nil, "create failed"
        end
        created = created + 1
        return {
            close = function()
                closed = closed + 1
            end,
            settimeout = function()
                return 1
            end,
            connect = function(_, value)
                path = value
                if failure == "connect" then
                    return nil, "connect failed"
                end
                return 1
            end,
            send = function(_, value)
                sent = value
                if failure == "send" then
                    return nil, "timeout"
                end
                return #value
            end,
            shutdown = function()
                return 1
            end,
            receive = function(_, pattern)
                assert(pattern == "*a")
                if receive_error then
                    return nil, receive_error
                end
                return response
            end,
        }
    end,
}
local mock = dofile("lua/voidgate.lua")
response = "rx_pkts=18446744073709551615\n"
assert(mock.stats().rx_pkts == "18446744073709551615")
response = "ok\n"
assert(mock.arm())
assert(sent == "arm\n" and path == "/run/voidgate.sock")
response = "(none)\n"
assert(#assert(mock.drops()) == 0)
response = "203.0.113.0/24 reason=1 age=0\n2001:db8::/64 reason=2 age=3\n"
local listed = assert(mock.drops())
assert(#listed == 2)
assert(listed[1].cidr == "203.0.113.0/24" and listed[1].reason == 1)
assert(listed[2].cidr == "2001:db8::/64" and listed[2].age == 3)
for _, stage in ipairs({ "create", "connect", "send" }) do
    failure = stage
    ok, err = mock.arm()
    assert(ok == nil and type(err) == "string")
    assert(created == closed)
end
failure = nil
receive_error = "timeout"
ok, err = mock.arm()
assert(ok == nil and err == "timeout")
assert(created == closed)
receive_error = nil
response = "error reading metrics\n"
ok, err = mock.stats()
assert(ok == nil and err == "error reading metrics")
local before = created
assert(mock.drop() == nil)
assert(mock.drop(123) == nil)
assert(mock.drop("a b") == nil)
assert(mock.drop("203.0.113.0/24\narm") == nil)
assert(created == before)
assert(created == closed)
print("Lua client tests passed")
