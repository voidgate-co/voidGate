-- SPDX-License-Identifier: Apache-2.0

package.path = "./lua/?.lua;" .. package.path
local vg = require("voidgate")
local n = 0

local function ok(cond, name)
    n = n + 1
    if cond then
        print("ok " .. n .. " - " .. name)
        return
    end

    print("not ok " .. n .. " - " .. name)
    os.exit(1)
end

local conn = assert(vg.new({ path = assert(arg[1]), timeout = 0.5 }))
local status = conn:status()
ok(status and status.state == "idle" and status.armed == false
    and status.iface == "test0", "idle status")
ok(type(status.rx_pps) == "number" and status.prefixes == 0,
    "idle counters")
ok(conn:arm() and conn:status().armed == true, "arm")
ok(conn:disarm() and conn:status().armed == false, "disarm")
local stats = conn:stats()
ok(stats and type(stats.rx_pkts) == "string" and stats.rx_pkts:match("^%d+$")
    and stats.dropped == "0" and stats.prefixes == 0, "stats")
ok(#assert(conn:drops()) == 0, "empty drops")
ok(conn:drop("203.0.113.0/24"), "drop v4")
local drops = conn:drops()
ok(drops and #drops == 1 and drops[1].cidr == "203.0.113.0/24"
    and type(drops[1].reason) == "number" and drops[1].age >= 0, "list v4 drop")
ok(conn:undrop("203.0.113.0/24") and #assert(conn:drops()) == 0, "undrop v4")
ok(conn:drop("2001:db8::/64")
    and conn:drops()[1].cidr == "2001:db8::/64", "drop v6")
ok(conn:undrop("2001:db8::/64"), "undrop v6")
local err
local pass
pass, err = conn:drop("bad-cidr")
ok(pass == nil and err == "error: bad cidr", "reject bad cidr")
ok(conn:drop("203.0.113.0/24") and conn:drop("2001:db8::/64")
    and conn:disarm() and #assert(conn:drops()) == 0
    and conn:status().armed == false, "disarm clears drops")

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
ok(conn:reload(), "reload allow_networks")
for _, cidr in ipairs({ "203.0.113.1/32", "2001:db8::1/128" }) do
    pass, err = conn:drop(cidr)
    ok(pass == nil and err == "error: refused or map update failed",
        "refuse drop of " .. cidr)
end
write_config(config .. "wake_pps = invalid\n")
pass, err = conn:reload()
ok(pass == nil and err == "error: reload failed", "reload invalid config")
write_config(config)
ok(conn:reload() and conn:drop("203.0.113.1/32")
    and conn:drop("2001:db8::1/128") and conn:disarm(), "reload restored")
local missing = vg.new({ path = arg[1] .. ".missing" })
pass, err = missing:status()
ok(pass == nil and type(err) == "string", "missing socket")

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
ok(mock.stats().rx_pkts == "18446744073709551615", "mock uint64 stats")
response = "ok\n"
ok(mock.arm() and sent == "arm\n" and path == "/run/voidgate.sock",
    "mock arm")
response = "(none)\n"
ok(#assert(mock.drops()) == 0, "mock empty drops")
response = "203.0.113.0/24 reason=1 age=0\n2001:db8::/64 reason=2 age=3\n"
local listed = mock.drops()
ok(listed and #listed == 2
    and listed[1].cidr == "203.0.113.0/24" and listed[1].reason == 1
    and listed[2].cidr == "2001:db8::/64" and listed[2].age == 3,
    "mock two drop lines")
for _, stage in ipairs({ "create", "connect", "send" }) do
    failure = stage
    pass, err = mock.arm()
    ok(pass == nil and type(err) == "string" and created == closed,
        "mock " .. stage .. " failure closes")
end
failure = nil
receive_error = "timeout"
pass, err = mock.arm()
ok(pass == nil and err == "timeout" and created == closed, "mock timeout")
receive_error = nil
response = "error reading metrics\n"
pass, err = mock.stats()
ok(pass == nil and err == "error reading metrics", "mock error reply")
local before = created
ok(mock.drop() == nil and mock.drop(123) == nil and mock.drop("a b") == nil
    and mock.drop("203.0.113.0/24\narm") == nil
    and created == before and created == closed, "mock drop rejects locally")
print("1.." .. n)
