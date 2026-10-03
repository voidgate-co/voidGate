-- SPDX-License-Identifier: Apache-2.0
-- Client methods against a real daemon. Run by resty.sh as a content
-- handler; prints TAP. ngx.var.vg_conf is the daemon's config file.

local vg = require("resty.voidgate")
local n = 0

local function ok(cond, name)
    n = n + 1
    ngx.say((cond and "ok " or "not ok ") .. n .. " - " .. name)
end

local conn = vg.new({ timeout = 0.5 })
local pass, err

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
    and drops[1].reason == 1 and drops[1].age >= 0, "list v4 drop")
ok(conn:undrop("203.0.113.0/24") and #assert(conn:drops()) == 0, "undrop v4")
ok(conn:drop("2001:db8::/64")
    and conn:drops()[1].cidr == "2001:db8::/64", "drop v6")
ok(conn:undrop("2001:db8::/64"), "undrop v6")
pass, err = conn:drop("bad-cidr")
ok(pass == nil and err == "error: bad cidr", "reject bad cidr")
ok(conn:drop() == nil and conn:drop(123) == nil and conn:drop("a b") == nil
    and conn:drop("203.0.113.0/24\narm") == nil, "drop rejects locally")
ok(conn:drop("203.0.113.0/24") and conn:drop("2001:db8::/64")
    and conn:disarm() and #assert(conn:drops()) == 0
    and conn:status().armed == false, "disarm clears drops")

ok(conn:drop("203.0.113.9/32", 60) and conn:drops()[1].reason == 4
    and conn:status().armed == true, "ttl drop")
ok(conn:drop("203.0.113.9/32") and conn:drops()[1].reason == 1,
    "manual drop upgrades a ttl drop")
ok(conn:disarm(), "disarm after ttl drop")
for _, ttl in ipairs({ 0, -1, 1.5, "x", 31536001 }) do
    pass, err = conn:drop("203.0.113.9/32", ttl)
    ok(pass == nil and err == "bad ttl", "reject ttl " .. tostring(ttl))
end

local config_path = ngx.var.vg_conf
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
    pass, err = conn:drop(cidr, 60)
    ok(pass == nil and err == "error: refused or map update failed",
        "refuse drop of " .. cidr)
end
write_config(config .. "wake_pps = invalid\n")
pass, err = conn:reload()
ok(pass == nil and err == "error: reload failed", "reload invalid config")
write_config(config)
ok(conn:reload() and conn:drop("203.0.113.1/32")
    and conn:drop("2001:db8::1/128") and conn:disarm(), "reload restored")

local missing = vg.new({ path = "/run/voidgate.sock.missing" })
pass, err = missing:status()
ok(pass == nil and type(err) == "string", "missing socket")

ngx.say("1.." .. n)
