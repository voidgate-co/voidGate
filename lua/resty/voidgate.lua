-- SPDX-License-Identifier: Apache-2.0
--
-- voidGate client for OpenResty (and OpenResty-based gateways such as
-- Kong and APISIX). Talks to the daemon's Unix socket with a non-blocking
-- ngx.socket.tcp cosocket. Cosockets yield, so the methods run in rewrite,
-- access, content or timer context; from any other phase (log,
-- header_filter, body_filter, init) use M.ban(), which runs in a timer.

local ngx = ngx

local M = {}
local client = {}
client.__index = client

local MAX_TTL = 31536000    -- one year, as the daemon

-- Keep uint64 counters as strings so LuaJIT does not round them.
local counters = {
    rx_pkts = true, rx_bytes = true, passed = true, dropped = true,
    non_ip = true, map_full = true, parse_err = true,
}

-- One command per connection: the daemon replies and closes.
local function request(self, cmd)
    local sock = ngx.socket.tcp()
    sock:settimeout(self.timeout * 1000)

    local ok, err = sock:connect("unix:" .. self.path)
    if not ok then
        return nil, err
    end

    local data
    ok, err = sock:send(cmd .. "\n")
    if ok then
        data, err = sock:receive("*a")
    end
    sock:close()

    if not data then
        return nil, err
    end
    if data:find("^error") then
        return nil, (data:gsub("\n+$", ""))
    end
    return data
end

local function kv(data)
    local t = {}
    for k, v in data:gmatch("([%w_]+)=(%S+)") do
        if counters[k] then
            t[k] = v
        elseif k == "armed" then
            t[k] = v == "1"
        else
            t[k] = tonumber(v) or v
        end
    end
    return t
end

local function check_ttl(ttl)
    ttl = tonumber(ttl)
    if not ttl or ttl ~= math.floor(ttl) or ttl < 1 or ttl > MAX_TTL then
        return nil
    end
    return ttl
end

function client:status()
    local data, err = request(self, "status")
    if not data then
        return nil, err
    end
    return kv(data)
end

function client:stats()
    local data, err = request(self, "stats")
    if not data then
        return nil, err
    end
    return kv(data)
end

function client:drops()
    local data, err = request(self, "drops")
    if not data then
        return nil, err
    end

    local out = {}
    for line in data:gmatch("[^\n]+") do
        local cidr, reason, age = line:match("^(%S+) reason=(%S+) age=(%S+)$")
        if cidr then
            out[#out + 1] = {
                cidr = cidr,
                reason = tonumber(reason) or reason,
                age = tonumber(age) or age,
            }
        end
    end
    return out
end

local function commit(self, cmd)
    local data, err = request(self, cmd)
    if not data then
        return nil, err
    end
    if data ~= "ok\n" then
        return nil, "unexpected response"
    end
    return true
end

function client:arm()
    return commit(self, "arm")
end

function client:disarm()
    return commit(self, "disarm")
end

function client:reload()
    return commit(self, "reload")
end

-- ttl (seconds, optional): the daemon lifts the drop itself after ttl.
function client:drop(cidr, ttl)
    if type(cidr) ~= "string" or cidr:find("%s") then
        return nil, "bad cidr"
    end
    if ttl == nil then
        return commit(self, "drop " .. cidr)
    end
    ttl = check_ttl(ttl)
    if not ttl then
        return nil, "bad ttl"
    end
    return commit(self, string.format("drop %s ttl=%d", cidr, ttl))
end

function client:undrop(cidr)
    if type(cidr) ~= "string" or cidr:find("%s") then
        return nil, "bad cidr"
    end
    return commit(self, "undrop " .. cidr)
end

-- opt: path (default /run/voidgate.sock), timeout in seconds (default 1).
function M.new(opt)
    opt = opt or {}
    return setmetatable({
        path = opt.path or "/run/voidgate.sock",
        timeout = opt.timeout or 1,
    }, client)
end

local default = M.new()
for _, name in ipairs({
    "status", "stats", "drops", "arm", "disarm", "drop", "undrop", "reload",
}) do
    M[name] = function(...)
        return default[name](default, ...)
    end
end

local function ban_timer(premature, c, cidr, ttl)
    if premature then
        return
    end

    local ok, err = c:drop(cidr, ttl)
    if not ok then
        ngx.log(ngx.ERR, "voidgate: drop ", cidr, " ttl=", ttl, ": ", err)
    end
end

-- Ban one client address at XDP for ttl seconds, from any phase.
-- Returns true once the ban is queued (or was queued within the window);
-- the daemon's answer is logged, not returned. Options:
--   dict    lua_shared_dict name. With it, an address is sent at most once
--           per window, so the burst of requests before XDP takes over
--           does not queue one timer per request. Recommended.
--   window  seconds, default 10.
--   client  a client from M.new(); default /run/voidgate.sock.
-- ip must be the real peer: ngx.var.remote_addr, or the realip module's
-- result only when set_real_ip_from lists your proxies.
function M.ban(ip, ttl, opt)
    opt = opt or {}

    if type(ip) ~= "string" or ip == "" or ip:find("[%s/]") then
        return nil, "bad ip"
    end

    ttl = check_ttl(ttl)
    if not ttl then
        return nil, "bad ttl"
    end

    local cidr = ip .. (ip:find(":", 1, true) and "/128" or "/32")

    if opt.dict then
        local dict = ngx.shared[opt.dict]
        if not dict then
            return nil, "no lua_shared_dict " .. opt.dict
        end

        local ok, err = dict:add(cidr, true, opt.window or 10)
        if not ok then
            if err == "exists" then
                return true
            end
            return nil, err
        end
    end

    return ngx.timer.at(0, ban_timer, opt.client or default, cidr, ttl)
end

return M
