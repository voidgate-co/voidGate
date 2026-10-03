#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run lua/resty/voidgate.lua inside nginx against a daemon in private
# namespaces: the client methods (resty.lua) and ban(). Needs OpenResty, or
# nginx with lua-nginx-module (Ubuntu: libnginx-mod-http-lua); set NGINX
# to pick the binary. Workers run as nobody:nogroup, so this also covers
# ctl_socket_group.
set -euo pipefail

. "$(dirname "$0")/../bin/create_env.sh"

conf=$work/voidgate.conf
prefix=$work/nginx

nginx=${NGINX:-$(command -v openresty || command -v nginx || true)}
if [[ -z $nginx ]]; then
    echo "skip: no openresty or nginx in PATH (set NGINX)" >&2
    exit 0
fi

cleanup() {
    local result=$?
    trap - EXIT
    if [[ $result != 0 && -e $prefix/error.log ]]; then
        cat "$prefix/error.log" >&2
    fi
    if [[ -e $prefix/nginx.pid ]]; then
        "$nginx" -p "$prefix" -c nginx.conf -s stop 2>/dev/null || true
    fi
    if [[ -e $work/voidgate.pid ]]; then
        "$root/voidgate" -s stop -c "$conf" 2>/dev/null || true
    fi
    exit "$result"
}
trap cleanup EXIT

cp "$root/t/conf/idle.conf" "$conf"
printf 'log_file = %s\n' "$work/daemon.log" >> "$conf"
printf 'pid_file = %s\n' "$work/voidgate.pid" >> "$conf"
printf 'ctl_socket_group = nogroup\n' >> "$conf"
# -v: one log line per drop, so the dedup check below can count them.
timeout --kill-after=2 10 "$root/voidgate" -d -v -c "$conf"

modules=
for m in ndk_http_module ngx_http_lua_module; do
    if [[ -e /usr/lib/nginx/modules/$m.so ]]; then
        modules+="load_module /usr/lib/nginx/modules/$m.so;"$'\n'
    fi
done

# Workers (nobody) may not read the checkout under a home directory.
mkdir -p "$prefix"
cp -r "$root/lua" "$work/lua"
cp "$root/t/integration/resty.lua" "$work/resty.lua"
chmod -R a+rX "$work"
chmod a+w "$conf"     # resty.lua rewrites it to test reload
cat > "$prefix/nginx.conf" <<NGINX
$modules
user nobody nogroup;
worker_processes 2;
pid $prefix/nginx.pid;
error_log $prefix/error.log info;
events {}
http {
    access_log off;
    lua_package_path "$work/lua/?.lua;;";
    lua_shared_dict vg_ban 1m;

    server {
        listen 127.0.0.1:8080;
        default_type text/plain;

        location = /t {
            set \$vg_conf $conf;
            content_by_lua_file $work/resty.lua;
        }

        location = /drops {
            content_by_lua_block {
                for _, d in ipairs(assert(require("resty.voidgate").drops())) do
                    ngx.say(d.cidr, " ", d.reason)
                end
            }
        }

        # ban() from the log phase, where cosockets are not allowed.
        location = /ban {
            content_by_lua_block { ngx.say("queued") }
            log_by_lua_block {
                local ok, err = require("resty.voidgate").ban(
                    ngx.var.arg_ip, 60, { dict = "vg_ban" })
                if not ok then
                    ngx.log(ngx.ERR, "ban: ", err)
                end
            }
        }
    }
}
NGINX

"$nginx" -p "$prefix" -c nginx.conf

get() {
    curl -fsS --retry 5 --retry-connrefused --retry-delay 0 \
        "http://127.0.0.1:8080$1"
}

wait_drops() {
    local i
    for i in $(seq 50); do
        [[ $(get /drops) == "$1" ]] && return 0
        sleep 0.1
    done
    echo "drops: want '$1', got '$(get /drops)'" >&2
    return 1
}

tap=$(get /t)
echo "$tap"
[[ $tap != *'not ok'* && $tap == *$'\n'1..* ]]

# Fifty requests from one address: one ban sent (shared-dict window).
for i in $(seq 50); do
    get '/ban?ip=198.18.0.20' > /dev/null
done
get '/ban?ip=2001:db8::20' > /dev/null
wait_drops $'198.18.0.20/32 4\n2001:db8::20/128 4'
[[ $(grep -c 'drop 198.18.0.20/32 reason 4' "$work/daemon.log") == 1 ]]
# The per-tick summary lands on the next tick (idle_poll_ms).
for i in $(seq 30); do
    grep -q '\] dropped [0-9]* prefix.*timed [1-9]' "$work/daemon.log" && break
    sleep 0.1
done
grep -q '\] dropped [0-9]* prefix.*timed [1-9]' "$work/daemon.log"
get '/ban?ip=1.2.3.4/24' > /dev/null
sleep 0.2
grep -q 'ban: bad ip' "$prefix/error.log"
! grep -q '\[alert\]\|\[crit\]' "$prefix/error.log"

echo "resty client tests passed"
