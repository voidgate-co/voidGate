#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the Lua client against voidgate in private network/mount namespaces."""

import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    subprocess.run(args, check=True)


def wait_ready(process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("voidgate exited before becoming ready")
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(0.5)
                client.connect("/run/voidgate.sock")
                client.sendall(b"status\n")
                if client.recv(1024).startswith(b"state="):
                    return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("timed out waiting for voidgate")


def integration(lua, daemon):
    # unshare makes mount propagation private before this child starts.
    run("mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", "/run")
    run("ip", "link", "add", "test0", "type", "veth", "peer", "name", "peer0")
    for interface in ("lo", "test0", "peer0"):
        run("ip", "link", "set", interface, "up")
    with tempfile.TemporaryDirectory(prefix="voidgate-lua-") as directory:
        config = Path(directory) / "voidgate.conf"
        config.write_text("""interface = test0
xdp_mode = skb
wake_pps = 1000000000
wake_mbps = 1000000000
clear_seconds = 3600
metrics_port = 0
remote_map_size = 64
drop_map_size = 64
local_networks = 198.51.100.10/32,2001:db8:1::10/128
""")
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen(
                [daemon, "-c", str(config)], stdout=log, stderr=log)
            try:
                wait_ready(process)
                subprocess.run(
                    lua + ["tests/test_lua.lua", "/run/voidgate.sock",
                           str(config)], check=True, timeout=30)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                if sys.exc_info()[0] is not None or process.returncode != 0:
                    log.seek(0)
                    print(log.read(), file=sys.stderr)
            if process.returncode != 0:
                raise RuntimeError("voidgate failed during shutdown")
    # The veth pair and private /run disappear when this namespace exits.


def main():
    os.chdir(ROOT)
    isolated = sys.argv[1:2] == ["--isolated"]
    args = sys.argv[2:] if isolated else sys.argv[1:]
    lua = shlex.split(args[0] if args else "lua")
    daemon = str(Path(args[1] if len(args) > 1 else "./voidgate").resolve())
    if os.geteuid() != 0:
        raise RuntimeError("requires root; run make test-lua (uses sudo)")
    for program in ["unshare", "mount", "ip"] + lua[:1]:
        if shutil.which(program) is None:
            raise RuntimeError(f"required program not found: {program}")
    if not lua:
        raise RuntimeError("LUA must name a Lua interpreter")
    if not os.access(daemon, os.X_OK):
        raise RuntimeError(f"build the daemon first: {daemon}")
    if isolated:
        if os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt"):
            raise RuntimeError("refusing to mount /run without isolation")
        integration(lua, daemon)
    else:
        run(*lua, "-e", 'require("socket.unix")')
        run("unshare", "--mount", "--net", "--fork", "--kill-child",
            "--propagation", "private", sys.executable, str(Path(__file__).resolve()),
            "--isolated", shlex.join(lua), daemon)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(f"Lua integration test failed: {error}")
