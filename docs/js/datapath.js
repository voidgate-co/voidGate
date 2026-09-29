(function () {
    var root = document.querySelector("[data-gate]");

    if (!root) {
        return;
    }

    var NS = "http://www.w3.org/2000/svg";
    var SPEED = 0.18;
    var LOG_ROWS = 6;
    var svgs = root.querySelectorAll("svg.flow");
    var log = root.querySelector(".pkt-log");
    var armedEl = root.querySelector("[data-m='armed']");
    var rxEl = root.querySelector("[data-m='rx']");
    var passEl = root.querySelector("[data-m='passed']");
    var dropEl = root.querySelector("[data-m='dropped']");
    var tabs = root.querySelectorAll(".seg button");
    var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var armed = false;
    var rx = 0;
    var passed = 0;
    var dropped = 0;
    var packets = [];
    var lastSpawn = 0;

    function rnd(n) {
        return Math.floor(Math.random() * n);
    }

    function hex() {
        return (rnd(0xffe) + 1).toString(16);
    }

    function keepPacket() {
        var all = [
            { src: "192.0.2.10", dst: ":22", why: "allow_ports 22, local side" },
            { src: "fe80::1", dst: "NDP 135", why: "ICMPv6 NDP, hop limit 255" },
            { src: "169.254.169.254", dst: ":80", why: "allow_v4 169.254.169.254/32" }
        ];

        return all[rnd(all.length)];
    }

    /* Pick a packet kind and the verdict voidgate.bpf.c would give it. */
    function make(isArmed) {
        var r = Math.random();
        var kind;
        var p;

        if (isArmed) {
            kind = r < 0.55 ? "attack" : (r < 0.82 ? "legit" : "keep");
        } else {
            kind = r < 0.75 ? "legit" : (r < 0.9 ? "keep" : "attack");
        }

        if (kind === "attack") {
            p = Math.random() < 0.7
                ? { src: "203.0.113." + (rnd(254) + 1), why: "drop_v4 203.0.113.0/24" }
                : { src: "2001:db8:bad::" + hex(), why: "drop_v6 2001:db8:bad::/64" };
            p.dst = ":80";
            p.route = "drop";

        } else if (kind === "keep") {
            p = keepPacket();
            p.route = "keep";

        } else {
            p = {
                src: Math.random() < 0.7
                    ? "192.0.2." + (rnd(200) + 20)
                    : "2001:db8:a::" + hex(),
                dst: Math.random() < 0.8 ? ":443" : ":80",
                why: "no rule matched, counted",
                route: "pass"
            };
        }

        if (!isArmed) {
            p.route = "idle";
            p.why = "cfg.armed = 0, not parsed";
        }

        p.kind = kind;
        p.verdict = p.route === "drop" ? "drop" : "pass";

        return p;
    }

    function paintMetrics() {
        armedEl.textContent = armed ? "1" : "0";
        rxEl.textContent = String(rx);
        passEl.textContent = String(passed);
        dropEl.textContent = String(dropped);
    }

    function cell(cls, text) {
        var el = document.createElement("span");

        el.className = cls;
        el.textContent = text;

        return el;
    }

    function addLog(p) {
        var li = document.createElement("li");

        li.className = "k-" + p.kind;
        li.appendChild(cell("src", p.src));
        li.appendChild(cell("dst", "→ " + p.dst));
        li.appendChild(cell("why", p.why));
        li.appendChild(cell("v v-" + p.verdict, p.verdict === "drop" ? "XDP_DROP" : "XDP_PASS"));
        log.insertBefore(li, log.firstChild);

        while (log.children.length > LOG_ROWS) {
            log.removeChild(log.lastChild);
        }
    }

    function seedLog() {
        var i;

        log.textContent = "";

        for (i = 0; i < LOG_ROWS; i++) {
            addLog(make(armed));
        }
    }

    function setArmed(next) {
        armed = next;
        root.dataset.armed = next ? "1" : "0";
        Array.prototype.forEach.call(tabs, function (btn) {
            var on = btn.getAttribute("data-arm") === (next ? "1" : "0");

            btn.setAttribute("aria-selected", on ? "true" : "false");
        });
        paintMetrics();

        if (reduced) {
            seedLog();
        }
    }

    function visibleSvg() {
        var i;

        for (i = 0; i < svgs.length; i++) {
            if (svgs[i].getBoundingClientRect().width > 0) {
                return svgs[i];
            }
        }

        return null;
    }

    function spawn(now) {
        var svg = visibleSvg();
        var info;
        var path;
        var dot;

        if (!svg) {
            return;
        }

        info = make(armed);
        path = svg.querySelector('[data-route="' + info.route + '"]');
        dot = document.createElementNS(NS, "circle");
        dot.setAttribute("r", "5");
        dot.setAttribute("class", "pk pk-" + info.kind);
        svg.querySelector(".pkts").appendChild(dot);

        rx += 1;
        packets.push({
            info: info,
            svg: svg,
            dot: dot,
            path: path,
            len: path.getTotalLength(),
            t0: now,
            countAt: Number(path.getAttribute("data-count-at")) || 0
        });
        paintMetrics();
    }

    function flash(svg, name) {
        var box = svg.querySelector(".verdict-" + name + ", .node-" + name);

        box.classList.add("hit");
        setTimeout(function () {
            box.classList.remove("hit");
        }, 360);
    }

    /* A counted packet leaves a sample in remote_*; show it reaching policy. */
    function feed(p, now) {
        var path = p.svg.querySelector('[data-route="feed"]');
        var dot = document.createElementNS(NS, "circle");

        flash(p.svg, "count");
        dot.setAttribute("r", "3");
        dot.setAttribute("class", "pk pk-feed");
        p.svg.querySelector(".pkts").appendChild(dot);
        packets.push({
            feed: true,
            svg: p.svg,
            dot: dot,
            path: path,
            len: path.getTotalLength(),
            t0: now
        });
    }

    function land(p) {
        if (p.feed) {
            flash(p.svg, "policy");
            p.dot.remove();
            return;
        }

        /* In IDLE the program only bumps rx_*; passed is an armed counter. */
        if (p.info.verdict === "drop") {
            dropped += 1;
        } else if (p.info.route !== "idle") {
            passed += 1;
        }

        flash(p.svg, p.info.verdict);
        addLog(p.info);
        paintMetrics();

        if (p.info.verdict === "drop") {
            p.dot.classList.add("pop");
            setTimeout(function () {
                p.dot.remove();
            }, 600);
        } else {
            p.dot.remove();
        }
    }

    function tick(now) {
        var interval = armed ? 420 : 900;
        var i;
        var p;
        var d;
        var pt;

        if (!document.hidden && now - lastSpawn >= interval) {
            spawn(now);
            lastSpawn = now;
        }

        for (i = packets.length - 1; i >= 0; i--) {
            p = packets[i];
            d = (now - p.t0) * SPEED;

            if (p.countAt && !p.fed && d >= p.countAt) {
                p.fed = true;
                feed(p, now);
            }

            if (d >= p.len) {
                packets.splice(i, 1);
                land(p);
                continue;
            }

            pt = p.path.getPointAtLength(d);
            p.dot.setAttribute("cx", pt.x);
            p.dot.setAttribute("cy", pt.y);
        }

        requestAnimationFrame(tick);
    }

    Array.prototype.forEach.call(tabs, function (btn) {
        btn.addEventListener("click", function () {
            setArmed(btn.getAttribute("data-arm") === "1");
        });
    });

    root.addEventListener("keydown", function (ev) {
        if (ev.key === "i" || ev.key === "I") {
            setArmed(false);
        }

        if (ev.key === "a" || ev.key === "A") {
            setArmed(true);
        }
    });

    setArmed(false);

    if (reduced) {
        return;
    }

    seedLog();
    requestAnimationFrame(function (now) {
        lastSpawn = now;
        tick(now);
    });
}());
