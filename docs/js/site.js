(function () {
    var header = document.querySelector(".site-header");
    var toggle = document.querySelector(".nav-toggle");
    var nav = document.getElementById("site-nav");
    var page = (location.pathname.split("/").pop() || "index.html");

    if (page === "" || page === "/") {
        page = "index.html";
    }

    if (nav) {
        Array.prototype.forEach.call(nav.querySelectorAll("a[href]"), function (a) {
            var href = a.getAttribute("href");

            if (href === page) {
                a.setAttribute("aria-current", "page");
            }
        });
    }

    if (toggle && header) {
        toggle.addEventListener("click", function () {
            var open = header.classList.toggle("is-open");

            toggle.setAttribute("aria-expanded", open ? "true" : "false");
            toggle.textContent = open ? "Close" : "Menu";
        });
    }

    buildToc();

    function buildToc() {
        var toc = document.querySelector(".toc");
        var prose = document.querySelector(".doc-body .prose");
        var heads;
        var list;
        var links = {};
        var io;

        if (!toc || !prose) {
            return;
        }

        heads = prose.querySelectorAll("h2");

        if (heads.length < 2) {
            return;
        }

        list = document.createElement("ol");

        Array.prototype.forEach.call(heads, function (h) {
            var li = document.createElement("li");
            var a = document.createElement("a");

            if (!h.id) {
                h.id = h.textContent.trim().toLowerCase()
                    .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
            }

            a.href = "#" + h.id;
            a.textContent = h.textContent;
            links[h.id] = a;
            li.appendChild(a);
            list.appendChild(li);
        });

        toc.appendChild(list);
        toc.hidden = false;

        if (!("IntersectionObserver" in window)) {
            return;
        }

        io = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
                if (!e.isIntersecting) {
                    return;
                }

                Object.keys(links).forEach(function (id) {
                    links[id].classList.toggle("is-current", id === e.target.id);
                });
            });
        }, { rootMargin: "-80px 0px -70% 0px" });

        Array.prototype.forEach.call(heads, function (h) {
            io.observe(h);
        });
    }

    document.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".copy");
        var block;
        var text;

        if (!btn) {
            return;
        }

        block = btn.closest(".code");

        if (!block) {
            return;
        }

        text = block.querySelector("pre").innerText;

        function ok() {
            var prev = btn.textContent;

            btn.textContent = "Copied";
            btn.classList.add("is-copied");
            setTimeout(function () {
                btn.textContent = prev;
                btn.classList.remove("is-copied");
            }, 1400);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(ok, function () {
                btn.textContent = "Copy failed";
            });
        } else {
            ok();
        }
    });
}());
