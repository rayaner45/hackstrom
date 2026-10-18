/* ============================================================
   HACKSTROM — main.js
   Features: Language switcher (EN/AR), canvas fx, GSAP reveals,
   counters, FAQ accordion, mobile nav, copy, back-to-top.
   Works even without GSAP/CDN (graceful fallbacks).
   ============================================================ */
(function () {
  "use strict";

  /* ================= LOADER ================= */
  var loaderHidden = false;
  function hideLoader() {
    if (loaderHidden) return;
    loaderHidden = true;
    var l = document.getElementById("loader");
    if (l) l.style.cssText = "display:none!important;";
    document.body.classList.remove("is-loading");
    startReveals();
  }
  setTimeout(hideLoader, 900);
  window.addEventListener("load", hideLoader);
  document.addEventListener("DOMContentLoaded", function () { setTimeout(hideLoader, 300); });

  /* ================= LANGUAGE ================= */
  var lang = localStorage.getItem("hs_lang") || "en";
  var langToggle = document.getElementById("langToggle");
  var langLabel = document.getElementById("langLabel");

  function applyLang(l) {
    lang = l;
    localStorage.setItem("hs_lang", l);
    var isAr = l === "ar";
    document.documentElement.lang = l;
    document.documentElement.dir = isAr ? "rtl" : "ltr";

    // Swap every [data-en][data-ar] element
    document.querySelectorAll("[data-en]").forEach(function (el) {
      var val = el.getAttribute(isAr ? "data-ar" : "data-en");
      if (val !== null) el.textContent = val;
    });

    // Toggle button label (target language)
    if (langLabel) langLabel.textContent = isAr ? "EN" : "AR";
  }

  applyLang(lang);

  if (langToggle) {
    langToggle.addEventListener("click", function () {
      applyLang(lang === "en" ? "ar" : "en");
    });
  }

  /* ================= CANVAS FX ================= */
  var cv = document.getElementById("fxCanvas");
  if (cv) {
    var cx = cv.getContext("2d");
    var W, H, pts = [];

    function init() {
      W = cv.width = window.innerWidth;
      H = cv.height = window.innerHeight;
      var n = Math.min(90, Math.floor((W * H) / 22000));
      pts = [];
      for (var i = 0; i < n; i++) {
        pts.push({
          x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.35,
          vy: (Math.random() - 0.5) * 0.35,
          r: Math.random() * 1.6 + 0.4,
          hue: Math.random() > 0.5 ? 270 : 195  // purple or cyan
        });
      }
    }

    function draw() {
      cx.clearRect(0, 0, W, H);

      // Lines
      for (var i = 0; i < pts.length; i++) {
        for (var j = i + 1; j < pts.length; j++) {
          var dx = pts[i].x - pts[j].x;
          var dy = pts[i].y - pts[j].y;
          var d = dx * dx + dy * dy;
          if (d < 20000) {
            cx.strokeStyle = "hsla(270,80%,70%," + (0.12 * (1 - d / 20000)) + ")";
            cx.lineWidth = 0.6;
            cx.beginPath();
            cx.moveTo(pts[i].x, pts[i].y);
            cx.lineTo(pts[j].x, pts[j].y);
            cx.stroke();
          }
        }
      }

      // Dots
      for (var k = 0; k < pts.length; k++) {
        var p = pts[k];
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
        cx.fillStyle = "hsla(" + p.hue + ",85%,65%,0.7)";
        cx.beginPath();
        cx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        cx.fill();
      }

      requestAnimationFrame(draw);
    }

    init();
    draw();
    window.addEventListener("resize", init);
  }

  /* ================= GSAP REVEALS (with fallback) ================= */
  var hasGSAP = typeof gsap !== "undefined";
  var hasST = typeof ScrollTrigger !== "undefined";

  function startReveals() {
    var heroEls = document.querySelectorAll(".hero .reveal");
    var otherEls = document.querySelectorAll(".reveal:not(.hero .reveal)");

    if (hasGSAP && hasST) {
      gsap.registerPlugin(ScrollTrigger);
      gsap.fromTo(heroEls, { y: 40, opacity: 0 }, { y: 0, opacity: 1, duration: 1, stagger: 0.1, ease: "power3.out", delay: 0.1 });
      otherEls.forEach(function (el) {
        ScrollTrigger.create({ trigger: el, start: "top 88%", toggleClass: "is-visible", once: true });
      });
    } else {
      // IntersectionObserver fallback
      heroEls.forEach(function (el) { el.classList.add("is-visible"); });
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add("is-visible"); io.unobserve(e.target); } });
      }, { threshold: 0.12 });
      otherEls.forEach(function (el) { io.observe(el); });
    }
  }

  /* ================= COUNTERS ================= */
  function animateCounters() {
    var counters = document.querySelectorAll("[data-count]");
    var io2 = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        var el = e.target;
        io2.unobserve(el);
        var target = parseInt(el.getAttribute("data-count"), 10) || 0;
        var dur = 2000;
        var start = performance.now();
        function step(now) {
          var p = Math.min((now - start) / dur, 1);
          var ease = 1 - Math.pow(1 - p, 4); // easeOutQuart
          el.textContent = Math.floor(ease * target).toLocaleString();
          if (p < 1) requestAnimationFrame(step);
          else el.textContent = target.toLocaleString();
        }
        requestAnimationFrame(step);
      });
    }, { threshold: 0.4 });
    counters.forEach(function (c) { io2.observe(c); });
  }
  // Delay so elements exist after loader
  setTimeout(animateCounters, 600);

  /* ================= HEADER ================= */
  var header = document.getElementById("header");
  var lastY = 0, ticking = false;
  function onScroll() {
    if (!header) return;
    var y = window.scrollY;
    header.classList.toggle("is-scrolled", y > 40);
    if (y > lastY && y > 160) { header.classList.add("is-hidden"); closeMenu(); }
    else header.classList.remove("is-hidden");
    lastY = y;
    ticking = false;
  }
  window.addEventListener("scroll", function () { if (!ticking) { requestAnimationFrame(onScroll); ticking = true; } });

  /* Active nav highlight */
  var sections = document.querySelectorAll("section[id]");
  var navLinks = document.querySelectorAll(".nav__link");
  window.addEventListener("scroll", function () {
    var y = window.scrollY + 150;
    sections.forEach(function (s) {
      if (y >= s.offsetTop && y < s.offsetTop + s.offsetHeight) {
        navLinks.forEach(function (l) {
          l.classList.toggle("active", l.getAttribute("href") === "#" + s.id);
        });
      }
    });
  });

  /* ================= MOBILE NAV ================= */
  var burger = document.getElementById("navBurger");
  var menu = document.getElementById("navMenu");
  function closeMenu() { if (menu) menu.classList.remove("is-open"); if (burger) burger.classList.remove("is-open"); }
  if (burger && menu) {
    burger.addEventListener("click", function () { menu.classList.toggle("is-open"); burger.classList.toggle("is-open"); });
    menu.querySelectorAll("a").forEach(function (a) { a.addEventListener("click", closeMenu); });
  }

  /* ================= SMOOTH SCROLL ================= */
  document.querySelectorAll('a[href^="#"]').forEach(function (a) {
    a.addEventListener("click", function (e) {
      var href = a.getAttribute("href");
      if (href === "#") return;
      var t = document.querySelector(href);
      if (t) { e.preventDefault(); window.scrollTo({ top: t.offsetTop - 80, behavior: "smooth" }); }
    });
  });

  /* ================= FAQ ================= */
  document.querySelectorAll(".faq__q").forEach(function (q) {
    q.addEventListener("click", function () {
      var item = q.parentElement;
      var wasActive = item.classList.contains("active");
      document.querySelectorAll(".faq__item").forEach(function (i) { i.classList.remove("active"); });
      if (!wasActive) item.classList.add("active");
    });
  });

  /* ================= LEADERBOARD ================= */
  // GitHub config — set your username and repo here after creating it
  // Leave empty to use local data/leaderboard.json
  var GH_USER = "rayaner45";
  var GH_REPO = "hackstrom";
  var GH_BRANCH = "main"; // or "master"

  function loadLeaderboard() {
    // Priority 1: GitHub raw (public, no auth needed)
    if (GH_USER && GH_REPO) {
      var url = "https://raw.githubusercontent.com/" + GH_USER + "/" + GH_REPO + "/" + GH_BRANCH + "/data/leaderboard.json?v=" + Date.now();

      fetch(url)
        .then(function(r) { if (!r.ok) throw new Error("github"); return r.json(); })
        .then(function(data) {
          if (Array.isArray(data) && data.length > 0) {
            renderLeaderboard(data);
          } else {
            throw new Error("bad data");
          }
        })
        .catch(function() { loadLocalLeaderboard(); }); // fallback
      return;
    }

    // Priority 2: Local JSON file
    loadLocalLeaderboard();
  }

  function loadLocalLeaderboard() {
    fetch("./data/leaderboard.json")
      .then(function(r) { if (!r.ok) throw new Error("fetch failed"); return r.json(); })
      .then(function(data) {
        if (Array.isArray(data) && data.length > 0) renderLeaderboard(data);
      })
      .catch(function() {
        var tbody = document.getElementById("lbBody");
        if (tbody) tbody.innerHTML = '<tr><td colspan="4" class="lb__loading">⚠ Could not load leaderboard</td></tr>';
      });
  }

  function renderLeaderboard(data) {
    // Fill podium (top 3)
    [1, 2, 3].forEach(function (rank) {
      var player = data.find(function (d) { return safeNum(d.rank) === rank; });
      if (!player) return;
      var card = document.querySelector('.lb__podium-card[data-rank="' + rank + '"]');
      if (!card) return;
      var nameEl = card.querySelector(".lb__podium-name");
      var ptsEl = card.querySelector(".lb__podium-points");
      var badgeEl = card.querySelector(".lb__podium-badge");
      var avEl = card.querySelector(".lb__podium-avatar");
      if (nameEl) nameEl.textContent = player.name || "";
      if (ptsEl) ptsEl.textContent = safeNum(player.points).toLocaleString() + " pts";
      if (badgeEl) badgeEl.textContent = player.badge || "";
      if (avEl) {
        if (player.avatar) {
          avEl.innerHTML = '<img src="' + escAttr(player.avatar) + '" alt="">';
          var pimg = avEl.querySelector("img");
          if (pimg) pimg.addEventListener("error", function () { pimg.remove(); });
        } else {
          avEl.innerHTML = '<i class="bi bi-person-fill"></i>';
        }
      }
    });

    // Fill table
    var tbody = document.getElementById("lbBody");
    if (!tbody) return;
    tbody.innerHTML = "";
    data.forEach(function (p) {
      var tr = document.createElement("tr");
      var rk = safeNum(p.rank);
      var rankClass = rk <= 3 ? " lb__rank--" + rk : "";
      var avatarHTML = '<span class="lb__player-avatar">' + (p.avatar
        ? '<img src="' + escAttr(p.avatar) + '" alt="">'
        : '<i class="bi bi-person-fill"></i>') + "</span>";

      tr.innerHTML =
        '<td><span class="lb__rank' + rankClass + '">#' + rk + "</span></td>" +
        '<td><div class="lb__player">' + avatarHTML +
        '<span class="lb__player-name">' + escHTML(player.name || "") + "</span></div></td>" +
        '<td><span class="lb__pts">' + safeNum(player.points).toLocaleString() + "</span></td>" +
        '<td><span class="lb__badge-cell">' + escHTML(player.badge || "—") + "</span></td>";
      tbody.appendChild(tr);
    });
  }

  function escHTML(s) {
    var d = document.createElement("div");
    d.textContent = String(s == null ? "" : s);
    return d.innerHTML;
  }

  // Escape a value for safe use inside a quoted HTML attribute
  function escAttr(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Coerce to a finite number (guards against hostile / malformed data)
  function safeNum(n) {
    var v = Number(n);
    return isFinite(v) ? v : 0;
  }

  // Load when the section is near viewport
  var lbSection = document.getElementById("leaderboard");
  if (lbSection) {
    var lbIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { loadLeaderboard(); lbIO.disconnect(); }
      });
    }, { rootMargin: "200px" });
    lbIO.observe(lbSection);
  }

  /* ================= COPY DISCORD ================= */
  var copyBtn = document.getElementById("copyDiscord");
  var copyToast = document.getElementById("copyToast");
  if (copyBtn) {
    copyBtn.addEventListener("click", function () {
      var link = "https://discord.gg/uVeYXjmgFm";
      if (navigator.clipboard) navigator.clipboard.writeText(link).catch(function () {});
      if (copyToast) { copyToast.classList.add("show"); setTimeout(function () { copyToast.classList.remove("show"); }, 1800); }
    });
  }

  /* ================= BACK TO TOP ================= */
  var btt = document.getElementById("backToTop");
  if (btt) {
    window.addEventListener("scroll", function () { btt.classList.toggle("show", window.scrollY > 600); });
    btt.addEventListener("click", function () { window.scrollTo({ top: 0, behavior: "smooth" }); });
  }

  /* ================= YEAR ================= */
  var yEl = document.getElementById("year");
  if (yEl) yEl.textContent = new Date().getFullYear();

})();
