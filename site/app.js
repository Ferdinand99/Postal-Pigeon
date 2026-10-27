// Wise Wren landing page — progressive enhancement only. Everything on the
// page works without this file: the nav wraps and all content is visible.
// It makes no network requests and stores nothing.
(function () {
  "use strict";

  // Tells the CSS the script is running (cancels the reveal safety net)
  document.documentElement.classList.add("js-ok");

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  // Nav: hairline once content scrolls under it --------------------------
  var bar = document.querySelector(".topbar");
  function onScroll() {
    if (bar) bar.classList.toggle("is-scrolled", window.scrollY > 4);
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // Mobile menu ------------------------------------------------------------
  var toggle = document.querySelector(".nav-toggle");
  var menu = document.getElementById("topnav");
  if (toggle && menu && bar) {
    toggle.hidden = false;
    var setOpen = function (open) {
      toggle.setAttribute("aria-expanded", String(open));
      toggle.setAttribute("aria-label", open ? "Close menu" : "Menu");
      menu.classList.toggle("open", open);
      bar.classList.toggle("menu-open", open);
    };
    toggle.addEventListener("click", function () {
      setOpen(toggle.getAttribute("aria-expanded") !== "true");
    });
    menu.addEventListener("click", function (e) {
      if (e.target.closest("a")) setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && menu.classList.contains("open")) {
        setOpen(false);
        toggle.focus();
      }
    });
    document.addEventListener("click", function (e) {
      if (menu.classList.contains("open") && !bar.contains(e.target)) setOpen(false);
    });
    // Tabbing out of the open menu closes it, so it never hides the page
    menu.addEventListener("focusout", function (e) {
      if (menu.classList.contains("open") && e.relatedTarget && !bar.contains(e.relatedTarget)) setOpen(false);
    });
    window.matchMedia("(min-width: 881px)").addEventListener("change", function (mq) {
      if (mq.matches) setOpen(false);
    });
  }

  // Current section in the nav ---------------------------------------------
  var navLinks = Array.prototype.slice.call(document.querySelectorAll('.topnav-link[href^="#"]'));
  if ("IntersectionObserver" in window && navLinks.length) {
    var byId = {};
    navLinks.forEach(function (a) {
      byId[a.getAttribute("href").slice(1)] = a;
    });
    var spy = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          var link = byId[entry.target.id];
          if (!link) return;
          if (entry.isIntersecting) {
            navLinks.forEach(function (a) {
              a.removeAttribute("aria-current");
            });
            link.setAttribute("aria-current", "true");
          } else if (link.getAttribute("aria-current")) {
            link.removeAttribute("aria-current");
          }
        });
      },
      { rootMargin: "-45% 0px -50% 0px" }
    );
    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) spy.observe(el);
    });
  }

  // Reveal on scroll, once ---------------------------------------------------
  var reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && !reduceMotion.matches) {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-in");
            io.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
    );
    reveals.forEach(function (el) {
      io.observe(el);
    });
  } else {
    reveals.forEach(function (el) {
      el.classList.add("is-in");
    });
  }

  // Keyboard users jumping to content that hasn't revealed yet see it at once
  document.addEventListener("focusin", function (e) {
    var el = e.target.closest && e.target.closest(".reveal");
    if (el) el.classList.add("is-in");
  });
})();
