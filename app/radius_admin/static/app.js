/* radius-admin: progressive enhancement only. Every page works without JS. */
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    document.body.classList.add("js");

    // Mobile navigation drawer.
    var toggle = document.querySelector("[data-nav-toggle]");
    var nav = document.getElementById("sidenav");
    if (toggle && nav) {
      toggle.addEventListener("click", function () {
        var open = nav.classList.toggle("open");
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && nav.classList.contains("open")) {
          nav.classList.remove("open");
          toggle.setAttribute("aria-expanded", "false");
          toggle.focus();
        }
      });
    }

    // Confirmation for destructive / high-impact forms.
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (!window.confirm(form.getAttribute("data-confirm"))) e.preventDefault();
      });
    });

    // Auto-submit selects (role change) with a confirmation.
    document.querySelectorAll("form[data-autosubmit] select").forEach(function (sel) {
      var initial = sel.value;
      sel.addEventListener("change", function () {
        if (window.confirm("Change role to " + sel.value + "? Their current sessions end.")) {
          sel.form.submit();
        } else {
          sel.value = initial;
        }
      });
    });

    // Reports: print button and checkbox filters that apply on change.
    document.querySelectorAll("[data-print]").forEach(function (btn) {
      btn.addEventListener("click", function () { window.print(); });
    });
    document.querySelectorAll("input[data-autosubmit]").forEach(function (box) {
      box.addEventListener("change", function () { box.form.submit(); });
    });

    // Radio-controlled reveal boxes (secret entry, SSID).
    document.querySelectorAll("[data-reveals]").forEach(function (radio) {
      var box = document.getElementById(radio.getAttribute("data-reveals"));
      if (!box) return;
      var group = document.querySelectorAll('input[name="' + radio.name + '"]');
      function sync() {
        box.hidden = !radio.checked;
        box.querySelectorAll("input").forEach(function (i) { i.disabled = !radio.checked; });
      }
      group.forEach(function (r) { r.addEventListener("change", sync); });
      sync();
    });

    // Copy buttons.
    document.querySelectorAll("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var el = document.getElementById(btn.getAttribute("data-copy"));
        if (!el || !navigator.clipboard) return;
        navigator.clipboard.writeText(el.textContent.trim()).then(function () {
          var old = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(function () { btn.textContent = old; }, 1500);
        });
      });
    });

    // Drop-down menus (row "Actions"/"Manage" menus, account menu): place the open menu
    // against the window, not its table, so a scrolling table wrapper cannot clip it. It
    // opens below its button, or above when there is no room below, and stays on screen.
    var MENUS = "details.row-menu, details.account-menu";
    function placeMenu(d) {
      var menu = d.querySelector(".menu"), btn = d.querySelector("summary");
      if (!menu || !btn) return;
      var gap = 6, edge = 8;
      var vw = document.documentElement.clientWidth, vh = window.innerHeight;
      menu.classList.add("menu-floating");
      menu.style.bottom = "auto";
      menu.style.right = "auto";
      menu.style.maxHeight = (vh - 2 * edge) + "px";
      var r = btn.getBoundingClientRect(), h = menu.offsetHeight, w = menu.offsetWidth;
      var top = r.bottom + gap;
      if (top + h > vh - edge) {
        top = (r.top - gap - h >= edge) ? r.top - gap - h : Math.max(edge, vh - edge - h);
      }
      var left = Math.min(Math.max(edge, r.right - w), vw - edge - w);
      menu.style.top = top + "px";
      menu.style.left = Math.max(edge, left) + "px";
    }
    document.querySelectorAll(MENUS).forEach(function (d) {
      d.addEventListener("toggle", function () { if (d.open) placeMenu(d); });
    });
    function placeOpenMenus() {
      document.querySelectorAll(MENUS.replace(/details\.([a-z-]+)/g, "details.$1[open]")).forEach(placeMenu);
    }
    window.addEventListener("resize", placeOpenMenus);
    window.addEventListener("scroll", placeOpenMenus, true);   // capture: table wrappers scroll too

    // Close open <details> menus on outside click / Escape.
    document.addEventListener("click", function (e) {
      document.querySelectorAll("details.account-menu[open], details.row-menu[open]").forEach(function (d) {
        if (!d.contains(e.target)) d.removeAttribute("open");
      });
    });
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Escape") return;
      document.querySelectorAll("details.account-menu[open], details.row-menu[open]").forEach(function (d) {
        d.removeAttribute("open");
        var s = d.querySelector("summary");
        if (s) s.focus();
      });
    });

    // Pop-up dialogs (e.g. the full 802.1X port list of a client).
    document.querySelectorAll("[data-dialog-open]").forEach(function (btn) {
      var dlg = document.getElementById(btn.getAttribute("data-dialog-open"));
      if (!dlg || typeof dlg.showModal !== "function") return;
      btn.addEventListener("click", function () { dlg.showModal(); });
      dlg.addEventListener("close", function () { btn.focus(); });
      dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });  // backdrop
    });

    // Tab key inserts a tab in the custom policy editor (Esc then Tab leaves).
    var editor = document.querySelector("textarea.code-edit");
    if (editor) {
      var escaped = false;
      editor.addEventListener("keydown", function (e) {
        if (e.key === "Escape") { escaped = true; return; }
        if (e.key === "Tab" && !e.shiftKey && !escaped) {
          e.preventDefault();
          var s = editor.selectionStart, t = editor.selectionEnd;
          editor.value = editor.value.slice(0, s) + "\t" + editor.value.slice(t);
          editor.selectionStart = editor.selectionEnd = s + 1;
        }
        escaped = false;
      });
    }
  });
})();
