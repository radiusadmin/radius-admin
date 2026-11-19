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

    // Confirmation dialog (replaces window.confirm). One <dialog> for the page, built on first
    // use: the question as its title, the rest of the message below, Cancel and an action button
    // named after the button that was pressed. Destructive actions get a red button and start
    // with Cancel focused. Escape, Cancel and a click on the backdrop all cancel.
    var confirmDlg = null, confirmDone = null;
    function buildConfirm() {
      var d = document.createElement("dialog");
      d.className = "confirm-dialog";
      d.setAttribute("aria-labelledby", "confirm-dialog-title");
      d.setAttribute("aria-describedby", "confirm-dialog-body");
      d.innerHTML = '<form method="dialog"><h2 id="confirm-dialog-title"></h2><p id="confirm-dialog-body"></p>' +
        '<div class="confirm-actions"><button type="submit" value="cancel" class="btn btn-quiet" data-cancel>Cancel</button>' +
        '<button type="submit" value="ok" class="btn btn-primary" data-ok>OK</button></div></form>';
      document.body.appendChild(d);
      d.addEventListener("click", function (e) { if (e.target === d) d.close("cancel"); });   // backdrop
      d.addEventListener("close", function () {
        var fn = confirmDone;
        confirmDone = null;
        if (fn) fn(d.returnValue === "ok");
      });
      return d;
    }
    function askConfirm(message, okLabel, danger, done) {
      if (typeof HTMLDialogElement !== "function") { done(window.confirm(message)); return; }  // very old browsers
      confirmDlg = confirmDlg || buildConfirm();
      var m = /^([^?]*\?)\s+([\s\S]+)$/.exec(message.trim());
      confirmDlg.querySelector("h2").textContent = m ? m[1] : message;
      var body = confirmDlg.querySelector("p");
      body.textContent = m ? m[2] : "";
      body.hidden = !m;
      var ok = confirmDlg.querySelector("[data-ok]"), cancel = confirmDlg.querySelector("[data-cancel]");
      ok.textContent = okLabel || "Confirm";
      ok.className = "btn " + (danger ? "btn-danger" : "btn-primary");
      confirmDlg.returnValue = "";
      confirmDone = done;
      confirmDlg.showModal();
      (danger ? cancel : ok).focus();
    }
    function actionLabel(btn) {
      var t = btn ? (btn.textContent || btn.value || "").trim() : "";
      return t && t.length <= 32 ? t : "Confirm";
    }

    // Forms with data-confirm ask first; on OK the form is submitted again (with the same
    // button), so the busy spinner and the browser's own checks run as usual.
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (form.getAttribute("data-confirmed") === "1") { form.removeAttribute("data-confirmed"); return; }
        e.preventDefault();
        var btn = e.submitter || form.querySelector('button[type="submit"], button:not([type])');
        var msg = (btn && btn.getAttribute("data-confirm")) || form.getAttribute("data-confirm");   // a button may ask its own question
        var danger = /danger/.test((btn && btn.className) || "") || /^(Delete|Remove|Disable)\b/.test(msg);
        askConfirm(msg, actionLabel(btn), danger, function (ok) {
          if (!ok) { if (btn) btn.focus(); return; }
          form.setAttribute("data-confirmed", "1");
          if (typeof form.requestSubmit === "function") form.requestSubmit(btn && btn.form === form ? btn : undefined);
          else form.submit();
        });
      });
    });

    // Auto-submit selects (role change) with a confirmation.
    document.querySelectorAll("form[data-autosubmit] select").forEach(function (sel) {
      var initial = sel.value;
      sel.addEventListener("change", function () {
        askConfirm("Change role to " + sel.value + "? Their current sessions end.", "Change role", false, function (ok) {
          if (ok) sel.form.submit();
          else { sel.value = initial; sel.focus(); }
        });
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

    // Busy buttons: a form with data-busy shows a spinner on the button that sent it (and,
    // if the attribute has text, that label) until the next page loads. Runs after the
    // data-confirm handler, so a cancelled confirmation leaves the button alone.
    function busy(btn, label) {
      btn.classList.add("is-busy");
      btn.setAttribute("aria-busy", "true");
      if (label) {
        if (!btn.hasAttribute("data-label")) btn.setAttribute("data-label", btn.textContent);
        btn.textContent = label;
      }
      setTimeout(function () { btn.disabled = true; }, 0);   // after the browser read its name/value
    }
    document.querySelectorAll("form[data-busy]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (e.defaultPrevented) return;
        var btn = e.submitter || form.querySelector('button[type="submit"], button:not([type])');
        if (btn) busy(btn, form.getAttribute("data-busy"));
      });
    });
    window.addEventListener("pageshow", function (e) {         // back button: page from the cache
      if (!e.persisted) return;
      document.querySelectorAll("form[data-busy] .is-busy").forEach(function (btn) {
        btn.classList.remove("is-busy");
        btn.removeAttribute("aria-busy");
        btn.disabled = false;
        if (btn.hasAttribute("data-label")) btn.textContent = btn.getAttribute("data-label");
      });
    });

    function getJSON(url) {
      return fetch(url, {credentials: "same-origin", cache: "no-store", headers: {Accept: "application/json"}})
        .then(function (r) {
          if (!r.ok) throw new Error("HTTP " + r.status);
          if ((r.headers.get("Content-Type") || "").indexOf("application/json") !== 0) {
            window.location.reload();      // signed out: the sign-in page came back instead
            return null;
          }
          return r.json();
        });
    }

    // Live status: [data-live] asks its JSON URL every data-live-interval seconds whether the
    // work is done ({"done": bool, "message": "..."}); the page reloads to show the result.
    // Without JavaScript a <noscript> meta refresh reloads the page instead.
    document.querySelectorAll("[data-live]").forEach(function (el) {
      var url = el.getAttribute("data-live");
      var every = Math.max(1, Number(el.getAttribute("data-live-interval")) || 2) * 1000;
      var limit = (Number(el.getAttribute("data-live-limit")) || 300) * 1000;
      var msg = el.querySelector("[data-live-message]");
      var offline = el.querySelector("[data-live-offline]");
      var started = Date.now(), misses = 0;
      function next() {
        if (Date.now() - started < limit) { setTimeout(tick, every); return; }
        el.classList.add("live-stopped");
        document.querySelectorAll("[data-live-busy]").forEach(function (b) {
          b.classList.remove("is-busy");
          b.removeAttribute("aria-busy");
        });
        if (msg) msg.textContent = el.getAttribute("data-live-timeout") || "Still waiting. Reload this page to check again.";
        if (offline) offline.hidden = true;
      }
      function tick() {
        getJSON(url).then(function (d) {
          if (!d) return;
          misses = 0;
          if (offline) offline.hidden = true;
          if (d.done) { window.location.reload(); return; }
          if (msg && typeof d.message === "string" && d.message) msg.textContent = d.message;
          next();
        }).catch(function () {
          misses += 1;
          if (offline && misses >= 2) offline.hidden = false;
          next();
        });
      }
      setTimeout(tick, every);
    });

    // Session actions (SPEC section 24). A form with data-coa is sent in the background; the
    // session's row shows "Sending…" and then Done or Failed, linked to the action's page.
    // One request asks for the state of every waiting action on the page. Without
    // JavaScript the form posts as usual and the list comes back with the same row states.
    var coaHost = document.querySelector("[data-coa-status]");
    var coaSummary = document.querySelector("[data-coa-summary]");
    var coaTimer = null, coaStarted = 0, COA_LIMIT = 300000;
    function span(cls, text) {
      var e = document.createElement("span");
      e.className = cls;
      if (text) e.textContent = text;
      return e;
    }
    function coaSpinner() {
      var sp = span("spinner");
      sp.setAttribute("aria-hidden", "true");
      return sp;
    }
    function coaBegin(cell, id, label, url) {             // same markup as the coa_state macro
      var a = document.createElement("a");
      a.className = "coa-link";
      a.href = url;
      a.appendChild(coaSpinner());
      a.appendChild(span("coa-text", "Sending…"));
      a.appendChild(span("cell-sub", label));
      cell.textContent = "";
      cell.appendChild(a);
      cell.setAttribute("data-coa-waiting", id);
    }
    function coaFinish(cell, state, message) {
      var sp = cell.querySelector(".spinner"), text = cell.querySelector(".coa-text");
      var tag = state === "ok" ? span("tag tag-ok", "Done")
        : state === "failed" ? span("tag tag-danger", "Failed") : span("tag tag-muted", "No answer yet");
      cell.removeAttribute("data-coa-waiting");
      if (text) text.remove();
      if (sp) sp.replaceWith(tag);
      else cell.insertBefore(tag, cell.firstChild);
      var link = cell.querySelector("a.coa-link");
      if (link && message && state !== "ok") link.title = message;
      if (cell.hasAttribute("data-coa-plain") && message) cell.appendChild(span("cell-sub", message));
    }
    function coaPoll() {
      coaTimer = null;
      var cells = Array.prototype.slice.call(document.querySelectorAll("[data-coa-waiting]"));
      if (!cells.length) return;
      if (Date.now() - coaStarted > COA_LIMIT) {
        cells.forEach(function (c) { coaFinish(c, "late", "Still waiting. Reload the page to check again."); });
        return;
      }
      var byId = {};
      cells.forEach(function (c) { byId[c.getAttribute("data-coa-waiting")] = c; });
      var again = function () { if (!coaTimer) coaTimer = setTimeout(coaPoll, 2000); };
      getJSON(coaHost.getAttribute("data-coa-status") + "?id=" + Object.keys(byId).join("&id=")).then(function (d) {
        if (!d) return;
        (d.requests || []).forEach(function (r) {
          if (r.state !== "waiting" && byId[r.id]) coaFinish(byId[r.id], r.state, r.message);
        });
        again();
      }).catch(again);
    }
    function coaWatch() {
      coaStarted = Date.now();
      if (!coaTimer) coaTimer = setTimeout(coaPoll, 1500);
    }
    function coaSay(text, bad) {
      if (!coaSummary) return;
      coaSummary.textContent = text;
      coaSummary.className = "coa-summary flash " + (bad ? "flash-error" : "flash-info");
      coaSummary.hidden = !text;
    }
    if (coaHost && document.querySelector("[data-coa-waiting]")) coaWatch();

    // Tick boxes for acting on several sessions: the bar counts the selection, its buttons
    // work once something is ticked and ask "<Action> N sessions?" first.
    var bulk = document.querySelector("form[data-bulk]");
    var syncBulk = function () {};
    if (bulk) {
      var bulkAll = document.querySelector("[data-bulk-all]");
      var bulkCount = bulk.querySelector("[data-bulk-count]");
      var bulkIdle = bulkCount ? bulkCount.textContent : "";
      var bulkBoxes = function () { return Array.prototype.slice.call(document.querySelectorAll("[data-bulk-box]")); };
      syncBulk = function () {
        var boxes = bulkBoxes();
        var n = boxes.filter(function (b) { return b.checked; }).length;
        var many = n === 1 ? "1 session" : n + " sessions";
        if (bulkCount) bulkCount.textContent = n ? many + " selected" : bulkIdle;
        bulk.classList.toggle("has-selection", n > 0);
        bulk.querySelectorAll("[data-bulk-button]").forEach(function (b) {
          b.disabled = !n;
          b.setAttribute("data-confirm", (b.getAttribute("data-confirm-many") || "").replace("{n}", many));
        });
        if (bulkAll) {
          bulkAll.checked = n > 0 && n === boxes.length;
          bulkAll.indeterminate = n > 0 && n < boxes.length;
        }
      };
      bulkBoxes().forEach(function (b) { b.addEventListener("change", syncBulk); });
      if (bulkAll) {
        bulkAll.addEventListener("change", function () {
          var on = bulkAll.checked;
          bulkBoxes().forEach(function (b) { b.checked = on; });
          syncBulk();
        });
      }
      syncBulk();
      window.addEventListener("pageshow", syncBulk);        // the browser may restore ticks
    }

    // Registered after the data-confirm handler, so a cancelled confirmation sends nothing.
    document.querySelectorAll("form[data-coa]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (e.defaultPrevented || !coaHost || !window.fetch || !window.URLSearchParams) return;
        e.preventDefault();
        var btn = e.submitter;
        var body = new URLSearchParams(new FormData(form));
        if (btn && btn.name) body.append(btn.name, btn.value);
        var menu = form.closest ? form.closest("details.row-menu") : null;
        if (menu) {
          menu.removeAttribute("open");
          var opener = menu.querySelector("summary");
          if (opener) opener.focus();
        }
        var buttons = form.querySelectorAll("button");
        buttons.forEach(function (b) { b.disabled = true; });
        var done = function () {
          buttons.forEach(function (b) { b.disabled = false; });
          syncBulk();
        };
        fetch(form.action, {method: "POST", credentials: "same-origin", headers: {Accept: "application/json"}, body: body})
          .then(function (r) {
            if ((r.headers.get("Content-Type") || "").indexOf("application/json") !== 0) {
              if (r.ok) { window.location.reload(); return null; }      // signed out
              throw new Error("HTTP " + r.status);
            }
            return r.json();
          }).then(function (d) {
            if (!d) return;
            (d.queued || []).forEach(function (x) {
              var row = document.querySelector('tr[data-session="' + x.sid + '"]');
              var cell = row && row.querySelector("[data-coa-state]");
              var box = row && row.querySelector("[data-bulk-box]");
              if (cell) coaBegin(cell, x.id, d.label, x.url);
              if (box) box.checked = false;
            });
            coaSay(d.message || "", !(d.queued || []).length);
            done();
            if ((d.queued || []).length) coaWatch();
          }).catch(function () {
            coaSay("The action could not be sent. Reload the page and try again.", true);
            done();
          });
      });
    });

    // Install log (Updates page): the Details drop-down fetches the log as it grows and keeps
    // the view at the bottom unless the reader scrolled up. Stays open across the reload
    // that shows the result.
    var logBox = document.querySelector("details[data-update-log]");
    if (logBox) {
      var term = logBox.querySelector("[data-log-text]");
      var note = logBox.querySelector("[data-log-note]");
      var bar = logBox.querySelector(".terminal-bar");
      var nameEl = logBox.querySelector("[data-log-name]");
      var logUrl = logBox.getAttribute("data-update-log");
      var offset = 0, logName = null, timer = null, inflight = false, MAX_CHARS = 400000;
      var live = logBox.hasAttribute("data-live-log");
      if (bar && live) bar.classList.add("is-live");
      var say = function (text) { if (note) { note.textContent = text; note.hidden = !text; } };
      var fetchLog = function () {
        timer = null;
        if (!logBox.open || inflight) return;
        inflight = true;
        getJSON(logUrl + (logUrl.indexOf("?") < 0 ? "?" : "&") + "offset=" + offset).then(function (d) {
          inflight = false;
          if (!d) return;
          if (!d.available) { say(d.message || "The install log is not available."); return; }
          if (d.name !== logName) { term.textContent = ""; logName = d.name; offset = 0; }
          if (nameEl && d.name) nameEl.textContent = d.name;
          var atEnd = term.scrollHeight - term.scrollTop - term.clientHeight < 24;
          if (d.skipped) term.appendChild(document.createTextNode("[… " + d.skipped + " earlier bytes not shown …]\n"));
          if (d.text) term.appendChild(document.createTextNode(d.text));
          if (term.textContent.length > MAX_CHARS) term.textContent = term.textContent.slice(-MAX_CHARS / 2);
          offset = d.offset;
          say(term.textContent ? "" : (d.message && d.message !== "ok" ? d.message : "The log is empty so far."));
          if (atEnd) term.scrollTop = term.scrollHeight;
          live = !!d.running;
          if (bar) bar.classList.toggle("is-live", live);
          if (live) timer = setTimeout(fetchLog, 2000);
        }).catch(function () {
          inflight = false;
          say("Lost contact with the console (it restarts during the install); retrying…");
          if (live) timer = setTimeout(fetchLog, 3000);
        });
      };
      logBox.addEventListener("toggle", function () {
        try { window.sessionStorage.setItem("ra-update-log-open", logBox.open ? "1" : "0"); } catch (e) { /* private mode */ }
        if (logBox.open && !timer) fetchLog();
      });
      try { if (window.sessionStorage.getItem("ra-update-log-open") === "1") logBox.open = true; } catch (e) { /* private mode */ }
      if (logBox.open) fetchLog();
    }
  });
})();
