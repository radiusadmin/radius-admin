/* Plays the safe-apply sequence in the hero. Without this script the figure shows every step
   and both endings; nothing else on the page needs JavaScript. */
(function () {
  "use strict";
  var fig = document.getElementById("safe-apply");
  if (!fig) { return; }
  var steps = Array.prototype.slice.call(fig.querySelectorAll(".step:not(.step-end)"));
  var ends = { ok: fig.querySelector(".step-ok"), fail: fig.querySelector(".step-fail") };
  var check = fig.querySelector(".step-check");
  var buttons = Array.prototype.slice.call(fig.querySelectorAll("[data-play]"));
  var live = document.getElementById("apply-live");
  var still = window.matchMedia("(prefers-reduced-motion: reduce)");
  var timers = [];
  var STEP_MS = 800;

  function clear() {
    timers.forEach(window.clearTimeout);
    timers = [];
    steps.concat([ends.ok, ends.fail]).forEach(function (s) {
      s.classList.remove("is-done", "is-now", "is-failed");
    });
  }

  function mark(i, outcome, seq) {
    seq.forEach(function (s, n) {
      s.classList.toggle("is-done", n <= i);
      s.classList.toggle("is-now", n === i);
    });
    check.classList.toggle("is-failed", outcome === "fail" && i === seq.length - 1);
  }

  function play(outcome, animate) {
    var seq = steps.concat([ends[outcome]]);
    clear();
    fig.setAttribute("data-outcome", outcome);
    buttons.forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-play") === outcome));
    });
    if (!animate || still.matches) {
      mark(seq.length - 1, outcome, seq);
    } else {
      mark(0, outcome, seq);
      seq.forEach(function (s, i) {
        if (i === 0) { return; }
        timers.push(window.setTimeout(function () { mark(i, outcome, seq); }, i * STEP_MS));
      });
    }
    return seq;
  }

  fig.classList.add("js");
  fig.querySelector(".apply-ctl").hidden = false;
  buttons.forEach(function (b) {
    b.addEventListener("click", function () {
      var outcome = b.getAttribute("data-play");
      play(outcome, true);
      live.textContent = outcome === "ok"
        ? "Outcome shown: FreeRADIUS is listening and the new configuration is live."
        : "Outcome shown: the check failed, the previous configuration was restored.";
    });
  });
  play("ok", true);
}());
