"""Admin-only: updates from signed builds (SPEC section 16).

The page shows the installed and the latest build on the chosen channel, the notes of every
build in between, and the update settings. The web app never contacts GitHub and never
installs anything itself: "Check now" asks the helper to start the check service, "Install"
asks the helper, which verifies the download's signature before it starts the install.
"""
import datetime
import json
import re

from flask import Blueprint, current_app, g, redirect, render_template, request, url_for
from markupsafe import Markup, escape

from .. import helper_client, versions
from ..flashing import flash
from ..security import role_required, stepup_required
from ..services import get_settings, set_setting
from ..updater import DAYS, MODES, last_check
from . import ev

bp = Blueprint("updates", __name__)

DAY_LABELS = {"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday", "thu": "Thursday",
              "fri": "Friday", "sat": "Saturday", "sun": "Sunday", "daily": "Every day"}
MODE_LABELS = {"off": "Off: never contact GitHub",
               "notify": "Notify: check once a day and show new builds here",
               "auto": "Automatic: install new builds by themselves"}


def _cfg():
    return current_app.config["RA"]


def _helper(action, timeout=30, **params):
    try:
        return helper_client.call(_cfg()["helper_socket"], action, timeout=timeout, **params)
    except helper_client.HelperError as e:
        return {"ok": False, "message": str(e)}


def notes_html(text):
    """The Markdown subset used in CHANGELOG.md and release notes (headings, bullets,
    paragraphs, `code`, **bold**), escaped first."""
    out, items, para = [], [], []

    def inline(s):
        s = str(escape(s))
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)

    def flush():
        if items:
            out.append("<ul>" + "".join("<li>%s</li>" % inline(i) for i in items) + "</ul>")
            items.clear()
        if para:
            out.append("<p>%s</p>" % inline(" ".join(para)))
            para.clear()

    for line in (text or "").splitlines():
        s = line.strip()
        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            flush()
            out.append("<h4>%s</h4>" % inline(m.group(2)))
        elif re.match(r"^[-*]\s+", s):
            if para:
                flush()
            items.append(re.sub(r"^[-*]\s+", "", s))
        elif s and items and line.startswith("  "):
            items[-1] += " " + s                       # continuation of a bullet
        elif s:
            if items:
                flush()
            para.append(s)
        else:
            flush()
    flush()
    return Markup("".join(out))


@bp.route("/updates")
@role_required("admin")
def index():
    s = get_settings()["update"]
    installed = versions.installed(_cfg()["build_file"])
    status = _helper("update_status")
    check = last_check()
    releases = []
    if check:
        try:
            releases = json.loads(check["releases"]) if isinstance(check["releases"], str) else check["releases"]
        except ValueError:
            releases = []
    state = status.get("state") or {}
    running = state.get("state") in ("queued", "installing")
    available = bool(check and check["ok"] and check["latest_version"] and check["channel"] == s["channel"]
                     and check["installed_version"] == installed["version"] and check["downloaded"])
    return render_template(
        "updates/index.html", s=s, installed=installed, status=status, check=check, releases=releases,
        state=state, running=running, available=available, notes_html=notes_html,
        channels=[(c, versions.CHANNEL_LABELS[c]) for c in versions.CHANNELS],
        modes=[(m, MODE_LABELS[m]) for m in MODES], days=[(d, DAY_LABELS[d]) for d in DAYS],
        hours=range(24), key_missing=status.get("ok") and not status.get("key_present"))


@bp.route("/updates/settings", methods=["POST"])
@role_required("admin")
@stepup_required
def save_settings():
    s = get_settings()["update"]
    new = {"channel": request.form.get("channel", ""), "mode": request.form.get("mode", ""),
           "window_day": request.form.get("window_day", ""), "window_hour": request.form.get("window_hour", "")}
    if (new["channel"] not in versions.CHANNELS or new["mode"] not in MODES or new["window_day"] not in DAYS
            or not (new["window_hour"].isdigit() and 0 <= int(new["window_hour"]) <= 23)):
        flash("Choose a channel, an update mode and a maintenance window from the lists.", "error")
        return redirect(url_for("updates.index"))
    new["window_hour"] = str(int(new["window_hour"]))
    changed = {k: {"from": s[k], "to": v} for k, v in new.items() if s[k] != v}
    for k in changed:
        set_setting("update_" + k, new[k])
    ev("update.settings", object_type="setting", detail=changed)
    if changed and new["mode"] != "off" and ("channel" in changed or "mode" in changed):
        _request_check()
        flash("Update settings saved. Checking the %s channel now." % new["channel"], "success")
    else:
        flash("Update settings saved." if changed else "No changes.", "success" if changed else "info")
    return redirect(url_for("updates.index"))


def _request_check():
    set_setting("update_check_requested", datetime.datetime.now(datetime.timezone.utc).isoformat())
    return _helper("update_check")


@bp.route("/updates/check", methods=["POST"])
@role_required("admin")
def check_now():
    if get_settings()["update"]["mode"] == "off":
        flash("Updates are off. Choose Notify or Automatic to check GitHub.", "error")
        return redirect(url_for("updates.index"))
    r = _request_check()
    ev("update.check", success=bool(r.get("ok")), object_type="update", detail={"message": r.get("message", "")})
    if r.get("ok"):
        flash("Checking for updates. Reload this page in a minute.", "success")
    else:
        flash("Could not start the update check: %s" % r.get("message"), "error")
    return redirect(url_for("updates.index"))


@bp.route("/updates/install", methods=["POST"])
@role_required("admin")
@stepup_required
def install():
    check = last_check()
    version = request.form.get("version", "")
    if not (check and check["ok"] and check["downloaded"] and version and version == check["latest_version"]):
        flash("That build is no longer the one on offer. Check again and review it first.", "error")
        return redirect(url_for("updates.index"))
    downgrade = bool(check["downgrade"])
    if downgrade and request.form.get("confirm_downgrade") != "1":
        flash("Confirm that you want to install an older build.", "error")
        return redirect(url_for("updates.index"))
    r = _helper("update_install", timeout=120, version=version, allow_downgrade=downgrade,
                actor=g.user["username"])
    ev("update.install_requested", success=bool(r.get("ok")), object_type="update", object_id=version,
       detail={"from": versions.installed(_cfg()["build_file"])["version"], "to": version,
               "downgrade": downgrade, "message": r.get("message", "")})
    if r.get("ok"):
        flash("Installing %s. The console restarts during the install; this page shows the result." % version,
              "success")
    else:
        flash("The update was not started: %s" % r.get("message"), "error")
    return redirect(url_for("updates.index"))
