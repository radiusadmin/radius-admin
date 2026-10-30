"""Alerts (SPEC section 13): open alerts and history for everyone; thresholds and
delivery settings for admins (step-up). The monitor service evaluates and sends."""
import re

from flask import Blueprint, current_app, g, redirect, render_template, request, url_for

from .. import db
from ..alerts import LABELS
from ..flashing import flash
from ..security import login_required, role_required, stepup_required
from . import ev, form_bool, form_str

bp = Blueprint("alerts", __name__, url_prefix="/alerts")
AAD = b"radius-admin/alert_settings/smtp"
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")
_ADDR_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}$")


def monitor_state():
    return db.query_one("SELECT *, heartbeat_at > now() - interval '3 minutes' AS alive FROM ui.monitor_state"
                        " WHERE id = 1")


@bp.route("/")
@login_required
def index():
    show = request.args.get("show", "")
    where = " WHERE kind <> 'test'" if show != "all" else ""
    rows = db.query("SELECT * FROM ui.alert" + where + " ORDER BY (state = 'open') DESC, opened_at DESC LIMIT 200")
    s = db.query_one("SELECT * FROM ui.alert_settings WHERE id = 1")
    return render_template("alerts/index.html", rows=rows, s=s, show=show, labels=LABELS, mon=monitor_state())


@bp.route("/settings", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def settings():
    s = db.query_one("SELECT *, smtp_pass_enc IS NOT NULL AS pass_set FROM ui.alert_settings WHERE id = 1")
    form, errors = dict(s), {}
    if request.method == "POST":
        for k in ("syslog_enabled", "email_enabled", "reject_enabled", "switch_enabled", "radius_enabled"):
            form[k] = form_bool(k)
        for k, lo, hi in (("reject_threshold", 1, 100000), ("reject_window_minutes", 1, 1440),
                          ("switch_failed_polls", 1, 20), ("smtp_port", 1, 65535)):
            try:
                form[k] = int(form_str(k) or "0")
                if not lo <= form[k] <= hi:
                    raise ValueError
            except ValueError:
                errors[k] = "Enter a whole number from %d to %d." % (lo, hi)
        form["smtp_host"] = form_str("smtp_host", maxlen=253)
        form["smtp_security"] = form_str("smtp_security") or "starttls"
        form["smtp_user"] = form_str("smtp_user", maxlen=200)
        form["mail_from"] = form_str("mail_from", maxlen=254)
        form["mail_to"] = form_str("mail_to", maxlen=1000)
        password = request.form.get("smtp_pass", "")
        clear_pass = form_bool("smtp_pass_clear")
        if form["smtp_host"] and not _HOST_RE.match(form["smtp_host"]):
            errors["smtp_host"] = "Enter a host name or IP address."
        if form["smtp_security"] not in ("starttls", "tls", "none"):
            errors["smtp_security"] = "Choose a security mode."
        if form["mail_from"] and not _ADDR_RE.match(form["mail_from"]):
            errors["mail_from"] = "Enter one email address."
        tos = [a.strip() for a in form["mail_to"].replace(";", ",").split(",") if a.strip()]
        if any(not _ADDR_RE.match(a) for a in tos) or len(tos) > 20:
            errors["mail_to"] = "Enter up to 20 email addresses separated by commas."
        if len(password) > 200 or any(ord(c) < 32 for c in password):
            errors["smtp_pass"] = "The password is too long or contains control characters."
        if form["email_enabled"] and not (form["smtp_host"] and form["mail_from"] and tos):
            errors["email_enabled"] = "Email needs a relay, a From address and at least one recipient."
        if form["smtp_user"] and form["smtp_security"] == "none":
            errors["smtp_security"] = "A login over an unencrypted connection is not allowed; use STARTTLS or TLS."
        if not errors:
            sets = ["syslog_enabled=%s", "email_enabled=%s", "reject_enabled=%s", "switch_enabled=%s",
                    "radius_enabled=%s", "reject_threshold=%s", "reject_window_minutes=%s", "switch_failed_polls=%s",
                    "smtp_host=%s", "smtp_port=%s", "smtp_security=%s", "smtp_user=%s", "mail_from=%s", "mail_to=%s",
                    "updated_at=now()", "updated_by=%s"]
            params = [form[k] for k in ("syslog_enabled", "email_enabled", "reject_enabled", "switch_enabled",
                                        "radius_enabled", "reject_threshold", "reject_window_minutes",
                                        "switch_failed_polls", "smtp_host", "smtp_port", "smtp_security", "smtp_user",
                                        "mail_from")] + [", ".join(tos), g.user["username"]]
            if password:
                sets.append("smtp_pass_enc=%s")
                params.append(current_app.config["RA_DATA_KEY"].encrypt(password.encode("utf-8"), AAD))
            elif clear_pass:
                sets.append("smtp_pass_enc=NULL")
            db.execute("UPDATE ui.alert_settings SET " + ", ".join(sets) + " WHERE id = 1", tuple(params))
            changed = {k: form[k] for k in ("syslog_enabled", "email_enabled", "reject_enabled", "switch_enabled",
                                            "radius_enabled", "reject_threshold", "reject_window_minutes",
                                            "switch_failed_polls", "smtp_host", "smtp_port", "smtp_security",
                                            "smtp_user", "mail_from") if form[k] != s[k]}
            if ", ".join(tos) != s["mail_to"]:
                changed["mail_to"] = ", ".join(tos)
            ev("alert.settings", object_type="alert_settings", object_id=1,
               detail={"changed": changed, "smtp_login_key_updated": bool(password), "smtp_login_key_removed": clear_pass})
            flash("Alert settings saved.", "success")
            return redirect(url_for("alerts.index"))
    return render_template("alerts/settings.html", s=form, errors=errors), (400 if errors else 200)


@bp.route("/test", methods=["POST"])
@role_required("admin")
def test():
    db.execute("UPDATE ui.alert_settings SET test_requested_at = now(), test_requested_by = %s WHERE id = 1",
               (g.user["username"],))
    ev("alert.test", object_type="alert_settings", object_id=1)
    flash("Test alert requested. The monitoring service sends it within a few seconds; check syslog"
          " (and your inbox if email is on). The result appears below.", "success")
    return redirect(url_for("alerts.index", show="all"))
