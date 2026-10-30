"""Switch monitoring (read-only SNMPv3, SPEC section 12).

Admins manage the SNMPv3 credentials and polling options (step-up required; the
passphrases are write-only and stored AES-256-GCM encrypted). Operators can ask for
an immediate refresh or test one switch. The web app never sends SNMP itself: it
queues the work and radius-admin-snmp.service (the only component allowed onto the
network) carries it out.
"""
from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .. import db
from ..flashing import flash
from ..security import login_required, role_required, stepup_required
from ..snmp import validate_passphrase, validate_username
from ..snmp_poller import encrypt_pass
from . import ev, form_bool, form_str

bp = Blueprint("snmp", __name__, url_prefix="/switch-monitoring")

AUTH_PROTOCOLS = ("SHA-256", "SHA-384", "SHA-512")


def profile():
    return db.query_one("SELECT id, enabled, username, auth_protocol, priv_protocol, poll_minutes,"
                        " auto_update_ports, refresh_requested_at, updated_at, updated_by, coa_port,"
                        " auth_pass_enc IS NOT NULL AS auth_set, priv_pass_enc IS NOT NULL AS priv_set"
                        " FROM ui.snmp_profile WHERE id = 1")


def overview():
    return db.query_one("SELECT count(*) AS total, count(s.client_id) AS polled,"
                        " count(*) FILTER (WHERE s.reachable) AS reachable, max(s.polled_at) AS last_poll"
                        " FROM ui.radius_client c LEFT JOIN ui.switch_status s ON s.client_id = c.id"
                        " WHERE c.is_switch")


@bp.route("/", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def index():
    p = profile()
    errors = {}
    form = dict(p)
    if request.method == "POST":
        form["enabled"] = form_bool("enabled")
        form["auto_update_ports"] = form_bool("auto_update_ports")
        form["username"] = form_str("username", maxlen=64)
        form["auth_protocol"] = form_str("auth_protocol") or "SHA-256"
        auth_pass = request.form.get("auth_pass", "")
        priv_pass = request.form.get("priv_pass", "")
        try:
            form["poll_minutes"] = int(form_str("poll_minutes") or "15")
            if not 5 <= form["poll_minutes"] <= 1440:
                raise ValueError
        except ValueError:
            errors["poll_minutes"] = "Enter a number of minutes between 5 and 1440."
        try:
            form["coa_port"] = int(form_str("coa_port") or "1700")
            if not 1 <= form["coa_port"] <= 65535:
                raise ValueError
        except ValueError:
            errors["coa_port"] = "Enter a UDP port from 1 to 65535 (Catalyst 1300: 1700)."
        if form["auth_protocol"] not in AUTH_PROTOCOLS:
            errors["auth_protocol"] = "Choose SHA-256, SHA-384 or SHA-512."
        if form["username"] or form["enabled"]:
            try:
                form["username"] = validate_username(form["username"])
            except ValueError as e:
                errors["username"] = str(e)
        for field, value, label, is_set in (("auth_pass", auth_pass, "Authentication passphrase", p["auth_set"]),
                                            ("priv_pass", priv_pass, "Privacy passphrase", p["priv_set"])):
            if value:
                try:
                    validate_passphrase(value, label)
                except ValueError as e:
                    errors[field] = str(e)
            elif form["enabled"] and not is_set:
                errors[field] = "%s is required to enable monitoring." % label
        if auth_pass and priv_pass and auth_pass == priv_pass:
            errors["priv_pass"] = "Use a different passphrase for privacy than for authentication."
        if not errors:
            key = current_app.config["RA_DATA_KEY"]
            sets = ["enabled=%s", "username=%s", "auth_protocol=%s", "poll_minutes=%s",
                    "auto_update_ports=%s", "coa_port=%s", "updated_at=now()", "updated_by=%s"]
            params = [form["enabled"], form["username"], form["auth_protocol"], form["poll_minutes"],
                      form["auto_update_ports"], form["coa_port"], g.user["username"]]
            if auth_pass:
                sets.append("auth_pass_enc=%s")
                params.append(encrypt_pass(key, "auth", auth_pass))
            if priv_pass:
                sets.append("priv_pass_enc=%s")
                params.append(encrypt_pass(key, "priv", priv_pass))
            if form["enabled"]:
                sets.append("refresh_requested_at=now()")
            db.execute("UPDATE ui.snmp_profile SET " + ", ".join(sets) + " WHERE id = 1", tuple(params))
            changed = {k: form[k] for k in ("enabled", "username", "auth_protocol", "poll_minutes",
                                            "auto_update_ports", "coa_port") if form[k] != p[k]}
            ev("snmp.settings", object_type="snmp_profile", object_id=1,
               detail={"changed": changed, "auth_pass_changed": bool(auth_pass),
                       "priv_pass_changed": bool(priv_pass)})
            flash("Switch monitoring settings saved." + (" A poll has been started." if form["enabled"] else ""),
                  "success")
            return redirect(url_for("snmp.index"))
    tests = db.query("SELECT t.*, c.name FROM ui.snmp_test t JOIN ui.radius_client c ON c.id = t.client_id"
                     " ORDER BY t.id DESC LIMIT 10")
    clients = db.query("SELECT id, name, ipaddr, is_switch, description FROM ui.radius_client ORDER BY name")
    return render_template("snmp/index.html", p=form, errors=errors, ov=overview(), tests=tests,
                           clients=clients, protocols=AUTH_PROTOCOLS), (400 if errors else 200)


@bp.route("/devices", methods=["POST"])
@role_required("admin")
@stepup_required
def devices():
    """Bulk-select which RADIUS clients are switches (polled over SNMP)."""
    chosen = set()
    for v in request.form.getlist("switch"):
        try:
            chosen.add(int(v))
        except ValueError:
            abort(400)
    rows = db.query("SELECT id, name, is_switch FROM ui.radius_client")
    on = [r for r in rows if r["id"] in chosen and not r["is_switch"]]
    off = [r for r in rows if r["id"] not in chosen and r["is_switch"]]
    for r in on + off:
        db.execute("UPDATE ui.radius_client SET is_switch = %s, updated_at = now() WHERE id = %s",
                   (r["id"] in chosen, r["id"]))
        if r["id"] not in chosen:
            db.execute("DELETE FROM ui.switch_status WHERE client_id = %s", (r["id"],))
    if on or off:
        ev("snmp.devices", object_type="radius_client",
           detail={"switches_added": sorted(r["name"] for r in on), "switches_removed": sorted(r["name"] for r in off)})
        db.execute("UPDATE ui.snmp_profile SET refresh_requested_at = now() WHERE id = 1 AND enabled")
    flash("%d marked as switch, %d unmarked." % (len(on), len(off)), "success")
    return redirect(url_for("snmp.index") + "#devices")


@bp.route("/refresh", methods=["POST"])
@role_required("operator")
def refresh():
    p = profile()
    if not p["enabled"]:
        flash("Switch monitoring is not enabled.", "error")
    else:
        db.execute("UPDATE ui.snmp_profile SET refresh_requested_at = now() WHERE id = 1")
        ev("snmp.refresh", object_type="snmp_profile", object_id=1)
        flash("Refresh requested. Results appear within a minute.", "success")
    return redirect(request.form.get("next_page") == "clients" and url_for("clients.index") or url_for("snmp.index"))


@bp.route("/test", methods=["POST"])
@role_required("operator")
def test():
    try:
        cid = int(request.form.get("client_id", ""))
    except ValueError:
        abort(400)
    c = db.query_one("SELECT id, name FROM ui.radius_client WHERE id = %s", (cid,))
    if c is None:
        abort(404)
    row = db.execute_returning("INSERT INTO ui.snmp_test (client_id, requested_by) VALUES (%s, %s) RETURNING id",
                               (cid, g.user["username"]))
    ev("snmp.test", object_type="radius_client", object_id=cid, detail={"name": c["name"]})
    return redirect(url_for("snmp.test_result", tid=row["id"]))


@bp.route("/test/<int:tid>")
@login_required
def test_result(tid):
    t = db.query_one("SELECT t.*, c.name, c.ipaddr FROM ui.snmp_test t JOIN ui.radius_client c ON c.id = t.client_id"
                     " WHERE t.id = %s", (tid,))
    if t is None:
        abort(404)
    p = profile()
    return render_template("snmp/test.html", t=t, p=p)
