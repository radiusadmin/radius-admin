"""First-run setup checklist (admins). Every status is computed from the live state; nothing
here changes configuration itself, it links to the page where each step is done."""
from flask import Blueprint, abort, redirect, render_template, request, url_for

from .. import db, sso
from ..flashing import flash
from ..security import role_required
from ..services import get_settings, pending_state, set_setting
from . import ev
from .dashboard import helper_status

bp = Blueprint("setup", __name__, url_prefix="/setup")

EXAMPLE_SUBNET = "192.0.2.0/24"     # the documentation range shipped as the default


def checklist():
    """[(key, title, required, done, detail, endpoint)] in the order an admin works through them."""
    s = get_settings()
    st = helper_status()
    n = db.query_one(
        "SELECT (SELECT count(*) FROM ui.radius_client WHERE enabled) AS clients,"
        " (SELECT count(*) FROM ui.access_rule WHERE enabled) AS rules,"
        " (SELECT count(DISTINCT username) FROM radusergroup WHERE groupname='net-admins') AS switch_admins,"
        " (SELECT count(*) FROM ui.admin_user WHERE role='admin' AND enabled) AS admins,"
        " (SELECT count(*) FROM ui.sso_group_role WHERE role='admin') AS sso_admin_groups,"
        " (SELECT enabled FROM ui.snmp_profile WHERE id = 1) AS monitoring,"
        " (SELECT email_enabled FROM ui.alert_settings WHERE id = 1) AS alert_email")
    pend = pending_state()
    fr_ok = bool(st.get("ok") and st.get("service_active") and st.get("listening"))
    saml_on = sso.settings(s["saml"])["enabled"]
    radsec_on = str(s["radsec"].get("enabled", "false")).lower() == "true"
    return [
        ("freeradius", "FreeRADIUS is running and reachable", True, fr_ok,
         (st.get("radiusd_version") or "") if fr_ok else (st.get("message") or "Not running or not listening."),
         "dashboard.index"),
        ("clients", "Add the switches and access points (RADIUS clients)", True, n["clients"] > 0,
         "%d enabled client%s" % (n["clients"], "" if n["clients"] == 1 else "s"), "clients.index"),
        ("rules", "Create access rules (directory group to VLAN)", True, n["rules"] > 0,
         "%d enabled rule%s" % (n["rules"], "" if n["rules"] == 1 else "s"), "rules.index"),
        ("admin_subnet", "Set the management subnet for switch admin logins", True,
         s["admin_subnet"] != EXAMPLE_SUBNET,
         "Still the example network %s" % EXAMPLE_SUBNET if s["admin_subnet"] == EXAMPLE_SUBNET
         else s["admin_subnet"], "settings.index"),
        ("applied", "Apply the configuration to FreeRADIUS", True,
         not pend.get("pending") and not pend.get("never_applied"),
         "Pending changes" if pend.get("pending") else "Up to date", "apply.index"),
        ("second_admin", "Make sure more than one person can administer the console", False,
         n["admins"] > 1 or (saml_on and n["sso_admin_groups"] > 0),
         "%d enabled admin account%s%s" % (n["admins"], "" if n["admins"] == 1 else "s",
                                           ", plus an SSO admin group" if saml_on and n["sso_admin_groups"] else ""),
         "admins.index"),
        ("switch_admins", "Add switch admin accounts", False, n["switch_admins"] > 0,
         "%d switch admin%s" % (n["switch_admins"], "" if n["switch_admins"] == 1 else "s"), "switch_admins.index"),
        ("sso", "Single sign-on for the console", False, saml_on, "On" if saml_on else "Off", "sso.settings"),
        ("radsec", "RadSec for clients that support it", False, radsec_on, "On" if radsec_on else "Off",
         "clients.radsec"),
        ("monitoring", "Switch monitoring (SNMPv3)", False, bool(n["monitoring"]),
         "On" if n["monitoring"] else "Off", "snmp.index"),
        ("alerts", "Alert e-mail", False, bool(n["alert_email"]), "On" if n["alert_email"] else "Syslog only",
         "alerts.settings"),
    ]


def summary():
    """For the dashboard: None once setup was finished, else counts."""
    s = get_settings()
    if s["setup_finished"]:
        return None
    items = checklist()
    req = [i for i in items if i[2]]
    return {"done": sum(1 for i in req if i[3]), "total": len(req)}


@bp.route("/", methods=["GET", "POST"])
@role_required("admin")
def index():
    s = get_settings()
    skipped = set(s["setup_skipped"])
    items = checklist()
    keys = {i[0]: i for i in items}
    if request.method == "POST":
        action, key = request.form.get("action", ""), request.form.get("item", "")
        if action in ("skip", "restore"):
            if key not in keys or keys[key][2]:
                abort(400, "Only optional steps can be skipped.")
            skipped = (skipped | {key}) if action == "skip" else (skipped - {key})
            set_setting("setup_skipped", ",".join(sorted(skipped)))
            ev("setup." + action, detail={"item": key})
        elif action == "finish":
            missing = [i[1] for i in items if i[2] and not i[3]]
            if missing:
                flash("Finish the required steps first: %s." % "; ".join(missing), "error")
                return redirect(url_for("setup.index"))
            set_setting("setup_finished", "true")
            ev("setup.finish", detail={"skipped": sorted(skipped)})
            flash("Setup is complete. You can reopen this checklist from Settings.", "success")
            return redirect(url_for("dashboard.index"))
        elif action == "reopen":
            set_setting("setup_finished", "false")
            ev("setup.reopen", detail={})
        else:
            abort(400)
        return redirect(url_for("setup.index"))
    required = [i for i in items if i[2]]
    return render_template("setup/index.html", items=items, skipped=skipped, finished=s["setup_finished"],
                           done=sum(1 for i in required if i[3]), total=len(required))
