"""Admin-only: settings (live, SPEC section 10) and custom policy (needs Apply)."""
import ipaddress

from flask import Blueprint, g, redirect, render_template, request, url_for

from ..crypto import sha256_hex
from ..flashing import flash
from ..security import SESSION_LIMITS, role_required, stepup_required
from ..services import get_settings, render_all, session_limits, set_setting, unlang
from . import ev, form_bool
from .auth import inline_stepup

bp = Blueprint("settings", __name__)


@bp.route("/settings", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def index():
    s = get_settings()
    s["limits"] = session_limits(s)
    errors = {}
    if request.method == "POST":
        limits = {}
        for k, (lo, hi, unit) in SESSION_LIMITS.items():
            v = request.form.get(k, "").strip()
            if k not in request.form:          # not on the submitted form: keep the current value
                continue
            if not (v.isdigit() and lo <= int(v) <= hi):
                errors[k] = "Enter a whole number of %s from %d to %d." % (unit, lo, hi)
            else:
                limits[k] = int(v)
        subnet = request.form.get("admin_subnet", "").strip()
        priv15 = form_bool("admin_priv15")
        banner = request.form.get("banner_text", "").strip().replace("\r\n", "\n")
        try:
            check = getattr(unlang(), "validate_admin_subnet", None)
            net = check(subnet) if check else ipaddress.ip_network(subnet, strict=True)
            if not check and net.prefixlen == 0:
                raise ValueError("A /0 network is not allowed.")
            subnet = str(net)
        except ValueError as e:
            errors["admin_subnet"] = (str(e) if check else
                                      "Enter a network in CIDR form, for example 192.0.2.0/24.")
        if not 20 <= len(banner) <= 4000:
            errors["banner_text"] = "The notice must be 20 to 4000 characters."
        if not errors:
            changed = {}
            if subnet != s["admin_subnet"]:
                set_setting("admin_subnet", subnet)
                changed["admin_subnet"] = {"from": s["admin_subnet"], "to": subnet}
            if priv15 != s["admin_priv15"]:
                set_setting("admin_priv15", "true" if priv15 else "false")
                changed["admin_priv15"] = {"from": s["admin_priv15"], "to": priv15}
            if banner != s["banner_text"]:
                set_setting("banner_text", banner)
                changed["banner_text"] = {"sha256": sha256_hex(banner)}
            for k, v in limits.items():
                if v != s["limits"][k]:
                    set_setting(k, str(v))
                    changed[k] = {"from": s["limits"][k], "to": v}
            ev("settings.update", object_type="setting", detail=changed)
            flash("Settings saved." if changed else "No changes.", "success" if changed else "info")
            return redirect(url_for("settings.index"))
        s = dict(s, admin_subnet=subnet, admin_priv15=priv15, banner_text=banner,
                 limits=dict(s["limits"], **{k: request.form.get(k, "") for k in SESSION_LIMITS}))
    return render_template("settings/index.html", s=s, errors=errors), (400 if errors else 200)


@bp.route("/custom-policy", methods=["GET", "POST"])
@role_required("admin")
def custom_policy():
    s = get_settings()
    text = s["custom_policy"]
    error = None
    need_stepup = False
    if request.method == "GET" and not g.session.get("stepup_ok"):
        return redirect(url_for("auth.stepup", next=request.path))
    if request.method == "POST":
        text = request.form.get("custom_policy", "").replace("\r\n", "\n")
        if not g.session.get("stepup_ok"):
            ok, attempted = inline_stepup(request.form)
            if not ok:
                if g.get("user") is None:
                    return redirect(url_for("auth.login"))
                need_stepup = True
                error = ("Verification failed. Check your password and second factor." if attempted else
                         "Your confirmation expired. Confirm your identity to save; your edits are kept below.")
                return render_template("settings/custom_policy.html", text=text, error=error,
                                       need_stepup=True), 401
        try:
            unlang().validate_custom_policy(text)
        except ValueError as e:
            error = str(e)
        if error is None:
            if text != s["custom_policy"]:
                set_setting("custom_policy", text)
                ev("settings.custom_policy", object_type="setting", object_id="custom_policy",
                   detail={"sha256_before": sha256_hex(s["custom_policy"]), "sha256_after": sha256_hex(text),
                           "length": len(text)})
                flash("Custom policy saved. Validate and apply to make it live.", "success")
            else:
                flash("No changes.", "info")
            return redirect(url_for("settings.custom_policy"))
        ev("settings.custom_policy", success=False, object_type="setting", object_id="custom_policy",
           detail={"error": error[:300]})
    return render_template("settings/custom_policy.html", text=text, error=error,
                           need_stepup=need_stepup), (400 if error else 200)


@bp.route("/custom-policy/preview")
@role_required("admin")
def policy_preview():
    try:
        policy, _ = render_all()
        error = None
    except Exception as e:
        policy, error = None, str(e)
    return render_template("settings/preview.html", policy=policy, error=error)
