"""Admin-only management of UI accounts. Every mutation requires step-up."""
from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import db
from ..flashing import flash
from ..security import ROLES, cfg, role_required, stepup_required
from ..users import create_user, enabled_admin_count, get_by_id, reset_password_temp
from . import ev, form_str

bp = Blueprint("admins", __name__, url_prefix="/ui-admins")


def _get(uid):
    u = get_by_id(uid)
    if u is None:
        abort(404)
    return u


ADMIN_ROLE_LOCK = 7212002


def _lock_admin_changes():
    """Serialize changes that can reduce the number of enabled admins (held to commit)."""
    db.execute("SELECT pg_advisory_xact_lock(%s)", (ADMIN_ROLE_LOCK,))


def _sso_account(u):
    """True (with a message) for single sign-on accounts: their role, password and second
    factor come from the identity provider, so these actions do not apply."""
    if u["auth_source"] == "saml":
        flash("%s signs in with single sign-on: the role follows the group mappings at each sign-in, and the "
              "password and second factor are managed by the identity provider." % u["username"], "error")
        return True
    return False


def _would_remove_last_admin(u, new_role=None, disabling=False):
    """Caller must hold _lock_admin_changes() and pass a row read after taking it."""
    if u["role"] != "admin" or not u["enabled"]:
        return False
    if disabling or (new_role and new_role != "admin"):
        return enabled_admin_count() <= 1
    return False


@bp.route("/")
@role_required("admin")
def index():
    users = db.query(
        "SELECT u.id, u.username, u.display_name, u.role, u.enabled, u.mfa_method, u.must_change_password, u.auth_source,"
        " u.last_login_at, host(u.last_login_ip) AS last_login_ip,"
        " (u.locked_until IS NOT NULL AND u.locked_until > now()) AS locked,"
        " (SELECT count(*) FROM ui.session s WHERE s.user_id = u.id) AS sessions"
        " FROM ui.admin_user u ORDER BY u.username")
    return render_template("admins/index.html", users=users, roles=ROLES)


@bp.route("/new", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def new():
    errors, d = {}, {"role": "viewer"}
    if request.method == "POST":
        d = {"username": form_str("username", maxlen=64).lower(), "display_name": form_str("display_name", maxlen=200),
             "role": form_str("role")}
        try:
            uid, temp = create_user(d["username"], d["role"], d["display_name"], cfg()["pbkdf2_iterations"])
        except ValueError as e:
            errors["username"] = str(e)
        else:
            ev("ui_admin.create", object_type="admin_user", object_id=uid,
               detail={"username": d["username"], "role": d["role"]})
            return render_template("admins/temp_password.html", username=d["username"], temp=temp, created=True)
    return render_template("admins/form.html", d=d, errors=errors, roles=ROLES), (400 if errors else 200)


@bp.route("/<int:uid>/role", methods=["POST"])
@role_required("admin")
@stepup_required
def set_role(uid):
    _lock_admin_changes()
    u = _get(uid)
    role = request.form.get("role")
    if role not in ROLES:
        abort(400)
    if _sso_account(u):
        return redirect(url_for("admins.index"))
    if _would_remove_last_admin(u, new_role=role):
        flash("You cannot remove the last enabled administrator.", "error")
        return redirect(url_for("admins.index"))
    if role != u["role"]:
        db.execute("UPDATE ui.admin_user SET role=%s, updated_at=now() WHERE id=%s", (role, uid))
        db.execute("DELETE FROM ui.session WHERE user_id=%s AND user_id<>%s", (uid, g.user["id"]))
        ev("ui_admin.role", object_type="admin_user", object_id=uid,
           detail={"username": u["username"], "from": u["role"], "to": role})
        flash("%s is now %s." % (u["username"], role), "success")
    return redirect(url_for("admins.index"))


@bp.route("/<int:uid>/enable", methods=["POST"])
@role_required("admin")
@stepup_required
def set_enabled(uid):
    _lock_admin_changes()
    u = _get(uid)
    enable = request.form.get("enabled") == "1"
    if not enable and uid == g.user["id"]:
        flash("You cannot disable your own account.", "error")
        return redirect(url_for("admins.index"))
    if not enable and _would_remove_last_admin(u, disabling=True):
        flash("You cannot disable the last enabled administrator.", "error")
        return redirect(url_for("admins.index"))
    db.execute("UPDATE ui.admin_user SET enabled=%s, updated_at=now() WHERE id=%s", (enable, uid))
    if not enable:
        db.execute("DELETE FROM ui.session WHERE user_id=%s", (uid,))
    ev("ui_admin.enable" if enable else "ui_admin.disable", object_type="admin_user", object_id=uid,
       detail={"username": u["username"]})
    flash("%s %s." % (u["username"], "enabled" if enable else "disabled"), "success")
    return redirect(url_for("admins.index"))


@bp.route("/<int:uid>/unlock", methods=["POST"])
@role_required("admin")
@stepup_required
def unlock(uid):
    u = _get(uid)
    db.execute("UPDATE ui.admin_user SET failed_count=0, locked_until=NULL, updated_at=now() WHERE id=%s", (uid,))
    ev("ui_admin.unlock", object_type="admin_user", object_id=uid, detail={"username": u["username"]})
    flash("%s unlocked." % u["username"], "success")
    return redirect(url_for("admins.index"))


@bp.route("/<int:uid>/reset-mfa", methods=["POST"])
@role_required("admin")
@stepup_required
def reset_mfa(uid):
    u = _get(uid)
    if _sso_account(u):
        return redirect(url_for("admins.index"))
    db.execute("UPDATE ui.admin_user SET mfa_method=NULL, totp_secret_enc=NULL, totp_last_step=NULL,"
               " cert_sha256=NULL, cert_subject=NULL, updated_at=now() WHERE id=%s", (uid,))
    db.execute("DELETE FROM ui.session WHERE user_id=%s AND id<>%s", (uid, g.session["id"]))
    ev("ui_admin.reset_mfa", object_type="admin_user", object_id=uid, detail={"username": u["username"]})
    if uid == g.user["id"]:
        g.session["mfa_ok"] = False
        db.execute("UPDATE ui.session SET mfa_ok=false WHERE id=%s", (g.session["id"],))
        flash("Your two-factor method was reset. Set up a new one now.", "info")
        return redirect(url_for("auth.enroll"))
    flash("Two-factor reset for %s. They will enrol again at next sign-in." % u["username"], "success")
    return redirect(url_for("admins.index"))


@bp.route("/<int:uid>/reset-password", methods=["POST"])
@role_required("admin")
@stepup_required
def reset_password(uid):
    u = _get(uid)
    if _sso_account(u):
        return redirect(url_for("admins.index"))
    if uid == g.user["id"]:
        flash("Use Account to change your own password.", "error")
        return redirect(url_for("admins.index"))
    temp = reset_password_temp(uid, cfg()["pbkdf2_iterations"])
    ev("ui_admin.reset_password", object_type="admin_user", object_id=uid, detail={"username": u["username"]})
    return render_template("admins/temp_password.html", username=u["username"], temp=temp, created=False)


@bp.route("/<int:uid>/delete", methods=["POST"])
@role_required("admin")
@stepup_required
def delete(uid):
    _lock_admin_changes()
    u = _get(uid)
    if uid == g.user["id"]:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admins.index"))
    if _would_remove_last_admin(u, disabling=True):
        flash("You cannot delete the last enabled administrator.", "error")
        return redirect(url_for("admins.index"))
    db.execute("DELETE FROM ui.admin_user WHERE id=%s", (uid,))
    ev("ui_admin.delete", object_type="admin_user", object_id=uid, detail={"username": u["username"]})
    flash("%s deleted." % u["username"], "success")
    return redirect(url_for("admins.index"))
