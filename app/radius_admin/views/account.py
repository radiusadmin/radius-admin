"""Own account: change password (also the forced change), MFA method, sessions."""
import functools

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import db
from ..crypto import verify_password
from ..flashing import flash
from ..security import (THEMES, cfg, destroy_session, login_required, rotate_session, safe_next,
                        stepup_required)
from ..users import change_password
from . import ev
from .auth import complete_enrollment, enrollment_context

bp = Blueprint("account", __name__, url_prefix="/account")


def local_account_only(view):
    """Password and two-factor pages: single sign-on accounts manage both at their IdP."""
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if g.get("user") and g.user["auth_source"] == "saml":
            flash("You sign in with single sign-on: your password and second factor are managed by "
                  "your identity provider.", "info")
            return redirect(url_for("account.index"))
        return view(*a, **kw)
    return wrapped


def mfa_done_required(view):
    """Signed in with MFA; password change may still be pending."""
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not g.get("user"):
            return redirect(url_for("auth.login"))
        if not g.session["mfa_ok"]:
            return redirect(url_for("auth.mfa") if g.user["mfa_method"] else url_for("auth.enroll"))
        return view(*a, **kw)
    return wrapped


@bp.route("/")
@login_required
def index():
    sessions = db.query(
        "SELECT id, created_at, last_seen_at, host(ip) AS ip, user_agent, mfa_ok FROM ui.session"
        " WHERE user_id=%s ORDER BY last_seen_at DESC", (g.user["id"],))
    return render_template("account/index.html", sessions=sessions, this_session=g.session["id"])


@bp.route("/password", methods=["GET", "POST"])
@mfa_done_required
@local_account_only
def password():
    forced = g.user["must_change_password"]
    errors = []
    if request.method == "POST":
        current = request.form.get("current_password", "")[:256]
        new = request.form.get("new_password", "")[:256]
        confirm = request.form.get("confirm_password", "")[:256]
        if not verify_password(current, g.user["password_hash"]):
            errors.append("Your current password is incorrect.")
            ev("account.password_change", success=False, object_type="admin_user",
               object_id=g.user["id"], detail={"reason": "bad_current"})
        elif new != confirm:
            errors.append("The new passwords do not match.")
        else:
            errors = change_password(g.user, new, cfg())
            if not errors:
                # End all other sessions; rotate this one.
                db.execute("DELETE FROM ui.session WHERE user_id=%s AND id<>%s",
                           (g.user["id"], g.session["id"]))
                rotate_session()
                ev("account.password_change", object_type="admin_user", object_id=g.user["id"],
                   detail={"forced": forced})
                flash("Your password was changed. Other sessions were signed out.", "success")
                return redirect(url_for("dashboard.index"))
            ev("account.password_change", success=False, object_type="admin_user",
               object_id=g.user["id"], detail={"reason": "policy"})
    return render_template("account/password.html", forced=forced, errors=errors,
                           min_length=cfg()["password_min_length"],
                           history=cfg()["password_history"]), (400 if errors else 200)


@bp.route("/mfa", methods=["GET", "POST"])
@login_required
@local_account_only
@stepup_required
def mfa():
    error = None
    method = request.values.get("method", g.user["mfa_method"] or "totp")
    if request.method == "POST":
        ok, error = complete_enrollment(request.form.get("method"), request.form)
        if ok:
            rotate_session()
            flash("Your two-factor method was updated.", "success")
            return redirect(url_for("account.index"))
    ctx = enrollment_context(request.form.get("candidate") if request.method == "POST" else None)
    return render_template("auth/enroll.html", error=error, method=method, forced=False,
                           action=url_for("account.mfa"), **ctx), (400 if error else 200)


@bp.route("/theme", methods=["POST"])
@login_required
def theme():
    """Colour theme: system (follow the browser), light or dark. Works without JS."""
    value = request.form.get("theme", "")
    if value not in THEMES:
        abort(400, "Unknown theme.")
    if value != g.user["theme"]:
        db.execute("UPDATE ui.admin_user SET theme=%s, updated_at=now() WHERE id=%s", (value, g.user["id"]))
        ev("account.theme", object_type="admin_user", object_id=g.user["id"],
           detail={"from": g.user["theme"], "to": value})
    g.set_theme_cookie = value      # so the sign-in page matches after sign-out
    return redirect(safe_next(request.form.get("return_to")) or url_for("account.index"))


@bp.route("/sessions/<int:sid>/revoke", methods=["POST"])
@login_required
def revoke(sid):
    n = db.execute("DELETE FROM ui.session WHERE id=%s AND user_id=%s", (sid, g.user["id"]))
    ev("account.session_revoke", success=bool(n), object_type="session", object_id=sid)
    if sid == g.session["id"]:
        g.session = None
        g.user = None
        g.clear_cookie = True
        return redirect(url_for("auth.login"))
    flash("Session revoked." if n else "That session no longer exists.", "success" if n else "info")
    return redirect(url_for("account.index"))


@bp.route("/sessions/revoke-others", methods=["POST"])
@login_required
def revoke_others():
    n = db.execute("DELETE FROM ui.session WHERE user_id=%s AND id<>%s", (g.user["id"], g.session["id"]))
    ev("account.session_revoke_others", object_type="admin_user", object_id=g.user["id"], detail={"count": n})
    flash("Signed out %d other session(s)." % n, "success")
    return redirect(url_for("account.index"))
