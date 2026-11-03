"""Local 802.1X users: username and password sign-in with EAP-TTLS/PAP (SPEC section 18).

Kept apart from switch admins (radcheck/net-admins): FreeRADIUS reads these accounts
only through radius_admin_dot1x_user_hex() inside the EAP-TTLS tunnel. Live
immediately; the access rules assign the VLAN by the user's groups.
"""
from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import db
from ..crypto import fr_pbkdf2_hash
from ..flashing import flash
from ..policy import check_switch_password, validate_switch_username
from ..security import cfg, login_required, role_required
from ..services import get_settings, unlang
from . import ev, form_bool, form_str
from .mab import expiry_date_value, parse_expiry_date

bp = Blueprint("dot1x_users", __name__, url_prefix="/dot1x-users")

MAX_GROUPS = 50


def parse_groups(text):
    """'Wired-Office, Lab' -> ['Wired-Office', 'Lab'] (validated, duplicates dropped)."""
    out, seen = [], set()
    for part in (text or "").split(","):
        name = part.strip()
        if not name:
            continue
        unlang().validate_ad_group(name)
        if name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    if len(out) > MAX_GROUPS:
        raise ValueError("Use at most %d groups." % MAX_GROUPS)
    return out


def _rule_groups():
    return {r["g"] for r in db.query("SELECT DISTINCT lower(ad_group) AS g FROM ui.access_rule WHERE enabled")}


def _get(uid):
    u = db.query_one("SELECT *, (expires_at IS NOT NULL AND expires_at <= now()) AS expired"
                     " FROM ui.dot1x_user WHERE id = %s", (uid,))
    if u is None:
        abort(404)
    return u


def _check_password(errors):
    pw = request.form.get("password", "")
    probs = check_switch_password(pw, cfg()["password_min_length"])
    if pw != request.form.get("confirm", ""):
        probs.append("The passwords do not match.")
    if probs:
        errors["password"] = " ".join(probs)
    return pw


def _form(errors):
    d = {"groups_text": form_str("groups", maxlen=4000), "description": form_str("description", maxlen=200),
         "expires": form_str("expires", maxlen=20), "enabled": form_bool("enabled")}
    try:
        d["groups"] = parse_groups(d["groups_text"])
    except ValueError as e:
        errors["groups"] = str(e)
    try:
        d["expires_at"] = parse_expiry_date(d["expires"])
    except ValueError as e:
        errors["expires"] = str(e)
    return d


@bp.route("/")
@login_required
def index():
    users = db.query("SELECT *, (expires_at IS NOT NULL AND expires_at <= now()) AS expired"
                     " FROM ui.dot1x_user ORDER BY lower(username)")
    s = get_settings()
    return render_template("dot1x_users/index.html", users=users, rule_groups=_rule_groups(),
                           ttls_on=s["dot1x_ttls"], directory_on=s["dot1x_ttls_directory"])


@bp.route("/new", methods=["GET", "POST"])
@role_required("operator")
def new():
    errors = {}
    d = {"username": "", "groups_text": "", "description": "", "expires": "", "enabled": True}
    if request.method == "POST":
        d.update(_form(errors), username=form_str("username", maxlen=64))
        try:
            validate_switch_username(d["username"])
        except ValueError as e:
            errors["username"] = str(e)
        if "username" not in errors and db.query_one(
                "SELECT 1 FROM ui.dot1x_user WHERE lower(username) = lower(%s)", (d["username"],)):
            errors["username"] = "That username already exists."
        pw = _check_password(errors)
        if not errors:
            row = db.execute_returning(
                "INSERT INTO ui.dot1x_user (username, password_hash, groups, description, enabled, expires_at,"
                " created_by) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (d["username"], fr_pbkdf2_hash(pw, cfg()["pbkdf2_iterations"]), d["groups"], d["description"],
                 d["enabled"], d["expires_at"], g.user["username"]))
            ev("dot1x_user.create", object_type="dot1x_user", object_id=d["username"],
               detail={"id": row["id"], "groups": d["groups"], "enabled": d["enabled"],
                       "expires_at": d["expires_at"].isoformat() if d["expires_at"] else None})
            flash("802.1X user %s created. This is live now." % d["username"], "success")
            return redirect(url_for("dot1x_users.index"))
    return render_template("dot1x_users/form.html", d=d, errors=errors, is_new=True,
                           rule_groups=_rule_groups(), min_length=cfg()["password_min_length"]), \
        (400 if errors else 200)


@bp.route("/<int:uid>/edit", methods=["GET", "POST"])
@role_required("operator")
def edit(uid):
    u = _get(uid)
    errors = {}
    d = {"username": u["username"], "groups_text": ", ".join(u["groups"]), "description": u["description"],
         "expires": expiry_date_value(u["expires_at"]), "enabled": u["enabled"]}
    if request.method == "POST":
        d.update(_form(errors))
        if not errors:
            db.execute("UPDATE ui.dot1x_user SET groups=%s, description=%s, enabled=%s, expires_at=%s,"
                       " updated_at=now() WHERE id=%s",
                       (d["groups"], d["description"], d["enabled"], d["expires_at"], uid))
            changed = {k: {"from": a, "to": b} for k, a, b in (
                ("groups", u["groups"], d["groups"]), ("enabled", u["enabled"], d["enabled"]),
                ("description", u["description"], d["description"]),
                ("expires_at", u["expires_at"].isoformat() if u["expires_at"] else None,
                 d["expires_at"].isoformat() if d["expires_at"] else None)) if a != b}
            ev("dot1x_user.update", object_type="dot1x_user", object_id=u["username"], detail=changed)
            flash("802.1X user %s saved. This is live now." % u["username"], "success")
            return redirect(url_for("dot1x_users.index"))
    return render_template("dot1x_users/form.html", d=d, errors=errors, is_new=False, uid=uid,
                           rule_groups=_rule_groups(), min_length=cfg()["password_min_length"]), \
        (400 if errors else 200)


@bp.route("/<int:uid>/password", methods=["GET", "POST"])
@role_required("operator")
def password(uid):
    u = _get(uid)
    errors = {}
    if request.method == "POST":
        pw = _check_password(errors)
        if not errors:
            db.execute("UPDATE ui.dot1x_user SET password_hash=%s, updated_at=now() WHERE id=%s",
                       (fr_pbkdf2_hash(pw, cfg()["pbkdf2_iterations"]), uid))
            ev("dot1x_user.credential_reset", object_type="dot1x_user", object_id=u["username"])
            flash("New password for %s set. This is live now." % u["username"], "success")
            return redirect(url_for("dot1x_users.index"))
    return render_template("dot1x_users/password.html", u=u, errors=errors,
                           min_length=cfg()["password_min_length"]), (400 if errors else 200)


@bp.route("/<int:uid>/delete", methods=["POST"])
@role_required("operator")
def delete(uid):
    u = _get(uid)
    db.execute("DELETE FROM ui.dot1x_user WHERE id=%s", (uid,))
    ev("dot1x_user.delete", object_type="dot1x_user", object_id=u["username"])
    flash("802.1X user %s deleted." % u["username"], "success")
    return redirect(url_for("dot1x_users.index"))
