"""Switch administrators: radcheck + radusergroup(net-admins). Live immediately."""
from flask import Blueprint, abort, redirect, render_template, request, url_for

from .. import db
from ..crypto import fr_pbkdf2_hash
from ..flashing import flash
from ..policy import check_switch_password, validate_switch_username
from ..security import cfg, login_required, role_required
from ..services import PW_ATTRS, SWITCH_GROUP, switch_admins
from . import ev, form_str

bp = Blueprint("switch_admins", __name__, url_prefix="/switch-admins")


def _exists(username):
    return db.query_one("SELECT 1 FROM radusergroup WHERE username=%s AND groupname=%s",
                        (username, SWITCH_GROUP)) is not None


def _set_password(username, password):
    value = fr_pbkdf2_hash(password, cfg()["pbkdf2_iterations"])
    # Remove every existing password attribute (incl. legacy Crypt-Password).
    db.execute("DELETE FROM radcheck WHERE username=%s AND attribute = ANY(%s)",
               (username, list(PW_ATTRS)))
    db.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s,'Password-With-Header',':=',%s)",
               (username, value))


@bp.route("/")
@login_required
def index():
    return render_template("switch_admins/index.html", admins=switch_admins(),
                           min_length=cfg()["password_min_length"])


@bp.route("/new", methods=["GET", "POST"])
@role_required("operator")
def new():
    errors = {}
    username = ""
    if request.method == "POST":
        username = form_str("username", maxlen=64)
        pw = request.form.get("password", "")
        try:
            validate_switch_username(username)
        except ValueError as e:
            errors["username"] = str(e)
        if not errors and (_exists(username) or db.query_one(
                "SELECT 1 FROM radcheck WHERE username=%s", (username,))):
            errors["username"] = "That username already exists."
        probs = check_switch_password(pw, cfg()["password_min_length"])
        if pw != request.form.get("confirm", ""):
            probs.append("The passwords do not match.")
        if probs:
            errors["password"] = " ".join(probs)
        if not errors:
            _set_password(username, pw)
            db.execute("INSERT INTO radusergroup (username, groupname, priority) VALUES (%s,%s,1)",
                       (username, SWITCH_GROUP))
            ev("switch_admin.create", object_type="switch_admin", object_id=username)
            flash("Switch admin %s created. This is live now." % username, "success")
            return redirect(url_for("switch_admins.index"))
    return render_template("switch_admins/form.html", errors=errors, username=username, is_new=True,
                           min_length=cfg()["password_min_length"]), (400 if errors else 200)


@bp.route("/<username>/password", methods=["GET", "POST"])
@role_required("operator")
def password(username):
    if not _exists(username):
        abort(404)
    errors = {}
    if request.method == "POST":
        pw = request.form.get("password", "")
        probs = check_switch_password(pw, cfg()["password_min_length"])
        if pw != request.form.get("confirm", ""):
            probs.append("The passwords do not match.")
        if probs:
            errors["password"] = " ".join(probs)
        else:
            _set_password(username, pw)
            ev("switch_admin.password_reset", object_type="switch_admin", object_id=username)
            flash("Password for %s updated. This is live now." % username, "success")
            return redirect(url_for("switch_admins.index"))
    return render_template("switch_admins/form.html", errors=errors, username=username, is_new=False,
                           min_length=cfg()["password_min_length"]), (400 if errors else 200)


@bp.route("/<username>/disable", methods=["POST"])
@role_required("operator")
def disable(username):
    if not _exists(username):
        abort(404)
    db.execute("DELETE FROM radcheck WHERE username=%s AND attribute='Auth-Type'", (username,))
    db.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s,'Auth-Type',':=','Reject')",
               (username,))
    ev("switch_admin.disable", object_type="switch_admin", object_id=username)
    flash("%s is disabled and can no longer sign in to switches." % username, "success")
    return redirect(url_for("switch_admins.index"))


@bp.route("/<username>/enable", methods=["POST"])
@role_required("operator")
def enable(username):
    if not _exists(username):
        abort(404)
    db.execute("DELETE FROM radcheck WHERE username=%s AND attribute='Auth-Type' AND value='Reject'", (username,))
    ev("switch_admin.enable", object_type="switch_admin", object_id=username)
    flash("%s is enabled." % username, "success")
    return redirect(url_for("switch_admins.index"))


@bp.route("/<username>/delete", methods=["POST"])
@role_required("operator")
def delete(username):
    if not _exists(username):
        abort(404)
    db.execute("DELETE FROM radusergroup WHERE username=%s AND groupname=%s", (username, SWITCH_GROUP))
    # Remove credentials only if the user is in no other group.
    if not db.query_one("SELECT 1 FROM radusergroup WHERE username=%s", (username,)):
        db.execute("DELETE FROM radcheck WHERE username=%s", (username,))
        db.execute("DELETE FROM radreply WHERE username=%s", (username,))
    ev("switch_admin.delete", object_type="switch_admin", object_id=username)
    flash("Switch admin %s deleted." % username, "success")
    return redirect(url_for("switch_admins.index"))
