"""SAML single sign-on: sign-in start, assertion consumer service, SP metadata and the
admin settings page with the group -> role mappings. Logic lives in ..sso."""
from flask import Blueprint, Response, abort, g, redirect, render_template, request, url_for

from .. import db, mfa, sso
from ..crypto import constant_time_eq, random_token, sha256_hex
from ..flashing import flash
from ..security import (ROLES, banner_acknowledged, create_session, role_required, safe_next,
                        stepup_required)
from ..services import get_settings, set_setting
from . import ev, form_bool, form_str

bp = Blueprint("sso", __name__)

NONCE_COOKIE = "__Host-radius_admin_saml"
REQUEST_TTL_MINUTES = 10
NO_PASSWORD = "!saml"          # never verifies (crypto.verify_password needs a PBKDF2 hash)


def _settings():
    return sso.settings(get_settings()["saml"])


def _base_url():
    return "https://" + request.host


def _refuse(message, reason, actor=None, status=401, **detail):
    mfa.record_attempt(actor or "", False)
    ev("auth.login", success=False, actor=actor, detail=dict(method="saml", reason=reason, **detail))
    return render_template("auth/sso_error.html", message=message), status


# ------------------------------------------------------------------ sign-in
@bp.route("/saml/login")
def login():
    s = _settings()
    if not s["enabled"]:
        abort(404)
    if not banner_acknowledged():
        return redirect(url_for("auth.login"))
    stepup = request.args.get("stepup") == "1"
    nxt = safe_next(request.args.get("next")) or url_for("dashboard.index")
    session_id = None
    if stepup:
        if not g.get("user") or not g.session["mfa_ok"] or g.user["auth_source"] != "saml":
            return redirect(url_for("auth.login"))
        session_id = g.session["id"]
    try:
        reqid, location = sso.authn_request(_base_url(), s, relay_state="", force=stepup)
    except Exception:
        flash("Single sign-on is not configured correctly. Use a local account or ask an administrator.", "error")
        return redirect(url_for("auth.login"))
    nonce = random_token(24)
    db.execute("DELETE FROM ui.saml_request WHERE created_at < now() - make_interval(mins => %s)",
               (REQUEST_TTL_MINUTES,))
    db.execute("INSERT INTO ui.saml_request (id, nonce_sha256, session_id, next_path) VALUES (%s,%s,%s,%s)",
               (reqid, sha256_hex(nonce), session_id, nxt))
    resp = redirect(location)
    # SameSite=None: the identity provider POSTs the answer from its own site. The value
    # is a one-time nonce, not a credential; it only ties the answer to this browser.
    resp.set_cookie(NONCE_COOKIE, nonce, max_age=REQUEST_TTL_MINUTES * 60, secure=True, httponly=True,
                    samesite="None", path="/")
    return resp


def _request_id(saml_response):
    """InResponseTo of the response (checked again by pysaml2 against this id)."""
    import re
    try:
        xml = sso._decoded(saml_response)
    except sso.SSOError:
        return None
    m = re.search(r'<(?:\w+:)?Response\b[^>]*\bInResponseTo="([A-Za-z0-9_.-]{1,100})"', xml)
    return m.group(1) if m else None


@bp.route("/saml/acs", methods=["POST"])
def acs():
    """Assertion consumer service. Exempt from the CSRF check (a cross-site POST by design);
    protected by the signature, audience, time window, InResponseTo, the browser nonce and
    the replay table instead."""
    s = _settings()
    if not s["enabled"]:
        abort(404)
    if mfa.ip_throttled():
        return _refuse("Too many failed sign-ins from your address. Try again later.", "ip_throttled", status=429)
    saml_response = request.form.get("SAMLResponse", "")
    reqid = _request_id(saml_response) if saml_response else None
    row = db.query_one("SELECT id, nonce_sha256, session_id, next_path FROM ui.saml_request WHERE id=%s"
                       " AND created_at > now() - make_interval(mins => %s)", (reqid, REQUEST_TTL_MINUTES)) \
        if reqid else None
    nonce = request.cookies.get(NONCE_COOKIE, "")
    if row is None or not nonce or not constant_time_eq(sha256_hex(nonce), row["nonce_sha256"]):
        return _refuse("This sign-in has expired or was started in another browser. Start again.", "no_request")
    db.execute("DELETE FROM ui.saml_request WHERE id=%s", (row["id"],))     # one answer per request
    try:
        r = sso.parse_response(_base_url(), s, saml_response, row["id"])
    except sso.SSOError as e:
        return _refuse(str(e), "invalid_response")
    db.execute("DELETE FROM ui.saml_replay WHERE expires_at < now()")
    if not db.execute("INSERT INTO ui.saml_replay (assertion_id, expires_at)"
                      " VALUES (%s, coalesce(%s::timestamptz, now() + interval '1 day')) ON CONFLICT DO NOTHING",
                      (r["assertion_id"], r["not_on_or_after"])):
        return _refuse("This sign-in response was already used.", "replay")
    if r["overage"]:
        return _refuse("Your account is in too many groups for the identity provider to list them. Ask an "
                       "administrator to emit only the groups assigned to this application.", "group_overage",
                       actor=r["name_id"])
    role, labels = sso.role_for(r["groups"])
    user = db.query_one("SELECT * FROM ui.admin_user WHERE saml_name_id = %s", (r["name_id"],))

    if row["session_id"] is not None:                      # step-up re-authentication
        sess = db.query_one("SELECT s.id, s.user_id FROM ui.session s WHERE s.id=%s", (row["session_id"],))
        if sess is None or user is None or user["id"] != sess["user_id"] or role is None or not user["enabled"]:
            return _refuse("Re-authentication did not confirm the signed-in user.", "stepup_mismatch",
                           actor=r["name_id"])
        db.execute("UPDATE ui.session SET stepup_at = now() WHERE id=%s", (sess["id"],))
        ev("auth.stepup", actor=user["username"], object_type="admin_user", object_id=user["id"],
           detail={"method": "saml", "authn_context": r["authn_context"]})
        return render_template("auth/sso_continue.html", next=row["next_path"])

    if role is None:
        return _refuse("You are not in a group that has access to this console.", "no_mapped_group",
                       actor=r["name_id"], groups=len(r["groups"]))
    if user is None:
        username = sso.username_for(r["name_id"])
        user = db.execute_returning(
            "INSERT INTO ui.admin_user (username, display_name, role, password_hash, must_change_password,"
            " auth_source, saml_name_id) VALUES (%s,%s,%s,%s,false,'saml',%s) RETURNING *",
            (username, r["display_name"], role, NO_PASSWORD, r["name_id"]))
        ev("ui_admin.create", actor=username, object_type="admin_user", object_id=user["id"],
           detail={"username": username, "role": role, "source": "saml", "groups": labels})
    elif not user["enabled"]:
        return _refuse("Your account is disabled in this console.", "disabled", actor=user["username"])
    elif user["role"] != role or (r["display_name"] and user["display_name"] != r["display_name"]):
        db.execute("UPDATE ui.admin_user SET role=%s, display_name=%s, updated_at=now() WHERE id=%s",
                   (role, r["display_name"] or user["display_name"], user["id"]))
        if user["role"] != role:
            ev("ui_admin.role", actor=user["username"], object_type="admin_user", object_id=user["id"],
               detail={"username": user["username"], "from": user["role"], "to": role, "source": "saml"})
    if g.get("session"):
        db.execute("DELETE FROM ui.session WHERE id=%s", (g.session["id"],))
    token = create_session(user["id"], mfa_ok=True)   # MFA is the identity provider's job
    db.execute("UPDATE ui.session SET stepup_at = now() WHERE token_sha256=%s", (sha256_hex(token),))
    db.execute("UPDATE ui.admin_user SET last_login_at=now(), last_login_ip=%s, failed_count=0 WHERE id=%s",
               (request.headers.get("X-Real-IP") or request.remote_addr, user["id"]))
    mfa.record_attempt(user["username"], True)
    ev("auth.login", actor=user["username"], object_type="admin_user", object_id=user["id"],
       detail={"method": "saml", "role": role, "groups": labels, "authn_context": r["authn_context"]})
    resp = Response(render_template("auth/sso_continue.html", next=row["next_path"]))
    resp.delete_cookie(NONCE_COOKIE, path="/", secure=True, httponly=True, samesite="None")
    return resp


@bp.route("/saml/metadata")
def metadata():
    """Service-provider metadata to register the portal with the identity provider."""
    return Response(sso.sp_metadata(_base_url(), _settings()), mimetype="application/samlmetadata+xml",
                    headers={"Content-Disposition": 'inline; filename="radius-admin-sp.xml"'})


# ------------------------------------------------------------------ settings
@bp.route("/settings/sso", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def settings():
    s = _settings()
    form, errors, idp = dict(s), [], None
    if request.method == "POST":
        form = {"enabled": form_bool("enabled"), "idp_metadata": request.form.get("idp_metadata", "")[:sso.MAX_METADATA + 1].strip(),
                "entity_id": form_str("entity_id", maxlen=300), "group_attribute": form_str("group_attribute", maxlen=300),
                "name_attribute": form_str("name_attribute", maxlen=300), "local_login": form_str("local_login")}
        try:
            sso.validate_attribute_name(form["group_attribute"], "Group claim")
            sso.validate_attribute_name(form["name_attribute"], "Display name claim")
            if form["entity_id"] and not form["entity_id"].startswith("https://"):
                raise ValueError("The entity ID must be an https:// URL (or empty for the default).")
            if form["local_login"] not in sso.LOCAL_LOGIN:
                raise ValueError("Choose who may still sign in with a local password.")
            if form["idp_metadata"] or form["enabled"]:
                idp = sso.idp_summary(_base_url(), dict(form), form["idp_metadata"])
            if form["enabled"] and not db.query_one("SELECT 1 FROM ui.sso_group_role"):
                raise ValueError("Map at least one group to a role before turning single sign-on on.")
        except ValueError as e:
            errors.append(str(e))
        else:
            changed = sorted(k for k in form if form[k] != s[k])
            for k, v in form.items():
                set_setting("saml_" + k, ("true" if v else "false") if isinstance(v, bool) else v)
            ev("sso.settings", detail={"changed": changed, "enabled": form["enabled"],
                                       "idp": idp["entity_id"] if idp else None})
            flash("Single sign-on settings saved." if changed else "No changes.", "success" if changed else "info")
            return redirect(url_for("sso.settings"))
    elif s["idp_metadata"]:
        try:
            idp = sso.idp_summary(_base_url(), s, s["idp_metadata"])
        except ValueError as e:
            errors.append(str(e))
    entity, acs_url = sso.sp_urls(_base_url(), form)
    groups = db.query("SELECT id, group_id, label, role FROM ui.sso_group_role ORDER BY label, group_id")
    return render_template("settings/sso.html", s=form, errors=errors, idp=idp, groups=groups, roles=ROLES,
                           sp_entity=entity, acs_url=acs_url), (400 if errors else 200)


@bp.route("/settings/sso/groups", methods=["POST"])
@role_required("admin")
@stepup_required
def add_group():
    try:
        gid = sso.validate_group_id(form_str("group_id", maxlen=300))
        role = form_str("role")
        if role not in ROLES:
            raise ValueError("Choose a role.")
        label = form_str("label", maxlen=200)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("sso.settings"))
    if db.query_one("SELECT 1 FROM ui.sso_group_role WHERE lower(group_id) = lower(%s)", (gid,)):
        flash("That group is already mapped.", "error")
        return redirect(url_for("sso.settings"))
    row = db.execute_returning("INSERT INTO ui.sso_group_role (group_id, label, role) VALUES (%s,%s,%s) RETURNING id",
                               (gid, label, role))
    ev("sso.group_add", object_type="sso_group_role", object_id=row["id"],
       detail={"group_id": gid, "label": label, "role": role})
    flash("Group mapped to %s. It applies from each user's next sign-in." % role, "success")
    return redirect(url_for("sso.settings"))


@bp.route("/settings/sso/groups/<int:mid>/delete", methods=["POST"])
@role_required("admin")
@stepup_required
def delete_group(mid):
    row = db.query_one("SELECT * FROM ui.sso_group_role WHERE id=%s", (mid,))
    if row is None:
        abort(404)
    if _settings()["enabled"] and db.query_one("SELECT count(*) AS n FROM ui.sso_group_role")["n"] <= 1:
        flash("Single sign-on is on: keep at least one mapping, or turn single sign-on off first.", "error")
        return redirect(url_for("sso.settings"))
    db.execute("DELETE FROM ui.sso_group_role WHERE id=%s", (mid,))
    ev("sso.group_delete", object_type="sso_group_role", object_id=mid,
       detail={"group_id": row["group_id"], "label": row["label"], "role": row["role"]})
    flash("Mapping removed. It applies from each user's next sign-in.", "success")
    return redirect(url_for("sso.settings"))
