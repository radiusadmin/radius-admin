"""Login: consent banner -> password -> MFA (or forced enrollment) -> forced password change.
Also step-up re-authentication and logout."""
import base64
import io

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .. import db, mfa, sso
from ..crypto import (b32, dummy_password_work, totp_new_secret, totp_uri, totp_verify,
                      verify_password)
from ..flashing import flash
from ..security import (banner_acknowledged, cfg, create_session, destroy_session,
                        presented_cert, rotate_session, safe_next, set_banner_ack)
from ..services import get_settings
from ..users import get_by_username
from . import ev, form_str

bp = Blueprint("auth", __name__)

GENERIC_FAIL = "Sign-in failed. Check your username and password."


@bp.route("/login", methods=["GET"])
def login():
    if g.get("user") and g.session["mfa_ok"]:
        return redirect(url_for("dashboard.index"))
    settings = get_settings()
    if not banner_acknowledged():
        return render_template("auth/banner.html", banner=settings["banner_text"])
    return render_template("auth/login.html", banner=settings["banner_text"])


@bp.route("/banner", methods=["POST"])
def banner_ack():
    if request.form.get("accept") != "1":
        return redirect(url_for("auth.login"))
    set_banner_ack()
    ev("auth.banner_ack", actor=None, detail={})
    return redirect(url_for("auth.login"))


def _fail(username, user=None, reason="bad_password"):
    mfa.record_attempt(username, False)
    locked = False
    if user is not None:
        locked = mfa.register_failure(user)
    ev("auth.login", success=False, actor=username or None, object_type="admin_user",
       object_id=user["id"] if user else None,
       detail={"reason": reason, **({"locked": True} if locked else {})})
    if locked:
        ev("auth.lockout", success=False, actor=username, object_type="admin_user",
           object_id=user["id"], detail={"minutes": cfg()["lockout_minutes"]})


@bp.route("/login", methods=["POST"])
def login_post():
    settings = get_settings()
    if not banner_acknowledged():
        flash("Acknowledge the notice before signing in.", "error")
        return redirect(url_for("auth.login"))
    username = form_str("username", maxlen=64).lower()
    password = request.form.get("password", "")[:256]
    if mfa.ip_throttled():
        mfa.record_attempt(username, False)
        ev("auth.login", success=False, actor=username or None, detail={"reason": "ip_throttled"})
        return render_template("auth/login.html", banner=settings["banner_text"],
                               error="Too many failed sign-ins from your address. Try again later."), 429
    user = get_by_username(username) if username else None
    if user is None:
        dummy_password_work(cfg()["pbkdf2_iterations"])
        _fail(username, None, "unknown_user")
        return render_template("auth/login.html", banner=settings["banner_text"], error=GENERIC_FAIL,
                               username=username), 401
    if mfa.is_locked(user):
        dummy_password_work(cfg()["pbkdf2_iterations"])
        mfa.record_attempt(username, False)
        ev("auth.login", success=False, actor=username, object_type="admin_user",
           object_id=user["id"], detail={"reason": "locked"})
        return render_template("auth/login.html", banner=settings["banner_text"], error=GENERIC_FAIL,
                               username=username), 401
    ok = verify_password(password, user["password_hash"])
    if not ok or not user["enabled"]:
        _fail(username, user, "bad_password" if not ok else "disabled")
        return render_template("auth/login.html", banner=settings["banner_text"], error=GENERIC_FAIL,
                               username=username), 401
    saml = sso.settings(settings["saml"])
    if saml["enabled"] and saml["local_login"] == "admins" and user["role"] != "admin":
        # With single sign-on on, local passwords can be kept for administrators only (break glass).
        _fail(username, None, "local_login_admins_only")
        return render_template("auth/login.html", banner=settings["banner_text"], error=GENERIC_FAIL,
                               username=username), 401
    # Password accepted: new session (fresh token) in "MFA pending" state.
    if g.get("session"):
        destroy_session()
    g.clear_cookie = False
    create_session(user["id"], mfa_ok=False)
    ev("auth.password_ok", actor=username, object_type="admin_user", object_id=user["id"])
    nxt = safe_next(request.args.get("next")) or ""
    if not user["mfa_method"]:
        return redirect(url_for("auth.enroll"))
    return redirect(url_for("auth.mfa", next=nxt) if nxt else url_for("auth.mfa"))


def _pending_user():
    """Session that passed the password step but not MFA."""
    if not g.get("user"):
        return None
    return g.user


@bp.route("/login/mfa", endpoint="mfa", methods=["GET", "POST"])
def mfa_view():
    user = _pending_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if g.session["mfa_ok"]:
        return redirect(url_for("dashboard.index"))
    if not user["mfa_method"]:
        return redirect(url_for("auth.enroll"))
    error = None
    if request.method == "POST":
        if mfa.ip_throttled():
            return render_template("auth/mfa.html", user=user, cert=presented_cert(),
                                   error="Too many failed sign-ins from your address. Try again later."), 429
        if mfa.is_locked(user):
            destroy_session()
            flash(GENERIC_FAIL, "error")
            return redirect(url_for("auth.login"))
        ok, method = mfa.verify_second_factor(user, request.form.get("code", "")[:16])
        if ok:
            rotate_session(mark_mfa_ok=True)
            mfa.register_success(user)
            mfa.record_attempt(user["username"], True)
            ev("auth.login", success=True, object_type="admin_user", object_id=user["id"],
               detail={"mfa": method})
            nxt = safe_next(request.args.get("next"))
            return redirect(nxt or url_for("dashboard.index"))
        mfa.record_attempt(user["username"], False)
        locked = mfa.register_failure(user)
        ev("auth.mfa", success=False, object_type="admin_user", object_id=user["id"],
           detail={"mfa": method, **({"locked": True} if locked else {})})
        if locked:
            ev("auth.lockout", success=False, object_type="admin_user", object_id=user["id"],
               detail={"minutes": cfg()["lockout_minutes"]})
            destroy_session()
            flash(GENERIC_FAIL, "error")
            return redirect(url_for("auth.login"))
        error = ("The certificate presented does not match your enrolled certificate."
                 if method == "cert" else "That code is not valid. Wait for the next code and try again.")
    return render_template("auth/mfa.html", user=user, cert=presented_cert(), error=error), (
        401 if error else 200)



# ---------------------------------------------------------- enrollment
def _candidate_aad():
    return b"radius-admin totp-candidate v1 session=%d user=%d" % (g.session["id"], g.user["id"])


def seal_candidate(secret):
    blob = current_app.config["RA_DATA_KEY"].encrypt(secret, _candidate_aad())
    return base64.urlsafe_b64encode(blob).decode()


def open_candidate(token):
    try:
        return current_app.config["RA_DATA_KEY"].decrypt(
            base64.urlsafe_b64decode(token.encode()), _candidate_aad())
    except Exception:
        return None


def qr_svg(uri):
    """Inline SVG (as data: URI is not needed; we embed markup) or None."""
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


def enrollment_context(candidate_token=None):
    secret = open_candidate(candidate_token) if candidate_token else None
    if secret is None:
        secret = totp_new_secret()
        candidate_token = seal_candidate(secret)
    uri = totp_uri(secret, g.user["username"], cfg()["totp_issuer"])
    return {"candidate": candidate_token, "secret_b32": " ".join(
        b32(secret)[i:i + 4] for i in range(0, len(b32(secret)), 4)),
        "qr": qr_svg(uri), "cert": presented_cert()}


def complete_enrollment(method, form):
    """Shared by forced enrollment and account MFA change. Returns (ok, error)."""
    user = g.user
    if method == "totp":
        secret = open_candidate(form.get("candidate", ""))
        if secret is None:
            return False, "The enrollment form expired. Scan the new code and try again."
        step = totp_verify(secret, form.get("code", "")[:16], None)
        if step is None:
            return False, "That code does not match. Check your authenticator's clock and try again."
        db.execute("UPDATE ui.admin_user SET mfa_method='totp', totp_secret_enc=%s, totp_last_step=%s,"
                   " cert_sha256=NULL, cert_subject=NULL, updated_at=now() WHERE id=%s",
                   (mfa.encrypt_totp(user["id"], secret), step, user["id"]))
        ev("mfa.enroll", object_type="admin_user", object_id=user["id"], detail={"method": "totp"})
        return True, None
    if method == "cert":
        pc = presented_cert()
        if pc is None:
            return False, ("No verified client certificate was presented. Make sure your certificate is installed in this browser, "
                           "reload the page and choose your certificate when the browser asks.")
        other = db.query_one("SELECT id FROM ui.admin_user WHERE cert_sha256=%s AND id<>%s",
                             (pc[0], user["id"]))
        if other:
            return False, "That certificate is already bound to another account."
        db.execute("UPDATE ui.admin_user SET mfa_method='cert', cert_sha256=%s, cert_subject=%s,"
                   " totp_secret_enc=NULL, totp_last_step=NULL, updated_at=now() WHERE id=%s",
                   (pc[0], pc[1][:500], user["id"]))
        ev("mfa.enroll", object_type="admin_user", object_id=user["id"],
           detail={"method": "cert", "cert_sha256": pc[0], "subject": pc[1][:500]})
        return True, None
    return False, "Choose an authentication method."


@bp.route("/login/enroll", methods=["GET", "POST"])
def enroll():
    user = _pending_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if user["mfa_method"]:
        return redirect(url_for("auth.mfa") if not g.session["mfa_ok"] else url_for("dashboard.index"))
    error = None
    method = request.values.get("method", "totp")
    if request.method == "POST":
        ok, error = complete_enrollment(request.form.get("method"), request.form)
        if ok:
            rotate_session(mark_mfa_ok=True)
            mfa.register_success(user)
            mfa.record_attempt(user["username"], True)
            ev("auth.login", success=True, object_type="admin_user", object_id=user["id"],
               detail={"mfa": request.form.get("method"), "enrolled": True})
            flash("Two-factor authentication is set up.", "success")
            return redirect(url_for("dashboard.index"))
        mfa.record_attempt(user["username"], False)
        if mfa.register_failure(user):
            ev("auth.lockout", success=False, object_type="admin_user", object_id=user["id"])
            destroy_session()
            flash(GENERIC_FAIL, "error")
            return redirect(url_for("auth.login"))
    ctx = enrollment_context(request.form.get("candidate") if request.method == "POST" else None)
    return render_template("auth/enroll.html", error=error, method=method, forced=True,
                           action=url_for("auth.enroll"), **ctx), (400 if error else 200)


# -------------------------------------------------------------- step-up
@bp.route("/stepup", methods=["GET", "POST"])
def stepup():
    user = g.get("user")
    if not user or not g.session["mfa_ok"]:
        return redirect(url_for("auth.login"))
    nxt = safe_next(request.values.get("next")) or url_for("dashboard.index")
    if user["auth_source"] == "saml":
        # Single sign-on users confirm their identity at the identity provider (ForceAuthn).
        return redirect(url_for("sso.login", stepup="1", next=nxt))
    error = None
    if request.method == "POST":
        if mfa.is_locked(user):
            destroy_session()
            flash(GENERIC_FAIL, "error")
            return redirect(url_for("auth.login"))
        pw_ok = verify_password(request.form.get("password", "")[:256], user["password_hash"])
        f_ok, method = mfa.verify_second_factor(user, request.form.get("code", "")[:16]) if pw_ok else (False, None)
        if pw_ok and f_ok:
            db.execute("UPDATE ui.session SET stepup_at = now() WHERE id=%s", (g.session["id"],))
            db.execute("UPDATE ui.admin_user SET failed_count=0 WHERE id=%s", (user["id"],))
            rotate_session()
            ev("auth.stepup", object_type="admin_user", object_id=user["id"], detail={"mfa": method})
            return redirect(nxt)
        locked = mfa.register_failure(user)
        ev("auth.stepup", success=False, object_type="admin_user", object_id=user["id"],
           detail={"reason": "bad_password" if not pw_ok else "bad_mfa"})
        if locked:
            ev("auth.lockout", success=False, object_type="admin_user", object_id=user["id"])
            destroy_session()
            flash(GENERIC_FAIL, "error")
            return redirect(url_for("auth.login"))
        error = "Verification failed. Check your password and second factor."
    return render_template("auth/stepup.html", next=nxt, error=error, cert=presented_cert(),
                           user=user), (401 if error else 200)


def inline_stepup(form):
    """Verify step-up fields submitted with a form (used where losing the form's
    content to a redirect would be costly). Returns (ok, attempted)."""
    user = g.user
    pw = form.get("stepup_password", "")
    if not pw:
        return False, False
    if mfa.is_locked(user):
        return False, True
    pw_ok = verify_password(pw[:256], user["password_hash"])
    f_ok, method = mfa.verify_second_factor(user, form.get("stepup_code", "")[:16]) if pw_ok else (False, None)
    if pw_ok and f_ok:
        db.execute("UPDATE ui.session SET stepup_at = now() WHERE id=%s", (g.session["id"],))
        db.execute("UPDATE ui.admin_user SET failed_count=0 WHERE id=%s", (user["id"],))
        g.session["stepup_ok"] = True
        ev("auth.stepup", object_type="admin_user", object_id=user["id"], detail={"mfa": method, "inline": True})
        return True, True
    if mfa.register_failure(user):
        ev("auth.lockout", success=False, object_type="admin_user", object_id=user["id"])
    ev("auth.stepup", success=False, object_type="admin_user", object_id=user["id"],
       detail={"reason": "bad_password" if not pw_ok else "bad_mfa", "inline": True})
    return False, True


@bp.route("/logout", methods=["POST"])
def logout():
    if g.get("user"):
        ev("auth.logout", object_type="admin_user", object_id=g.user["id"])
        destroy_session()
    flash("You are signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/")
def root():
    return redirect(url_for("dashboard.index"))
