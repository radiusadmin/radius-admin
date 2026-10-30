"""Server-side sessions, CSRF, RBAC, step-up, client IP and client-cert helpers."""
import functools
import hmac
import re
from urllib.parse import unquote, urlsplit

from flask import abort, current_app, g, redirect, request, url_for

from . import db
from .flashing import flash
from .crypto import (cert_pem_to_der, cert_subject, constant_time_eq, random_token,
                     sha256_hex)

COOKIE = "__Host-radius_admin"
PRE_COOKIE = "__Host-radius_admin_pre"
THEME_COOKIE = "__Host-radius_admin_theme"
THEMES = ("system", "light", "dark")
# Editable in Settings (ui.setting); defaults come from the config file. (min, max, unit)
SESSION_LIMITS = {"session_idle_minutes": (5, 480, "minutes"),
                  "session_absolute_hours": (1, 24, "hours"),
                  "stepup_minutes": (1, 60, "minutes")}
ROLES = ("viewer", "operator", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
PENDING_MFA_MAX_MINUTES = 10


def cfg():
    return current_app.config["RA"]


# ------------------------------------------------------------------ client IP
def client_ip():
    """nginx -> gunicorn runs over a unix socket, so remote_addr is empty; nginx
    sets X-Real-IP to $remote_addr (overwriting anything the client sent)."""
    ip = None
    if cfg()["trust_proxy_headers"]:
        ip = request.headers.get("X-Real-IP")
    ip = ip or request.remote_addr
    if not ip:
        return None
    import ipaddress
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None


# ---------------------------------------------------------- client certificate
def presented_cert():
    """Return (sha256_hex_of_der, subject) if nginx verified a client cert, else None.

    Only X-Client-Verify: SUCCESS with X-Client-Cert ($ssl_client_escaped_cert) is
    trusted. nginx must overwrite both headers on every request (proxy_set_header).
    """
    if request.headers.get("X-Client-Verify", "") != "SUCCESS":
        return None
    raw = request.headers.get("X-Client-Cert", "")
    if not raw:
        return None
    try:
        der = cert_pem_to_der(unquote(raw))
    except ValueError:
        return None
    return sha256_hex(der), cert_subject(der)


def cert_matches(user):
    pc = presented_cert()
    if not pc or not user.get("cert_sha256"):
        return False
    return hmac.compare_digest(pc[0].encode(), user["cert_sha256"].encode())


# ---------------------------------------------------------------- sessions
def _cookie_kwargs():
    return dict(secure=True, httponly=True, samesite="Strict", path="/")


def create_session(user_id, mfa_ok=False, response_hook=True):
    token = random_token(32)
    csrf = random_token(32)
    db.execute(
        "INSERT INTO ui.session (token_sha256, user_id, mfa_ok, csrf_token, ip, user_agent)"
        " VALUES (%s,%s,%s,%s,%s,%s)",
        (sha256_hex(token), user_id, mfa_ok, csrf, client_ip(),
         (request.headers.get("User-Agent") or "")[:300]))
    g.set_cookie = token
    return token


def rotate_session(mark_mfa_ok=None):
    """Issue a new token (and CSRF token) for the current session row."""
    sess = g.session
    token = random_token(32)
    csrf = random_token(32)
    if mark_mfa_ok is None:
        db.execute("UPDATE ui.session SET token_sha256=%s, csrf_token=%s WHERE id=%s",
                   (sha256_hex(token), csrf, sess["id"]))
    else:
        db.execute("UPDATE ui.session SET token_sha256=%s, csrf_token=%s, mfa_ok=%s,"
                   " stepup_at=CASE WHEN %s THEN now() ELSE stepup_at END WHERE id=%s",
                   (sha256_hex(token), csrf, mark_mfa_ok, mark_mfa_ok, sess["id"]))
    sess["csrf_token"] = csrf
    if mark_mfa_ok is not None:
        sess["mfa_ok"] = mark_mfa_ok
    g.set_cookie = token


def destroy_session():
    if g.get("session"):
        db.execute("DELETE FROM ui.session WHERE id=%s", (g.session["id"],))
    g.session = None
    g.user = None
    g.clear_cookie = True


def load_session():
    g.session = None
    g.user = None
    token = request.cookies.get(COOKIE)
    if not token or len(token) > 100:
        return
    c = cfg()
    # Session limits: the admin's values from Settings (ui.setting), else the config file;
    # clamped to SESSION_LIMITS here as well, so a bad stored value can never widen them.
    lim = ", ".join(
        "least(greatest(coalesce((SELECT substring(value from '^[0-9]{1,4}$')::integer FROM ui.setting"
        " WHERE key = '%s'), %%s), %d), %d) AS %s" % (k, lo, hi, k)
        for k, (lo, hi, _unit) in SESSION_LIMITS.items())
    row = db.query_one(
        "WITH lim AS (SELECT " + lim + ")"
        " SELECT s.id AS sid, s.user_id, s.mfa_ok, s.csrf_token, s.created_at, s.last_seen_at,"
        " s.stepup_at,"
        " (now() - s.last_seen_at) > make_interval(mins => lim.session_idle_minutes) AS idle_expired,"
        " (now() - s.created_at) > make_interval(hours => lim.session_absolute_hours) AS abs_expired,"
        " (now() - s.created_at) > make_interval(mins => %s) AS pending_expired,"
        " (s.stepup_at IS NOT NULL AND (now() - s.stepup_at) <= make_interval(mins => lim.stepup_minutes)) AS stepup_ok,"
        " u.id, u.username, u.display_name, u.role, u.enabled, u.must_change_password,"
        " u.mfa_method, u.cert_sha256, u.cert_subject, u.totp_secret_enc, u.totp_last_step,"
        " u.locked_until, u.password_hash, u.password_changed_at, u.theme, u.auth_source"
        " FROM ui.session s JOIN ui.admin_user u ON u.id = s.user_id CROSS JOIN lim"
        " WHERE s.token_sha256 = %s",
        tuple(c[k] for k in SESSION_LIMITS) + (PENDING_MFA_MAX_MINUTES, sha256_hex(token)))
    if row is None:
        g.clear_cookie = True
        return
    expired = row["idle_expired"] or row["abs_expired"] or not row["enabled"] or (
        not row["mfa_ok"] and row["pending_expired"])
    if expired:
        db.execute("DELETE FROM ui.session WHERE id=%s", (row["sid"],))
        g.clear_cookie = True
        g.session_expired = True
        return
    db.execute("UPDATE ui.session SET last_seen_at = now() WHERE id=%s", (row["sid"],))
    # Commit at once so no request holds a lock on its own session row while it runs:
    # otherwise two admins disabling each other deadlock (each holds its session row and
    # waits for the other's, via the admin-change lock), and parallel requests of one
    # browser serialize on that row.
    db.commit()
    g.session = {"id": row["sid"], "mfa_ok": row["mfa_ok"], "csrf_token": row["csrf_token"],
                 "created_at": row["created_at"], "stepup_ok": row["stepup_ok"],
                 "stepup_at": row["stepup_at"]}
    g.user = {k: row[k] for k in (
        "id", "username", "display_name", "role", "enabled", "must_change_password",
        "mfa_method", "cert_sha256", "cert_subject", "totp_secret_enc", "totp_last_step",
        "locked_until", "password_hash", "password_changed_at", "theme", "auth_source")}


def apply_cookie(response):
    if g.get("set_cookie"):
        response.set_cookie(COOKIE, g.set_cookie, **_cookie_kwargs())
    elif g.get("clear_cookie"):
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
    return response


# -------------------------------------------------------------------- CSRF
def same_origin_ok():
    """Origin (or, if absent, Referer) must name this host."""
    host = request.host.lower()
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        return urlsplit(origin).netloc.lower() == host
    ref = request.headers.get("Referer")
    if ref:
        return urlsplit(ref).netloc.lower() == host
    return False


def check_csrf():
    """Called for every POST. Authenticated: session token. Pre-auth: double-submit."""
    if not same_origin_ok():
        abort(403, "Request origin could not be verified.")
    sent = request.form.get("csrf_token", "")
    if g.get("session"):
        expected = g.session["csrf_token"]
    else:
        expected = request.cookies.get(PRE_COOKIE, "").split(".")[0]
    if not sent or not expected or not constant_time_eq(sent, expected):
        abort(403, "Your form expired or was submitted from another page. Reload and try again.")


def csrf_token():
    if g.get("session"):
        return g.session["csrf_token"]
    return pre_token()


# ---------------------------------------- pre-auth cookie (CSRF + banner ack)
def _pre_mac(token):
    key = hmac.new(current_app.config["RA_DATA_KEY_RAW"], b"radius-admin pre-auth v1",
                   "sha256").digest()
    return hmac.new(key, ("banner-ack|" + token).encode(), "sha256").hexdigest()


def pre_token():
    if g.get("pre_token"):
        return g.pre_token
    tok = request.cookies.get(PRE_COOKIE, "").split(".")[0]
    if not tok or len(tok) > 64:
        tok = random_token(24)
        g.set_pre_cookie = tok
    g.pre_token = tok
    return tok


def banner_acknowledged():
    parts = request.cookies.get(PRE_COOKIE, "").split(".")
    if len(parts) != 2 or not parts[0]:
        return False
    return constant_time_eq(parts[1], _pre_mac(parts[0]))


def set_banner_ack():
    tok = pre_token()
    g.set_pre_cookie = tok + "." + _pre_mac(tok)


def apply_pre_cookie(response):
    if g.get("set_pre_cookie"):
        response.set_cookie(PRE_COOKIE, g.set_pre_cookie, **_cookie_kwargs())
    return response


# ------------------------------------------------------------ colour theme
def current_theme():
    """The signed-in user's theme; before sign-in, the theme cookie (a display hint only)."""
    if g.get("user"):
        return g.user.get("theme") or "system"
    t = request.cookies.get(THEME_COOKIE, "")
    return t if t in THEMES else "system"


def apply_theme_cookie(response):
    if g.get("set_theme_cookie"):
        response.set_cookie(THEME_COOKIE, g.set_theme_cookie, max_age=365 * 86400, **_cookie_kwargs())
    return response


# --------------------------------------------------------------- decorators
def login_required(view):
    """Full session: password + MFA done, MFA enrolled, password not expired."""
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not g.get("user"):
            if g.get("session_expired"):
                flash("Your session expired. Sign in again.", "info")
            return redirect(url_for("auth.login"))
        if not g.session["mfa_ok"]:
            if not g.user["mfa_method"]:
                return redirect(url_for("auth.enroll"))
            return redirect(url_for("auth.mfa"))
        if g.user["must_change_password"]:
            return redirect(url_for("account.password"))
        return view(*a, **kw)
    return wrapped


def role_required(min_role):
    def deco(view):
        @functools.wraps(view)
        @login_required
        def wrapped(*a, **kw):
            if ROLE_RANK[g.user["role"]] < ROLE_RANK[min_role]:
                abort(403, "Your role (%s) does not allow this action." % g.user["role"])
            return view(*a, **kw)
        return wrapped
    return deco


def has_role(min_role):
    return bool(g.get("user")) and ROLE_RANK[g.user["role"]] >= ROLE_RANK[min_role]


def stepup_required(view):
    """Require password + MFA re-verification within stepup_minutes.

    GET requests are redirected to the step-up page and come back; POSTs whose
    step-up has lapsed are bounced to step-up and must be resubmitted.
    """
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not g.session.get("stepup_ok"):
            if request.method == "GET":
                nxt = request.full_path if request.query_string else request.path
            else:
                flash("Confirm your identity, then submit the form again.", "info")
                nxt = safe_next(request.form.get("return_to")) or request.path
            return redirect(url_for("auth.stepup", next=nxt))
        return view(*a, **kw)
    return wrapped


_SAFE_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-][A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?$")


def safe_next(target):
    """Allow-list for redirect targets: a local path only.

    Must start with exactly one "/" followed by a non-"/" and non-"\\" character,
    contain no scheme/netloc, no backslash, no control characters, and must still
    satisfy all of that after percent-decoding (rejects /%2f/evil, /%5cevil, etc.).
    """
    if not target or not isinstance(target, str) or len(target) > 2000:
        return None
    candidates = [target]
    decoded = target
    for _ in range(3):  # repeated decoding catches %252f and similar
        decoded = unquote(decoded)
        candidates.append(decoded)
    for t in candidates:
        if not t.startswith("/") or t.startswith("//") or "\\" in t:
            return None
        if any(ord(c) < 0x20 or ord(c) == 0x7f for c in t):
            return None
        parts = urlsplit(t)
        if parts.scheme or parts.netloc:
            return None
        if "/" in t[1:2] or "\\" in t[1:2]:
            return None
    if not _SAFE_PATH_RE.match(target):
        return None
    return target
