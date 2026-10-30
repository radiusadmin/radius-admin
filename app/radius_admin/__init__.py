"""radius-admin: web administration UI for FreeRADIUS (FIPS deployment)."""
import datetime
import os

from flask import Flask, g, render_template, request, url_for

__all__ = ["create_app"]

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


def create_app(config_path=None, overrides=None):
    from . import audit, db, security
    from .config import load_config
    from .crypto import DataKey, require_fips_or_die, fips_status

    cfg = load_config(config_path, overrides)
    if cfg["require_fips"]:
        require_fips_or_die()

    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["RA"] = cfg
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
    app.config["SESSION_COOKIE_NAME"] = "unused"  # Flask sessions are not used
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 3600
    # Flask's flash() needs app.secret_key / session; we keep flashes in g instead.
    with open(cfg["key_file"], "rb") as fh:
        raw = fh.read()
    app.config["RA_DATA_KEY"] = DataKey(raw)
    app.config["RA_DATA_KEY_RAW"] = raw
    app.config["RA_FIPS"] = fips_status()
    audit.configure_syslog(cfg["log_syslog"])

    # Versioned asset URLs (?v=<sha256 prefix>): a new release changes the URL, so
    # browsers never mix new pages with a cached old stylesheet or script.
    import hashlib
    _asset_v = {}
    for _name in ("app.css", "app.js"):
        with open(os.path.join(app.static_folder, _name), "rb") as fh:
            _asset_v[_name] = hashlib.sha256(fh.read()).hexdigest()[:12]

    def asset_url(name):
        return url_for("static", filename=name, v=_asset_v.get(name, ""))
    app.jinja_env.globals["asset_url"] = asset_url

    app.jinja_env.autoescape = True
    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    from .flashing import install_flash
    install_flash(app)

    from .views import (account, admins, alerts as alerts_v, apply as apply_v, auth, clients, dashboard, logs,
                        mab, reports, rules, sessions, settings as settings_v, setup, snmp as snmp_v,
                        sso as sso_v, switch_admins)
    for bp in (auth.bp, account.bp, dashboard.bp, clients.bp, switch_admins.bp, rules.bp,
               mab.bp, apply_v.bp, logs.bp, settings_v.bp, admins.bp, snmp_v.bp, sessions.bp,
               alerts_v.bp, reports.bp, sso_v.bp, setup.bp):
        app.register_blueprint(bp)

    # The SAML assertion consumer service receives a cross-site POST from the identity
    # provider by design; it is verified by signature, InResponseTo, a browser nonce and a
    # replay table instead of the CSRF token (views/sso.py).
    CSRF_EXEMPT = ("sso.acs",)

    @app.before_request
    def _before():
        g.now = datetime.datetime.now(datetime.timezone.utc)
        if request.endpoint == "static":
            return None
        security.load_session()
        if request.method == "POST" and request.endpoint not in CSRF_EXEMPT:
            security.check_csrf()
        return None

    @app.after_request
    def _after(resp):
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Pragma"] = "no-cache"
            security.apply_cookie(resp)
            security.apply_pre_cookie(resp)
            security.apply_theme_cookie(resp)
        return resp

    @app.teardown_request
    def _teardown(exc):
        db.close_db(exc)

    @app.context_processor
    def _ctx():
        from .services import pending_state
        user = g.get("user")
        full = bool(user) and g.get("session") and g.session["mfa_ok"] and not user["must_change_password"]
        pending = None
        if full and request.endpoint not in ("static",):
            try:
                pending = pending_state()
            except Exception:  # never break page rendering over the banner
                pending = None
        nav = None
        if full and request.endpoint not in ("static",):
            try:   # tables are missing until the postgres phase has run
                nav = db.query_one_optional(
                    "SELECT (SELECT count(*) FROM ui.alert WHERE state = 'open') AS alerts,"
                    " (SELECT count(*) FROM mab_pending WHERE NOT ignored) AS unknown_mab")
            except Exception:
                nav = None
        return {
            "current_user": user if full else None,
            "pending": pending,
            "nav_counts": nav,
            "fips": app.config["RA_FIPS"],
            # FIPS mode is the install-time choice (require_fips). When it is off, no page
            # mentions FIPS at all (rule 7); when it is on, pages show whether the OS complies.
            "fips_mode": cfg["require_fips"],
            "server_name": cfg["server_name"] or request.host.split(":")[0],
            "now": g.get("now"),
            "theme": security.current_theme() if request.endpoint != "static" else "system",
            "sso_enabled": _sso_enabled() if (request.endpoint or "").startswith("auth.") else False,
        }

    def _sso_enabled():
        from . import sso
        from .services import get_settings
        try:
            return sso.settings(get_settings()["saml"])["enabled"]
        except Exception:  # never break the sign-in page over SSO settings
            return False

    def _err(code, default):
        def handler(e):
            desc = getattr(e, "description", None) or default
            return render_template("error.html", code=code, message=desc), code
        return handler

    app.register_error_handler(400, _err(400, "The request could not be understood."))
    app.register_error_handler(403, _err(403, "You do not have permission to do that."))
    app.register_error_handler(404, _err(404, "That page does not exist."))
    app.register_error_handler(405, _err(405, "That method is not allowed here."))
    app.register_error_handler(413, _err(413, "The upload is too large (limit 2 MiB)."))

    @app.errorhandler(500)
    def _500(e):
        audit.log_syslog("internal error on %s %s" % (request.method, request.path))
        return render_template("error.html", code=500,
                               message="Something went wrong. The error was logged."), 500

    app.jinja_env.filters["dt"] = _fmt_dt
    app.jinja_env.filters["dtc"] = _fmt_dt_cell
    from .ports import port_summary, same_ports
    app.jinja_env.filters["ports"] = port_summary
    app.jinja_env.globals["same_ports"] = same_ports
    from . import oui
    app.jinja_env.filters["vendor"] = oui.vendor
    app.jinja_env.filters["mac"] = _fmt_mac
    app.jinja_env.filters["duration"] = _fmt_duration
    app.jinja_env.filters["ago"] = _fmt_ago
    # Globals (not context) so imported macros can use them too.
    app.jinja_env.globals["csrf_token"] = security.csrf_token
    app.jinja_env.globals["has_role"] = security.has_role
    return app


def _fmt_dt_cell(value):
    """Timestamp for a table cell: date and time may wrap onto two lines on narrow screens."""
    from markupsafe import Markup, escape
    text = _fmt_dt(value)
    if " " not in text:
        return text
    date, rest = text.split(" ", 1)
    return Markup('<span class="dt"><span>%s</span> <span>%s</span></span>') % (escape(date), escape(rest))


def _fmt_mac(value):
    """Any MAC notation -> AA-BB-CC-DD-EE-FF (the MAB format); other text unchanged."""
    from .oui import normalize
    h = normalize(value)
    if h is None:
        return value or ""
    return "-".join(h[i:i + 2] for i in range(0, 12, 2))


def _fmt_duration(seconds):
    if seconds is None:
        return "—"
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return "—"
    if s < 0:
        s = 0
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return "%d d %d h" % (d, h)
    if h:
        return "%d h %d min" % (h, m)
    if m:
        return "%d min" % m
    return "%d s" % s


def _fmt_ago(value):
    """'5 min ago' / 'in 3 d' relative to now (UTC)."""
    if not value or not isinstance(value, datetime.datetime):
        return "—"
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = (now - value).total_seconds()
    if 0 <= delta < 60:
        return "just now"
    if delta >= 0:
        return _fmt_duration(delta) + " ago"
    return "in " + _fmt_duration(-delta)


def _fmt_dt(value):
    if not value:
        return "—"
    if isinstance(value, datetime.datetime):
        return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)
