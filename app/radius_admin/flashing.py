"""Flash messages without Flask's cookie session.

Messages queued during a request that ends in a redirect travel in a short-lived,
HMAC-authenticated cookie (UI text only, never secrets; the ui.session table has no
column for them). Same-request messages are rendered directly.
"""
import base64
import hmac
import json

from flask import current_app, g, request

FLASH_COOKIE = "__Host-radius_admin_flash"


def _mac(data: bytes) -> str:
    key = hmac.new(current_app.config["RA_DATA_KEY_RAW"], b"radius-admin flash v1", "sha256").digest()
    return hmac.new(key, data, "sha256").hexdigest()


def flash(message, category="info"):
    g.setdefault("flashes_out", []).append((category, str(message)))


def get_flashed_messages(with_categories=False):
    msgs = list(g.get("flashes_in", [])) + list(g.pop("flashes_out", []))
    g.flashes_in = []
    g.flashes_consumed = True
    return msgs if with_categories else [m for _, m in msgs]


def install_flash(app):
    app.jinja_env.globals["get_flashed_messages"] = get_flashed_messages

    @app.before_request
    def _load_flashes():
        g.flashes_in = []
        raw = request.cookies.get(FLASH_COOKIE)
        if not raw or "." not in raw:
            return
        data_b64, mac = raw.rsplit(".", 1)
        try:
            data = base64.urlsafe_b64decode(data_b64.encode())
            if hmac.compare_digest(mac, _mac(data)):
                g.flashes_in = [tuple(x) for x in json.loads(data)][:10]
        except (ValueError, TypeError):
            pass
        g.clear_flash_cookie = True

    @app.after_request
    def _save_flashes(resp):
        if request.endpoint == "static":
            return resp
        pending = list(g.get("flashes_out", []))
        if not g.get("flashes_consumed"):
            pending = list(g.get("flashes_in", [])) + pending
        if pending and resp.status_code in (301, 302, 303, 307, 308):
            data = json.dumps(pending[:10]).encode()
            val = base64.urlsafe_b64encode(data).decode() + "." + _mac(data)
            resp.set_cookie(FLASH_COOKIE, val, secure=True, httponly=True,
                            samesite="Strict", path="/", max_age=120)
        elif g.get("clear_flash_cookie"):
            resp.delete_cookie(FLASH_COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
        return resp
