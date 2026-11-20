"""Second-factor providers for device admin logins (SPEC section 29).

ui.mfa_provider holds the providers; their shared secrets are stored encrypted with the data
key (AES-256-GCM, additional data = provider id) and decrypted only to render the clients
file. ui.mfa_policy / ui.mfa_policy_client / ui.mfa_exempt decide, live, which device admin
logins need a second factor (radius_admin_mfa_hex in sql/101-mfa.sql).
"""
import json

from . import db

TYPE_LABELS = {"duo": "Duo Authentication Proxy", "radius-mfa": "Remote RADIUS MFA server"}
KIND_LABELS = {"local": "Local device admin accounts", "directory": "Directory accounts"}
ACCOUNT_KINDS = ("local", "directory")
EXEMPT_MAX = 10
_AAD = b"radius-admin:mfa_provider:"
PROVIDER_COLS = ("id, type, label, enabled, settings, secrets_enc, install_state, installed_version,"
                 " verified, created_at, updated_at")


def _aad(pid):
    return _AAD + pid.encode("ascii")


def data_key(explicit=None):
    """The data key: the one given, else the running app's."""
    if explicit is not None:
        return explicit
    from flask import current_app, has_app_context
    if has_app_context() and "RA_DATA_KEY" in current_app.config:
        return current_app.config["RA_DATA_KEY"]
    raise RuntimeError("the data key is needed to read second-factor provider secrets")


def encrypt_secrets(key, pid, secrets):
    return key.encrypt(json.dumps(secrets, sort_keys=True).encode("utf-8"), _aad(pid))


def decrypt_secrets(key, pid, blob):
    from .services import unlang
    if blob is None:
        return {}
    try:
        data = json.loads(key.decrypt(bytes(blob), _aad(pid)).decode("utf-8"))
    except Exception:
        raise unlang().PolicyInputError("The shared secret of second-factor provider %s cannot be read"
                                      " (was the data key replaced?). Enter it again." % pid)
    if not isinstance(data, dict):
        raise unlang().PolicyInputError("The stored secrets of second-factor provider %s are damaged." % pid)
    return data


def load_providers(conn=None):
    rows = db.query("SELECT " + PROVIDER_COLS + " FROM ui.mfa_provider ORDER BY id", conn=conn)
    out = []
    for r in rows:
        r = dict(r)
        r["settings"] = r["settings"] if isinstance(r["settings"], dict) else json.loads(r["settings"] or "{}")
        out.append(r)
    return out


def get_provider(pid, conn=None):
    for p in load_providers(conn):
        if p["id"] == pid:
            return p
    return None


def render_inputs(conn=None, key=None):
    """The enabled providers with their secrets, as unlang.render_mfa takes them."""
    out = []
    providers = [p for p in load_providers(conn) if p["enabled"]]
    if not providers:
        return out
    k = data_key(key)
    for p in providers:
        item = dict(p["settings"])
        item.update(decrypt_secrets(k, p["id"], p["secrets_enc"]))
        item.update(id=p["id"], type=p["type"], enabled=True)
        out.append(item)
    return out


def load_policy(conn=None):
    """{kind: {enabled, provider_id, client_scope, client_ids}} for both account kinds."""
    rows = {r["account_kind"]: dict(r) for r in db.query(
        "SELECT account_kind, enabled, provider_id, client_scope FROM ui.mfa_policy", conn=conn)}
    clients = db.query("SELECT account_kind, client_id FROM ui.mfa_policy_client ORDER BY client_id", conn=conn)
    out = {}
    for kind in ACCOUNT_KINDS:
        r = rows.get(kind) or {"enabled": False, "provider_id": None, "client_scope": "all"}
        out[kind] = {"enabled": bool(r["enabled"]), "provider_id": r["provider_id"],
                     "client_scope": r["client_scope"],
                     "client_ids": [c["client_id"] for c in clients if c["account_kind"] == kind]}
    return out


def load_exempt(conn=None):
    return [r["username"] for r in db.query("SELECT username FROM ui.mfa_exempt ORDER BY lower(username)",
                                            conn=conn)]


def providers_in_use(conn=None):
    """Provider ids that an account kind's policy names (enabled or not)."""
    return {r["provider_id"] for r in db.query(
        "SELECT provider_id FROM ui.mfa_policy WHERE provider_id IS NOT NULL", conn=conn)}
