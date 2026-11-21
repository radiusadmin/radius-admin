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


def coverage(conn=None):
    """Which device admin logins need a second factor, for reports and the setup checklist:
    {kind: {enabled, provider_id, provider (label), provider_type, provider_on, clients ('all'
    or a list of client names), label}}, plus 'exempt' (local accounts) and 'providers'."""
    providers = {p["id"]: p for p in load_providers(conn)}
    names = {r["id"]: r["name"] for r in db.query("SELECT id, name FROM ui.radius_client", conn=conn)}
    out = {}
    for kind, pol in load_policy(conn).items():
        p = providers.get(pol["provider_id"]) if pol["provider_id"] else None
        out[kind] = {"enabled": pol["enabled"], "provider_id": pol["provider_id"],
                     "provider": (p["label"] or TYPE_LABELS.get(p["type"], p["id"])) if p else "",
                     "provider_type": p["type"] if p else "", "provider_on": bool(p and p["enabled"]),
                     "clients": "all" if pol["client_scope"] == "all" else sorted(
                         names[c] for c in pol["client_ids"] if c in names),
                     "label": KIND_LABELS[kind]}
    out["exempt"] = load_exempt(conn)
    out["providers"] = list(providers.values())
    return out


MFA_METHODS = {"pap-admin+mfa": "local", "admin-ldap+mfa": "directory"}


def provider_at(kind, when, conn=None):
    """The provider that the second-factor rule for `kind` named at time `when`: the current
    rule, with every later change (audit action integration.policy, detail {kind: {provider_id:
    {from, to}}}) undone, newest first. None when the rule named none."""
    pid = load_policy(conn)[kind]["provider_id"]
    for r in db.query("SELECT detail FROM ui.audit_log WHERE action = 'integration.policy' AND success AND at > %s"
                      " ORDER BY at DESC, id DESC", (when,), conn=conn):
        d = r["detail"] if isinstance(r["detail"], dict) else json.loads(r["detail"] or "{}")
        change = (d.get(kind) or {}).get("provider_id") if isinstance(d.get(kind), dict) else None
        if isinstance(change, dict) and "from" in change:
            pid = change["from"]
    return pid


def login_provider(authmethod, when, conn=None):
    """For an authentication log record of a login with a second factor: {id, label, type,
    kind} of the provider it went to (reconstructed from the rules at that time), or None for
    other methods or when it cannot be known."""
    kind = MFA_METHODS.get(authmethod or "")
    if kind is None or when is None:
        return None
    pid = provider_at(kind, when, conn)
    if not pid:
        return None
    p = get_provider(pid, conn)
    return {"id": pid, "kind": kind, "type": p["type"] if p else "",
            "label": (p["label"] or TYPE_LABELS.get(p["type"], pid)) if p else pid}


def coverage_text(c):
    """One account kind's coverage in words (c: one entry of coverage())."""
    if not c["enabled"]:
        return "not required"
    where = "all clients" if c["clients"] == "all" else "selected clients: " + (", ".join(c["clients"]) or "none")
    if not c["provider_on"]:
        return "required on %s, but %s is off: these logins are rejected" % (where, c["provider"] or "the provider")
    return "%s, on %s" % (c["provider"], where)


# ---------------------------------------------------------------- Duo on this server (SPEC section 29.2)
DUO_ID = "duo"
DUO_FILE_RE = r"duoauthproxy-(\d{1,4}\.\d{1,4}\.\d{1,4})-src\.tgz"
UPLOAD_MAX = 128 * 1024 * 1024


def ensure_duo(key, conn=None):
    """The Duo provider row, created (off, with new random shared secrets) when missing."""
    from .crypto import ALNUM, random_string
    p = get_provider(DUO_ID, conn)
    if p is not None:
        return p
    secrets = {"secret": random_string(32, ALNUM), "primary_secret": random_string(32, ALNUM)}
    db.execute("INSERT INTO ui.mfa_provider (id, type, label, enabled, settings, secrets_enc)"
               " VALUES (%s, 'duo', 'Duo Authentication Proxy on this server', false, %s::jsonb, %s)",
               (DUO_ID, json.dumps({"failmode": "secure", "factors": "auto"}),
                encrypt_secrets(key, DUO_ID, secrets)), conn=conn)
    return get_provider(DUO_ID, conn)


def duo_secrets(key, p):
    return decrypt_secrets(key, DUO_ID, p["secrets_enc"])


def duo_configured(key, p):
    """True when ikey, skey and API hostname are set (the provider can be turned on)."""
    s = p["settings"]
    return bool(s.get("ikey") and s.get("api_host") and duo_secrets(key, p).get("skey"))


def build_check(installed, entries, provider=DUO_ID):
    """How the signed catalog sees an installed build (the helper's `installed` record):
    {'verified': catalog-checked at install or listed since (same SHA-256, not withdrawn),
     'withdrawn': the catalog withdrew this build (same SHA-256 or same version)}."""
    installed = installed or {}
    version, digest = installed.get("version") or "", installed.get("sha256") or ""
    mine = [e for e in entries or [] if e.get("provider") == provider]
    listed = any(digest and e.get("sha256") == digest and not e.get("withdrawn") for e in mine)
    withdrawn = any(e.get("withdrawn") and ((digest and e.get("sha256") == digest)
                                            or (version and e.get("version") == version)) for e in mine)
    fips = any(digest and e.get("sha256") == digest and e.get("fips") and not e.get("withdrawn") for e in mine)
    return {"verified": bool(installed) and (installed.get("verified") == "catalog" or listed) and not withdrawn,
            "listed": listed, "withdrawn": withdrawn,
            # FIPS mode (SPEC section 29.4): installed in FIPS mode and FIPS-capable in the catalog
            "fips_capable": fips and installed.get("fips") is True}
