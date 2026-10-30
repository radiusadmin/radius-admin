"""Domain services shared by views and the CLI: settings, rendering, pending state,
staging files, user/account operations."""
import os
import tempfile

from flask import current_app, g

from . import db
from .crypto import sha256_hex

SETTING_KEYS = ("admin_subnet", "admin_priv15", "custom_policy", "banner_text", "mab_default_vlan",
                "radsec_enabled", "radsec_listen", "radsec_port", "radsec_max_connections",
                "radsec_idle_timeout", "radsec_ocsp", "radsec_ocsp_url",
                "saml_enabled", "saml_idp_metadata", "saml_entity_id", "saml_group_attribute",
                "saml_name_attribute", "saml_local_login", "setup_skipped", "setup_finished",
                "session_idle_minutes", "session_absolute_hours", "stepup_minutes")
RADSEC_KEYS = ("enabled", "listen", "port", "max_connections", "idle_timeout", "ocsp", "ocsp_url")
SAML_KEYS = ("enabled", "idp_metadata", "entity_id", "group_attribute", "name_attribute", "local_login")
DEFAULT_BANNER = ("This system is for authorized use only. Activity on this system is "
                  "monitored and recorded.")


def unlang():
    # Imported lazily so the app still starts (and shows a clear error) if the
    # FR engineer's module is broken.
    from . import unlang as mod
    return mod


# ---------------------------------------------------------------- settings
def get_settings(conn=None):
    rows = db.query("SELECT key, value FROM ui.setting", conn=conn)
    raw = {r["key"]: r["value"] for r in rows}
    return {
        "admin_subnet": raw.get("admin_subnet", "192.0.2.0/24"),
        "admin_priv15": raw.get("admin_priv15", "false").lower() == "true",
        "custom_policy": raw.get("custom_policy", ""),
        "banner_text": raw.get("banner_text") or DEFAULT_BANNER,
        "mab_default_vlan": raw.get("mab_default_vlan", ""),
        # RadSec listener, as stored (strings); validated by unlang.validate_radsec_settings
        "radsec": {k: raw["radsec_" + k] for k in RADSEC_KEYS if "radsec_" + k in raw},
        # portal single sign-on (sso.settings normalizes)
        "saml": {k: raw["saml_" + k] for k in SAML_KEYS if "saml_" + k in raw},
        # first-run setup checklist (views/setup.py)
        "setup_skipped": [k for k in raw.get("setup_skipped", "").split(",") if k],
        "setup_finished": raw.get("setup_finished", "false") == "true",
        # console session limits as stored ('' = the config file's value; see session_limits())
        "session": {k: raw.get(k, "") for k in ("session_idle_minutes", "session_absolute_hours", "stepup_minutes")},
    }


def session_limits(settings=None):
    """Effective console session limits: Settings value if valid, else the config file's."""
    from .security import SESSION_LIMITS, cfg
    stored = (settings or get_settings())["session"]
    out = {}
    for k, (lo, hi, _unit) in SESSION_LIMITS.items():
        v = stored.get(k, "")
        out[k] = min(max(int(v), lo), hi) if v.isdigit() else cfg()[k]
    return out


def set_setting(key, value, conn=None):
    if key not in SETTING_KEYS:
        raise ValueError("unknown setting " + key)
    db.execute(
        "INSERT INTO ui.setting (key, value, updated_at) VALUES (%s, %s, now())"
        " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        (key, value), conn=conn)


# --------------------------------------------------------------- rendering
RULE_COLS = "id, priority, connection, ssid, ad_group, vlan, enabled, description"
CLIENT_COLS = ("id, name, ipaddr, secret, require_ma, limit_proxy_state, nas_type, enabled, description,"
               " key_status, transport, radsec_peer_name")


def load_rules(conn=None):
    return db.query("SELECT " + RULE_COLS + " FROM ui.access_rule ORDER BY priority, id", conn=conn)


def load_clients(conn=None):
    return db.query("SELECT " + CLIENT_COLS + " FROM ui.radius_client ORDER BY name", conn=conn)


def render_all(conn=None):
    """Return (policy_text, clients_text) rendered from the current DB state.

    SPEC section 10: access rules and settings are evaluated live by FreeRADIUS through
    SQL functions, so the policy file depends only on the custom policy body.
    """
    u = unlang()
    settings = get_settings(conn)
    clients = [dict(c) for c in load_clients(conn)]
    for c in clients:
        # SPEC section 11: a client without a usable plaintext key is never rendered
        # (the DB CHECK already forbids enabling it; this is belt and braces).
        if c.get("key_status", "ok") != "ok":
            c["enabled"] = False
        c.pop("key_status", None)
    return u.render_policy(settings["custom_policy"]), u.render_clients(clients, settings["radsec"])


LIVE_POLICY_MARKERS = ("radius_admin_vlan_hex(", "radius_admin_vlan_rule_hex(")
OPS_POLICY_MARKER = "radius_admin_mab_hex("


def _has_live(text):
    return any(m in text for m in LIVE_POLICY_MARKERS)


def policy_format_upgrade(applied_policy, new_policy):
    """True when the live policy file predates the current format: either rules were
    still rendered into unlang (before SPEC section 10), or it lacks the section 13
    functions (MAB expiry/approval queue, reject reasons, matched rule)."""
    if applied_policy is None or new_policy is None:
        return False
    if not _has_live(applied_policy) and _has_live(new_policy):
        return True
    return OPS_POLICY_MARKER not in applied_policy and OPS_POLICY_MARKER in new_policy


def last_applied(conn=None):
    return db.query_one(
        "SELECT id, at, actor, action, policy_sha256, clients_sha256, backup_id, message"
        " FROM ui.apply_log WHERE success AND action IN ('apply','rollback')"
        " ORDER BY id DESC LIMIT 1", conn=conn)


def pending_state(conn=None):
    """Compare render(current DB) with the last successful apply. Cached per request."""
    if conn is None and "pending_state" in g:
        return g.pending_state
    try:
        policy, clients = render_all(conn)
    except Exception as e:  # validation error in stored data or broken unlang module
        state = {"pending": True, "error": str(e), "policy": True, "clients": True}
    else:
        last = last_applied(conn)
        ph, ch = sha256_hex(policy), sha256_hex(clients)
        if last is None:
            state = {"pending": True, "never_applied": True, "policy": True, "clients": True,
                     "policy_sha256": ph, "clients_sha256": ch}
        else:
            state = {"pending": ph != last["policy_sha256"] or ch != last["clients_sha256"],
                     "policy": ph != last["policy_sha256"], "clients": ch != last["clients_sha256"],
                     "policy_sha256": ph, "clients_sha256": ch, "last": last, "format_upgrade": False}
            if state["policy"]:
                try:
                    state["format_upgrade"] = policy_format_upgrade(read_applied()["policy"], policy)
                except RuntimeError:  # no app context (CLI)
                    pass
    if conn is None:
        g.pending_state = state
    return state


# ------------------------------------------------------------ staging files
def _write_0600(path, text):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def staging_dir():
    return current_app.config["RA"]["staging_dir"]


def write_staging(policy, clients, base=None):
    base = base or staging_dir()
    os.makedirs(base, mode=0o700, exist_ok=True)
    _write_0600(os.path.join(base, "policy"), policy)
    _write_0600(os.path.join(base, "clients"), clients)


def read_staging(base=None):
    base = base or staging_dir()
    out = {}
    for name in ("policy", "clients"):
        try:
            with open(os.path.join(base, name), encoding="utf-8") as fh:
                out[name] = fh.read()
        except OSError:
            out[name] = None
    return out


def applied_dir(base=None):
    return os.path.join(base or staging_dir(), "applied")


def read_applied(base=None):
    """Copy of the last successfully applied files, kept by the app (see apply view)."""
    d = applied_dir(base)
    out = {}
    for name in ("policy", "clients"):
        try:
            with open(os.path.join(d, name), encoding="utf-8") as fh:
                out[name] = fh.read()
        except OSError:
            out[name] = None
    return out


def save_applied(policy, clients, base=None, backup_id=None):
    """Record what is now live. The helper's backup <backup_id> holds the files that
    were live BEFORE this apply, so the previous applied copy is archived under
    applied/history/<backup_id>/ for a later rollback to that backup."""
    d = applied_dir(base)
    os.makedirs(d, mode=0o700, exist_ok=True)
    prev = read_applied(base)
    if backup_id and prev["policy"] is not None and prev["clients"] is not None:
        h = os.path.join(d, "history", backup_id)
        os.makedirs(h, mode=0o700, exist_ok=True)
        _write_0600(os.path.join(h, "policy"), prev["policy"])
        _write_0600(os.path.join(h, "clients"), prev["clients"])
    _write_0600(os.path.join(d, "policy"), policy)
    _write_0600(os.path.join(d, "clients"), clients)


def restore_applied_from_history(backup_id, base=None, new_backup_id=None):
    """After a successful rollback: the archived copy becomes the applied copy.
    Returns (policy, clients) or None when no archived copy exists (then the
    applied copy is removed because it no longer reflects what is live)."""
    d = applied_dir(base)
    # The helper backs up the files it replaces during a rollback too; keep the
    # matching applied copy so that backup can itself be rolled back to later.
    prev = read_applied(base)
    if new_backup_id and prev["policy"] is not None and prev["clients"] is not None:
        nh = os.path.join(d, "history", new_backup_id)
        os.makedirs(nh, mode=0o700, exist_ok=True)
        _write_0600(os.path.join(nh, "policy"), prev["policy"])
        _write_0600(os.path.join(nh, "clients"), prev["clients"])
    h = os.path.join(d, "history", backup_id)
    try:
        with open(os.path.join(h, "policy"), encoding="utf-8") as fh:
            policy = fh.read()
        with open(os.path.join(h, "clients"), encoding="utf-8") as fh:
            clients = fh.read()
    except OSError:
        for name in ("policy", "clients"):
            try:
                os.unlink(os.path.join(d, name))
            except OSError:
                pass
        return None
    _write_0600(os.path.join(d, "policy"), policy)
    _write_0600(os.path.join(d, "clients"), clients)
    return policy, clients


# ----------------------------------------------------------- switch admins
SWITCH_GROUP = "net-admins"
PW_ATTRS = ("Password-With-Header", "Crypt-Password", "Cleartext-Password", "SSHA2-256-Password",
            "PBKDF2-Password", "SHA2-Password", "NT-Password", "MD5-Password", "SMD5-Password",
            "SHA-Password", "SSHA-Password")


def switch_admins(conn=None):
    """Users in group net-admins, with credential / disabled state."""
    rows = db.query(
        "SELECT g.username,"
        " bool_or(c.attribute = 'Password-With-Header' AND c.value LIKE '{X-PBKDF2}%%') AS pbkdf2,"
        " bool_or(c.attribute IN ('Crypt-Password','Cleartext-Password','MD5-Password','SHA-Password',"
        "  'SSHA-Password','SMD5-Password','NT-Password','SHA2-Password','SSHA2-256-Password')"
        "  OR (c.attribute = 'Password-With-Header' AND c.value NOT LIKE '{X-PBKDF2}%%')) AS legacy,"
        " bool_or(c.attribute = 'Auth-Type' AND c.value = 'Reject') AS disabled"
        " FROM radusergroup g LEFT JOIN radcheck c ON c.username = g.username"
        " WHERE g.groupname = %s GROUP BY g.username ORDER BY g.username",
        (SWITCH_GROUP,), conn=conn)
    return rows
