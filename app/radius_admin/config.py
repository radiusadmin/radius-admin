"""Configuration loading (INI, SPEC section 2).

The config file is /etc/radius-admin/radius-admin.conf unless the environment
variable RADIUS_ADMIN_CONFIG names another file. Only the [app] section is read
here; [helper] belongs to the root helper.
"""
import configparser
import os

DEFAULT_CONFIG_PATH = "/etc/radius-admin/radius-admin.conf"

DEFAULTS = {
    "require_fips": True,
    "db_dsn": "dbname=radius host=/var/run/postgresql user=radius_admin",
    "key_file": "/etc/radius-admin/keys/data.key",
    "helper_socket": "/run/radius-admin-helper.sock",
    "helper_timeout": 120,
    "staging_dir": "/var/lib/radius-admin/staging",
    "session_idle_minutes": 15,
    "session_absolute_hours": 8,
    "stepup_minutes": 5,
    "lockout_threshold": 5,
    "lockout_minutes": 15,
    "ip_failure_limit": 20,
    "ip_failure_window_minutes": 15,
    "password_min_length": 15,
    "password_history": 5,
    "pbkdf2_iterations": 600000,
    "log_syslog": True,
    # nginx talks to gunicorn over a unix socket, so the peer address is
    # meaningless; the client IP comes from X-Real-IP set by nginx.
    "trust_proxy_headers": True,
    "totp_issuer": "RADIUS Admin",
    # Shown in the page header and sign-in screen. Empty = the host name the browser used.
    "server_name": "",
    "db_pool_max": 8,
    # CoA / Disconnect (SPEC section 13): radclient from the FreeRADIUS build. Empty =
    # look in the usual places (and next to it, <prefix>/share/freeradius for dictionaries).
    "radclient": "",
    "radius_dict_dir": "",
}

_BOOL = {k for k, v in DEFAULTS.items() if isinstance(v, bool)}
_INT = {k for k, v in DEFAULTS.items() if isinstance(v, int) and not isinstance(v, bool)}


class ConfigError(Exception):
    pass


def _coerce(key, value):
    if key in _BOOL:
        if isinstance(value, bool):
            return value
        v = str(value).strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
        raise ConfigError(f"{key}: expected a boolean, got {value!r}")
    if key in _INT:
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ConfigError(f"{key}: expected an integer, got {value!r}") from None
    return value


def load_config(path=None, overrides=None):
    """Return a dict of settings: defaults < file [app] section < overrides."""
    cfg = dict(DEFAULTS)
    if path is None:
        path = os.environ.get("RADIUS_ADMIN_CONFIG", DEFAULT_CONFIG_PATH)
    if path and os.path.exists(path):
        cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
        with open(path, encoding="utf-8") as fh:
            cp.read_file(fh)
        if cp.has_section("app"):
            for key, value in cp.items("app"):
                cfg[key] = value
    elif path and overrides is None:
        raise ConfigError(f"configuration file not found: {path}")
    for key, value in (overrides or {}).items():
        cfg[key] = value
    for key in list(cfg):
        cfg[key] = _coerce(key, cfg[key])
    cfg["config_path"] = path
    if cfg["pbkdf2_iterations"] < 1000:
        raise ConfigError("pbkdf2_iterations must be >= 1000 (OpenSSL FIPS provider minimum)")
    if cfg["password_min_length"] < 15:
        raise ConfigError("password_min_length must be >= 15")
    if cfg["lockout_threshold"] < 1:
        raise ConfigError("lockout_threshold must be >= 1")
    return cfg
