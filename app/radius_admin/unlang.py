"""Rendering of the generated FreeRADIUS policy and clients files, plus validators.

Owned by the FreeRADIUS engineer (SPEC sections 5 and 10). Pure functions, stdlib
only, deterministic output (no timestamps) so the result can be hashed to detect
pending changes.

Since SPEC section 10, access rules and settings are NOT rendered: the generated
policy asks PostgreSQL on every request (radius_admin_vlan, radius_admin_admin_source_ok,
radius_admin_priv15 from sql/40-live-policy.sql). The rule/setting validators below are
still what the web app uses before writing ui.access_rule / ui.setting.

Security model: every value that is interpolated into FreeRADIUS configuration is
validated against a strict whitelist first, so no accepted input can break out
of a quoted string, a regular expression or a configuration section. The only
free-form input is the admin-only custom policy, which is checked by
validate_custom_policy() and is additionally checked by the root helper and by
`radiusd -XC` before it is installed.
"""
import hashlib
import ipaddress
import re

from . import vendors

__all__ = [
    "PolicyInputError",
    "render_policy",
    "render_clients",
    "sha256_hex",
    "validate_ssid",
    "validate_ad_group",
    "validate_vlan",
    "validate_mac",
    "validate_client_name",
    "validate_ipaddr",
    "validate_secret",
    "validate_custom_policy",
    "validate_nas_type",
    "validate_admin_subnet",
    "validate_radsec_peer_name",
    "validate_radsec_settings",
    "RADSEC_DEFAULTS",
    "validate_mfa_provider",
    "render_mfa",
    "render_duo_config",
    "validate_duo_settings",
    "MFA_TYPES",
    "POLICY_PATH",
    "CLIENTS_PATH",
]

POLICY_PATH = "/etc/freeradius/policy.d/radius-admin"
CLIENTS_PATH = "/etc/freeradius/radius-admin-clients.conf"
# RadSec reuses the RADIUS server certificate and the site CA that EAP-TLS uses
# (mods-available/eap), so the web app never handles a private key.
CERT_DIR = "/etc/freeradius/certs/site"
RADSEC_CLIENTS_SECTION = "radius_admin_radsec"
# RFC 6614 section 2.3: the shared secret over TLS is the fixed string "radsec".
RADSEC_SECRET = "radsec"
TLS12_CIPHERS = ("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
                 "ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256")
RADSEC_DEFAULTS = {"enabled": False, "listen": "*", "port": 2083, "max_connections": 16,
                   "idle_timeout": 30, "ocsp": False, "ocsp_url": ""}

# Second-factor providers (SPEC section 29). A device admin login that needs a second
# factor is proxied to realm radius_admin_mfa_<id>. The Duo Authentication Proxy listens
# on 127.0.0.1:DUO_PROXY_PORT and sends the password check back to the virtual server
# MFA_PRIMARY_SERVER on 127.0.0.1:MFA_PRIMARY_PORT (client section MFA_CLIENTS_SECTION).
MFA_TYPES = ("duo", "radius-mfa")
MFA_REALM_PREFIX = "radius_admin_mfa_"
MFA_PRIMARY_SERVER = "radius-admin-mfa-primary"
MFA_CLIENTS_SECTION = "radius_admin_mfa"
MFA_PROXY_CLIENT = "radius-admin-duo-proxy"
MFA_PRIMARY_PORT = 18121
DUO_PROXY_PORT = 18120
MFA_TIMEOUT_DEFAULT = 60

CUSTOM_POLICY_MAX_BYTES = 64 * 1024


class PolicyInputError(ValueError):
    """Raised for any input that cannot be safely rendered. Message is human readable."""


def sha256_hex(text):
    """SHA-256 of the UTF-8 encoding of text, as lowercase hex (pending-change detection)."""
    if isinstance(text, bytes):
        data = text
    else:
        data = str(text).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- validators

_SSID_RE = re.compile(r"[A-Za-z0-9 _.\-]{1,32}")
_AD_GROUP_RE = re.compile(r"[A-Za-z0-9 _.()&\-]{1,64}")
_CLIENT_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,63}")
_NAS_TYPE_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
_VLAN_RE = re.compile(r"[0-9]{1,4}")
# 12 hex digits; a separator (-, : or .) is optional after every octet. Same
# grammar as the unlang regex in radius_admin_mab so UI and server agree.
_MAC_GRAMMAR = r"([0-9a-f]{2})[-:.]?([0-9a-f]{2})[-:.]?([0-9a-f]{2})[-:.]?([0-9a-f]{2})[-:.]?([0-9a-f]{2})[-:.]?([0-9a-f]{2})"
_MAC_RE = re.compile(_MAC_GRAMMAR, re.IGNORECASE)
_TRISTATE = ("yes", "no", "auto")


def _require_str(value, what):
    if not isinstance(value, str):
        raise PolicyInputError("%s must be text." % what)
    return value


def validate_ssid(ssid):
    """SSID: 1-32 chars of letters, digits, space, underscore, dot, hyphen. Returns it."""
    _require_str(ssid, "SSID")
    if not _SSID_RE.fullmatch(ssid):
        raise PolicyInputError(
            "SSID must be 1-32 characters: letters, digits, space, underscore, dot or hyphen.")
    return ssid


def validate_ad_group(group):
    """AD group name (cn): 1-64 chars of letters, digits, space, _ . ( ) & -. Returns it."""
    _require_str(group, "AD group")
    if not _AD_GROUP_RE.fullmatch(group):
        raise PolicyInputError(
            "AD group must be 1-64 characters: letters, digits, space and _ . ( ) & -")
    return group


def validate_vlan(vlan):
    """VLAN id 1-4094 given as int or decimal string. Returns int."""
    if isinstance(vlan, bool):
        raise PolicyInputError("VLAN must be a whole number from 1 to 4094.")
    if isinstance(vlan, int):
        v = vlan
    elif isinstance(vlan, str) and _VLAN_RE.fullmatch(vlan.strip()):
        v = int(vlan.strip(), 10)
    else:
        raise PolicyInputError("VLAN must be a whole number from 1 to 4094.")
    if not 1 <= v <= 4094:
        raise PolicyInputError("VLAN must be a whole number from 1 to 4094.")
    return v


def validate_mac(mac):
    """Accept aabbccddeeff, AA-BB-CC-DD-EE-FF, aa:bb:.., aabb.ccdd.eeff (any case).

    Returns the normalized form AA-BB-CC-DD-EE-FF used in mab_device.mac.
    """
    _require_str(mac, "MAC address")
    m = _MAC_RE.fullmatch(mac.strip())
    if not m:
        raise PolicyInputError(
            "MAC address must be 12 hex digits, e.g. AA-BB-CC-DD-EE-FF, aa:bb:cc:dd:ee:ff, "
            "aabb.ccdd.eeff or aabbccddeeff.")
    return "-".join(g.upper() for g in m.groups())


def validate_client_name(name):
    """RADIUS client name: 1-63 chars [A-Za-z0-9._-]. Returns it."""
    _require_str(name, "Client name")
    if not _CLIENT_NAME_RE.fullmatch(name):
        raise PolicyInputError(
            "Client name must be 1-63 characters: letters, digits, dot, underscore or hyphen.")
    return name


def validate_nas_type(nas_type):
    _require_str(nas_type, "NAS type")
    if not _NAS_TYPE_RE.fullmatch(nas_type):
        raise PolicyInputError("NAS type must be 1-32 characters: letters, digits, _ or -.")
    return nas_type


def validate_ipaddr(value):
    """IPv4/IPv6 address or network (CIDR). Returns the normalized text.

    Networks must not have host bits set and must not be /0 (that would accept
    RADIUS packets from anywhere with this secret).
    """
    _require_str(value, "IP address")
    v = value.strip()
    if not v or len(v) > 64 or "%" in v:
        raise PolicyInputError("Enter an IPv4/IPv6 address or network, e.g. 192.0.2.10 or 192.0.2.0/24.")
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=True)
            if net.prefixlen == 0:
                raise PolicyInputError("A /0 network is not allowed.")
            if net.prefixlen == net.max_prefixlen:
                return str(net.network_address)
            return str(net)
        return str(ipaddress.ip_address(v))
    except PolicyInputError:
        raise
    except ValueError:
        raise PolicyInputError(
            "Enter an IPv4/IPv6 address or network (no host bits set), e.g. 192.0.2.10 or 192.0.2.0/24.")


def validate_admin_subnet(value):
    """Admin subnet for device admin logins. Returns ipaddress network object."""
    _require_str(value, "Admin subnet")
    try:
        net = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError:
        raise PolicyInputError("Admin subnet must be a network in CIDR form, e.g. 192.0.2.0/24.")
    if net.prefixlen == 0:
        raise PolicyInputError("Admin subnet must not be /0.")
    return net


_PEER_NAME_RE = re.compile(r"[A-Za-z0-9*][A-Za-z0-9 ._*-]{0,252}")
_OCSP_URL_RE = re.compile(r"https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,200})?")


def validate_radsec_peer_name(value):
    """Expected certificate name of a RadSec client (its CN or first DNS SAN).

    Empty means "any certificate from the trusted CA". Letters, digits, space and
    . _ * - only (rendered inside a quoted configuration value). Returns it stripped.
    """
    _require_str(value, "Certificate name")
    v = value.strip()
    if v and not _PEER_NAME_RE.fullmatch(v):
        raise PolicyInputError("Certificate name must be up to 253 characters: letters, digits, space "
                               "and . _ * - (for example ap1.example.net).")
    return v


def _int_in(value, lo, hi, what):
    if isinstance(value, bool):
        raise PolicyInputError("%s must be a whole number from %d to %d." % (what, lo, hi))
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,6}", value.strip()):
        value = int(value.strip(), 10)
    if not isinstance(value, int) or not lo <= value <= hi:
        raise PolicyInputError("%s must be a whole number from %d to %d." % (what, lo, hi))
    return value


def validate_radsec_settings(s):
    """Server-wide RadSec listener settings -> normalized dict (see RADSEC_DEFAULTS)."""
    if not isinstance(s, dict):
        raise PolicyInputError("Invalid RadSec settings.")
    out = dict(RADSEC_DEFAULTS)
    out["enabled"] = _truthy(s.get("enabled", False))
    listen = _require_str(s.get("listen", "*") or "*", "Listen address").strip()
    if listen != "*":
        try:
            listen = str(ipaddress.ip_address(listen))
        except ValueError:
            raise PolicyInputError("Listen address must be * (all addresses) or one IPv4/IPv6 address.")
    out["listen"] = listen
    out["port"] = _int_in(s.get("port", 2083), 1, 65535, "Port")
    out["max_connections"] = _int_in(s.get("max_connections", 16), 1, 1024, "Maximum connections")
    out["idle_timeout"] = _int_in(s.get("idle_timeout", 30), 5, 3600, "Idle timeout")
    out["ocsp"] = _truthy(s.get("ocsp", False))
    url = _require_str(s.get("ocsp_url", "") or "", "OCSP URL").strip()
    if url and not _OCSP_URL_RE.fullmatch(url):
        raise PolicyInputError("OCSP URL must look like http://ocsp.example.net:8080/ocsp (letters, digits, "
                               ". - / only).")
    out["ocsp_url"] = url
    return out


def _check_secret_syntax(secret):
    """Rules that make a secret safe inside `secret = "..."` (render-time check).

    No double quote, backslash, whitespace or control characters (cannot break
    out of / alter the quoted string) and no "${" (FreeRADIUS expands ${...}
    references inside double-quoted configuration values).
    """
    if not isinstance(secret, str) or not secret:
        raise PolicyInputError("Shared secret must not be empty.")
    for ch in secret:
        o = ord(ch)
        if o < 0x21 or o > 0x7E:
            raise PolicyInputError("Shared secret must contain only printable ASCII without spaces.")
        if ch in '"\\':
            raise PolicyInputError('Shared secret must not contain " or \\.')
    if "${" in secret:
        raise PolicyInputError("Shared secret must not contain the sequence ${.")


def validate_secret(secret):
    """Policy for secrets entered in the UI: 16-128 printable ASCII, no " \\ whitespace or ${."""
    _require_str(secret, "Shared secret")
    if not 16 <= len(secret) <= 128:
        raise PolicyInputError("Shared secret must be 16-128 characters long.")
    _check_secret_syntax(secret)
    return secret


_CUSTOM_FORBIDDEN = [
    (re.compile(r"\$-?INCLUDE", re.IGNORECASE), "$INCLUDE / $-INCLUDE"),
    (re.compile(r"\$ENV", re.IGNORECASE), "$ENV"),
    (re.compile(r"\$TEMPLATE", re.IGNORECASE), "$TEMPLATE"),
    (re.compile(r"\$\{"), "${...} configuration references"),
    (re.compile(r"%\{\s*exec\s*:", re.IGNORECASE), "the exec xlat"),
    (re.compile(r"%\{\s*config\s*:", re.IGNORECASE), "the config xlat"),
    (re.compile(r"Exec-Program", re.IGNORECASE), "Exec-Program"),
    # Raw/numeric attribute names (Attr-502 == Exec-Program, Vendor-9-Attr-1,
    # Cisco-Attr-1, Attr-26.9.1 ...). FreeRADIUS 3.2 accepts these only with an
    # "Attr-<digit>" component (dict_unknown_from_str), so this covers every form.
    (re.compile(r"Attr-\d", re.IGNORECASE), "raw attribute numbers (Attr-N)"),
    (re.compile(r"\bVendor-[\w-]*-Attr-\d", re.IGNORECASE), "raw vendor attributes"),
    (re.compile(r"`"), "backticks"),
    (re.compile(r"\bperl\b", re.IGNORECASE), "perl"),
    (re.compile(r"\bpython[0-9]*\b", re.IGNORECASE), "python"),
]


def _brace_balance_ok(text):
    """Conservative check that the custom body cannot close its enclosing section.

    Two independent counts must both stay >= 0 and end at 0:
      1. a tokenizer-aware count that skips # comments, quoted strings ("", '', ``)
         and /regex/ literals following =~ or !~ (strings may not span lines);
      2. a raw count of every brace character in the text.
    Hiding a brace from one count changes the other, so text that really closes
    radius_admin_custom (or policy {}) early is refused. Valid but unusual input
    (e.g. a lone brace inside a string) is also refused; that is acceptable.
    """
    raw = 0
    for ch in text:
        if ch == "{":
            raw += 1
        elif ch == "}":
            raw -= 1
            if raw < 0:
                return False
    if raw != 0:
        return False

    depth = 0
    i, n = 0, len(text)
    prev = ""  # last significant (non-space) character outside strings/comments
    prev2 = ""
    while i < n:
        ch = text[i]
        if ch == "#":
            nl = text.find("\n", i)
            if nl < 0:
                break
            i = nl
            continue
        regex = ch == "/" and prev == "~" and prev2 in ("=", "!")
        if ch in ("'", '"', "`") or regex:
            q = ch
            i += 1
            while i < n and text[i] != q:
                if text[i] == "\n":
                    return False  # unterminated string / regex
                if text[i] == "\\":
                    i += 1
                i += 1
            if i >= n:
                return False
            i += 1
            prev2, prev = prev, q
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
        if not ch.isspace():
            prev2, prev = prev, ch
        i += 1
    return depth == 0


def validate_custom_policy(text):
    """Admin-supplied unlang body of radius_admin_custom. Returns it unchanged."""
    _require_str(text, "Custom policy")
    if len(text.encode("utf-8")) > CUSTOM_POLICY_MAX_BYTES:
        raise PolicyInputError("Custom policy must be at most 64 KiB.")
    for ch in text:
        if ch in "\t\n\r":
            continue
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise PolicyInputError("Custom policy must not contain control characters.")
    for rx, label in _CUSTOM_FORBIDDEN:
        if rx.search(text):
            raise PolicyInputError("Custom policy must not use %s." % label)
    if not _brace_balance_ok(text):
        raise PolicyInputError("Custom policy has unbalanced braces or an unterminated string.")
    return text


# --------------------------------------------------------------------------- rendering

_HEADER = (
    "#\n"
    "#  Generated by radius-admin. DO NOT EDIT.\n"
    "#  This file is overwritten every time changes are applied from the web UI.\n"
    "#\n"
)


def _truthy(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "yes", "1", "on"):
            return True
        if s in ("false", "no", "0", "off", ""):
            return False
    raise PolicyInputError("Invalid boolean setting value.")


def _append_group_hex(indent):
    """Unlang that appends ",<hex>" of &control:Tmp-String-9[0] to &control:Tmp-String-3
    unless the list already holds that name, then drops the item.

    rlm_ldap caches a group once per lookup it runs (the user object's memberOf and the
    membership_filter search), so every direct group arrives twice. Names compare
    byte-for-byte, as hex. The hex goes through &control:Tmp-String-2, cleared first: if
    the hex xlat fails (name longer than 1023 bytes) the item is empty, the list gets an
    empty entry and the list check that follows turns it into "x" (no match), as before.
    """
    t = "\t" * indent
    return (
        t + "update control {\n"
        + t + "\t&Tmp-String-2 !* ANY\n"
        + t + "}\n"
        + t + "update control {\n"
        + t + '\t&Tmp-String-2 := "%{hex:control:Tmp-String-9[0]}"\n'
        + t + "}\n"
        + t + 'if ("%{control:Tmp-String-3}," !~ /,%{control:Tmp-String-2},/) {\n'
        + t + "\tupdate control {\n"
        + t + '\t\t&Tmp-String-3 := "%{control:Tmp-String-3},%{control:Tmp-String-2}"\n'
        + t + "\t}\n"
        + t + "}\n"
        + t + "update control {\n"
        + t + "\t&Tmp-String-9[0] !* ANY\n"
        + t + "\t&Tmp-String-2 !* ANY\n"
        + t + "}\n"
    )


def _directory_groups_hex(indent):
    """Unlang: the directory groups in &control:Tmp-String-9 (copied there from
    &control:ldap_user-LDAP-Group) as the hex list radius_admin_vlan_rule_hex() and
    radius_admin_admin_group_hex() take, in &control:Tmp-String-3 (attribute copy + %{hex:...}
    per item, like EAP-TLS, each name once); "x" (no match) when a group name is too long for
    the hex xlat."""
    t = "\t" * indent
    return (
        t + "update control {\n"
        + t + '\t&Tmp-String-3 := ""\n'
        + t + "\t&Tmp-String-7 !* ANY\n"
        + t + "}\n"
        + t + "update control {\n"
        + t + "\t&Tmp-String-7 += &control:Tmp-String-9[*]\n"
        + t + "}\n"
        + t + "foreach &control:Tmp-String-7 {\n"
        + _append_group_hex(indent + 1)
        + t + "}\n"
        + t + "if (\"%{control:Tmp-String-3}\" !~ /^(,[0-9a-f]+)*$/) {\n"
        + t + "\tupdate control {\n"
        + t + '\t\t&Tmp-String-3 := "x"\n'
        + t + "\t}\n"
        + t + "}\n"
    )


# The directory groups that the inner site copied to &control:Tmp-String-9 (two tabs of indent).
_DIRECTORY_GROUPS_HEX = _directory_groups_hex(2)

# A device admin login: plain PAP/CHAP from a device's management plane (no EAP, no port
# type Ethernet, no SSID). radius_admin_admin_authorize and radius_admin_postauth use the same
# test.
_ADMIN_REQUEST = "!&EAP-Message && (!&NAS-Port-Type || &NAS-Port-Type != Ethernet) && !&Called-Station-Id"


def _admin_source_check(indent):
    """Unlang: &control:Tmp-String-8 := "t" when the packet source address is inside the
    management subnet (radius_admin_admin_source_ok_hex), else "f". The address goes to SQL
    as hex: IPv4 = the 4 raw octets (8 digits); IPv6 = hex of its printed text form."""
    t = "\t" * indent
    return (
        t + "if (&Packet-Src-IP-Address) {\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Tmp-IP-Address-0 := \"%{Packet-Src-IP-Address}\"\n"
        + t + "\t}\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Tmp-String-4 := \"%{hex:control:Tmp-IP-Address-0}\"\n"
        + t + "\t}\n"
        + t + "}\n"
        + t + "elsif (&Packet-Src-IPv6-Address) {\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Tmp-String-5 := \"%{Packet-Src-IPv6-Address}\"\n"
        + t + "\t}\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Tmp-String-4 := \"%{hex:control:Tmp-String-5}\"\n"
        + t + "\t}\n"
        + t + "}\n"
        + t + "update control {\n"
        + t + '\t&Tmp-String-8 := "f"\n'
        + t + "}\n"
        + t + "if (&control:Tmp-String-4 && &control:Tmp-String-4 =~ /^[0-9a-f]{8}$|^([0-9a-f]{2}){2,64}$/) {\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Tmp-String-8 := \"%{sql:SELECT radius_admin_admin_source_ok_hex('%{control:Tmp-String-4}')}\"\n"
        + t + "\t}\n"
        + t + "}\n"
    )


_OUTSIDE_SUBNET = "radius-admin: device admin login from an address outside the management subnet"


def _reject_with(reason, indent):
    t = "\t" * indent
    return (t + "update request {\n"
            + t + "\t&Module-Failure-Message := \"" + reason + "\"\n"
            + t + "}\n"
            + t + "reject\n")


def _outside_subnet_reject(indent):
    """Reject unless _admin_source_check found the source inside the management subnet."""
    t = "\t" * indent
    return (t + "if (!&control:Tmp-String-8 || &control:Tmp-String-8 != \"t\") {\n"
            + _reject_with(_OUTSIDE_SUBNET, indent + 1)
            + t + "}\n")


def _ldap_user_lookup(indent, auth_type):
    """Find a device admin in the directory (ldap_user, which caches the group names) and
    copy the groups to &control:Tmp-String-9. With auth_type, the password is then checked
    with an LDAP bind as that person (Auth-Type ldap_user)."""
    t = "\t" * indent
    return (t + "ldap_user\n"
            + t + "if (notfound) {\n"
            + _reject_with("radius-admin: no such device admin (not a local account, not found in the directory)",
                           indent + 1)
            + t + "}\n"
            + t + "elsif (!ok && !updated) {\n"
            + _reject_with("radius-admin: the directory could not be searched for this user", indent + 1)
            + t + "}\n"
            + t + "update control {\n"
            + (t + "\t&Auth-Type := ldap_user\n" if auth_type else "")
            + t + "\t&Tmp-String-9 !* ANY\n"
            + t + "}\n"
            + t + "update control {\n"
            + t + "\t&Tmp-String-9 += &control:ldap_user-LDAP-Group[*]\n"
            + t + "}\n")


# Class that radius-admin-mfa-primary returns through the Duo proxy (SPEC section 29).
_MFA_CLASS_PREFIX = "radius-admin:"


def _mfa_class_hex(method):
    """Class is an octets attribute: %{proxy-reply:Class} prints it as 0x<hex>. Comparing that
    text never fails to evaluate, unlike a comparison of a Class that is not there."""
    return "0x" + (_MFA_CLASS_PREFIX + method).encode("ascii").hex()
_MFA_RESULT_RX = "/^(duo|radius-mfa):([a-z][a-z0-9-]{0,31})$/"
_MFA_UNAVAILABLE = "radius-admin: a second factor is required for this login, but its provider is turned off"
_MFA_UNDECIDED = "radius-admin: could not determine whether this login needs a second factor"
_MFA_LOCAL_REMOTE = ("radius-admin: a remote second-factor server checks directory accounts only,"
                     " and this is a local account")
_MFA_NOT_PROXIED = ("radius-admin: a second factor is required, but the login did not reach its provider"
                    " (the provider's configuration is not applied)")
_MFA_BAD_CLASS = "radius-admin: the Duo proxy's answer did not carry the password check of radius-admin-mfa-primary"
_MFA_REFUSED_DUO = ("radius-admin: refused in the second-factor chain (the password was wrong, the account is not"
                    " a device admin, or the second factor was denied)")
_MFA_REFUSED_REMOTE = ("radius-admin: the second-factor server refused the login (the password was wrong or the"
                       " second factor was denied)")
_MFA_NO_ANSWER = "radius-admin: the second-factor provider did not answer"


def _mfa_decision(indent):
    """Unlang for radius_admin_admin_authorize, after &control:Tmp-String-0 holds the
    radius_admin_admin_directory_hex result: ask radius_admin_mfa_hex whether the login needs
    a second factor (user name and client shortname as hex, the account kind as a literal).
    A provider -> Proxy-To-Realm radius_admin_mfa_<id>, marker &control:Tmp-Integer-0 (1 Duo,
    2 remote server), method <pap-admin|admin-ldap>+mfa, management subnet checked, directory
    groups looked up for a remote server, and `return` so that no later module chooses an
    Auth-Type. 'off' and 'exempt' continue; anything else (provider off, database error,
    malformed answer) rejects."""
    t = "\t" * indent
    return (
        t + "# Second factor (SPEC section 29), decided live on every login\n"
        + t + "update control {\n"
        + t + "\t&Tmp-String-5 := \"%{client:shortname}\"\n"
        + t + "}\n"
        + t + "if (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Tmp-String-7 := \"%{sql:SELECT radius_admin_mfa_hex('%{hex:User-Name}', '%{hex:control:Tmp-String-5}', 'directory')}\"\n"
        + t + "\t}\n"
        + t + "}\n"
        + t + "else {\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Tmp-String-7 := \"%{sql:SELECT radius_admin_mfa_hex('%{hex:User-Name}', '%{hex:control:Tmp-String-5}', 'local')}\"\n"
        + t + "\t}\n"
        + t + "}\n"
        + t + "if (&control:Tmp-String-7 && &control:Tmp-String-7 =~ " + _MFA_RESULT_RX + ") {\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Proxy-To-Realm := \"" + MFA_REALM_PREFIX + "%{2}\"\n"
        + t + "\t}\n"
        + t + "\tif (&control:Tmp-String-7 =~ /^duo:/) {\n"
        + t + "\t\tupdate control {\n"
        + t + "\t\t\t&Tmp-Integer-0 := 1\n"
        + t + "\t\t}\n"
        + t + "\t}\n"
        + t + "\telse {\n"
        + t + "\t\tupdate control {\n"
        + t + "\t\t\t&Tmp-Integer-0 := 2\n"
        + t + "\t\t}\n"
        + t + "\t}\n"
        + t + "\tif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        + t + "\t\tupdate control {\n"
        + t + '\t\t\t&Tmp-String-1 := "admin-ldap+mfa"\n'
        + t + "\t\t}\n"
        + t + "\t}\n"
        + t + "\telse {\n"
        + t + "\t\tupdate control {\n"
        + t + '\t\t\t&Tmp-String-1 := "pap-admin+mfa"\n'
        + t + "\t\t}\n"
        + t + "\t}\n"
        + _admin_source_check(indent + 1)
        + _outside_subnet_reject(indent + 1)
        + t + "\tif (&control:Tmp-Integer-0 == 2) {\n"
        + t + "\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        + _ldap_user_lookup(indent + 3, auth_type=False)
        + t + "\t\t}\n"
        + t + "\t\telse {\n"
        + _reject_with(_MFA_LOCAL_REMOTE, indent + 3)
        + t + "\t\t}\n"
        + t + "\t}\n"
        + t + "\tupdate control {\n"
        + t + "\t\t&Tmp-String-0 !* ANY\n"
        + t + "\t\t&Tmp-String-7 !* ANY\n"
        + t + "\t}\n"
        + t + "\t# the provider checks the password: no later module may choose an Auth-Type\n"
        + t + "\treturn\n"
        + t + "}\n"
        + t + "elsif (&control:Tmp-String-7 && &control:Tmp-String-7 == \"unavailable\") {\n"
        + _reject_with(_MFA_UNAVAILABLE, indent + 1)
        + t + "}\n"
        + t + "elsif (\"%{control:Tmp-String-7}\" != \"off\" && \"%{control:Tmp-String-7}\" != \"exempt\") {\n"
        + _reject_with(_MFA_UNDECIDED, indent + 1)
        + t + "}\n"
        + t + "update control {\n"
        + t + "\t&Tmp-String-5 !* ANY\n"
        + t + "\t&Tmp-String-7 !* ANY\n"
        + t + "}\n"
    )


def _reply_lines(profile, list_name, indent):
    """The vendor profile's reply attributes for one purpose (SPEC section 26), as
    unlang update-section lines. Values were validated by vendors.validate()."""
    pad = "\t" * indent
    return "".join("%s&%s %s %s\n" % (pad, e["attr"], e["op"], vendors.format_value(e["value"], _REPLY_REFS))
                   for e in profile["reply"][list_name])


# What each placeholder of a reply value becomes in the policy.
_REPLY_REFS = {"{vlan}": "&control:Tmp-String-0", "{role}": "&control:Tmp-String-4"}
# The client's vendor profile when it is not the default (render_clients writes it).
_CLIENT_PROFILE = "%{client:radius_admin_profile}"


def _reply_block(default, others, list_name, indent):
    """`update reply` with one purpose's attributes. With other profiles in use whose
    attributes differ from the default's, one branch per distinct attribute list, chosen
    by the client's radius_admin_profile; the default profile's list in the else branch.
    Profile ids are validated ([a-z0-9-]), so they are safe inside the quoted literal."""
    def update(p, ind):
        pad = "\t" * ind
        if not p["reply"][list_name]:           # optional list left empty: nothing to send
            return pad + "noop\n"
        return pad + "update reply {\n" + _reply_lines(p, list_name, ind + 1) + pad + "}\n"
    groups = []                 # [attribute list, [profile ids], a profile with that list]
    for p in others:
        lst = p["reply"][list_name]
        if lst == default["reply"][list_name]:
            continue
        for grp in groups:
            if grp[0] == lst:
                grp[1].append(p["id"])
                break
        else:
            groups.append([lst, [p["id"]], p])
    if not groups:
        return update(default, indent)
    pad = "\t" * indent
    out = []
    for i, (_, ids, p) in enumerate(groups):
        cond = " || ".join('"' + _CLIENT_PROFILE + '" == "' + pid + '"' for pid in ids)
        out.append(pad + ("if" if i == 0 else "elsif") + " (" + cond + ") {\n" + update(p, indent + 1) + pad + "}\n")
    out.append(pad + "else {\n" + update(default, indent + 1) + pad + "}\n")
    return "".join(out)


def _profile_is(ids):
    return " || ".join('"' + _CLIENT_PROFILE + '" == "' + pid + '"' for pid in ids)


def _mab_port_condition(default, others):
    """Which NAS-Port-Type values start MAB, per client profile (vendors.MAB_PORT_TYPES).
    Every profile in use Ethernet-only (Catalyst 1300): the original condition."""
    profiles = [default] + list(others)
    parts = []
    for t in vendors.MAB_PORT_TYPES:
        yes = [p["id"] for p in others if t in p["mab"]["port_types"]]
        if t in default["mab"]["port_types"]:
            no = [p["id"] for p in others if t not in p["mab"]["port_types"]]
            test = "!(" + _profile_is(no) + ")" if no else None
        elif yes:
            test = "(" + _profile_is(yes) + ")"
        else:
            continue
        parts.append("&NAS-Port-Type == " + t + ("" if test is None else " && " + test))
    if parts == ["&NAS-Port-Type == Ethernet"] or not any(t != "Ethernet" for p in profiles for t in p["mab"]["port_types"]):
        return "&NAS-Port-Type && &NAS-Port-Type == Ethernet"
    return "&NAS-Port-Type && (" + " || ".join("(" + x + ")" for x in parts) + ")"


def _role_block(default, others, indent):
    """After the VLAN of an 802.1X accept: the matched access rule's role (ui.access_rule.role,
    looked up by rule id through radius_admin_rule_role), sent with the profile's role
    attributes. Nothing when no profile in use has any."""
    if not default["reply"]["role"] and not any(p["reply"]["role"] for p in others):
        return ""
    pad = "\t" * indent
    return (pad + "# the matched rule's role (SPEC section 26); the rule id is digits only\n"
            + pad + "if (&control:Tmp-String-6 && &control:Tmp-String-6 =~ /^[0-9]{1,10}$/) {\n"
            + pad + "\tupdate control {\n"
            + pad + "\t\t&Tmp-String-4 := \"%{sql:SELECT radius_admin_rule_role(%{control:Tmp-String-6})}\"\n"
            + pad + "\t}\n"
            + pad + "\tif (&control:Tmp-String-4 && &control:Tmp-String-4 =~ /^[A-Za-z0-9._-]{1,64}$/) {\n"
            + _reply_block(default, others, "role", indent + 2)
            + pad + "\t}\n"
            + pad + "}\n")


def render_policy(custom="", profile=None, others=()):
    """Full text of /etc/freeradius/policy.d/radius-admin (deterministic).

    Access rules and the admin settings are NOT rendered: FreeRADIUS evaluates them
    live through the SQL functions of sql/40-live-policy.sql on every request
    (SPEC section 10). Only the admin-supplied custom policy body and the vendor
    profiles' reply attributes (SPEC section 26) vary: `profile` is the default one,
    `others` those that some client names in the clients file.
    """
    if custom is None:
        custom = ""
    validate_custom_policy(custom)
    profile = vendors.validate(profile) if profile is not None else vendors.default()
    seen = {profile["id"]}
    checked = []
    for p in others or ():
        p = vendors.validate(p)
        if p["id"] not in seen:
            seen.add(p["id"])
            checked.append(p)
    others = sorted(checked, key=lambda p: p["id"])
    mab_ports = _mab_port_condition(profile, others)

    mac_rx = "/^" + _MAC_GRAMMAR + "$/i"
    mac_norm = '"%{toupper:%{1}-%{2}-%{3}-%{4}-%{5}-%{6}}"'

    o = [_HEADER, "\n"]

    # ---------------------------------------------------------------- MAB (authorize)
    o.append(
        "#\n"
        "#  MAC Authentication Bypass. Called in authorize after preprocess.\n"
        "#  Accepts only MACs registered (and enabled) in mab_device. Not EAP.\n"
        "#\n"
        "radius_admin_mab {\n"
        "\tif (!&EAP-Message && " + mab_ports + " && &User-Name && &User-Name =~ " + mac_rx + ") {\n"
        "\t\tupdate control {\n"
        '\t\t\t&Tmp-String-1 := "mab"\n'
        "\t\t\t&Tmp-String-2 := " + mac_norm + "\n"
        "\t\t}\n"
        "\t\tif (&Calling-Station-Id) {\n"
        "\t\t\tif (&Calling-Station-Id =~ " + mac_rx + ") {\n"
        "\t\t\t\tif (" + mac_norm + ' != "%{control:Tmp-String-2}") {\n'
        "\t\t\t\t\tupdate request {\n"
        "\t\t\t\t\t\t&Module-Failure-Message := \"radius-admin: MAB User-Name does not match Calling-Station-Id\"\n"
        "\t\t\t\t\t}\n"
        "\t\t\t\t\treject\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t\telse {\n"
        "\t\t\t\tupdate request {\n"
        "\t\t\t\t\t&Module-Failure-Message := \"radius-admin: MAB Calling-Station-Id is not a MAC address\"\n"
        "\t\t\t\t}\n"
        "\t\t\t\treject\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\t# Live decision (sql/70-operations.sql): '<vlan>', 'disabled', 'expired',\n"
        "\t\t# 'certificate' (the MAC has authenticated with 802.1X; never queued) or\n"
        "\t\t# 'unknown' (the MAC is then queued for one-click approval in the UI).\n"
        "\t\t# The MAC argument is built from regex captures of hex digits; NAS address\n"
        "\t\t# and port are passed hex-encoded only.\n"
        "\t\tupdate control {\n"
        "\t\t\t&Tmp-String-5 := \"%{hex:NAS-Port-Id}\"\n"
        "\t\t}\n"
        "\t\tif (\"%{control:Tmp-String-5}\" !~ /^([0-9a-f]{2})*$/) {\n"
        "\t\t\tupdate control {\n"
        '\t\t\t\t&Tmp-String-5 := ""\n'
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tupdate control {\n"
        "\t\t\t&Tmp-String-0 := \"%{sql:SELECT radius_admin_mab_hex('%{control:Tmp-String-2}', '%{hex:NAS-IP-Address}', '%{control:Tmp-String-5}')}\"\n"
        "\t\t}\n"
        "\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 =~ /^[0-9]{1,4}$/) {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Auth-Type := Accept\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"expired\") {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: MAB registration expired\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"certificate\") {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: MAB not used: this device authenticates with 802.1X\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"disabled\") {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: MAB device is disabled\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: MAB device not registered (added to the approval queue)\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tnoop\n"
        "\t}\n"
        "}\n\n"
    )

    # ---------------------------------------------------------------- RadSec
    # The TLS connection's certificate is only visible through %{listen:TLS-...}
    # (FreeRADIUS does not copy it into requests), so it can never be mistaken for
    # an EAP-TLS client certificate carried inside that connection.
    o.append(
        "#\n"
        "#  RadSec (RADIUS over TLS, RFC 6614). Called first in authorize and preacct.\n"
        "#  A RadSec client with an expected certificate name only gets an answer when\n"
        "#  the certificate of its TLS connection carries that name (CN or first DNS SAN).\n"
        "#\n"
        "radius_admin_radsec {\n"
        "\tif (\"%{client:proto}\" == \"tls\" && \"%{client:radsec_peer_name}\" != \"\") {\n"
        "\t\tif (\"%{tolower:%{listen:TLS-Client-Cert-Common-Name}}\" != \"%{client:radsec_peer_name}\" && \\\n"
        "\t\t    \"%{tolower:%{listen:TLS-Client-Cert-Subject-Alt-Name-Dns}}\" != \"%{client:radsec_peer_name}\") {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: RadSec certificate does not match the name configured for this client\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tnoop\n"
        "\t}\n"
        "}\n\n"
    )

    # ---------------------------------------------------------------- device admins, directory
    o.append(
        "#\n"
        "#  Device admin logins with a directory account (SPEC section 28). Called in\n"
        "#  authorize after sql and before pap. A name that is not a local account, while\n"
        "#  directory accounts are on (radius_admin_admin_directory_hex), is looked up in the\n"
        "#  directory (ldap_user, which also caches its group names) and its password is\n"
        "#  checked with an LDAP bind as that person. The management subnet is checked first,\n"
        "#  so a device outside it never makes the server bind. radius_admin_postauth then\n"
        "#  requires one of the configured directory groups.\n"
        "#\n"
        "#  A login that needs a second factor (SPEC section 29, radius_admin_mfa_hex) is\n"
        "#  proxied to the provider's realm instead: for Duo the provider sends the password\n"
        "#  check back to radius-admin-mfa-primary (radius_admin_mfa_primary_*); a remote\n"
        "#  RADIUS server checks the password and the second factor itself, after the\n"
        "#  directory lookup here. &control:Tmp-Integer-0 = 1 (Duo) or 2 (remote) marks it.\n"
        "#\n"
        "radius_admin_admin_authorize {\n"
        "\tif (" + _ADMIN_REQUEST + " && &User-Name && &User-Password && !&control:Auth-Type) {\n"
        "\t\tupdate control {\n"
        "\t\t\t&Tmp-String-0 := \"%{sql:SELECT radius_admin_admin_directory_hex('%{hex:User-Name}')}\"\n"
        "\t\t}\n"
        + _mfa_decision(2) +
        "\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        "\t\t\tupdate control {\n"
        '\t\t\t\t&Tmp-String-1 := "admin-ldap"\n'
        "\t\t\t\t&Tmp-String-0 !* ANY\n"
        "\t\t\t}\n"
        + _admin_source_check(3)
        + _outside_subnet_reject(3)
        + _ldap_user_lookup(3, auth_type=True) +
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-0 !* ANY\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tnoop\n"
        "\t}\n"
        "}\n\n"
    )

    # ---------------------------------------------------------------- second factor, step 1
    o.append(
        "#\n"
        "#  Second factor, password check (SPEC section 29). The Duo Authentication Proxy\n"
        "#  sends the device admin login it received from the default server back to the\n"
        "#  virtual server radius-admin-mfa-primary (127.0.0.1 only), which checks the\n"
        "#  password and the device admin group exactly like radius_admin_admin_authorize /\n"
        "#  radius_admin_postauth, and answers with Class \"radius-admin:<method>\". The\n"
        "#  default server checked the management subnet before it proxied the login.\n"
        "#\n"
        "radius_admin_mfa_primary_authorize {\n"
        "\tif (&EAP-Message || !&User-Name || !&User-Password) {\n"
        "\t\tupdate request {\n"
        "\t\t\t&Module-Failure-Message := \"radius-admin: only device admin logins with a password reach the second-factor chain\"\n"
        "\t\t}\n"
        "\t\treject\n"
        "\t}\n"
        "\tupdate control {\n"
        "\t\t&Tmp-String-0 := \"%{sql:SELECT radius_admin_admin_directory_hex('%{hex:User-Name}')}\"\n"
        "\t}\n"
        "\tif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        "\t\tupdate control {\n"
        '\t\t\t&Tmp-String-1 := "admin-ldap"\n'
        "\t\t\t&Tmp-String-0 !* ANY\n"
        "\t\t}\n"
        + _ldap_user_lookup(2, auth_type=True) +
        "\t}\n"
        "\telse {\n"
        "\t\tupdate control {\n"
        '\t\t\t&Tmp-String-1 := "pap-admin"\n'
        "\t\t\t&Tmp-String-0 !* ANY\n"
        "\t\t}\n"
        "\t}\n"
        "}\n\n"
        "radius_admin_mfa_primary_postauth {\n"
        "\tif (&control:Tmp-String-1 && &control:Tmp-String-1 == \"admin-ldap\") {\n"
        + _directory_groups_hex(2) +
        "\t\tif (\"%{control:Tmp-String-3}\" =~ /^(,[0-9a-f]+)*$/ && \"%{sql:SELECT radius_admin_admin_group_hex('%{control:Tmp-String-3}')}\" == \"t\") {\n"
        "\t\t\tupdate reply {\n"
        '\t\t\t\t&Class := "' + _MFA_CLASS_PREFIX + 'admin-ldap"\n'
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: the directory account is not in a device admin group\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t}\n"
        "\telsif (&control:Tmp-String-1 && &control:Tmp-String-1 == \"pap-admin\" && SQL-Group == \"net-admins\") {\n"
        "\t\tupdate reply {\n"
        '\t\t\t&Class := "' + _MFA_CLASS_PREFIX + 'pap-admin"\n'
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tupdate request {\n"
        "\t\t\t&Module-Failure-Message := \"radius-admin: user is not a device admin (not in group net-admins)\"\n"
        "\t\t}\n"
        "\t\treject\n"
        "\t}\n"
        "}\n\n"
    )

    # ---------------------------------------------------------------- EAP-TTLS inner tunnel
    # Local 802.1X accounts only (ui.dot1x_user): the inner tunnel never reads radcheck,
    # so a device admin's password cannot open a network port.
    pbkdf2_rx = "/^\\{X-PBKDF2\\}HMACSHA2\\+256:[A-Za-z0-9+\\/=]+:[A-Za-z0-9+\\/=]+:[A-Za-z0-9+\\/=]+$/"
    o.append(
        "#\n"
        "#  802.1X with a username and password: EAP-TTLS with PAP inside the tunnel,\n"
        "#  local accounts. Called by sites-available/radius-admin-inner, the virtual\n"
        "#  server behind EAP-TTLS. The method and the inner User-Name are recorded on the\n"
        "#  outer request for the authentication log, also when the login fails.\n"
        "#\n"
        "radius_admin_inner_authorize {\n"
        "\tupdate outer.control {\n"
        '\t\t&Tmp-String-1 := "ttls-pap"\n'
        "\t\t&Stripped-User-Name := &User-Name\n"
        "\t}\n"
        "\tif (&EAP-Message || !&User-Name || !&User-Password) {\n"
        "\t\tupdate outer.request {\n"
        "\t\t\t&Module-Failure-Message := \"radius-admin: only PAP is accepted inside EAP-TTLS\"\n"
        "\t\t}\n"
        "\t\treject\n"
        "\t}\n"
        "\t# The stored hash, or why there is none (sql/95-dot1x-passwords.sql)\n"
        "\tupdate control {\n"
        "\t\t&Tmp-String-0 := \"%{sql:SELECT radius_admin_dot1x_user_hex('%{hex:User-Name}')}\"\n"
        "\t}\n"
        "\tif (&control:Tmp-String-0 && &control:Tmp-String-0 =~ " + pbkdf2_rx + ") {\n"
        "\t\tupdate control {\n"
        "\t\t\t&Password-With-Header := &control:Tmp-String-0\n"
        "\t\t}\n"
        "\t}\n"
        "\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        "\t\t# Not a local user: sites-available/radius-admin-inner asks the directory\n"
        "\t\t# (ldap_user, an LDAP bind as the user).\n"
        "\t\tupdate outer.control {\n"
        '\t\t\t&Tmp-String-1 := "ttls-ldap"\n'
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"off\") {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: username and password sign-in (EAP-TTLS) is turned off\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"disabled\") {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: 802.1X user is disabled\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"expired\") {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: 802.1X user has expired\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: no such 802.1X user\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\treject\n"
        "\t}\n"
        "}\n\n"
        "#\n"
        "#  Inner tunnel, password accepted: mark the outer session so that\n"
        "#  radius_admin_postauth assigns the VLAN from the user's groups. For a\n"
        "#  directory user these are the directory groups the inner site copied to\n"
        "#  &control:Tmp-String-9, passed on hex-encoded (as for EAP-TLS computers).\n"
        "#\n"
        "radius_admin_inner_postauth {\n"
        "\tif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        + _DIRECTORY_GROUPS_HEX +
        "\t\tupdate outer.session-state {\n"
        '\t\t\t&Tmp-String-1 := "ttls-ldap"\n'
        "\t\t\t&Stripped-User-Name := &User-Name\n"
        "\t\t\t&Tmp-String-3 := &control:Tmp-String-3\n"
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tupdate outer.session-state {\n"
        '\t\t\t&Tmp-String-1 := "ttls-pap"\n'
        "\t\t\t&Stripped-User-Name := &User-Name\n"
        "\t\t}\n"
        "\t}\n"
        "}\n\n"
        "#\n"
        "#  Inner tunnel, rejected: a wrong password has no reason of its own yet. Method,\n"
        "#  user and reason are also kept in the outer session: PEAP sends the failure\n"
        "#  inside the tunnel and the outer Access-Reject (and its log row) follows one\n"
        "#  round later, where radius_admin_reject restores them.\n"
        "#\n"
        "radius_admin_inner_reject {\n"
        "\tif (!&outer.request:Module-Failure-Message) {\n"
        "\t\tif (&outer.control:Tmp-String-1 && (&outer.control:Tmp-String-1 == \"ttls-ldap\" || &outer.control:Tmp-String-1 == \"peap-ldap\")) {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: the directory refused the password (wrong password, or a disabled, locked or expired account)\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: wrong password for 802.1X user\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "\tupdate outer.session-state {\n"
        "\t\t&Tmp-String-4 := &outer.control:Tmp-String-1\n"
        "\t\t&Tmp-String-5 := &outer.control:Stripped-User-Name\n"
        "\t\t&Module-Failure-Message := &outer.request:Module-Failure-Message\n"
        "\t}\n"
        "}\n\n"
        "#\n"
        "#  Outer Access-Reject (sites-available/default, Post-Auth-Type REJECT, before the\n"
        "#  log): a reject that follows a refused inner tunnel in an earlier round (PEAP)\n"
        "#  gets that round's method, user and reason.\n"
        "#\n"
        "radius_admin_reject {\n"
        "\t# A device admin login that needed a second factor (SPEC section 29) and has no reason\n"
        "\t# yet: the provider refused it, did not answer (FreeRADIUS's \"lack of any response\"), or it was\n"
        "\t# never proxied (realm not applied: \"No Auth-Type found\"). %{proxy-reply:...} expands to \"\"\n"
        "\t# without a reply, where a comparison of the attribute would fail to evaluate.\n"
        "\tif (&control:Tmp-Integer-0 && (!&Module-Failure-Message || &Module-Failure-Message =~ /lack of any response from home server|No Auth-Type found/)) {\n"
        "\t\tif (\"%{proxy-reply:Packet-Type}\" == \"Access-Reject\") {\n"
        "\t\t\tif (&control:Tmp-Integer-0 == 1) {\n"
        "\t\t\t\tupdate request {\n"
        "\t\t\t\t\t&Module-Failure-Message := \"" + _MFA_REFUSED_DUO + "\"\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t\telse {\n"
        "\t\t\t\tupdate request {\n"
        "\t\t\t\t\t&Module-Failure-Message := \"" + _MFA_REFUSED_REMOTE + "\"\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&Module-Failure-Message && &Module-Failure-Message =~ /lack of any response from home server/) {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"" + _MFA_NO_ANSWER + "\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"" + _MFA_NOT_PROXIED + "\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "\t# A directory device admin whose LDAP bind was refused (radius_admin_admin_authorize):\n"
        "\t# rlm_ldap's own message (\"Bind credentials incorrect\") becomes the plain reason; any\n"
        "\t# other failure (directory unreachable, ...) keeps its text.\n"
        "\tif (&control:Tmp-String-1 && &control:Tmp-String-1 == \"admin-ldap\" && (!&Module-Failure-Message || &Module-Failure-Message =~ /(Bind credentials incorrect|Invalid credentials)/)) {\n"
        "\t\tupdate request {\n"
        "\t\t\t&Module-Failure-Message := \"radius-admin: the directory refused the password (wrong password, or a disabled, locked or expired account)\"\n"
        "\t\t}\n"
        "\t}\n"
        "\tif (!&control:Tmp-String-1 && &session-state:Tmp-String-4 && &session-state:Tmp-String-4 =~ /^(ttls-pap|ttls-ldap|peap|peap-ldap)$/) {\n"
        "\t\tupdate control {\n"
        "\t\t\t&Tmp-String-1 := &session-state:Tmp-String-4\n"
        "\t\t\t&Stripped-User-Name := &session-state:Tmp-String-5\n"
        "\t\t}\n"
        "\t\tif (&session-state:Module-Failure-Message) {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := &session-state:Module-Failure-Message\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tnoop\n"
        "\t}\n"
        "}\n\n"
    )

    # ---------------------------------------------------------------- PEAP inner tunnel
    # Local 802.1X users that allow PEAP (ui.dot1x_user.nt_hash); standard mode only.
    o.append(
        "#\n"
        "#  802.1X with a username and password over PEAP: EAP-MSCHAPv2 inside the tunnel,\n"
        "#  local users that allow PEAP. Called by sites-available/radius-admin-peap in every\n"
        "#  inner round (identity, challenge response, acknowledgement).\n"
        "#\n"
        "radius_admin_peap_authorize {\n"
        "\tupdate outer.control {\n"
        '\t\t&Tmp-String-1 := "peap"\n'
        "\t\t&Stripped-User-Name := &User-Name\n"
        "\t}\n"
        "\tif (!&EAP-Message || !&User-Name) {\n"
        "\t\tupdate outer.request {\n"
        "\t\t\t&Module-Failure-Message := \"radius-admin: only EAP-MSCHAPv2 is accepted inside PEAP\"\n"
        "\t\t}\n"
        "\t\treject\n"
        "\t}\n"
        "\t# The NT hash, or why there is none (sql/95-dot1x-passwords.sql)\n"
        "\tupdate control {\n"
        "\t\t&Tmp-String-0 := \"%{sql:SELECT radius_admin_dot1x_nt_hex('%{hex:User-Name}')}\"\n"
        "\t}\n"
        "\tif (&control:Tmp-String-0 && &control:Tmp-String-0 =~ /^0x[0-9a-f]{32}$/) {\n"
        "\t\t# checked here against the NT hash, never by the domain controller\n"
        "\t\tupdate control {\n"
        "\t\t\t&NT-Password := \"%{control:Tmp-String-0}\"\n"
        "\t\t\t&MS-CHAP-Use-NTLM-Auth := No\n"
        "\t\t}\n"
        "\t}\n"
        "\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        "\t\t# Not a local user: sites-available/radius-admin-peap finds the person in the\n"
        "\t\t# directory; rlm_mschap asks the domain controller (ntlm_auth).\n"
        "\t\tupdate outer.control {\n"
        '\t\t\t&Tmp-String-1 := "peap-ldap"\n'
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"off\") {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: username and password sign-in with PEAP is turned off\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"nopeap\") {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: PEAP is not allowed for this 802.1X user\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"disabled\") {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: 802.1X user is disabled\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"expired\") {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: 802.1X user has expired\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate outer.request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: no such 802.1X user\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\treject\n"
        "\t}\n"
        "}\n\n"
        "#\n"
        "#  PEAP inner tunnel, password accepted: mark the outer session (the outer\n"
        "#  Access-Accept follows one round later, after the PEAP result exchange).\n"
        "#\n"
        "radius_admin_peap_postauth {\n"
        "\tif (&control:Tmp-String-0 && &control:Tmp-String-0 == \"directory\") {\n"
        + _DIRECTORY_GROUPS_HEX +
        "\t\tupdate outer.session-state {\n"
        '\t\t\t&Tmp-String-1 := "peap-ldap"\n'
        "\t\t\t&Stripped-User-Name := &User-Name\n"
        "\t\t\t&Tmp-String-3 := &control:Tmp-String-3\n"
        "\t\t}\n"
        "\t}\n"
        "\telse {\n"
        "\t\tupdate outer.session-state {\n"
        '\t\t\t&Tmp-String-1 := "peap"\n'
        "\t\t\t&Stripped-User-Name := &User-Name\n"
        "\t\t}\n"
        "\t}\n"
        "}\n\n"
    )

    # ---------------------------------------------------------------- post-auth
    o.append(
        "#\n"
        "#  Site policy. Called at the start of post-auth.\n"
        "#\n"
        "radius_admin_postauth {\n"
        "\t# MAC Authentication Bypass (accepted in authorize by radius_admin_mab)\n"
        "\t# The request shape is re-checked so that a Tmp-String-1 added by another module\n"
        "\t# (users file, SQL radcheck, LDAP) can never select this branch.\n"
        "\tif (!&EAP-Message && " + mab_ports + " && &User-Name && &User-Name =~ " + mac_rx + " && \\\n"
        '\t    &control:Tmp-String-1 && &control:Tmp-String-1 == "mab" && &control:Tmp-String-0 && &control:Tmp-String-0 =~ /^[0-9]{1,4}$/) {\n'
        + _reply_block(profile, others, "vlan", 2) +
        "\t}\n"
        "\n"
        "\t# Device admin logins (switches, access points, firewalls: plain PAP, no port\n"
        "\t# type or SSID). Local accounts (radcheck + group net-admins) or, marked\n"
        "\t# admin-ldap by radius_admin_admin_authorize, directory accounts in a configured\n"
        "\t# group. Source subnet, groups and priv15 come live from ui.setting via SQL\n"
        "\t# functions; an empty result (e.g. database down) means reject.\n"
        "\t# SECURITY: request/directory data is passed to %{sql:...} ONLY as hex\n"
        "\t# (%{hex:...}, alphabet [0-9a-f]); FreeRADIUS un-escapes backslash sequences\n"
        "\t# in %{sql:...} arguments after SQL escaping, so raw strings could inject SQL.\n"
        "\t# A login that needed a second factor (&control:Tmp-Integer-0, SPEC section 29) is\n"
        "\t# accepted only on the provider's Access-Accept; for Duo the answer must carry the\n"
        "\t# Class of radius-admin-mfa-primary, which checked the password and the group. The\n"
        "\t# provider's own reply attributes are dropped; the profile's are added here.\n"
        "\telsif (" + _ADMIN_REQUEST + ") {\n"
        "\t\tif (!&control:Tmp-Integer-0 && (!&control:Tmp-String-1 || &control:Tmp-String-1 != \"admin-ldap\")) {\n"
        "\t\t\tupdate control {\n"
        '\t\t\t\t&Tmp-String-1 := "pap-admin"\n'
        "\t\t\t}\n"
        "\t\t}\n"
        + _admin_source_check(2) +
        "\t\tif (!&control:Tmp-String-8 || &control:Tmp-String-8 != \"t\") {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"" + _OUTSIDE_SUBNET + "\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-Integer-0) {\n"
        "\t\t\t# accept only when this whole condition is true (a condition that fails to\n"
        "\t\t\t# evaluate counts as false, so it lands in a reject branch below)\n"
        "\t\t\tif (\"%{proxy-reply:Packet-Type}\" == \"Access-Accept\" && ((\"%{control:Tmp-Integer-0}\" == \"1\" && "
        "((\"%{control:Tmp-String-1}\" == \"pap-admin+mfa\" && \"%{proxy-reply:Class}\" == \""
        + _mfa_class_hex("pap-admin") + "\") || (\"%{control:Tmp-String-1}\" == \"admin-ldap+mfa\" && \"%{proxy-reply:Class}\" == \""
        + _mfa_class_hex("admin-ldap") + "\"))) || (\"%{control:Tmp-Integer-0}\" == \"2\" && "
        "\"%{control:Tmp-String-1}\" == \"admin-ldap+mfa\"))) {\n"
        "\t\t\t\tupdate {\n"
        "\t\t\t\t\t&reply: !* ANY\n"
        "\t\t\t\t}\n"
        "\t\t\t\tif (\"%{control:Tmp-Integer-0}\" == \"1\") {\n"
        "\t\t\t\t\t# Duo: radius-admin-mfa-primary checked the password and the group\n"
        "\t\t\t\t\tif (\"%{sql:SELECT radius_admin_priv15()}\" == \"t\") {\n"
        + _reply_block(profile, others, "admin_full", 6) +
        "\t\t\t\t\t}\n"
        "\t\t\t\t}\n"
        "\t\t\t\telse {\n"
        "\t\t\t\t\t# remote server: the directory groups looked up before proxying\n"
        + _directory_groups_hex(5) +
        "\t\t\t\t\tif (\"%{control:Tmp-String-3}\" =~ /^(,[0-9a-f]+)*$/ && \"%{sql:SELECT radius_admin_admin_group_hex('%{control:Tmp-String-3}')}\" == \"t\") {\n"
        "\t\t\t\t\t\tif (\"%{sql:SELECT radius_admin_priv15()}\" == \"t\") {\n"
        + _reply_block(profile, others, "admin_full", 7) +
        "\t\t\t\t\t\t}\n"
        "\t\t\t\t\t}\n"
        "\t\t\t\t\telse {\n"
        + _reject_with("radius-admin: the directory account is not in a device admin group", 6) +
        "\t\t\t\t\t}\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t\telsif (\"%{proxy-reply:Packet-Type}\" != \"Access-Accept\") {\n"
        + _reject_with(_MFA_NOT_PROXIED, 4) +
        "\t\t\t}\n"
        "\t\t\telsif (\"%{control:Tmp-Integer-0}\" == \"2\") {\n"
        + _reject_with(_MFA_LOCAL_REMOTE, 4) +
        "\t\t\t}\n"
        "\t\t\telse {\n"
        + _reject_with(_MFA_BAD_CLASS, 4) +
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&control:Tmp-String-1 == \"admin-ldap\") {\n"
        + _directory_groups_hex(3) +
        "\t\t\tif (\"%{control:Tmp-String-3}\" =~ /^(,[0-9a-f]+)*$/ && \"%{sql:SELECT radius_admin_admin_group_hex('%{control:Tmp-String-3}')}\" == \"t\") {\n"
        "\t\t\t\tif (\"%{sql:SELECT radius_admin_priv15()}\" == \"t\") {\n"
        + _reply_block(profile, others, "admin_full", 5) +
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t\telse {\n"
        "\t\t\t\tupdate request {\n"
        "\t\t\t\t\t&Module-Failure-Message := \"radius-admin: the directory account is not in a device admin group\"\n"
        "\t\t\t\t}\n"
        "\t\t\t\treject\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (SQL-Group == \"net-admins\") {\n"
        "\t\t\tif (\"%{sql:SELECT radius_admin_priv15()}\" == \"t\") {\n"
        + _reply_block(profile, others, "admin_full", 4) +
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: user is not a device admin (not in group net-admins)\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t}\n"
        "\n"
        "\t# 802.1X with a username and password (EAP-TTLS/PAP or PEAP-MSCHAPv2, local\n"
        "\t# accounts or the directory). The session marker is set only\n"
        "\t# by radius_admin_inner_postauth / radius_admin_peap_postauth, after the password\n"
        "\t# was accepted inside the tunnel; the VLAN comes from the local user's groups, or\n"
        "\t# from the directory groups recorded with the marker.\n"
        "\telsif (&EAP-Message && &session-state:Tmp-String-1 && (&session-state:Tmp-String-1 == \"ttls-pap\" || &session-state:Tmp-String-1 == \"ttls-ldap\" || &session-state:Tmp-String-1 == \"peap\" || &session-state:Tmp-String-1 == \"peap-ldap\") && &session-state:Stripped-User-Name) {\n"
        "\t\tupdate control {\n"
        "\t\t\t&Tmp-String-1 := &session-state:Tmp-String-1\n"
        "\t\t\t&Stripped-User-Name := &session-state:Stripped-User-Name\n"
        '\t\t\t&Tmp-String-3 := ""\n'
        "\t\t}\n"
        "\t\tif ((&control:Tmp-String-1 == \"ttls-ldap\" || &control:Tmp-String-1 == \"peap-ldap\") && &session-state:Tmp-String-3) {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-3 := &session-state:Tmp-String-3\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tupdate session-state {\n"
        "\t\t\t&Tmp-String-1 !* ANY\n"
        "\t\t\t&Stripped-User-Name !* ANY\n"
        "\t\t\t&Tmp-String-3 !* ANY\n"
        "\t\t}\n"
        "\t\tif (&NAS-Port-Type && &NAS-Port-Type == Ethernet) {\n"
        "\t\t\tupdate control {\n"
        '\t\t\t\t&Tmp-String-7 := "true"\n'
        '\t\t\t\t&Tmp-String-8 := ""\n'
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate control {\n"
        '\t\t\t\t&Tmp-String-7 := "false"\n'
        "\t\t\t\t&Tmp-String-8 := \"%{hex:Called-Station-Id}\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tif ((&control:Tmp-String-1 == \"ttls-ldap\" || &control:Tmp-String-1 == \"peap-ldap\") && \"%{control:Tmp-String-3}\" =~ /^(,[0-9a-f]+)*$/ && \"%{control:Tmp-String-8}\" =~ /^([0-9a-f]{2})*$/) {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-0 := \"%{sql:SELECT radius_admin_vlan_rule_hex(%{control:Tmp-String-7}, '%{control:Tmp-String-8}', '%{control:Tmp-String-3}')}\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif ((&control:Tmp-String-1 == \"ttls-pap\" || &control:Tmp-String-1 == \"peap\") && \"%{control:Tmp-String-8}\" =~ /^([0-9a-f]{2})*$/) {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-0 := \"%{sql:SELECT radius_admin_dot1x_vlan_rule_hex('%{hex:control:Stripped-User-Name}', %{control:Tmp-String-7}, '%{control:Tmp-String-8}')}\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-0 !* ANY\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 =~ /^([0-9]{1,4}):([0-9]{1,10})$/) {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-0 := \"%{1}\"\n"
        "\t\t\t\t&Tmp-String-6 := \"%{2}\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-0 !* ANY\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 =~ /^[0-9]{1,4}$/) {\n"
        + _reply_block(profile, others, "vlan", 3) + _role_block(profile, others, 3) +
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: no enabled access rule matches the user's groups for this connection\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t}\n"
        "\n"
        "\t# 802.1X EAP-TLS: VLAN from the live access rules (radius_admin_vlan_hex)\n"
        "\telse {\n"
        "\t\tupdate control {\n"
        '\t\t\t&Tmp-String-1 := "eap-tls"\n'
        "\t\t}\n"
        "\t\tif (!&TLS-Client-Cert-Subject-Alt-Name-Dns) {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: client certificate has no DNS name (subject alternative name)\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\n"
        "\t\t# Look up the computer by certificate DNS SAN (only known after the TLS\n"
        "\t\t# handshake, so not during authorize) and cache its AD group names,\n"
        "\t\t# including nested groups, in &control:LDAP-Group.\n"
        "\t\tldap.authorize\n"
        "\n"
        "\t\t# All of the computer's group names, hex-encoded from the RAW attribute values\n"
        "\t\t# (attribute-to-attribute copy + %{hex:...[0]}: the names are never re-parsed\n"
        "\t\t# as a string, so backslashes/quotes stay literal). Case-insensitive compare\n"
        "\t\t# happens in SQL. No length limit on the list (dynamic buffers); one group name\n"
        "\t\t# longer than 1023 bytes would fail the hex xlat -> list check below -> reject.\n"
        "\t\t# Each name once: rlm_ldap caches direct groups twice (memberOf + filter search).\n"
        "\t\tupdate control {\n"
        '\t\t\t&Tmp-String-3 := ""\n'
        "\t\t\t&Tmp-String-9 !* ANY\n"
        "\t\t}\n"
        "\t\tupdate control {\n"
        "\t\t\t&Tmp-String-9 += &control:LDAP-Group[*]\n"
        "\t\t}\n"
        "\t\tforeach &control:LDAP-Group {\n"
        + _append_group_hex(3) +
        "\t\t}\n"
        "\t\tif (&NAS-Port-Type && &NAS-Port-Type == Ethernet) {\n"
        "\t\t\tupdate control {\n"
        '\t\t\t\t&Tmp-String-7 := "true"\n'
        '\t\t\t\t&Tmp-String-8 := ""\n'
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate control {\n"
        '\t\t\t\t&Tmp-String-7 := "false"\n'
        "\t\t\t\t&Tmp-String-8 := \"%{hex:Called-Station-Id}\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tif (\"%{control:Tmp-String-3}\" =~ /^(,[0-9a-f]+)*$/ && \"%{control:Tmp-String-8}\" =~ /^([0-9a-f]{2})*$/) {\n"
        "\t\t\t# '<vlan>:<rule id>'; the rule id is logged in radpostauth.rule_id\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-0 := \"%{sql:SELECT radius_admin_vlan_rule_hex(%{control:Tmp-String-7}, '%{control:Tmp-String-8}', '%{control:Tmp-String-3}')}\"\n"
        "\t\t\t}\n"
        "\t\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 =~ /^([0-9]{1,4}):([0-9]{1,10})$/) {\n"
        "\t\t\t\tupdate control {\n"
        "\t\t\t\t\t&Tmp-String-0 := \"%{1}\"\n"
        "\t\t\t\t\t&Tmp-String-6 := \"%{2}\"\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t\telse {\n"
        "\t\t\t\tupdate control {\n"
        "\t\t\t\t\t&Tmp-String-0 !* ANY\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-0 !* ANY\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tif (&control:Tmp-String-0 && &control:Tmp-String-0 =~ /^[0-9]{1,4}$/) {\n"
        + _reply_block(profile, others, "vlan", 3) + _role_block(profile, others, 3) +
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: no enabled access rule matches the computer's AD groups for this connection\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t}\n"
        "\n"
        "\tradius_admin_custom\n"
        "}\n\n"
    )

    # ---------------------------------------------------------------- custom
    o.append(
        "#\n"
        "#  Custom policy (admin supplied, verbatim). Called last by radius_admin_postauth.\n"
        "#\n"
        "radius_admin_custom {\n"
    )
    if custom.strip():
        o.append(custom if custom.endswith("\n") else custom + "\n")
    else:
        o.append("\tnoop\n")
    o.append("}\n")
    return "".join(o)


def _client_profile_line(c, default_id, indent):
    """radius_admin_profile for a client whose vendor profile is not the default."""
    pid = c.get("vendor_profile") or ""
    if not pid or pid == default_id:
        return ""
    if not vendors.valid_id(pid):
        raise PolicyInputError("Client %s: invalid vendor profile." % c.get("name"))
    return "%sradius_admin_profile = %s\n" % ("\t" * indent, pid)


_MFA_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")


def _mfa_int(value, what, lo, hi):
    if isinstance(value, bool):
        raise PolicyInputError("%s must be a whole number from %d to %d." % (what, lo, hi))
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value.strip()):
        value = int(value.strip())
    if not isinstance(value, int) or not lo <= value <= hi:
        raise PolicyInputError("%s must be a whole number from %d to %d." % (what, lo, hi))
    return value


def validate_mfa_provider(p):
    """A second-factor provider as stored in ui.mfa_provider plus its decrypted secrets
    (SPEC section 29). Returns a normalized copy:
      duo:        id, type, enabled, secret (default server -> Duo proxy), primary_secret
                  (Duo proxy -> radius-admin-mfa-primary); address 127.0.0.1, port
                  DUO_PROXY_PORT, timeout MFA_TIMEOUT_DEFAULT are fixed.
      radius-mfa: id, type, enabled, address (IP address, not a network), port, secret,
                  timeout (5-60 s), require_ma (yes/no).
    """
    if not isinstance(p, dict):
        raise PolicyInputError("Invalid second-factor provider.")
    pid = p.get("id")
    if not isinstance(pid, str) or not _MFA_ID_RE.fullmatch(pid):
        raise PolicyInputError("Provider id must be 1-32 lower-case letters, digits or hyphens, starting with a letter.")
    ptype = p.get("type")
    if ptype not in MFA_TYPES:
        raise PolicyInputError("Provider %s: type must be duo or radius-mfa." % pid)
    out = {"id": pid, "type": ptype, "enabled": _truthy(p.get("enabled", False))}
    try:
        validate_secret(p.get("secret"))
    except PolicyInputError as e:
        raise PolicyInputError("Provider %s: %s" % (pid, e))
    out["secret"] = p["secret"]
    if ptype == "duo":
        try:
            validate_secret(p.get("primary_secret"))
        except PolicyInputError as e:
            raise PolicyInputError("Provider %s (password check): %s" % (pid, e))
        out.update(primary_secret=p["primary_secret"], address="127.0.0.1", port=DUO_PROXY_PORT,
                   timeout=MFA_TIMEOUT_DEFAULT, require_ma="yes")
        return out
    addr = validate_ipaddr(p.get("address") or "")
    if "/" in addr:
        raise PolicyInputError("Provider %s: the server address must be one address, not a network." % pid)
    out["address"] = str(ipaddress.ip_address(addr))
    out["port"] = _mfa_int(p.get("port", 1812), "Provider %s: port" % pid, 1, 65535)
    out["timeout"] = _mfa_int(p.get("timeout", MFA_TIMEOUT_DEFAULT), "Provider %s: timeout" % pid, 5, 60)
    ma = p.get("require_ma", "yes") or "yes"
    if ma not in ("yes", "no"):
        raise PolicyInputError("Provider %s: require Message-Authenticator must be yes or no." % pid)
    out["require_ma"] = ma
    return out


def render_mfa(providers):
    """The second-factor part of the clients file (SPEC section 29), deterministic: for every
    enabled provider a home_server, home_server_pool and realm radius_admin_mfa_<id>; with an
    enabled Duo provider also the listener of radius-admin-mfa-primary on 127.0.0.1 and its
    one client (the Duo proxy). Empty without enabled providers."""
    checked, seen = [], set()
    for p in providers or ():
        p = validate_mfa_provider(p)
        if p["id"] in seen:
            raise PolicyInputError("Duplicate second-factor provider %s." % p["id"])
        seen.add(p["id"])
        if p["enabled"]:
            checked.append(p)
    if not checked:
        return ""
    checked.sort(key=lambda p: p["id"])
    duo = [p for p in checked if p["type"] == "duo"]
    if len(duo) > 1:
        raise PolicyInputError("Only one Duo provider can be enabled.")
    out = ["\n#\n#  Second-factor providers (SPEC section 29): device admin logins that need a second\n"
           "#  factor are proxied to realm " + MFA_REALM_PREFIX + "<id>.\n#\n"]
    if duo:
        out.append(
            "listen {\n"
            "\ttype = auth\n"
            "\tipv4addr = 127.0.0.1\n"
            "\tport = %d\n"
            "\tproto = udp\n"
            "\tvirtual_server = %s\n"
            "\tclients = %s\n"
            "}\n"
            "\n"
            "clients %s {\n"
            "\tclient %s {\n"
            "\t\tipv4addr = 127.0.0.1\n"
            '\t\tsecret = "%s"\n'
            "\t\tshortname = %s\n"
            "\t\trequire_message_authenticator = yes\n"
            "\t}\n"
            "}\n"
            % (MFA_PRIMARY_PORT, MFA_PRIMARY_SERVER, MFA_CLIENTS_SECTION, MFA_CLIENTS_SECTION,
               MFA_PROXY_CLIENT, duo[0]["primary_secret"], MFA_PROXY_CLIENT))
    for p in checked:
        name = MFA_REALM_PREFIX + p["id"]
        family = "ipv6addr" if ":" in p["address"] else "ipv4addr"
        out.append(
            "\nhome_server %s {\n"
            "\ttype = auth\n"
            "\t%s = %s\n"
            "\tport = %d\n"
            "\tproto = udp\n"
            '\tsecret = "%s"\n'
            "\trequire_message_authenticator = %s\n"
            "\tresponse_window = %d\n"
            "\tzombie_period = %d\n"
            "\trevive_interval = 60\n"
            "\tstatus_check = none\n"
            "}\n"
            "\n"
            "home_server_pool %s {\n"
            "\ttype = fail-over\n"
            "\thome_server = %s\n"
            "}\n"
            "\n"
            "realm %s {\n"
            "\tauth_pool = %s\n"
            "}\n"
            % (name, family, p["address"], p["port"], p["secret"], p["require_ma"], p["timeout"],
               2 * p["timeout"], name, name, name, name))
    return "".join(out)


_DUO_IKEY_RE = re.compile(r"DI[A-Z0-9]{18}")
_DUO_SKEY_RE = re.compile(r"[A-Za-z0-9]{40}")
_DUO_API_RE = re.compile(r"api-[a-z0-9]{1,16}\.duosecurity\.com")
_DUO_SECRET_RE = re.compile(r"[A-Za-z0-9]{16,128}")
DUO_FACTORS = ("auto", "push", "phone", "passcode")
DUO_CONFIG_HEADER = "; radius-admin"


def validate_duo_settings(s, fips=False):
    """Settings of the Duo provider as the portal stores them (SPEC section 29.2): ikey,
    skey, api_host (from the Duo Admin Panel), failmode (secure|safe; FIPS mode: secure),
    factors (auto, push, phone, passcode), and the generated secrets `secret` (default server
    -> Duo proxy) and `primary_secret` (Duo proxy -> radius-admin-mfa-primary), letters and
    digits only. Returns a normalized copy."""
    if not isinstance(s, dict):
        raise PolicyInputError("Invalid Duo settings.")
    out = {}
    for key, rx, msg in (("ikey", _DUO_IKEY_RE, "Integration key must be 20 characters starting with DI."),
                         ("skey", _DUO_SKEY_RE, "Secret key must be 40 letters and digits."),
                         ("api_host", _DUO_API_RE, "API hostname must look like api-xxxxxxxx.duosecurity.com."),
                         ("secret", _DUO_SECRET_RE, "Duo proxy secret must be 16-128 letters and digits."),
                         ("primary_secret", _DUO_SECRET_RE, "Password check secret must be 16-128 letters and digits.")):
        v = s.get(key)
        if not isinstance(v, str) or not rx.fullmatch(v):
            raise PolicyInputError(msg)
        out[key] = v
    failmode = s.get("failmode", "secure") or "secure"
    if failmode not in ("secure", "safe"):
        raise PolicyInputError("Fail mode must be secure or safe.")
    out["failmode"] = "secure" if fips else failmode
    factors = s.get("factors", "auto") or "auto"
    parts = factors.split(",") if isinstance(factors, str) else []
    if not parts or len(parts) > 4 or any(f not in DUO_FACTORS for f in parts) or len(set(parts)) != len(parts):
        raise PolicyInputError("Factors must be auto, push, phone or passcode.")
    out["factors"] = ",".join(parts)
    return out


def render_duo_config(s, fips=False):
    """authproxy.cfg for the Duo Authentication Proxy (SPEC section 29.2), deterministic:
    [radius_server_auto] on 127.0.0.1:DUO_PROXY_PORT for the default server, primary
    authentication by [radius_client] at radius-admin-mfa-primary (127.0.0.1:MFA_PRIMARY_PORT),
    whose Class is passed back; Message-Authenticator in both directions; fips_mode in FIPS
    mode. The root helper checks the same grammar."""
    s = validate_duo_settings(s, fips)
    main = "[main]\nlog_auth_events=true\n" + ("fips_mode=true\n" if fips else "")
    return (DUO_CONFIG_HEADER + ": generated by the portal (SPEC section 29.2). Do not edit: applying changes\n"
            "; replaces this file. Duo Authentication Proxy for device admin logins that need a second factor.\n"
            "\n" + main + "\n"
            "[radius_client]\n"
            "host=127.0.0.1\n"
            "port=%d\n"
            "secret=%s\n"
            "pass_through_attr_names=Class\n"
            "\n"
            "[radius_server_auto]\n"
            "ikey=%s\n"
            "skey=%s\n"
            "api_host=%s\n"
            "radius_ip_1=127.0.0.1\n"
            "radius_secret_1=%s\n"
            "interface=127.0.0.1\n"
            "port=%d\n"
            "client=radius_client\n"
            "failmode=%s\n"
            "factors=%s\n"
            "pass_through_attr_names=Message-Authenticator\n"
            "force_message_authenticator=true\n"
            % (MFA_PRIMARY_PORT, s["primary_secret"], s["ikey"], s["skey"], s["api_host"], s["secret"],
               DUO_PROXY_PORT, s["failmode"], s["factors"]))


def render_clients(clients, radsec=None, default_profile=None, mfa=None):
    """Full text of /etc/freeradius/radius-admin-clients.conf (deterministic).

    UDP clients are top-level client sections. RadSec clients (transport "radsec")
    go into their own clients section with the TLS listener that uses it; both are
    rendered only while RadSec is enabled and at least one RadSec client is enabled.
    The file is $INCLUDEd at the top level of radiusd.conf (via clients.conf), where
    listen and clients sections are valid, so no further file needs installing.
    A client whose vendor profile differs from `default_profile` (an id; default
    vendors.DEFAULT_ID) carries it as radius_admin_profile (SPEC section 26).
    """
    default_id = default_profile or vendors.DEFAULT_ID
    blocks, radsec_blocks = [], []
    seen_names, seen_addrs, seen_tls_addrs = set(), set(), set()
    for c in clients or []:
        if not isinstance(c, dict):
            raise PolicyInputError("Invalid RADIUS client.")
        if not _truthy(c.get("enabled", True)):
            continue
        name = validate_client_name(c.get("name"))
        if name in seen_names:
            raise PolicyInputError("Duplicate RADIUS client name %s." % name)
        seen_names.add(name)
        addr = validate_ipaddr(c.get("ipaddr") or "")
        key = str(ipaddress.ip_network(addr, strict=True))
        family = "ipv6addr" if ":" in addr else "ipv4addr"
        transport = c.get("transport", "udp") or "udp"
        if transport not in ("udp", "radsec"):
            raise PolicyInputError("Client %s: transport must be udp or radsec." % name)
        if transport == "radsec":
            if key in seen_tls_addrs:
                raise PolicyInputError("Duplicate RadSec client address %s (client %s)." % (addr, name))
            seen_tls_addrs.add(key)
            peer = validate_radsec_peer_name(c.get("radsec_peer_name", "") or "")
            nas_type = validate_nas_type(c.get("nas_type", "other") or "other")
            radsec_blocks.append((name, (
                "\tclient %s {\n"
                "\t\t%s = %s\n"
                "\t\tproto = tls\n"
                '\t\tsecret = "%s"\n'
                "\t\tshortname = %s\n"
                "\t\tnas_type = %s\n"
                "%s"
                '\t\tradsec_peer_name = "%s"\n'
                "\t}\n"
            ) % (name, family, addr, RADSEC_SECRET, name, nas_type, _client_profile_line(c, default_id, 2),
                 peer.lower())))
            continue
        if key in seen_addrs:
            raise PolicyInputError("Duplicate RADIUS client address %s (client %s)." % (addr, name))
        seen_addrs.add(key)
        secret = c.get("secret")
        try:
            _check_secret_syntax(secret)
        except PolicyInputError as e:
            raise PolicyInputError("Client %s: %s" % (name, e))
        ma = c.get("require_ma", "auto") or "auto"
        lps = c.get("limit_proxy_state", "auto") or "auto"
        if ma not in _TRISTATE or lps not in _TRISTATE:
            raise PolicyInputError("Client %s: require_ma / limit_proxy_state must be yes, no or auto." % name)
        nas_type = validate_nas_type(c.get("nas_type", "other") or "other")
        blocks.append((name, (
            "client %s {\n"
            "\t%s = %s\n"
            '\tsecret = "%s"\n'
            "\tshortname = %s\n"
            "\tnas_type = %s\n"
            "%s"
            "\trequire_message_authenticator = %s\n"
            "\tlimit_proxy_state = %s\n"
            "}\n"
        ) % (name, family, addr, secret, name, nas_type, _client_profile_line(c, default_id, 1), ma, lps)))
    blocks.sort(key=lambda b: b[0])
    text = _HEADER + "".join("\n" + b for _, b in blocks)
    rs = validate_radsec_settings(radsec if radsec is not None else {})
    if rs["enabled"] and radsec_blocks:
        radsec_blocks.sort(key=lambda b: b[0])
        text += _render_radsec_listener(rs) + (
            "\nclients %s {\n" % RADSEC_CLIENTS_SECTION + "".join(b for _, b in radsec_blocks) + "}\n")
    return text + render_mfa(mfa)


def _render_radsec_listener(rs):
    if rs["listen"] == "*":
        addr = "ipaddr = *"
    else:
        addr = ("ipv6addr = %s" if ":" in rs["listen"] else "ipv4addr = %s") % rs["listen"]
    ocsp = ""
    if rs["ocsp"]:
        ocsp = (
            "\t\tocsp {\n"
            "\t\t\tenable = yes\n"
            "\t\t\toverride_cert_url = %s\n"
            "%s"
            "\t\t\tuse_nonce = yes\n"
            "\t\t\ttimeout = 5\n"
            "\t\t\tsoftfail = no\n"
            "\t\t}\n"
        ) % ("yes" if rs["ocsp_url"] else "no",
             ('\t\t\turl = "%s"\n' % rs["ocsp_url"]) if rs["ocsp_url"] else "")
    return (
        "\n#\n"
        "#  RadSec listener (RADIUS over TLS, RFC 6614). Clients must present a certificate\n"
        "#  issued by the site CA; per-client name checks are in policy radius_admin_radsec.\n"
        "#\n"
        "listen {\n"
        "\ttype = auth+acct\n"
        "\t%s\n"
        "\tport = %d\n"
        "\tproto = tcp\n"
        "\tvirtual_server = default\n"
        "\tclients = %s\n"
        "\tlimit {\n"
        "\t\tmax_connections = %d\n"
        "\t\tlifetime = 0\n"
        "\t\tidle_timeout = %d\n"
        "\t}\n"
        "\ttls {\n"
        "\t\tprivate_key_file = %s/radius.key\n"
        "\t\tcertificate_file = %s/radius.pem\n"
        "\t\tca_file = %s/ca.pem\n"
        "\t\trequire_client_cert = yes\n"
        '\t\ttls_min_version = "1.2"\n'
        '\t\ttls_max_version = "1.3"\n'
        '\t\tcipher_list = "%s"\n'
        '\t\tecdh_curve = "secp384r1:prime256v1"\n'
        "\t\tfragment_size = 8192\n"
        "%s"
        "\t}\n"
        "}\n"
    ) % (addr, rs["port"], RADSEC_CLIENTS_SECTION, rs["max_connections"], rs["idle_timeout"],
         CERT_DIR, CERT_DIR, CERT_DIR, TLS12_CIPHERS, ocsp)
