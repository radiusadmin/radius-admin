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
    """Admin subnet for switch-admin logins. Returns ipaddress network object."""
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


def render_policy(custom=""):
    """Full text of /etc/freeradius/policy.d/radius-admin (deterministic).

    Access rules and the admin settings are NOT rendered: FreeRADIUS evaluates them
    live through the SQL functions of sql/40-live-policy.sql on every request
    (SPEC section 10). Only the admin-supplied custom policy body varies.
    """
    if custom is None:
        custom = ""
    validate_custom_policy(custom)

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
        "\tif (!&EAP-Message && &NAS-Port-Type && &NAS-Port-Type == Ethernet && &User-Name && &User-Name =~ " + mac_rx + ") {\n"
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
        "\t\t# Live decision (sql/70-operations.sql): '<vlan>', 'disabled', 'expired' or\n"
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

    # ---------------------------------------------------------------- post-auth
    o.append(
        "#\n"
        "#  Site policy. Called at the start of post-auth.\n"
        "#\n"
        "radius_admin_postauth {\n"
        "\t# MAC Authentication Bypass (accepted in authorize by radius_admin_mab)\n"
        "\t# The request shape is re-checked so that a Tmp-String-1 added by another module\n"
        "\t# (users file, SQL radcheck, LDAP) can never select this branch.\n"
        "\tif (!&EAP-Message && &NAS-Port-Type && &NAS-Port-Type == Ethernet && &User-Name && &User-Name =~ " + mac_rx + " && \\\n"
        '\t    &control:Tmp-String-1 && &control:Tmp-String-1 == "mab" && &control:Tmp-String-0 && &control:Tmp-String-0 =~ /^[0-9]{1,4}$/) {\n'
        "\t\tupdate reply {\n"
        "\t\t\t&Tunnel-Type := VLAN\n"
        "\t\t\t&Tunnel-Medium-Type := IEEE-802\n"
        "\t\t\t&Tunnel-Private-Group-Id := &control:Tmp-String-0\n"
        "\t\t}\n"
        "\t}\n"
        "\n"
        "\t# Switch/device admin logins (plain PAP, no port type or SSID).\n"
        "\t# Source subnet and priv15 come live from ui.setting via SQL functions;\n"
        "\t# an empty result (e.g. database down) means reject.\n"
        "\t# SECURITY: request/directory data is passed to %{sql:...} ONLY as hex\n"
        "\t# (%{hex:...}, alphabet [0-9a-f]); FreeRADIUS un-escapes backslash sequences\n"
        "\t# in %{sql:...} arguments after SQL escaping, so raw strings could inject SQL.\n"
        "\telsif (!&EAP-Message && (!&NAS-Port-Type || &NAS-Port-Type != Ethernet) && !&Called-Station-Id) {\n"
        "\t\tupdate control {\n"
        '\t\t\t&Tmp-String-1 := "pap-admin"\n'
        "\t\t}\n"
        "\t\t# The packet source address in hex: IPv4 = the 4 raw octets (8 digits);\n"
        "\t\t# IPv6 = hex of its printed text form.\n"
        "\t\tif (&Packet-Src-IP-Address) {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-IP-Address-0 := \"%{Packet-Src-IP-Address}\"\n"
        "\t\t\t}\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-4 := \"%{hex:control:Tmp-IP-Address-0}\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telsif (&Packet-Src-IPv6-Address) {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-5 := \"%{Packet-Src-IPv6-Address}\"\n"
        "\t\t\t}\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-4 := \"%{hex:control:Tmp-String-5}\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tupdate control {\n"
        '\t\t\t&Tmp-String-8 := "f"\n'
        "\t\t}\n"
        "\t\tif (&control:Tmp-String-4 && &control:Tmp-String-4 =~ /^[0-9a-f]{8}$|^([0-9a-f]{2}){2,64}$/) {\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-8 := \"%{sql:SELECT radius_admin_admin_source_ok_hex('%{control:Tmp-String-4}')}\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\tif (!&control:Tmp-String-8 || &control:Tmp-String-8 != \"t\") {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: switch admin login from an address outside the management subnet\"\n"
        "\t\t\t}\n"
        "\t\t\treject\n"
        "\t\t}\n"
        "\t\telsif (SQL-Group == \"net-admins\") {\n"
        "\t\t\tif (\"%{sql:SELECT radius_admin_priv15()}\" == \"t\") {\n"
        "\t\t\t\tupdate reply {\n"
        '\t\t\t\t\t&Cisco-AVPair += "shell:priv-lvl=15"\n'
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\telse {\n"
        "\t\t\tupdate request {\n"
        "\t\t\t\t&Module-Failure-Message := \"radius-admin: user is not a switch admin (not in group net-admins)\"\n"
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
        "\t\tupdate control {\n"
        '\t\t\t&Tmp-String-3 := ""\n'
        "\t\t\t&Tmp-String-9 !* ANY\n"
        "\t\t}\n"
        "\t\tupdate control {\n"
        "\t\t\t&Tmp-String-9 += &control:LDAP-Group[*]\n"
        "\t\t}\n"
        "\t\tforeach &control:LDAP-Group {\n"
        "\t\t\tupdate control {\n"
        '\t\t\t\t&Tmp-String-3 := "%{control:Tmp-String-3},%{hex:control:Tmp-String-9[0]}"\n'
        "\t\t\t}\n"
        "\t\t\tupdate control {\n"
        "\t\t\t\t&Tmp-String-9[0] !* ANY\n"
        "\t\t\t}\n"
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
        "\t\t\tupdate reply {\n"
        "\t\t\t\t&Tunnel-Type := VLAN\n"
        "\t\t\t\t&Tunnel-Medium-Type := IEEE-802\n"
        "\t\t\t\t&Tunnel-Private-Group-Id := &control:Tmp-String-0\n"
        "\t\t\t}\n"
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


def render_clients(clients, radsec=None):
    """Full text of /etc/freeradius/radius-admin-clients.conf (deterministic).

    UDP clients are top-level client sections. RadSec clients (transport "radsec")
    go into their own clients section with the TLS listener that uses it; both are
    rendered only while RadSec is enabled and at least one RadSec client is enabled.
    The file is $INCLUDEd at the top level of radiusd.conf (via clients.conf), where
    listen and clients sections are valid, so no further file needs installing.
    """
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
                '\t\tradsec_peer_name = "%s"\n'
                "\t}\n"
            ) % (name, family, addr, RADSEC_SECRET, name, nas_type, peer.lower())))
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
            "\trequire_message_authenticator = %s\n"
            "\tlimit_proxy_state = %s\n"
            "}\n"
        ) % (name, family, addr, secret, name, nas_type, ma, lps)))
    blocks.sort(key=lambda b: b[0])
    text = _HEADER + "".join("\n" + b for _, b in blocks)
    rs = validate_radsec_settings(radsec if radsec is not None else {})
    if rs["enabled"] and radsec_blocks:
        radsec_blocks.sort(key=lambda b: b[0])
        text += _render_radsec_listener(rs) + (
            "\nclients %s {\n" % RADSEC_CLIENTS_SECTION + "".join(b for _, b in radsec_blocks) + "}\n")
    return text


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
