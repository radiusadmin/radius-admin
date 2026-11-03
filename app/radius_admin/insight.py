"""Helpers that turn raw RADIUS records into something an operator can act on
(SPEC section 13): which switch a NAS address is, what a reject reason means,
the client certificate's expiry, the AD groups the rule matcher saw."""
import datetime
import ipaddress
import re

from . import db

# (pattern in the recorded reason, plain-language hint). First match wins.
REASON_HINTS = (
    (r"MAB device not registered", "This MAC is not registered. Approve it under MAB devices → Unknown devices, "
                                   "or add it with Add device."),
    (r"MAB not used: this device authenticates with (a certificate|802\.1X)",
     "This MAC has authenticated with 802.1X (a certificate or a username and password), so it is not offered "
     "for MAB approval. The switch "
     "tried MAB, usually because 802.1X timed out or the port tries MAB first; check the computer's 802.1X "
     "client and the port's authentication order."),
    (r"MAB registration expired", "The device's MAB registration has expired. Edit the device and set a new "
                                  "expiry date (or clear it)."),
    (r"MAB device is disabled", "The device is registered but disabled. Enable it on its MAB entry."),
    (r"MAB User-Name does not match", "The switch sent a MAC in User-Name that differs from Calling-Station-Id; "
                                      "check the switch's MAB settings."),
    (r"MAB Calling-Station-Id is not a MAC", "The switch's Calling-Station-Id is not a MAC address; check the "
                                             "switch's RADIUS attribute settings."),
    (r"username and password sign-in \(EAP-TTLS\) is turned off",
     "Username and password 802.1X is turned off. Turn it on in Settings, or configure the device for a "
     "certificate (EAP-TLS)."),
    (r"802\.1X user is disabled", "The local 802.1X user is disabled. Enable it under 802.1X users."),
    (r"802\.1X user has expired", "The local 802.1X user has expired. Set a new expiry date (or clear it) under "
                                  "802.1X users."),
    (r"no such 802\.1X user", "No local 802.1X user has this name (the name inside the tunnel, not the outer "
                              "anonymous identity). Add the user under 802.1X users, or check the device's "
                              "settings."),
    (r"wrong password for 802\.1X user", "Wrong password for this 802.1X user. Set a new one under 802.1X users "
                                         "if the user has forgotten it."),
    (r"only PAP is accepted inside EAP-TTLS", "Set the device's EAP-TTLS inner authentication to PAP (the "
                                             "password is protected by the TLS tunnel)."),
    (r"no enabled access rule matches the user's groups",
     "None of the 802.1X user's groups has an enabled access rule for this kind of connection (wired, or this "
     "SSID). Add a rule or change the user's groups."),
    (r"no enabled access rule", "None of the computer's AD groups (below) has an enabled access rule for this "
                                "kind of connection (wired, or this SSID). Add a rule or change the computer's "
                                "group membership."),
    (r"no DNS name", "The client certificate has no DNS subject alternative name, which is how the computer is "
                     "looked up in AD. Re-issue the certificate from the computer template."),
    (r"outside the management subnet", "Switch admin logins are accepted only from switches in the management "
                                       "subnet (Settings)."),
    (r"not a switch admin|not in group net-admins", "The user exists but is not a switch admin."),
    (r"(?i)digest does not match|password.*(incorrect|does not match|mismatch)|Cleartext-Password",
     "Wrong password for this switch admin account."),
    (r"(?i)no .*password|No known good password|User not found|No Auth-Type",
     "Unknown user, or the account has no usable password."),
    (r"(?i)certificate (has )?expired", "The client certificate has expired. Renew it on the computer "
                                        "(auto-enrolment)."),
    (r"(?i)revoked|OCSP", "The certificate was reported revoked, or the OCSP responder could not confirm it. "
                          "Check the certificate status in the PKI."),
    (r"(?i)unable to get (local )?issuer|unknown ca|self.signed|verify failed",
     "The client certificate was not issued by the trusted site CA chain."),
    (r"(?i)User-Name contains whitespace|User-Name .*(invalid|not allowed)",
     "The user name sent by the device contains characters FreeRADIUS refuses (for example spaces)."),
    (r"(?i)No mutually acceptable types|(PEAP|TTLS|MD5|MSCHAP|NAK).*(not|disabled|reject)|Peer NAK",
     "The device tried an EAP method this server does not offer. Configure it for a certificate (EAP-TLS), or "
     "for a username and password with EAP-TTLS and PAP inside."),
    (r"(?i)sql|database|rlm_sql", "A database error occurred; check PostgreSQL and the FreeRADIUS log."),
)


def reason_hint(reason, reply=None):
    if not reason:
        if reply == "Access-Reject":
            return ("No reason was recorded. Authentications logged before this release have none; otherwise "
                    "the request was rejected before the site policy ran (for example a failed TLS handshake).")
        return ""
    for pat, hint in REASON_HINTS:
        if re.search(pat, reason):
            return hint
    return ""


def clean_reason(reason):
    """Strip the 'radius-admin: ' / module prefixes for display."""
    if not reason:
        return ""
    r = reason.strip()
    r = re.sub(r"^radius-admin:\s*", "", r)
    return r[:500]


def decode_groups(hexlist):
    """',<hex>,<hex>' -> ['Group A', 'Group B'] (undecodable items are shown as such)."""
    out = []
    if not hexlist:
        return out
    for item in hexlist.split(","):
        if not item:
            continue
        try:
            out.append(bytes.fromhex(item).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            out.append("<undecodable: %s…>" % item[:16])
    return out


def cert_expiry(value):
    """FreeRADIUS TLS-Client-Cert-Expiration (ASN.1 UTCTime 'YYMMDDhhmmssZ' or
    GeneralizedTime 'YYYYMMDDhhmmssZ') -> aware datetime, or None."""
    if not value:
        return None
    v = value.strip()
    for fmt in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.datetime.strptime(v, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------- NAS -> client
class ClientIndex:
    """Map NAS addresses to RADIUS clients (most specific entry wins)."""

    def __init__(self, rows):
        self.entries = []
        for r in rows:
            try:
                net = ipaddress.ip_network(str(r["ipaddr"]), strict=False)
            except ValueError:
                continue
            self.entries.append((net, r))
        self.entries.sort(key=lambda e: -e[0].prefixlen)
        self.by_id = {r["id"]: r for _, r in self.entries}

    @classmethod
    def load(cls, conn=None):
        return cls(db.query("SELECT id, name, ipaddr, is_switch, enabled FROM ui.radius_client", conn=conn))

    def find(self, addr):
        if addr is None:
            return None
        try:
            ip = ipaddress.ip_address(str(addr).split("/")[0])
        except ValueError:
            return None
        for net, r in self.entries:
            if ip.version == net.version and ip in net:
                return r
        return None


def port_status(ports, port_name):
    """Find a port in switch_status.ports by name (gi1/0/4 == gi4 on standalone)."""
    if not ports or not port_name:
        return None
    from .snmp import cli_port_name
    want = cli_port_name(str(port_name)).lower()
    for p in ports:
        if str(p.get("name", "")).lower() == want:
            return p
    return None
