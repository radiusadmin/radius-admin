"""SAML 2.0 single sign-on for the portal (service provider side, pysaml2).

The portal only verifies the identity provider's signatures, so it holds no SAML private
key: AuthnRequests go out unsigned over HTTP-Redirect, responses come back over HTTP-POST
and must carry a signed assertion or a signed response (RSA/ECDSA with SHA-2; SHA-1 is
refused before pysaml2 sees the message). Roles come from group claims mapped in
ui.sso_group_role (Microsoft Entra ID sends group object IDs); no match means no access.
"""
import base64
import re
import zlib

from . import db

GROUPS_ENTRA = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
GROUPS_OVERAGE = "http://schemas.microsoft.com/claims/groups.link"
NAME_ENTRA = "http://schemas.microsoft.com/identity/claims/displayname"
DEFAULTS = {"enabled": False, "idp_metadata": "", "entity_id": "", "group_attribute": GROUPS_ENTRA,
            "name_attribute": NAME_ENTRA, "local_login": "all"}
LOCAL_LOGIN = ("all", "admins")
MAX_METADATA = 256 * 1024
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
XMLSEC = "/usr/bin/xmlsec1"
# SHA-1 based XML signature and digest algorithms (xmldsig, xmldsig-more)
_SHA1_ALG = re.compile(r'Algorithm\s*=\s*"[^"]*(?:#rsa-sha1|#dsa-sha1|#ecdsa-sha1|#hmac-sha1|#sha1)"', re.I)
_ATTR_NAME_RE = re.compile(r"[A-Za-z0-9:/._#-]{1,256}")
_GROUP_ID_RE = re.compile(r"[A-Za-z0-9 ._@:/=+-]{1,256}")


class SSOError(Exception):
    """Sign-in refused. The message is safe to show to the user."""


def settings(raw):
    """Normalize the saml_* settings dict (strings from ui.setting)."""
    s = dict(DEFAULTS)
    s.update({k: v for k, v in raw.items() if k in DEFAULTS})
    s["enabled"] = str(s["enabled"]).lower() in ("true", "1", "yes", "on")
    if s["local_login"] not in LOCAL_LOGIN:
        s["local_login"] = "all"
    return s


def validate_attribute_name(value, what):
    if not _ATTR_NAME_RE.fullmatch(value or ""):
        raise ValueError("%s must be 1-256 characters: letters, digits and : / . _ # -" % what)
    return value


def validate_group_id(value):
    v = (value or "").strip()
    if not _GROUP_ID_RE.fullmatch(v):
        raise ValueError("Group ID must be 1-256 characters (an Entra object ID such as "
                         "3f2504e0-4f89-11d3-9a0c-0305e82c3301, or a group name).")
    return v


def sp_urls(base_url, s):
    entity = s["entity_id"] or base_url + "/saml/metadata"
    return entity, base_url + "/saml/acs"


def _config(base_url, s, metadata=None):
    from saml2 import BINDING_HTTP_POST
    from saml2.config import SPConfig
    entity, acs = sp_urls(base_url, s)
    conf = {
        "entityid": entity,
        "xmlsec_binary": XMLSEC,
        "allow_unknown_attributes": True,
        "accepted_time_diff": 120,
        "service": {"sp": {
            "endpoints": {"assertion_consumer_service": [(acs, BINDING_HTTP_POST)]},
            "allow_unsolicited": False,
            "authn_requests_signed": False,
            "want_response_signed": False,
            "want_assertions_signed": False,
            "want_assertions_or_response_signed": True,
        }},
    }
    md = s["idp_metadata"] if metadata is None else metadata
    if md:
        conf["metadata"] = {"inline": [md]}
    c = SPConfig()
    c.load(conf)
    return c


def idp_summary(base_url, s, metadata):
    """Validate IdP metadata. Returns {"entity_id", "sso_url", "certs"} or raises ValueError."""
    if not metadata or len(metadata.encode("utf-8")) > MAX_METADATA:
        raise ValueError("Paste the identity provider's federation metadata XML (at most 256 KiB).")
    if "<!DOCTYPE" in metadata or "<!ENTITY" in metadata:
        raise ValueError("The metadata must not contain a DOCTYPE or entity declarations.")
    from saml2 import BINDING_HTTP_REDIRECT
    try:
        c = _config(base_url, s, metadata)
        idps = list(c.metadata.identity_providers())
    except Exception as e:  # pysaml2 raises many types for bad XML
        raise ValueError("The metadata could not be read: %s" % (str(e)[:200] or type(e).__name__))
    if len(idps) != 1:
        raise ValueError("The metadata must describe exactly one identity provider (found %d)." % len(idps))
    entity = idps[0]
    sso = [x["location"] for x in c.metadata.single_sign_on_service(entity, BINDING_HTTP_REDIRECT)]
    if not sso:
        raise ValueError("The identity provider offers no HTTP-Redirect sign-in endpoint.")
    certs = c.metadata.certs(entity, "idpsso", "signing")
    if not certs:
        raise ValueError("The metadata contains no signing certificate.")
    return {"entity_id": entity, "sso_url": sso[0], "certs": len(certs)}


def sp_metadata(base_url, s):
    from saml2.metadata import entity_descriptor
    return str(entity_descriptor(_config(base_url, s, metadata="")))


def authn_request(base_url, s, relay_state, force=False):
    """Returns (request_id, redirect_url)."""
    from saml2 import BINDING_HTTP_REDIRECT
    from saml2.client import Saml2Client
    c = _config(base_url, s)
    client = Saml2Client(c)
    entity = list(c.metadata.identity_providers())[0]
    kw = {"force_authn": "true"} if force else {}
    reqid, info = client.prepare_for_authenticate(entityid=entity, relay_state=relay_state,
                                                  binding=BINDING_HTTP_REDIRECT, **kw)
    location = dict(info["headers"])["Location"]
    return reqid, location


def _decoded(saml_response):
    try:
        raw = base64.b64decode(saml_response, validate=False)
    except ValueError:
        raise SSOError("The sign-in response could not be read.")
    if len(raw) > 512 * 1024:
        raise SSOError("The sign-in response is too large.")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return zlib.decompress(raw, -15).decode("utf-8")
        except (zlib.error, UnicodeDecodeError):
            raise SSOError("The sign-in response could not be read.")


def parse_response(base_url, s, saml_response, request_id):
    """Verify a POSTed SAMLResponse answering request_id. Returns
    {"name_id", "assertion_id", "not_on_or_after", "groups", "overage", "display_name", "authn_context"}."""
    from saml2 import BINDING_HTTP_POST
    from saml2.client import Saml2Client
    xml = _decoded(saml_response)
    if _SHA1_ALG.search(xml):
        raise SSOError("The identity provider signed with SHA-1, which is not accepted. "
                       "Configure it to sign with SHA-256.")
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        raise SSOError("The sign-in response could not be read.")
    client = Saml2Client(_config(base_url, s))
    try:
        resp = client.parse_authn_request_response(saml_response, BINDING_HTTP_POST,
                                                   outstanding={request_id: "/"})
    except Exception as e:  # signature, audience, time, InResponseTo, status: all refusals
        raise SSOError("The sign-in response was not accepted (%s)." % (type(e).__name__,))
    if resp is None or not resp.assertion:
        raise SSOError("The sign-in response contained no assertion.")
    ava = resp.ava or {}
    name_id = getattr(resp.name_id, "text", None) or ""
    if not name_id or len(name_id) > 256:
        raise SSOError("The sign-in response did not identify the user.")
    a = resp.assertion
    not_after = None
    if a.conditions is not None and a.conditions.not_on_or_after:
        not_after = a.conditions.not_on_or_after
    ctx = ""
    try:
        ctx = a.authn_statement[0].authn_context.authn_context_class_ref.text or ""
    except (AttributeError, IndexError):
        pass
    groups = [str(g).strip() for g in ava.get(s["group_attribute"], []) if str(g).strip()]
    names = ava.get(s["name_attribute"], [])
    return {"name_id": name_id, "assertion_id": a.id, "not_on_or_after": not_after,
            "groups": groups, "overage": GROUPS_OVERAGE in ava,
            "display_name": str(names[0])[:200] if names else "", "authn_context": ctx[:200]}


def role_for(groups, conn=None):
    """Highest role among the user's mapped groups, or None."""
    if not groups:
        return None, []
    rows = db.query("SELECT group_id, label, role FROM ui.sso_group_role WHERE lower(group_id) = ANY(%s)",
                    ([g.lower() for g in groups],), conn=conn)
    if not rows:
        return None, []
    best = max(rows, key=lambda r: ROLE_RANK[r["role"]])
    return best["role"], [r["label"] or r["group_id"] for r in rows]


def username_for(name_id, conn=None):
    """A free portal username derived from the NameID (UPN or object ID)."""
    base = re.sub(r"[^a-z0-9._-]", ".", name_id.lower().replace("@", "."))
    base = re.sub(r"\.+", ".", base).strip(".-_")[:56] or "sso-user"
    if len(base) < 2:
        base = "sso-" + base
    name, n = base, 1
    while db.query_one("SELECT 1 FROM ui.admin_user WHERE username = %s", (name,), conn=conn):
        n += 1
        name = "%s-%d" % (base, n)
    return name
