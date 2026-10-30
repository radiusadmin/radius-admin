"""SAML single sign-on against a real pysaml2 identity provider (throwaway RSA-3072 key)."""
import base64
import datetime
from urllib.parse import parse_qs, urlparse

import pytest
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT
from saml2.config import IdPConfig
from saml2.metadata import entity_descriptor
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_PERSISTENT, NameID
from saml2.server import Server
from saml2.xmldsig import DIGEST_SHA1, DIGEST_SHA256, SIG_RSA_SHA1, SIG_RSA_SHA256

from conftest import BASE_URL, Browser, login
from radius_admin.sso import GROUPS_ENTRA, GROUPS_OVERAGE, NAME_ENTRA

IDP_ENTITY = "https://idp.example.net/saml"
SP_ENTITY = BASE_URL + "/saml/metadata"
ACS = BASE_URL + "/saml/acs"


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def _key_and_cert(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.net")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    kp, cp = tmp_path / "idp.key", tmp_path / "idp.pem"
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(kp), str(cp)


@pytest.fixture
def idp(app, tmp_path, superconn):
    """A pysaml2 IdP trusting this console; the console configured to trust it."""
    b = Browser(app)
    sp_md = b.text(b.get("/saml/metadata"))
    kp, cp = _key_and_cert(tmp_path)
    c = IdPConfig()
    c.load({"entityid": IDP_ENTITY, "xmlsec_binary": "/usr/bin/xmlsec1", "key_file": kp, "cert_file": cp,
            "allow_unknown_attributes": True,
            "service": {"idp": {"endpoints": {"single_sign_on_service": [("https://idp.example.net/sso",
                                                                          BINDING_HTTP_REDIRECT)]},
                                "name_id_format": [NAMEID_FORMAT_PERSISTENT],
                                "policy": {"default": {"lifetime": {"minutes": 15}, "attribute_restrictions": None,
                                                       "name_form": NAME_FORMAT_URI}}}},
            "metadata": {"inline": [sp_md]}})
    server = Server(config=c)
    md = str(entity_descriptor(c))
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('saml_enabled','true'), ('saml_idp_metadata', %s)"
                 " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (md,))
    q(superconn, "INSERT INTO ui.sso_group_role (group_id, label, role) VALUES"
                 " ('g-view','Viewers','viewer'), ('g-ops','Operators','operator'), ('G-ADM','Admins','admin')")
    server.metadata_xml = md
    return server


def start(b, stepup=False, nxt=None):
    """Banner + /saml/login -> (request id, ForceAuthn flag)."""
    if not stepup:
        b.post("/banner", {"accept": "1"}, csrf_page="/login")
    url = "/saml/login" + ("?stepup=1" if stepup else "") + (("&" if stepup else "?") + "next=" + nxt if nxt else "")
    r = b.get(url)
    assert r.status_code == 302, b.text(r)
    loc = r.headers["Location"]
    assert loc.startswith("https://idp.example.net/sso?")
    return loc


def answer(idp, loc, name_id="alice@example.net", groups=("g-ops",), sign=True, sha1=False, extra=None,
           tamper=None, in_response_to=None):
    req = idp.parse_authn_request(parse_qs(urlparse(loc).query)["SAMLRequest"][0], BINDING_HTTP_REDIRECT)
    identity = {GROUPS_ENTRA: list(groups), NAME_ENTRA: ["Alice Example"]}
    identity.update(extra or {})
    resp = idp.create_authn_response(
        identity, in_response_to or req.message.id, ACS, SP_ENTITY,
        name_id=NameID(format=NAMEID_FORMAT_PERSISTENT, text=name_id),
        authn={"class_ref": PASSWORDPROTECTEDTRANSPORT}, sign_assertion=sign, sign_response=False,
        sign_alg=SIG_RSA_SHA1 if sha1 else SIG_RSA_SHA256, digest_alg=DIGEST_SHA1 if sha1 else DIGEST_SHA256)
    xml = str(resp)
    if tamper:
        xml = xml.replace(*tamper)
    return base64.b64encode(xml.encode()).decode(), req


def post_acs(b, saml_response):
    return b.post("/saml/acs", {"SAMLResponse": saml_response}, csrf=False,
                  headers={"Origin": "https://idp.example.net"}, origin=False)


def sso_login(b, idp, **kw):
    resp, _ = answer(idp, start(b), **kw)
    return post_acs(b, resp)


# ------------------------------------------------------------------ sign-in
def test_sso_sign_in_creates_user_with_mapped_role(app, idp, superconn):
    b = Browser(app)
    r = sso_login(b, idp)
    assert r.status_code == 200 and 'http-equiv="refresh" content="0;url=/dashboard' in b.text(r)
    t = b.text(b.get("/dashboard"))
    assert "Alice Example" in t and "operator" in t
    assert q(superconn, "SELECT username, role, auth_source, saml_name_id, mfa_method FROM ui.admin_user") == [
        ("alice.example.net", "operator", "saml", "alice@example.net", None)]
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='auth.login' AND success")[0][0]
    assert d["method"] == "saml" and d["groups"] == ["Operators"]
    # SSO users have no password: the local form refuses them
    b2 = Browser(app)
    r = b2.post("/banner", {"accept": "1"}, csrf_page="/login")
    r = b2.post("/login", {"username": "alice.example.net", "password": "!saml"})
    assert r.status_code == 401


def test_highest_role_wins_and_role_follows_groups(app, idp, superconn):
    sso_login(Browser(app), idp, groups=("g-view", "g-adm"))       # group IDs compare case-insensitively
    assert q(superconn, "SELECT role FROM ui.admin_user") == [("admin",)]
    sso_login(Browser(app), idp, groups=("g-view",))
    assert q(superconn, "SELECT role FROM ui.admin_user") == [("viewer",)]
    assert q(superconn, "SELECT detail->>'to' FROM ui.audit_log WHERE action='ui_admin.role'") == [("viewer",)]


@pytest.mark.parametrize("kw,text", [
    ({"groups": ("unmapped",)}, "not in a group that has access"),
    ({"groups": (), "extra": {GROUPS_OVERAGE: ["https://graph.microsoft.com/v1.0/users/x/getMemberObjects"]}},
     "too many groups"),
    ({"sign": False}, "not accepted"),
    ({"sha1": True}, "SHA-1"),
    ({"tamper": ("g-view", "G-ADM"), "groups": ("g-view",)}, "not accepted"),
    ({"in_response_to": "id-not-ours"}, "expired or was started in another browser"),
])
def test_refused_responses(app, idp, superconn, kw, text):
    b = Browser(app)
    r = sso_login(b, idp, **kw)
    assert r.status_code == 401 and text in b.text(r), b.text(r)
    assert q(superconn, "SELECT count(*) FROM ui.admin_user")[0][0] == 0
    assert b.get("/dashboard").status_code == 302
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action='auth.login' AND NOT success")[0][0] == 1


def test_response_bound_to_browser_and_single_use(app, idp):
    b, other = Browser(app), Browser(app)
    resp, _ = answer(idp, start(b))
    other.post("/banner", {"accept": "1"}, csrf_page="/login")
    r = post_acs(other, resp)                   # no nonce cookie for this request
    assert r.status_code == 401 and "another browser" in other.text(r)
    resp, _ = answer(idp, start(b))
    assert post_acs(b, resp).status_code == 200
    assert post_acs(b, resp).status_code == 401  # replayed


def test_disabled_sso_user_refused(app, idp, superconn):
    sso_login(Browser(app), idp)
    q(superconn, "UPDATE ui.admin_user SET enabled=false")
    b = Browser(app)
    r = sso_login(b, idp)
    assert r.status_code == 401 and "disabled" in b.text(r)


def test_sso_off_means_no_endpoints(app, browser, superconn):
    assert browser.get("/saml/login").status_code == 404
    assert browser.post("/saml/acs", {"SAMLResponse": "x"}, csrf=False).status_code == 404
    assert "Sign in with single sign-on" not in browser.text(browser.get("/login"))


# ------------------------------------------------------------------ step-up and account
def test_sso_stepup_uses_force_authn(app, idp, superconn):
    b = Browser(app)
    sso_login(b, idp, groups=("g-adm",))
    q(superconn, "UPDATE ui.session SET stepup_at = now() - interval '1 day'")
    r = b.get("/stepup?next=/settings/sso")
    assert r.status_code == 302 and "/saml/login?stepup=1" in r.headers["Location"]
    loc = start(b, stepup=True, nxt="/settings/sso")
    resp, req = answer(idp, loc, groups=("g-adm",))
    assert req.message.force_authn == "true"
    r = post_acs(b, resp)
    assert r.status_code == 200 and "url=/settings/sso" in b.text(r)
    assert b.get("/settings/sso").status_code == 200
    assert q(superconn, "SELECT detail->>'method' FROM ui.audit_log WHERE action='auth.stepup'") == [("saml",)]
    # someone else's assertion cannot step up this session
    q(superconn, "UPDATE ui.session SET stepup_at = now() - interval '1 day'")
    resp, _ = answer(idp, start(b, stepup=True), name_id="mallory@example.net", groups=("g-adm",))
    assert post_acs(b, resp).status_code == 401


def test_sso_user_has_no_password_or_mfa_pages(app, idp):
    b = Browser(app)
    sso_login(b, idp)
    for path in ("/account/password", "/account/mfa"):
        r = b.get(path)
        assert r.status_code == 302 and r.headers["Location"].endswith("/account/")
    assert "Single sign-on" in b.text(b.get("/account/"))


def test_local_passwords_for_admins_only(app, idp, superconn, make_user):
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('saml_local_login','admins')"
                 " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
    op = make_user(username="op1", role="operator")
    r = login(Browser(app), superconn, op, expect_ok=False)
    assert r.status_code == 401
    adm = make_user(username="adm1", role="admin")
    login(Browser(app), superconn, adm)                       # break-glass admin still works


# ------------------------------------------------------------------ settings page
def test_settings_page(app, browser, superconn, logged_in, idp):
    logged_in("admin")
    t = browser.text(browser.get("/settings/sso"))
    assert SP_ENTITY in t and ACS in t and IDP_ENTITY in t
    base = {"group_attribute": GROUPS_ENTRA, "name_attribute": NAME_ENTRA, "local_login": "all", "enabled": "1"}
    r = browser.post("/settings/sso", dict(base, idp_metadata="<not xml"))
    assert r.status_code == 400 and "could not be read" in browser.text(r)
    r = browser.post("/settings/sso", dict(base, idp_metadata='<!DOCTYPE x [<!ENTITY a "b">]><x/>'))
    assert r.status_code == 400
    q(superconn, "DELETE FROM ui.sso_group_role")
    r = browser.post("/settings/sso", dict(base, idp_metadata=idp.metadata_xml))
    assert r.status_code == 400 and "Map at least one group" in browser.text(r)
    r = browser.post("/settings/sso/groups", {"group_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                                              "label": "Admins", "role": "admin"})
    assert r.status_code == 302
    r = browser.post("/settings/sso", dict(base, idp_metadata=idp.metadata_xml, local_login="admins"))
    assert r.status_code == 302
    assert dict(q(superconn, "SELECT key, value FROM ui.setting WHERE key LIKE %s", ("saml_%",)))[
        "saml_local_login"] == "admins"
    mid = q(superconn, "SELECT id FROM ui.sso_group_role")[0][0]
    r = browser.post("/settings/sso/groups/%d/delete" % mid, {})
    assert "keep at least one mapping" in browser.text(browser.get("/settings/sso"))
    actions = [a for (a,) in q(superconn, "SELECT action FROM ui.audit_log WHERE action LIKE %s ORDER BY id", ("sso.%",))]
    assert actions == ["sso.group_add", "sso.settings"]


def test_settings_page_admin_only(browser, logged_in):
    logged_in("operator")
    assert browser.get("/settings/sso").status_code == 403
