"""Certificates page (SPEC section 30): upload, CSR, client CA, OCSP, staging and Apply diff."""
import datetime
import io
import json
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from conftest import stepup


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class Pki:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP384R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(_name("Example Test CA")).issuer_name(_name("Example Test CA"))
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                     .sign(self.key, hashes.SHA384()))

    def issue(self, public_key, cn="radius.example.net", sans=("radius.example.net",), days=90, ca=False,
              eku=ExtendedKeyUsageOID.SERVER_AUTH, past=False):
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=days + 10) if past else now - datetime.timedelta(minutes=5)
        end = now - datetime.timedelta(days=1) if past else now + datetime.timedelta(days=days)
        b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(self.cert.subject)
             .public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(start)
             .not_valid_after(end).add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if sans:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        if eku is not None:
            b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        return b.sign(self.key, hashes.SHA384())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key, password=None):
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


@pytest.fixture
def pki():
    return Pki()


@pytest.fixture
def admin(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    return u


def files(**kw):
    return {k: (io.BytesIO(v), k + ".pem") for k, v in kw.items()}


def upload(browser, kind, data):
    return browser.post("/certificates/%s/upload" % kind, data, csrf_page="/certificates/",
                        content_type="multipart/form-data")


def row(superconn, kind):
    with superconn.cursor() as cur:
        cur.execute("SELECT cert_pem, key_enc, csr_pem, csr_key_enc, source FROM ui.tls_cert WHERE kind = %s", (kind,))
        return cur.fetchone()


def flashes(browser):
    return browser.text(browser.get("/certificates/"))


def test_page_for_every_role_forms_for_admin_only(app, browser, superconn, logged_in):
    logged_in("viewer")
    t = browser.text(browser.get("/certificates/"))
    assert "802.1X server certificate" in t and "Client certificate CA" in t and "Portal HTTPS certificate" in t
    assert "Upload a certificate and key" not in t
    r = browser.post("/certificates/eap_server/upload", {}, csrf_page="/certificates/")
    assert r.status_code == 403


def test_upload_needs_stepup(app, browser, superconn, logged_in, pki):
    logged_in("admin")
    with superconn.cursor() as cur:
        cur.execute("UPDATE ui.session SET stepup_at = now() - interval '1 day'")
    k = ec.generate_private_key(ec.SECP384R1())
    r = upload(browser, "eap_server", files(cert_file=pem(pki.issue(k.public_key())), key_file=key_pem(k)))
    assert r.status_code == 302 and "/stepup" in r.headers["Location"]
    assert row(superconn, "eap_server") is None


def test_upload_eap_server_staged_and_applied(app, browser, superconn, admin, pki):
    k = ec.generate_private_key(ec.SECP384R1())
    c = pki.issue(k.public_key())
    r = upload(browser, "eap_server", files(cert_file=pem(c) + pem(pki.cert), key_file=key_pem(k)))
    assert r.status_code == 302
    cert_pem, key_enc, csr, _, source = row(superconn, "eap_server")
    assert source == "upload" and cert_pem.count("BEGIN CERTIFICATE") == 2
    assert b"PRIVATE KEY" not in bytes(key_enc)                     # stored encrypted
    with superconn.cursor() as cur:
        cur.execute("SELECT detail::text FROM ui.audit_log WHERE action = 'certificate.upload'")
        detail = cur.fetchone()[0]
    assert "radius.example.net" in detail and "PRIVATE" not in detail and "key" not in json.loads(detail)
    # the Apply page shows what changes, with the key only as a fingerprint
    t = browser.text(browser.get("/apply/"))
    assert "Certificates (private keys shown only as fingerprints)" in t
    assert "CN=radius.example.net" in t and "private key: SHA-256" in t and "BEGIN" not in t
    # validate stages the certificates file for the helper
    r = browser.post("/apply/validate", {}, csrf_page="/apply/")
    assert r.status_code == 200
    staged = json.load(open(os.path.join(app.config["RA"]["staging_dir"], "certificates")))
    assert staged["format"] == 1 and staged["eap_server"]["key"].startswith("-----BEGIN PRIVATE KEY-----")
    assert "client_ca" not in staged and "eap_ocsp" not in staged
    assert oct(os.stat(os.path.join(app.config["RA"]["staging_dir"], "certificates")).st_mode & 0o777) == "0o600"


@pytest.mark.parametrize("case,msg", [
    ("rsa2048", "not allowed"), ("mismatch", "does not belong"), ("expired", "expired"),
    ("ca_leaf", "CA certificate"), ("client_eku", "server authentication"), ("encrypted", "enter its password"),
    ("junk", "nothing else"),
])
def test_bad_uploads_refused(app, browser, superconn, admin, pki, case, msg):
    k = ec.generate_private_key(ec.SECP384R1())
    cert, key = pem(pki.issue(k.public_key())), key_pem(k)
    if case == "rsa2048":
        rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert, key = pem(pki.issue(rk.public_key())), key_pem(rk)
    elif case == "mismatch":
        key = key_pem(ec.generate_private_key(ec.SECP384R1()))
    elif case == "expired":
        cert = pem(pki.issue(k.public_key(), past=True))
    elif case == "ca_leaf":
        cert, key = pem(pki.cert), key_pem(pki.key)
    elif case == "client_eku":
        cert = pem(pki.issue(k.public_key(), eku=ExtendedKeyUsageOID.CLIENT_AUTH))
    elif case == "encrypted":
        key = key_pem(k, "Example-Pass-1")
    elif case == "junk":
        cert = cert + b"\n$INCLUDE /etc/shadow\n"
    upload(browser, "eap_server", files(cert_file=cert, key_file=key))
    assert row(superconn, "eap_server") is None
    assert msg in flashes(browser)


def test_encrypted_key_with_password_and_pkcs12(app, browser, superconn, admin, pki):
    k = ec.generate_private_key(ec.SECP256R1())
    c = pki.issue(k.public_key())
    upload(browser, "eap_server", dict(files(cert_file=pem(c), key_file=key_pem(k, "Example-Pass-1")),
                                       password="Example-Pass-1"))
    assert row(superconn, "eap_server") is not None
    rk = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    p12 = pkcs12.serialize_key_and_certificates(b"x", rk, pki.issue(rk.public_key()), [pki.cert],
                                                serialization.BestAvailableEncryption(b"Example-Pass-2"))
    upload(browser, "eap_server", {"p12_file": (io.BytesIO(p12), "s.p12"), "password": "Example-Pass-2"})
    cert_pem = row(superconn, "eap_server")[0]
    assert cert_pem.count("BEGIN CERTIFICATE") == 2
    assert x509.load_pem_x509_certificate(cert_pem.encode()).public_key().key_size == 3072


def test_csr_then_issued_certificate(app, browser, superconn, admin, pki):
    r = browser.post("/certificates/eap_server/csr", {"common_name": "radius.example.net",
                     "dns_names": "radius2.example.net", "key_type": "ecdsa-p384"}, csrf_page="/certificates/")
    assert r.status_code == 302
    _, _, csr_pem, csr_key, _ = row(superconn, "eap_server")
    assert csr_pem and csr_key and b"PRIVATE" not in bytes(csr_key)
    d = browser.get("/certificates/eap_server/request.csr")
    assert d.status_code == 200 and b"CERTIFICATE REQUEST" in d.data
    csr = x509.load_pem_x509_csr(d.data)
    names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert names == ["radius.example.net", "radius2.example.net"]
    # a certificate for another key is refused; the one issued for the request is accepted
    other = pki.issue(ec.generate_private_key(ec.SECP384R1()).public_key())
    browser.post("/certificates/eap_server/issued", files(cert_file=pem(other)), csrf_page="/certificates/",
                 content_type="multipart/form-data")
    assert row(superconn, "eap_server")[0] is None
    issued = pki.issue(csr.public_key(), sans=names)
    browser.post("/certificates/eap_server/issued", files(cert_file=pem(issued), chain_file=pem(pki.cert)),
                 csrf_page="/certificates/", content_type="multipart/form-data")
    cert_pem, key_enc, csr_pem, csr_key, source = row(superconn, "eap_server")
    assert source == "csr" and csr_pem is None and csr_key is None and key_enc
    # the stored key is the request's key
    from radius_admin import certs
    with app.app_context():
        key = serialization.load_pem_private_key(certs.managed_key(
            {"kind": "eap_server", "key_enc": key_enc}, app.config["RA_DATA_KEY"]).encode(), None)
    assert key.public_key().public_numbers() == csr.public_key().public_numbers()


def test_portal_certificate_must_name_the_portal(app, browser, superconn, admin, pki):
    app.fake_helper.cert_status = {"portal_configured": True, "portal_server_name": "radius.example.net"}
    k = ec.generate_private_key(ec.SECP384R1())
    upload(browser, "portal_server", files(cert_file=pem(pki.issue(k.public_key(), cn="x.example.net",
                                                                   sans=("x.example.net",))), key_file=key_pem(k)))
    assert row(superconn, "portal_server") is None
    assert "does not name radius.example.net" in flashes(browser)
    upload(browser, "portal_server", files(cert_file=pem(pki.issue(k.public_key())), key_file=key_pem(k)))
    assert row(superconn, "portal_server") is not None, flashes(browser)[flashes(browser).find("flash"):][:600]


def test_client_ca_and_forget(app, browser, superconn, admin, pki):
    k = ec.generate_private_key(ec.SECP384R1())
    upload(browser, "client_ca", files(cert_file=pem(pki.issue(k.public_key()))))
    assert row(superconn, "client_ca") is None and "is not a CA certificate" in flashes(browser)
    upload(browser, "client_ca", {"cert_text": pem(pki.cert).decode()})
    assert row(superconn, "client_ca")[0].startswith("-----BEGIN CERTIFICATE-----")
    browser.post("/certificates/client_ca/forget", {}, csrf_page="/certificates/")
    assert row(superconn, "client_ca") is None


def test_ocsp_setting(app, browser, superconn, admin):
    browser.post("/certificates/ocsp", {"mode": "on", "url": "ldap://x"}, csrf_page="/certificates/")
    assert "http(s) URL" in flashes(browser)
    browser.post("/certificates/ocsp", {"mode": "on", "url": "http://ocsp.example.net/ocsp"},
                 csrf_page="/certificates/")
    from radius_admin import services
    with app.test_request_context():
        files_ = services.render_provider_files()
    assert json.loads(files_["certificates"])["eap_ocsp"] == {"enable": True, "url": "http://ocsp.example.net/ocsp"}
    browser.post("/certificates/ocsp", {"mode": "keep", "url": ""}, csrf_page="/certificates/")
    with app.test_request_context():
        assert "certificates" not in services.render_provider_files()


def test_installed_certificates_shown(app, browser, superconn, logged_in):
    logged_in("viewer")
    app.fake_helper.cert_status = {
        "eap_server": [{"subject": "CN=radius.example.net", "issuer": "CN=radius-admin EAP CA radius.example.net",
                        "not_before": "Nov 20 12:00:00 2026 GMT", "not_after": "Nov 25 12:00:00 2026 GMT",
                        "sha256": "AB:" * 31 + "AB", "san": ["DNS:radius.example.net"], "key": "ECDSA P-384",
                        "ca": False, "expired": False}],
        "eap_ocsp": {"enable": False, "url": ""}, "portal_configured": True, "portal_server_name": "radius.example.net"}
    t = browser.text(browser.get("/certificates/"))
    assert "CN=radius-admin EAP CA radius.example.net" in t and "2026-11-25" in t and "ECDSA P-384" in t
    assert "made by the installer: replace it" in t and "expires in 4 days" in t


def test_rollback_before_portal_managed_certs_drops_applied_copy(app, browser, superconn, admin, pki):
    """A rollback that puts back certificate files from before the portal managed them leaves no
    applied certificates copy, so the next Apply shows (and installs) them all again."""
    k = ec.generate_private_key(ec.SECP384R1())
    upload(browser, "eap_server", files(cert_file=pem(pki.issue(k.public_key())), key_file=key_pem(k)))
    r = browser.post("/apply/apply", {}, csrf_page="/apply/")
    assert r.status_code == 200
    from radius_admin import services
    with app.app_context():
        app.config["RA"]  # noqa
        assert "certificates" in services.read_applied(app.config["RA"]["staging_dir"])["providers"]
    bid = app.fake_helper.backups[-1]
    app.fake_helper.fail_next["rollback"] = {"ok": True, "message": "rolled back", "backup_id": "20261023T999999Z",
                                            "certificates_changed": ["eap_cert", "eap_key"]}
    r = browser.post("/apply/rollback", {"backup_id": bid}, csrf_page="/apply/")
    assert r.status_code == 200
    assert "certificates" not in services.read_applied(app.config["RA"]["staging_dir"])["providers"]
    t = browser.text(browser.get("/apply/"))
    assert "@@ -0,0" in t and "[802.1X server certificate]" in t
