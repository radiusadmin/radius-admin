"""Certificates managed in the portal (SPEC section 30).

Three certificates: the 802.1X (EAP) server certificate of FreeRADIUS, the CA bundle that issues
client certificates (trusted by FreeRADIUS for EAP-TLS and by the portal for client-certificate
sign-in) and the portal's own HTTPS certificate; plus the OCSP setting of EAP-TLS. A row in
ui.tls_cert means the portal manages that certificate; no row keeps whatever is installed.
Private keys are stored encrypted with the data key (AES-256-GCM). Changes reach the server
through Review and apply: render_bundle() is staged as the `certificates` file, and the root
helper checks it again, installs it, restarts FreeRADIUS / reloads nginx and rolls back.

Only FIPS-safe key types (SPEC section 7): RSA 3072 bits or more, ECDSA P-256 or P-384.
"""
import datetime
import hashlib
import json
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import db

KINDS = ("eap_server", "client_ca", "portal_server")
SERVER_KINDS = ("eap_server", "portal_server")
LABELS = {"eap_server": "802.1X server certificate", "client_ca": "Client certificate CA",
          "portal_server": "Portal HTTPS certificate"}
KEY_TYPES = {"ecdsa-p384": "ECDSA P-384", "ecdsa-p256": "ECDSA P-256", "rsa-3072": "RSA 3072", "rsa-4096": "RSA 4096"}
OCSP_MODES = ("keep", "off", "on")
OCSP_URL_RE = re.compile(r"\Ahttps?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,200})?\Z")
DNS_RE = re.compile(r"\A(?=.{1,253}\Z)(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
MAX_PEM = 64 * 1024
SIGNATURE_HASHES = ("sha256", "sha384", "sha512")


class CertError(ValueError):
    """A certificate, key or CSR that cannot be used; the message is shown to the admin."""


# ------------------------------------------------------------------ parsing and checks
def _text(data):
    if isinstance(data, bytes):
        try:
            data = data.decode("ascii")
        except UnicodeDecodeError:
            raise CertError("expected PEM text")
    return (data or "").replace("\r\n", "\n").strip()


def load_certs(data, what="certificate"):
    """PEM certificates (one or more), in order. Anything else in the text is refused."""
    text = _text(data)
    if not text:
        raise CertError("the %s is empty" % what)
    if len(text) > MAX_PEM:
        raise CertError("the %s is too large" % what)
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+?\n-----END CERTIFICATE-----", text)
    rest = re.sub(r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+?\n-----END CERTIFICATE-----", "", text)
    if not blocks or rest.strip():
        raise CertError("the %s must be PEM certificates (-----BEGIN CERTIFICATE-----) and nothing else" % what)
    out = []
    for b in blocks:
        try:
            out.append(x509.load_pem_x509_certificate(b.encode()))
        except ValueError:
            raise CertError("the %s contains a certificate that cannot be read" % what)
    return out


def load_key(data, password=None):
    text = _text(data)
    if not text or len(text) > MAX_PEM or "PRIVATE KEY-----" not in text:
        raise CertError("expected a PEM private key (-----BEGIN PRIVATE KEY-----)")
    try:
        return serialization.load_pem_private_key(text.encode(), password=password.encode() if password else None)
    except TypeError:
        raise CertError("the private key is encrypted: enter its password" if not password
                        else "the private key is not encrypted, or the password is wrong")
    except ValueError:
        raise CertError("the private key cannot be read" + (" (wrong password?)" if password else ""))


def key_desc(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA %d" % pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"secp256r1": "ECDSA P-256", "secp384r1": "ECDSA P-384"}.get(pub.curve.name, "ECDSA " + pub.curve.name)
    return type(pub).__name__.replace("PublicKey", "").replace("_", "") or "unknown"


def key_allowed(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return pub.key_size >= 3072
    return isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name in ("secp256r1", "secp384r1")


def _utc(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def _not_after(c):
    return _utc(getattr(c, "not_valid_after_utc", None) or c.not_valid_after)


def _not_before(c):
    return _utc(getattr(c, "not_valid_before_utc", None) or c.not_valid_before)


def _ext(c, cls):
    try:
        return c.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def is_ca(c):
    bc = _ext(c, x509.BasicConstraints)
    return bool(bc and bc.ca)


def sans(c):
    v = _ext(c, x509.SubjectAlternativeName)
    if not v:
        return []
    return ["DNS:" + n for n in v.get_values_for_type(x509.DNSName)] + \
           ["IP:" + str(n) for n in v.get_values_for_type(x509.IPAddress)]


def fingerprint(c):
    return c.fingerprint(hashes.SHA256()).hex(":").upper()


def describe(c):
    now = datetime.datetime.now(datetime.timezone.utc)
    na = _not_after(c)
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "not_before": _not_before(c), "not_after": na, "days_left": (na - now).days,
            "expired": na <= now, "sha256": fingerprint(c), "san": sans(c), "key": key_desc(c.public_key()),
            "ca": is_ca(c), "self_signed": c.subject == c.issuer}


def _pem(certs):
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _same_key(cert, key):
    f = serialization.PublicFormat.SubjectPublicKeyInfo
    e = serialization.Encoding.DER
    return cert.public_key().public_bytes(e, f) == key.public_key().public_bytes(e, f)


def check_server(certs, key, server_name=None, what="certificate"):
    """A server certificate (leaf first, then intermediates) and its key, as the helper checks
    them (SPEC section 30). Returns (cert_pem, key_pem)."""
    leaf = certs[0]
    now = datetime.datetime.now(datetime.timezone.utc)
    if _not_after(leaf) <= now:
        raise CertError("the %s expired on %s" % (what, _not_after(leaf).strftime("%Y-%m-%d")))
    if is_ca(leaf):
        raise CertError("the first certificate is a CA certificate; put the server certificate first")
    if not key_allowed(leaf.public_key()):
        raise CertError("key type %s is not allowed: use RSA 3072 or larger, or ECDSA P-256 / P-384"
                        % key_desc(leaf.public_key()))
    alg = leaf.signature_hash_algorithm
    if alg is None or alg.name not in SIGNATURE_HASHES:
        raise CertError("the %s is signed with %s, which is not allowed (SHA-256, SHA-384 or SHA-512 only)"
                        % (what, alg.name if alg else "an unknown hash"))
    eku = _ext(leaf, x509.ExtendedKeyUsage)
    if eku is not None and ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        raise CertError("the %s is not for server authentication (extended key usage)" % what)
    if key is not None and not _same_key(leaf, key):
        raise CertError("the private key does not belong to the %s" % what)
    if server_name and "dns:" + server_name.lower() not in [s.lower() for s in sans(leaf)]:
        raise CertError("the %s does not name %s (subject alternative name)" % (what, server_name))
    for c in certs[1:]:
        if not is_ca(c):
            raise CertError("after the server certificate only CA certificates (the chain) may follow")
    return _pem(certs), (_key_pem(key) if key is not None else None)


def check_ca_bundle(certs):
    now = datetime.datetime.now(datetime.timezone.utc)
    for c in certs:
        if not is_ca(c):
            raise CertError("%s is not a CA certificate" % c.subject.rfc4514_string())
        if _not_after(c) <= now:
            raise CertError("%s expired on %s" % (c.subject.rfc4514_string(), _not_after(c).strftime("%Y-%m-%d")))
    return _pem(certs)


def load_pkcs12(data, password):
    """A .p12/.pfx file: (certs leaf first, key)."""
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, password.encode() if password else None)
    except ValueError:
        raise CertError("the PKCS#12 file cannot be read (wrong password?)")
    if key is None or cert is None:
        raise CertError("the PKCS#12 file must hold a certificate and its private key")
    return [cert] + list(extra or []), key


# ------------------------------------------------------------------ CSR
def generate_csr(common_name, dns_names, key_type="ecdsa-p384"):
    """(csr_pem, key_pem) for a server certificate."""
    if key_type not in KEY_TYPES:
        raise CertError("unknown key type")
    names = []
    for n in [common_name] + list(dns_names):
        n = (n or "").strip().lower()
        if n and n not in names:
            if not DNS_RE.match(n):
                raise CertError("%r is not a DNS name" % n)
            names.append(n)
    if not names:
        raise CertError("give the server's DNS name")
    if key_type.startswith("rsa-"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=int(key_type[4:]))
    else:
        key = ec.generate_private_key(ec.SECP384R1() if key_type == "ecdsa-p384" else ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .sign(key, hashes.SHA384() if key_type != "ecdsa-p256" else hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode(), _key_pem(key)


def csr_info(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    try:
        names = ["DNS:" + n for n in csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    return {"subject": csr.subject.rfc4514_string(), "san": names, "key": key_desc(csr.public_key())}


# ------------------------------------------------------------------ storage
def _aad(kind, what):
    return ("radius-admin:tls_cert:%s:%s" % (kind, what)).encode()


def rows(conn=None):
    return {r["kind"]: r for r in db.query(
        "SELECT kind, cert_pem, key_enc, csr_pem, csr_key_enc, source, updated_at, updated_by FROM ui.tls_cert",
        conn=conn)}


def save_cert(kind, cert_pem, key_pem, datakey, actor, source="upload"):
    key_enc = datakey.encrypt(key_pem.encode(), _aad(kind, "key")) if key_pem else None
    db.execute("INSERT INTO ui.tls_cert (kind, cert_pem, key_enc, source, updated_at, updated_by)"
               " VALUES (%s, %s, %s, %s, now(), %s)"
               " ON CONFLICT (kind) DO UPDATE SET cert_pem = EXCLUDED.cert_pem, key_enc = EXCLUDED.key_enc,"
               " source = EXCLUDED.source, updated_at = now(), updated_by = EXCLUDED.updated_by",
               (kind, cert_pem, key_enc, source, actor))


def save_csr(kind, csr_pem, key_pem, datakey, actor):
    enc = datakey.encrypt(key_pem.encode(), _aad(kind, "csr_key"))
    db.execute("INSERT INTO ui.tls_cert (kind, csr_pem, csr_key_enc, updated_at, updated_by)"
               " VALUES (%s, %s, %s, now(), %s)"
               " ON CONFLICT (kind) DO UPDATE SET csr_pem = EXCLUDED.csr_pem, csr_key_enc = EXCLUDED.csr_key_enc,"
               " updated_at = now(), updated_by = EXCLUDED.updated_by",
               (kind, csr_pem, enc, actor))


def csr_key(row, datakey):
    return serialization.load_pem_private_key(
        datakey.decrypt(bytes(row["csr_key_enc"]), _aad(row["kind"], "csr_key")), password=None)


def complete_csr(kind, cert_pem, key_pem, datakey, actor):
    """The issued certificate for the pending CSR: it and the CSR's key become the managed pair."""
    db.execute("UPDATE ui.tls_cert SET cert_pem = %s, key_enc = %s, source = 'csr', csr_pem = NULL,"
               " csr_key_enc = NULL, updated_at = now(), updated_by = %s WHERE kind = %s",
               (cert_pem, datakey.encrypt(key_pem.encode(), _aad(kind, "key")), actor, kind))


def forget(kind, what="all"):
    if what == "csr":
        db.execute("UPDATE ui.tls_cert SET csr_pem = NULL, csr_key_enc = NULL, updated_at = now() WHERE kind = %s",
                   (kind,))
        db.execute("DELETE FROM ui.tls_cert WHERE kind = %s AND cert_pem IS NULL", (kind,))
    else:
        db.execute("DELETE FROM ui.tls_cert WHERE kind = %s", (kind,))


def managed_key(row, datakey):
    return datakey.decrypt(bytes(row["key_enc"]), _aad(row["kind"], "key")).decode()


def ocsp_setting(settings):
    mode = settings.get("eap_ocsp") or "keep"
    return (mode if mode in OCSP_MODES else "keep"), settings.get("eap_ocsp_url") or ""


# ------------------------------------------------------------------ the staged file
def render_bundle(conn, datakey, settings):
    """The `certificates` file for the helper, or None when the portal manages nothing."""
    doc = {}
    for kind, r in rows(conn).items():
        if not r["cert_pem"]:
            continue
        if kind == "client_ca":
            doc[kind] = r["cert_pem"]
        elif r["key_enc"] is not None:
            doc[kind] = {"cert": r["cert_pem"], "key": managed_key(r, datakey)}
    mode, url = ocsp_setting(settings)
    if mode != "keep":
        doc["eap_ocsp"] = {"enable": mode == "on", "url": url if mode == "on" else ""}
    if not doc:
        return None
    return json.dumps(dict({"format": 1}, **doc), sort_keys=True, indent=1) + "\n"


def summary(bundle_text):
    """The staged file as lines an admin can review: no keys, only their fingerprints."""
    if not bundle_text:
        return ""
    try:
        doc = json.loads(bundle_text)
    except ValueError:
        return "(unreadable)"
    out = []
    for kind in KINDS:
        v = doc.get(kind)
        if v is None:
            continue
        pem = v if kind == "client_ca" else v.get("cert", "")
        out.append("[%s]" % LABELS[kind])
        try:
            for c in load_certs(pem):
                d = describe(c)
                out.append("  %s  (issuer %s)" % (d["subject"], d["issuer"]))
                out.append("    valid until %s, %s, SHA-256 %s" % (d["not_after"].strftime("%Y-%m-%d"), d["key"],
                                                                   d["sha256"][:23]))
        except CertError as e:
            out.append("  %s" % e)
        if kind != "client_ca":
            out.append("  private key: SHA-256 %s" % hashlib.sha256(v.get("key", "").encode()).hexdigest()[:16])
    if "eap_ocsp" in doc:
        o = doc["eap_ocsp"]
        out.append("[OCSP for EAP-TLS]")
        out.append("  %s" % (("on, responder " + o.get("url", "")) if o.get("enable") else "off"))
    return "\n".join(out) + "\n"
