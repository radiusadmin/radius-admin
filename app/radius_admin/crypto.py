"""All cryptographic primitives used by the app (SPEC section 7).

* Randomness: ssl.RAND_bytes only (OpenSSL DRBG, FIPS provider when enabled).
* Hashing / MAC: hashlib / hmac (OpenSSL-backed).
* Password hashing: PBKDF2-HMAC-SHA256.
* Encryption at rest: AES-256-GCM via python3-cryptography (system libssl).
* TOTP: RFC 6238 HMAC-SHA1 (approved for HMAC use), implemented on stdlib hmac.
"""
import base64
import hashlib
import hmac
import os
import ssl
import struct
import time

FIPS_PROC = "/proc/sys/crypto/fips_enabled"

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
# Temp passwords avoid look-alike characters.
TEMP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


# --------------------------------------------------------------------- random
def random_bytes(n: int) -> bytes:
    return ssl.RAND_bytes(n)


def random_token(nbytes: int = 32) -> str:
    """URL-safe token (no padding) from RAND_bytes."""
    return base64.urlsafe_b64encode(random_bytes(nbytes)).rstrip(b"=").decode("ascii")


def random_string(length: int, alphabet: str = ALNUM) -> str:
    """Uniform random string via rejection sampling over RAND_bytes."""
    n = len(alphabet)
    limit = 256 - (256 % n)
    out = []
    while len(out) < length:
        for b in random_bytes(max(16, length * 2)):
            if b < limit:
                out.append(alphabet[b % n])
                if len(out) == length:
                    break
    return "".join(out)


def generate_radius_secret() -> str:
    return random_string(32, ALNUM)


def generate_temp_password() -> str:
    # 20 chars from a 57-char alphabet ~ 116 bits.
    return random_string(20, TEMP_ALPHABET)


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def constant_time_eq(a, b) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


# ------------------------------------------------------- UI password hashing
UI_HASH_PREFIX = "pbkdf2-sha256"


def hash_password(password: str, iterations: int = 600000) -> str:
    salt = random_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)
    return "%s$%d$%s$%s" % (
        UI_HASH_PREFIX,
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        prefix, iters, salt_b64, hash_b64 = stored.split("$")
        if prefix != UI_HASH_PREFIX:
            return False
        iters = int(iters)
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
    except (ValueError, AttributeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, len(expected))
    return hmac.compare_digest(dk, expected)


_DUMMY_SALT = None


def dummy_password_work(iterations: int = 600000) -> None:
    """Spend the same time as a real verify (unknown-user timing equalisation)."""
    global _DUMMY_SALT
    if _DUMMY_SALT is None:
        _DUMMY_SALT = random_bytes(16)
    hashlib.pbkdf2_hmac("sha256", b"dummy-password-for-timing", _DUMMY_SALT, iterations, 32)


# ------------------------------------------ FreeRADIUS rlm_pap PBKDF2 format
FR_PBKDF2_HEADER = "{X-PBKDF2}"


def fr_pbkdf2_hash(password: str, iterations: int = 600000) -> str:
    """Value for radcheck `Password-With-Header :=`, accepted by rlm_pap 3.2.x.

    {X-PBKDF2}HMACSHA2+256:<b64(uint32 BE iterations)>:<b64 salt>:<b64 dk>
    """
    salt = random_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return "%sHMACSHA2+256:%s:%s:%s" % (
        FR_PBKDF2_HEADER, b64(struct.pack(">I", iterations)), b64(salt), b64(dk))


def fr_pbkdf2_parse(value: str):
    """Parse a {X-PBKDF2} value -> (digest, iterations, salt, dk). Raises ValueError."""
    if not value.startswith(FR_PBKDF2_HEADER):
        raise ValueError("missing {X-PBKDF2} header")
    parts = value[len(FR_PBKDF2_HEADER):].split(":")
    if len(parts) != 4:
        raise ValueError("expected 4 colon-separated fields")
    digest, it_b64, salt_b64, dk_b64 = parts
    it_raw = base64.b64decode(it_b64, validate=True)
    if len(it_raw) != 4:
        raise ValueError("iterations must be 4 bytes")
    (iterations,) = struct.unpack(">I", it_raw)
    return digest, iterations, base64.b64decode(salt_b64, validate=True), base64.b64decode(dk_b64, validate=True)


def fr_pbkdf2_verify(password: str, value: str) -> bool:
    digest, iterations, salt, dk = fr_pbkdf2_parse(value)
    if digest != "HMACSHA2+256":
        raise ValueError("unsupported digest " + digest)
    calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, len(dk))
    return hmac.compare_digest(calc, dk)


# ----------------------------------------------------------------- AES-GCM
class DataKey:
    """AES-256-GCM wrapper for secrets at rest (TOTP seeds)."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("data key must be exactly 32 bytes")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self._aead = AESGCM(key)

    @classmethod
    def from_file(cls, path: str) -> "DataKey":
        with open(path, "rb") as fh:
            key = fh.read()
        return cls(key)

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        nonce = random_bytes(12)
        return b"\x01" + nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, blob: bytes, aad: bytes) -> bytes:
        blob = bytes(blob)
        if len(blob) < 1 + 12 + 16 or blob[0] != 1:
            raise ValueError("bad ciphertext")
        return self._aead.decrypt(blob[1:13], blob[13:], aad)


# -------------------------------------------------------------------- TOTP
TOTP_PERIOD = 30
TOTP_DIGITS = 6


def hotp(key: bytes, counter: int, digits: int = TOTP_DIGITS, digest: str = "sha1") -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_now_step(now: float = None) -> int:
    return int((time.time() if now is None else now) // TOTP_PERIOD)


def totp_verify(key: bytes, code: str, last_step, now: float = None, window: int = 1):
    """Return the matched time step, or None. Rejects steps <= last_step (replay)."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    current = totp_now_step(now)
    matched = None
    for step in range(current - window, current + window + 1):
        # Check every candidate so timing does not depend on which step matched.
        if hmac.compare_digest(hotp(key, step).encode(), code.encode()):
            matched = step
    if matched is None:
        return None
    if last_step is not None and matched <= last_step:
        return None
    return matched


def totp_new_secret() -> bytes:
    return random_bytes(20)


def b32(secret: bytes) -> str:
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def totp_uri(secret: bytes, account: str, issuer: str) -> str:
    from urllib.parse import quote
    label = quote(f"{issuer}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={b32(secret)}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}")


# --------------------------------------------------------------- FIPS check
def fips_status():
    """Return dict(kernel=bool|None, openssl=bool|None, ok=bool)."""
    kernel = None
    try:
        with open(FIPS_PROC) as fh:
            kernel = fh.read().strip() == "1"
    except OSError:
        kernel = None
    openssl = None
    try:
        import _hashlib
        openssl = _hashlib.get_fips_mode() == 1
    except (ImportError, AttributeError, ValueError):
        openssl = None
    return {"kernel": kernel, "openssl": openssl, "ok": bool(kernel) and bool(openssl),
            "openssl_version": ssl.OPENSSL_VERSION}


class FipsError(RuntimeError):
    pass


def require_fips_or_die():
    st = fips_status()
    if not st["ok"]:
        raise FipsError(
            "FIPS mode required but not active (kernel fips_enabled=%s, OpenSSL FIPS mode=%s). "
            "Set require_fips = false only for testing." % (st["kernel"], st["openssl"]))
    return st


# ---------------------------------------------------------- client certs
def cert_pem_to_der(pem: str) -> bytes:
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    s = pem.find(begin)
    e = pem.find(end, s + 1)
    if s < 0 or e < 0:
        raise ValueError("not a PEM certificate")
    body = "".join(pem[s + len(begin):e].split())
    return base64.b64decode(body, validate=True)


def cert_subject(der: bytes) -> str:
    try:
        from cryptography import x509
        return x509.load_der_x509_certificate(der).subject.rfc4514_string()
    except Exception:  # pragma: no cover - informational only
        return ""


def read_or_create_key(path: str) -> DataKey:
    """Used by tests / first-run tooling only; production key is created by install.sh."""
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "wb") as fh:
            fh.write(random_bytes(32))
    return DataKey.from_file(path)
