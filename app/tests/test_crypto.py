"""Pure crypto tests: RFC 6238 vectors, PBKDF2 formats, AES-GCM, FIPS check."""
import base64
import hashlib
import hmac
import struct

import pytest

from radius_admin import crypto


# RFC 6238 Appendix B, SHA1 mode, seed "12345678901234567890", 8 digits.
RFC6238_SHA1 = [
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
]


@pytest.mark.parametrize("t,expected", RFC6238_SHA1)
def test_rfc6238_vectors(t, expected):
    key = b"12345678901234567890"
    assert crypto.hotp(key, t // 30, digits=8) == expected


def test_rfc4226_hotp_vectors():
    key = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [crypto.hotp(key, i) for i in range(10)] == expected


def test_totp_verify_window_and_replay():
    key = b"12345678901234567890"
    now = 1234567890
    step = now // 30
    code = crypto.hotp(key, step)
    assert crypto.totp_verify(key, code, None, now=now) == step
    # previous / next step accepted (+-1), two steps away rejected
    assert crypto.totp_verify(key, crypto.hotp(key, step - 1), None, now=now) == step - 1
    assert crypto.totp_verify(key, crypto.hotp(key, step + 1), None, now=now) == step + 1
    assert crypto.totp_verify(key, crypto.hotp(key, step - 2), None, now=now) is None
    # replay: same or older step rejected
    assert crypto.totp_verify(key, code, step, now=now) is None
    assert crypto.totp_verify(key, crypto.hotp(key, step - 1), step - 1, now=now) is None
    assert crypto.totp_verify(key, "abcdef", None, now=now) is None
    assert crypto.totp_verify(key, "12345", None, now=now) is None


def test_fr_pbkdf2_format_exact():
    v = crypto.fr_pbkdf2_hash("Switch-Password-123", 600000)
    m = __import__("re").fullmatch(
        r"\{X-PBKDF2\}HMACSHA2\+256:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)", v)
    assert m, v
    it_raw = base64.b64decode(m.group(1), validate=True)
    assert len(it_raw) == 4 and struct.unpack(">I", it_raw)[0] == 600000
    assert m.group(1) == "AAknwA=="  # standard base64 WITH padding of 0x000927C0
    salt = base64.b64decode(m.group(2), validate=True)
    dk = base64.b64decode(m.group(3), validate=True)
    assert len(salt) == 16 and len(dk) == 32
    # independent recomputation, as rlm_pap does with PKCS5_PBKDF2_HMAC(sha256)
    assert hmac.compare_digest(dk, hashlib.pbkdf2_hmac("sha256", b"Switch-Password-123", salt, 600000, 32))
    assert crypto.fr_pbkdf2_verify("Switch-Password-123", v)
    assert not crypto.fr_pbkdf2_verify("Switch-Password-124", v)
    digest, iters, s2, d2 = crypto.fr_pbkdf2_parse(v)
    assert (digest, iters, s2, d2) == ("HMACSHA2+256", 600000, salt, dk)


def test_fr_pbkdf2_known_vector():
    # Deterministic check of the encoding against a fixed salt.
    salt = bytes(range(16))
    dk = hashlib.pbkdf2_hmac("sha256", b"password", salt, 600000, 32)
    expected = "{X-PBKDF2}HMACSHA2+256:AAknwA==:%s:%s" % (
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode())
    assert crypto.fr_pbkdf2_verify("password", expected)


def test_ui_password_hash_roundtrip():
    h = crypto.hash_password("A-very-long-password-1", 1000)
    assert h.startswith("pbkdf2-sha256$1000$")
    assert crypto.verify_password("A-very-long-password-1", h)
    assert not crypto.verify_password("A-very-long-password-2", h)
    assert not crypto.verify_password("x", "garbage")
    assert not crypto.verify_password("x", "bcrypt$1$a$b")


def test_aes_gcm_roundtrip_and_aad_binding():
    dk = crypto.DataKey(crypto.random_bytes(32))
    blob = dk.encrypt(b"secret-seed", b"user=1")
    assert dk.decrypt(blob, b"user=1") == b"secret-seed"
    with pytest.raises(Exception):
        dk.decrypt(blob, b"user=2")
    tampered = bytearray(blob)
    tampered[-1] ^= 1
    with pytest.raises(Exception):
        dk.decrypt(bytes(tampered), b"user=1")
    with pytest.raises(ValueError):
        crypto.DataKey(b"short")


def test_random_helpers():
    s = crypto.generate_radius_secret()
    assert len(s) == 32 and s.isalnum() and s.isascii()
    assert crypto.generate_radius_secret() != s
    t = crypto.generate_temp_password()
    assert len(t) == 20
    assert len(crypto.random_token(32)) == 43


def test_no_forbidden_randomness_or_hashes_in_app_code():
    import pathlib
    import re
    root = pathlib.Path(crypto.__file__).parent
    for p in root.rglob("*.py"):
        if p.name == "unlang.py":
            continue
        src = p.read_text()
        assert not re.search(r"^\s*(import random|from random|import secrets|from secrets)", src, re.M), p
        assert "os.urandom" not in src, p
        assert "uuid4" not in src, p
        assert not re.search(r"hashlib\.(md5|sha1)\b", src), p
        assert '"md5"' not in src.lower(), p


def test_fips_status_shape(monkeypatch, tmp_path):
    st = crypto.fips_status()
    assert set(st) >= {"kernel", "openssl", "ok"}
    f = tmp_path / "fips"
    f.write_text("0\n")
    monkeypatch.setattr(crypto, "FIPS_PROC", str(f))
    assert crypto.fips_status()["kernel"] is False
    with pytest.raises(crypto.FipsError):
        crypto.require_fips_or_die()


def test_app_refuses_start_without_fips(tmp_path, monkeypatch):
    from radius_admin import create_app
    f = tmp_path / "fips"
    f.write_text("0\n")
    monkeypatch.setattr(crypto, "FIPS_PROC", str(f))
    key = tmp_path / "k"
    key.write_bytes(crypto.random_bytes(32))
    with pytest.raises(crypto.FipsError):
        create_app(config_path="", overrides={"require_fips": True, "key_file": str(key)})


def test_cert_pem_to_der():
    from conftest import make_cert
    pem, sha, esc = make_cert()
    der = crypto.cert_pem_to_der(pem)
    assert hashlib.sha256(der).hexdigest() == sha
    with pytest.raises(ValueError):
        crypto.cert_pem_to_der("nope")
