"""Root helper: integration_push_test (SPEC sections 5 and 29.3) against a fake Duo Auth API:
keys from the applied authproxy.cfg, signature v5 (HMAC-SHA512 over the JSON body), preauth
then a push, the result only, a rate limit, and no request at all for bad input."""
import base64
import datetime
import hashlib
import hmac
import http.server
import json
import os
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from test_helper import _write, env  # noqa: F401
from test_helper_duo import DUO, SETTINGS, denv  # noqa: F401

API = SETTINGS["api_host"]
EMPTY = hashlib.sha512(b"").hexdigest()


def _cert(tmp, name, ca=None, ca_key=None):
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject if ca else subject)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1)))
    if ca is None:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    else:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
    cert = b.sign(ca_key or key, hashes.SHA384())
    cp, kp = os.path.join(tmp, name + ".crt"), os.path.join(tmp, name + ".key")
    with open(cp, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cert, key, cp, kp


class FakeDuo:
    """Duo's Auth API as far as the helper uses it. Users: alice (enrolled, approves), bob
    (enrolled, denies), carol (does not answer), dave (not enrolled), eve (bypass)."""

    def __init__(self, tmp):
        ca, ca_key, self.ca_path, _ = _cert(tmp, "Test Duo CA")
        _, _, self.crt, self.key = _cert(tmp, API, ca, ca_key)
        self.requests, self.fail = [], None
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self._serve()

            def do_POST(self):
                self._serve()

            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                path, _, query = self.path.partition("?")
                canon = "\n".join([self.headers["Date"], self.command, API, path, query,
                                   hashlib.sha512(body.encode()).hexdigest(), EMPTY])
                good = "Basic " + base64.b64encode(("%s:%s" % (SETTINGS["ikey"], hmac.new(
                    SETTINGS["skey"].encode(), canon.encode(), hashlib.sha512).hexdigest())).encode()).decode()
                params = json.loads(body) if body else {}
                fake.requests.append({"path": path, "params": params, "auth": self.headers.get("Authorization"),
                                      "signed": self.headers.get("Authorization") == good,
                                      "type": self.headers.get("Content-Type"), "host": self.headers.get("Host")})
                if fake.fail:
                    out = fake.fail
                elif self.headers.get("Authorization") != good:
                    out = {"stat": "FAIL", "code": 40103, "message": "Invalid signature in request credentials"}
                elif path == "/auth/v2/preauth":
                    res = {"alice": "auth", "bob": "auth", "carol": "auth", "dave": "enroll", "eve": "allow"}
                    out = {"stat": "OK", "response": {"result": res.get(params.get("username"), "deny"),
                                                      "status_msg": "preauth for %s" % params.get("username")}}
                elif path == "/auth/v2/auth":
                    out = {"alice": {"result": "allow", "status": "allow", "status_msg": "Success. Logging you in..."},
                           "bob": {"result": "deny", "status": "deny", "status_msg": "Login request denied."},
                           "carol": {"result": "deny", "status": "timeout", "status_msg": "Login timed out."}
                           }[params["username"]]
                    out = {"stat": "OK", "response": out}
                else:
                    out = {"stat": "FAIL", "code": 40401, "message": "Resource not found"}
                data = json.dumps(out).encode()
                self.send_response(200 if out.get("stat") == "OK" else 401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.crt, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def paths(self):
        return [r["path"] for r in self.requests]


@pytest.fixture
def duo(denv):  # noqa: F811
    with open(denv.duocfg, "wb") as fh:          # the applied configuration
        fh.write(DUO)
    fake = FakeDuo(denv.root)
    os.chmod(fake.ca_path, 0o644)
    with open(denv.conf, "a") as fh:
        fh.write("duo_api_connect = 127.0.0.1:%d\nduo_api_cafile = %s\n" % (fake.port, fake.ca_path))
    yield denv, fake
    fake.httpd.shutdown()


def push(e, user):
    return e.call({"action": "integration_push_test", "id": "duo", "username": user})


def test_push_approved(duo):
    e, fake = duo
    r = push(e, "alice")
    assert r["ok"] is True and r["result"] == "allow" and r["status_msg"] == "Success. Logging you in..."
    assert fake.paths() == ["/auth/v2/preauth", "/auth/v2/auth"]
    assert all(q["signed"] for q in fake.requests)                       # v5, HMAC-SHA512
    assert all(q["type"] == "application/json" and q["host"] == API for q in fake.requests)
    assert fake.requests[1]["params"] == {"username": "alice", "factor": "push", "device": "auto"}
    sig = base64.b64decode(fake.requests[0]["auth"].split()[1]).decode().split(":")[1]
    assert len(sig) == 128                                                # SHA-512, never SHA-1
    text = json.dumps(r)
    assert SETTINGS["skey"] not in text and SETTINGS["ikey"] not in text
    assert set(r) == {"ok", "action", "message", "result", "status_msg", "pushed"} and r["pushed"] is True


@pytest.mark.parametrize("user,result,calls", [("bob", "deny", 2), ("carol", "timeout", 2),
                                               ("dave", "not_enrolled", 1), ("eve", "allow", 1)])
def test_push_outcomes(duo, user, result, calls):
    e, fake = duo
    r = push(e, user)
    assert r["ok"] is True and r["result"] == result and len(fake.requests) == calls
    assert r["pushed"] is (calls == 2)                    # only the auth call sends a push


def test_duo_refusal_is_an_error_result(duo):
    e, fake = duo
    fake.fail = {"stat": "FAIL", "code": 40103, "message": "Invalid signature in request credentials"}
    r = push(e, "alice")
    assert r["ok"] is True and r["result"] == "error" and "Invalid signature" in r["status_msg"]
    assert fake.paths() == ["/auth/v2/preauth"]


@pytest.mark.parametrize("user", ["", "a b", "x" * 65, "al\nice", "alice;rm", None, 5, "ali%63e"])
def test_bad_username_never_reaches_duo(duo, user):
    e, fake = duo
    r = push(e, user)
    assert r["ok"] is False and "username" in r["message"] and fake.requests == []


def test_rate_limit(duo):
    e, fake = duo
    assert push(e, "alice")["result"] == "allow"
    r = push(e, "alice")
    assert r["ok"] is False and "wait" in r["message"] and len(fake.requests) == 2
    assert push(e, "bob")["ok"] is True                                     # another user may
    state = os.path.join(e.work, "push-test.json")
    with open(state) as fh:
        assert "alice" not in fh.read()                                    # names are not kept
    # ten requests to Duo an hour overall, pushes or not
    now = time.time()
    with open(state, "w") as fh:
        json.dump({"tries": [[now - 100 - i, "x%d" % i, False] for i in range(10)]}, fh)
    r = push(e, "eve")
    assert r["ok"] is False and "10 test pushes an hour" in r["message"]


def test_a_refusal_before_any_push_does_not_hold_up_a_retry(duo):
    """Duo refused before sending a push (not enrolled, no access): nothing reached the phone,
    so the per-user wait does not start; the attempt still counts toward the hourly cap."""
    e, fake = duo
    for _ in range(2):
        r = push(e, "dave")
        assert r["ok"] is True and r["result"] == "not_enrolled" and r["pushed"] is False
    state = os.path.join(e.work, "push-test.json")
    with open(state) as fh:
        assert len(json.load(fh)["tries"]) == 2


def test_needs_an_applied_configuration(duo):
    e, fake = duo
    with open(e.duocfg, "wb") as fh:
        fh.write(b"; Duo sample\n[radius_server_auto]\nikey=\n")
    r = push(e, "alice")
    assert r["ok"] is False and "apply" in r["message"] and fake.requests == []
    os.unlink(os.path.join(e.duo, ".radius-admin"))
    r = push(e, "alice")
    assert r["ok"] is False and "not installed" in r["message"]


def test_certificate_must_verify(duo):
    e, fake = duo
    with open(e.conf) as fh:
        conf = fh.read()
    with open(e.conf, "w") as fh:                                             # system CAs: not ours
        fh.write("\n".join(ln for ln in conf.splitlines() if not ln.startswith("duo_api_cafile")) + "\n")
    r = push(e, "alice")
    assert r["ok"] is True and r["result"] == "error" and fake.requests == []
