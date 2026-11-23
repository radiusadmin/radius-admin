"""tools/licence/licence-tool.py: key generation, issuing, the register, the local web page,
and that the app accepts exactly what the tool signs. Throwaway homes only."""
import datetime
import http.client
import importlib.util
import json
import os
import re
import sys
import threading
import http.server
import urllib.parse

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "app"))
spec = importlib.util.spec_from_file_location("licence_tool", os.path.join(ROOT, "tools/licence/licence-tool.py"))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

from radius_admin import licence as app_licence   # noqa: E402

D = datetime.date


@pytest.fixture
def home(tmp_path):
    h = tool.Home(str(tmp_path / "home"))
    h.keygen()
    return h


def app_keys(home):
    return app_licence.load_public_keys(os.path.dirname(home.pub_file))


def test_keygen_modes_and_refuses_to_replace(home):
    assert os.stat(home.key_file).st_mode & 0o777 == 0o600
    assert os.stat(home.path).st_mode & 0o777 == 0o700
    with pytest.raises(tool.ToolError, match="refusing to replace"):
        home.keygen()


def test_issue_is_accepted_by_the_app(home):
    lid, path, text = home.issue("Example Corp", "250-999", today=D(2026, 12, 1))
    assert lid == "RA-2026-0001" and os.stat(path).st_mode & 0o777 == 0o600
    lic = app_licence.parse(text, app_keys(home))
    assert lic["licensee"] == "Example Corp" and lic["tier"] == "250-999"
    assert lic["starts"] == D(2026, 12, 1) and lic["expires"] == D(2027, 11, 30)
    assert home.issue("Example Org", today=D(2026, 12, 2))[0] == "RA-2026-0002"
    assert home.issue("Example Org", today=D(2027, 1, 2))[0] == "RA-2027-0001"
    assert [r["licence_id"] for r in home.register()] == ["RA-2026-0001", "RA-2026-0002", "RA-2027-0001"]


def test_leap_day_and_exception_without_end(home):
    _, _, text = home.issue("Example Corp", starts="2028-02-29", today=D(2028, 2, 1))
    assert app_licence.parse(text, app_keys(home))["expires"] == D(2029, 2, 28)
    _, _, text = home.issue("Example Corp", "", "exception", today=D(2028, 2, 1))
    assert app_licence.parse(text, app_keys(home))["expires"] is None


@pytest.mark.parametrize("kw, message", [
    ({"licensee": " "}, "licensee"), ({"type_": "enterprise"}, "type"), ({"tier": "1-10"}, "tier"),
    ({"starts": "2026-13-01"}, "starts"), ({"starts": "2026-12-01", "expires": "2026-11-01"}, "before starts"),
])
def test_issue_validation(home, kw, message):
    args = {"licensee": "Example Corp"}
    args.update(kw)
    with pytest.raises(tool.ToolError, match=message):
        home.issue(**args)
    assert home.register() == []


def test_verify_and_revoke(home, tmp_path):
    lid, _, text = home.issue("Example Corp")
    assert home.verify(text)["licence_id"] == lid
    with pytest.raises(tool.ToolError):
        home.verify(text.replace("Example Corp", "Example Org"))
    other = tool.Home(str(tmp_path / "other"))
    other.keygen()
    with pytest.raises(tool.ToolError, match="not signed with this"):
        other.verify(text)
    home.note(lid, "refunded")
    assert tool.status_of(home.find(lid), D.today())[0] == "revoked"


def test_status_words():
    r = {"starts": "2026-01-01", "expires": "2026-12-31", "revoked": ""}
    assert tool.status_of(r, D(2026, 6, 1))[0] == "ok"
    assert tool.status_of(r, D(2026, 12, 10)) == ("soon", "21 days left")
    assert tool.status_of(r, D(2027, 1, 2)) == ("expired", "Ended 2 days ago")
    assert tool.status_of(r, D(2025, 12, 1))[0] == "future"


def test_cli(home, capsys):
    assert tool.main(["--home", home.path, "issue", "--licensee", "Example Corp", "--tier", "5,000+"]) == 0
    assert "RA-" in capsys.readouterr().out
    assert tool.main(["--home", home.path, "list"]) == 0
    assert "Example Corp" in capsys.readouterr().out
    path = os.path.join(home.issued, home.register()[0]["file"])
    assert tool.main(["--home", home.path, "verify", path]) == 0
    assert tool.main(["--home", home.path + "-missing", "issue", "--licensee", "x"]) == 1


# ----------------------------------------------------------------- local web page
@pytest.fixture
def web(home):
    token = "test-token-" + "x" * 20
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), tool.make_handler(home, token))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1], token
    srv.shutdown()


def req(port, method, path, body=None, cookie=None, origin=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {}
    if cookie:
        h["Cookie"] = "lt=" + cookie
    if origin:
        h["Origin"] = origin
    if body is not None:
        body = urllib.parse.urlencode(body)
        h["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read().decode()


def test_web_needs_the_token(web):
    port, token = web
    assert req(port, "GET", "/")[0] == 403
    assert req(port, "GET", "/?token=wrong")[0] == 403
    code, headers, _ = req(port, "GET", "/?token=" + token)
    assert code == 303 and "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    code, headers, body = req(port, "GET", "/", cookie=token)
    assert code == 200 and "No licences issued yet" in body
    assert "default-src 'none'" in headers["Content-Security-Policy"] and "<style" not in body
    assert "<a href='/' aria-current=page>Licences</a>" in body and "Register<" not in body
    assert "<a href='/new' aria-current=page>Issue</a>" in req(port, "GET", "/new", cookie=token)[2]
    assert req(port, "POST", "/new", {"licensee": "x", "csrf": token})[0] == 403          # no cookie


def test_web_issue_download_renew_revoke(web, home):
    port, token = web
    code, _, _ = req(port, "POST", "/new", {"licensee": "Example Corp", "tier": "50-249", "type": "commercial",
                                            "starts": "2026-12-01", "expires": "", "scope": "Unlimited",
                                            "notes": "", "csrf": token}, cookie=token)
    assert code == 303
    lid = home.register()[0]["licence_id"]
    code, headers, body = req(port, "GET", "/download?id=" + lid, cookie=token)
    assert code == 200 and "attachment" in headers["Content-Disposition"]
    assert app_licence.parse(body, app_keys(home))["expires"] == D(2027, 11, 30)
    code, _, body = req(port, "GET", "/new?renew=" + lid, cookie=token)
    assert "value='2027-12-01'" in body and "Renewal of " + lid in body
    assert req(port, "POST", "/revoke", {"id": lid, "reason": "revoked", "csrf": token}, cookie=token)[0] == 303
    assert home.find(lid)["revoked"] == "revoked"
    code, _, body = req(port, "POST", "/verify", {"text": body, "csrf": token}, cookie=token)
    assert code == 400                                       # an HTML page, not a licence file
    code, _, body = req(port, "POST", "/verify", {"text": home.file_text(lid), "csrf": token}, cookie=token)
    assert code == 200 and "Valid signature" in body


def test_web_post_from_its_own_page(web, home):
    # Browsers send "Origin: null" on form POSTs from a page whose Referrer-Policy is
    # no-referrer (Fetch standard), so the policy must let the real origin through.
    port, token = web
    code, headers, _ = req(port, "GET", "/new", cookie=token)
    assert headers["Referrer-Policy"] == "same-origin"
    code, _, _ = req(port, "POST", "/new", {"licensee": "Example Corp", "csrf": token}, cookie=token,
                     origin="http://127.0.0.1:%d" % port)
    assert code == 303 and len(home.register()) == 1
    assert req(port, "POST", "/new", {"licensee": "x", "csrf": token}, cookie=token, origin="null")[0] == 403
    assert len(home.register()) == 1


def test_web_refuses_forged_posts_and_bad_ids(web, home):
    port, token = web
    assert req(port, "POST", "/new", {"licensee": "x", "csrf": "nope"}, cookie=token)[0] == 403
    assert req(port, "POST", "/new", {"licensee": "x", "csrf": token}, cookie=token,
               origin="http://evil.example.com")[0] == 403
    assert home.register() == []
    code, _, body = req(port, "POST", "/new", {"licensee": "", "csrf": token}, cookie=token)
    assert code == 400 and "licensee" in body
    assert req(port, "GET", "/download?id=../signing-key", cookie=token)[0] == 400
    code, _, body = req(port, "GET", "/download?id=RA-2026-9999", cookie=token)
    assert code == 400 and "BEGIN" not in body
    assert re.search(r"<script", req(port, "GET", "/new", cookie=token)[2]) is None
