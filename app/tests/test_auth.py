"""Login, banner, lockout, throttle, MFA (TOTP + cert), sessions, CSRF, headers."""
import re

from conftest import Browser, fresh_code, login, make_cert, stepup


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def test_banner_required_before_login(browser, make_user):
    u = make_user()
    r = browser.post("/login", {"username": u.username, "password": u.password}, csrf_page="/login")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_banner_cookie_cannot_be_forged(browser, make_user):
    u = make_user()
    browser.get("/login")
    browser.c.set_cookie("__Host-radius_admin_pre", "abc.deadbeef", domain="radius.test")
    r = browser.post("/login", {"username": u.username, "password": u.password}, csrf="abc")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_login_requires_mfa_then_ok(browser, superconn, make_user):
    u = make_user()
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    r = browser.post("/login", {"username": u.username, "password": u.password})
    assert r.headers["Location"].endswith("/login/mfa")
    # Not yet authenticated
    r = browser.get("/clients/")
    assert r.status_code == 302 and "/login/mfa" in r.headers["Location"]
    r = browser.post("/login/mfa", {"code": fresh_code(superconn, u)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert browser.get("/clients/").status_code == 200
    actions = [a for (a,) in q(superconn, "SELECT action FROM ui.audit_log ORDER BY id")]
    assert "auth.banner_ack" in actions and "auth.password_ok" in actions and "auth.login" in actions


def test_session_cookie_attributes_and_rotation(browser, superconn, make_user):
    u = make_user()
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    r = browser.post("/login", {"username": u.username, "password": u.password})
    c1 = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("__Host-radius_admin=")][0]
    for attr in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
        assert attr in c1
    assert "Domain" not in c1
    r = browser.post("/login/mfa", {"code": fresh_code(superconn, u)})
    c2 = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("__Host-radius_admin=")][0]
    assert c1.split(";")[0] != c2.split(";")[0]  # rotated on MFA success
    tok = c2.split(";")[0].split("=", 1)[1]
    # DB stores only the hash
    rows = q(superconn, "SELECT token_sha256 FROM ui.session")
    import hashlib
    assert rows == [(hashlib.sha256(tok.encode()).hexdigest(),)]


def test_wrong_password_generic_error(browser, make_user):
    u = make_user()
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    r1 = browser.post("/login", {"username": u.username, "password": "wrong-password-xx"})
    r2 = browser.post("/login", {"username": "nobody", "password": "wrong-password-xx"})
    assert r1.status_code == r2.status_code == 401
    assert "Sign-in failed" in browser.text(r1) and "Sign-in failed" in browser.text(r2)


def test_lockout_after_threshold(browser, superconn, make_user):
    u = make_user()
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    for _ in range(5):
        browser.post("/login", {"username": u.username, "password": "bad-bad-bad-bad"})
    assert q(superconn, "SELECT locked_until > now() FROM ui.admin_user WHERE id=%s", (u.id,))[0][0]
    r = browser.post("/login", {"username": u.username, "password": u.password})
    assert r.status_code == 401  # correct password refused while locked
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action='auth.lockout'")[0][0] == 1
    # expire lock
    q(superconn, "UPDATE ui.admin_user SET locked_until = now() - interval '1 minute' WHERE id=%s", (u.id,))
    login(browser, superconn, u)


def test_mfa_failures_count_toward_lockout(browser, superconn, make_user):
    u = make_user()
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    for i in range(5):
        r = browser.post("/login", {"username": u.username, "password": u.password})
        if r.status_code != 302:
            break
        browser.post("/login/mfa", {"code": "000000"})
    assert q(superconn, "SELECT locked_until > now() FROM ui.admin_user WHERE id=%s", (u.id,))[0][0]


def test_per_ip_throttle(app, superconn, make_user):
    u = make_user()
    b = Browser(app, ip="192.0.2.99")
    b.post("/banner", {"accept": "1"}, csrf_page="/login")
    for i in range(20):
        b.post("/login", {"username": "ghost%d" % i, "password": "whatever-password"})
    r = b.post("/login", {"username": u.username, "password": u.password})
    assert r.status_code == 429
    # Another IP is unaffected
    b2 = Browser(app, ip="192.0.2.100")
    login(b2, superconn, u)


def test_totp_replay_rejected(browser, superconn, make_user, app):
    u = make_user()
    code = fresh_code(superconn, u)
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    browser.post("/login", {"username": u.username, "password": u.password})
    assert browser.post("/login/mfa", {"code": code}).status_code == 302
    b2 = Browser(app)
    b2.post("/banner", {"accept": "1"}, csrf_page="/login")
    b2.post("/login", {"username": u.username, "password": u.password})
    r = b2.post("/login/mfa", {"code": code})  # same code again
    assert r.status_code == 401


def test_totp_secret_encrypted_at_rest(superconn, make_user):
    u = make_user()
    blob = bytes(q(superconn, "SELECT totp_secret_enc FROM ui.admin_user WHERE id=%s", (u.id,))[0][0])
    assert u.secret not in blob and len(blob) == 1 + 12 + 20 + 16


def test_forced_totp_enrollment(browser, superconn, make_user):
    from radius_admin.crypto import hotp, totp_now_step
    import base64
    u = make_user(mfa=None)
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    r = browser.post("/login", {"username": u.username, "password": u.password})
    assert r.headers["Location"].endswith("/login/enroll")
    assert browser.get("/dashboard").headers["Location"].endswith("/login/enroll")
    page = browser.text(browser.get("/login/enroll"))
    assert "data:image/svg+xml;base64," in page  # QR via python3-qrcode
    key_b32 = re.search(r'class="mono key">([A-Z2-7 ]+)<', page).group(1).replace(" ", "")
    candidate = re.search(r'name="candidate" value="([^"]+)"', page).group(1)
    secret = base64.b32decode(key_b32 + "=" * (-len(key_b32) % 8))
    r = browser.post("/login/enroll", {"method": "totp", "candidate": candidate, "code": "000000"},
                     csrf_page="/login/enroll")
    assert r.status_code == 400
    r = browser.post("/login/enroll", {"method": "totp", "candidate": candidate,
                                       "code": hotp(secret, totp_now_step())}, csrf_page="/login/enroll")
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert q(superconn, "SELECT mfa_method FROM ui.admin_user WHERE id=%s", (u.id,))[0][0] == "totp"
    assert browser.get("/dashboard").status_code == 200


def test_cert_enrollment_and_login(browser, app, superconn, make_user):
    pem, sha, esc = make_cert("alice-cert")
    good = {"X-Client-Verify": "SUCCESS", "X-Client-Cert": esc}
    u = make_user(mfa=None)
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    browser.post("/login", {"username": u.username, "password": u.password})
    # Without a verified cert, enrolment refuses
    r = browser.post("/login/enroll", {"method": "cert"}, csrf_page="/login/enroll")
    assert r.status_code == 400
    r = browser.post("/login/enroll", {"method": "cert"}, csrf_page="/login/enroll?method=cert", headers=good)
    assert r.status_code == 302
    row = q(superconn, "SELECT mfa_method, cert_sha256, cert_subject FROM ui.admin_user WHERE id=%s", (u.id,))[0]
    assert row[0] == "cert" and row[1] == sha and "alice-cert" in row[2]
    # New login with the cert
    b2 = Browser(app)
    b2.post("/banner", {"accept": "1"}, csrf_page="/login")
    b2.post("/login", {"username": u.username, "password": u.password})
    assert b2.post("/login/mfa", {}, headers=good).status_code == 302
    assert b2.get("/dashboard").status_code == 200


def test_cert_header_forgery_rejected(app, superconn, make_user):
    pem, sha, esc = make_cert("bob")
    u = make_user(username="bob", mfa="cert", cert_sha256=sha)
    for headers in ({"X-Client-Verify": "FAILED:unable to verify", "X-Client-Cert": esc},
                    {"X-Client-Verify": "NONE", "X-Client-Cert": esc},
                    {"X-Client-Cert": esc},
                    {"X-Client-Verify": "SUCCESS"},
                    {"X-Client-Verify": "SUCCESS", "X-Client-Cert": make_cert("other")[2]},
                    {"X-Client-Verify": "success", "X-Client-Cert": esc}):
        b = Browser(app)
        b.post("/banner", {"accept": "1"}, csrf_page="/login")
        b.post("/login", {"username": u.username, "password": u.password})
        r = b.post("/login/mfa", {}, headers=headers)
        assert r.status_code == 401, headers
        q(superconn, "UPDATE ui.admin_user SET failed_count=0, locked_until=NULL WHERE id=%s", (u.id,))
    b = Browser(app)
    b.post("/banner", {"accept": "1"}, csrf_page="/login")
    b.post("/login", {"username": u.username, "password": u.password})
    assert b.post("/login/mfa", {}, headers={"X-Client-Verify": "SUCCESS", "X-Client-Cert": esc}).status_code == 302


def test_csrf_rejections(browser, superconn, logged_in):
    logged_in("operator")
    good = browser.csrf_from("/mab/new")
    data = {"mac": "00-11-22-33-44-55", "vlan": "40", "enabled": "1"}
    assert browser.post("/mab/new", data, csrf=False).status_code == 403
    assert browser.post("/mab/new", data, csrf="x" * 43).status_code == 403
    # Missing Origin and Referer
    assert browser.post("/mab/new", data, csrf=good, origin=False).status_code == 403
    # Cross-site Origin
    assert browser.post("/mab/new", data, csrf=good, headers={"Origin": "https://evil.example"}).status_code == 403
    # Referer fallback works
    r = browser.post("/mab/new", data, csrf=good, origin=False, headers={"Referer": "https://radius.test/mab/new"})
    assert r.status_code == 302
    assert q(superconn, "SELECT count(*) FROM mab_device")[0][0] == 1


def test_csrf_on_login_form(browser, make_user):
    u = make_user()
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    r = browser.post("/login", {"username": u.username, "password": u.password}, csrf="forged")
    assert r.status_code == 403


def test_idle_and_absolute_expiry(browser, superconn, logged_in):
    logged_in("viewer")
    assert browser.get("/dashboard").status_code == 200
    q(superconn, "UPDATE ui.session SET last_seen_at = now() - interval '16 minutes'")
    r = browser.get("/dashboard")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    assert q(superconn, "SELECT count(*) FROM ui.session")[0][0] == 0


def test_absolute_expiry(browser, superconn, logged_in):
    logged_in("viewer")
    q(superconn, "UPDATE ui.session SET created_at = now() - interval '8 hours 1 minute', last_seen_at = now()")
    r = browser.get("/dashboard")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_logout_destroys_session(browser, superconn, logged_in):
    logged_in("viewer")
    r = browser.post("/logout", {}, csrf_page="/dashboard")
    assert r.status_code == 302
    assert q(superconn, "SELECT count(*) FROM ui.session")[0][0] == 0
    assert browser.get("/dashboard").status_code == 302


def test_disabled_user_session_dropped(browser, superconn, logged_in):
    u = logged_in("viewer")
    q(superconn, "UPDATE ui.admin_user SET enabled=false WHERE id=%s", (u.id,))
    assert browser.get("/dashboard").status_code == 302


def test_security_headers(browser, logged_in):
    for path in ("/login",):
        r = browser.get(path)
        csp = r.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Referrer-Policy"] == "same-origin"
    logged_in("viewer")
    r = browser.get("/dashboard")
    assert r.headers["Cache-Control"] == "no-store"
    assert "Content-Security-Policy" in r.headers
    body = browser.text(r)
    assert "<style" not in body and " style=" not in body
    assert not re.search(r"<script(?![^>]*\bsrc=)", body)
    assert not re.search(r"\son[a-z]+=", body)


def test_static_assets_served(browser):
    assert browser.get("/static/app.css").status_code == 200
    assert browser.get("/static/app.js").status_code == 200


def test_open_redirect_blocked(browser, superconn, make_user):
    u = make_user()
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    browser.post("/login", {"username": u.username, "password": u.password})
    r = browser.post("/login/mfa?next=//evil.example/x", {"code": fresh_code(superconn, u)})
    assert r.headers["Location"].endswith("/dashboard")


def test_forced_password_change_and_history(browser, superconn, make_user):
    u = make_user(must_change=True)
    login(browser, superconn, u)
    r = browser.get("/dashboard")
    assert r.status_code == 302 and r.headers["Location"].endswith("/account/password")
    page = "/account/password"
    # too short
    r = browser.post(page, {"current_password": u.password, "new_password": "Short-1a",
                            "confirm_password": "Short-1a"})
    assert r.status_code == 400 and "at least 15" in browser.text(r)
    # reuse of current
    r = browser.post(page, {"current_password": u.password, "new_password": u.password,
                            "confirm_password": u.password})
    assert r.status_code == 400 and "not used recently" in browser.text(r)
    # contains username
    bad = "alice-Password-12345"
    r = browser.post(page, {"current_password": u.password, "new_password": bad, "confirm_password": bad})
    assert r.status_code == 400
    # wrong current
    new = "Brand-New-Passphrase-77"
    r = browser.post(page, {"current_password": "nope-nope-nope", "new_password": new, "confirm_password": new})
    assert r.status_code == 400
    r = browser.post(page, {"current_password": u.password, "new_password": new, "confirm_password": new})
    assert r.status_code == 302
    assert browser.get("/dashboard").status_code == 200
    # history: going back to the original is refused
    r = browser.post(page, {"current_password": new, "new_password": u.password, "confirm_password": u.password})
    assert r.status_code == 400 and "not used recently" in browser.text(r)


def test_own_session_list_and_revoke(app, browser, superconn, logged_in, make_user):
    u = logged_in("viewer")
    other = Browser(app, ip="192.0.2.77")
    login(other, superconn, u)
    assert other.get("/dashboard").status_code == 200
    page = browser.text(browser.get("/account/"))
    assert "192.0.2.77" in page
    r = browser.post("/account/sessions/revoke-others", {}, csrf_page="/account/")
    assert r.status_code == 302
    assert other.get("/dashboard").status_code == 302
    assert browser.get("/dashboard").status_code == 200


def test_mfa_switch_requires_stepup(browser, superconn, logged_in):
    u = logged_in("viewer")
    # A fresh sign-in counts as a step-up; age it past stepup_minutes.
    assert browser.get("/account/mfa").status_code == 200
    q(superconn, "UPDATE ui.session SET stepup_at = now() - interval '6 minutes'")
    r = browser.get("/account/mfa")
    assert r.status_code == 302 and "/stepup" in r.headers["Location"]
    stepup(browser, superconn, u)
    assert browser.get("/account/mfa").status_code == 200


def test_audit_never_contains_secrets(browser, superconn, logged_in):
    u = logged_in("admin")
    rows = q(superconn, "SELECT detail::text FROM ui.audit_log")
    for (d,) in rows:
        assert u.password not in (d or "")
