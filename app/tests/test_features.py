"""RBAC, step-up, CRUD pages, switch-admin PBKDF2 rows, apply flow, audit chain, CLI."""
import os
import re

import psycopg2
import pytest

from conftest import APP_DSN, Browser, login, stepup


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def expire_stepup(superconn):
    q(superconn, "UPDATE ui.session SET stepup_at = now() - interval '10 minutes'")


# ------------------------------------------------------------------ RBAC
VIEW_PAGES = ["/dashboard", "/clients/", "/switch-admins/", "/rules/", "/mab/",
              "/apply/", "/auth-log", "/audit-log", "/account/"]


@pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
def test_all_roles_can_view(browser, logged_in, role):
    logged_in(role)
    for p in VIEW_PAGES:
        r = browser.get(p)
        assert r.status_code == 200, (role, p, r.status_code)


def test_viewer_cannot_mutate(browser, superconn, logged_in):
    logged_in("viewer")
    tok = browser.csrf_from("/dashboard")
    for path, data in [("/clients/new", {"name": "x", "ipaddr": "10.0.0.1", "secret_mode": "generate"}),
                       ("/mab/new", {"mac": "00:11:22:33:44:55", "vlan": "40"}),
                       ("/rules/new", {"connection": "wired", "ad_group": "G", "vlan": "5", "priority": "1"}),
                       ("/switch-admins/new", {"username": "x", "password": "a" * 20, "confirm": "a" * 20}),
                       ("/apply/validate", {}), ("/apply/apply", {}), ("/apply/rollback", {"backup_id": "20260101T000000Z"}),
                       ("/audit-log/verify", {})]:
        r = browser.post(path, data, csrf=tok)
        assert r.status_code == 403, path
    for p in ("/clients/new", "/mab/new", "/rules/new", "/switch-admins/new", "/settings", "/custom-policy",
              "/ui-admins/"):
        assert browser.get(p).status_code == 403, p
    assert q(superconn, "SELECT count(*) FROM mab_device")[0][0] == 0


def test_operator_limits(browser, logged_in):
    logged_in("operator")
    assert browser.get("/clients/new").status_code == 200
    for p in ("/settings", "/custom-policy", "/ui-admins/"):
        assert browser.get(p).status_code == 403, p
    tok = browser.csrf_from("/dashboard")
    assert browser.post("/apply/rollback", {"backup_id": "20260101T000000Z"}, csrf=tok).status_code == 403
    assert browser.post("/ui-admins/1/unlock", {}, csrf=tok).status_code == 403


def test_viewer_secrets_masked(browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw1','192.0.2.1','SuperSecretValue123456')")
    logged_in("viewer")
    for p in ("/clients/", "/apply/", "/dashboard"):
        assert "SuperSecretValue123456" not in browser.text(browser.get(p)), p
    assert browser.get("/clients/1/secret").status_code == 403


def test_operator_cannot_reveal_secret(browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw1','192.0.2.1','SuperSecretValue123456')")
    logged_in("operator")
    assert browser.get("/clients/1/secret").status_code == 403
    assert "SuperSecretValue123456" not in browser.text(browser.get("/clients/1/edit"))


def test_admin_reveal_requires_stepup_and_is_audited(browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw1','192.0.2.1','SuperSecretValue123456')")
    u = logged_in("admin")
    expire_stepup(superconn)
    r = browser.get("/clients/1/secret")
    assert r.status_code == 302 and "/stepup" in r.headers["Location"]
    # wrong step-up
    r = browser.post("/stepup", {"password": "wrong-password-123", "code": "000000", "next": "/clients/1/secret"})
    assert r.status_code == 401
    stepup(browser, superconn, u)
    page = browser.text(browser.get("/clients/1/secret"))
    assert "SuperSecretValue123456" not in page  # GET does not reveal
    r = browser.post("/clients/1/secret", {})
    assert "SuperSecretValue123456" in browser.text(r)
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action='client.secret_reveal'")[0][0] == 1
    detail = q(superconn, "SELECT detail::text FROM ui.audit_log WHERE action='client.secret_reveal'")[0][0]
    assert "SuperSecretValue" not in detail


def test_stepup_post_redirects_when_lapsed(browser, superconn, logged_in):
    logged_in("operator")
    expire_stepup(superconn)
    tok = browser.csrf_from("/apply/")
    r = browser.post("/apply/apply", {"return_to": "/apply/"}, csrf=tok)
    assert r.status_code == 302 and "/stepup" in r.headers["Location"]
    assert not browser.app.fake_helper.requests or all(x["action"] != "apply" for x in browser.app.fake_helper.requests)


# ---------------------------------------------------------------- clients
def test_client_crud(browser, superconn, logged_in):
    logged_in("operator")
    r = browser.post("/clients/new", {"name": "sw-192-0-2-26", "ipaddr": "192.0.2.26", "secret_mode": "generate",
                                      "nas_type": "cisco", "require_ma": "yes", "limit_proxy_state": "auto",
                                      "enabled": "1", "description": "lab"})
    assert r.status_code == 200
    row = q(superconn, "SELECT name, ipaddr, secret, require_ma FROM ui.radius_client")[0]
    assert row[0] == "sw-192-0-2-26" and row[3] == "yes"
    assert re.fullmatch(r"[A-Za-z0-9]{32}", row[2])
    assert row[2] in browser.text(r)  # shown once to the creator
    # invalid input
    r = browser.post("/clients/new", {"name": "bad name!", "ipaddr": "999.1.1.1", "secret_mode": "set",
                                      "secret": "short"})
    assert r.status_code == 400
    # duplicate name
    r = browser.post("/clients/new", {"name": "sw-192-0-2-26", "ipaddr": "192.0.2.27", "secret_mode": "generate"})
    assert r.status_code == 400
    # edit keep secret
    r = browser.post("/clients/1/edit", {"name": "sw-192-0-2-26", "ipaddr": "192.0.2.0/28", "secret_mode": "keep",
                                         "nas_type": "cisco", "require_ma": "auto", "limit_proxy_state": "no"})
    assert r.status_code == 302
    row2 = q(superconn, "SELECT ipaddr, secret, enabled, limit_proxy_state FROM ui.radius_client")[0]
    assert row2 == ("192.0.2.0/28", row[2], False, "no")
    # set explicit secret
    r = browser.post("/clients/1/edit", {"name": "sw-192-0-2-26", "ipaddr": "192.0.2.26", "secret_mode": "set",
                                         "secret": "Explicit-Secret-0123", "nas_type": "cisco", "require_ma": "auto",
                                         "limit_proxy_state": "auto", "enabled": "1"})
    assert r.status_code == 302
    assert q(superconn, "SELECT secret FROM ui.radius_client")[0][0] == "Explicit-Secret-0123"
    r = browser.post("/clients/1/delete", {}, csrf_page="/clients/")
    assert r.status_code == 302
    assert q(superconn, "SELECT count(*) FROM ui.radius_client")[0][0] == 0
    acts = [a for (a,) in q(superconn, "SELECT action FROM ui.audit_log WHERE action LIKE 'client.%%' ORDER BY id")]
    assert acts == ["client.create", "client.update", "client.update", "client.delete"]
    for (d,) in q(superconn, "SELECT detail::text FROM ui.audit_log"):
        assert "Explicit-Secret" not in (d or "") and row[2] not in (d or "")


# ---------------------------------------------------------- switch admins
def test_switch_admin_lifecycle(browser, superconn, logged_in):
    from radius_admin.crypto import fr_pbkdf2_verify
    logged_in("operator")
    pw = "Switch-Admin-Pass-2026"
    r = browser.post("/switch-admins/new", {"username": "netops1", "password": pw, "confirm": pw})
    assert r.status_code == 302
    rows = q(superconn, "SELECT attribute, op, value FROM radcheck WHERE username='netops1'")
    assert len(rows) == 1 and rows[0][0] == "Password-With-Header" and rows[0][1] == ":="
    # test config uses 1000 iterations for speed (0x000003E8); production 600000 -> AAknwA==
    assert rows[0][2].startswith("{X-PBKDF2}HMACSHA2+256:AAAD6A==:")
    assert fr_pbkdf2_verify(pw, rows[0][2])
    assert q(superconn, "SELECT groupname FROM radusergroup WHERE username='netops1'") == [("net-admins",)]
    # Policy: too short / forbidden chars / mismatch
    for bad in ("short", 'has"quote-in-it-xxxxx', "back\\slash-in-it-xxxx"):
        r = browser.post("/switch-admins/netops1/password", {"password": bad, "confirm": bad})
        assert r.status_code == 400, bad
    r = browser.post("/switch-admins/netops1/password", {"password": pw + "x", "confirm": pw + "y"})
    assert r.status_code == 400
    # Disable / enable
    browser.post("/switch-admins/netops1/disable", {}, csrf_page="/switch-admins/")
    assert ("Auth-Type", ":=", "Reject") in q(superconn, "SELECT attribute, op, value FROM radcheck WHERE username='netops1'")
    assert "is-off" in browser.text(browser.get("/switch-admins/"))
    browser.post("/switch-admins/netops1/enable", {}, csrf_page="/switch-admins/")
    assert q(superconn, "SELECT count(*) FROM radcheck WHERE username='netops1' AND attribute='Auth-Type'")[0][0] == 0
    browser.post("/switch-admins/netops1/delete", {}, csrf_page="/switch-admins/")
    assert q(superconn, "SELECT count(*) FROM radcheck WHERE username='netops1'")[0][0] == 0
    assert q(superconn, "SELECT count(*) FROM radusergroup WHERE username='netops1'")[0][0] == 0


def test_legacy_crypt_password_badge_and_reset(browser, superconn, logged_in):
    q(superconn, "INSERT INTO radcheck (username, attribute, op, value) VALUES ('old','Crypt-Password',':=','$6$abc$def')")
    q(superconn, "INSERT INTO radusergroup (username, groupname, priority) VALUES ('old','net-admins',1)")
    logged_in("operator")
    assert "Legacy hash" in browser.text(browser.get("/switch-admins/"))
    pw = "Replacement-Password-1"
    r = browser.post("/switch-admins/old/password", {"password": pw, "confirm": pw})
    assert r.status_code == 302
    attrs = [a for (a,) in q(superconn, "SELECT attribute FROM radcheck WHERE username='old'")]
    assert attrs == ["Password-With-Header"]
    assert "Legacy hash" not in browser.text(browser.get("/switch-admins/"))


def test_switch_admin_sql_injection_is_inert(browser, superconn, logged_in):
    logged_in("operator")
    r = browser.post("/switch-admins/new", {"username": "x'; DROP TABLE radcheck; --", "password": "a" * 20,
                                            "confirm": "a" * 20})
    assert r.status_code == 400
    assert q(superconn, "SELECT count(*) FROM radcheck")[0][0] == 0


# -------------------------------------------------------------------- MAB
def test_mab_crud_and_import(browser, superconn, logged_in):
    logged_in("operator")
    r = browser.post("/mab/new", {"mac": "aa:bb:cc:dd:ee:ff", "vlan": "40", "description": "printer", "enabled": "1"})
    assert r.status_code == 302
    assert q(superconn, "SELECT mac, vlan, enabled FROM mab_device") == [("AA-BB-CC-DD-EE-FF", 40, True)]
    assert browser.post("/mab/new", {"mac": "aabb.ccdd.eeff", "vlan": "41"}).status_code == 400  # duplicate
    assert browser.post("/mab/new", {"mac": "zz", "vlan": "41"}).status_code == 400
    assert browser.post("/mab/new", {"mac": "00-00-00-00-00-01", "vlan": "5000"}).status_code == 400
    r = browser.post("/mab/1/edit", {"mac": "AA-BB-CC-DD-EE-FF", "vlan": "41", "description": "moved"})
    assert r.status_code == 302
    assert q(superconn, "SELECT vlan, enabled FROM mab_device") == [(41, False)]
    # CSV import: one bad row -> nothing imported
    bad = "mac,vlan,description\n00:11:22:33:44:55,40,ok\nnot-a-mac,40,bad\n"
    r = browser.post("/mab/import", {"text": bad, "mode": "add"})
    assert r.status_code == 400 and "Line 3" in browser.text(r)
    assert q(superconn, "SELECT count(*) FROM mab_device")[0][0] == 1
    good = "mac,vlan,description\n00:11:22:33:44:55,40,cam\n0011.2233.4466,50,phone\naa-bb-cc-dd-ee-ff,42,upd\n"
    r = browser.post("/mab/import", {"text": good, "mode": "upsert"})
    assert r.status_code == 302
    assert q(superconn, "SELECT mac, vlan FROM mab_device ORDER BY mac") == [
        ("00-11-22-33-44-55", 40), ("00-11-22-33-44-66", 50), ("AA-BB-CC-DD-EE-FF", 42)]
    # file upload
    import io
    tok = browser.csrf_from("/mab/import")
    r = browser.c.post("/mab/import", base_url="https://radius.test",
                       headers={"Origin": "https://radius.test", "X-Real-IP": browser.ip},
                       data={"csrf_token": tok, "mode": "add",
                             "file": (io.BytesIO(b"de:ad:be:ef:00:01,7,x\n"), "m.csv")},
                       content_type="multipart/form-data")
    assert r.status_code == 302
    assert q(superconn, "SELECT count(*) FROM mab_device")[0][0] == 4
    r = browser.post("/mab/1/delete", {}, csrf_page="/mab/")
    assert r.status_code == 302
    # MAB changes are live: they must not create pending-apply state by themselves
    assert 'class="apply-note"' not in browser.text(browser.get("/mab/"))


# ---------------------------------------------------------------- rules
def test_rules_crud_and_reorder(browser, superconn, logged_in):
    logged_in("operator")
    for prio, grp, vlan in ((10, "Wired-Support", 510), (20, "Wired-Office", 500)):
        r = browser.post("/rules/new", {"connection": "wired", "ad_group": grp, "vlan": str(vlan),
                                        "priority": str(prio), "enabled": "1"})
        assert r.status_code == 302
    r = browser.post("/rules/new", {"connection": "wireless", "ssid": "Example_Admin", "ad_group": "WIRELESS-SUPPORT",
                                    "vlan": "510", "priority": "10", "enabled": "1"})
    assert r.status_code == 302
    assert browser.post("/rules/new", {"connection": "wireless", "ssid": "", "ad_group": "X", "vlan": "1",
                                       "priority": "1"}).status_code == 400
    assert browser.post("/rules/new", {"connection": "wired", "ad_group": 'Bad"Group', "vlan": "1",
                                       "priority": "1"}).status_code == 400
    assert q(superconn, "SELECT ssid FROM ui.access_rule WHERE connection='wired'") == [(None,), (None,)]
    r = browser.post("/rules/2/move", {"direction": "up"}, csrf_page="/rules/")
    assert r.status_code == 302
    assert q(superconn, "SELECT ad_group FROM ui.access_rule WHERE connection='wired' ORDER BY priority") == [
        ("Wired-Office",), ("Wired-Support",)]
    page = browser.text(browser.get("/rules/"))
    assert "Wireless: Example_Admin" in page and 'class="apply-note"' not in page.split("<main")[1]
    r = browser.post("/rules/3/edit", {"connection": "wireless", "ssid": "Example_Admin", "ad_group": "WIRELESS-SUPPORT",
                                       "vlan": "511", "priority": "10"})
    assert r.status_code == 302
    assert q(superconn, "SELECT vlan, enabled FROM ui.access_rule WHERE id=3") == [(511, False)]
    assert browser.post("/rules/3/delete", {}, csrf_page="/rules/").status_code == 302


# ------------------------------------------------------------ apply flow
def test_apply_flow(app, browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw1','192.0.2.1','SuperSecretValue123456')")
    u = logged_in("operator")
    staging = app.config["RA"]["staging_dir"]
    page = browser.text(browser.get("/dashboard"))
    assert "Pending changes" in page
    page = browser.text(browser.get("/apply/"))
    assert "SuperSecretValue123456" not in page and "********" in page
    assert "d-add" in page
    # validate
    r = browser.post("/apply/validate", {}, csrf_page="/apply/")
    assert r.status_code == 200 and "Validation passed" in browser.text(r)
    for n in ("policy", "clients"):
        st = os.stat(os.path.join(staging, n))
        assert st.st_mode & 0o777 == 0o600
    with open(os.path.join(staging, "clients")) as fh:
        assert "SuperSecretValue123456" in fh.read()
    # apply (fresh login = step-up ok)
    m = re.search(r'name="expected" value="([^"]+)"', page)
    r = browser.post("/apply/apply", {"expected": m.group(1)}, csrf_page="/apply/")
    assert r.status_code == 200 and "Configuration applied" in browser.text(r), browser.text(r)
    log = q(superconn, "SELECT action, success, backup_id, policy_sha256 FROM ui.apply_log ORDER BY id")
    assert [x[0] for x in log] == ["validate", "apply"] and all(x[1] for x in log)
    assert log[1][2] == "20261023T100000Z"
    assert os.path.exists(os.path.join(staging, "applied", "policy"))
    # now in sync
    assert "Pending changes" not in browser.text(browser.get("/dashboard"))
    assert "FreeRADIUS matches the database" in browser.text(browser.get("/apply/"))
    # a staged change creates pending state; a live change (MAB) does not
    browser.post("/mab/new", {"mac": "00-00-00-00-00-01", "vlan": "5", "enabled": "1"})
    assert "Pending changes" not in browser.text(browser.get("/dashboard"))
    q(superconn, "UPDATE ui.setting SET value='if (&User-Name == \"z\") {\n\treject\n}\n' WHERE key='custom_policy'")
    assert "Pending changes" in browser.text(browser.get("/dashboard"))
    # stale "expected" hash refused
    r = browser.post("/apply/apply", {"expected": m.group(1)}, csrf_page="/apply/")
    assert r.status_code == 302
    assert len(q(superconn, "SELECT 1 FROM ui.apply_log WHERE action='apply'")) == 1
    acts = [a for (a,) in q(superconn, "SELECT action FROM ui.audit_log WHERE action LIKE 'config.%%'")]
    assert acts == ["config.validate", "config.apply"]


def test_apply_failure_rolled_back(app, browser, superconn, logged_in):
    logged_in("operator")
    app.fake_helper.fail_next["apply"] = {"ok": False, "rolled_back": True, "message": "radiusd failed to start",
                                          "output": ["line1", "line2"]}
    r = browser.post("/apply/apply", {}, csrf_page="/apply/")
    t = browser.text(r)
    assert "Apply failed" in t and "previous configuration was restored" in t and "line2" in t
    assert q(superconn, "SELECT success FROM ui.apply_log") == [(False,)]
    assert "Pending changes" in browser.text(browser.get("/dashboard"))


def test_helper_unavailable(app, browser, superconn, logged_in):
    logged_in("operator")
    app.config["RA"]["helper_socket"] = "/nonexistent/helper.sock"
    assert browser.get("/dashboard").status_code == 200
    r = browser.post("/apply/validate", {}, csrf_page="/apply/")
    assert "helper unavailable" in browser.text(r)


def test_rollback_admin_stepup(app, browser, superconn, logged_in):
    u = logged_in("admin")
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    bid = app.fake_helper.backups[0]
    expire_stepup(superconn)
    tok = browser.csrf_from("/apply/")
    r = browser.post("/apply/rollback", {"backup_id": bid}, csrf=tok)
    assert r.status_code == 302 and "/stepup" in r.headers["Location"]
    stepup(browser, superconn, u)
    assert browser.post("/apply/rollback", {"backup_id": "../../etc"}, csrf_page="/apply/").status_code == 302
    r = browser.post("/apply/rollback", {"backup_id": bid}, csrf_page="/apply/")
    assert "Rollback complete" in browser.text(r)
    assert app.fake_helper.requests[-1] == {"action": "rollback", "backup_id": bid}
    assert q(superconn, "SELECT action, success FROM ui.apply_log ORDER BY id DESC LIMIT 1") == [("rollback", True)]


# ------------------------------------------------- settings & custom policy
def test_settings_and_custom_policy(browser, superconn, logged_in):
    u = logged_in("admin")
    expire_stepup(superconn)
    assert "/stepup" in browser.get("/settings").headers["Location"]
    stepup(browser, superconn, u)
    r = browser.post("/settings", {"admin_subnet": "192.0.2.0/24", "admin_priv15": "1",
                                   "banner_text": "Authorized use only. New banner text here."})
    assert r.status_code == 302
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='admin_priv15'") == [("true",)]
    assert browser.post("/settings", {"admin_subnet": "192.0.2.1/24", "banner_text": "x" * 30}).status_code == 400
    r = browser.post("/custom-policy", {"custom_policy": "if (&User-Name == \"x\") {\n\treject\n}\n"})
    assert r.status_code == 302
    r = browser.post("/custom-policy", {"custom_policy": "$INCLUDE /etc/passwd"})
    assert r.status_code == 400
    r = browser.post("/custom-policy", {"custom_policy": "update reply { Reply-Message := \"%{exec:/bin/id}\" }"})
    assert r.status_code == 400
    # Lapsed step-up on POST keeps the text and asks inline
    expire_stepup(superconn)
    text = "if (&User-Name == \"y\") {\n\treject\n}\n"
    r = browser.post("/custom-policy", {"custom_policy": text}, csrf_page="/account/")
    assert r.status_code == 401 and "stepup_password" in browser.text(r) and "&#34;y&#34;" in browser.text(r)
    from conftest import fresh_code
    r = browser.post("/custom-policy", {"custom_policy": text, "stepup_password": u.password,
                                        "stepup_code": fresh_code(superconn, u)}, csrf_page="/account/")
    assert r.status_code == 302
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='custom_policy'") == [(text,)]


# ----------------------------------------------------------- UI admins
def test_ui_admin_management(app, browser, superconn, logged_in):
    u = logged_in("admin")
    r = browser.post("/ui-admins/new", {"username": "carol", "display_name": "Carol", "role": "operator"})
    assert r.status_code == 200
    temp = re.search(r'id="temp-pw" class="mono">([^<]+)<', browser.text(r)).group(1)
    row = q(superconn, "SELECT id, role, must_change_password FROM ui.admin_user WHERE username='carol'")[0]
    assert row[1:] == ("operator", True)
    cid = row[0]
    # Carol signs in, is forced to enrol MFA
    b2 = Browser(app, ip="192.0.2.60")
    b2.post("/banner", {"accept": "1"}, csrf_page="/login")
    r = b2.post("/login", {"username": "carol", "password": temp})
    assert r.headers["Location"].endswith("/login/enroll")
    # role change, lock/unlock, reset MFA, disable, last-admin protection
    assert browser.post("/ui-admins/%d/role" % cid, {"role": "viewer"}, csrf_page="/ui-admins/").status_code == 302
    assert q(superconn, "SELECT role FROM ui.admin_user WHERE id=%s", (cid,)) == [("viewer",)]
    q(superconn, "UPDATE ui.admin_user SET locked_until = now() + interval '1 hour' WHERE id=%s", (cid,))
    assert "Locked" in browser.text(browser.get("/ui-admins/"))
    browser.post("/ui-admins/%d/unlock" % cid, {}, csrf_page="/ui-admins/")
    assert q(superconn, "SELECT locked_until FROM ui.admin_user WHERE id=%s", (cid,)) == [(None,)]
    browser.post("/ui-admins/%d/enable" % cid, {"enabled": "0"}, csrf_page="/ui-admins/")
    assert q(superconn, "SELECT enabled FROM ui.admin_user WHERE id=%s", (cid,)) == [(False,)]
    r = browser.post("/ui-admins/%d/role" % u.id, {"role": "viewer"}, csrf_page="/ui-admins/")
    assert q(superconn, "SELECT role FROM ui.admin_user WHERE id=%s", (u.id,)) == [("admin",)]
    r = browser.post("/ui-admins/%d/reset-password" % cid, {}, csrf_page="/ui-admins/")
    assert r.status_code == 200 and "temp-pw" in browser.text(r)
    browser.post("/ui-admins/%d/delete" % cid, {}, csrf_page="/ui-admins/")
    assert q(superconn, "SELECT count(*) FROM ui.admin_user WHERE id=%s", (cid,)) == [(0,)]
    # step-up enforced
    expire_stepup(superconn)
    r = browser.post("/ui-admins/new", {"username": "dave", "role": "viewer"}, csrf_page="/ui-admins/")
    assert r.status_code == 302 and "/stepup" in r.headers["Location"]
    assert q(superconn, "SELECT count(*) FROM ui.admin_user WHERE username='dave'") == [(0,)]


def test_reset_mfa_forces_reenrollment(app, browser, superconn, logged_in, make_user):
    logged_in("admin")
    v = make_user(username="vic", role="viewer")
    b2 = Browser(app, ip="192.0.2.61")
    login(b2, superconn, v)
    browser.post("/ui-admins/%d/reset-mfa" % v.id, {}, csrf_page="/ui-admins/")
    assert b2.get("/dashboard").status_code == 302  # sessions ended
    b3 = Browser(app, ip="192.0.2.62")
    b3.post("/banner", {"accept": "1"}, csrf_page="/login")
    r = b3.post("/login", {"username": "vic", "password": v.password})
    assert r.headers["Location"].endswith("/login/enroll")


# -------------------------------------------------------------- audit log
def test_audit_chain_verify_and_tamper(app, browser, superconn, logged_in):
    from radius_admin import audit
    logged_in("operator")
    browser.post("/mab/new", {"mac": "00-00-00-00-00-01", "vlan": "5", "enabled": "1"})
    conn = psycopg2.connect(APP_DSN)
    try:
        ok, n, bad, msg = audit.verify_chain(conn=conn)
        assert ok and n >= 4, msg
        r = browser.post("/audit-log/verify", {}, csrf_page="/audit-log")
        assert "Chain intact" in browser.text(r)
        # radius_admin cannot modify history
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute("UPDATE ui.audit_log SET actor='x'")
        conn.rollback()
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute("DELETE FROM ui.audit_log")
        conn.rollback()
        # superuser tampering (trigger bypassed) is detected
        with superconn.cursor() as cur:
            cur.execute("SET session_replication_role = replica")
            cur.execute("UPDATE ui.audit_log SET detail = '{\"mac\": \"FF-FF-FF-FF-FF-FF\"}' WHERE action='mab.create'")
            cur.execute("SET session_replication_role = DEFAULT")
        ok, n, bad, msg = audit.verify_chain(conn=conn)
        assert not ok and "does not match" in msg
        r = browser.post("/audit-log/verify", {}, csrf_page="/audit-log")
        assert "Chain broken" in browser.text(r)
        # deletion detected as a broken link
        with superconn.cursor() as cur:
            cur.execute("SET session_replication_role = replica")
            cur.execute("UPDATE ui.audit_log SET detail = NULL, hash = hash WHERE false")
            cur.execute("DELETE FROM ui.audit_log WHERE id = 2")
            cur.execute("SET session_replication_role = DEFAULT")
        ok, n, bad, msg = audit.verify_chain(conn=conn)
        assert not ok
    finally:
        conn.close()


def test_audit_concurrent_inserts_keep_chain(app):
    import threading
    from radius_admin import audit
    errors = []

    def worker(i):
        try:
            c = psycopg2.connect(APP_DSN)
            for j in range(10):
                audit.write("test.concurrent", actor="t%d" % i, detail={"j": j}, conn=c)
                c.commit()
            c.close()
        except Exception as e:  # pragma: no cover
            errors.append(e)
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    c = psycopg2.connect(APP_DSN)
    ok, n, bad, msg = audit.verify_chain(conn=c)
    c.close()
    assert ok and n == 50, msg


def test_auth_log_page(browser, superconn, logged_in):
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, callingstationid, vlan)"
                 " VALUES ('host1.example.net','Access-Accept','eap-tls','192.0.2.5','AA-BB-CC-00-11-22','510'),"
                 " ('baduser','Access-Reject','pap-admin','192.0.2.6',NULL,NULL)")
    logged_in("viewer")
    t = browser.text(browser.get("/auth-log?reply=Access-Reject"))
    assert "baduser" in t and "host1.example.net" not in t
    t = browser.text(browser.get("/auth-log?mac=aa-bb-cc"))
    assert "host1.example.net" in t
    assert "baduser" in browser.text(browser.get("/dashboard"))
    assert browser.get("/auth-log?since=garbage&page=x").status_code == 200


# ------------------------------------------------------------------- CLI
def test_cli(app, tmp_path, superconn, capsys):
    from radius_admin import cli
    cfgp = tmp_path / "ra.conf"
    cfgp.write_text("[app]\nrequire_fips = false\ndb_dsn = %s\nkey_file = %s\nlog_syslog = false\n"
                    "pbkdf2_iterations = 1000\n" % (APP_DSN, app.config["RA"]["key_file"]))
    assert cli.main(["--config", str(cfgp), "create-admin", "--username", "root-admin", "--role", "admin"]) == 0
    out = capsys.readouterr().out
    temp = out.strip().splitlines()[-1]
    assert len(temp) == 20
    assert q(superconn, "SELECT role, must_change_password FROM ui.admin_user WHERE username='root-admin'") == [("admin", True)]
    assert cli.main(["--config", str(cfgp), "create-admin", "--username", "root-admin", "--role", "admin"]) == 2
    out_dir = tmp_path / "out"
    assert cli.main(["--config", str(cfgp), "render", "--out-dir", str(out_dir)]) == 0
    assert (out_dir / "policy").stat().st_mode & 0o777 == 0o600
    assert cli.main(["--config", str(cfgp), "verify-audit"]) == 0
    rc = cli.main(["--config", str(cfgp), "check-fips"])
    assert rc in (0, 1)
    capsys.readouterr()


def test_cli_account_recovery(app, tmp_path, superconn, capsys):
    from radius_admin import cli
    cfgp = tmp_path / "ra.conf"
    cfgp.write_text("[app]\nrequire_fips = false\ndb_dsn = %s\nkey_file = %s\nlog_syslog = false\n"
                    "pbkdf2_iterations = 1000\n" % (APP_DSN, app.config["RA"]["key_file"]))
    assert cli.main(["--config", str(cfgp), "create-admin", "--username", "locked", "--role", "admin"]) == 0
    first = capsys.readouterr().out.strip().splitlines()[-1]
    q(superconn, "UPDATE ui.admin_user SET failed_count=7, locked_until=now()+interval '1 hour', enabled=false,"
                 " mfa_method='totp', totp_last_step=5, must_change_password=false WHERE username='locked'")
    uid = q(superconn, "SELECT id FROM ui.admin_user WHERE username='locked'")[0][0]
    q(superconn, "INSERT INTO ui.session (token_sha256, user_id, csrf_token) VALUES ('cli-test-token', %d, 't')" % uid)
    # unknown user
    assert cli.main(["--config", str(cfgp), "reset-password", "--username", "nobody"]) == 2
    capsys.readouterr()
    # unlock only
    assert cli.main(["--config", str(cfgp), "unlock", "--username", "LOCKED"]) == 0
    assert q(superconn, "SELECT failed_count, locked_until FROM ui.admin_user WHERE id=%d" % uid) == [(0, None)]
    # reset password (+mfa): new temp password, re-enabled, sessions gone, must change
    assert cli.main(["--config", str(cfgp), "reset-password", "--username", "locked", "--reset-mfa"]) == 0
    temp = capsys.readouterr().out.strip().splitlines()[-1]
    assert len(temp) == 20 and temp != first
    assert q(superconn, "SELECT enabled, must_change_password, mfa_method, failed_count FROM ui.admin_user"
                        " WHERE id=%d" % uid) == [(True, True, None, 0)]
    assert q(superconn, "SELECT count(*) FROM ui.session WHERE user_id=%d" % uid) == [(0,)]
    from radius_admin.crypto import verify_password
    h = q(superconn, "SELECT password_hash FROM ui.admin_user WHERE id=%d" % uid)[0][0]
    assert verify_password(temp, h)
    acts = [r[0] for r in q(superconn, "SELECT action FROM ui.audit_log WHERE object_id='%d' ORDER BY id" % uid)]
    assert acts[-2:] == ["ui_admin.unlock", "ui_admin.reset_password"]
    assert cli.main(["--config", str(cfgp), "reset-mfa", "--username", "locked"]) == 0
    assert cli.main(["--config", str(cfgp), "verify-audit"]) == 0
    capsys.readouterr()


def test_render_deterministic(app):
    from radius_admin import services
    c = psycopg2.connect(APP_DSN)
    try:
        a = services.render_all(c)
        b = services.render_all(c)
    finally:
        c.close()
    assert a == b
