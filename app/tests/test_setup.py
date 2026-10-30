"""First-run setup checklist: computed from live state, required vs optional, audited."""
import re


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def mark_applied(app, superconn):
    from radius_admin import services
    from radius_admin.crypto import sha256_hex
    with app.test_request_context():
        policy, clients = services.render_all()
    q(superconn, "INSERT INTO ui.apply_log (actor, action, policy_sha256, clients_sha256, success)"
                 " VALUES ('t', 'apply', %s, %s, true)", (sha256_hex(policy), sha256_hex(clients)))


def make_ready(app, superconn):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw1','198.51.100.11',"
                 "'AbCdEfGhIjKlMnOpQrStUvWx12345678')")
    q(superconn, "INSERT INTO ui.access_rule (priority, connection, ad_group, vlan) VALUES (10,'wired','Staff',100)")
    q(superconn, "UPDATE ui.setting SET value='198.51.100.0/24' WHERE key='admin_subnet'")
    mark_applied(app, superconn)


def test_dashboard_strip_until_finished(app, browser, superconn, logged_in):
    logged_in("admin")
    t = browser.text(browser.get("/dashboard"))
    assert "Finish setting up this server" in t and "1 of 5 required steps done" in t   # FreeRADIUS is up
    t = browser.text(browser.get("/setup/"))
    assert "Still the example network 192.0.2.0/24" in t and "disabled" in t.split("Finish setup")[0][-80:]
    r = browser.post("/setup/", {"action": "finish"})
    assert r.status_code == 302 and "Finish the required steps first" in browser.text(browser.get("/setup/"))
    make_ready(app, superconn)
    t = browser.text(browser.get("/setup/"))
    assert "5 of 5 required steps done" in t and "All required steps are done." in t
    r = browser.post("/setup/", {"action": "finish"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert "Finish setting up this server" not in browser.text(browser.get("/dashboard"))
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action='setup.finish'")[0][0] == 1
    browser.post("/setup/", {"action": "reopen"})
    assert "Finish setting up this server" in browser.text(browser.get("/dashboard"))


def test_status_follows_live_state(app, browser, superconn, logged_in):
    logged_in("admin")
    app.fake_helper.fail_next["status"] = {"message": "helper unavailable (test)"}
    t = browser.text(browser.get("/setup/"))
    assert "helper unavailable (test)" in t
    make_ready(app, superconn)
    q(superconn, "UPDATE ui.radius_client SET description='x', ipaddr='198.51.100.12'")   # now pending
    assert "Pending changes" in browser.text(browser.get("/setup/"))


def test_skip_only_optional_steps(browser, superconn, logged_in):
    logged_in("admin")
    r = browser.post("/setup/", {"action": "skip", "item": "radsec"})
    assert r.status_code == 302
    t = browser.text(browser.get("/setup/"))
    assert re.search(r'class="is-skipped".*?RadSec', t, re.S)
    assert browser.post("/setup/", {"action": "skip", "item": "clients"}).status_code == 400
    assert browser.post("/setup/", {"action": "skip", "item": "nonsense"}).status_code == 400
    browser.post("/setup/", {"action": "restore", "item": "radsec"})
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='setup_skipped'") == [("",)]
    assert [a for (a,) in q(superconn, "SELECT action FROM ui.audit_log WHERE action LIKE %s ORDER BY id",
                             ("setup.%",))] == ["setup.skip", "setup.restore"]


def test_admins_only(browser, logged_in):
    logged_in("operator")
    assert browser.get("/setup/").status_code == 403
    assert "Finish setting up this server" not in browser.text(browser.get("/dashboard"))
