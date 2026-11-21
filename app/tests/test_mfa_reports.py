"""Second factor in reports, the authentication log, the setup checklist and the device
timeout advice (SPEC section 29.4)."""
import csv
import io
import json

from conftest import stepup


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def provider(superconn, pid="duo", ptype="duo", enabled=True, label="Duo Authentication Proxy on this server"):
    q(superconn, "INSERT INTO ui.mfa_provider (id, type, label, enabled) VALUES (%s, %s, %s, %s)",
      (pid, ptype, label, enabled))


def rule(superconn, kind, pid, enabled=True, scope="all"):
    q(superconn, "UPDATE ui.mfa_policy SET enabled=%s, provider_id=%s, client_scope=%s WHERE account_kind=%s",
      (enabled, pid, scope, kind))


def add_client(superconn, name, ip, profile=None, enabled=True):
    return q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, vendor_profile, enabled)"
                        " VALUES (%s, %s, %s, %s, %s) RETURNING id",
             (name, ip, "TestSwitchSecret0123456789", profile, enabled))[0][0]


def add_device_admin(superconn, name):
    q(superconn, "INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, 'net-admins', 1)", (name,))
    q(superconn, "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'PBKDF2-Password', ':=', %s)",
      (name, "HMACSHA2+SHA256:AAAnEA==:c2FsdHNhbHRzYWx0:aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA=="))


def admin(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    return u


# ------------------------------------------------------------------ privileged-access report
def test_report_without_second_factor(browser, superconn, logged_in):
    add_device_admin(superconn, "netops1")
    admin(browser, superconn, logged_in)
    t = browser.text(browser.get("/reports/privileged"))
    assert "Second factor for device admin logins" in t
    assert "not required" in t and "n/a" not in t
    assert "nobody can log in" not in t


def test_report_lists_coverage_and_exemptions(browser, superconn, logged_in):
    add_device_admin(superconn, "netops1")
    add_device_admin(superconn, "breakglass")
    provider(superconn)
    provider(superconn, "nps", "radius-mfa", enabled=False, label="")
    rule(superconn, "local", "duo")
    rule(superconn, "directory", "nps", scope="selected")
    cid = add_client(superconn, "fw-edge", "192.0.2.20")
    q(superconn, "INSERT INTO ui.mfa_policy_client (account_kind, client_id) VALUES ('directory', %s)", (cid,))
    q(superconn, "INSERT INTO ui.mfa_exempt (username) VALUES ('BreakGlass')")
    admin(browser, superconn, logged_in)
    body = browser.get("/reports/privileged?format=csv").get_data(as_text=True)
    rows = list(csv.reader(io.StringIO(body.lstrip("﻿"))))
    by_name = {r[0]: r for r in rows if len(r) >= 7}
    assert by_name["netops1"][5] == "Duo Authentication Proxy on this server, on all clients"
    assert by_name["breakglass"][5] == "exempt (break-glass)"
    sec = rows.index(["Second factor for device admin logins"])
    assert rows[sec + 1] == ["Accounts", "Required", "Provider", "Provider state", "Clients", "Exempt (break-glass)"]
    assert rows[sec + 2] == ["Local device admin accounts", "yes", "Duo Authentication Proxy on this server", "on",
                             "all clients", "BreakGlass"]
    assert rows[sec + 3] == ["Directory accounts", "yes", "Remote RADIUS MFA server", "off", "fw-edge", "—"]
    t = browser.text(browser.get("/reports/privileged"))
    assert "rejected when its provider is off or does not answer" in t
    # no exemption: the lock-out warning
    q(superconn, "DELETE FROM ui.mfa_exempt")
    t = browser.text(browser.get("/reports/privileged"))
    assert "No local device admin is exempt" in t and "FIPS" not in t


def test_coverage_text_names_a_provider_that_is_off():
    from radius_admin import integrations as ig
    c = {"enabled": True, "provider": "Duo", "provider_on": False, "clients": ["sw1", "sw2"]}
    assert ig.coverage_text(c) == "required on selected clients: sw1, sw2, but Duo is off: these logins are rejected"
    assert ig.coverage_text(dict(c, enabled=False)) == "not required"


# ------------------------------------------------------------------ authentication log
def _auth(superconn, method, reply="Access-Accept", age="0 minutes"):
    return q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, authdate)"
                        " VALUES ('netops1', %s, %s, '192.0.2.10', now() - %s::interval) RETURNING id",
             (reply, method, age))[0][0]


def _policy_event(superconn, detail):
    """An integration.policy audit record written now (the audit log is hash-chained)."""
    from radius_admin import audit
    audit.write("integration.policy", actor="admin1", object_type="mfa_policy", detail=detail, conn=superconn)


def test_auth_detail_shows_the_provider_of_the_time(browser, superconn, logged_in):
    provider(superconn)
    provider(superconn, "nps", "radius-mfa", label="Office NPS")
    rule(superconn, "local", "duo")
    rule(superconn, "directory", "nps")
    old = _auth(superconn, "admin-ldap+mfa", age="3 hours")
    # then the directory rule was moved from duo to nps
    _policy_event(superconn, {"directory": {"provider_id": {"from": "duo", "to": "nps"}}})
    _policy_event(superconn, {"exempt": {"from": [], "to": ["breakglass"]}})
    new = _auth(superconn, "admin-ldap+mfa", age="-1 minute")
    plain = _auth(superconn, "pap-admin", age="-1 minute")
    local = _auth(superconn, "pap-admin+mfa", reply="Access-Reject", age="-1 minute")
    logged_in("viewer")
    t = browser.text(browser.get("/auth-log/%d" % new))
    assert "Second factor</dt><dd>Office NPS" in t and ">nps<" in t
    t = browser.text(browser.get("/auth-log/%d" % old))
    assert "Second factor</dt><dd>Duo Authentication Proxy on this server" in t
    t = browser.text(browser.get("/auth-log/%d" % local))
    assert "Second factor</dt><dd>Duo Authentication Proxy on this server" in t
    assert "Second factor</dt>" not in browser.text(browser.get("/auth-log/%d" % plain))
    # a rule that named no provider at that time
    early = _auth(superconn, "pap-admin+mfa", age="1 minute")
    _policy_event(superconn, {"local": {"provider_id": {"from": None, "to": "duo"},
                                        "enabled": {"from": False, "to": True}}})
    assert "Provider not known" in browser.text(browser.get("/auth-log/%d" % early))
    # a failed change does not count
    from radius_admin import audit
    audit.write("integration.policy", actor="admin1", success=False, object_type="mfa_policy",
                detail={"local": {"provider_id": {"from": "nps", "to": "duo"}}}, conn=superconn)
    assert "Provider not known" in browser.text(browser.get("/auth-log/%d" % early))


def test_provider_at_and_login_provider(app, superconn):
    from radius_admin import integrations as ig
    provider(superconn)
    rule(superconn, "local", "duo")
    with app.app_context():
        assert ig.login_provider("pap-admin", None) is None
        assert ig.login_provider("mab", "2026-01-01") is None
        assert ig.login_provider("pap-admin+mfa", "2026-01-01")["id"] == "duo"
        _policy_event(superconn, {"local": {"provider_id": {"from": "gone", "to": "duo"}}})
        lp = ig.login_provider("pap-admin+mfa", "2000-01-01")
        assert lp == {"id": "gone", "kind": "local", "type": "", "label": "gone"}     # deleted since


# ------------------------------------------------------------------ setup checklist
def test_setup_checklist_has_an_optional_second_factor_step(browser, superconn, logged_in):
    admin(browser, superconn, logged_in)
    t = browser.text(browser.get("/setup/"))
    assert "Second factor for device admins" in t
    from radius_admin.views import setup
    with browser.app.test_request_context():
        from flask import g
        g.user = {"username": "admin1", "role": "admin"}
        items = {i[0]: i for i in setup.checklist()}
    assert items["mfa"][2] is False and items["mfa"][3] is False and items["mfa"][4] == "Off"
    assert items["mfa"][5] == "integrations.index"
    provider(superconn, enabled=False)
    rule(superconn, "local", "duo")
    with browser.app.test_request_context():
        items = {i[0]: i for i in setup.checklist()}
    assert items["mfa"][3] is False and "is off" in items["mfa"][4]
    q(superconn, "UPDATE ui.mfa_provider SET enabled = true")
    with browser.app.test_request_context():
        items = {i[0]: i for i in setup.checklist()}
    assert items["mfa"][3] is True
    assert items["mfa"][4] == "Local device admin accounts: Duo Authentication Proxy on this server, on all clients"
    # optional: it can be skipped
    r = browser.post("/setup/", {"action": "skip", "item": "mfa"}, csrf_page="/setup/")
    assert r.status_code == 302


# ------------------------------------------------------------------ device timeout advice
def test_vendor_profiles_carry_a_timeout_hint():
    from radius_admin import vendors
    c1300 = vendors.builtin("cisco-c1300")
    text, commands = vendors.mfa_timeout_hint(c1300)
    assert commands and "radius-server timeout" in text
    text, commands = vendors.mfa_timeout_hint(vendors.builtin("generic-rfc"))
    assert not commands and text == vendors.GENERIC_MFA_TIMEOUT and "60 seconds" in text
    # custom profiles: the form round trip keeps it
    f = vendors.profile_to_form(c1300)
    assert f["setup_mfa_timeout"] == c1300["setup"]["mfa_timeout"]
    p, errors = vendors.form_to_profile(dict(f, id="custom-a", setup_mfa_timeout="radius-server timeout 45\r\n"))
    assert errors == {} and p["setup"]["mfa_timeout"] == "radius-server timeout 45"
    p, errors = vendors.form_to_profile(dict(f, id="custom-b", setup_mfa_timeout="  "))
    assert p["setup"]["mfa_timeout"] is None
    p, errors = vendors.form_to_profile(dict(f, id="custom-c", setup_mfa_timeout="x\x01y"))
    assert "setup_mfa_timeout" in errors


def test_integrations_page_shows_the_timeout_per_profile(browser, superconn, logged_in):
    add_client(superconn, "sw1", "192.0.2.21", "cisco-c1300")
    add_client(superconn, "sw2", "192.0.2.22", "cisco-c1300")
    fw = add_client(superconn, "fw-edge", "192.0.2.20", "generic-rfc")
    add_client(superconn, "old", "192.0.2.23", "cisco-c1300", enabled=False)
    logged_in("viewer")
    t = browser.text(browser.get("/integrations/"))
    assert "RADIUS timeout on the devices" in t
    assert "Cisco Catalyst 1200/1300 <span class=\"small muted\">2 clients</span>" in t
    assert "<pre class=\"code\">radius-server timeout 30" in t
    assert "1 client</span>" in t and "at least 60 seconds in total" in t
    # rules for selected clients only: the advice for those
    provider(superconn)
    rule(superconn, "local", "duo", scope="selected")
    q(superconn, "INSERT INTO ui.mfa_policy_client (account_kind, client_id) VALUES ('local', %s)", (fw,))
    t = browser.text(browser.get("/integrations/"))
    assert "Cisco Catalyst" not in t.split("RADIUS timeout on the devices")[1]
    assert "at least 60 seconds in total" in t
