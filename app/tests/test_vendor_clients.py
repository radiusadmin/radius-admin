"""A vendor profile and a CoA port per RADIUS client (SPEC section 26): the client form, the
default profile setting, rendering for Apply, CoA through the monitor, the sessions page and
the CSV import column."""
import re

import pytest

from conftest import APP_DSN
from test_client_import import do_import
from test_operations import _client, _radclient, _session, q

GENERIC = "generic-rfc"
SETTINGS = {"admin_subnet": "192.0.2.0/24", "banner_text": "This system is for authorized use only. Testing."}


def _render(app):
    from radius_admin import services
    with app.app_context():
        return services.render_all()


def _profile_of(superconn, name):
    return q(superconn, "SELECT vendor_profile, coa_port FROM ui.radius_client WHERE name = %s", (name,))[0]


# ----------------------------------------------------------------------- client form
def test_client_form_sets_profile_and_port(app, browser, superconn, logged_in):
    logged_in("operator")
    t = browser.text(browser.get("/clients/new"))
    assert "Device profile" in t and "Default: Cisco Catalyst 1200/1300" in t
    assert ">Generic (RFC standard attributes)</option>" in t and "tested on hardware" not in t
    assert "Session-action port (UDP)" in t
    r = browser.post("/clients/new", {"name": "ap-1", "ipaddr": "192.0.2.31", "secret_mode": "set",
                                      "secret": "Plaintext-Key-0031-abcdef", "vendor_profile": GENERIC,
                                      "coa_port": "3800", "enabled": "1"}, csrf_page="/clients/new")
    # setting a secret asks for step-up; the operator's session from logged_in has it
    assert r.status_code in (200, 302), browser.text(r)[:2000]
    assert _profile_of(superconn, "ap-1") == (GENERIC, 3800)
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action = 'client.create'")[0][0]
    assert d["vendor_profile"] == GENERIC and d["coa_port"] == 3800
    cid = q(superconn, "SELECT id FROM ui.radius_client WHERE name = 'ap-1'")[0][0]
    t = browser.text(browser.get("/clients/%d/edit" % cid))
    assert re.search(r'<option value="generic-rfc" selected', t)
    r = browser.post("/clients/%d/edit" % cid, {"name": "ap-1", "ipaddr": "192.0.2.31", "secret_mode": "keep",
                                                 "vendor_profile": "", "coa_port": "", "enabled": "1"},
                     csrf_page="/clients/%d/edit" % cid)
    assert r.status_code == 302, browser.text(r)[:2000]
    assert _profile_of(superconn, "ap-1") == (None, None)
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action = 'client.update'")[0][0]
    assert d["changed"] == {"vendor_profile": None, "coa_port": None}
    t = browser.text(browser.get("/clients/"))
    assert "Device profile / options" in t and "Cisco Catalyst 1200/1300" in t


@pytest.mark.parametrize("field,value,message", [
    ("vendor_profile", "no-such-profile", "Choose a device profile from the list."),
    ("vendor_profile", "../etc", "Choose a device profile from the list."),
    ("coa_port", "0", "Enter a UDP port from 1 to 65535"),
    ("coa_port", "70000", "Enter a UDP port from 1 to 65535"),
    ("coa_port", "17x0", "Enter a UDP port from 1 to 65535"),
])
def test_client_form_refuses_bad_profile_or_port(app, browser, superconn, logged_in, field, value, message):
    cid = _client(superconn)
    logged_in("operator")
    form = {"name": "sw1", "ipaddr": "192.0.2.10", "secret_mode": "keep", "enabled": "1", field: value}
    r = browser.post("/clients/%d/edit" % cid, form, csrf_page="/clients/%d/edit" % cid)
    assert r.status_code == 400 and message in browser.text(r)
    assert _profile_of(superconn, "sw1") == (None, None)


# ----------------------------------------------------------------------- rendering for Apply
def test_render_names_the_profile_of_clients_that_differ(app, superconn):
    _client(superconn, "sw1", "192.0.2.10")
    gid = _client(superconn, "ap-1", "192.0.2.31")
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = %s WHERE id = %s", (GENERIC, gid))
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = 'cisco-c1300' WHERE name = 'sw1'")  # = the default
    policy, clients = _render(app)
    assert clients.count("radius_admin_profile") == 1
    assert re.search(r"client ap-1 \{[^}]*\tradius_admin_profile = generic-rfc\n", clients)
    assert '"%{client:radius_admin_profile}" == "generic-rfc"' in policy
    assert "&Service-Type := Administrative-User" in policy and '&Cisco-AVPair += "shell:priv-lvl=15"' in policy


def test_render_without_other_profiles_is_unchanged(app, superconn):
    from radius_admin import unlang
    gid = _client(superconn, "ap-1", "192.0.2.31")
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = %s, enabled = false WHERE id = %s", (GENERIC, gid))
    policy, clients = _render(app)
    assert policy == unlang.render_policy("")          # a disabled client adds no branch
    assert "radius_admin_profile" not in clients


def test_render_refuses_a_profile_the_server_lacks(app, superconn):
    from radius_admin import unlang
    gid = _client(superconn, "ap-1", "192.0.2.31")
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = 'gone-profile' WHERE id = %s", (gid,))
    with pytest.raises(unlang.PolicyInputError, match="ap-1 uses vendor profile gone-profile"):
        _render(app)


def test_default_profile_setting(app, browser, superconn, logged_in):
    _client(superconn, "sw1", "192.0.2.10")
    cid = _client(superconn, "sw2", "192.0.2.11")
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = 'cisco-c1300' WHERE id = %s", (cid,))
    logged_in("admin")
    t = browser.text(browser.get("/settings"))
    assert "Default device profile" in t and "takes effect when you next apply changes" in t
    r = browser.post("/settings", dict(SETTINGS, default_vendor_profile="nope"))
    assert r.status_code == 400 and "Choose a device profile from the list." in browser.text(r)
    r = browser.post("/settings", dict(SETTINGS, default_vendor_profile=GENERIC))
    assert r.status_code == 302
    assert q(superconn, "SELECT value FROM ui.setting WHERE key = 'default_vendor_profile'") == [(GENERIC,)]
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action = 'settings.update' ORDER BY id DESC LIMIT 1")[0][0]
    assert d["default_vendor_profile"] == {"from": "cisco-c1300", "to": GENERIC}
    policy, clients = _render(app)
    # sw1 follows the new default; sw2 keeps the Catalyst profile it names
    assert re.search(r"client sw2 \{[^}]*\tradius_admin_profile = cisco-c1300\n", clients)
    assert not re.search(r"client sw1 \{[^}]*radius_admin_profile", clients)
    assert '"%{client:radius_admin_profile}" == "cisco-c1300"' in policy
    assert policy.index("Cisco-AVPair") < policy.index("Service-Type := Administrative-User")   # default in else


# ----------------------------------------------------------------------- CoA through the monitor
def test_monitor_uses_the_clients_profile_and_port(app, superconn):
    from fake_coa import FakeSwitch
    from radius_admin import db, snmp_poller
    rc, dd = _radclient()
    if not rc:
        pytest.skip("radclient not available (set RADIUS_ADMIN_TEST_FR_PREFIX to a FreeRADIUS install prefix)")
    sw = FakeSwitch("Plaintext-Key-0001-abcdef")
    try:
        cid = _client(superconn, ip="127.0.0.1")
        q(superconn, "UPDATE ui.radius_client SET vendor_profile = %s, coa_port = %s WHERE id = %s",
          (GENERIC, sw.port, cid))
        for action in ("disconnect", "reauth"):
            q(superconn, "INSERT INTO ui.coa_request (client_id, action, acct_session_id, calling_station_id, nas_ip,"
                         " nas_port_id, username, requested_by) VALUES (%s, %s, '0000002D', 'AA-BB-CC-00-00-04',"
                         " '127.0.0.1', '1/1/4', 'host/pc4', 'op')", (cid, action))
        conn = db.connect(APP_DSN)
        try:
            snmp_poller.run_coa(conn, {"radclient": rc, "radius_dict_dir": dd}, snmp_poller.load_profile(conn))
            conn.commit()
        finally:
            conn.close()
        res = q(superconn, "SELECT action, ok, message FROM ui.coa_request ORDER BY id")
        assert res[0][:2] == ("disconnect", True) and "Disconnect-ACK" in res[0][2]
        assert res[1][:2] == ("reauth", False) and "no reauth action" in res[1][2]
        (got,) = sw.requests                        # the refused action was never sent
        assert got["code"] == "Disconnect-Request" and got["cisco"] == []
        assert got["attrs"]["Acct-Session-Id"] == "0000002D" and got["attrs"]["Calling-Station-Id"] == "AA-BB-CC-00-00-04"
    finally:
        sw.close()


def test_coa_port_falls_back_to_the_profile():
    from radius_admin import vendors
    assert vendors.coa_port({"coa_port": None}, vendors.default()) == 1700
    assert vendors.coa_port({}, vendors.builtin(GENERIC)) == 3799
    assert vendors.coa_port({"coa_port": 1812}, vendors.builtin(GENERIC)) == 1812


# ----------------------------------------------------------------------- sessions page
def test_sessions_offer_only_the_actions_the_profile_has(app, browser, superconn, logged_in):
    cid = _client(superconn)
    sid = _session(superconn)
    logged_in("operator")
    row = re.search(r'data-session="%d">(.*?)</tr>' % sid, browser.text(browser.get("/sessions/")), re.S).group(1)
    assert "Re-authenticate" in row and "Bounce port" in row and "Disconnect" in row
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = %s WHERE id = %s", (GENERIC, cid))
    row = re.search(r'data-session="%d">(.*?)</tr>' % sid, browser.text(browser.get("/sessions/")), re.S).group(1)
    assert "Re-authenticate" not in row and "Bounce port" not in row and "Disconnect" in row
    r = browser.post("/sessions/coa", {"sid": [sid], "action": "bounce"}, csrf_page="/sessions/")
    assert r.status_code == 302 and not q(superconn, "SELECT 1 FROM ui.coa_request")
    t = browser.text(browser.get(r.headers["Location"]))
    assert "sw1 (Generic (RFC standard attributes)) cannot bounce a port" in t
    r = browser.post("/sessions/coa", {"sid": [sid], "action": "disconnect"}, csrf_page="/sessions/")
    assert q(superconn, "SELECT action FROM ui.coa_request") == [("disconnect",)]


def test_accounting_setup_text_follows_the_profiles(app, browser, superconn, logged_in):
    cid = _client(superconn)
    logged_in("viewer")
    t = browser.text(browser.get("/sessions/"))
    assert "Cisco Catalyst 1200/1300:" in t and "aaa accounting dot1x start-stop group radius" in t
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = %s WHERE id = %s", (GENERIC, cid))
    t = browser.text(browser.get("/sessions/"))
    assert "aaa accounting" not in t
    assert "Generic (RFC standard attributes): enable RADIUS accounting with start and stop records" in t


# ----------------------------------------------------------------------- CSV import
def test_import_vendor_profile_column(app, browser, superconn, logged_in):
    logged_in("admin")
    do_import(browser, "ip,secret,hostname,secret_type,vendor_profile\r\n"
                       "192.0.2.41,Example-Plaintext-Key-0041,sw-41,plaintext,generic-rfc\r\n"
                       "192.0.2.42,Example-Plaintext-Key-0042,sw-42,plaintext,\r\n")
    assert _profile_of(superconn, "sw-41")[0] == GENERIC and _profile_of(superconn, "sw-42")[0] is None
    # empty keeps the current profile, "default" resets it, an id sets it
    do_import(browser, "ip,secret,hostname,secret_type,vendor_profile\r\n"
                       "192.0.2.41,Example-Plaintext-Key-0041,sw-41,plaintext,\r\n"
                       "192.0.2.42,Example-Plaintext-Key-0042,sw-42,plaintext,generic-rfc\r\n")
    assert _profile_of(superconn, "sw-41")[0] == GENERIC and _profile_of(superconn, "sw-42")[0] == GENERIC
    do_import(browser, "ip,secret,hostname,secret_type,vendor_profile\r\n"
                       "192.0.2.41,Example-Plaintext-Key-0041,sw-41,plaintext,default\r\n")
    assert _profile_of(superconn, "sw-41")[0] is None


def test_import_refuses_an_unknown_profile():
    from radius_admin import client_import as ci, unlang
    with pytest.raises(ci.ImportError_) as e:
        ci.parse_csv("ip,secret,hostname,secret_type,vendor_profile\r\n"
                     "192.0.2.41,Example-Plaintext-Key-0041,sw-41,plaintext,juniper\r\n", unlang)
    assert "vendor_profile must be default or one of: cisco-c1300, generic-rfc." in str(e.value.errors)


# ----------------------------------------------------------------------- a role per access rule
def test_rule_role_field(app, browser, superconn, logged_in):
    logged_in("operator")
    form = {"connection": "wired", "ad_group": "Wired-Office", "vlan": "500", "priority": "10", "enabled": "1"}
    r = browser.post("/rules/new", dict(form, role="office-staff"), csrf_page="/rules/new")
    assert r.status_code == 302, browser.text(r)[:2000]
    rid, role = q(superconn, "SELECT id, role FROM ui.access_rule")[0]
    assert role == "office-staff"
    assert q(superconn, "SELECT detail->>'role' FROM ui.audit_log WHERE action = 'rule.create'") == [("office-staff",)]
    t = browser.text(browser.get("/rules/"))
    assert "office-staff" in t
    for bad in ('x"y', "two words", "a" * 65, "%{exec:/bin/id}"):
        r = browser.post("/rules/%d/edit" % rid, dict(form, role=bad), csrf_page="/rules/%d/edit" % rid)
        assert r.status_code == 400 and "A role is 1-64 letters" in browser.text(r), bad
    r = browser.post("/rules/%d/edit" % rid, dict(form, role=""), csrf_page="/rules/%d/edit" % rid)
    assert r.status_code == 302 and q(superconn, "SELECT role FROM ui.access_rule") == [(None,)]


def test_rule_role_lookup_function(superconn):
    rid = q(superconn, "INSERT INTO ui.access_rule (priority, connection, ad_group, vlan, role) VALUES"
                       " (10, 'wired', 'Wired-Office', 500, 'office-staff') RETURNING id")[0][0]
    assert q(superconn, "SELECT radius_admin_rule_role(%s)", (rid,)) == [("office-staff",)]
    assert q(superconn, "SELECT radius_admin_rule_role(%s)", (rid + 1000,)) == [("",)]
    assert q(superconn, "SELECT radius_admin_rule_role(9999999999)") == [("",)]      # 10 digits: no overflow
    q(superconn, "UPDATE ui.access_rule SET enabled = false")
    assert q(superconn, "SELECT radius_admin_rule_role(%s)", (rid,)) == [("",)]
    import psycopg2
    for bad in ('x"; reject', "two words", "", "a" * 65, "ä"):
        with pytest.raises(psycopg2.errors.CheckViolation):
            q(superconn, "UPDATE ui.access_rule SET role = %s", (bad,))
    grants = dict(q(superconn, "SELECT r, has_function_privilege(r, 'radius_admin_rule_role(bigint)', 'EXECUTE')"
                               " FROM unnest(ARRAY['radius_fr', 'radius_admin']) r"))
    assert grants == {"radius_fr": True, "radius_admin": False}
