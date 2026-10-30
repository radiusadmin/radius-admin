"""SPEC section 10: access rules and settings are live; tester uses radius_admin_vlan()."""
import os

import pytest

from conftest import fresh_code


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


SEED = [  # SPEC section 8
    (10, "wired", None, "Wired-Support", 510), (20, "wired", None, "Wired-Office", 500), (30, "wired", None, "Wired-Utility", 520),
    (10, "wireless", "Example_Main_Test", "Wireless-Office-Test", 530), (10, "wireless", "Example_Admin", "WIRELESS-SUPPORT", 510),
    (10, "wireless", "Example_Main", "WIRELESS-OFFICE", 530),
]


@pytest.fixture
def seeded(superconn):
    for r in SEED:
        q(superconn, "INSERT INTO ui.access_rule (priority, connection, ssid, ad_group, vlan) VALUES (%s,%s,%s,%s,%s)", r)


def run_tester(browser, connection, groups, ssid="", called=""):
    r = browser.post("/rules/", {"t_connection": connection, "t_ssid": ssid, "t_called": called,
                                 "t_groups": "\n".join(groups)}, csrf_page="/rules/")
    return r, browser.text(r)


def test_tester_wired_first_match_and_case_insensitive(browser, superconn, logged_in, seeded):
    logged_in("viewer")  # read-only role may use it
    r, t = run_tester(browser, "wired", ["Domain Computers", "wired-office", "WIRED-SUPPORT"])
    assert r.status_code == 200
    assert "Accept, VLAN" in t and '<span class="vlan">510</span></p>' in t  # Wired-Support priority 10 wins
    assert "Wired-Support" in t
    r, t = run_tester(browser, "wired", ["wired-utility"])
    assert '<span class="vlan">520</span></p>' in t


def test_tester_wireless_by_ssid_and_called_station(browser, superconn, logged_in, seeded):
    logged_in("viewer")
    r, t = run_tester(browser, "wireless", ["wireless-support"], ssid="Example_Admin")
    assert '<span class="vlan">510</span></p>' in t
    r, t = run_tester(browser, "wireless", ["WIRELESS-OFFICE"], called="AA-BB-CC-DD-EE-FF:Example_Main")
    assert '<span class="vlan">530</span></p>' in t
    # SSID suffix must be ':'-anchored: Example_Main must not match ...:Example_Main_Test
    r, t = run_tester(browser, "wireless", ["WIRELESS-OFFICE"], called="AA-BB-CC-DD-EE-FF:Example_Main_Test")
    assert "Reject, no VLAN" in t


def test_tester_unknown_ssid(browser, superconn, logged_in, seeded):
    logged_in("viewer")
    r, t = run_tester(browser, "wireless", ["WIRELESS-SUPPORT"], ssid="Guest")
    assert "Reject, no VLAN" in t and "No enabled wireless rule exists for this SSID" in t


def test_tester_wired_group_does_not_match_wireless(browser, superconn, logged_in, seeded):
    logged_in("viewer")
    r, t = run_tester(browser, "wireless", ["Wired-Support"], ssid="Example_Admin")
    assert "Reject, no VLAN" in t and "None of these groups" in t
    r, t = run_tester(browser, "wired", ["WIRELESS-SUPPORT"])
    assert "Reject, no VLAN" in t


def test_tester_disabled_rule_ignored(browser, superconn, logged_in, seeded):
    logged_in("operator")
    q(superconn, "UPDATE ui.access_rule SET enabled=false WHERE ad_group='Wired-Support'")
    r, t = run_tester(browser, "wired", ["Wired-Support", "Wired-Office"])
    assert '<span class="vlan">500</span></p>' in t
    r, t = run_tester(browser, "wired", ["Wired-Support"])
    assert "Reject, no VLAN" in t


def test_tester_vlan_comes_from_function(browser, superconn, logged_in, seeded):
    """The shown VLAN equals radius_admin_vlan() called as radius_admin (grant exercised)."""
    logged_in("viewer")
    r, t = run_tester(browser, "wired", ["Wired-Office"])
    got = q(superconn, "SELECT radius_admin_vlan('Ethernet', '', 'Wired-Office')")[0][0]
    assert got == "500" and '<span class="vlan">500</span></p>' in t
    assert "radius_admin_vlan('Ethernet', '', 'Wired-Office')" in t


def test_tester_input_validation(browser, superconn, logged_in, seeded):
    logged_in("viewer")
    r, t = run_tester(browser, "wired", [])
    assert r.status_code == 400 and "at least one AD group" in t
    r, t = run_tester(browser, "wireless", ["X"])
    assert r.status_code == 400 and "SSID" in t
    r, t = run_tester(browser, "wired", ["a,b"])
    assert r.status_code == 400
    # No data change from the tester
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action LIKE 'rule.%%'")[0][0] == 0


def _apply_once(browser):
    r = browser.post("/apply/apply", {}, csrf_page="/apply/")
    assert "Configuration applied" in browser.text(r)
    assert "Pending changes" not in browser.text(browser.get("/dashboard"))


def test_rules_and_settings_do_not_create_pending(browser, superconn, logged_in):
    u = logged_in("admin")
    _apply_once(browser)
    # rule create / edit / reorder / delete
    for prio, grp in ((10, "Wired-Support"), (20, "Wired-Office")):
        browser.post("/rules/new", {"connection": "wired", "ad_group": grp, "vlan": "510", "priority": str(prio), "enabled": "1"})
    browser.post("/rules/1/edit", {"connection": "wired", "ad_group": "Wired-Support", "vlan": "511", "priority": "10"})
    browser.post("/rules/2/move", {"direction": "up"}, csrf_page="/rules/")
    browser.post("/rules/2/delete", {}, csrf_page="/rules/")
    assert q(superconn, "SELECT count(*) FROM ui.access_rule")[0][0] == 1
    assert "Pending changes" not in browser.text(browser.get("/dashboard"))
    # settings
    r = browser.post("/settings", {"admin_subnet": "198.51.100.0/24", "admin_priv15": "1",
                                   "banner_text": "Authorized use only. Banner text for testing."})
    assert r.status_code == 302
    assert q(superconn, "SELECT radius_admin_priv15(), radius_admin_admin_source_ok('198.51.100.9')")[0] == (True, True)
    assert "Pending changes" not in browser.text(browser.get("/dashboard"))
    assert "FreeRADIUS matches the database" in browser.text(browser.get("/apply/"))
    acts = [a for (a,) in q(superconn, "SELECT action FROM ui.audit_log WHERE action LIKE 'rule.%%' OR action LIKE 'settings.%%'")]
    assert acts.count("rule.create") == 2 and "rule.update" in acts and "rule.reorder" in acts \
        and "rule.delete" in acts and "settings.update" in acts
    # clients and custom policy still create pending changes
    browser.post("/clients/new", {"name": "sw9", "ipaddr": "192.0.2.9", "secret_mode": "generate",
                                  "nas_type": "cisco", "require_ma": "auto", "limit_proxy_state": "auto", "enabled": "1"})
    assert "Pending changes" in browser.text(browser.get("/dashboard"))
    _apply_once(browser)
    r = browser.post("/custom-policy", {"custom_policy": "if (&User-Name == \"q\") {\n\treject\n}\n"})
    assert r.status_code == 302
    page = browser.text(browser.get("/dashboard"))
    assert "Pending changes" in page and "Custom policy" in page


def test_settings_validation_live(browser, superconn, logged_in):
    logged_in("admin")
    for bad in ("192.0.2.1/24", "0.0.0.0/0", "not-a-net"):
        r = browser.post("/settings", {"admin_subnet": bad, "banner_text": "x" * 30})
        assert r.status_code == 400, bad
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='admin_subnet'") == [("192.0.2.0/24",)]


def _nav_groups(browser):
    t = browser.text(browser.get("/dashboard"))
    nav = t[t.index('id="sidenav"'):t.index("</nav>", t.index('id="sidenav"'))]
    parts = nav.split('<p class="nav-group">')
    return {p.split("</p>")[0]: p for p in parts[1:]}


def test_navigation_groups(browser, logged_in):
    logged_in("admin")
    g = _nav_groups(browser)
    assert list(g) == ["Network access", "Monitoring", "Records", "Administration"]
    for item in ("RADIUS clients", "Access rules", "MAB devices", "Switch admins", "Custom policy", "Apply changes"):
        assert item in g["Network access"], item
    for item in ("Settings", "Single sign-on", "UI admins", "Setup checklist"):
        assert item in g["Administration"], item


def test_navigation_without_administration_for_operators(browser, logged_in):
    logged_in("operator")
    g = _nav_groups(browser)
    assert "Administration" not in g and "Custom policy" not in g["Network access"]


def test_apply_note_only_where_apply_is_needed(browser, superconn, logged_in):
    logged_in("admin")
    q(superconn, "INSERT INTO ui.access_rule (priority, connection, ad_group, vlan) VALUES (10,'wired','Wired-Support',510)")
    for p in ("/rules/", "/rules/new", "/rules/1/edit", "/mab/", "/switch-admins/", "/settings", "/settings/sso"):
        assert 'class="apply-note"' not in browser.text(browser.get(p)), p      # saving takes effect at once
    for p in ("/clients/", "/clients/new", "/clients/radsec", "/clients/import", "/custom-policy"):
        t = browser.text(browser.get(p))
        assert "Changes here reach FreeRADIUS when you" in t, p
    t = browser.text(browser.get("/rules/"))
    assert "next authentication" in t and 'data-confirm="Delete the rule' in t


def test_format_upgrade_notice(app, browser, superconn, logged_in):
    """An apply_log baseline from the old (rules-in-unlang) render shows as pending
    once, and the Apply page explains it."""
    logged_in("operator")
    staging = app.config["RA"]["staging_dir"]
    from radius_admin.crypto import sha256_hex
    old_policy = "# generated by radius-admin - do not edit\npolicy radius_admin_postauth {\n\tif (LDAP-Group == \"Wired-Support\") {}\n}\n"
    os.makedirs(os.path.join(staging, "applied"), mode=0o700)
    for name, text in (("policy", old_policy), ("clients", "")):
        with open(os.path.join(staging, "applied", name), "w") as fh:
            fh.write(text)
    q(superconn, "INSERT INTO ui.apply_log (actor, action, policy_sha256, clients_sha256, success, backup_id)"
                 " VALUES ('old','apply',%s,%s,true,'20261001T000000Z')", (sha256_hex(old_policy), sha256_hex("")))
    from radius_admin import unlang
    assert "radius_admin_vlan_rule_hex(" in unlang.render_policy("")
    t = browser.text(browser.get("/dashboard"))
    assert "Pending changes" in t and "updates the FreeRADIUS policy file" in t
    t = browser.text(browser.get("/apply/"))
    assert "Policy format updated; apply once." in t
    _apply_once(browser)
    assert "Policy format updated" not in browser.text(browser.get("/apply/"))


def test_previous_release_policy_needs_one_apply():
    """A policy applied by the previous release (live rules, no MAB function) is reported
    as a format update; the current render is not."""
    from radius_admin import services, unlang
    new = unlang.render_policy("")
    old_live = new.replace("radius_admin_vlan_rule_hex(", "radius_admin_vlan_hex(").replace(
        "radius_admin_mab_hex(", "SELECT vlan FROM mab_device WHERE (")
    assert services.policy_format_upgrade(old_live, new)
    assert not services.policy_format_upgrade(new, new)
    assert not services.policy_format_upgrade(None, new)
