"""One action disables and removes Duo (SPEC section 29.3): provider off (and, when asked, the
second-factor rules that name it), apply, then the helper's integration_remove. Every step is
audited; the helper's own reason shows when it refuses."""
from test_duo_apply import applies, breakdown, installed
from test_duo_portal import SETTINGS_FORM, admin, audit, helper_of, idir, q  # noqa: F401 (fixture)
from test_mfa import REMOTE_FORM


def duo_on_and_applied(browser, superconn, logged_in):
    installed(browser)
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    browser.post("/apply/apply", {}, csrf_page="/apply/")


def actions(browser, n=0):
    return [r["action"] for r in helper_of(browser).requests[n:]]


def test_disable_and_remove_in_one_action(app, browser, superconn, logged_in, idir):
    duo_on_and_applied(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    assert "Disable and remove Duo" in body and "Disable Duo and remove it?" in body
    n, a = len(helper_of(browser).requests), applies(browser)
    r = browser.post("/integrations/duo/remove", csrf_page="/integrations/duo", follow_redirects=True)
    assert r.status_code == 200
    assert q(superconn, "SELECT enabled FROM ui.mfa_provider WHERE id='duo'") == [(False,)]
    assert applies(browser) == a + 1 and "integration_remove" in actions(browser, n)
    assert "radius_admin_mfa_duo" not in helper_of(browser).staged["clients"][0]
    assert not breakdown(app)["pending"]
    assert audit(superconn, "integration.configure")[-1] == {"enabled": {"from": True, "to": False}}
    assert audit(superconn, "config.apply")[-1]["source"] == "duo_remove"
    assert audit(superconn, "integration.remove_requested")
    assert "removal" in browser.text(r).lower()


def test_already_off_removes_without_an_apply(browser, superconn, logged_in, idir):
    duo_on_and_applied(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", then="apply"), csrf_page="/integrations/duo")
    body = browser.text(browser.get("/integrations/duo"))
    assert "Disable and remove Duo" not in body and ">Remove Duo<" in body
    a = applies(browser)
    browser.post("/integrations/duo/remove", csrf_page="/integrations/duo")
    assert applies(browser) == a and actions(browser)[-1] == "integration_remove"


def test_a_rule_that_names_duo_is_turned_off_only_when_asked(browser, superconn, logged_in, idir):
    duo_on_and_applied(browser, superconn, logged_in)
    q(superconn, "UPDATE ui.mfa_policy SET enabled=true, provider_id='duo', client_scope='all'"
                 " WHERE account_kind='local'")
    body = browser.text(browser.get("/integrations/duo"))
    rule = "Local device admin accounts require Duo on all clients"
    assert rule in body and 'name="rules_off"' in body
    n, a = len(helper_of(browser).requests), applies(browser)
    r = browser.post("/integrations/duo/remove", csrf_page="/integrations/duo", follow_redirects=True)
    assert rule in browser.text(r) and applies(browser) == a and "integration_remove" not in actions(browser, n)
    assert q(superconn, "SELECT enabled FROM ui.mfa_provider WHERE id='duo'") == [(True,)]
    assert q(superconn, "SELECT enabled FROM ui.mfa_policy WHERE account_kind='local'") == [(True,)]
    browser.post("/integrations/duo/remove", {"rules_off": "1"}, csrf_page="/integrations/duo")
    assert q(superconn, "SELECT enabled FROM ui.mfa_policy WHERE account_kind='local'") == [(False,)]
    assert audit(superconn, "integration.policy")[-1]["local"]["enabled"] == {"from": True, "to": False}
    assert applies(browser) == a + 1 and actions(browser)[-1] == "integration_remove"


def test_other_pending_changes_stop_it(browser, superconn, logged_in, idir):
    duo_on_and_applied(browser, superconn, logged_in)
    browser.post("/integrations/remote/new", REMOTE_FORM)
    n, a = len(helper_of(browser).requests), applies(browser)
    r = browser.post("/integrations/duo/remove", csrf_page="/integrations/duo", follow_redirects=True)
    assert "Other changes are pending" in browser.text(r) and "nps-mfa" in browser.text(r)
    assert applies(browser) == a and "integration_remove" not in actions(browser, n)
    assert q(superconn, "SELECT enabled FROM ui.mfa_provider WHERE id='duo'") == [(True,)]


def test_a_failed_apply_stops_before_the_removal(browser, superconn, logged_in, idir):
    duo_on_and_applied(browser, superconn, logged_in)
    why = "restart failed (freeradius did not start); previous configuration restored"
    helper_of(browser).fail_next["apply"] = {"message": why}
    n = len(helper_of(browser).requests)
    r = browser.post("/integrations/duo/remove", csrf_page="/integrations/duo", follow_redirects=True)
    assert why in browser.text(r) and "integration_remove" not in actions(browser, n)


def test_the_helpers_reason_is_shown(browser, superconn, logged_in, idir):
    installed(browser)
    admin(browser, superconn, logged_in)
    why = "FreeRADIUS still uses Duo Authentication Proxy: turn the provider off and apply the changes first"
    helper_of(browser).fail_next["integration_remove"] = {"message": why}
    r = browser.post("/integrations/duo/remove", csrf_page="/integrations/duo", follow_redirects=True)
    assert why in browser.text(r)
    assert audit(superconn, "integration.remove_requested")[-1]["message"] == why
