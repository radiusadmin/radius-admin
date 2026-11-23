"""Saving the Duo settings applies them from the Duo page (SPEC section 29.3): the pending
changes split by part (services.pending_breakdown), one apply path for the Apply page and the
Duo page (services.apply_now), the confirmation preview, and never a partial apply."""
import json

from test_duo_portal import SETTINGS_FORM, admin, audit, helper_of, idir, q  # noqa: F401 (fixture)
from test_mfa import REMOTE_FORM


def installed(browser):
    helper_of(browser).duo["installed"] = {"version": "6.8.1", "verified": "catalog"}


def breakdown(app):
    with app.test_request_context():
        from radius_admin import services
        return services.pending_breakdown()


def applies(browser):
    return len(helper_of(browser).backups)


def test_pending_breakdown_tells_duo_from_the_rest(app, browser, superconn, logged_in, idir):
    installed(browser)
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    b = breakdown(app)
    assert b["pending"] and not b["only_duo"]                     # never applied: everything is new
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    b = breakdown(app)
    assert not b["pending"] and not b["duo"] and b["others"] == []
    # a Duo setting: only Duo's file
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", enabled="1", factors="push"),
                 csrf_page="/integrations/duo")
    b = breakdown(app)
    assert b["pending"] and b["only_duo"] and b["duo_file"] and b["others"] == []
    # a remote MFA server is another provider: not "only Duo"
    browser.post("/integrations/remote/new", REMOTE_FORM)
    b = breakdown(app)
    assert b["duo"] and not b["only_duo"] and b["mfa"] == ["nps-mfa"]
    assert any("nps-mfa" in o for o in b["others"])
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    # Duo turned off: its blocks leave the clients file, nothing else changes
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey=""), csrf_page="/integrations/duo")
    b = breakdown(app)
    assert b["only_duo"] and not b["duo_file"] and b["mfa"] == [] and not b["clients"]
    # a RADIUS client is the base clients file
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw9', '192.0.2.99',"
                 " 'TestSwitchSecret0123456789')")
    b = breakdown(app)
    assert b["clients"] and not b["only_duo"] and "RADIUS clients" in b["others"]


def test_preview_shows_the_change_without_saving(app, browser, superconn, logged_in, idir):
    installed(browser)
    admin(browser, superconn, logged_in)
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    r = browser.post("/integrations/duo/preview", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    assert r.status_code == 200 and r.mimetype == "application/json"
    d = r.get_json()
    assert d["ok"] and d["only_duo"] and d["others"] == [] and not d["errors"]
    assert any("Duo Authentication Proxy" in x for x in d["restarts"]) and any("FreeRADIUS" in x for x in d["restarts"])
    text = json.dumps(d)
    assert SETTINGS_FORM["skey"] not in text and "skey=********" in text and "ikey=" + SETTINGS_FORM["ikey"] in text
    # nothing was saved or audited
    assert q(superconn, "SELECT count(*) FROM ui.mfa_provider WHERE id='duo' AND enabled")[0][0] == 0
    assert audit(superconn, "integration.configure") == []
    # an invalid form: the errors, no preview
    d = browser.post("/integrations/duo/preview", dict(SETTINGS_FORM, ikey="DI1"), csrf_page="/integrations/duo").get_json()
    assert not d["ok"] and "ikey" in d["errors"]
    # another change pending: listed
    browser.post("/integrations/remote/new", REMOTE_FORM)
    d = browser.post("/integrations/duo/preview", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo").get_json()
    assert d["ok"] and not d["only_duo"] and any("nps-mfa" in o for o in d["others"])


def test_preview_needs_admin_and_step_up(browser, superconn, logged_in, idir):
    logged_in("operator")
    r = browser.post("/integrations/duo/preview", SETTINGS_FORM, csrf_page="/integrations/duo")
    assert r.status_code in (302, 403)


def test_save_and_apply_only_duo(app, browser, superconn, logged_in, idir):
    installed(browser)
    admin(browser, superconn, logged_in)
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    n = applies(browser)
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1", then="apply"),
                     csrf_page="/integrations/duo")
    body = browser.text(r)
    assert r.status_code == 200 and applies(browser) == n + 1
    assert "Duo settings saved and applied" in body and "The Auth Proxy was able to reach Duo" in body
    assert "provider-duo" in helper_of(browser).staged
    assert not breakdown(app)["pending"]
    d = audit(superconn, "config.apply")[-1]
    assert d["source"] == "duo"
    assert audit(superconn, "integration.configure")[-1]["enabled"] == {"from": False, "to": True}
    # the Apply page goes through the same path
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", enabled="1", factors="push"),
                 csrf_page="/integrations/duo")
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    assert audit(superconn, "config.apply")[-1]["source"] == "apply"


def test_never_a_partial_apply(app, browser, superconn, logged_in, idir):
    installed(browser)
    admin(browser, superconn, logged_in)
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    browser.post("/integrations/remote/new", REMOTE_FORM)                  # another change waits
    n = applies(browser)
    # "apply" while others are pending: saved, not applied
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1", then="apply"),
                     csrf_page="/integrations/duo", follow_redirects=True)
    body = browser.text(r)
    assert applies(browser) == n and "Other changes are pending" in body and 'href="/apply/"' in body
    assert q(superconn, "SELECT enabled FROM ui.mfa_provider WHERE id='duo'") == [(True,)]
    # apply all without the tick: not applied
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", enabled="1", then="apply_all"),
                     csrf_page="/integrations/duo", follow_redirects=True)
    assert applies(browser) == n
    # save Duo only: saved, nothing goes live
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", enabled="1", factors="push",
                                                        then="save"), csrf_page="/integrations/duo",
                     follow_redirects=True)
    assert applies(browser) == n and "Review and apply" in browser.text(r)
    # apply all with the tick: everything at once
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", enabled="1", then="apply_all",
                                                        confirm_all="1"), csrf_page="/integrations/duo")
    assert r.status_code == 200 and applies(browser) == n + 1 and not breakdown(app)["pending"]
    assert "home_server radius_admin_mfa_nps-mfa" in helper_of(browser).staged["clients"][0]


def test_failed_apply_shows_the_helpers_reason(app, browser, superconn, logged_in, idir):
    installed(browser)
    admin(browser, superconn, logged_in)
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    why = "the Duo Authentication Proxy did not start with the new configuration (exit 1)"
    helper_of(browser).fail_next["apply"] = {"message": why}
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1", then="apply"),
                     csrf_page="/integrations/duo")
    body = browser.text(r)
    assert r.status_code == 200 and why in body and "The Auth Proxy was able to reach Duo" not in body
    assert breakdown(app)["pending"]                                 # saved, still pending
    assert audit(superconn, "config.apply")[-1]["source"] == "duo"


def test_test_waits_for_an_applied_configuration(browser, superconn, logged_in, idir):
    """While Duo still runs its sample configuration, Test says to apply first instead of
    running Duo's check against it."""
    installed(browser)
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    assert "Apply your Duo settings first" in body and "Run the check" not in body
    r = browser.post("/integrations/duo/test", {}, csrf_page="/integrations/duo")
    assert "Apply your Duo settings first" in browser.text(r) and "The Auth Proxy was able" not in browser.text(r)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1", then="apply_all", confirm_all="1"),
                 csrf_page="/integrations/duo")
    body = browser.text(browser.get("/integrations/duo"))
    assert "Apply your Duo settings first" not in body and "Run the check" in body


def test_page_has_the_confirmation_dialog(browser, superconn, logged_in, idir):
    installed(browser)
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    assert 'data-duo-preview="/integrations/duo/preview"' in body and '<dialog id="duo-apply-dialog"' in body
    assert 'name="then" value="apply"' in body and 'name="confirm_all"' in body and "up to ~3 minutes" in body
