"""Send a test push from the Duo page (SPEC section 29.3): admin + step-up, the username
checked before the helper is asked, the result and Duo's message shown, audited without keys."""
from test_duo_apply import installed
from test_duo_portal import SETTINGS_FORM, admin, audit, helper_of, idir  # noqa: F401 (fixture)


def applied(browser, superconn, logged_in):
    installed(browser)
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1", then="apply_all", confirm_all="1"),
                 csrf_page="/integrations/duo")


def pushes(browser):
    return [r for r in helper_of(browser).requests if r["action"] == "integration_push_test"]


def test_push_sent_and_shown(browser, superconn, logged_in, idir):
    applied(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    assert "Send a test push" in body and 'name="username"' in body
    r = browser.post("/integrations/duo/push-test", {"username": "alice"}, csrf_page="/integrations/duo")
    body = browser.text(r)
    assert r.status_code == 200 and "Approved" in body and "Success. Logging you in..." in body
    assert pushes(browser)[-1] == {"action": "integration_push_test", "id": "duo", "username": "alice"}
    assert audit(superconn, "integration.push_test")[-1] == {"username": "alice", "result": "allow", "pushed": True}
    assert 'id="duo-push"' in body and 'action="/integrations/duo/push-test#duo-push"' in body


def test_push_outcomes_are_named(browser, superconn, logged_in, idir):
    applied(browser, superconn, logged_in)
    for result, text in (("deny", "Denied"), ("timeout", "No answer"), ("not_enrolled", "Not enrolled"),
                         ("error", "Duo could not be asked")):
        helper_of(browser).push = {"result": result, "status_msg": "msg-" + result}
        body = browser.text(browser.post("/integrations/duo/push-test", {"username": "bob"},
                                         csrf_page="/integrations/duo"))
        assert text in body and "msg-" + result in body, result


def test_bad_username_never_reaches_the_helper(browser, superconn, logged_in, idir):
    applied(browser, superconn, logged_in)
    r = browser.post("/integrations/duo/push-test", {"username": "a b"}, csrf_page="/integrations/duo")
    assert r.status_code == 400 and "Username" in browser.text(r) and pushes(browser) == []


def test_helper_refusal_shown_and_audited(browser, superconn, logged_in, idir):
    applied(browser, superconn, logged_in)
    helper_of(browser).fail_next["integration_push_test"] = {"message": "a test push to this user was sent 3 s ago; wait 28 s"}
    body = browser.text(browser.post("/integrations/duo/push-test", {"username": "alice"}, csrf_page="/integrations/duo"))
    assert "wait 28 s" in body
    assert audit(superconn, "integration.push_test")[-1]["result"] == "refused"


def test_needs_applied_settings_and_admin(browser, superconn, logged_in, idir):
    installed(browser)
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    assert "Send a test push" not in body
    r = browser.post("/integrations/duo/push-test", {"username": "alice"}, csrf_page="/integrations/duo")
    assert "Apply your Duo settings first" in browser.text(r) and pushes(browser) == []


def test_operator_cannot_push(browser, superconn, logged_in, idir):
    installed(browser)
    logged_in("operator")
    assert "Send a test push" not in browser.text(browser.get("/integrations/duo"))
    r = browser.post("/integrations/duo/push-test", {"username": "alice"}, csrf_page="/integrations/duo")
    assert r.status_code in (302, 403) and pushes(browser) == []


def test_a_refusal_before_any_push_says_so(browser, superconn, logged_in, idir):
    applied(browser, superconn, logged_in)
    helper_of(browser).push = {"result": "deny", "pushed": False,
                               "status_msg": "Your account does not have access to this application."}
    body = browser.text(browser.post("/integrations/duo/push-test", {"username": "jdoe"},
                                     csrf_page="/integrations/duo"))
    assert "Refused by Duo before any push" in body and "does not have access" in body
    helper_of(browser).push = {"result": "allow", "pushed": False, "status_msg": "Bypass user"}
    body = browser.text(browser.post("/integrations/duo/push-test", {"username": "eve"},
                                     csrf_page="/integrations/duo"))
    assert "Allowed by Duo without a push" in body
