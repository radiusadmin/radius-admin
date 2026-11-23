"""A POST bounced to step-up comes back to a page that answers GET (SPEC section 4): the form's
return_to, else the page the form was on (Referer, this host), else the action itself only
when it answers GET too. Sending the browser to a POST-only URL ended in 405 Method Not Allowed
after the re-authentication (Remove Duo)."""
from urllib.parse import parse_qs, urlsplit

from conftest import BASE_URL


def lapsed(superconn, logged_in):
    logged_in("admin")
    with superconn.cursor() as cur:
        cur.execute("UPDATE ui.session SET stepup_at = now() - interval '1 day'")


def bounced_to(r):
    assert r.status_code == 302
    loc = urlsplit(r.headers["Location"])
    assert loc.path == "/stepup"
    return parse_qs(loc.query).get("next", [None])[0]


def test_post_only_action_returns_to_the_page_it_was_on(browser, superconn, logged_in):
    lapsed(superconn, logged_in)                          # signed in, step-up lapsed
    r = browser.post("/integrations/duo/remove", csrf_page="/integrations/duo",
                     headers={"Referer": BASE_URL + "/integrations/duo"})
    assert bounced_to(r) == "/integrations/duo"
    assert browser.get("/integrations/duo").status_code == 200


def test_post_only_action_without_referer_never_returns_to_itself(browser, superconn, logged_in):
    lapsed(superconn, logged_in)
    r = browser.post("/integrations/duo/remove", csrf_page="/integrations/duo")
    assert bounced_to(r) in (None, "/dashboard", "/")


def test_foreign_referer_is_ignored(browser, superconn, logged_in):
    lapsed(superconn, logged_in)
    r = browser.post("/integrations/duo/remove", csrf_page="/integrations/duo",
                     headers={"Referer": "https://evil.example.net/integrations/duo"})
    assert bounced_to(r) in (None, "/dashboard", "/")


def test_form_page_that_answers_get_comes_back_to_itself(browser, superconn, logged_in):
    lapsed(superconn, logged_in)
    r = browser.post("/integrations/remote/new", {"id": "x"}, csrf_page="/integrations/duo")
    assert bounced_to(r) == "/integrations/remote/new"


def test_a_page_that_answers_only_post_is_never_the_way_back(browser, superconn, logged_in):
    """The page the form was on can itself be a POST result (the Duo check shows its result at
    /integrations/duo/test): neither that Referer nor such a return_to is used."""
    lapsed(superconn, logged_in)
    r = browser.post("/integrations/duo/push-test", {"username": "alice"}, csrf_page="/integrations/duo",
                     headers={"Referer": BASE_URL + "/integrations/duo/test"})
    assert bounced_to(r) in (None, "/dashboard", "/")
    r = browser.post("/integrations/duo/push-test", {"username": "alice", "return_to": "/integrations/duo/test"},
                     csrf_page="/integrations/duo")
    assert bounced_to(r) in (None, "/dashboard", "/")


def test_duo_forms_come_back_to_the_duo_page(browser, superconn, logged_in):
    import re
    h = browser.app.fake_helper
    h.duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    h.catalog = {"serial": 3, "source": "release", "message": "", "entries": [
        {"provider": "duo", "version": "6.8.1", "sha256": "b" * 64, "fips": False, "withdrawn": False}]}
    lapsed(superconn, logged_in)                          # the page itself needs no step-up
    body = browser.text(browser.get("/integrations/duo"))
    forms = re.findall(r'<form method="post" action="/integrations/duo[^"]*"[^>]*>(.*?)</form>', body, re.S)
    assert len(forms) >= 5 and all('name="return_to" value="/integrations/duo"' in f for f in forms)
    r = browser.post("/integrations/duo/push-test", {"username": "alice", "return_to": "/integrations/duo"},
                     csrf_page="/integrations/duo", headers={"Referer": BASE_URL + "/integrations/duo/test"})
    assert bounced_to(r) == "/integrations/duo"
