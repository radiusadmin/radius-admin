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
