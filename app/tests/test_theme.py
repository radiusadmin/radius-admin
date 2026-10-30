"""Colour theme: per-user setting rendered as html[data-theme], audited, no inline script."""
import re

from radius_admin.security import THEME_COOKIE


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def html_theme(text):
    m = re.search(r'<html lang="en"(?: data-theme="(\w+)")?>', text)
    assert m, "no <html> tag"
    return m.group(1)


def test_default_follows_system(browser, logged_in):
    logged_in("viewer")
    t = browser.text(browser.get("/dashboard"))
    assert html_theme(t) is None
    assert re.search(r'value="system" aria-pressed="true"', t)
    assert "<script>" not in t and " style=" not in t     # CSP: no inline script or style


def test_choose_dark_then_light(browser, superconn, logged_in):
    u = logged_in("viewer")       # any role may choose its own theme
    r = browser.post("/account/theme", {"theme": "dark", "return_to": "/clients/"}, csrf_page="/dashboard")
    assert r.status_code == 302 and r.headers["Location"].endswith("/clients/")
    assert THEME_COOKIE in r.headers.get("Set-Cookie", "")
    assert q(superconn, "SELECT theme FROM ui.admin_user WHERE id=%s", (u.id,)) == [("dark",)]
    t = browser.text(browser.get("/dashboard"))
    assert html_theme(t) == "dark" and re.search(r'value="dark" aria-pressed="true"', t)
    browser.post("/account/theme", {"theme": "light"}, csrf_page="/dashboard")
    assert html_theme(browser.text(browser.get("/dashboard"))) == "light"
    rows = q(superconn, "SELECT detail->>'from', detail->>'to' FROM ui.audit_log"
                        " WHERE action='account.theme' ORDER BY id")
    assert rows == [("system", "dark"), ("dark", "light")]


def test_rejects_unknown_theme_and_foreign_redirect(browser, superconn, logged_in):
    u = logged_in("operator")
    r = browser.post("/account/theme", {"theme": "neon"}, csrf_page="/dashboard")
    assert r.status_code == 400
    assert q(superconn, "SELECT theme FROM ui.admin_user WHERE id=%s", (u.id,)) == [("system",)]
    r = browser.post("/account/theme", {"theme": "dark", "return_to": "//evil.example/x"}, csrf_page="/dashboard")
    assert r.status_code == 302 and r.headers["Location"].endswith("/account/")


def test_requires_csrf_and_sign_in(browser, logged_in):
    r = browser.post("/account/theme", {"theme": "dark"}, csrf=False)
    assert r.status_code == 403
    logged_in("viewer")
    r = browser.post("/account/theme", {"theme": "dark"}, csrf=False)
    assert r.status_code == 403


def test_sign_in_page_uses_cookie_hint(browser):
    browser.c.set_cookie(THEME_COOKIE, "dark", domain="radius.test")
    assert html_theme(browser.text(browser.get("/login"))) == "dark"
    browser.c.set_cookie(THEME_COOKIE, "x\" onload=\"alert(1)", domain="radius.test")
    assert html_theme(browser.text(browser.get("/login"))) is None


def test_every_dark_rule_has_an_explicit_twin(app):
    """A rule under the OS dark media query must also exist for data-theme="dark"."""
    import os
    css = open(os.path.join(app.static_folder, "app.css"), encoding="utf-8").read()
    os_dark = re.findall(r':root:not\(\[data-theme="light"\]\)([^{]*)\{([^}]*)\}', css)
    norm = lambda s: " ".join(s.split())  # noqa: E731
    explicit = dict((norm(sel), norm(body)) for sel, body in
                    re.findall(r':root\[data-theme="dark"\]([^{]*)\{([^}]*)\}', css))
    assert os_dark, "no OS dark rules found"
    for sel, body in os_dark:
        assert explicit.get(norm(sel)) == norm(body), "missing or different dark twin for %r" % sel
