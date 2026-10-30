from conftest import login


def test_login_page_shows_banner(browser):
    r = browser.get("/login")
    assert r.status_code == 200
    assert "Testing banner text" in browser.text(r)
    assert "I understand and consent" in browser.text(r)


def test_full_login(browser, superconn, make_user):
    u = make_user()
    login(browser, superconn, u)
    r = browser.get("/dashboard")
    assert r.status_code == 200, browser.text(r)
    assert "Dashboard" in browser.text(r)


def test_static_assets_are_versioned(app, browser):
    import hashlib, os, re
    html = browser.text(browser.get("/login"))
    for name in ("app.css", "app.js"):
        with open(os.path.join(app.static_folder, name), "rb") as fh:
            v = hashlib.sha256(fh.read()).hexdigest()[:12]
        assert re.search(r'/static/%s\?v=%s"' % (re.escape(name), v), html), name
