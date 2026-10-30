"""FIPS is invisible when FIPS mode is off: no page mentions it (docs/PLAN-universal.md)."""


def _get_pages(app):
    """Every GET route without URL arguments."""
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and not rule.arguments and rule.endpoint != "static":
            yield rule.rule


def test_no_page_mentions_fips_in_standard_mode(app, browser, logged_in):
    assert app.config["RA"]["require_fips"] is False
    for path in ("/login",):
        assert "FIPS" not in browser.text(browser.get(path)), path
    browser.post("/banner", {"accept": "1"}, csrf_page="/login")
    assert "FIPS" not in browser.text(browser.get("/login"))
    logged_in("admin")
    seen = 0
    for path in _get_pages(app):
        r = browser.get(path)
        assert "FIPS" not in browser.text(r), "%s mentions FIPS" % path
        seen += 1
    assert seen > 25


def test_fips_mode_shows_status(app, browser, logged_in):
    app.config["RA"]["require_fips"] = True      # as if installed with --fips (this host is not)
    logged_in("admin")
    t = browser.text(browser.get("/dashboard"))
    assert "FIPS not active" in t and "FIPS mode" in t
