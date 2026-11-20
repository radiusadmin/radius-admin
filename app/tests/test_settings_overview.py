"""The side panel's single Settings button and the categorised settings overview behind it."""
import re

import pytest

SETTINGS_LINK = re.compile(r'<a class="nav-settings" href="/settings/overview" ?(aria-current="page")?>')


def nav(text):
    return text.split('<nav id="sidenav"', 1)[1].split("</nav>", 1)[0]


def current(text):
    """Labels of the side panel links marked as the current page."""
    return [re.sub(r"<[^>]+>", "", m).strip() for m in
            re.findall(r'aria-current="page">(.*?)</a>', nav(text), re.S)]


def test_admin_sees_one_settings_button_at_the_bottom(browser, logged_in):
    logged_in("admin")
    n = nav(browser.text(browser.get("/dashboard")))
    assert "Administration" not in n
    for gone in ('href="/settings"', "/settings/sso", "/ui-admins/", "/setup/", "/updates"):
        assert gone not in n, gone
    assert SETTINGS_LINK.search(n)
    # the button sits in its own footer after every other group
    assert n.index('class="nav-foot"') > n.index("Records") and n.rstrip().endswith("</div>")


def test_overview_lists_every_settings_page_by_category(browser, logged_in):
    logged_in("admin")
    r = browser.get("/settings/overview")
    assert r.status_code == 200
    t = browser.text(r)
    main = t.split('<main', 1)[1]
    for heading in ("RADIUS and switches", "Console access", "Notifications", "Maintenance"):
        assert f">{heading}</h2>" in main
    for href in ('href="/settings"', 'href="/ui-admins/"', 'href="/settings/sso"', 'href="/alerts/settings"',
                 'href="/updates"', 'href="/setup/"'):
        assert href in main, href
    assert current(t) == ["Settings"]
    assert "All settings" not in main                   # no back link on the overview itself


def test_settings_pages_highlight_the_button_and_link_back(browser, logged_in):
    logged_in("admin")
    for path in ("/settings", "/setup/", "/alerts/settings"):
        t = browser.text(browser.get(path))
        assert current(t) == ["Settings"], path
        assert '<p class="crumb"><a href="/settings/overview">All settings</a></p>' in t, path
    t = browser.text(browser.get("/alerts/"))            # the alert list stays under Monitoring
    assert current(t) == ["Alerts"] and "All settings" not in t
    t = browser.text(browser.get("/custom-policy"))      # custom policy stays under Network access
    assert current(t) == ["Custom policy"] and "All settings" not in t


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_non_admins_get_no_settings_button(browser, logged_in, role):
    logged_in(role)
    t = browser.text(browser.get("/dashboard"))
    assert not SETTINGS_LINK.search(nav(t)) and 'class="nav-foot"' not in t
    assert browser.get("/settings/overview").status_code == 403
