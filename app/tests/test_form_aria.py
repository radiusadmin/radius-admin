"""Form fields carry aria-describedby once, and an invalid field's error is in it.

The described() macro writes aria-describedby itself; a second, hand-written copy on
the same element is invalid HTML and browsers keep only the first one, which used to
drop the error id from invalid fields."""
from html.parser import HTMLParser

import pytest

from conftest import stepup


class _Attrs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, attrs))

    handle_startendtag = handle_starttag


def check_described(html):
    p = _Attrs()
    p.feed(html)
    invalid = 0
    for tag, attrs in p.elements:
        names = [k for k, _ in attrs]
        label = "<%s %s>" % (tag, dict(attrs).get("id") or dict(attrs).get("name"))
        assert names.count("aria-describedby") <= 1, "aria-describedby twice on " + label
        a = dict(attrs)
        if a.get("aria-invalid") == "true" and a.get("id"):
            invalid += 1
            assert a["id"] + "-error" in (a.get("aria-describedby") or "").split(), label
    return invalid


PW = "Correct-Horse-Battery-9-Long"

PAGES = [
    # (path, needs step-up, invalid form)
    ("/clients/new", False, {"name": "bad name", "ipaddr": "192.0.2.10", "transport": "udp",
                             "radsec_peer_name": "", "dot1x_ports": "x" * 1200, "secret_mode": "manual",
                             "secret": "short", "require_ma": "auto", "limit_proxy_state": "auto",
                             "nas_type": "cisco", "key_scope": "server"}),
    ("/settings", True, {"admin_subnet": "not-a-subnet",
                         "banner_text": "This system is for authorized use only. Testing."}),
    ("/mab/new", False, {"mac": "zz", "vlan": "10", "expires": "2001-01-01"}),
    ("/dot1x-users/new", False, {"username": "bad user", "password": PW, "confirm": PW,
                                 "groups": "Wired;Office", "expires": "2001-01-01"}),
    ("/ui-admins/new", True, {"username": "Bad User", "role": "viewer"}),
    ("/rules/new", False, {"priority": "high", "connection": "wired", "ad_group": "Wired-Office", "vlan": "10"}),
]


@pytest.mark.parametrize("path,needs_stepup,form", PAGES, ids=[p[0] for p in PAGES])
def test_aria_describedby_once(browser, superconn, logged_in, path, needs_stepup, form):
    u = logged_in("admin")
    if needs_stepup:
        stepup(browser, superconn, u)
    r = browser.get(path)
    assert r.status_code == 200, browser.text(r)[-1500:]
    assert check_described(browser.text(r)) == 0
    r = browser.post(path, form)
    assert r.status_code == 400, browser.text(r)[-1500:]
    assert check_described(browser.text(r)) >= 1
