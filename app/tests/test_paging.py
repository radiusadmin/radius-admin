"""Numbered pages on the authentication log, audit log and sessions list (paging.Pager)."""
import re

from radius_admin.paging import MAX_PAGE, Pager


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)


def _nums(html):
    """The page links and the current page, in order, as shown: ['1', '…', '4', '[5]', …]."""
    nav = re.search(r'<nav class="pager".*?</nav>', html, re.S)
    assert nav, "no pager"
    out = []
    for m in re.finditer(r'class="pager-num( is-current)?"[^>]*>(\d+)<|class="pager-gap"', nav.group(0)):
        out.append("…" if m.group(2) is None else ("[%s]" % m.group(2) if m.group(1) else m.group(2)))
    return out


# ------------------------------------------------------------------ Pager
def test_pager_numbers():
    assert Pager(1, 50, 0).numbers() == [1] and Pager(1, 50, 0).first == 0
    assert Pager(1, 50, 50).pages == 1 and Pager(1, 50, 51).pages == 2
    assert Pager(1, 50, 7 * 50).numbers() == [1, 2, 3, None, 7]
    assert Pager(4, 50, 7 * 50).numbers() == [1, 2, 3, 4, 5, 6, 7]      # gap of one page shows the page
    assert Pager(10, 50, 40 * 50).numbers() == [1, None, 8, 9, 10, 11, 12, None, 40]
    assert Pager(40, 50, 40 * 50).numbers() == [1, None, 38, 39, 40]


def test_pager_bounds():
    p = Pager(99, 50, 120)                                  # past the end: last page
    assert (p.page, p.offset, p.first, p.last) == (3, 100, 101, 120)
    assert p.has_prev and not p.has_next
    p = Pager(0, 50, 120)
    assert (p.page, p.offset, p.has_prev, p.has_next) == (1, 0, False, True)
    p = Pager(1, 50, MAX_PAGE * 50 + 1)                     # count was capped
    assert p.capped and p.pages == MAX_PAGE and p.total == MAX_PAGE * 50


# ------------------------------------------------------------------ pages
def test_auth_log_numbered_pages(app, browser, superconn, logged_in):
    logged_in("viewer")
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, authdate)"
                 " SELECT 'user' || i, CASE WHEN mod(i, 2) = 0 THEN 'Access-Reject' ELSE 'Access-Accept' END,"
                 " 'eap-tls', '192.0.2.10', now() - make_interval(secs => i) FROM generate_series(1, 320) i")
    t = browser.text(browser.get("/auth-log"))
    assert "1–50 of 320" in t and _nums(t) == ["[1]", "2", "3", "…", "7"]
    assert 'href="/auth-log?page=2"' in t and 'rel="next"' in t and "Older" not in t
    assert ">user1<" in t and ">user51<" not in t

    t = browser.text(browser.get("/auth-log?page=4"))
    assert "151–200 of 320" in t and _nums(t) == ["1", "2", "3", "[4]", "5", "6", "7"]
    assert ">user151<" in t and ">user150<" not in t

    t = browser.text(browser.get("/auth-log?page=999"))                 # clamped to the last page
    assert "301–320 of 320" in t and _nums(t)[-1] == "[7]" and ">user320<" in t

    t = browser.text(browser.get("/auth-log?reply=Access-Reject&page=2"))   # filters stay in the links
    assert "51–100 of 160" in t and _nums(t) == ["1", "[2]", "3", "4"]
    assert 'href="/auth-log?page=3&amp;reply=Access-Reject"' in t and "user=&" not in t


def test_auth_log_single_page_has_count_only(app, browser, superconn, logged_in):
    logged_in("viewer")
    t = browser.text(browser.get("/auth-log"))
    assert 'class="pager"' not in t                                     # empty: no pager at all
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress)"
                 " SELECT 'user' || i, 'Access-Accept', 'eap-tls', '192.0.2.10' FROM generate_series(1, 3) i")
    t = browser.text(browser.get("/auth-log"))
    assert "1–3 of 3" in t and "pager-num" not in t and "Previous" not in t


def test_audit_log_numbered_pages(app, browser, superconn, logged_in):
    logged_in("viewer")
    q(superconn, "INSERT INTO ui.audit_log (actor, action, success, prev_hash, hash)"
                 " SELECT 'tester', 'test.event' || i, true, 'x', 'x' FROM generate_series(1, 130) i")
    t = browser.text(browser.get("/audit-log?action=test."))
    assert "1–50 of 130" in t and _nums(t) == ["[1]", "2", "3"]
    assert 'href="/audit-log?page=2&amp;action=test."' in t or 'href="/audit-log?action=test.&amp;page=2"' in t
    t = browser.text(browser.get("/audit-log?action=test.&page=3"))
    assert "101–130 of 130" in t and "test.event1<" in t and "test.event31<" not in t


def test_sessions_numbered_pages(app, browser, superconn, logged_in):
    logged_in("viewer")
    q(superconn, "INSERT INTO radacct (acctsessionid, acctuniqueid, username, nasipaddress, nasportid,"
                 " acctstarttime, callingstationid)"
                 " SELECT 'S' || i, md5(i::text), 'host/pc' || i || '.example.net', '192.0.2.10', 'gi1/0/4',"
                 " now() - make_interval(mins => i), NULL FROM generate_series(1, 120) i")
    t = browser.text(browser.get("/sessions/"))
    assert "120 open sessions" in t and "1–50 of 120" in t and _nums(t) == ["[1]", "2", "3"]
    assert "host/pc1.example.net" in t and "host/pc51.example.net" not in t
    t = browser.text(browser.get("/sessions/?page=3"))
    assert "101–120 of 120" in t and "host/pc120.example.net" in t and "host/pc100.example.net" not in t
    t = browser.text(browser.get("/sessions/?q=pc11"))                  # pc11, pc110..pc119
    assert "1–11 of 11" in t and "pager-num" not in t
