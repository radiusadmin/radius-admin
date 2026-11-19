"""Session actions: several sessions at once, state in the session's row, the list of past
actions, and lists that keep their filters when you go back to them (SPEC section 24)."""
import base64
import json
import re
from urllib.parse import parse_qs, urlsplit

from conftest import APP_DSN
from test_operations import _client, _session, q

JSON = {"Accept": "application/json"}


def _row(html, sid):
    """The <tr> of one session."""
    m = re.search(r'<tr[^>]*data-session="%d">(.*?)</tr>' % sid, html, re.S)
    assert m, "no row for session %d" % sid
    return m.group(1)


def _href(html, text):
    """Query arguments of the link labelled `text`."""
    m = re.search(r'href="([^"]*)"[^>]*>%s<' % re.escape(text), html)
    assert m, "no link %r" % text
    parts = urlsplit(m.group(1).replace("&amp;", "&"))
    return parts.path, {k: v[0] for k, v in parse_qs(parts.query).items()}


def _as(browser, logged_in, role):
    """Sign in as another role in a fresh browser session."""
    browser.c = browser.app.test_client()
    return logged_in(role)


def _three(superconn):
    _client(superconn)
    return [_session(superconn, 30 + i, False, "3C-22-FB-00-00-0%d" % i, "host/pc%d" % i) for i in (1, 2, 3)]


# ----------------------------------------------------------------------- several sessions at once
def test_bulk_action_queues_one_request_per_session(app, browser, superconn, logged_in):
    sids = _three(superconn)
    ended = _session(superconn, 90, True, "3C-22-FB-00-00-09", "host/gone")
    stray = q(superconn, "INSERT INTO radacct (acctsessionid, acctuniqueid, username, nasipaddress, nasportid,"
                         " acctstarttime, callingstationid) VALUES ('0000002F', md5(random()::text), 'host/stray',"
                         " '198.51.100.77', 'gi1/0/9', now(), '3C-22-FB-00-00-0A') RETURNING radacctid")[0][0]
    logged_in("operator")
    r = browser.post("/sessions/coa", {"sid": sids + [ended, stray, sids[0]], "action": "reauth"}, csrf_page="/sessions/")
    assert r.status_code == 302
    rows = q(superconn, "SELECT radacct_id, action, username, requested_by, done_at FROM ui.coa_request ORDER BY id")
    assert rows == [(sids[0], "reauth", "host/pc1", "operator1", None), (sids[1], "reauth", "host/pc2", "operator1", None),
                    (sids[2], "reauth", "host/pc3", "operator1", None)]
    audit = q(superconn, "SELECT detail->>'user', detail->>'selected' FROM ui.audit_log WHERE action = 'coa.request'"
                         " ORDER BY id")
    assert audit == [("host/pc1", "5"), ("host/pc2", "5"), ("host/pc3", "5")]          # one audit event each
    t = browser.text(browser.get(r.headers["Location"]))
    assert "Re-authenticate requested for 3 sessions." in t
    assert "Not sent for 2 sessions:" in t and "host/gone (the session has already ended)" in t
    assert "198.51.100.77) is not a RADIUS client" in t


def test_bulk_action_answers_json_for_the_page_script(app, browser, superconn, logged_in):
    sids = _three(superconn)
    logged_in("operator")
    r = browser.post("/sessions/coa", {"sid": sids[:2], "action": "disconnect"}, csrf_page="/sessions/", headers=JSON)
    d = r.get_json()
    assert r.status_code == 200 and d["label"] == "Disconnect" and d["skipped"] == []
    assert [(x["sid"], x["url"]) for x in d["queued"]] == [(sids[0], "/sessions/coa/1"), (sids[1], "/sessions/coa/2")]
    assert d["message"] == "Disconnect requested for 2 sessions."
    # a session whose request is still waiting is not queued twice
    d = browser.post("/sessions/coa", {"sid": sids, "action": "disconnect"}, csrf_page="/sessions/", headers=JSON).get_json()
    assert [x["sid"] for x in d["queued"]] == [sids[2]]
    assert [x["reason"] for x in d["skipped"]] == ["an earlier request for it is still waiting"] * 2
    assert q(superconn, "SELECT count(*) FROM ui.coa_request")[0][0] == 3


def test_bulk_action_input_is_checked(app, browser, superconn, logged_in):
    sids = _three(superconn)
    logged_in("operator")
    post = lambda data: browser.post("/sessions/coa", data, csrf_page="/sessions/")      # noqa: E731
    assert post({"sid": ["1 OR 1=1"], "action": "reauth"}).status_code == 400
    assert post({"sid": ["1\n"], "action": "reauth"}).status_code == 400
    assert post({"sid": [str(n) for n in range(1, 52)], "action": "reauth"}).status_code == 400      # over one page
    assert post({"sid": sids, "action": "reboot"}).status_code == 400
    r = post({"action": "reauth"})
    assert r.status_code == 302 and "Select at least one session first." in browser.text(browser.get("/sessions/"))
    assert post({"sid": ["999999"], "action": "reauth"}).status_code == 302
    assert q(superconn, "SELECT count(*) FROM ui.coa_request")[0][0] == 0
    _as(browser, logged_in, "viewer")
    assert browser.post("/sessions/coa", {"sid": sids, "action": "reauth"}, csrf_page="/sessions/").status_code == 403
    assert q(superconn, "SELECT count(*) FROM ui.coa_request")[0][0] == 0


# ----------------------------------------------------------------------- the 30-day view
def test_history_view_offers_actions_for_sessions_still_up(app, browser, superconn, logged_in):
    _client(superconn)
    up = _session(superconn)
    ended = _session(superconn, 120, True, "3C-22-FB-00-00-02", "host/pc2")
    logged_in("operator")
    t = browser.text(browser.get("/sessions/?history=1"))
    assert 'id="coa-bulk"' in t
    row = _row(t, up)
    assert 'name="sid" value="%d" form="coa-bulk"' % up in row and "Re-authenticate" in row and "Disconnect" in row
    row = _row(t, ended)
    assert 'name="sid"' not in row and "Actions" not in row and "User-Request" in row
    r = browser.post("/sessions/coa", {"sid": [up, ended], "action": "reauth"}, csrf_page="/sessions/?history=1")
    assert r.headers["Location"].endswith("/sessions/?history=1")                    # back in the same view
    assert q(superconn, "SELECT radacct_id FROM ui.coa_request") == [(up,)]
    # nothing to act on: no bar, no tick boxes
    q(superconn, "UPDATE radacct SET acctstoptime = now()")
    q(superconn, "DELETE FROM ui.coa_request")
    t = browser.text(browser.get("/sessions/?history=1"))
    assert 'id="coa-bulk"' not in t and 'name="sid"' not in t
    _as(browser, logged_in, "viewer")
    assert 'name="sid"' not in browser.text(browser.get("/sessions/?history=1"))


# ----------------------------------------------------------------------- state in the row
def test_row_shows_the_latest_action_and_status_url(app, browser, superconn, logged_in):
    sids = _three(superconn)
    logged_in("operator")
    browser.post("/sessions/coa", {"sid": sids[:2], "action": "bounce"}, csrf_page="/sessions/")
    t = browser.text(browser.get("/sessions/"))
    assert 'data-coa-status="/sessions/coa/status"' in t
    assert 'data-coa-waiting="1"' in _row(t, sids[0]) and "Bounce port" in _row(t, sids[0])
    assert "data-coa-waiting" not in _row(t, sids[2]) and "coa-link" not in _row(t, sids[2])
    assert '<meta http-equiv="refresh"' in t                               # without JavaScript the page reloads
    d = browser.get("/sessions/coa/status?id=1&id=2&id=77&id=x&id=1%0A", headers=JSON).get_json()
    assert d == {"requests": [{"id": 1, "state": "waiting", "message": ""}, {"id": 2, "state": "waiting", "message": ""}]}
    q(superconn, "UPDATE ui.coa_request SET done_at = now(), ok = true, message = 'The switch acknowledged (CoA-ACK).'"
                 " WHERE id = 1")
    q(superconn, "UPDATE ui.coa_request SET done_at = now(), ok = false, message = 'The switch refused <b>.'"
                 " WHERE id = 2")
    d = browser.get("/sessions/coa/status?id=1&id=2").get_json()
    assert [(x["id"], x["state"]) for x in d["requests"]] == [(1, "ok"), (2, "failed")]
    assert d["requests"][1]["message"] == "The switch refused <b>."
    t = browser.text(browser.get("/sessions/"))
    assert "data-coa-waiting" not in t and '<meta http-equiv="refresh"' not in t
    assert "tag-ok" in _row(t, sids[0]) and "/sessions/coa/1" in _row(t, sids[0])
    assert "tag-danger" in _row(t, sids[1]) and "The switch refused &lt;b&gt;." in _row(t, sids[1])
    # an old result leaves the row; it stays under Session actions
    q(superconn, "UPDATE ui.coa_request SET requested_at = now() - interval '16 minutes'")
    t = browser.text(browser.get("/sessions/"))
    assert "coa-link" not in t
    assert "/sessions/coa/1" in browser.text(browser.get("/sessions/actions"))
    assert browser.get("/sessions/coa/status").get_json() == {"requests": []}
    browser.c = browser.app.test_client()
    assert browser.get("/sessions/coa/status?id=1").status_code == 302          # signed out


# ----------------------------------------------------------------------- past actions
def test_session_actions_page(app, browser, superconn, logged_in):
    sids = _three(superconn)
    other = _client(superconn, "sw2", "192.0.2.11")
    logged_in("operator")
    browser.post("/sessions/coa", {"sid": sids[:2], "action": "reauth"}, csrf_page="/sessions/")
    browser.post("/sessions/coa", {"sid": sids[2:], "action": "disconnect"}, csrf_page="/sessions/")
    q(superconn, "UPDATE ui.coa_request SET done_at = now(), ok = true, message = 'The switch acknowledged (CoA-ACK).'"
                 " WHERE id = 1")
    q(superconn, "UPDATE ui.coa_request SET done_at = now(), ok = false, message = 'No reply from the switch.'"
                 " WHERE id = 2")
    _as(browser, logged_in, "viewer")                                    # read-only roles can look
    t = browser.text(browser.get("/sessions/actions"))
    assert ">Session actions</a>" in t and 'href="/sessions/actions" aria-current="page"' in t
    for rid in (1, 2, 3):
        assert 'href="/sessions/coa/%d"' % rid in t
    assert "host/pc1" in t and "No reply from the switch." in t and 'data-coa-waiting="3"' in t
    assert t.index("/sessions/coa/3") < t.index("/sessions/coa/1")           # newest first

    def shown(query):
        return sorted(int(x) for x in set(re.findall(r'href="/sessions/coa/(\d+)"', browser.text(
            browser.get("/sessions/actions?" + query)))))
    assert shown("result=ok") == [1] and shown("result=failed") == [2] and shown("result=waiting") == [3]
    assert shown("action=disconnect") == [3] and shown("action=reauth") == [1, 2] and shown("action=x") == [1, 2, 3]
    assert shown("q=pc2") == [2] and shown("q=3c:22:fb:00:00:03") == [3] and shown("q=operator1") == [1, 2, 3]
    assert shown("q=100%25") == [] and shown("switch=%d" % other) == [] and shown("switch=abc") == [1, 2, 3]
    assert "No session actions match." in browser.text(browser.get("/sessions/actions?q=nothing"))
    # the action's own page: everything about it, and the way back keeps the filters
    browser.get("/sessions/actions?result=failed&q=pc")
    t = browser.text(browser.get("/sessions/coa/2"))
    assert "No reply from the switch." in t and "3C-22-FB-00-00-02" in t and "still open" in t and "operator1" in t
    assert _href(t, "Back to session actions") == ("/sessions/actions", {"result": "failed", "q": "pc"})
    assert 'href="/sessions/actions" aria-current="page"' in t
    assert browser.get("/sessions/coa/99").status_code == 404
    t = browser.text(browser.get("/sessions/"))
    assert 'href="/sessions/" aria-current="page"' in t and 'href="/sessions/actions" aria-current' not in t


def test_session_actions_page_is_paged(app, browser, superconn, logged_in):
    cid = _client(superconn)
    q(superconn, "INSERT INTO ui.coa_request (client_id, action, nas_ip, username, requested_by, done_at, ok)"
                 " SELECT %s, 'reauth', '192.0.2.10', 'host/n' || n, 'op', now(), true FROM generate_series(1, 60) n", (cid,))
    logged_in("viewer")
    t = browser.text(browser.get("/sessions/actions"))
    assert "1–50 of 60" in t and "host/n60" in t and "host/n10<" not in t
    t = browser.text(browser.get("/sessions/actions?page=2&action=reauth"))
    assert "51–60 of 60" in t and "host/n10<" in t and "action=reauth" in t


# ----------------------------------------------------------------------- going back keeps the filters
def test_back_to_sessions_keeps_filters_and_page(app, browser, superconn, logged_in):
    sids = _three(superconn)
    logged_in("operator")
    browser.post("/sessions/coa", {"sid": sids[:1], "action": "reauth"}, csrf_page="/sessions/")
    assert _href(browser.text(browser.get("/sessions/coa/1")), "Back to sessions") == ("/sessions/", {})
    assert browser.get("/sessions/?q=pc&history=1&switch=1&page=1").status_code == 200
    assert _href(browser.text(browser.get("/sessions/coa/1")), "Back to sessions") == (
        "/sessions/", {"q": "pc", "history": "1", "switch": "1", "page": "1"})
    r = browser.post("/sessions/coa", {"sid": sids[1:2], "action": "reauth"}, csrf_page="/sessions/coa/1")
    path, args = urlsplit(r.headers["Location"]).path, parse_qs(urlsplit(r.headers["Location"]).query)
    assert path == "/sessions/" and args == {"q": ["pc"], "history": ["1"], "switch": ["1"], "page": ["1"]}
    # the same from Session actions
    assert _href(browser.text(browser.get("/sessions/actions")), "Back to sessions")[1]["q"] == "pc"
    # the menu link opens the plain list, and that is then what "back" means
    assert browser.get("/sessions/").status_code == 200
    assert _href(browser.text(browser.get("/sessions/coa/1")), "Back to sessions") == ("/sessions/", {})


def test_back_links_on_other_lists(app, browser, superconn, logged_in):
    cid = _client(superconn)
    aid = q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, callingstationid, authdate)"
                       " VALUES ('host/pc1', 'Access-Reject', 'eap-tls', '192.0.2.10', '3C-22-FB-00-00-01', now())"
                       " RETURNING id")[0][0]
    mid = q(superconn, "INSERT INTO mab_device (mac, vlan, description) VALUES ('AA-BB-CC-00-00-01', 20, 'printer')"
                       " RETURNING id")[0][0]
    logged_in("admin")
    # authentication log
    browser.get("/auth-log?user=pc1&reply=Access-Reject&since=2026-01-01&page=1")
    assert _href(browser.text(browser.get("/auth-log/%d" % aid)), "Back to log") == (
        "/auth-log", {"user": "pc1", "reply": "Access-Reject", "since": "2026-01-01", "page": "1"})
    # RADIUS clients: Cancel on the form and the redirect after a row action
    browser.get("/clients/?q=sw")
    assert _href(browser.text(browser.get("/clients/%d/edit" % cid)), "Cancel") == ("/clients/", {"q": "sw"})
    r = browser.post("/clients/%d/enable" % cid, {"enabled": "0"}, csrf_page="/clients/?q=sw")
    assert r.status_code == 302 and r.headers["Location"].endswith("/clients/?q=sw")
    # MAB devices
    browser.get("/mab/?q=printer&show=expiring")
    assert _href(browser.text(browser.get("/mab/%d/edit" % mid)), "Cancel") == ("/mab/", {"q": "printer", "show": "expiring"})
    r = browser.post("/mab/%d/delete" % mid, csrf_page="/mab/?q=printer")
    assert r.status_code == 302 and r.headers["Location"].endswith("/mab/?q=printer")
    # adding something new opens the whole list, where the new entry is
    assert _href(browser.text(browser.get("/mab/new")), "Cancel")[0] == "/mab/"
    r = browser.post("/mab/new", {"mac": "AA-BB-CC-00-00-02", "vlan": "20", "enabled": "1"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/mab/")


def test_remembered_filters_are_not_trusted(app, browser, superconn, logged_in):
    from radius_admin import listnav
    sids = _three(superconn)
    logged_in("operator")
    browser.post("/sessions/coa", {"sid": sids[:1], "action": "reauth"}, csrf_page="/sessions/")

    def back(value):
        browser.c.set_cookie(listnav.COOKIE, value, domain="radius.test", secure=True)
        r = browser.get("/sessions/coa/1")
        assert r.status_code == 200
        return _href(browser.text(r), "Back to sessions")

    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()
    assert back("not base64 at all!") == ("/sessions/", {})
    assert back(enc(["a", "list"])) == ("/sessions/", {})
    assert back(enc({"sessions.index": "q=1"})) == ("/sessions/", {})
    assert back("A" * 3500) == ("/sessions/", {})
    # only the list's own arguments, as text, cut to 100 characters; nothing reaches another endpoint
    path, args = back(enc({"sessions.index": {"q": "x" * 300, "page": 7, "next": "https://example.com/", "history": "1"},
                           "auth.logout": {"q": "1"}, "static": {"filename": "app.js"}}))
    assert path == "/sessions/" and args == {"q": "x" * 100, "history": "1"}
    path, args = back(enc({"sessions.index": {"q": '"><script>alert(1)</script>&x=1#'}}))
    assert path == "/sessions/" and args == {"q": '"><script>alert(1)</script>&x=1#'}
    assert "<script>alert" not in browser.text(browser.get("/sessions/coa/1"))
    # signing out forgets the filters
    browser.get("/sessions/?q=pc1")
    r = browser.post("/logout", csrf_page="/sessions/coa/1")
    assert any(c.startswith(listnav.COOKIE + "=;") for c in r.headers.getlist("Set-Cookie"))


# ----------------------------------------------------------------------- monitor
def test_monitor_does_not_wait_on_a_silent_switch_for_every_request(app, superconn, monkeypatch):
    from radius_admin import coa, db, snmp_poller
    quiet = _client(superconn)
    fine = _client(superconn, "sw2", "192.0.2.11")
    for cid, ip in ((quiet, "192.0.2.10"), (quiet, "192.0.2.10"), (fine, "192.0.2.11"), (quiet, "192.0.2.10")):
        q(superconn, "INSERT INTO ui.coa_request (client_id, action, calling_station_id, nas_ip, requested_by)"
                     " VALUES (%s, 'reauth', 'AA-BB-CC-00-00-01', %s, 'op')", (cid, ip))
    sent = []

    def fake_send(action, host, port, secret, request_text, radclient, dict_dir, **kw):
        sent.append(str(host))
        if str(host) == "192.0.2.10":
            return coa.parse_reply("(0) No reply from server for ID 12 socket 3\n", host)
        return True, "The switch acknowledged (CoA-ACK)."
    monkeypatch.setattr(snmp_poller, "coa_tool", lambda cfg: ("/x/radclient", "/x/dict", None))
    monkeypatch.setattr(coa, "send", fake_send)
    conn = db.connect(APP_DSN)
    try:
        assert snmp_poller.run_coa(conn, {}, None) == 4
        conn.commit()
    finally:
        conn.close()
    assert sent == ["192.0.2.10", "192.0.2.11"]                 # one timeout, not three
    res = q(superconn, "SELECT ok, message FROM ui.coa_request ORDER BY id")
    assert [r[0] for r in res] == [False, False, True, False]
    assert res[0][1].startswith("No reply from the switch") and "did not answer the request before this one" in res[1][1]
    assert res[3][1] == res[1][1]
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action = 'coa.result'")[0][0] == 4
