"""Progress indicators for work that finishes in the background (SPEC section 23): each
waiting page shows a spinner and asks a JSON status URL; only a <noscript> meta refresh
remains for browsers without JavaScript."""
import os
import re

from conftest import APP_DSN  # noqa: F401  (the app fixtures use the test database)

TEMPLATES = os.path.join(os.path.dirname(__file__), "..", "radius_admin", "templates")


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        try:
            return cur.fetchall()
        except Exception:
            return None


def _switch(superconn, name="sw1", ip="192.0.2.10"):
    return q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, is_switch) VALUES (%s,%s,%s,true)"
                        " RETURNING id", (name, ip, "Plaintext-Key-0001-abcdef"))[0][0]


def _waiting(t, url):
    assert 'data-live="%s"' % url in t and 'class="spinner"' in t
    head = t.split("</head>")[0]
    assert re.search(r'<noscript><meta http-equiv="refresh" content="\d+"></noscript>', head)
    assert not re.search(r'(?<!<noscript>)<meta http-equiv="refresh"', head)
    assert "refreshes every few seconds" not in t


def test_no_template_reloads_itself_without_noscript():
    """Meta refresh only through noscript_refresh (or the SSO hand-off, which is a redirect)."""
    for root, _, files in os.walk(TEMPLATES):
        for f in files:
            text = open(os.path.join(root, f), encoding="utf-8").read()
            if 'http-equiv="refresh"' in text and f not in ("_macros.html", "sso_continue.html"):
                raise AssertionError("%s: use m.noscript_refresh() and m.live_status()" % f)


def test_snmp_test_page_waits_with_a_spinner(app, browser, superconn, logged_in):
    cid = _switch(superconn)
    logged_in("operator")
    r = browser.post("/switch-monitoring/test", {"client_id": str(cid)}, csrf_page="/clients/")
    tid = int(r.headers["Location"].rsplit("/", 1)[1])
    t = browser.text(browser.get(r.headers["Location"]))
    _waiting(t, "/switch-monitoring/test/%d/status" % tid)
    assert "Testing sw1 over SNMPv3…" in t
    assert browser.get("/switch-monitoring/test/%d/status" % tid).get_json() == {"done": False}
    q(superconn, "UPDATE ui.snmp_test SET done_at = now(), ok = true, message = 'sysName sw1'")
    assert browser.get("/switch-monitoring/test/%d/status" % tid).get_json() == {"done": True}
    t = browser.text(browser.get(r.headers["Location"]))
    assert "data-live=" not in t and "sysName sw1" in t and "noscript><meta" not in t
    assert browser.get("/switch-monitoring/test/999/status").status_code == 404


def test_coa_page_waits_with_a_spinner(app, browser, superconn, logged_in):
    cid = _switch(superconn)
    rid = q(superconn, "INSERT INTO ui.coa_request (client_id, action, acct_session_id, calling_station_id, nas_ip,"
                       " requested_by) VALUES (%s, 'reauth', '0000002A', '3C-22-FB-00-00-01', '192.0.2.10', 't')"
                       " RETURNING id", (cid,))[0][0]
    logged_in("viewer")
    t = browser.text(browser.get("/sessions/coa/%d" % rid))
    _waiting(t, "/sessions/coa/%d/status" % rid)
    assert "Sending the request to sw1…" in t
    assert browser.get("/sessions/coa/%d/status" % rid).get_json() == {"done": False}
    q(superconn, "UPDATE ui.coa_request SET done_at = now(), ok = true, message = 'CoA-ACK'")
    assert browser.get("/sessions/coa/%d/status" % rid).get_json() == {"done": True}
    assert "data-live=" not in browser.text(browser.get("/sessions/coa/%d" % rid))
    assert browser.get("/sessions/coa/999/status").status_code == 404


def test_snmp_refresh_waits_until_every_switch_was_polled(app, browser, superconn, logged_in):
    a, b = _switch(superconn), _switch(superconn, "sw2", "192.0.2.11")
    q(superconn, "UPDATE ui.snmp_profile SET enabled = true")
    q(superconn, "INSERT INTO ui.switch_status (client_id, reachable, polled_at) VALUES (%s, true, now() - interval '1 hour')", (a,))
    logged_in("admin")
    r = browser.post("/switch-monitoring/refresh", {}, csrf_page="/switch-monitoring/")
    assert r.status_code == 302
    t = browser.text(browser.get("/switch-monitoring/"))
    _waiting(t, "/switch-monitoring/refresh/status")
    assert "Refreshing…" in t and "Results appear within a minute" not in t
    assert browser.get("/switch-monitoring/refresh/status").get_json() == {"done": False}
    q(superconn, "UPDATE ui.switch_status SET polled_at = now() + interval '1 second'")
    assert browser.get("/switch-monitoring/refresh/status").get_json() == {"done": False}   # sw2 not yet
    q(superconn, "INSERT INTO ui.switch_status (client_id, reachable, polled_at) VALUES (%s, false, now() + interval '1 second')", (b,))
    assert browser.get("/switch-monitoring/refresh/status").get_json() == {"done": True}
    t = browser.text(browser.get("/switch-monitoring/"))
    assert "data-live=" not in t and 'data-busy="Refreshing…"' in t
    q(superconn, "UPDATE ui.snmp_profile SET refresh_requested_at = now() - interval '10 minutes'")
    q(superconn, "DELETE FROM ui.switch_status")
    assert browser.get("/switch-monitoring/refresh/status").get_json() == {"done": True}       # gave up


def test_alert_test_waits_until_it_was_sent(app, browser, superconn, logged_in):
    logged_in("admin")
    r = browser.post("/alerts/test", {}, csrf_page="/alerts/")
    assert r.status_code == 302
    t = browser.text(browser.get(r.headers["Location"]))
    _waiting(t, "/alerts/test/status")
    assert "Sending the test alert…" in t and "within a few seconds" not in t
    assert browser.get("/alerts/test/status").get_json() == {"done": False}
    q(superconn, "INSERT INTO ui.alert (kind, state, message, opened_at, resolved_at)"
                 " VALUES ('test', 'resolved', 'Test alert', now() + interval '1 second', now())")
    assert browser.get("/alerts/test/status").get_json() == {"done": True}
    t = browser.text(browser.get(r.headers["Location"]))
    assert "data-live=" not in t and 'data-busy="Sending…"' in t


def test_slow_forms_show_a_busy_button(app, browser, logged_in):
    logged_in("admin")
    t = browser.text(browser.get("/apply/"))
    for label in ("Validating…", "Applying…"):
        assert 'data-busy="%s"' % label in t


def test_confirmations_use_the_page_dialog_not_browser_boxes():
    """data-confirm and the role select ask in app.js's own <dialog>; window.confirm only as
    the fallback for browsers without <dialog>, and no alert() or prompt() at all."""
    js = open(os.path.join(TEMPLATES, "..", "static", "app.js"), encoding="utf-8").read()
    code = "\n".join(ln.split("//")[0] for ln in js.splitlines())
    assert not re.search(r"\b(alert|prompt)\s*\(", code)
    calls = re.findall(r"window\.confirm\s*\(", code)
    assert len(calls) == 1 and 'typeof HTMLDialogElement !== "function"' in code
    assert "showModal()" in code and 'form[data-confirm]' in code
    css = open(os.path.join(TEMPLATES, "..", "static", "app.css"), encoding="utf-8").read()
    assert ".confirm-dialog" in css


def test_confirm_messages_are_rendered_as_data(app, browser, superconn, logged_in):
    """The question travels in the data-confirm attribute (escaped), never in a script."""
    q(superconn, "INSERT INTO ui.access_rule (priority, connection, ad_group, vlan, enabled, description)"
                 " VALUES (10, 'wired', %s, 510, true, '')", ('Grp"<b>x',))
    logged_in("operator")
    t = browser.text(browser.get("/rules/"))
    assert re.search(r'data-confirm="Delete the rule for Grp(&#34;|&quot;)&lt;b&gt;x \(VLAN 510\)\?', t)
    assert 'Grp"<b>x' not in t
