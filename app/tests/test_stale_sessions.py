"""Accounting records that never got an Accounting-Stop (SPEC section 25): the monitor closes
those that a newer session of the same device on the same switch has replaced and those whose
switch stopped sending interim updates a day ago; a session the switch says it does not have
(CoA/Disconnect-NAK Session-Context-Not-Found) is closed too."""
import pytest

from conftest import APP_DSN
from test_operations import _client, _radclient, q


def _acct(superconn, csi, start_hours, update_hours=None, nas="192.0.2.10", port="gi1/0/4", user=None):
    return q(superconn, "INSERT INTO radacct (acctsessionid, acctuniqueid, username, nasipaddress, nasportid,"
                        " acctstarttime, acctupdatetime, acctsessiontime, callingstationid)"
                        " VALUES ('0000003A', md5(random()::text), %s, %s, %s, now() - make_interval(hours => %s),"
                        " now() - make_interval(hours => %s),"
                        " CASE WHEN %s::integer IS NOT NULL THEN (%s::integer - %s::integer) * 3600 END, %s)"
                        " RETURNING radacctid",
             (user or csi.replace("-", "").lower(), nas, port, start_hours, update_hours, update_hours,
              start_hours, update_hours, csi))[0][0]


def _close():
    from radius_admin import db, snmp_poller
    conn = db.connect(APP_DSN)
    try:
        return snmp_poller.close_stale_sessions(conn)
    finally:
        conn.close()


def _state(superconn, sid):
    return q(superconn, "SELECT acctstoptime IS NOT NULL, acctterminatecause FROM radacct WHERE radacctid = %s",
             (sid,))[0]


def test_monitor_closes_superseded_and_stale_sessions(app, browser, superconn, logged_in):
    _client(superconn)
    _client(superconn, "sw2", "192.0.2.11")
    mac = "AA-BB-CC-00-00-31"
    oldest = _acct(superconn, mac, 170, 169)                       # replaced twice
    older = _acct(superconn, mac, 22, None)                        # replaced, never had an update
    latest = _acct(superconn, mac, 2, 1)                           # the device's current session
    elsewhere = _acct(superconn, mac, 160, 1, nas="192.0.2.11")    # the same MAC on another switch: its own
    silent = _acct(superconn, "AA-BB-CC-00-00-32", 60, 30)         # interim updates stopped 30 h ago
    no_interims = _acct(superconn, "AA-BB-CC-00-00-33", 72)        # switch sends no interim updates: kept
    fresh = _acct(superconn, "AA-BB-CC-00-00-34", 40, 1)
    logged_in("viewer")
    assert browser.text(browser.get("/sessions/")).count('title="aabbcc000031"') == 4

    assert _close() == {"superseded": 2, "stale": 1}
    assert _state(superconn, oldest) == (True, "Superseded")
    assert _state(superconn, older) == (True, "Superseded")
    assert _state(superconn, silent) == (True, "Stale-Session")
    for sid in (latest, elsewhere, no_interims, fresh):
        assert _state(superconn, sid) == (False, None)
    # a replaced session ends when the next one started; a silent one at its last update
    assert q(superconn, "SELECT a.acctstoptime = b.acctstarttime, a.acctsessiontime = 20 * 3600"
                        " FROM radacct a, radacct b WHERE a.radacctid = %s AND b.radacctid = %s",
             (older, latest))[0] == (True, True)
    assert q(superconn, "SELECT acctstoptime = acctupdatetime, acctsessiontime = 30 * 3600 FROM radacct"
                        " WHERE radacctid = %s", (silent,))[0] == (True, True)
    assert _close() == {"superseded": 0, "stale": 0}               # idempotent

    t = browser.text(browser.get("/sessions/"))
    assert t.count('title="aabbcc000031"') == 2 and "aabbcc000032" not in t
    t = browser.text(browser.get("/sessions/?history=1&q=AA-BB-CC-00-00-31"))
    assert "newer session from this device" in t
    assert "no accounting update" in browser.text(browser.get("/sessions/?history=1&q=AA-BB-CC-00-00-32"))


def test_a_late_stop_still_records_the_real_end(app, superconn):
    """FreeRADIUS's stop query falls back to updating a row that is already closed, so a real
    Accounting-Stop arriving after the monitor closed the record still wins."""
    sid = _acct(superconn, "AA-BB-CC-00-00-35", 50, 26)
    _close()
    assert _state(superconn, sid) == (True, "Stale-Session")
    uid = q(superconn, "SELECT acctuniqueid FROM radacct WHERE radacctid = %s", (sid,))[0][0]
    # queries.conf, accounting.stop: the last query has no "AcctStopTime IS NULL"
    q(superconn, "UPDATE radacct SET acctstoptime = now(), acctterminatecause = 'User-Request'"
                 " WHERE acctuniqueid = %s", (uid,))
    assert _state(superconn, sid) == (True, "User-Request")


def test_only_the_owner_closes_sessions(app, superconn):
    """The web app's role still has no write access to radacct; it reaches it only through the
    two functions, which take no session data from the caller."""
    import psycopg2
    from radius_admin import db
    sid = _acct(superconn, "AA-BB-CC-00-00-36", 30, 3)
    conn = db.connect(APP_DSN)
    try:
        with pytest.raises(psycopg2.Error):
            db.execute("UPDATE radacct SET acctstoptime = now() WHERE radacctid = %s", (sid,), conn=conn)
        conn.rollback()
        db.query_one("SELECT * FROM radius_admin_close_stale_sessions(0)", conn=conn)
        conn.commit()
    finally:
        conn.close()
    assert _state(superconn, sid) == (False, None)          # 0 hours is raised to the 24 h minimum


def _queue(superconn, cid, sid, action="disconnect"):
    return q(superconn, "INSERT INTO ui.coa_request (client_id, action, acct_session_id, calling_station_id, nas_ip,"
                        " nas_port_id, username, requested_by, radacct_id) VALUES (%s, %s, '0000003A',"
                        " 'AA-BB-CC-00-00-37', '192.0.2.10', 'gi1/0/4', 'aabbcc000037', 'op', %s) RETURNING id",
             (cid, action, sid))[0][0]


def _run_coa(monkeypatch, out):
    from radius_admin import coa, db, snmp_poller
    monkeypatch.setattr(snmp_poller, "coa_tool", lambda cfg: ("/x/radclient", "/x/dict", None))
    monkeypatch.setattr(coa, "send", lambda action, host, *a, **kw: coa.parse_reply(out, host))
    conn = db.connect(APP_DSN)
    try:
        snmp_poller.run_coa(conn, {}, None)
        conn.commit()
    finally:
        conn.close()


NAK_503 = ("Sent Disconnect-Request Id 7 from 0.0.0.0:41000 to 192.0.2.10:1700 length 60\n"
           "Received Disconnect-NAK Id 7 from 192.0.2.10:1700 to 0.0.0.0:41000 length 26\n"
           "\tError-Cause = Session-Context-Not-Found\n")


def test_a_session_the_switch_does_not_have_is_closed(app, browser, superconn, logged_in, monkeypatch):
    cid = _client(superconn)
    sid = _acct(superconn, "AA-BB-CC-00-00-37", 5, 1)
    rid = _queue(superconn, cid, sid)
    _run_coa(monkeypatch, NAK_503)
    ok, msg = q(superconn, "SELECT ok, message FROM ui.coa_request WHERE id = %s", (rid,))[0]
    assert ok is False and "Session-Context-Not-Found" in msg
    assert "no longer has this session" in msg and "marked as ended" in msg
    assert _state(superconn, sid) == (True, "Session-Not-Found")
    logged_in("viewer")
    assert "no longer has this session" in browser.text(browser.get("/sessions/coa/%d" % rid))
    assert "the switch no longer has it" in browser.text(browser.get("/sessions/?history=1&q=AA-BB-CC-00-00-37"))


def test_other_refusals_leave_the_session_open(app, superconn, monkeypatch):
    cid = _client(superconn)
    sid = _acct(superconn, "AA-BB-CC-00-00-37", 5, 1)
    _queue(superconn, cid, sid)
    _run_coa(monkeypatch, NAK_503.replace("Session-Context-Not-Found", "Missing-Attribute"))
    assert _state(superconn, sid) == (False, None)
    _queue(superconn, cid, sid, "reauth")
    _run_coa(monkeypatch, "Received CoA-ACK Id 8 from 192.0.2.10:1700 to 0.0.0.0:41000 length 20\n")
    assert _state(superconn, sid) == (False, None)


def test_close_after_coa_needs_a_failed_request_that_says_so(app, superconn):
    """radius_admin_close_after_coa(request id) closes only the session named by a finished,
    refused request whose answer was Session-Context-Not-Found."""
    from radius_admin import db
    cid = _client(superconn)
    sid = _acct(superconn, "AA-BB-CC-00-00-37", 5, 1)
    waiting = _queue(superconn, cid, sid)
    acked = _queue(superconn, cid, sid)
    q(superconn, "UPDATE ui.coa_request SET done_at = now(), ok = true,"
                 " message = 'Session-Context-Not-Found' WHERE id = %s", (acked,))
    conn = db.connect(APP_DSN)
    try:
        for rid in (waiting, acked, 999999):
            assert db.query_one("SELECT radius_admin_close_after_coa(%s) AS r", (rid,), conn=conn)["r"] is False
        conn.commit()
    finally:
        conn.close()
    assert _state(superconn, sid) == (False, None)


def test_monitor_closes_session_on_nak_from_a_switch(app, superconn):
    """End to end with radclient: the switch answers Disconnect-NAK Session-Context-Not-Found."""
    from fake_coa import FakeSwitch
    from radius_admin import db, snmp_poller
    rc, dd = _radclient()
    if not rc:
        pytest.skip("radclient not available (set RADIUS_ADMIN_TEST_FR_PREFIX to a FreeRADIUS install prefix)")
    sw = FakeSwitch("Plaintext-Key-0001-abcdef", nak=True)
    try:
        cid = _client(superconn, ip="127.0.0.1")
        q(superconn, "UPDATE ui.snmp_profile SET coa_port = %s", (sw.port,))
        sid = _acct(superconn, "AA-BB-CC-00-00-38", 5, 1, nas="127.0.0.1")
        q(superconn, "INSERT INTO ui.coa_request (client_id, action, calling_station_id, nas_ip, nas_port_id,"
                     " requested_by, radacct_id) VALUES (%s, 'disconnect', 'AA-BB-CC-00-00-38', '127.0.0.1',"
                     " 'gi1/0/4', 'op', %s)", (cid, sid))
        conn = db.connect(APP_DSN)
        try:
            snmp_poller.run_coa(conn, {"radclient": rc, "radius_dict_dir": dd}, snmp_poller.load_profile(conn))
            conn.commit()
        finally:
            conn.close()
    finally:
        sw.close()
    assert _state(superconn, sid) == (True, "Session-Not-Found")
