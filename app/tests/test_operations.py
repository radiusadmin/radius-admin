"""SPEC section 13: sessions, authentication detail, per-port 802.1X state, alerts,
CoA / Disconnect, MAB expiry / vendors / unknown-device queue, audit reports."""
import csv
import datetime
import io
import json
import os
import socket
import threading

import psycopg2
import pytest

from conftest import APP_DSN

HERE = os.path.dirname(os.path.abspath(__file__))
SCRATCH_FR = os.environ.get("RADIUS_ADMIN_TEST_FR_PREFIX", "")


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def _client(superconn, name="sw1", ip="192.0.2.10", is_switch=True, secret="Plaintext-Key-0001-abcdef"):
    return q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, is_switch) VALUES (%s,%s,%s,%s)"
                        " RETURNING id", (name, ip, secret, is_switch))[0][0]


def _rule(superconn, group="Wired-Support", vlan=510):
    return q(superconn, "INSERT INTO ui.access_rule (priority, connection, ad_group, vlan, enabled, description)"
                        " VALUES (10, 'wired', %s, %s, true, 'Support workstations') RETURNING id", (group, vlan))[0][0]


def _hexgroups(*names):
    return "".join("," + n.encode().hex() for n in names)


# ======================================================================= pure helpers
def test_vendor_lookup_and_private_addresses():
    from radius_admin import oui
    if not oui.available():
        pytest.skip("ieee-data not installed")
    assert "Cisco" in oui.vendor("00:1B:0C:12:34:56")
    assert oui.vendor("001b.0c12.3456") == oui.vendor("00-1B-0C-12-34-56")
    assert oui.vendor("DA:A1:19:00:00:01") == oui.PRIVATE          # locally administered bit
    assert oui.vendor("not a mac") == "" and oui.normalize("aabb.ccdd.eeff") == "AABBCCDDEEFF"


def test_insight_helpers():
    from radius_admin import insight
    assert insight.decode_groups(_hexgroups("Wired-Support", "R&D Lab (Bldg-2)", "Guests,Wired-Support")) == [
        "Wired-Support", "R&D Lab (Bldg-2)", "Guests,Wired-Support"]
    assert insight.decode_groups(",zz,") == ["<undecodable: zz…>"]
    exp = insight.cert_expiry("271231235959Z")
    assert exp == datetime.datetime(2027, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)
    assert insight.cert_expiry("20271231235959Z") == exp and insight.cert_expiry("garbage") is None
    assert "Approve" in insight.reason_hint("radius-admin: MAB device not registered (added to the approval queue)")
    assert "EAP-TLS" in insight.reason_hint("eap: No mutually acceptable types found")
    assert "revoked" in insight.reason_hint("eap_tls: ocsp: Cert status: revoked")
    assert "No reason" in insight.reason_hint(None, "Access-Reject") and insight.reason_hint(None, "Access-Accept") == ""
    idx = insight.ClientIndex([{"id": 1, "name": "net", "ipaddr": "192.0.2.0/24", "is_switch": False, "enabled": True},
                               {"id": 2, "name": "host", "ipaddr": "192.0.2.10", "is_switch": True, "enabled": True}])
    assert idx.find("192.0.2.10")["name"] == "host" and idx.find("192.0.2.11")["name"] == "net"
    assert idx.find("172.16.0.1") is None and idx.find("garbage") is None


def test_port_state_parsing():
    from radius_admin import snmp
    ctl = {snmp.OID_DOT1X_PORT_CONTROL + ".4": "2", snmp.OID_DOT1X_PORT_CONTROL + ".5": "2",
           snmp.OID_DOT1X_PORT_CONTROL + ".6": "2", snmp.OID_DOT1X_PORT_CONTROL + ".7": "3"}
    names = {snmp.OID_IF_NAME + ".%d" % i: "gi%d" % i for i in (4, 5, 6, 7)}
    pae = {snmp.OID_DOT1X_PAE_STATE + ".4": "5", snmp.OID_DOT1X_PAE_STATE + ".5": "7",
           snmp.OID_DOT1X_PAE_STATE + ".6": "2"}
    st = {snmp.OID_DOT1X_PORT_STATUS + ".4": "1", snmp.OID_DOT1X_PORT_STATUS + ".5": "2",
          snmp.OID_DOT1X_PORT_STATUS + ".6": "2"}
    oper = {snmp.OID_IF_OPER + ".4": "1", snmp.OID_IF_OPER + ".5": "1", snmp.OID_IF_OPER + ".6": "2"}
    users = {snmp.OID_DOT1X_SESSION_USER + ".4": "68 6F 73 74 2F 70 63 31"}           # "host/pc1" as hex
    bridge = {snmp.OID_BRIDGE_PORT_IF + ".104": "4"}                                    # bridge port 104 = ifIndex 4
    pvid = {snmp.OID_PVID + ".104": "510", snmp.OID_PVID + ".5": "1"}
    ports = snmp.build_ports(ctl, names, pae, st, oper, users, bridge, pvid)
    assert [p["name"] for p in ports] == ["gi1/0/4", "gi1/0/5", "gi1/0/6"]           # only port-control auto
    p4, p5, p6 = ports
    assert p4["authorized"] and p4["user"] == "host/pc1" and p4["vlan"] == 510 and p4["state_text"] == "authorized"
    assert p5["authorized"] is False and p5["state_text"] == "held after a failed attempt" and p5["vlan"] == 1
    assert p6["oper"] == "down" and p6["state_text"] == "link down"
    # every optional table missing: still one row per 802.1X port, nothing invented
    bare = snmp.build_ports(ctl, names, {}, {}, {}, {}, {}, {})
    assert [p["authorized"] for p in bare] == [None, None, None] and all(not p["user"] for p in bare)


def test_save_status_tracks_failures_and_ports(app, superconn):
    from radius_admin import db, snmp_poller
    cid = _client(superconn)
    conn = db.connect(APP_DSN)
    try:
        snmp_poller._save_status(conn, cid, None, "no response")
        snmp_poller._save_status(conn, cid, None, "no response")
        conn.commit()
        assert q(superconn, "SELECT reachable, fail_count, last_ok_at FROM ui.switch_status")[0] == (False, 2, None)
        st = {"sys_name": "SW1", "sys_descr": "C1300", "uptime_seconds": 5, "dot1x_supported": True,
              "dot1x_ports": "gi1/0/4", "dot1x_port_count": 1, "radius_servers": [],
              "ports": [{"name": "gi1/0/4", "authorized": True, "user": "aa-bb-cc-00-00-01", "vlan": 510}]}
        snmp_poller._save_status(conn, cid, st)
        conn.commit()
    finally:
        conn.close()
    r = q(superconn, "SELECT reachable, fail_count, last_ok_at IS NOT NULL, ports FROM ui.switch_status")[0]
    assert r[:3] == (True, 0, True) and r[3][0]["name"] == "gi1/0/4"


# ======================================================================= MAB
def test_mab_expiry_form_and_list(app, browser, superconn, logged_in):
    logged_in("operator")
    r = browser.post("/mab/new", {"mac": "00:1b:0c:00:00:01", "vlan": "40", "description": "printer",
                                  "enabled": "1", "expires": "2000-01-01"}, csrf_page="/mab/new")
    assert r.status_code == 400 and "in the past" in browser.text(r)
    tomorrow = (datetime.datetime.now(datetime.timezone.utc).date() + datetime.timedelta(days=1)).isoformat()
    r = browser.post("/mab/new", {"mac": "00:1b:0c:00:00:01", "vlan": "40", "description": "printer",
                                  "enabled": "1", "expires": tomorrow}, csrf_page="/mab/new")
    assert r.status_code == 302
    exp = q(superconn, "SELECT expires_at FROM mab_device WHERE mac='00-1B-0C-00-00-01'")[0][0]
    # end of that day = next midnight UTC (compared in UTC: the test connection uses the
    # server's time zone, which need not be UTC)
    assert exp.astimezone(datetime.timezone.utc).date().isoformat() > tomorrow
    assert exp.astimezone(datetime.timezone.utc).time() == datetime.time(0)
    q(superconn, "INSERT INTO mab_device (mac, vlan, expires_at) VALUES ('00-1B-0C-00-00-02', 41, now() - interval '1 day')")
    t = browser.text(browser.get("/mab/"))
    assert "Expired" in t and "Cisco" in t or "Expired" in t        # vendor shown when ieee-data is installed
    assert "00-1B-0C-00-00-02" in browser.text(browser.get("/mab/?show=expired"))
    assert "00-1B-0C-00-00-02" not in browser.text(browser.get("/mab/?show=expiring"))
    # editing other fields keeps an already-past expiry without complaint
    mid = q(superconn, "SELECT id FROM mab_device WHERE mac='00-1B-0C-00-00-02'")[0][0]
    form = browser.text(browser.get("/mab/%d/edit" % mid))
    past = form.split('name="expires" type="date" value="')[1].split('"')[0]
    r = browser.post("/mab/%d/edit" % mid, {"mac": "00-1B-0C-00-00-02", "vlan": "42", "description": "x",
                                            "enabled": "1", "expires": past}, csrf_page="/mab/%d/edit" % mid)
    assert r.status_code == 302
    assert q(superconn, "SELECT vlan, expires_at < now() FROM mab_device WHERE id=%s", (mid,))[0] == (42, True)


def test_app_sessions_are_utc_whatever_the_server_zone(app, superconn):
    """Timestamps the app formats as "... UTC" (alerts, reports) must really be UTC."""
    from radius_admin import db
    from conftest import APP_DSN
    with superconn.cursor() as cur:
        cur.execute("SHOW timezone")
        server_zone = cur.fetchone()[0]
    with app.app_context():
        assert db.query_one("SHOW timezone")["TimeZone"] == "UTC"
        assert db.query_one("SELECT current_user AS u")["u"] == "radius_admin"   # role option kept
    c = db.connect(APP_DSN)
    try:
        with c.cursor() as cur:
            cur.execute("SHOW timezone")
            assert cur.fetchone()[0] == "UTC", "standalone connections (monitor, CLI) too; server: " + server_zone
    finally:
        c.close()


def test_mab_csv_expires_column(app, browser, superconn, logged_in):
    logged_in("operator")
    r = browser.post("/mab/import", {"text": "mac,vlan,description,expires\n00-1B-0C-00-00-03,40,cam,2099-12-31\n"
                                             "00-1B-0C-00-00-04,40,cam\n", "mode": "add"}, csrf_page="/mab/import")
    assert r.status_code == 302
    rows = dict(q(superconn, "SELECT mac, expires_at IS NOT NULL FROM mab_device"))
    assert rows == {"00-1B-0C-00-00-03": True, "00-1B-0C-00-00-04": False}
    r = browser.post("/mab/import", {"text": "00-1B-0C-00-00-05,40,cam,31/12/2099\n", "mode": "add"},
                     csrf_page="/mab/import")
    assert r.status_code == 400 and "YYYY-MM-DD" in browser.text(r)


def test_unknown_device_queue_approve(app, browser, superconn, logged_in):
    cid = _client(superconn)
    q(superconn, "INSERT INTO mab_pending (mac, attempts, nas_ip, nas_port_id) VALUES"
                 " ('00-1B-0C-00-00-09', 3, '192.0.2.10', 'gi1/0/7'), ('DA-A1-19-00-00-01', 1, NULL, NULL)")
    logged_in("operator")
    r = browser.post("/mab/unknown/default-vlan", {"default_vlan": "130"}, csrf_page="/mab/unknown")
    assert r.status_code == 302
    t = browser.text(browser.get("/mab/unknown"))
    assert "00-1B-0C-00-00-09" in t and "sw1" in t and "gi1/0/7" in t and 'value="130"' in t
    assert "Private (randomized" in t
    assert "2" in browser.text(browser.get("/mab/")).split("Unknown devices")[1][:80]   # tab count
    r = browser.post("/mab/unknown/00-1B-0C-00-00-09/approve", {"vlan": "130", "expires_days": "7",
                                                                 "description": ""}, csrf_page="/mab/unknown")
    assert r.status_code == 302
    d = q(superconn, "SELECT vlan, enabled, expires_at > now() + interval '6 days', description FROM mab_device"
                     " WHERE mac='00-1B-0C-00-00-09'")[0]
    assert d[:3] == (130, True, True) and "192.0.2.10" in d[3] and "gi1/0/7" in d[3]
    assert q(superconn, "SELECT count(*) FROM mab_pending WHERE mac='00-1B-0C-00-00-09'")[0][0] == 0
    ad = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='mab.approve'")[0][0]
    assert ad["mac"] == "00-1B-0C-00-00-09" and ad["vlan"] == 130 and ad["attempts"] == 3
    # bad VLAN: nothing registered
    r = browser.post("/mab/unknown/DA-A1-19-00-00-01/approve", {"vlan": "5000"}, csrf_page="/mab/unknown")
    assert r.status_code == 302 and q(superconn, "SELECT count(*) FROM mab_device WHERE mac='DA-A1-19-00-00-01'")[0][0] == 0
    # hide, then show again, then dismiss
    browser.post("/mab/unknown/DA-A1-19-00-00-01/ignore", {"on": "1"}, csrf_page="/mab/unknown")
    assert q(superconn, "SELECT ignored FROM mab_pending")[0][0] is True
    assert "/mab/unknown/DA-A1-19-00-00-01/approve" not in browser.text(browser.get("/mab/unknown"))
    assert "DA-A1-19-00-00-01" in browser.text(browser.get("/mab/unknown?ignored=1"))
    browser.post("/mab/unknown/DA-A1-19-00-00-01/ignore", {"on": "0", "from_ignored": "1"}, csrf_page="/mab/unknown")
    browser.post("/mab/unknown/DA-A1-19-00-00-01/dismiss", {}, csrf_page="/mab/unknown")
    assert q(superconn, "SELECT count(*) FROM mab_pending")[0][0] == 0
    assert cid


def test_unknown_queue_rbac(app, browser, superconn, logged_in):
    q(superconn, "INSERT INTO mab_pending (mac) VALUES ('00-1B-0C-00-00-0A')")
    logged_in("viewer")
    t = browser.text(browser.get("/mab/unknown"))
    assert "00-1B-0C-00-00-0A" in t and "Approve" not in t
    r = browser.post("/mab/unknown/00-1B-0C-00-00-0A/approve", {"vlan": "10"}, csrf_page="/mab/unknown")
    assert r.status_code == 403
    assert browser.post("/mab/unknown/zz/approve", {"vlan": "10"}, csrf_page="/mab/unknown").status_code == 403


def test_mab_pending_function_bounded(superconn):
    """The FreeRADIUS-facing function caps the queue at 2000 rows."""
    q(superconn, "BEGIN")
    try:
        q(superconn, "DELETE FROM mab_pending")
        q(superconn, "INSERT INTO mab_pending (mac) SELECT regexp_replace(upper(lpad(to_hex(g), 12, '0')),"
                     " '(..)(?!$)', '\\1-', 'g') FROM generate_series(1, 2000) g")
        q(superconn, "SET LOCAL ROLE radius_fr")
        assert q(superconn, "SELECT radius_admin_mab_hex('AA-AA-AA-AA-AA-AA', '', '')")[0][0] == "unknown"
        q(superconn, "RESET ROLE")
        assert q(superconn, "SELECT count(*) FROM mab_pending")[0][0] == 2000
    finally:
        q(superconn, "ROLLBACK")


# ======================================================================= auth detail
def test_auth_log_reason_and_detail(app, browser, superconn, logged_in):
    _client(superconn)
    rid = _rule(superconn)
    aid = q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, callingstationid,"
                       " nasporttype, vlan, certsan, nasportid, cert_cn, cert_subject, cert_issuer, cert_serial,"
                       " cert_expiry, ad_groups_hex, rule_id) VALUES ('host/pc1.example.net', 'Access-Accept',"
                       " 'eap-tls', '192.0.2.10', '3C-22-FB-00-00-01', 'Ethernet', '510', 'pc1.example.net',"
                       " 'gi1/0/4', 'pc1.example.net', '/CN=pc1.example.net', '/DC=net/CN=Example-IssuingCA',"
                       " '1a2b', '200101000000Z', %s, %s) RETURNING id", (_hexgroups("Domain Computers", "WIRED-SUPPORT"), rid))[0][0]
    rej = q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, callingstationid, reason)"
                       " VALUES ('aabbcc0000ff', 'Access-Reject', 'mab', '192.0.2.10', 'AA-BB-CC-00-00-FF',"
                       " 'radius-admin: MAB device not registered (added to the approval queue)') RETURNING id")[0][0]
    q(superconn, "INSERT INTO mab_pending (mac) VALUES ('AA-BB-CC-00-00-FF')")
    logged_in("viewer")
    t = browser.text(browser.get("/auth-log"))
    assert "sw1" in t and "gi1/0/4" in t and "MAB device not registered" in t
    t = browser.text(browser.get("/auth-log/%d" % aid))
    assert "Wired-Support" in t and "matched" in t and "Support workstations" in t
    assert "Domain Computers" in t and "Example-IssuingCA" in t and "Expired" in t      # 2020 expiry
    t = browser.text(browser.get("/auth-log/%d" % rej))
    assert "Why it was rejected" in t and "Unknown devices" in t and "approval queue" in t
    assert browser.get("/auth-log/999999").status_code == 404


# ======================================================================= sessions + CoA
def _session(superconn, start_minutes=30, stop=False, csi="3C-22-FB-00-00-01", user="host/pc1.example.net"):
    return q(superconn, "INSERT INTO radacct (acctsessionid, acctuniqueid, username, nasipaddress, nasportid,"
                        " acctstarttime, acctupdatetime, acctstoptime, callingstationid, acctterminatecause)"
                        " VALUES ('0000002A', md5(random()::text), %s, '192.0.2.10', 'gi1/0/4',"
                        " now() - make_interval(mins => %s), NULL, CASE WHEN %s THEN now() END, %s,"
                        " CASE WHEN %s THEN 'User-Request' END) RETURNING radacctid",
             (user, start_minutes, stop, csi, stop))[0][0]


def test_sessions_page(app, browser, superconn, logged_in):
    logged_in("viewer")
    assert "No accounting received yet" in browser.text(browser.get("/sessions/"))
    cid = _client(superconn)
    _client(superconn, "sw2", "192.0.2.11")
    sid = _session(superconn)
    _session(superconn, 120, True, "3C-22-FB-00-00-02", "host/pc2")
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, callingstationid, vlan, authdate)"
                 " VALUES ('host/pc1.example.net', 'Access-Accept', 'eap-tls', '192.0.2.10', '3C-22-FB-00-00-01',"
                 " '510', now() - interval '31 minutes')")
    q(superconn, "INSERT INTO ui.switch_status (client_id, reachable, ports) VALUES (%s, true, %s)",
      (cid, json.dumps([{"name": "gi1/0/4", "authorized": True, "oper": "up", "user": "host/pc1"}])))
    t = browser.text(browser.get("/sessions/"))
    assert "host/pc1.example.net" in t and "host/pc2" not in t
    assert "sw1" in t and "gi1/0/4" in t and ">510<" in t and "Authorized" in t
    assert "1 of 2 switches sent accounting" in t and "sw2" in t
    assert "Actions" not in t                                          # viewer: no CoA menu
    t = browser.text(browser.get("/sessions/?history=1"))
    assert "host/pc2" in t and "User-Request" in t
    assert "host/pc2" not in browser.text(browser.get("/sessions/?q=pc1&history=1"))
    assert "host/pc1" in browser.text(browser.get("/sessions/?q=3c22fb000001"))
    assert sid


def test_coa_request_queue_and_rbac(app, browser, superconn, logged_in):
    _client(superconn)
    sid = _session(superconn)
    ended = _session(superconn, 60, True, "3C-22-FB-00-00-02", "host/pc2")
    logged_in("viewer")
    r = browser.post("/sessions/%d/coa" % sid, {"action": "reauth"}, csrf_page="/sessions/")
    assert r.status_code == 403
    browser.cookies = {}


def test_coa_request_operator(app, browser, superconn, logged_in):
    _client(superconn)
    sid = _session(superconn)
    ended = _session(superconn, 60, True, "3C-22-FB-00-00-02", "host/pc2")
    logged_in("operator")
    assert "Actions" in browser.text(browser.get("/sessions/"))
    assert browser.post("/sessions/%d/coa" % sid, {"action": "explode"}, csrf_page="/sessions/").status_code == 400
    r = browser.post("/sessions/%d/coa" % sid, {"action": "bounce"}, csrf_page="/sessions/")
    assert r.status_code == 302 and "/sessions/coa/" in r.headers["Location"]
    row = q(superconn, "SELECT action, acct_session_id, calling_station_id, host(nas_ip), nas_port_id, requested_by,"
                       " done_at FROM ui.coa_request")[0]
    assert row == ("bounce", "0000002A", "3C-22-FB-00-00-01", "192.0.2.10", "gi1/0/4", "operator1", None)
    t = browser.text(browser.get(r.headers["Location"]))
    assert "Bounce port" in t and "Sending" in t
    assert q(superconn, "SELECT detail->>'action' FROM ui.audit_log WHERE action='coa.request'")[0][0] == "bounce"
    r = browser.post("/sessions/%d/coa" % ended, {"action": "disconnect"}, csrf_page="/sessions/")
    assert r.status_code == 302 and q(superconn, "SELECT count(*) FROM ui.coa_request")[0][0] == 1


def _radclient():
    from radius_admin import coa
    prefix = SCRATCH_FR or ""
    for cand in ([os.path.join(prefix, "bin", "radclient")] if prefix else []) + ["/usr/bin/radclient"]:
        if os.access(cand, os.X_OK):
            try:
                return cand, coa.find_dict_dir(cand)
            except coa.CoaError:
                pass
    return None, None


def test_monitor_sends_coa_with_radclient(app, superconn):
    """End to end through the monitor: queued request -> radclient -> RFC 5176 switch (simulated)."""
    from fake_coa import FakeSwitch
    from radius_admin import db, snmp_poller
    rc, dd = _radclient()
    if not rc:
        pytest.skip("radclient not available (set RADIUS_ADMIN_TEST_FR_PREFIX to a FreeRADIUS install prefix)")
    sw = FakeSwitch("Plaintext-Key-0001-abcdef")
    try:
        cid = _client(superconn, ip="127.0.0.1")
        q(superconn, "UPDATE ui.snmp_profile SET coa_port = %s", (sw.port,))
        for action in ("reauth", "disconnect"):
            q(superconn, "INSERT INTO ui.coa_request (client_id, action, acct_session_id, calling_station_id, nas_ip,"
                         " nas_port_id, username, requested_by) VALUES (%s, %s, '0000002A', 'AA-BB-CC-00-00-01',"
                         " '127.0.0.1', 'gi1/0/4', 'host/pc1', 'op')", (cid, action))
        conn = db.connect(APP_DSN)
        try:
            profile = snmp_poller.load_profile(conn)
            n = snmp_poller.run_coa(conn, {"radclient": rc, "radius_dict_dir": dd}, profile)
            conn.commit()
        finally:
            conn.close()
        assert n == 2
        res = q(superconn, "SELECT action, ok, message FROM ui.coa_request ORDER BY id")
        assert res[0][:2] == ("reauth", True) and "CoA-ACK" in res[0][2]
        assert res[1][:2] == ("disconnect", True) and "Disconnect-ACK" in res[1][2]
        got = sw.requests
        assert [g["code"] for g in got] == ["CoA-Request", "Disconnect-Request"]
        assert all(g["auth_ok"] and g["msg_auth_ok"] for g in got)
        assert got[0]["cisco"] == ["subscriber:command=reauthenticate"] and got[1]["cisco"] == []
        assert got[0]["attrs"]["Acct-Session-Id"] == "0000002A" and got[0]["attrs"]["NAS-IP-Address"] == "127.0.0.1"
        assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action='coa.result' AND success")[0][0] == 2
    finally:
        sw.close()


def test_monitor_coa_failures_are_reported(app, superconn):
    from radius_admin import db, snmp_poller
    cid = _client(superconn)
    q(superconn, "INSERT INTO ui.coa_request (client_id, action, acct_session_id, nas_ip) VALUES (%s, 'reauth',"
                 " 'bad\"id', '192.0.2.10')", (cid,))
    conn = db.connect(APP_DSN)
    try:
        snmp_poller.run_coa(conn, {"radclient": "/nonexistent/radclient"}, None)
        conn.commit()
    finally:
        conn.close()
    ok, msg = q(superconn, "SELECT ok, message FROM ui.coa_request")[0]
    assert ok is False and "radclient" in msg


# ======================================================================= alerts
@pytest.fixture
def mon_conn(app):
    from radius_admin import db
    conn = db.connect(APP_DSN)
    yield conn
    conn.close()


@pytest.fixture
def syslog_lines(monkeypatch):
    from radius_admin import audit
    lines = []
    monkeypatch.setattr(audit, "log_syslog", lambda msg, priority=None: lines.append(msg))
    return lines


def test_reject_spike_opens_once_and_resolves(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    q(superconn, "UPDATE ui.alert_settings SET reject_threshold = 5, reject_window_minutes = 5")
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, reason)"
                 " SELECT 'u' || g, 'Access-Reject', 'mab', '192.0.2.10', 'radius-admin: MAB device is disabled'"
                 " FROM generate_series(1, 6) g")
    s = alerts.load_settings(mon_conn)
    alerts.check_rejects(mon_conn, s)
    alerts.check_rejects(mon_conn, s)       # still high: no second alert / notification
    mon_conn.commit()
    rows = q(superconn, "SELECT kind, state, message, notified FROM ui.alert")
    assert len(rows) == 1 and rows[0][:2] == ("reject_spike", "open")
    assert "6 rejects" in rows[0][2] and "MAB device is disabled x6" in rows[0][2] and rows[0][3] == "syslog"
    assert len([ln for ln in syslog_lines if "ALERT OPEN reject_spike" in ln]) == 1
    q(superconn, "UPDATE radpostauth SET authdate = now() - interval '1 hour'")
    alerts.check_rejects(mon_conn, s)
    mon_conn.commit()
    assert q(superconn, "SELECT state FROM ui.alert")[0][0] == "resolved"
    assert any("ALERT RESOLVED reject_spike" in ln for ln in syslog_lines)
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action IN ('alert.open','alert.resolve')")[0][0] == 2


def test_switch_down_alert(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    a = _client(superconn)
    b = _client(superconn, "ap1", "192.0.2.12", is_switch=False)
    q(superconn, "INSERT INTO ui.switch_status (client_id, reachable, fail_count, error) VALUES"
                 " (%s, false, 2, 'no response'), (%s, false, 9, 'no response')", (a, b))
    s = alerts.load_settings(mon_conn)
    alerts.check_switches(mon_conn, s, snmp_enabled=False)        # monitoring off: nothing
    assert q(superconn, "SELECT count(*) FROM ui.alert")[0][0] == 0
    alerts.check_switches(mon_conn, s, snmp_enabled=True)
    mon_conn.commit()
    rows = q(superconn, "SELECT subject, state, message FROM ui.alert")
    assert rows == [(str(a), "open", rows[0][2])] and "sw1" in rows[0][2]       # ap1 is not a switch
    q(superconn, "UPDATE ui.switch_status SET reachable = true, fail_count = 0 WHERE client_id = %s", (a,))
    alerts.check_switches(mon_conn, s, snmp_enabled=True)
    mon_conn.commit()
    assert q(superconn, "SELECT state FROM ui.alert")[0][0] == "resolved"


def test_radius_down_needs_two_checks(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    s = alerts.load_settings(mon_conn)
    state = {}
    down = {"ok": True, "service_active": False, "listening": False}
    alerts.check_radius(mon_conn, s, down, state)
    mon_conn.commit()
    assert q(superconn, "SELECT count(*) FROM ui.alert")[0][0] == 0      # a restart during Apply
    assert q(superconn, "SELECT radius_ok FROM ui.monitor_state")[0][0] is False
    alerts.check_radius(mon_conn, s, down, state)
    alerts.check_radius(mon_conn, s, {"ok": True, "service_active": True, "listening": False}, state)
    mon_conn.commit()
    rows = q(superconn, "SELECT kind, state, message FROM ui.alert")
    assert len(rows) == 1 and rows[0][:2] == ("radius_down", "open")
    alerts.check_radius(mon_conn, s, {"ok": True, "service_active": True, "listening": True}, state)
    mon_conn.commit()
    assert q(superconn, "SELECT state FROM ui.alert")[0][0] == "resolved"
    assert any("ALERT OPEN radius_down" in ln for ln in syslog_lines)


class _FakeSMTP:
    """Just enough SMTP (no TLS) to receive one message."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.messages = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        c, _ = self.sock.accept()
        f = c.makefile("rwb")
        f.write(b"220 fake\r\n")
        f.flush()
        data, in_data = [], False
        for raw in f:
            line = raw.decode().rstrip("\r\n")
            if in_data:
                if line == ".":
                    self.messages.append("\n".join(data))
                    in_data = False
                    f.write(b"250 ok\r\n")
                else:
                    data.append(line)
            elif line.upper().startswith("EHLO"):
                f.write(b"250-fake\r\n250 8BITMIME\r\n")
            elif line.upper() == "DATA":
                in_data = True
                f.write(b"354 go\r\n")
            elif line.upper() == "QUIT":
                f.write(b"221 bye\r\n")
                f.flush()
                break
            else:
                f.write(b"250 ok\r\n")
            f.flush()
        c.close()


def test_email_delivery(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    smtp = _FakeSMTP()
    q(superconn, "UPDATE ui.alert_settings SET email_enabled = true, smtp_host = '127.0.0.1', smtp_port = %s,"
                 " smtp_security = 'none', mail_from = 'radius@example.net', mail_to = 'netops@example.net'",
      (smtp.port,))
    s = alerts.load_settings(mon_conn)
    channels = alerts.send_test(mon_conn, s, "admin1")
    mon_conn.commit()
    assert channels == ["syslog", "email"]
    for _ in range(50):
        if smtp.messages:
            break
        threading.Event().wait(0.05)
    msg = smtp.messages[0]
    assert "Subject: [radius-admin] Test alert" in msg and "admin1" in msg and "To: netops@example.net" in msg
    # a login over plaintext is refused, and a failed email never breaks monitoring
    s = dict(s, smtp_user="relay", smtp_port=1)
    assert any(c.startswith("email failed") for c in alerts.notify(mon_conn, s, None, "test", "open", "", "x"))


def test_alert_pages_and_settings(app, browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.alert (kind, subject, state, message) VALUES ('radius_down', '', 'open', 'The FreeRADIUS service is not active.')")
    logged_in("viewer")
    t = browser.text(browser.get("/alerts/"))
    assert "FreeRADIUS down" in t and "not active" in t and "monitoring service has not reported" in t
    assert "Alert settings" not in t
    assert 'class="badge badge-danger"' in browser.text(browser.get("/dashboard"))
    assert "1 open alert" in browser.text(browser.get("/dashboard"))
    assert browser.get("/alerts/settings").status_code == 403


def test_alert_settings_admin(app, browser, superconn, logged_in):
    logged_in("admin")
    data = {"syslog_enabled": "1", "email_enabled": "1", "reject_enabled": "1", "reject_threshold": "40",
            "reject_window_minutes": "10", "switch_enabled": "1", "switch_failed_polls": "3", "radius_enabled": "1",
            "smtp_host": "smtp.example.net", "smtp_port": "587", "smtp_security": "none", "smtp_user": "relay",
            "smtp_pass": "S3cret-relay", "mail_from": "radius@example.net", "mail_to": "a@example.net, b@example.net"}
    r = browser.post("/alerts/settings", data, csrf_page="/alerts/settings")
    assert r.status_code == 400 and "unencrypted" in browser.text(r)
    data["smtp_security"] = "starttls"
    r = browser.post("/alerts/settings", data, csrf_page="/alerts/settings")
    assert r.status_code == 302
    row = q(superconn, "SELECT reject_threshold, email_enabled, mail_to, smtp_pass_enc FROM ui.alert_settings")[0]
    assert row[:3] == (40, True, "a@example.net, b@example.net")
    assert row[3] is not None and b"S3cret-relay" not in bytes(row[3])
    detail = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='alert.settings'")[0][0]
    assert detail["smtp_login_key_updated"] is True and "S3cret" not in json.dumps(detail)
    # the monitor can decrypt it with the same key
    from radius_admin import db, snmp_poller
    from radius_admin.crypto import DataKey
    key = app.config["RA_DATA_KEY"]
    conn = db.connect(APP_DSN)
    try:
        s = db.query_one("SELECT * FROM ui.alert_settings", conn=conn)
        assert snmp_poller.smtp_password(key, s) == "S3cret-relay"
    finally:
        conn.close()
    assert DataKey
    r = browser.post("/alerts/test", {}, csrf_page="/alerts/")
    assert r.status_code == 302
    assert q(superconn, "SELECT test_requested_by FROM ui.alert_settings")[0][0] == "admin1"


def test_monitor_heartbeat_and_housekeeping(app, superconn):
    from radius_admin import db, snmp_poller
    q(superconn, "INSERT INTO mab_pending (mac, last_seen) VALUES ('00-1B-0C-00-00-0B', now() - interval '31 days'),"
                 " ('00-1B-0C-00-00-0C', now())")
    conn = db.connect(APP_DSN)
    try:
        snmp_poller.heartbeat(conn, "/usr/bin/radclient")
        snmp_poller.housekeeping(conn)
    finally:
        conn.close()
    assert q(superconn, "SELECT heartbeat_at IS NOT NULL, radclient FROM ui.monitor_state")[0] == (True, "/usr/bin/radclient")
    assert q(superconn, "SELECT mac FROM mab_pending") == [("00-1B-0C-00-00-0C",)]


# ======================================================================= reports
def test_reports_render_and_export(app, browser, superconn, logged_in):
    _client(superconn)
    _rule(superconn)
    q(superconn, "INSERT INTO mab_device (mac, vlan, description) VALUES ('00-1B-0C-00-00-01', 40, '=HYPERLINK(\"x\")')")
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, reason) VALUES"
                 " ('u1', 'Access-Reject', 'mab', '192.0.2.10', 'radius-admin: MAB device is disabled'),"
                 " ('u2', 'Access-Accept', 'eap-tls', '192.0.2.10', NULL)")
    _session(superconn)
    logged_in("admin")
    from radius_admin.views.reports import REPORTS
    for key in REPORTS:
        r = browser.get("/reports/%s" % key)
        assert r.status_code == 200, key
        r = browser.get("/reports/%s?format=csv" % key)
        assert r.status_code == 200 and r.headers["Content-Type"].startswith("text/csv"), key
        assert "attachment" in r.headers["Content-Disposition"]
    t = browser.text(browser.get("/reports/auth_summary"))
    assert "sw1" in t and "MAB device is disabled" in t
    body = browser.get("/reports/mab?format=csv").get_data(as_text=True)
    rows = list(csv.reader(io.StringIO(body.lstrip("﻿"))))
    assert rows[0][0] == "MAC" and rows[1][3].startswith("'=")          # formula neutralized
    t = browser.text(browser.get("/reports/privileged"))
    assert "admin1" in t and "console administrator" in t
    t = browser.text(browser.get("/reports/clients"))
    assert "Plaintext-Key" not in t                                       # never a secret
    n = q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action IN ('report.view', 'report.export')")[0][0]
    assert n >= 2 * len(REPORTS)


def test_reports_rbac_and_period(app, browser, superconn, logged_in):
    logged_in("viewer")
    t = browser.text(browser.get("/reports/"))
    assert "Privileged access" not in t and "Configuration changes" in t
    assert browser.get("/reports/privileged").status_code == 403
    assert browser.get("/reports/nonsense").status_code == 404
    t = browser.text(browser.get("/reports/changes?since=2026-01-02&until=2026-01-01"))
    assert "2026-01-01 00:00 to 2026-01-02 24:00 UTC" in t                # swapped into order


def test_changes_report_excludes_signins_by_default(app, browser, superconn, logged_in):
    logged_in("admin")
    browser.post("/mab/new", {"mac": "00-1B-0C-00-00-0D", "vlan": "40", "enabled": "1"}, csrf_page="/mab/new")
    t = browser.text(browser.get("/reports/changes"))
    assert "mab.create" in t and "auth.login" not in t
    assert "auth.login" in browser.text(browser.get("/reports/changes?signins=1"))


# ======================================================================= pages and wording
def test_client_page_shows_port_states(app, browser, superconn, logged_in):
    cid = _client(superconn)
    q(superconn, "INSERT INTO ui.switch_status (client_id, reachable, dot1x_supported, dot1x_ports, dot1x_port_count,"
                 " ports) VALUES (%s, true, true, 'gi1/0/4-5', 2, %s)",
      (cid, json.dumps([{"name": "gi1/0/4", "authorized": True, "oper": "up", "user": "00-1b-0c-00-00-01", "vlan": 40},
                        {"name": "gi1/0/5", "authorized": False, "oper": "up", "state_text": "held after a failed attempt"}])))
    logged_in("admin")
    t = browser.text(browser.get("/clients/%d/edit" % cid))
    assert "1 of 2 authorized" in t and "held after a failed attempt" in t and "00-1B-0C-00-00-01" in t


def test_no_smart_card_wording(app, browser, superconn, logged_in):
    root = os.path.join(os.path.dirname(HERE), "radius_admin")
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith((".html", ".py")):
                text = open(os.path.join(dirpath, f), encoding="utf-8").read().lower()
                assert "smart card" not in text and "cac/piv" not in text, f
