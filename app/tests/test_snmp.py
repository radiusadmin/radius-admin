"""SPEC section 12: read-only SNMPv3 switch monitoring."""
import os
import shutil
import subprocess

import psycopg2
import pytest

from conftest import APP_DSN

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def _fixture_status(name):
    from radius_admin import snmp
    vals = snmp.parse_output(open(os.path.join(DATA, name)).read())
    pick = lambda b: {k: v for k, v in vals.items() if k.startswith(b)}
    return snmp.build_status(pick("1.3.6.1.2.1.1."), pick(snmp.OID_DOT1X_PORT_CONTROL),
                             pick(snmp.OID_IF_NAME), {}, {})


# ------------------------------------------------------------- parsing (real switch output)
def test_real_c1300_standalone_ports():
    st = _fixture_status("snmp_c1300_48p.txt")
    assert st["sys_name"] == "SW-ACCESS-09" and "C1300-48P-4G" in st["sys_descr"]
    # ifName gi4 (standalone) -> CLI/CSV name gi1/0/4; ports 4, 5, 8 are port-control auto
    assert st["dot1x_ports"] == "gi1/0/4-5,gi1/0/8" and st["dot1x_port_count"] == 3
    assert st["dot1x_supported"] and st["uptime_seconds"] == 6830975


def test_real_c1300_stack_no_dot1x():
    st = _fixture_status("snmp_c1300_24xs_stack.txt")
    assert st["sys_name"] == "SW-CORE-02"
    assert st["dot1x_supported"] and st["dot1x_ports"] == "" and st["dot1x_port_count"] == 0


def test_compress_and_compare():
    from radius_admin.snmp import compress_ports, cli_port_name
    from radius_admin.ports import same_ports
    assert cli_port_name("gi4") == "gi1/0/4" and cli_port_name("te1/0/3") == "te1/0/3"
    assert cli_port_name("Po1") == "Po1"
    assert compress_ports(["te1/0/1", "te1/0/2", "te1/0/3", "te1/0/23", "te2/0/1"]) == "te1/0/1-3,te1/0/23,te2/0/1"
    assert same_ports("gi1/0/4-5,gi1/0/8", "gi1/0/4,gi1/0/5,gi1/0/8")
    assert same_ports("GI1/0/4-5, gi1/0/8", "gi1/0/4-5,gi1/0/8")
    assert not same_ports("gi1/0/4-6", "gi1/0/4-5")


def test_radius_counters_ext_table():
    from radius_admin import snmp
    ext = {snmp.OID_RADIUS_EXT + ".3.1": "C0 00 02 05", snmp.OID_RADIUS_EXT + ".4.1": "1812",
           snmp.OID_RADIUS_EXT + ".6.1": "120", snmp.OID_RADIUS_EXT + ".8.1": "100",
           snmp.OID_RADIUS_EXT + ".9.1": "15", snmp.OID_RADIUS_EXT + ".12.1": "3",
           snmp.OID_RADIUS_EXT + ".13.1": "0", snmp.OID_RADIUS_EXT + ".14.1": "2"}
    st = snmp.build_status({}, {}, {}, ext, {})
    assert st["radius_servers"] == [{"address": "192.0.2.5", "port": 1812, "requests": 120, "accepts": 100,
                                     "rejects": 15, "bad_authenticators": 3, "pending": 0, "timeouts": 2,
                                     "index": "1"}]


def test_credential_validation_and_no_argv_secrets():
    from radius_admin.snmp import Session, validate_passphrase, validate_username
    with pytest.raises(ValueError):
        validate_username("bad user")
    for bad in ("short", "has space in it", 'quote"inside1', "x" * 65):
        with pytest.raises(ValueError):
            validate_passphrase(bad, "P")
    with pytest.raises(Exception):
        Session("u", "MD5", "AuthPass-Test-1", "AES", "PrivPass-Test-2")
    with Session("radmon", "SHA-256", "AuthPass-Test-1", "AES", "PrivPass-Test-2") as s:
        conf = os.path.join(s.dir, "snmp.conf")
        assert oct(os.stat(conf).st_mode & 0o777) == "0o600"
        assert "defAuthType SHA-256" in open(conf).read()
        d = s.dir
    assert not os.path.exists(d)   # wiped and removed


# ------------------------------------------------------------- live agent (local snmpd)
AGENT_ARGS = ["-v3", "-l", "authPriv", "-u", "radmon", "-a", "SHA-256", "-A", "AuthPass-Test-1",
              "-x", "AES", "-X", "PrivPass-Test-2", "-t", "1", "-r", "0", "127.0.0.1", "1.3.6.1.2.1.1.5.0"]


def _agent_answers():
    try:
        p = subprocess.run(["snmpget"] + AGENT_ARGS, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "test-switch-01" in p.stdout


@pytest.fixture(scope="module")
def snmpd(tmp_path_factory):
    """A local Net-SNMP agent on 127.0.0.1:161 with user radmon (SHA-256 / AES-128).
    Port 161 needs root: when the suite runs as another user (postgres), start the agent
    beforehand as root (tests/README: snmpd test agent) or these tests are skipped."""
    if not shutil.which("snmpget"):
        pytest.skip("Net-SNMP tools not installed")
    if _agent_answers():
        yield
        return
    if os.geteuid() != 0 or not shutil.which("snmpd"):
        pytest.skip("no test SNMP agent on 127.0.0.1:161 (start one as root, see tests/README_snmpd.txt)")
    d = tmp_path_factory.mktemp("snmpd")
    conf = d / "snmpd.conf"
    conf.write_text("rouser radmon authpriv .1\nsysName test-switch-01\nsysDescr Test agent\n"
                    'createUser radmon SHA-256 "AuthPass-Test-1" AES "PrivPass-Test-2"\n')
    (d / "persist").mkdir()
    p = subprocess.run(["snmpd", "-C", "-c", str(conf), "-p", str(d / "pid"), "--persistentDir=%s" % (d / "persist"),
                        "-Lf", str(d / "log"), "udp:127.0.0.1:161"], capture_output=True)
    if p.returncode != 0:
        pytest.skip("cannot start snmpd")
    import time
    time.sleep(1.5)
    yield
    try:
        os.kill(int((d / "pid").read_text().strip()), 15)
    except Exception:
        pass


def _set_profile(superconn, app, user="radmon", auth="AuthPass-Test-1", priv="PrivPass-Test-2", auto=False):
    from radius_admin.snmp_poller import encrypt_pass
    key = app.config["RA_DATA_KEY"]
    q(superconn, "UPDATE ui.snmp_profile SET enabled=true, username=%s, auth_pass_enc=%s, priv_pass_enc=%s,"
                 " auto_update_ports=%s WHERE id=1",
      (user, psycopg2.Binary(encrypt_pass(key, "auth", auth)), psycopg2.Binary(encrypt_pass(key, "priv", priv)), auto))


def test_poller_cycle_against_agent(app, superconn, snmpd):
    from radius_admin import snmp_poller, db
    _set_profile(superconn, app)
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, dot1x_ports) VALUES"
                 " ('sw-live','127.0.0.1','Plaintext-Key-0001-abcdef','gi1/0/1'),"
                 " ('sw-dead','127.0.0.9','Plaintext-Key-0002-abcdef',''),"
                 " ('net','198.51.100.0/28','Plaintext-Key-0003-abcdef',''),"
                 " ('wifi-ap','127.0.0.1/32','Plaintext-Key-0004-abcdef','')")
    q(superconn, "UPDATE ui.radius_client SET is_switch = (name <> 'wifi-ap')")   # the AP is not a switch
    conn = db.connect(APP_DSN)
    try:
        prof = snmp_poller.load_profile(conn)
        n, ok, upd = snmp_poller.run_cycle(conn, app.config["RA_DATA_KEY"], prof)
    finally:
        conn.close()
    assert (n, ok, upd) == (3, 1, 0)
    rows = {r[0]: r[1:] for r in q(superconn, "SELECT c.name, s.reachable, s.sys_name, s.dot1x_supported, s.error"
                                               " FROM ui.switch_status s JOIN ui.radius_client c ON c.id=s.client_id")}
    assert rows["sw-live"][:3] == (True, "test-switch-01", False)
    assert rows["sw-dead"][0] is False and rows["sw-dead"][3]
    assert "not a single address" in rows["net"][3]
    assert "wifi-ap" not in rows                       # not a switch -> never polled
    # the CSV value is untouched (no 802.1X MIB on this agent)
    assert q(superconn, "SELECT dot1x_ports FROM ui.radius_client WHERE name='sw-live'")[0][0] == "gi1/0/1"


def test_poller_wrong_credentials(app, superconn, snmpd):
    from radius_admin import snmp_poller, db
    _set_profile(superconn, app, auth="WrongPass-Test-9")
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, is_switch) VALUES ('sw-live','127.0.0.1','Plaintext-Key-0001-abcdef',true)")
    conn = db.connect(APP_DSN)
    try:
        snmp_poller.run_cycle(conn, app.config["RA_DATA_KEY"], snmp_poller.load_profile(conn))
    finally:
        conn.close()
    r = q(superconn, "SELECT reachable, error FROM ui.switch_status")[0]
    assert r[0] is False and "uthentication" in r[1]


def test_auto_update_ports_audited(app, superconn, monkeypatch):
    from radius_admin import snmp_poller, db
    _set_profile(superconn, app, auto=True)
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, dot1x_ports) VALUES"
                 " ('sw9','192.0.2.9','Plaintext-Key-0001-abcdef','gi1/0/1-2'),"
                 " ('sw2','192.0.2.2','Plaintext-Key-0002-abcdef','gi1/0/4,gi1/0/5,gi1/0/8')")
    q(superconn, "UPDATE ui.radius_client SET is_switch = true")
    st = _fixture_status("snmp_c1300_48p.txt")
    monkeypatch.setattr(snmp_poller, "poll_switch", lambda session, host: dict(st))
    conn = db.connect(APP_DSN)
    try:
        n, ok, upd = snmp_poller.run_cycle(conn, app.config["RA_DATA_KEY"], snmp_poller.load_profile(conn))
    finally:
        conn.close()
    assert (n, ok, upd) == (2, 2, 1)   # sw2 already matches (different formatting) -> untouched
    got = dict(q(superconn, "SELECT name, dot1x_ports FROM ui.radius_client"))
    assert got == {"sw9": "gi1/0/4-5,gi1/0/8", "sw2": "gi1/0/4,gi1/0/5,gi1/0/8"}
    a = q(superconn, "SELECT actor, detail FROM ui.audit_log WHERE action='client.dot1x_ports_auto'")
    assert len(a) == 1 and a[0][0] == "system:snmp-poller" and a[0][1]["to"] == "gi1/0/4-5,gi1/0/8"


def test_test_request_executed(app, superconn, snmpd):
    from radius_admin import snmp_poller, db
    _set_profile(superconn, app)
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw-live','127.0.0.1','Plaintext-Key-0001-abcdef')")
    q(superconn, "INSERT INTO ui.snmp_test (client_id, requested_by) VALUES (1, 'tester')")
    conn = db.connect(APP_DSN)
    try:
        assert snmp_poller.run_tests(conn, app.config["RA_DATA_KEY"], snmp_poller.load_profile(conn)) == 1
    finally:
        conn.close()
    ok, msg = q(superconn, "SELECT ok, message FROM ui.snmp_test")[0]
    assert ok is True and "test-switch-01" in msg


# ------------------------------------------------------------- UI
def test_settings_page_admin_stepup_and_secrets_write_only(app, browser, superconn, logged_in):
    logged_in("admin")
    r = browser.post("/switch-monitoring/", {"enabled": "1", "username": "radmon", "auth_protocol": "SHA-256",
                                             "auth_pass": "AuthPass-Test-1", "priv_pass": "PrivPass-Test-2",
                                             "poll_minutes": "10"})
    assert r.status_code == 302, browser.text(r)[-2000:]
    row = q(superconn, "SELECT enabled, username, poll_minutes, auth_pass_enc, priv_pass_enc FROM ui.snmp_profile")[0]
    assert row[:3] == (True, "radmon", 10)
    assert b"AuthPass-Test-1" not in bytes(row[3]) and b"PrivPass-Test-2" not in bytes(row[4])
    from radius_admin.snmp_poller import decrypt_pass
    assert decrypt_pass(app.config["RA_DATA_KEY"], "auth", row[3]) == "AuthPass-Test-1"
    page = browser.text(browser.get("/switch-monitoring/"))
    assert "AuthPass-Test-1" not in page and "PrivPass-Test-2" not in page and "set</span>" in page
    for (d,) in q(superconn, "SELECT coalesce(detail::text,'') FROM ui.audit_log"):
        assert "AuthPass" not in d and "PrivPass" not in d
    # keep passphrases when fields are left empty
    browser.post("/switch-monitoring/", {"enabled": "1", "username": "radmon", "auth_protocol": "SHA-384",
                                         "poll_minutes": "10"})
    assert q(superconn, "SELECT auth_protocol, auth_pass_enc = %s FROM ui.snmp_profile", (row[3],))[0] == ("SHA-384", True)
    # validation
    r = browser.post("/switch-monitoring/", {"enabled": "1", "username": "bad user", "poll_minutes": "2",
                                             "auth_protocol": "MD5", "priv_pass": "AuthPass-Test-1",
                                             "auth_pass": "AuthPass-Test-1"})
    t = browser.text(r)
    assert r.status_code == 400 and "between 5 and 1440" in t and "SHA-256, SHA-384" in t and "different passphrase" in t


def test_rbac(app, browser, superconn, logged_in, make_user):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw1','192.0.2.1','Plaintext-Key-0001-abcdef')")
    logged_in("operator")
    assert browser.get("/switch-monitoring/").status_code == 403
    r = browser.post("/switch-monitoring/test", {"client_id": "1"}, csrf_page="/clients/")
    assert r.status_code == 302 and q(superconn, "SELECT count(*) FROM ui.snmp_test")[0][0] == 1
    t = browser.text(browser.get(r.headers["Location"]))
    assert "Waiting for the monitoring service" in t and 'http-equiv="refresh"' in t
    from conftest import Browser, login
    v = Browser(app, ip="192.0.2.51")
    login(v, superconn, make_user(username="viewer1", role="viewer"))
    assert v.post("/switch-monitoring/test", {"client_id": "1"}, csrf_page="/clients/").status_code == 403


def test_client_list_shows_status_and_mismatch(app, browser, superconn, logged_in):
    q(superconn, "UPDATE ui.snmp_profile SET enabled=true")
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, dot1x_ports, is_switch) VALUES"
                 " ('sw9','192.0.2.9','Plaintext-Key-0001-abcdef','gi1/0/1-2',true),"
                 " ('sw8','192.0.2.8','Plaintext-Key-0002-abcdef','',true)")
    q(superconn, "INSERT INTO ui.switch_status (client_id, reachable, sys_name, dot1x_supported, dot1x_ports, radius_servers)"
                 " VALUES (1, true, 'SW-ACCESS-09', true, 'gi1/0/4-5,gi1/0/8', '[{\"address\":\"192.0.2.5\",\"bad_authenticators\":4}]'),"
                 " (2, false, '', false, '', '[]')")
    logged_in("viewer")
    t = browser.text(browser.get("/clients/"))
    assert "Differs from switch" in t and "SW-ACCESS-09" in t and "No answer" in t and "Bad authenticators" in t
    assert "Switch reports (SNMP, port-control auto)" in t


def test_switch_flag_form_and_import(app, browser, superconn, logged_in):
    logged_in("admin")
    # import: option marks new clients as switches; is_switch column overrides per row
    from test_client_import import upload, confirm
    text = ("ip,secret,hostname,secret_type,key_scope,dot1x_ports,is_switch\n"
            "192.0.2.30,Plaintext-Key-0001-abcdef,sw-a,plaintext,server,,\n"
            "203.0.113.201,Plaintext-Key-0002-abcdef,wifi-aps,plaintext,,,no\n")
    r = upload(browser, text, is_switch=True)
    assert r.status_code == 200, browser.text(r)[-2000:]
    confirm(browser, r)
    assert dict(q(superconn, "SELECT name, is_switch FROM ui.radius_client")) == {"sw-a": True, "wifi-aps": False}
    # without the option, new clients are not switches
    r = upload(browser, "192.0.2.31,Plaintext-Key-0003-abcdef,sw-b,plaintext\n")
    confirm(browser, r)
    assert q(superconn, "SELECT is_switch FROM ui.radius_client WHERE name='sw-b'")[0][0] is False
    # edit form toggles it
    cid = q(superconn, "SELECT id FROM ui.radius_client WHERE name='sw-b'")[0][0]
    page = browser.text(browser.get("/clients/%d/edit" % cid))
    assert "This is a switch" in page
    form = {"name": "sw-b", "ipaddr": "192.0.2.31", "secret_mode": "keep", "nas_type": "other",
            "require_ma": "auto", "limit_proxy_state": "auto", "enabled": "1", "is_switch": "1", "dot1x_ports": ""}
    assert browser.post("/clients/%d/edit" % cid, form).status_code == 302
    assert q(superconn, "SELECT is_switch FROM ui.radius_client WHERE id=%s", (cid,))[0][0] is True


def test_bulk_monitored_devices(app, browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, is_switch) VALUES"
                 " ('sw1','192.0.2.1','Plaintext-Key-0001-abcdef',false),('ap1','203.0.113.201','Plaintext-Key-0002-abcdef',true)")
    q(superconn, "INSERT INTO ui.switch_status (client_id, reachable) VALUES (2, false)")
    logged_in("admin")
    assert "Monitored devices" in browser.text(browser.get("/switch-monitoring/"))
    r = browser.post("/switch-monitoring/devices", {"switch": "1"}, csrf_page="/switch-monitoring/")
    assert r.status_code == 302
    assert dict(q(superconn, "SELECT name, is_switch FROM ui.radius_client")) == {"sw1": True, "ap1": False}
    assert q(superconn, "SELECT count(*) FROM ui.switch_status")[0][0] == 0   # stale status of ap1 removed
    a = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='snmp.devices'")[0][0]
    assert a == {"switches_added": ["sw1"], "switches_removed": ["ap1"]}
