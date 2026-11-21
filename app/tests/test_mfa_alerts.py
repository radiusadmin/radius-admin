"""Second-factor alerts (SPEC section 29.4): mfa_provider_down, mfa_timeouts, mfa_unverified,
mfa_withdrawn; raised by the monitor service from radpostauth and the helper's
integration_status / integration_catalog."""
import json
import os

import pytest

from conftest import APP_DSN, stepup

HERE = os.path.dirname(os.path.abspath(__file__))
DIGEST = "a" * 64
UP = {"ok": True, "fips_enabled": False, "integrations": {"duo": {
    "label": "Duo Authentication Proxy", "service_active": True, "listening": True, "state": {},
    "installed": {"version": "6.8.1", "sha256": DIGEST, "verified": "catalog", "installed": "2026-11-20T10:00:00Z"}}}}


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def integ(**duo):
    out = json.loads(json.dumps(UP))
    out["integrations"]["duo"].update(duo)
    return out


def installed(**kw):
    inst = dict(UP["integrations"]["duo"]["installed"])
    inst.update(kw)
    return integ(installed=inst)


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


def duo_provider(superconn, enabled=True, applied=True):
    q(superconn, "INSERT INTO ui.mfa_provider (id, type, label, enabled) VALUES ('duo', 'duo', 'Duo', %s)", (enabled,))
    if applied:
        q(superconn, "INSERT INTO ui.apply_log (actor, action, policy_sha256, clients_sha256, providers_sha256, success)"
                     " VALUES ('admin1', 'apply', %s, %s, %s, true)", ("1" * 64, "2" * 64, "3" * 64))


def alerts_of(superconn, kind=None):
    sql = "SELECT kind, subject, state, message FROM ui.alert"
    return q(superconn, sql + (" WHERE kind = %s" if kind else "") + " ORDER BY id", (kind,) if kind else ())


def test_reason_matches_the_policy():
    """The timeout alert counts the reason radius_admin_reject writes; keep the two equal."""
    from radius_admin import alerts
    with open(os.path.join(HERE, "..", "radius_admin", "unlang.py"), encoding="utf-8") as fh:
        assert '_MFA_NO_ANSWER = "%s"' % alerts.MFA_NO_ANSWER in fh.read()
    for kind in alerts.MFA_KINDS:
        assert kind in alerts.LABELS


def test_provider_down_only_for_an_applied_duo(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    s = alerts.load_settings(mon_conn)
    assert s["mfa_enabled"] is True and s["mfa_timeout_enabled"] is True        # on by default
    state = {}
    down = integ(service_active=False, listening=False)
    for _ in range(3):                                      # no Duo provider at all
        alerts.check_mfa_provider(mon_conn, s, down, state)
    duo_provider(superconn, enabled=True, applied=False)
    for _ in range(3):                                      # turned on but never applied: the apply page says so
        alerts.check_mfa_provider(mon_conn, s, down, state)
    mon_conn.commit()
    assert alerts_of(superconn) == []
    q(superconn, "UPDATE ui.mfa_provider SET enabled = false")
    q(superconn, "INSERT INTO ui.apply_log (actor, action, policy_sha256, clients_sha256, providers_sha256, success)"
                 " VALUES ('admin1', 'apply', 'p', 'c', 'x', true)")
    for _ in range(3):                                      # applied but off
        alerts.check_mfa_provider(mon_conn, s, down, state)
    mon_conn.commit()
    assert alerts_of(superconn) == []


def test_provider_down_needs_two_checks_and_resolves(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    duo_provider(superconn)
    s = alerts.load_settings(mon_conn)
    state = {}
    alerts.check_mfa_provider(mon_conn, s, integ(service_active=False, listening=False), state)
    mon_conn.commit()
    assert alerts_of(superconn) == []                       # one check: Apply restarting the proxy
    alerts.check_mfa_provider(mon_conn, s, integ(listening=False), state)
    mon_conn.commit()
    rows = alerts_of(superconn)
    assert [r[:3] for r in rows] == [("mfa_provider_down", "duo", "open")]
    assert "does not listen on 127.0.0.1:18120" in rows[0][3] and "break-glass" in rows[0][3]
    # a helper error neither resolves nor opens a second one
    for _ in range(3):
        alerts.check_mfa_provider(mon_conn, s, {"ok": False, "message": "unknown action"}, state)
    alerts.check_mfa_provider(mon_conn, s, integ(service_active=False, listening=False), state)
    mon_conn.commit()
    rows = alerts_of(superconn)
    assert len(rows) == 1 and rows[0][2] == "open" and "is not active" in rows[0][3]
    alerts.check_mfa_provider(mon_conn, s, UP, state)
    mon_conn.commit()
    assert alerts_of(superconn)[0][2] == "resolved"
    assert any("ALERT OPEN mfa_provider_down [duo]" in ln for ln in syslog_lines)
    assert any("ALERT RESOLVED mfa_provider_down [duo]" in ln for ln in syslog_lines)
    # not installed any more (removed outside the portal) while still on
    for _ in range(2):
        alerts.check_mfa_provider(mon_conn, s, integ(installed={}, service_active=False, listening=False), state)
    mon_conn.commit()
    assert "turned on but not installed" in alerts_of(superconn)[-1][3]
    # switched off: resolves and stays quiet
    q(superconn, "UPDATE ui.alert_settings SET mfa_enabled = false")
    s = alerts.load_settings(mon_conn)
    for _ in range(3):
        alerts.check_mfa_provider(mon_conn, s, integ(service_active=False), state)
    mon_conn.commit()
    assert [r[2] for r in alerts_of(superconn)] == ["resolved", "resolved"]


def _reject(superconn, n, reason, nas="192.0.2.10", user="netadmin", age="0 minutes"):
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, reason, authdate)"
                 " SELECT %s || g, 'Access-Reject', 'pap-admin+mfa', %s, %s, now() - %s::interval"
                 " FROM generate_series(1, %s) g", (user, nas, reason, age, n))


def test_timeouts_over_a_window(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    s = alerts.load_settings(mon_conn)
    assert (s["mfa_timeout_threshold"], s["mfa_timeout_window_minutes"]) == (3, 15)
    _reject(superconn, 2, alerts.MFA_NO_ANSWER)
    _reject(superconn, 5, "radius-admin: refused in the second-factor chain (wrong password, not a device admin,"
                          " or the second factor was denied)")         # denied pushes are not timeouts
    _reject(superconn, 4, alerts.MFA_NO_ANSWER, age="20 minutes")      # outside the window
    alerts.check_mfa_timeouts(mon_conn, s)
    mon_conn.commit()
    assert alerts_of(superconn) == []
    _reject(superconn, 1, alerts.MFA_NO_ANSWER, nas="192.0.2.11", user="other")
    alerts.check_mfa_timeouts(mon_conn, s)
    alerts.check_mfa_timeouts(mon_conn, s)                  # still high: one alert, one notification
    mon_conn.commit()
    rows = alerts_of(superconn)
    assert [r[:3] for r in rows] == [("mfa_timeouts", "", "open")]
    assert rows[0][3].startswith("3 device admin logins (3 accounts) got no answer") and "192.0.2.10 x2" in rows[0][3]
    assert len([ln for ln in syslog_lines if "ALERT OPEN mfa_timeouts" in ln]) == 1
    q(superconn, "UPDATE radpostauth SET authdate = now() - interval '1 hour'")
    alerts.check_mfa_timeouts(mon_conn, s)
    mon_conn.commit()
    assert alerts_of(superconn)[0][2] == "resolved"
    # its own switch
    q(superconn, "UPDATE ui.alert_settings SET mfa_timeout_enabled = false, mfa_enabled = true")
    _reject(superconn, 10, alerts.MFA_NO_ANSWER)
    alerts.check_mfa_timeouts(mon_conn, alerts.load_settings(mon_conn))
    mon_conn.commit()
    assert len(alerts_of(superconn)) == 1


CATALOG = {"ok": True, "serial": 4, "entries": [
    {"provider": "duo", "version": "6.8.1", "sha256": DIGEST, "fips": False, "withdrawn": False},
    {"provider": "duo", "version": "6.7.0", "sha256": "c" * 64, "fips": False, "withdrawn": True}]}


def test_unverified_build_reported_daily(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    s = alerts.load_settings(mon_conn)
    pasted = installed(version="6.9.0", sha256="d" * 64, verified="pasted-hash")
    duo_provider(superconn, enabled=False)
    alerts.check_mfa_builds(mon_conn, s, pasted, CATALOG)   # installed but not in use
    mon_conn.commit()
    assert alerts_of(superconn) == []
    q(superconn, "UPDATE ui.mfa_provider SET enabled = true")
    alerts.check_mfa_builds(mon_conn, s, pasted, CATALOG)
    alerts.check_mfa_builds(mon_conn, s, pasted, CATALOG)
    mon_conn.commit()
    rows = alerts_of(superconn)
    assert [r[:3] for r in rows] == [("mfa_unverified", "duo", "open")] and "6.9.0" in rows[0][3]
    assert len([ln for ln in syslog_lines if "ALERT OPEN mfa_unverified" in ln]) == 1
    # a day later it is sent again, once
    q(superconn, "UPDATE ui.alert SET opened_at = now() - interval '25 hours'")
    for _ in range(3):
        alerts.check_mfa_builds(mon_conn, s, pasted, CATALOG)
    mon_conn.commit()
    sent = [ln for ln in syslog_lines if "ALERT OPEN mfa_unverified" in ln]
    assert len(sent) == 2 and "Still open: " in sent[1]
    assert q(superconn, "SELECT reminded_at IS NOT NULL FROM ui.alert")[0][0] is True
    # a helper or catalog error changes nothing
    alerts.check_mfa_builds(mon_conn, s, {"ok": False}, CATALOG)
    alerts.check_mfa_builds(mon_conn, s, pasted, {"ok": False})
    mon_conn.commit()
    assert alerts_of(superconn)[0][2] == "open"
    # a later catalog lists the hash: verified without a reinstall
    listed = dict(CATALOG, serial=5, entries=CATALOG["entries"] + [
        {"provider": "duo", "version": "6.9.0", "sha256": "d" * 64, "fips": False, "withdrawn": False}])
    alerts.check_mfa_builds(mon_conn, s, pasted, listed)
    mon_conn.commit()
    rows = alerts_of(superconn)
    assert rows[0][2] == "resolved"
    assert any("ALERT RESOLVED mfa_unverified [duo]: The signed catalog now lists" in ln for ln in syslog_lines)
    # a catalog-verified build never alerts
    alerts.check_mfa_builds(mon_conn, s, UP, CATALOG)
    mon_conn.commit()
    assert len(alerts_of(superconn)) == 1


def test_withdrawn_build(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    s = alerts.load_settings(mon_conn)
    old = installed(version="6.7.0", sha256="c" * 64)
    alerts.check_mfa_builds(mon_conn, s, old, CATALOG)      # installed, even without a provider row
    mon_conn.commit()
    rows = alerts_of(superconn)
    assert [r[:3] for r in rows] == [("mfa_withdrawn", "duo", "open")]
    assert "6.7.0" in rows[0][3] and "serial 4" in rows[0][3]
    # matched by version too (a pasted-hash install of a build the catalog later withdrew)
    other = installed(version="6.7.0", sha256="e" * 64, verified="pasted-hash")
    alerts.check_mfa_builds(mon_conn, s, other, CATALOG)
    mon_conn.commit()
    assert len(alerts_of(superconn)) == 1
    q(superconn, "UPDATE ui.alert SET opened_at = now() - interval '2 days'")
    alerts.check_mfa_builds(mon_conn, s, old, CATALOG)
    mon_conn.commit()
    assert len([ln for ln in syslog_lines if "ALERT OPEN mfa_withdrawn" in ln]) == 2
    alerts.check_mfa_builds(mon_conn, s, UP, CATALOG)       # upgraded to a current build
    mon_conn.commit()
    assert alerts_of(superconn)[0][2] == "resolved"
    alerts.check_mfa_builds(mon_conn, s, old, CATALOG)
    q(superconn, "UPDATE ui.alert_settings SET mfa_enabled = false")
    alerts.check_mfa_builds(mon_conn, alerts.load_settings(mon_conn), old, CATALOG)
    mon_conn.commit()
    assert [r[2] for r in alerts_of(superconn)] == ["resolved", "resolved"]


def test_monitor_asks_the_helper(app, superconn, mon_conn, monkeypatch, syslog_lines):
    """run_alerts: integration_status every round, the catalog at most once an hour and only
    with Duo installed; an older helper without these actions raises nothing."""
    from radius_admin import helper_client, snmp_poller
    calls = []
    answers = {"status": {"ok": True, "service_active": True, "listening": True},
               "integration_status": installed(version="6.7.0", sha256="c" * 64), "integration_catalog": CATALOG}

    def fake(sock, action, timeout=120, **params):
        calls.append(action)
        return answers[action]
    monkeypatch.setattr(helper_client, "call", fake)
    cfg = {"helper_socket": "/nonexistent"}
    mfa_state = {}
    for _ in range(3):
        snmp_poller.run_alerts(mon_conn, cfg, app.config["RA_DATA_KEY"], None, {}, {}, mfa_state)
    assert calls.count("integration_status") == 3 and calls.count("integration_catalog") == 1
    assert [r[:3] for r in alerts_of(superconn)] == [("mfa_withdrawn", "duo", "open")]
    # not installed: no catalog read at all
    calls.clear()
    answers["integration_status"] = integ(installed={}, service_active=False, listening=False)
    snmp_poller.run_alerts(mon_conn, cfg, app.config["RA_DATA_KEY"], None, {}, {}, {})
    assert "integration_catalog" not in calls and alerts_of(superconn)[0][2] == "resolved"

    def old_helper(sock, action, timeout=120, **params):
        if action.startswith("integration_"):
            return {"ok": False, "message": "unknown action"}
        return answers[action]
    monkeypatch.setattr(helper_client, "call", old_helper)
    duo_provider(superconn)
    for _ in range(3):
        snmp_poller.run_alerts(mon_conn, cfg, app.config["RA_DATA_KEY"], None, {}, {}, {})
    assert len(alerts_of(superconn)) == 1


def test_settings_page(app, browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    body = browser.text(browser.get("/alerts/settings"))
    assert "Second factor for device admins" in body and 'name="mfa_timeout_threshold" value="3"' in body
    assert "FIPS" not in body
    base = {"syslog_enabled": "1", "reject_enabled": "1", "reject_threshold": "25", "reject_window_minutes": "5",
            "switch_enabled": "1", "switch_failed_polls": "2", "radius_enabled": "1", "portal_enabled": "1",
            "smtp_port": "25", "smtp_security": "starttls"}
    r = browser.post("/alerts/settings", dict(base, mfa_enabled="1", mfa_timeout_enabled="1",
                                              mfa_timeout_threshold="0", mfa_timeout_window_minutes="15"),
                     csrf_page="/alerts/settings")
    assert r.status_code == 400 and "from 1 to 100000" in browser.text(r)
    r = browser.post("/alerts/settings", dict(base, mfa_timeout_enabled="1", mfa_timeout_threshold="5",
                                              mfa_timeout_window_minutes="30"), csrf_page="/alerts/settings")
    assert r.status_code == 302
    assert q(superconn, "SELECT mfa_enabled, mfa_timeout_enabled, mfa_timeout_threshold, mfa_timeout_window_minutes"
                        " FROM ui.alert_settings")[0] == (False, True, 5, 30)
    changed = q(superconn, "SELECT detail FROM ui.audit_log WHERE action = 'alert.settings'")[0][0]["changed"]
    assert changed == {"mfa_enabled": False, "mfa_timeout_threshold": 5, "mfa_timeout_window_minutes": 30}
    # a form without the new numbers (an older page still open) keeps them
    r = browser.post("/alerts/settings", dict(base, mfa_enabled="1"), csrf_page="/alerts/settings")
    assert r.status_code == 302
    assert q(superconn, "SELECT mfa_enabled, mfa_timeout_threshold FROM ui.alert_settings")[0] == (True, 5)
    t = browser.text(browser.get("/alerts/"))
    assert "Second-factor provider" in t and "Second factor not answering</dt><dd><span class=\"muted\">Off" in t


def test_alert_list_labels(app, browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.alert (kind, subject, state, message) VALUES"
                 " ('mfa_provider_down', 'duo', 'open', 'duoauthproxy.service is not active.'),"
                 " ('mfa_unverified', 'duo', 'open', 'Duo Authentication Proxy 6.9.0 is in use but unverified.')")
    logged_in("viewer")
    t = browser.text(browser.get("/alerts/"))
    assert "Second-factor provider down" in t and "Unverified second-factor build" in t
    d = browser.text(browser.get("/dashboard"))
    assert "2 open alerts" in d and "Second-factor provider down" in d


def test_fips_mode_build_not_fips_capable(app, superconn, mon_conn, syslog_lines):
    from radius_admin import alerts
    s = alerts.load_settings(mon_conn)
    duo_provider(superconn)
    std = installed(fips=False)
    alerts.check_mfa_builds(mon_conn, s, std, CATALOG)                 # standard mode: catalog-checked, fine
    mon_conn.commit()
    assert alerts_of(superconn) == []
    fips = dict(std, fips_enabled=True)
    alerts.check_mfa_builds(mon_conn, s, fips, CATALOG)
    mon_conn.commit()
    rows = alerts_of(superconn)
    assert [r[:3] for r in rows] == [("mfa_unverified", "duo", "open")] and rows[0][3].startswith("FIPS mode: ")
    ok_cat = dict(CATALOG, entries=[dict(CATALOG["entries"][0], fips=True)] + CATALOG["entries"][1:])
    inst = installed(fips=True)
    alerts.check_mfa_builds(mon_conn, s, dict(inst, fips_enabled=True), ok_cat)
    mon_conn.commit()
    assert alerts_of(superconn)[0][2] == "resolved"
