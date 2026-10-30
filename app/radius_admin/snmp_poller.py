"""radius-admin-snmp: the monitor service (python3 -m radius_admin.snmp_poller).

Runs as OS user radius-admin in its own systemd unit, the only radius-admin
component allowed to send network traffic (UDP to the management subnet). It:
  * polls the RADIUS clients marked as switches over SNMPv3 (when enabled), stores
    the result and per-port 802.1X state in ui.switch_status and, when enabled,
    copies the detected 802.1X ports into ui.radius_client.dot1x_ports (audited);
  * executes "test this switch" requests (ui.snmp_test) and CoA / Disconnect
    requests (ui.coa_request) queued by the web UI;
  * evaluates the alerts once a minute (alerts.py) and writes a heartbeat;
  * removes old queue rows once an hour.
"""
import concurrent.futures
import datetime
import json
import signal
import sys
import time

from . import alerts, audit, coa, db, helper_client
from .config import ConfigError, load_config
from .crypto import DataKey, fips_status
from .ports import same_ports
from .snmp import Session, SnmpError, poll_switch, single_host

ACTOR = "system:snmp-poller"
WORKERS = 8
TICK = 5            # seconds between checks for tests / refresh / CoA requests
ALERT_EVERY = 60    # seconds between alert evaluations
HEARTBEAT_EVERY = 30   # the UI treats the service as stopped after 3 minutes without one
HOUSEKEEP_EVERY = 3600
_stop = False


def aad(field):
    return b"radius-admin/snmp_profile/" + field.encode()


def encrypt_pass(key, field, value):
    return key.encrypt(value.encode("utf-8"), aad(field))


def decrypt_pass(key, field, blob):
    return key.decrypt(bytes(blob), aad(field)).decode("utf-8")


def load_profile(conn):
    return db.query_one("SELECT * FROM ui.snmp_profile WHERE id = 1", conn=conn)


def make_session(profile, key):
    if not profile or not profile["username"] or not profile["auth_pass_enc"] or not profile["priv_pass_enc"]:
        raise SnmpError("SNMPv3 credentials are not set")
    return Session(profile["username"], profile["auth_protocol"],
                   decrypt_pass(key, "auth", profile["auth_pass_enc"]),
                   profile["priv_protocol"], decrypt_pass(key, "priv", profile["priv_pass_enc"]))


def _save_status(conn, client_id, st=None, error=""):
    if st is None:
        db.execute("INSERT INTO ui.switch_status (client_id, polled_at, reachable, error, fail_count)"
                   " VALUES (%s, now(), false, %s, 1)"
                   " ON CONFLICT (client_id) DO UPDATE SET polled_at = now(), reachable = false,"
                   " error = EXCLUDED.error, fail_count = ui.switch_status.fail_count + 1",
                   (client_id, error[:300]), conn=conn)
        return
    db.execute(
        "INSERT INTO ui.switch_status (client_id, polled_at, reachable, error, sys_name, sys_descr, uptime_seconds,"
        " dot1x_supported, dot1x_ports, dot1x_port_count, radius_servers, ports, fail_count, last_ok_at)"
        " VALUES (%s, now(), true, '', %s, %s, %s, %s, %s, %s, %s, %s, 0, now())"
        " ON CONFLICT (client_id) DO UPDATE SET polled_at = now(), reachable = true, error = '',"
        " sys_name = EXCLUDED.sys_name, sys_descr = EXCLUDED.sys_descr, uptime_seconds = EXCLUDED.uptime_seconds,"
        " dot1x_supported = EXCLUDED.dot1x_supported, dot1x_ports = EXCLUDED.dot1x_ports,"
        " dot1x_port_count = EXCLUDED.dot1x_port_count, radius_servers = EXCLUDED.radius_servers,"
        " ports = EXCLUDED.ports, fail_count = 0, last_ok_at = now()",
        (client_id, st["sys_name"], st["sys_descr"], st["uptime_seconds"], st["dot1x_supported"],
         st["dot1x_ports"], st["dot1x_port_count"], json.dumps(st["radius_servers"]),
         json.dumps(st.get("ports", []))), conn=conn)


def poll_one(session, client):
    host = single_host(client["ipaddr"])
    if host is None:
        return client, None, "not a single address (network entries are not polled)"
    try:
        return client, poll_switch(session, host), ""
    except SnmpError as e:
        return client, None, str(e)


def run_cycle(conn, key, profile):
    """Poll every client once. Returns (polled, reachable, ports_updated)."""
    clients = db.query("SELECT id, name, ipaddr, dot1x_ports FROM ui.radius_client WHERE is_switch ORDER BY id", conn=conn)
    session = make_session(profile, key)
    reachable = updated = 0
    with session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(lambda c: poll_one(session, c), clients))
    for client, st, err in results:
        _save_status(conn, client["id"], st, err)
        if st is None:
            continue
        reachable += 1
        if (profile["auto_update_ports"] and st["dot1x_supported"]
                and not same_ports(client["dot1x_ports"] or "", st["dot1x_ports"])):
            db.execute("UPDATE ui.radius_client SET dot1x_ports = %s, updated_at = now() WHERE id = %s",
                       (st["dot1x_ports"], client["id"]), conn=conn)
            audit.write("client.dot1x_ports_auto", actor=ACTOR, object_type="radius_client",
                        object_id=client["id"], detail={"name": client["name"],
                                                        "from": client["dot1x_ports"] or "",
                                                        "to": st["dot1x_ports"]}, conn=conn)
            updated += 1
    conn.commit()
    return len(clients), reachable, updated


def run_tests(conn, key, profile):
    pending = db.query("SELECT t.id, t.client_id, c.name, c.ipaddr, c.dot1x_ports FROM ui.snmp_test t"
                       " JOIN ui.radius_client c ON c.id = t.client_id"
                       " WHERE t.done_at IS NULL ORDER BY t.id LIMIT 10", conn=conn)
    if not pending:
        return 0
    try:
        session = make_session(profile, key)
    except (SnmpError, ValueError) as e:
        for t in pending:
            db.execute("UPDATE ui.snmp_test SET done_at = now(), ok = false, message = %s WHERE id = %s",
                       (str(e)[:300], t["id"]), conn=conn)
        conn.commit()
        return len(pending)
    with session:
        for t in pending:
            client = {"id": t["client_id"], "name": t["name"], "ipaddr": t["ipaddr"]}
            _, st, err = poll_one(session, client)
            if st is not None:
                _save_status(conn, t["client_id"], st)
                msg = "%s answered: %s; 802.1X ports (auto): %s; %d RADIUS server(s)." % (
                    t["ipaddr"], st["sys_name"] or "(no name)", st["dot1x_ports"] or "none",
                    len(st["radius_servers"]))
            else:
                _save_status(conn, t["client_id"], None, err)
                msg = err
            db.execute("UPDATE ui.snmp_test SET done_at = now(), ok = %s, message = %s WHERE id = %s",
                       (st is not None, msg[:500], t["id"]), conn=conn)
            conn.commit()
    return len(pending)


# ---------------------------------------------------------------- CoA / Disconnect
def coa_tool(cfg):
    """(radclient, dict_dir, None) or (None, None, reason)."""
    try:
        rc = coa.find_radclient(cfg.get("radclient", ""))
        return rc, coa.find_dict_dir(rc, cfg.get("radius_dict_dir", "")), None
    except coa.CoaError as e:
        return None, None, str(e)


def run_coa(conn, cfg, profile):
    pending = db.query("SELECT r.*, host(r.nas_ip) AS nas, c.name, c.ipaddr, c.secret, c.enabled, c.key_status"
                       " FROM ui.coa_request r JOIN ui.radius_client c ON c.id = r.client_id"
                       " WHERE r.done_at IS NULL ORDER BY r.id LIMIT 10", conn=conn)
    if not pending:
        return 0
    rc, dd, why = coa_tool(cfg)
    port = int((profile or {}).get("coa_port") or 1700)
    for r in pending:
        ok, msg = False, ""
        if why:
            msg = "Cannot send: %s" % why
        elif not r["enabled"] or r.get("key_status", "ok") != "ok":
            msg = "%s is disabled or has no usable shared key in this console." % r["name"]
        else:
            host = single_host(r["ipaddr"]) or r["nas"]
            try:
                req = coa.build_request(r["action"], r["nas"], r["acct_session_id"], r["calling_station_id"],
                                        r["nas_port_id"])
                ok, msg = coa.send(r["action"], host, port, r["secret"], req, rc, dd)
            except coa.CoaError as e:
                msg = "Not sent: %s" % e
        db.execute("UPDATE ui.coa_request SET done_at = now(), ok = %s, message = %s WHERE id = %s",
                   (ok, msg[:500], r["id"]), conn=conn)
        audit.write("coa.result", actor=ACTOR, success=ok, object_type="radius_client", object_id=r["client_id"],
                    detail={"request_id": r["id"], "action": r["action"], "switch": r["name"], "message": msg[:200]},
                    conn=conn)
        conn.commit()
    return len(pending)


# ---------------------------------------------------------------- alerts / heartbeat
def smtp_password(key, settings):
    if not settings or not settings.get("smtp_pass_enc"):
        return None
    try:
        return key.decrypt(bytes(settings["smtp_pass_enc"]), b"radius-admin/alert_settings/smtp").decode("utf-8")
    except Exception:
        return None


def helper_status(cfg):
    try:
        return helper_client.call(cfg["helper_socket"], "status", timeout=30)
    except helper_client.HelperError as e:
        return {"ok": False, "message": str(e)}


def run_alerts(conn, cfg, key, profile, radius_state):
    settings = alerts.load_settings(conn)
    if settings is None:
        return
    pw = smtp_password(key, settings)
    alerts.check_radius(conn, settings, helper_status(cfg), radius_state, pw)
    conn.commit()
    alerts.check_rejects(conn, settings, pw)
    conn.commit()
    alerts.check_switches(conn, settings, bool(profile and profile["enabled"]), pw)
    conn.commit()


def run_alert_test(conn, key, last_seen):
    settings = alerts.load_settings(conn)
    req = settings and settings["test_requested_at"]
    if req is None or req == last_seen:
        return last_seen
    alerts.send_test(conn, settings, settings["test_requested_by"], smtp_password(key, settings))
    conn.commit()
    return req


def heartbeat(conn, radclient_note):
    db.execute("UPDATE ui.monitor_state SET heartbeat_at = now(), radclient = %s WHERE id = 1",
               (radclient_note[:300],), conn=conn)
    conn.commit()


def housekeeping(conn):
    db.execute("DELETE FROM mab_pending WHERE last_seen < now() - interval '30 days'", conn=conn)
    db.execute("DELETE FROM ui.coa_request WHERE requested_at < now() - interval '90 days'", conn=conn)
    db.execute("DELETE FROM ui.snmp_test WHERE requested_at < now() - interval '7 days'", conn=conn)
    db.execute("DELETE FROM ui.alert WHERE state = 'resolved' AND resolved_at < now() - interval '400 days'",
               conn=conn)
    conn.commit()


def loop(cfg, once=False):
    key = DataKey.from_file(cfg["key_file"])
    conn = db.connect(cfg["db_dsn"])
    last_cycle = 0.0
    last_alerts = last_housekeep = last_beat = -1e9
    last_refresh_seen = None
    last_test_seen = None
    radius_state = {}
    rc, _, why = coa_tool(cfg)
    radclient_note = rc or ("unavailable: " + why)
    while not _stop:
        try:
            profile = load_profile(conn)
            conn.commit()
            now = time.monotonic()
            if now - last_beat >= HEARTBEAT_EVERY:
                heartbeat(conn, radclient_note)
                last_beat = now
            run_coa(conn, cfg, profile)
            if profile:
                run_tests(conn, key, profile)
            if profile and profile["enabled"]:
                due = now - last_cycle >= profile["poll_minutes"] * 60
                req = profile["refresh_requested_at"]
                if req is not None and req != last_refresh_seen:
                    due, last_refresh_seen = True, req
                if due or once:
                    started = time.monotonic()
                    n, ok, upd = run_cycle(conn, key, profile)
                    last_cycle = started
                    audit.log_syslog("snmp poll: %d clients, %d reachable, %d port lists updated" % (n, ok, upd))
                    last_alerts = -1e9      # evaluate switch alerts right after a poll
            last_test_seen = run_alert_test(conn, key, last_test_seen)
            if now - last_alerts >= ALERT_EVERY or once:
                run_alerts(conn, cfg, key, profile, radius_state)
                last_alerts = now
            if now - last_housekeep >= HOUSEKEEP_EVERY:
                housekeeping(conn)
                last_housekeep = now
        except (SnmpError, ValueError) as e:
            conn.rollback()
            audit.log_syslog("snmp poll error: %s" % e)
        except Exception as e:  # keep the service alive; DB errors reconnect
            audit.log_syslog("monitor error: %s: %s" % (type(e).__name__, e))
            try:
                conn.close()
            except Exception:
                pass
            time.sleep(TICK)
            try:
                conn = db.connect(cfg["db_dsn"])
            except Exception as e2:
                audit.log_syslog("monitor: database unavailable: %s" % e2)
                time.sleep(TICK)
                continue
        if once:
            break
        time.sleep(TICK)
    conn.close()


def _sigterm(*_):
    global _stop
    _stop = True


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        cfg = load_config()
    except ConfigError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    audit.configure_syslog(cfg["log_syslog"])
    if cfg["require_fips"] and not fips_status()["ok"]:
        print("error: FIPS mode required but not active", file=sys.stderr)
        return 3
    signal.signal(signal.SIGTERM, _sigterm)
    loop(cfg, once="--once" in argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
