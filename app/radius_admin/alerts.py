"""Alerts (SPEC section 13): reject spikes, switches that stop answering SNMP, and
FreeRADIUS down. Evaluated by the monitor service once a minute; each condition opens
one ui.alert row (one open row per kind+subject) and notifies once when it opens and
once when it resolves.

Notification channels:
  syslog  always available: tag radius-admin, facility authpriv, priority warning
          (crit for FreeRADIUS down, notice when resolved). Forward with rsyslog to a SIEM.
  email   SMTP relay; off by default. The monitor unit may only reach the management
          subnet, so a relay elsewhere needs an IPAddressAllow drop-in (RUNBOOK 6.5).
"""
import email.message
import email.utils
import json
import smtplib
import socket
import ssl
import syslog

from . import audit, db

ACTOR = "system:monitor"
LABELS = {"reject_spike": "Reject spike", "switch_down": "Switch not responding",
          "radius_down": "FreeRADIUS down", "monitor_down": "Monitoring stopped", "test": "Test alert"}


def load_settings(conn):
    return db.query_one("SELECT * FROM ui.alert_settings WHERE id = 1", conn=conn)


# ---------------------------------------------------------------- notifications
def _syslog(kind, state, subject, message):
    pri = syslog.LOG_NOTICE if state == "resolved" else (syslog.LOG_CRIT if kind == "radius_down"
                                                           else syslog.LOG_WARNING)
    audit.log_syslog("ALERT %s %s%s: %s" % (state.upper(), kind, (" [%s]" % subject) if subject else "", message),
                     priority=pri)


def send_email(settings, subject, body, password=None, timeout=15):
    """Raises on failure. TLS certificates are verified against the system trust store."""
    to = [a.strip() for a in (settings["mail_to"] or "").replace(";", ",").split(",") if a.strip()]
    if not settings["smtp_host"] or not settings["mail_from"] or not to:
        raise ValueError("email is not fully configured (relay, from and to are required)")
    msg = email.message.EmailMessage()
    msg["From"] = settings["mail_from"]
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(usegmt=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=socket.getfqdn() or "radius-admin")
    msg.set_content(body)
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    host, port, sec = settings["smtp_host"], int(settings["smtp_port"]), settings["smtp_security"]
    if sec == "tls":
        s = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
    else:
        s = smtplib.SMTP(host, port, timeout=timeout)
    try:
        s.ehlo()
        if sec == "starttls":
            s.starttls(context=ctx)
            s.ehlo()
        if settings["smtp_user"]:
            if sec == "none":
                raise ValueError("refusing to send the SMTP password without TLS")
            s.login(settings["smtp_user"], password or "")
        s.send_message(msg)
    finally:
        try:
            s.quit()
        except Exception:
            pass


def notify(conn, settings, alert_id, kind, state, subject, message, smtp_password=None):
    channels = []
    if settings is None or settings["syslog_enabled"]:
        _syslog(kind, state, subject, message)
        channels.append("syslog")
    if settings is not None and settings["email_enabled"]:
        try:
            send_email(settings, "[radius-admin] %s %s%s" % (
                LABELS.get(kind, kind), "resolved" if state == "resolved" else "",
                (": " + subject) if subject else ""),
                "%s\n\nState: %s\nKind: %s\n\n-- radius-admin monitor on %s\n" % (
                    message, state, kind, socket.getfqdn()), password=smtp_password)
            channels.append("email")
        except Exception as e:  # never let a mail problem stop monitoring
            channels.append("email failed: %s" % str(e)[:150])
            audit.log_syslog("alert email failed: %s" % e, priority=syslog.LOG_ERR)
    if alert_id is not None:
        db.execute("UPDATE ui.alert SET notified = left(%s, 500) WHERE id = %s", ("; ".join(channels), alert_id),
                   conn=conn)
    return channels


# ---------------------------------------------------------------- state changes
def open_alert(conn, settings, kind, subject, message, detail=None, smtp_password=None):
    """Open (once) an alert. Returns the new id, or None when one is already open."""
    row = db.query_one("INSERT INTO ui.alert (kind, subject, state, message, detail) VALUES (%s,%s,'open',%s,%s)"
                       " ON CONFLICT (kind, subject) WHERE state = 'open' DO NOTHING RETURNING id",
                       (kind, subject or "", message[:1000], json.dumps(detail or {})), conn=conn)
    if row is None:
        db.execute("UPDATE ui.alert SET message = %s, detail = %s WHERE kind = %s AND subject = %s AND state = 'open'",
                   (message[:1000], json.dumps(detail or {}), kind, subject or ""), conn=conn)
        return None
    audit.write("alert.open", actor=ACTOR, object_type="alert", object_id=row["id"],
                detail={"kind": kind, "subject": subject, "message": message[:300]}, conn=conn)
    notify(conn, settings, row["id"], kind, "open", subject, message, smtp_password)
    return row["id"]


def resolve_alert(conn, settings, kind, subject, message, smtp_password=None):
    row = db.query_one("UPDATE ui.alert SET state = 'resolved', resolved_at = now() WHERE kind = %s AND subject = %s"
                       " AND state = 'open' RETURNING id, message", (kind, subject or ""), conn=conn)
    if row is None:
        return None
    audit.write("alert.resolve", actor=ACTOR, object_type="alert", object_id=row["id"],
                detail={"kind": kind, "subject": subject}, conn=conn)
    notify(conn, settings, None, kind, "resolved", subject, message, smtp_password)
    return row["id"]


# ---------------------------------------------------------------- checks
def check_rejects(conn, settings, smtp_password=None):
    if not settings["reject_enabled"]:
        resolve_alert(conn, settings, "reject_spike", "", "Reject spike alerting was switched off.", smtp_password)
        return
    win = int(settings["reject_window_minutes"])
    thr = int(settings["reject_threshold"])
    n = db.query_one("SELECT count(*) AS n FROM radpostauth WHERE reply = 'Access-Reject'"
                     " AND authdate > now() - make_interval(mins => %s)", (win,), conn=conn)["n"]
    if n >= thr:
        top = db.query("SELECT coalesce(host(nasipaddress), '?') AS nas, coalesce(authmethod, 'other') AS m,"
                       " count(*) AS n FROM radpostauth WHERE reply = 'Access-Reject'"
                       " AND authdate > now() - make_interval(mins => %s) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 3",
                       (win,), conn=conn)
        reasons = db.query("SELECT coalesce(nullif(reason, ''), '(no reason)') AS r, count(*) AS n FROM radpostauth"
                           " WHERE reply = 'Access-Reject' AND authdate > now() - make_interval(mins => %s)"
                           " GROUP BY 1 ORDER BY 2 DESC LIMIT 3", (win,), conn=conn)
        where = ", ".join("%s %s x%d" % (t["nas"], t["m"], t["n"]) for t in top)
        why = "; ".join("%s x%d" % (r["r"].replace("radius-admin: ", ""), r["n"]) for r in reasons)
        open_alert(conn, settings, "reject_spike", "",
                   "%d rejects in the last %d minutes (threshold %d). Top: %s. Reasons: %s." % (n, win, thr, where, why),
                   {"count": n, "window_minutes": win, "threshold": thr}, smtp_password)
    elif n < max(1, thr // 2):      # hysteresis: resolve only well below the threshold
        resolve_alert(conn, settings, "reject_spike", "",
                      "Rejects back to %d in the last %d minutes." % (n, win), smtp_password)


def check_switches(conn, settings, snmp_enabled, smtp_password=None):
    rows = db.query("SELECT c.id, c.name, c.ipaddr, c.is_switch, c.enabled, s.reachable, s.fail_count, s.error,"
                    " s.last_ok_at FROM ui.radius_client c LEFT JOIN ui.switch_status s ON s.client_id = c.id",
                    conn=conn)
    need = int(settings["switch_failed_polls"])
    active = settings["switch_enabled"] and snmp_enabled
    known = set()
    for r in rows:
        subj = str(r["id"])
        known.add(subj)
        if not (active and r["is_switch"] and r["enabled"]):
            resolve_alert(conn, settings, "switch_down", subj,
                          "%s is no longer monitored." % r["name"], smtp_password)
            continue
        if r["reachable"] is False and (r["fail_count"] or 0) >= need:
            since = r["last_ok_at"].strftime("%Y-%m-%d %H:%M UTC") if r["last_ok_at"] else "never answered"
            open_alert(conn, settings, "switch_down", subj,
                       "%s (%s) does not answer SNMP: %s. Last answer: %s." % (r["name"], r["ipaddr"], r["error"], since),
                       {"client_id": r["id"], "name": r["name"], "failed_polls": r["fail_count"]}, smtp_password)
        elif r["reachable"] is True:
            resolve_alert(conn, settings, "switch_down", subj, "%s answers SNMP again." % r["name"], smtp_password)
    for a in db.query("SELECT subject FROM ui.alert WHERE kind = 'switch_down' AND state = 'open'", conn=conn):
        if a["subject"] not in known:
            resolve_alert(conn, settings, "switch_down", a["subject"], "The client was deleted.", smtp_password)


def check_radius(conn, settings, status, state, smtp_password=None):
    """status: helper 'status' response (or {'ok': False, 'message': ...}).
    state: dict kept by the caller across checks ({'down_checks': int})."""
    ok = bool(status.get("ok")) and bool(status.get("service_active")) and status.get("listening", True) is not False
    if ok:
        msg = "FreeRADIUS active%s." % (" and listening" if status.get("listening") else "")
    elif not status.get("ok"):
        msg = "Cannot check FreeRADIUS: %s" % (status.get("message") or "helper error")
    elif not status.get("service_active"):
        msg = "The FreeRADIUS service is not active."
    else:
        msg = "FreeRADIUS is running but not listening on its RADIUS port."
    db.execute("UPDATE ui.monitor_state SET radius_checked_at = now(), radius_ok = %s, radius_message = %s WHERE id = 1",
               (ok, msg[:300]), conn=conn)
    if not settings["radius_enabled"]:
        resolve_alert(conn, settings, "radius_down", "", "FreeRADIUS alerting was switched off.", smtp_password)
        return
    if ok:
        state["down_checks"] = 0
        resolve_alert(conn, settings, "radius_down", "", "FreeRADIUS is back: " + msg, smtp_password)
    else:
        # two checks in a row (about two minutes) so the short restart of Apply never alerts
        state["down_checks"] = state.get("down_checks", 0) + 1
        if state["down_checks"] >= 2:
            open_alert(conn, settings, "radius_down", "", msg, {"helper": status.get("message", "")}, smtp_password)


def send_test(conn, settings, by, smtp_password=None):
    msg = "Test alert requested by %s. If you can read this, alert delivery works." % (by or "an administrator")
    row = db.query_one("INSERT INTO ui.alert (kind, subject, state, message, resolved_at)"
                       " VALUES ('test', '', 'resolved', %s, now()) RETURNING id", (msg,), conn=conn)
    return notify(conn, settings, row["id"], "test", "open", "", msg, smtp_password)
