"""Alerts (SPEC section 13): reject spikes, switches that stop answering SNMP,
FreeRADIUS down, the web portal (nginx) down and the second factor (SPEC section 29.4). Evaluated by the monitor service once a minute; each condition opens
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

from . import audit, db, integrations

ACTOR = "system:monitor"
LABELS = {"reject_spike": "Reject spike", "switch_down": "Switch not responding",
          "radius_down": "FreeRADIUS down", "portal_down": "Portal down", "monitor_down": "Monitoring stopped",
          "mfa_provider_down": "Second-factor provider down", "mfa_timeouts": "Second factor not answering",
          "mfa_unverified": "Unverified second-factor build", "mfa_withdrawn": "Withdrawn second-factor build",
          "test": "Test alert"}
MFA_KINDS = ("mfa_provider_down", "mfa_timeouts", "mfa_unverified", "mfa_withdrawn")
# the reject reason of radius_admin_reject when a proxied login got no answer (unlang._MFA_NO_ANSWER)
MFA_NO_ANSWER = "radius-admin: the second-factor provider did not answer"
REMIND_HOURS = 24       # open unverified / withdrawn build alerts are sent again once a day


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


def check_portal(conn, settings, status, state, smtp_password=None):
    """The web portal (nginx), from the same helper 'status' response as check_radius.
    state: dict kept by the caller across checks ({'down_checks': int}). A helper error is
    left to the FreeRADIUS check; a helper without portal_* fields, or a server whose nginx
    site is not enabled, never alerts."""
    if not status.get("ok"):
        return
    if status.get("portal_configured") is not True:
        state["down_checks"] = 0
        resolve_alert(conn, settings, "portal_down", "", "The portal's nginx site is not enabled on this server.",
                      smtp_password)
        return
    ok = bool(status.get("portal_active")) and bool(status.get("portal_listening"))
    if ok:
        msg = "nginx active and listening on TCP 443."
    elif not status.get("portal_active"):
        msg = "nginx (the web portal) is not active."
    else:
        msg = "nginx is running but not listening on TCP 443."
    # no "last check" is kept: whenever someone can read it in the portal, nginx is up
    if not settings["portal_enabled"]:
        resolve_alert(conn, settings, "portal_down", "", "Portal alerting was switched off.", smtp_password)
        return
    if ok:
        state["down_checks"] = 0
        resolve_alert(conn, settings, "portal_down", "", "The portal is back: " + msg, smtp_password)
    else:
        # two checks in a row (about two minutes): an nginx reload or one retry never alerts
        state["down_checks"] = state.get("down_checks", 0) + 1
        if state["down_checks"] >= 2:
            open_alert(conn, settings, "portal_down", "", msg, None, smtp_password)


# ---------------------------------------------------------------- second factor (SPEC section 29.4)
def remind_alert(conn, settings, kind, subject, hours=REMIND_HOURS, smtp_password=None):
    """Send an alert that is still open again once it was last sent `hours` ago."""
    row = db.query_one("UPDATE ui.alert SET reminded_at = now() WHERE kind = %s AND subject = %s AND state = 'open'"
                       " AND coalesce(reminded_at, opened_at) < now() - make_interval(hours => %s)"
                       " RETURNING id, message", (kind, subject or "", int(hours)), conn=conn)
    if row is None:
        return None
    notify(conn, settings, row["id"], kind, "open", subject, "Still open: " + row["message"], smtp_password)
    return row["id"]


def _duo_applied(conn):
    """The enabled Duo provider, when the last successful apply installed a Duo configuration
    (before the first apply the proxy is not meant to run, and the apply page says so)."""
    row = db.query_one("SELECT p.id, p.label FROM ui.mfa_provider p WHERE p.type = 'duo' AND p.enabled"
                       " AND coalesce((SELECT a.providers_sha256 FROM ui.apply_log a WHERE a.success"
                       "  AND a.action IN ('apply', 'rollback') ORDER BY a.id DESC LIMIT 1), '') <> ''",
                       conn=conn)
    return row


def check_mfa_provider(conn, settings, integ, state, smtp_password=None):
    """mfa_provider_down. integ: the helper's integration_status response; state: dict kept by
    the caller ({'down_checks': int}). A helper error (or a helper without integration_status)
    neither opens nor resolves; two failed checks in a row are needed (Apply restarts the proxy)."""
    if not settings.get("mfa_enabled", True):
        state["down_checks"] = 0
        for a in db.query("SELECT subject FROM ui.alert WHERE kind = 'mfa_provider_down' AND state = 'open'",
                          conn=conn):
            resolve_alert(conn, settings, "mfa_provider_down", a["subject"],
                          "Second-factor alerting was switched off.", smtp_password)
        return
    p = _duo_applied(conn)
    if p is None:
        state["down_checks"] = 0
        resolve_alert(conn, settings, "mfa_provider_down", "duo", "The Duo provider is off or no longer applied.",
                      smtp_password)
        return
    if not integ.get("ok"):
        return
    duo = (integ.get("integrations") or {}).get("duo") or {}
    if not duo.get("installed"):
        msg = "The Duo Authentication Proxy is turned on but not installed on this server."
    elif not duo.get("service_active"):
        msg = "duoauthproxy.service is not active: device admin logins that need a second factor are rejected."
    elif not duo.get("listening"):
        msg = ("The Duo Authentication Proxy runs but does not listen on 127.0.0.1:18120: device admin logins"
               " that need a second factor are rejected.")
    else:
        state["down_checks"] = 0
        resolve_alert(conn, settings, "mfa_provider_down", "duo",
                      "The Duo Authentication Proxy is active and listening again.", smtp_password)
        return
    state["down_checks"] = state.get("down_checks", 0) + 1
    if state["down_checks"] >= 2:
        open_alert(conn, settings, "mfa_provider_down", "duo", msg + " Exempt break-glass accounts still log in.",
                   {"provider": "duo", "installed": bool(duo.get("installed")),
                    "service_active": bool(duo.get("service_active")), "listening": bool(duo.get("listening"))},
                   smtp_password)


def check_mfa_timeouts(conn, settings, smtp_password=None):
    """mfa_timeouts: device admin logins rejected because the provider did not answer."""
    if not settings.get("mfa_timeout_enabled", True):
        resolve_alert(conn, settings, "mfa_timeouts", "", "Second-factor timeout alerting was switched off.",
                      smtp_password)
        return
    win = int(settings.get("mfa_timeout_window_minutes") or 15)
    thr = int(settings.get("mfa_timeout_threshold") or 3)
    r = db.query_one("SELECT count(*) AS n, count(DISTINCT username) AS users FROM radpostauth"
                     " WHERE reply = 'Access-Reject' AND reason = %s AND authdate > now() - make_interval(mins => %s)",
                     (MFA_NO_ANSWER, win), conn=conn)
    n = r["n"]
    if n >= thr:
        top = db.query("SELECT coalesce(host(nasipaddress), '?') AS nas, count(*) AS n FROM radpostauth"
                       " WHERE reply = 'Access-Reject' AND reason = %s AND authdate > now() - make_interval(mins => %s)"
                       " GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 3", (MFA_NO_ANSWER, win), conn=conn)
        open_alert(conn, settings, "mfa_timeouts", "",
                   "%d device admin login%s (%d account%s) got no answer from the second-factor provider in the last"
                   " %d minutes (threshold %d). Clients: %s. Check the provider's service and its connection to the"
                   " vendor's cloud." % (n, "" if n == 1 else "s", r["users"], "" if r["users"] == 1 else "s", win, thr,
                                         ", ".join("%s x%d" % (t["nas"], t["n"]) for t in top)),
                   {"count": n, "accounts": r["users"], "window_minutes": win, "threshold": thr}, smtp_password)
    elif n < max(1, thr // 2):
        resolve_alert(conn, settings, "mfa_timeouts", "",
                      "Second-factor timeouts back to %d in the last %d minutes." % (n, win), smtp_password)


def check_mfa_builds(conn, settings, integ, catalog, smtp_password=None):
    """mfa_unverified (an enabled provider runs a build installed with an admin-pasted SHA-256 that
    the signed catalog still does not list) and mfa_withdrawn (the installed build is withdrawn in
    the catalog). Both are sent again once a day while open. integ / catalog: the helper's
    integration_status / integration_catalog responses; an error leaves the alerts as they are."""
    kinds = ("mfa_unverified", "mfa_withdrawn")
    if not settings.get("mfa_enabled", True):
        for kind in kinds:
            resolve_alert(conn, settings, kind, "duo", "Second-factor alerting was switched off.", smtp_password)
        return
    if not integ.get("ok") or not catalog.get("ok"):
        return
    inst = ((integ.get("integrations") or {}).get("duo") or {}).get("installed") or {}
    version, digest = inst.get("version") or "", inst.get("sha256") or ""
    check = integrations.build_check(inst, catalog.get("entries"))
    listed, withdrawn = check["listed"], check["withdrawn"]
    enabled = db.query_one("SELECT enabled FROM ui.mfa_provider WHERE id = 'duo'", conn=conn)
    if inst and enabled and enabled["enabled"] and integ.get("fips_enabled") and not check["fips_capable"]:
        # FIPS mode (SPEC section 29.4): the helper refuses to apply Duo until the build qualifies
        if open_alert(conn, settings, "mfa_unverified", "duo",
                      "FIPS mode: Duo Authentication Proxy %s is turned on but is not a FIPS-capable build in the"
                      " signed catalog (or was installed before FIPS mode was turned on). Changes to Duo cannot be"
                      " applied; install a FIPS-capable build or turn the Duo provider off and apply."
                      % (version or "(unknown version)"),
                      {"provider": "duo", "version": version, "sha256": digest, "fips": True}, smtp_password) is None:
            remind_alert(conn, settings, "mfa_unverified", "duo", smtp_password=smtp_password)
    elif inst and enabled and enabled["enabled"] and inst.get("verified") == "pasted-hash" and not listed:
        if open_alert(conn, settings, "mfa_unverified", "duo",
                      "Duo Authentication Proxy %s is in use but unverified: it was installed with a SHA-256 an admin"
                      " entered, and the project's signed catalog does not list it. Install a build from the catalog"
                      " when one is available." % (version or "(unknown version)"),
                      {"provider": "duo", "version": version, "sha256": digest}, smtp_password) is None:
            remind_alert(conn, settings, "mfa_unverified", "duo", smtp_password=smtp_password)
    else:
        resolve_alert(conn, settings, "mfa_unverified", "duo",
                      "No unverified second-factor build is in use any more." if not listed else
                      "The signed catalog now lists the installed Duo build.", smtp_password)
    if inst and withdrawn:
        if open_alert(conn, settings, "mfa_withdrawn", "duo",
                      "Duo Authentication Proxy %s is installed, but this build was withdrawn from the project's"
                      " signed catalog (serial %s). Install a current build from the Duo integration page."
                      % (version or "(unknown version)", catalog.get("serial", "?")),
                      {"provider": "duo", "version": version, "sha256": digest, "catalog_serial": catalog.get("serial")},
                      smtp_password) is None:
            remind_alert(conn, settings, "mfa_withdrawn", "duo", smtp_password=smtp_password)
    else:
        resolve_alert(conn, settings, "mfa_withdrawn", "duo", "The withdrawn Duo build is no longer installed.",
                      smtp_password)


def send_test(conn, settings, by, smtp_password=None):
    msg = "Test alert requested by %s. If you can read this, alert delivery works." % (by or "an administrator")
    row = db.query_one("INSERT INTO ui.alert (kind, subject, state, message, resolved_at)"
                       " VALUES ('test', '', 'resolved', %s, now()) RETURNING id", (msg,), conn=conn)
    return notify(conn, settings, row["id"], "test", "open", "", msg, smtp_password)
