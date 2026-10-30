"""Audit reports (SPEC section 13): CSV for spreadsheets, and a print layout that the
browser saves as PDF. Every view and export is recorded in the audit log.

Each report is one table (columns + rows) with optional extra sections for the
printable version. Periods are whole UTC days; snapshot reports show current state.
"""
import csv
import datetime
import io
import json
import socket

from flask import Blueprint, Response, abort, g, render_template, request

from .. import db, insight, oui
from ..security import has_role, login_required
from ..services import get_settings, switch_admins
from . import ev

bp = Blueprint("reports", __name__, url_prefix="/reports")
MAX_ROWS = 50000

# key: (title, description, needs a period, minimum role)
REPORTS = {
    "changes": ("Configuration changes", "Every change made through this console and by its services, with who, "
                "when, from where and what changed (the audit log). Sign-ins can be included.", True, "viewer"),
    "auth_summary": ("Authentication summary", "Accepts and rejects per switch and method, top reject reasons and "
                     "the stations rejected most often.", True, "viewer"),
    "privileged": ("Privileged access", "Switch admin accounts (priv 15 setting, password scheme, disabled) and "
                   "console administrators (role, two-factor method, last sign-in).", False, "admin"),
    "sessions": ("Network sessions", "Who was connected where and when, from RADIUS accounting.", True, "viewer"),
    "clients": ("RADIUS clients", "Inventory of switches and other RADIUS clients with key and monitoring state.",
                False, "viewer"),
    "mab": ("MAB devices", "Devices admitted by MAC address, with vendor, VLAN and expiry; plus approvals in the "
            "period.", True, "viewer"),
    "rules": ("Access rules", "The access rules (AD group to VLAN) in evaluation order.", False, "viewer"),
    "alerts": ("Alerts", "Alerts raised and cleared in the period.", True, "viewer"),
    "coa": ("Session actions", "Disconnect, re-authenticate and port-bounce requests and their results.", True,
            "viewer"),
}
SIGNIN_ACTIONS = ("auth.", "session.", "account.stepup", "account.banner")


def _period():
    today = datetime.datetime.now(datetime.timezone.utc).date()

    def parse(name, default):
        v = request.args.get(name, "").strip()
        try:
            return datetime.date.fromisoformat(v) if v else default
        except ValueError:
            return default
    since = parse("since", today - datetime.timedelta(days=30))
    until = parse("until", today)
    if until < since:
        since, until = until, since
    if (until - since).days > 3660:
        since = until - datetime.timedelta(days=3660)
    start = datetime.datetime.combine(since, datetime.time(0), tzinfo=datetime.timezone.utc)
    end = datetime.datetime.combine(until + datetime.timedelta(days=1), datetime.time(0), tzinfo=datetime.timezone.utc)
    return since, until, start, end


def _fmt(v):
    if v is None:
        return ""
    if isinstance(v, datetime.datetime):
        return v.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, default=str)
    return str(v)


# ---------------------------------------------------------------- builders
def build(key, start, end, opts):
    """-> {"columns": [...], "rows": [[...]], "sections": [{"title", "columns", "rows"}], "notes": [...]}"""
    rep = {"columns": [], "rows": [], "sections": [], "notes": []}
    if key == "changes":
        where = ["at >= %s", "at < %s"]
        if not opts.get("signins"):
            where.append("NOT (" + " OR ".join("action LIKE %s" for _ in SIGNIN_ACTIONS) + ")")
        params = [start, end] + ([a + "%" for a in SIGNIN_ACTIONS] if not opts.get("signins") else [])
        rows = db.query("SELECT id, at, actor, host(actor_ip) AS ip, action, object_type, object_id, success, detail"
                        " FROM ui.audit_log WHERE " + " AND ".join(where) + " ORDER BY id LIMIT %s",
                        params + [MAX_ROWS])
        rep["columns"] = ["#", "Time", "Who", "From", "Action", "Object", "Result", "Detail"]
        rep["rows"] = [[r["id"], r["at"], r["actor"], r["ip"], r["action"],
                        ("%s %s" % (r["object_type"] or "", r["object_id"] or "")).strip(),
                        "ok" if r["success"] else "FAILED", r["detail"]] for r in rows]
        rep["notes"].append("Audit records are hash-chained; verify the chain under Audit log.")
    elif key == "auth_summary":
        idx = insight.ClientIndex.load()
        rows = db.query("SELECT host(nasipaddress) AS nas, coalesce(authmethod, 'other') AS method,"
                        " count(*) FILTER (WHERE reply = 'Access-Accept') AS accepts,"
                        " count(*) FILTER (WHERE reply = 'Access-Reject') AS rejects"
                        " FROM radpostauth WHERE authdate >= %s AND authdate < %s GROUP BY 1, 2", (start, end))
        agg = {}
        for r in rows:
            c = idx.find(r["nas"])
            name = c["name"] if c else (r["nas"] or "(unknown)")
            a = agg.setdefault((name, r["method"]), [0, 0])
            a[0] += r["accepts"]
            a[1] += r["rejects"]
        rep["columns"] = ["Switch / client", "Method", "Accepts", "Rejects", "Reject %"]
        for (name, method), (acc, rej) in sorted(agg.items()):
            tot = acc + rej
            rep["rows"].append([name, method, acc, rej, "%.1f" % (100.0 * rej / tot) if tot else "0.0"])
        reasons = db.query("SELECT coalesce(nullif(reason, ''), '(not recorded)') AS reason, count(*) AS n"
                           " FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= %s AND authdate < %s"
                           " GROUP BY 1 ORDER BY 2 DESC LIMIT 20", (start, end))
        rep["sections"].append({"title": "Top reject reasons", "columns": ["Reason", "Rejects"],
                                "rows": [[insight.clean_reason(r["reason"]), r["n"]] for r in reasons]})
        top = db.query("SELECT username, coalesce(callingstationid, '') AS station, count(*) AS n, max(authdate) AS last"
                       " FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= %s AND authdate < %s"
                       " GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 20", (start, end))
        rep["sections"].append({"title": "Most rejected users / stations",
                                "columns": ["User", "Station", "Rejects", "Last"],
                                "rows": [[r["username"], r["station"], r["n"], r["last"]] for r in top]})
    elif key == "privileged":
        st = get_settings()
        rep["columns"] = ["Account", "Kind", "Privilege", "Credential", "Status", "Two-factor", "Last sign-in"]
        for a in switch_admins():
            cred = "PBKDF2-HMAC-SHA-256" if a["pbkdf2"] and not a["legacy"] else (
                "legacy hash (migrate)" if a["legacy"] else "none")
            rep["rows"].append([a["username"], "switch admin (RADIUS)",
                                "priv 15" if st["admin_priv15"] else "switch default", cred,
                                "disabled" if a["disabled"] else "enabled", "n/a", ""])
        for u in db.query("SELECT username, role, mfa_method, enabled, locked_until, last_login_at, host(last_login_ip)"
                          " AS ip, must_change_password FROM ui.admin_user ORDER BY username"):
            status = "disabled" if not u["enabled"] else (
                "locked" if u["locked_until"] and u["locked_until"] > datetime.datetime.now(datetime.timezone.utc)
                else "enabled")
            rep["rows"].append([u["username"], "console administrator", u["role"],
                                "password" + (" (must change)" if u["must_change_password"] else ""), status,
                                {"totp": "authenticator app (TOTP)", "cert": "client certificate"}.get(
                                    u["mfa_method"], "not enrolled"),
                                "%s %s" % (_fmt(u["last_login_at"]), u["ip"] or "")])
        rep["notes"].append("Switch admin logins are accepted only from %s; priv 15 is %s." % (
            st["admin_subnet"], "granted" if st["admin_priv15"] else "not granted"))
    elif key == "sessions":
        idx = insight.ClientIndex.load()
        rows = db.query("SELECT username, callingstationid, host(nasipaddress) AS nas, nasportid, acctstarttime,"
                        " acctstoptime, acctsessiontime, acctterminatecause, host(framedipaddress) AS ip"
                        " FROM radacct WHERE acctstarttime < %s AND coalesce(acctstoptime, now()) >= %s"
                        " ORDER BY acctstarttime LIMIT %s", (end, start, MAX_ROWS))
        rep["columns"] = ["User", "Station", "Vendor", "Switch", "Port", "Started", "Ended", "Duration (s)",
                          "End cause", "IP"]
        for r in rows:
            c = idx.find(r["nas"])
            rep["rows"].append([r["username"], r["callingstationid"], oui.vendor(r["callingstationid"]),
                                c["name"] if c else r["nas"], r["nasportid"], r["acctstarttime"],
                                r["acctstoptime"] or "(open)", r["acctsessiontime"], r["acctterminatecause"], r["ip"]])
    elif key == "clients":
        rows = db.query("SELECT c.name, c.ipaddr, c.nas_type, c.enabled, c.key_status, c.key_scope, c.require_ma,"
                        " c.limit_proxy_state, c.is_switch, c.dot1x_ports, c.description, s.reachable, s.sys_descr,"
                        " s.polled_at FROM ui.radius_client c LEFT JOIN ui.switch_status s ON s.client_id = c.id"
                        " ORDER BY c.name")
        rep["columns"] = ["Name", "Address", "NAS type", "Enabled", "Key", "Key scope", "Message-Authenticator",
                          "Proxy-State", "Monitored", "SNMP", "Model", "802.1X ports", "Description"]
        for r in rows:
            rep["rows"].append([r["name"], r["ipaddr"], r["nas_type"], r["enabled"],
                                {"ok": "plaintext (usable)"}.get(r["key_status"], r["key_status"]), r["key_scope"],
                                r["require_ma"], r["limit_proxy_state"], r["is_switch"],
                                "" if r["reachable"] is None else ("answering" if r["reachable"] else "no answer"),
                                (r["sys_descr"] or "")[:80], r["dot1x_ports"], r["description"]])
        rep["notes"].append("Shared secrets are never included in reports.")
    elif key == "mab":
        rows = db.query("SELECT mac, vlan, description, enabled, expires_at, created_at, updated_at FROM mab_device"
                        " ORDER BY mac LIMIT %s", (MAX_ROWS,))
        now = datetime.datetime.now(datetime.timezone.utc)
        rep["columns"] = ["MAC", "Vendor", "VLAN", "Description", "Status", "Expires", "Registered", "Updated"]
        for r in rows:
            status = "expired" if r["expires_at"] and r["expires_at"] <= now else (
                "enabled" if r["enabled"] else "disabled")
            rep["rows"].append([r["mac"], oui.vendor(r["mac"]), r["vlan"], r["description"], status,
                                r["expires_at"] or "never", r["created_at"], r["updated_at"]])
        approvals = db.query("SELECT at, actor, action, detail FROM ui.audit_log WHERE action IN"
                             " ('mab.approve', 'mab.create', 'mab.delete', 'mab.import') AND at >= %s AND at < %s"
                             " ORDER BY id", (start, end))
        rep["sections"].append({"title": "Registrations, approvals and removals in the period",
                                "columns": ["Time", "Who", "Action", "Detail"],
                                "rows": [[a["at"], a["actor"], a["action"], a["detail"]] for a in approvals]})
    elif key == "rules":
        rows = db.query("SELECT priority, connection, ssid, ad_group, vlan, enabled, description, updated_at"
                        " FROM ui.access_rule ORDER BY connection, ssid NULLS FIRST, priority, id")
        rep["columns"] = ["Order", "Connection", "SSID", "AD group", "VLAN", "Enabled", "Description", "Updated"]
        rep["rows"] = [[r["priority"], r["connection"], r["ssid"], r["ad_group"], r["vlan"], r["enabled"],
                        r["description"], r["updated_at"]] for r in rows]
        rep["notes"].append("The first enabled rule whose AD group matches assigns the VLAN; no match means reject.")
    elif key == "alerts":
        rows = db.query("SELECT kind, subject, state, opened_at, resolved_at, message, notified FROM ui.alert"
                        " WHERE opened_at < %s AND coalesce(resolved_at, now()) >= %s ORDER BY opened_at",
                        (end, start))
        rep["columns"] = ["Opened", "Cleared", "Alert", "State", "Message", "Sent to"]
        rep["rows"] = [[r["opened_at"], r["resolved_at"] if r["kind"] != "test" else "", r["kind"], r["state"],
                        r["message"], r["notified"]] for r in rows]
    elif key == "coa":
        rows = db.query("SELECT r.requested_at, r.requested_by, r.action, c.name, r.nas_port_id, r.username,"
                        " r.calling_station_id, r.ok, r.message, r.done_at FROM ui.coa_request r"
                        " JOIN ui.radius_client c ON c.id = r.client_id WHERE r.requested_at >= %s"
                        " AND r.requested_at < %s ORDER BY r.id", (start, end))
        rep["columns"] = ["Requested", "By", "Action", "Switch", "Port", "User", "Station", "Result", "Message"]
        rep["rows"] = [[r["requested_at"], r["requested_by"], r["action"], r["name"], r["nas_port_id"], r["username"],
                        r["calling_station_id"], "pending" if r["done_at"] is None else ("ok" if r["ok"] else "failed"),
                        r["message"]] for r in rows]
        rep["notes"].append("Requests older than 90 days are removed automatically; the audit log keeps them.")
    if len(rep["rows"]) >= MAX_ROWS:
        rep["notes"].append("Truncated at %d rows; choose a shorter period." % MAX_ROWS)
    return rep


# ---------------------------------------------------------------- views
def _check(key):
    if key not in REPORTS:
        abort(404)
    if not has_role(REPORTS[key][3]):
        abort(403)


@bp.route("/")
@login_required
def index():
    since, until, _, _ = _period()
    return render_template("reports/index.html", reports=REPORTS, since=since, until=until)


def _csv_cell(v):
    s = _fmt(v)
    # spreadsheet formula injection: neutralize cells that a spreadsheet would evaluate
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    return s


@bp.route("/<key>")
@login_required
def view(key):
    _check(key)
    since, until, start, end = _period()
    opts = {"signins": request.args.get("signins") == "1"}
    rep = build(key, start, end, opts)
    title, desc, periodic, _ = REPORTS[key]
    fmt = request.args.get("format", "html")
    detail = {"report": key, "since": since.isoformat() if periodic else None,
              "until": until.isoformat() if periodic else None, "rows": len(rep["rows"]), "format": fmt}
    if fmt == "csv":
        ev("report.export", object_type="report", object_id=key, detail=detail)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(rep["columns"])
        for row in rep["rows"]:
            w.writerow([_csv_cell(v) for v in row])
        for sec in rep["sections"]:
            w.writerow([])
            w.writerow([sec["title"]])
            w.writerow(sec["columns"])
            for row in sec["rows"]:
                w.writerow([_csv_cell(v) for v in row])
        name = "radius-admin-%s-%s.csv" % (key, (since.isoformat() + "_" + until.isoformat()) if periodic
                                          else datetime.date.today().isoformat())
        return Response("﻿" + buf.getvalue(), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="%s"' % name})
    ev("report.view", object_type="report", object_id=key, detail=detail)
    fmt_rows = [[_fmt(v) for v in r] for r in rep["rows"]]
    sections = [dict(s, rows=[[_fmt(v) for v in r] for r in s["rows"]]) for s in rep["sections"]]
    return render_template("reports/print.html", key=key, title=title, desc=desc, periodic=periodic,
                           since=since, until=until, columns=rep["columns"], rows=fmt_rows, sections=sections,
                           notes=rep["notes"], opts=opts, generated=datetime.datetime.now(datetime.timezone.utc),
                           by=g.user["username"], host=socket.getfqdn())
