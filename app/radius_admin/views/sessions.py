"""Live sessions (radacct) and CoA / Disconnect requests (SPEC section 13).

Sessions come from RADIUS accounting (switch: aaa accounting dot1x start-stop group
radius). Each open session is matched to the RADIUS client by NAS address, to the
latest Access-Accept for the same station (VLAN, method, record) and, when switch
monitoring is on, to the port's live 802.1X state.

Disconnect / re-authenticate / bounce are queued in ui.coa_request; the monitor
service (the only component with network access) sends them with radclient to the
switch's dynamic-authorization port (Catalyst 1300: UDP 1700, firmware 4.1.3.36+).

One request or many go through the same POST (SPEC section 24): every open session
chosen gets its own ui.coa_request row and audit event. The sessions page shows the
state of each request in the session's row; "Session actions" lists all of them.
"""
import datetime

from flask import Blueprint, abort, g, jsonify, redirect, render_template, request, url_for

from .. import db, oui, paging
from ..flashing import flash
from ..listnav import list_url
from ..insight import ClientIndex, port_status
from ..security import login_required, role_required
from ..snmp import is_blocked
from . import ev

bp = Blueprint("sessions", __name__, url_prefix="/sessions")
PAGE = 50
STALE_HOURS = 24
MAX_BULK = PAGE             # one request can name at most one page of sessions
MAX_STATUS_IDS = 200
RECENT_MINUTES = 15         # a finished request stays in its session's row this long
# label, what it does to one session, what it does to several (confirmation text)
COA_ACTIONS = {
    "reauth": ("Re-authenticate", "The switch re-runs 802.1X/MAB for this session; the device keeps its link.",
               "The switches re-run 802.1X/MAB for these sessions; the devices keep their link."),
    "bounce": ("Bounce port", "The switch shuts the port briefly and re-enables it; the device reconnects.",
               "The switches shut each port briefly and re-enable it; the devices reconnect."),
    "disconnect": ("Disconnect", "The switch ends the session; the device must authenticate again.",
                   "The switches end these sessions; the devices must authenticate again."),
}
# The latest request for the session, shown in its row while it waits and for a while after.
COA_JOIN = (
    " LEFT JOIN LATERAL (SELECT r.id AS coa_id, r.action AS coa_action, r.done_at AS coa_done_at,"
    "  r.ok AS coa_ok, r.message AS coa_message FROM ui.coa_request r"
    "  WHERE r.radacct_id = a.radacctid"
    "  AND (r.done_at IS NULL OR r.requested_at > now() - make_interval(mins => %s))"
    "  ORDER BY r.id DESC LIMIT 1) cr ON true")
REQUEST_SELECT = ("SELECT r.*, host(r.nas_ip) AS nas, c.name AS switch_name FROM ui.coa_request r"
                  " JOIN ui.radius_client c ON c.id = r.client_id")

SESSION_COLS = (
    "a.radacctid, a.acctsessionid, a.acctuniqueid, a.username, host(a.nasipaddress) AS nas, a.nasportid,"
    " a.nasporttype, a.acctstarttime, a.acctupdatetime, a.acctstoptime, a.acctsessiontime,"
    " a.callingstationid, a.calledstationid, a.acctterminatecause, a.framedipaddress,"
    " a.acctinputoctets, a.acctoutputoctets,"
    " pa.id AS auth_id, pa.vlan, pa.authmethod")
# The Access-Accept that started the session: same station and switch, at most 5 minutes
# after accounting start (switches send Accounting-Start right after the Accept).
AUTH_JOIN = (
    " LEFT JOIN LATERAL (SELECT p.id, p.vlan, p.authmethod FROM radpostauth p"
    "  WHERE p.reply = 'Access-Accept' AND p.callingstationid = a.callingstationid"
    "  AND p.nasipaddress = a.nasipaddress"
    "  AND p.authdate <= coalesce(a.acctstarttime, now()) + interval '5 minutes'"
    "  ORDER BY p.authdate DESC LIMIT 1) pa ON true")


def _switch_ports():
    """{client_id: ports list} from the last SNMP poll."""
    try:
        rows = db.query("SELECT client_id, ports, reachable, polled_at FROM ui.switch_status")
    except Exception:  # monitoring tables missing on a half-upgraded install
        return {}
    return {r["client_id"]: r for r in rows}


def _decorate(rows, idx, ports):
    now = datetime.datetime.now(datetime.timezone.utc)
    for r in rows:
        c = idx.find(r["nas"])
        r["client"] = c
        r["vendor"] = oui.vendor(r["callingstationid"])
        start = r["acctstarttime"]
        if r["acctstoptime"] is None and start:
            r["duration"] = (now - start).total_seconds()
        else:
            r["duration"] = r["acctsessiontime"]
        last = r["acctupdatetime"] or start
        r["stale"] = bool(r["acctstoptime"] is None and last and (now - last).total_seconds() > STALE_HOURS * 3600
                          and r["acctupdatetime"] is not None)
        r["port"] = None
        if c and c["id"] in ports:
            r["port"] = port_status(ports[c["id"]]["ports"], r["nasportid"])
    return rows


def _accounting_overview(idx):
    rows = db.query("SELECT host(nasipaddress) AS nas, max(greatest(acctstarttime, acctupdatetime, acctstoptime)) AS last,"
                    " count(*) FILTER (WHERE acctstoptime IS NULL) AS open"
                    " FROM radacct WHERE acctstarttime > now() - interval '30 days' GROUP BY nasipaddress")
    seen = {}
    for r in rows:
        c = idx.find(r["nas"])
        if c:
            prev = seen.get(c["id"])
            if not prev or (r["last"] and (prev["last"] is None or r["last"] > prev["last"])):
                seen[c["id"]] = r
    switches = [c for c in idx.by_id.values() if c["is_switch"] and c["enabled"]]
    silent = sorted((c for c in switches if c["id"] not in seen), key=lambda c: c["name"])
    return {"switches": len(switches), "sending": len([c for c in switches if c["id"] in seen]),
            "silent": silent, "any": bool(rows)}


@bp.route("/")
@login_required
def index():
    q = request.args.get("q", "").strip()[:100]
    sw = request.args.get("switch", "")
    history = request.args.get("history") == "1"
    idx = ClientIndex.load()
    where, params = [], []
    if history:
        where.append("a.acctstarttime > now() - interval '30 days'")
    else:
        where.append("a.acctstoptime IS NULL")
    if q:
        qm = q.replace(":", "").replace("-", "").replace(".", "")
        where.append("(a.username ILIKE %s OR a.nasportid ILIKE %s OR"
                     " regexp_replace(coalesce(a.callingstationid, ''), '[^0-9A-Fa-f]', '', 'g') ILIKE %s"
                     " OR host(a.framedipaddress) = %s)")
        params += ["%" + q + "%", "%" + q + "%", "%" + qm + "%", q]
    client = None
    if sw:
        try:
            client = idx.by_id.get(int(sw))
        except ValueError:
            client = None
        if client:
            where.append("a.nasipaddress <<= %s::inet")
            params.append(str(client["ipaddr"]))
    w = " WHERE " + " AND ".join(where)
    pager = paging.Pager(paging.requested_page(), PAGE, paging.count(db, " FROM radacct a" + w, params, PAGE))
    rows = db.query("SELECT " + SESSION_COLS + ", cr.* FROM radacct a" + AUTH_JOIN + COA_JOIN + w +
                    " ORDER BY a.acctstarttime DESC NULLS LAST, a.radacctid DESC LIMIT %s OFFSET %s",
                    [RECENT_MINUTES] + params + [PAGE, pager.offset])
    rows = _decorate(rows, idx, _switch_ports())
    open_count = db.query_one("SELECT count(*) AS n FROM radacct WHERE acctstoptime IS NULL")["n"]
    mon = db.query_one("SELECT radclient, heartbeat_at FROM ui.monitor_state WHERE id = 1")
    switches = sorted((c for c in idx.by_id.values()), key=lambda c: c["name"])
    waiting = [r["coa_id"] for r in rows if r["coa_id"] and r["coa_done_at"] is None]
    return render_template("sessions/index.html", rows=rows, q=q, sw=sw, history=history, pager=pager,
                           open_count=open_count, acct=_accounting_overview(idx), switches=switches,
                           mon=mon, actions=COA_ACTIONS, waiting=waiting, max_bulk=MAX_BULK,
                           selectable=any(r["acctstoptime"] is None and r["client"] for r in rows))


def _session_name(s):
    return s["username"] or s["callingstationid"] or "session %d" % s["radacctid"]


def _plural(n):
    return "1 session" if n == 1 else "%d sessions" % n


def _queue(action, sids):
    """Queue `action` for each session id. Returns (queued, skipped): queued holds
    {"sid", "id", "name"}; skipped {"sid", "name", "reason"} for sessions that have ended,
    whose switch is unknown or disabled, or that already have a request waiting."""
    rows = db.query("SELECT a.radacctid, a.acctsessionid, a.username, host(a.nasipaddress) AS nas, a.nasportid,"
                    " a.acctstoptime, a.callingstationid, EXISTS (SELECT 1 FROM ui.coa_request r"
                    "  WHERE r.radacct_id = a.radacctid AND r.done_at IS NULL) AS waiting"
                    " FROM radacct a WHERE a.radacctid = ANY(%s)", (sids,))
    by_id = {r["radacctid"]: r for r in rows}
    idx = ClientIndex.load()
    queued, skipped = [], []
    for sid in sids:
        s = by_id.get(sid)
        if s is None:
            skipped.append({"sid": sid, "name": "session %d" % sid, "reason": "it is no longer in the accounting records"})
            continue
        c = idx.find(s["nas"])
        if s["acctstoptime"] is not None:
            reason = "the session has already ended"
        elif c is None:
            reason = "its switch (%s) is not a RADIUS client in this console" % s["nas"]
        elif not c["enabled"]:
            reason = "%s is disabled in this console" % c["name"]
        elif s["waiting"]:
            reason = "an earlier request for it is still waiting"
        else:
            reason = None
        if reason:
            skipped.append({"sid": sid, "name": _session_name(s), "reason": reason})
            continue
        row = db.execute_returning(
            "INSERT INTO ui.coa_request (client_id, action, acct_session_id, calling_station_id, nas_ip, nas_port_id,"
            " username, requested_by, radacct_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (c["id"], action, (s["acctsessionid"] or "")[:200], (s["callingstationid"] or "")[:64], s["nas"],
             (s["nasportid"] or "")[:100], (s["username"] or "")[:253], g.user["username"], sid))
        ev("coa.request", object_type="radius_client", object_id=c["id"],
           detail={"action": action, "switch": c["name"], "nas_ip": s["nas"], "port": s["nasportid"],
                   "station": s["callingstationid"], "user": s["username"], "request_id": row["id"],
                   "selected": len(sids)})
        queued.append({"sid": sid, "id": row["id"], "name": _session_name(s),
                       "where": ("%s %s" % (c["name"], s["nasportid"] or "")).strip()})
    return queued, skipped


def _summary(action, queued, skipped):
    label = COA_ACTIONS[action][0]
    parts = []
    if len(queued) == 1:
        parts.append("%s requested for %s on %s." % (label, queued[0]["name"], queued[0]["where"]))
    elif queued:
        parts.append("%s requested for %s." % (label, _plural(len(queued))))
    if skipped:
        shown = "; ".join("%s (%s)" % (x["name"], x["reason"]) for x in skipped[:3])
        more = " and %d more" % (len(skipped) - 3) if len(skipped) > 3 else ""
        parts.append("Not sent for %s: %s%s." % (_plural(len(skipped)), shown, more))
    return " ".join(parts)


def _wants_json():
    return request.headers.get("Accept", "").startswith("application/json")


@bp.route("/coa", methods=["POST"])
@role_required("operator")
def coa():
    """Queue one action for the chosen sessions (`sid`, once per session)."""
    action = request.form.get("action", "")
    if action not in COA_ACTIONS:
        abort(400)
    sids = []
    for v in request.form.getlist("sid"):
        if not (v.isascii() and v.isdigit() and len(v) <= 18):
            abort(400)
        if int(v) not in sids:
            sids.append(int(v))
    if len(sids) > MAX_BULK:
        abort(400)
    if not sids:
        message, queued, skipped = "Select at least one session first.", [], []
    else:
        queued, skipped = _queue(action, sids)
        message = _summary(action, queued, skipped)
    if _wants_json():
        return jsonify(action=action, label=COA_ACTIONS[action][0], message=message, skipped=skipped,
                       queued=[{"sid": x["sid"], "id": x["id"], "url": url_for("sessions.coa_result", rid=x["id"])}
                               for x in queued])
    flash(message, "success" if queued and not skipped else "info" if queued else "error")
    return redirect(list_url("sessions.index"))


def _state(r):
    return "waiting" if r["done_at"] is None else "ok" if r["ok"] else "failed"


@bp.route("/coa/status")
@login_required
def coa_states():
    """State of several requests at once, for the rows of the sessions page."""
    ids = []
    for v in request.args.getlist("id")[:MAX_STATUS_IDS]:
        if v.isascii() and v.isdigit() and len(v) <= 9:
            ids.append(int(v))
    rows = db.query("SELECT id, done_at, ok, message FROM ui.coa_request WHERE id = ANY(%s)", (ids,)) if ids else []
    return jsonify(requests=[{"id": r["id"], "state": _state(r), "message": r["message"][:300]} for r in rows])


@bp.route("/coa/<int:rid>/status")
@login_required
def coa_status(rid):
    r = db.query_one("SELECT done_at FROM ui.coa_request WHERE id = %s", (rid,))
    if r is None:
        abort(404)
    return jsonify(done=r["done_at"] is not None)


@bp.route("/coa/<int:rid>")
@login_required
def coa_result(rid):
    r = db.query_one(REQUEST_SELECT + " WHERE r.id = %s", (rid,))
    if r is None:
        abort(404)
    mon = db.query_one("SELECT radclient, heartbeat_at FROM ui.monitor_state WHERE id = 1")
    port = db.query_one("SELECT coa_port FROM ui.snmp_profile WHERE id = 1")
    session = None
    if r.get("radacct_id"):
        session = db.query_one("SELECT acctstarttime, acctstoptime, acctterminatecause FROM radacct"
                               " WHERE radacctid = %s", (r["radacct_id"],))
    return render_template("sessions/coa.html", r=r, mon=mon, actions=COA_ACTIONS, session=session,
                           vendor=oui.vendor(r["calling_station_id"]),
                           coa_port=port["coa_port"] if port else 1700, blocked=is_blocked(r["message"]))


@bp.route("/actions")
@login_required
def actions():
    """Every session action requested (kept 90 days), newest first."""
    q = request.args.get("q", "").strip()[:100]
    sw = request.args.get("switch", "")
    action = request.args.get("action", "")
    result = request.args.get("result", "")
    idx = ClientIndex.load()
    where, params = [], []
    if q:
        qm = q.replace(":", "").replace("-", "").replace(".", "")
        where.append("(r.username ILIKE %s OR r.nas_port_id ILIKE %s OR r.requested_by ILIKE %s"
                     " OR regexp_replace(r.calling_station_id, '[^0-9A-Fa-f]', '', 'g') ILIKE %s)")
        params += ["%" + q + "%", "%" + q + "%", "%" + q + "%", "%" + (qm or q) + "%"]
    if sw.isascii() and sw.isdigit() and len(sw) <= 9:
        where.append("r.client_id = %s")
        params.append(int(sw))
    else:
        sw = ""
    if action in COA_ACTIONS:
        where.append("r.action = %s")
        params.append(action)
    else:
        action = ""
    if result == "waiting":
        where.append("r.done_at IS NULL")
    elif result == "ok":
        where.append("r.ok")
    elif result == "failed":
        where.append("r.done_at IS NOT NULL AND NOT coalesce(r.ok, false)")
    else:
        result = ""
    frm = (" FROM ui.coa_request r JOIN ui.radius_client c ON c.id = r.client_id"
           + ((" WHERE " + " AND ".join(where)) if where else ""))
    pager = paging.Pager(paging.requested_page(), PAGE, paging.count(db, frm, params, PAGE))
    rows = db.query("SELECT r.*, host(r.nas_ip) AS nas, c.name AS switch_name" + frm +
                    " ORDER BY r.id DESC LIMIT %s OFFSET %s", params + [PAGE, pager.offset])
    mon = db.query_one("SELECT radclient, heartbeat_at FROM ui.monitor_state WHERE id = 1")
    switches = sorted((c for c in idx.by_id.values()), key=lambda c: c["name"])
    return render_template("sessions/actions.html", rows=rows, q=q, sw=sw, action=action, result=result,
                           pager=pager, switches=switches, actions=COA_ACTIONS, mon=mon,
                           waiting=any(r["done_at"] is None for r in rows))
