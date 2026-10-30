"""Live sessions (radacct) and CoA / Disconnect requests (SPEC section 13).

Sessions come from RADIUS accounting (switch: aaa accounting dot1x start-stop group
radius). Each open session is matched to the RADIUS client by NAS address, to the
latest Access-Accept for the same station (VLAN, method, record) and, when switch
monitoring is on, to the port's live 802.1X state.

Disconnect / re-authenticate / bounce are queued in ui.coa_request; the monitor
service (the only component with network access) sends them with radclient to the
switch's dynamic-authorization port (Catalyst 1300: UDP 1700, firmware 4.1.3.36+).
"""
import datetime

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import db, oui
from ..flashing import flash
from ..insight import ClientIndex, port_status
from ..security import login_required, role_required
from . import ev

bp = Blueprint("sessions", __name__, url_prefix="/sessions")
PAGE = 100
STALE_HOURS = 24
COA_ACTIONS = {
    "reauth": ("Re-authenticate", "The switch re-runs 802.1X/MAB for this session; the device keeps its link."),
    "bounce": ("Bounce port", "The switch shuts the port briefly and re-enables it; the device reconnects."),
    "disconnect": ("Disconnect", "The switch ends the session; the device must authenticate again."),
}

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
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    rows = db.query("SELECT " + SESSION_COLS + " FROM radacct a" + AUTH_JOIN + w +
                    " ORDER BY a.acctstarttime DESC NULLS LAST, a.radacctid DESC LIMIT %s OFFSET %s",
                    params + [PAGE + 1, (page - 1) * PAGE])
    more = len(rows) > PAGE
    rows = _decorate(rows[:PAGE], idx, _switch_ports())
    open_count = db.query_one("SELECT count(*) AS n FROM radacct WHERE acctstoptime IS NULL")["n"]
    recent_coa = db.query("SELECT r.*, host(r.nas_ip) AS nas, c.name AS switch_name FROM ui.coa_request r"
                          " JOIN ui.radius_client c ON c.id = r.client_id ORDER BY r.id DESC LIMIT 5")
    mon = db.query_one("SELECT radclient, heartbeat_at FROM ui.monitor_state WHERE id = 1")
    switches = sorted((c for c in idx.by_id.values()), key=lambda c: c["name"])
    return render_template("sessions/index.html", rows=rows, q=q, sw=sw, history=history, page=page, more=more,
                           open_count=open_count, acct=_accounting_overview(idx), switches=switches,
                           recent_coa=recent_coa, mon=mon, actions=COA_ACTIONS)


def _session(sid):
    row = db.query_one("SELECT " + SESSION_COLS + " FROM radacct a" + AUTH_JOIN + " WHERE a.radacctid = %s", (sid,))
    if row is None:
        abort(404)
    return row


@bp.route("/<int:sid>/coa", methods=["POST"])
@role_required("operator")
def coa(sid):
    action = request.form.get("action", "")
    if action not in COA_ACTIONS:
        abort(400)
    s = _session(sid)
    if s["acctstoptime"] is not None:
        flash("That session has already ended.", "error")
        return redirect(url_for("sessions.index"))
    c = ClientIndex.load().find(s["nas"])
    if c is None:
        flash("The session's switch (%s) is not a RADIUS client in this console." % s["nas"], "error")
        return redirect(url_for("sessions.index"))
    if not c["enabled"]:
        flash("%s is disabled in this console; enable it first." % c["name"], "error")
        return redirect(url_for("sessions.index"))
    row = db.execute_returning(
        "INSERT INTO ui.coa_request (client_id, action, acct_session_id, calling_station_id, nas_ip, nas_port_id,"
        " username, requested_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (c["id"], action, (s["acctsessionid"] or "")[:200], (s["callingstationid"] or "")[:64], s["nas"],
         (s["nasportid"] or "")[:100], (s["username"] or "")[:253], g.user["username"]))
    ev("coa.request", object_type="radius_client", object_id=c["id"],
       detail={"action": action, "switch": c["name"], "nas_ip": s["nas"], "port": s["nasportid"],
               "station": s["callingstationid"], "user": s["username"], "request_id": row["id"]})
    return redirect(url_for("sessions.coa_result", rid=row["id"]))


@bp.route("/coa/<int:rid>")
@login_required
def coa_result(rid):
    r = db.query_one("SELECT r.*, host(r.nas_ip) AS nas, c.name AS switch_name FROM ui.coa_request r"
                     " JOIN ui.radius_client c ON c.id = r.client_id WHERE r.id = %s", (rid,))
    if r is None:
        abort(404)
    mon = db.query_one("SELECT radclient, heartbeat_at FROM ui.monitor_state WHERE id = 1")
    port = db.query_one("SELECT coa_port FROM ui.snmp_profile WHERE id = 1")
    return render_template("sessions/coa.html", r=r, mon=mon, actions=COA_ACTIONS,
                           coa_port=port["coa_port"] if port else 1700)
