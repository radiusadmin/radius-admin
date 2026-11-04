"""Authentication log (radpostauth) and audit log (ui.audit_log) with chain verification."""
import datetime
import json

from flask import Blueprint, abort, render_template, request

from .. import audit, db, insight, oui, paging
from ..services import display_zone
from ..security import login_required, role_required
from . import ev

bp = Blueprint("logs", __name__)
PAGE = 50
AUDIT_COLS = ("SELECT id, at, actor, host(actor_ip) AS actor_ip, action, object_type, object_id,"
              " detail, success, hash")


def _day_start(day):
    """Midnight starting this day in the display time zone."""
    return datetime.datetime.combine(day, datetime.time(), tzinfo=display_zone())


def _date(name):
    v = request.args.get(name, "").strip()
    if not v:
        return None
    try:
        return datetime.date.fromisoformat(v)
    except ValueError:
        return None


@bp.route("/auth-log")
@login_required
def auth_log():
    f = {k: request.args.get(k, "").strip()[:100] for k in ("user", "nas", "mac", "reply", "method")}
    since, until = _date("since"), _date("until")
    where, params = [], []
    if f["user"]:
        where.append("username ILIKE %s")
        params.append("%" + f["user"] + "%")
    if f["nas"]:
        where.append("host(nasipaddress) LIKE %s")
        params.append(f["nas"] + "%")
    if f["mac"]:
        where.append("callingstationid ILIKE %s")
        params.append("%" + f["mac"].replace(":", "-") + "%")
    if f["reply"] in ("Access-Accept", "Access-Reject"):
        where.append("reply = %s")
        params.append(f["reply"])
    if f["method"] in ("eap-tls", "ttls-pap", "ttls-ldap", "peap", "peap-ldap", "pap-admin", "mab", "other"):
        where.append("authmethod = %s")
        params.append(f["method"])
    if since:
        where.append("authdate >= %s")
        params.append(_day_start(since))
    if until:
        where.append("authdate < %s")
        params.append(_day_start(until + datetime.timedelta(days=1)))
    frm = " FROM radpostauth" + ((" WHERE " + " AND ".join(where)) if where else "")
    pager = paging.Pager(paging.requested_page(), PAGE, paging.count(db, frm, params, PAGE))
    rows = db.query("SELECT id, authdate, username, reply, authmethod, host(nasipaddress) AS nas,"
                    " calledstationid, callingstationid, nasporttype, vlan, certsan, reason, nasportid"
                    + frm + " ORDER BY authdate DESC, id DESC LIMIT %s OFFSET %s",
                    params + [PAGE, pager.offset])
    idx = insight.ClientIndex.load()
    for r in rows:
        r["client"] = idx.find(r["nas"])
        r["reason_text"] = insight.clean_reason(r["reason"])
    return render_template("logs/auth.html", rows=rows, f=f, since=since, until=until, pager=pager)


@bp.route("/auth-log/<int:aid>")
@login_required
def auth_detail(aid):
    r = db.query_one("SELECT *, host(nasipaddress) AS nas FROM radpostauth WHERE id = %s", (aid,))
    if r is None:
        abort(404)
    client = insight.ClientIndex.load().find(r["nas"])
    groups = insight.decode_groups(r.get("ad_groups_hex"))
    rule = None
    if r.get("rule_id"):
        rule = db.query_one("SELECT id, priority, connection, ssid, ad_group, vlan, enabled, description"
                            " FROM ui.access_rule WHERE id = %s", (r["rule_id"],))
    expiry = insight.cert_expiry(r.get("cert_expiry"))
    mac = oui.normalize(r["callingstationid"])
    mab = pending = None
    if mac:
        mac_dash = "-".join(mac[i:i + 2] for i in range(0, 12, 2))
        mab = db.query_one("SELECT id, vlan, enabled, expires_at FROM mab_device WHERE mac = %s", (mac_dash,))
        pending = db.query_one("SELECT mac, ignored FROM mab_pending_open WHERE mac = %s", (mac_dash,))
    history = db.query("SELECT id, authdate, reply, vlan, reason FROM radpostauth"
                       " WHERE id <> %s AND ((callingstationid IS NOT NULL AND callingstationid = %s)"
                       "  OR (callingstationid IS NULL AND username = %s))"
                       " ORDER BY authdate DESC LIMIT 10", (aid, r["callingstationid"], r["username"]))
    session = None
    if r["callingstationid"]:
        session = db.query_one("SELECT radacctid, acctstarttime, acctstoptime, nasportid FROM radacct"
                               " WHERE callingstationid = %s AND nasipaddress = %s"
                               " ORDER BY acctstarttime DESC NULLS LAST LIMIT 1", (r["callingstationid"], r["nas"]))
    now = datetime.datetime.now(datetime.timezone.utc)
    return render_template("logs/auth_detail.html", r=r, client=client, groups=groups, rule=rule,
                           expiry=expiry, expired=bool(expiry and expiry <= now),
                           reason=insight.clean_reason(r.get("reason")),
                           hint=insight.reason_hint(r.get("reason"), r["reply"]),
                           mab=mab, pending=pending, history=history, session=session)


@bp.route("/audit-log")
@login_required
def audit_log():
    f = {k: request.args.get(k, "").strip()[:100] for k in ("actor", "action", "result")}
    where, params = [], []
    if f["actor"]:
        where.append("actor ILIKE %s")
        params.append("%" + f["actor"] + "%")
    if f["action"]:
        where.append("action LIKE %s")
        params.append(f["action"] + "%")
    if f["result"] in ("ok", "fail"):
        where.append("success = %s")
        params.append(f["result"] == "ok")
    frm = " FROM ui.audit_log" + ((" WHERE " + " AND ".join(where)) if where else "")
    pager = paging.Pager(paging.requested_page(), PAGE, paging.count(db, frm, params, PAGE))
    rows = _audit_rows(frm, params, pager)
    return render_template("logs/audit.html", rows=rows, f=f, pager=pager, verify=None)


def _audit_rows(frm, params, pager):
    rows = db.query(AUDIT_COLS + frm + " ORDER BY id DESC LIMIT %s OFFSET %s", list(params) + [PAGE, pager.offset])
    for r in rows:
        r["detail_json"] = json.dumps(r["detail"], sort_keys=True) if r["detail"] is not None else ""
    return rows


@bp.route("/audit-log/verify", methods=["POST"])
@role_required("operator")
def audit_verify():
    ok, count, bad_id, msg = audit.verify_chain()
    ev("audit.verify", success=ok, object_type="audit_log", detail={"records": count, "first_bad_id": bad_id})
    frm = " FROM ui.audit_log"
    pager = paging.Pager(1, PAGE, paging.count(db, frm, [], PAGE))
    return render_template("logs/audit.html", rows=_audit_rows(frm, [], pager),
                           f={"actor": "", "action": "", "result": ""}, pager=pager,
                           verify={"ok": ok, "count": count, "bad_id": bad_id, "message": msg})
