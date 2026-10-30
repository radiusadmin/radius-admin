from flask import Blueprint, render_template

from .. import db, helper_client
from ..security import cfg, has_role, login_required
from ..alerts import LABELS
from ..insight import clean_reason
from ..services import pending_state

bp = Blueprint("dashboard", __name__)


def helper_status():
    try:
        return helper_client.call(cfg()["helper_socket"], "status", timeout=10)
    except helper_client.HelperError as e:
        return {"ok": False, "message": str(e)}


@bp.route("/dashboard")
@login_required
def index():
    status = helper_status()
    counts = db.query_one(
        "SELECT (SELECT count(*) FROM ui.radius_client WHERE enabled) AS clients,"
        " (SELECT count(*) FROM ui.access_rule WHERE enabled) AS rules,"
        " (SELECT count(*) FROM mab_device WHERE enabled) AS mab,"
        " (SELECT count(DISTINCT username) FROM radusergroup WHERE groupname='net-admins') AS switch_admins,"
        " (SELECT count(*) FROM radpostauth WHERE reply='Access-Reject' AND authdate > now() - interval '24 hours') AS rejects_24h,"
        " (SELECT count(*) FROM radpostauth WHERE reply='Access-Accept' AND authdate > now() - interval '24 hours') AS accepts_24h")
    rejects = db.query(
        "SELECT id, authdate, username, authmethod, host(nasipaddress) AS nas, callingstationid, certsan, reason"
        " FROM radpostauth WHERE reply='Access-Reject' ORDER BY authdate DESC LIMIT 10")
    for r in rejects:
        r["reason_text"] = clean_reason(r["reason"])
    ops = db.query_one_optional(
        "SELECT (SELECT count(*) FROM radacct WHERE acctstoptime IS NULL) AS sessions,"
        " (SELECT count(*) FROM mab_pending WHERE NOT ignored) AS unknown_mab,"
        " (SELECT heartbeat_at > now() - interval '3 minutes' FROM ui.monitor_state WHERE id = 1) AS monitor_alive,"
        " (SELECT heartbeat_at FROM ui.monitor_state WHERE id = 1) AS heartbeat_at")
    open_alerts = []
    if ops is not None:
        open_alerts = db.query("SELECT kind, message, opened_at FROM ui.alert WHERE state = 'open'"
                               " ORDER BY opened_at DESC LIMIT 10")
    from .setup import summary
    setup = summary() if has_role("admin") else None
    return render_template("dashboard.html", status=status, counts=counts, rejects=rejects,
                           state=pending_state(), ops=ops, open_alerts=open_alerts, labels=LABELS, setup=setup)
