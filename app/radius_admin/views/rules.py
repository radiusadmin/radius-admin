"""Access rules (802.1X VLAN assignment). Live: FreeRADIUS evaluates them on every
request through SQL function radius_admin_vlan() (SPEC section 10)."""
from flask import Blueprint, abort, redirect, render_template, request, url_for

from .. import db
from ..flashing import flash
from ..security import login_required, role_required
from ..services import load_rules, unlang
from . import ev, form_bool, form_str

bp = Blueprint("rules", __name__, url_prefix="/rules")


def _get(rid):
    row = db.query_one("SELECT * FROM ui.access_rule WHERE id=%s", (rid,))
    if row is None:
        abort(404)
    return row


def grouped(rules):
    """Wired group first, then SSID groups in order of lowest rule id (as rendered)."""
    wired = [r for r in rules if r["connection"] == "wired"]
    ssids = {}
    for r in sorted((r for r in rules if r["connection"] == "wireless"), key=lambda r: r["id"]):
        ssids.setdefault(r["ssid"], [])
    for r in rules:
        if r["connection"] == "wireless":
            ssids[r["ssid"]].append(r)
    groups = [("Wired (Ethernet)", None, sorted(wired, key=lambda r: (r["priority"], r["id"])))]
    for ssid, rs in ssids.items():
        groups.append(("Wireless: " + ssid, ssid, sorted(rs, key=lambda r: (r["priority"], r["id"]))))
    return groups


WIRELESS_PORT_TYPE = "Wireless-802.11"


def _match_test(form):
    """Ask radius_admin_vlan() (the same matcher FreeRADIUS uses, via radius_admin_vlan_hex) for a VLAN."""
    conn_type = form.get("t_connection", "wired")
    ssid = (form.get("t_ssid") or "").strip()[:64]
    called = (form.get("t_called") or "").strip()[:253]
    raw_groups = (form.get("t_groups") or "")[:8000]
    groups = [g.strip() for g in raw_groups.replace("\r", "").split("\n") if g.strip()][:200]
    t = {"connection": conn_type, "ssid": ssid, "called": called, "groups_text": raw_groups,
         "groups": groups, "errors": []}
    if conn_type not in ("wired", "wireless"):
        t["errors"].append("Choose wired or wireless.")
    if conn_type == "wireless" and not (ssid or called):
        t["errors"].append("Enter the SSID or a full Called-Station-Id.")
    if not groups:
        t["errors"].append("Enter at least one AD group name.")
    if any("," in g for g in groups):
        t["errors"].append("Group names cannot contain commas (FreeRADIUS passes the list comma-separated).")
    if t["errors"]:
        return t
    port_type = "Ethernet" if conn_type == "wired" else WIRELESS_PORT_TYPE
    if conn_type == "wired":
        called_station = called
    else:
        called_station = called or ("00-00-00-00-00-00:" + ssid)
    t["port_type"], t["called_station"] = port_type, called_station
    row = db.query_one("SELECT radius_admin_vlan(%s, %s, %s) AS vlan",
                       (port_type, called_station, ",".join(groups)))
    t["vlan"] = row["vlan"]
    # Explain which rule produced it (display only; the VLAN above is authoritative).
    lowered = [g.lower() for g in groups]
    if conn_type == "wired":
        cand = db.query("SELECT id, priority, connection, ssid, ad_group, vlan FROM ui.access_rule"
                        " WHERE enabled AND connection='wired' AND lower(ad_group) = ANY(%s)"
                        " ORDER BY priority, id LIMIT 1", (lowered,))
    else:
        cand = db.query("SELECT id, priority, connection, ssid, ad_group, vlan FROM ui.access_rule"
                        " WHERE enabled AND connection='wireless' AND ssid IS NOT NULL AND %s <> ''"
                        " AND right(%s, length(ssid) + 1) = ':' || ssid AND lower(ad_group) = ANY(%s)"
                        " ORDER BY priority, id LIMIT 1", (called_station, called_station, lowered))
    t["rule"] = cand[0] if cand else None
    if t["rule"] is not None and str(t["rule"]["vlan"]) != str(t["vlan"]):
        t["rule"] = None  # never show an explanation that disagrees with the function
    t["unknown_ssid"] = False
    if conn_type == "wireless" and t["vlan"] is None:
        known = db.query_one("SELECT 1 AS x FROM ui.access_rule WHERE enabled AND connection='wireless'"
                             " AND ssid IS NOT NULL AND %s <> '' AND right(%s, length(ssid) + 1) = ':' || ssid",
                             (called_station, called_station))
        t["unknown_ssid"] = known is None
    return t


@bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Rule list plus the read-only "test a match" tool. The POST only carries test
    inputs and changes nothing, so every role may use it."""
    test = _match_test(request.form) if request.method == "POST" else None
    rules = load_rules()
    return render_template("rules/index.html", groups=grouped(rules), count=len(rules), test=test,
                           wireless_port_type=WIRELESS_PORT_TYPE), (400 if test and test["errors"] else 200)


def _parse():
    u = unlang()
    errors = {}
    d = {"connection": form_str("connection"), "ssid": form_str("ssid", maxlen=64) or None,
         "ad_group": form_str("ad_group", maxlen=128), "description": form_str("description", maxlen=200),
         "enabled": form_bool("enabled")}
    try:
        d["priority"] = int(form_str("priority") or "0")
        if not 0 <= d["priority"] <= 100000:
            raise ValueError
    except ValueError:
        errors["priority"] = "Priority must be a whole number from 0 to 100000."
        d["priority"] = form_str("priority")
    if d["connection"] not in ("wired", "wireless"):
        errors["connection"] = "Choose wired or wireless."
    if d["connection"] == "wireless":
        try:
            u.validate_ssid(d["ssid"] or "")
        except ValueError as e:
            errors["ssid"] = str(e)
    else:
        d["ssid"] = None
    try:
        u.validate_ad_group(d["ad_group"])
    except ValueError as e:
        errors["ad_group"] = str(e)
    try:
        r = u.validate_vlan(form_str("vlan"))
        d["vlan"] = int(r) if r is not None else int(form_str("vlan"))
    except (ValueError, TypeError) as e:
        errors["vlan"] = str(e) or "VLAN must be 1-4094."
        d["vlan"] = form_str("vlan")
    return d, errors


@bp.route("/new", methods=["GET", "POST"])
@role_required("operator")
def new():
    d, errors = {"connection": "wired", "priority": 100, "enabled": True}, {}
    if request.method == "POST":
        d, errors = _parse()
        if not errors:
            row = db.execute_returning(
                "INSERT INTO ui.access_rule (priority, connection, ssid, ad_group, vlan, description, enabled)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (d["priority"], d["connection"], d["ssid"], d["ad_group"], d["vlan"], d["description"], d["enabled"]))
            ev("rule.create", object_type="access_rule", object_id=row["id"],
               detail={k: d[k] for k in ("priority", "connection", "ssid", "ad_group", "vlan", "enabled")})
            flash("Rule added. It applies from the next authentication.", "success")
            return redirect(url_for("rules.index"))
    return render_template("rules/form.html", r=d, errors=errors, is_new=True), (400 if errors else 200)


@bp.route("/<int:rid>/edit", methods=["GET", "POST"])
@role_required("operator")
def edit(rid):
    existing = _get(rid)
    d, errors = dict(existing), {}
    if request.method == "POST":
        d, errors = _parse()
        d["id"] = rid
        if not errors:
            db.execute("UPDATE ui.access_rule SET priority=%s, connection=%s, ssid=%s, ad_group=%s, vlan=%s,"
                       " description=%s, enabled=%s, updated_at=now() WHERE id=%s",
                       (d["priority"], d["connection"], d["ssid"], d["ad_group"], d["vlan"],
                        d["description"], d["enabled"], rid))
            ev("rule.update", object_type="access_rule", object_id=rid,
               detail={"before": {k: existing[k] for k in ("priority", "connection", "ssid", "ad_group", "vlan", "enabled")},
                       "after": {k: d[k] for k in ("priority", "connection", "ssid", "ad_group", "vlan", "enabled")}})
            flash("Rule saved. It applies from the next authentication.", "success")
            return redirect(url_for("rules.index"))
    return render_template("rules/form.html", r=d, errors=errors, is_new=False), (400 if errors else 200)


@bp.route("/<int:rid>/delete", methods=["POST"])
@role_required("operator")
def delete(rid):
    row = _get(rid)
    db.execute("DELETE FROM ui.access_rule WHERE id=%s", (rid,))
    ev("rule.delete", object_type="access_rule", object_id=rid,
       detail={k: row[k] for k in ("priority", "connection", "ssid", "ad_group", "vlan")})
    flash("Rule deleted. It no longer applies from the next authentication.", "success")
    return redirect(url_for("rules.index"))


@bp.route("/<int:rid>/move", methods=["POST"])
@role_required("operator")
def move(rid):
    """Swap priority with the neighbour in the same group (wired / same SSID)."""
    row = _get(rid)
    direction = request.form.get("direction")
    if direction not in ("up", "down"):
        abort(400)
    peers = db.query(
        "SELECT id, priority FROM ui.access_rule WHERE connection=%s AND ssid IS NOT DISTINCT FROM %s"
        " ORDER BY priority, id", (row["connection"], row["ssid"]))
    ids = [p["id"] for p in peers]
    i = ids.index(rid)
    j = i - 1 if direction == "up" else i + 1
    if 0 <= j < len(ids):
        # Renumber the group 10, 20, 30... in the new order to keep priorities distinct.
        ids[i], ids[j] = ids[j], ids[i]
        for n, pid in enumerate(ids, start=1):
            db.execute("UPDATE ui.access_rule SET priority=%s, updated_at=now() WHERE id=%s", (n * 10, pid))
        ev("rule.reorder", object_type="access_rule", object_id=rid,
           detail={"direction": direction, "order": ids})
        flash("Rule order changed. It applies from the next authentication.", "success")
    return redirect(url_for("rules.index"))
