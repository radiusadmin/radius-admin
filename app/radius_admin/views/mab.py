"""MAB devices (public.mab_device). Read live by FreeRADIUS: no Apply needed.

SPEC section 13: optional expiry (expires_at), vendor names (oui.py) and the
unknown-device queue (public.mab_pending, filled by radius_admin_mab_hex()).
"""
import csv
import datetime
import io

from flask import Blueprint, abort, redirect, render_template, request, url_for

from .. import db, oui
from ..flashing import flash
from ..insight import ClientIndex
from ..security import login_required, role_required
from ..services import get_settings, set_setting, unlang
from . import ev, form_bool, form_str

bp = Blueprint("mab", __name__, url_prefix="/mab")
PAGE = 100
MAX_IMPORT = 5000
MAX_IMPORT_LINES = 10000
MAX_IMPORT_BYTES = 1024 * 1024


def _get(mid):
    row = db.query_one("SELECT * FROM mab_device WHERE id=%s", (mid,))
    if row is None:
        abort(404)
    return row


@bp.route("/")
@login_required
def index():
    q = request.args.get("q", "").strip()[:100]
    show = request.args.get("show", "")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    where, params = [], []
    if q:
        where.append("(mac ILIKE %s OR description ILIKE %s OR vlan::text = %s)")
        qm = q.upper().replace(":", "-").replace(".", "")
        params += ["%" + qm + "%", "%" + q + "%", q]
    if show == "expired":
        where.append("expires_at IS NOT NULL AND expires_at <= now()")
    elif show == "expiring":
        where.append("expires_at > now() AND expires_at <= now() + interval '14 days'")
    w = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one("SELECT count(*) AS n FROM mab_device" + w, params)["n"]
    rows = db.query("SELECT *, (expires_at IS NOT NULL AND expires_at <= now()) AS expired"
                    " FROM mab_device" + w + " ORDER BY mac LIMIT %s OFFSET %s",
                    params + [PAGE, (page - 1) * PAGE])
    return render_template("mab/index.html", devices=rows, q=q, show=show, page=page, total=total,
                           pages=max(1, (total + PAGE - 1) // PAGE), counts=_counts())


def _counts():
    return db.query_one(
        "SELECT (SELECT count(*) FROM mab_pending WHERE NOT ignored) AS pending,"
        " (SELECT count(*) FROM mab_device WHERE expires_at IS NOT NULL AND expires_at <= now()) AS expired,"
        " (SELECT count(*) FROM mab_device WHERE expires_at > now()"
        "  AND expires_at <= now() + interval '14 days') AS expiring")


EXPIRY_CHOICES = (("", "Never"), ("1", "1 day"), ("7", "7 days"), ("30", "30 days"), ("90", "90 days"),
                  ("365", "1 year"))


def parse_expiry_date(text):
    """'YYYY-MM-DD' -> end of that day UTC (the next midnight). '' -> None.
    Raises ValueError for bad or past dates."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        d = datetime.date.fromisoformat(text)
    except ValueError:
        raise ValueError("Enter the date as YYYY-MM-DD.") from None
    end = datetime.datetime.combine(d + datetime.timedelta(days=1), datetime.time(0, 0),
                                    tzinfo=datetime.timezone.utc)
    if end <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("The expiry date is in the past.")
    if d.year > 2100:
        raise ValueError("Choose a date before 2100.")
    return end


def expiry_from_days(days):
    days = (days or "").strip()
    if not days:
        return None
    if days not in {k for k, _ in EXPIRY_CHOICES}:
        raise ValueError("Choose an expiry from the list.")
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=int(days))


def expiry_date_value(expires_at):
    """expires_at -> the YYYY-MM-DD shown in the form (the last day of access)."""
    if not expires_at:
        return ""
    return (expires_at.astimezone(datetime.timezone.utc) - datetime.timedelta(seconds=1)).date().isoformat()


def _parse():
    u = unlang()
    errors, d = {}, {"description": form_str("description", maxlen=200), "enabled": form_bool("enabled"),
                     "mac": form_str("mac", maxlen=40), "vlan": form_str("vlan", maxlen=8),
                     "expires": form_str("expires", maxlen=20), "expires_at": None}
    try:
        d["expires_at"] = parse_expiry_date(d["expires"])
    except ValueError as e:
        errors["expires"] = str(e)
    try:
        d["mac"] = u.validate_mac(d["mac"])
    except ValueError as e:
        errors["mac"] = str(e)
    try:
        u.validate_vlan(d["vlan"])
        d["vlan"] = int(d["vlan"])
    except (ValueError, TypeError) as e:
        errors["vlan"] = str(e) or "VLAN must be 1-4094."
    return d, errors


@bp.route("/new", methods=["GET", "POST"])
@role_required("operator")
def new():
    d, errors = {"enabled": True, "mac": request.args.get("mac", "")[:40]}, {}
    if request.method == "POST":
        d, errors = _parse()
        if not errors and db.query_one("SELECT 1 FROM mab_device WHERE mac=%s", (d["mac"],)):
            errors["mac"] = "This MAC address is already registered."
        if not errors:
            row = db.execute_returning(
                "INSERT INTO mab_device (mac, vlan, description, enabled, expires_at) VALUES (%s,%s,%s,%s,%s)"
                " RETURNING id", (d["mac"], d["vlan"], d["description"], d["enabled"], d["expires_at"]))
            db.execute("DELETE FROM mab_pending WHERE mac=%s", (d["mac"],))
            ev("mab.create", object_type="mab_device", object_id=row["id"],
               detail={"mac": d["mac"], "vlan": d["vlan"], "enabled": d["enabled"],
                       "expires_at": d["expires_at"].isoformat() if d["expires_at"] else None})
            flash("Device %s registered. This is live now." % d["mac"], "success")
            return redirect(url_for("mab.index"))
    return render_template("mab/form.html", d=d, errors=errors, is_new=True), (400 if errors else 200)


@bp.route("/<int:mid>/edit", methods=["GET", "POST"])
@role_required("operator")
def edit(mid):
    existing = _get(mid)
    d, errors = dict(existing), {}
    d["expires"] = expiry_date_value(existing["expires_at"])
    if request.method == "POST":
        d, errors = _parse()
        d["id"] = mid
        # an unchanged (already past) expiry date may be kept while editing other fields
        if errors.get("expires") and d["expires"] == expiry_date_value(existing["expires_at"]):
            errors.pop("expires")
            d["expires_at"] = existing["expires_at"]
        if not errors and db.query_one("SELECT 1 FROM mab_device WHERE mac=%s AND id<>%s", (d["mac"], mid)):
            errors["mac"] = "This MAC address is already registered."
        if not errors:
            db.execute("UPDATE mab_device SET mac=%s, vlan=%s, description=%s, enabled=%s, expires_at=%s,"
                       " updated_at=now() WHERE id=%s",
                       (d["mac"], d["vlan"], d["description"], d["enabled"], d["expires_at"], mid))

            def _exp(v):
                return v.isoformat() if v else None
            ev("mab.update", object_type="mab_device", object_id=mid,
               detail={"before": {"mac": existing["mac"], "vlan": existing["vlan"], "enabled": existing["enabled"],
                                  "expires_at": _exp(existing["expires_at"])},
                       "after": {"mac": d["mac"], "vlan": d["vlan"], "enabled": d["enabled"],
                                 "expires_at": _exp(d["expires_at"])}})
            flash("Device %s saved. This is live now." % d["mac"], "success")
            return redirect(url_for("mab.index"))
    return render_template("mab/form.html", d=d, errors=errors, is_new=False), (400 if errors else 200)


@bp.route("/<int:mid>/delete", methods=["POST"])
@role_required("operator")
def delete(mid):
    row = _get(mid)
    db.execute("DELETE FROM mab_device WHERE id=%s", (mid,))
    ev("mab.delete", object_type="mab_device", object_id=mid, detail={"mac": row["mac"], "vlan": row["vlan"]})
    flash("Device %s removed. This is live now." % row["mac"], "success")
    return redirect(url_for("mab.index"))


def parse_csv(text):
    """Parse mac,vlan,description lines. Returns (records, errors). Header row optional."""
    u = unlang()
    records, errors, seen = [], [], set()
    if len(text) > MAX_IMPORT_BYTES:
        return [], ["The input is larger than 1 MiB. Split it into smaller files."]
    reader = csv.reader(io.StringIO(text))
    try:
        for lineno, row in enumerate(reader, start=1):
            if lineno > MAX_IMPORT_LINES:
                errors.append("Too many lines (limit %d)." % MAX_IMPORT_LINES)
                break
            if _parse_row(u, lineno, row, records, errors, seen):
                break
    except csv.Error as e:
        errors.append("Line %d: not valid CSV (%s)." % (reader.line_num, str(e)[:100]))
    return records, errors


def _parse_row(u, lineno, row, records, errors, seen):
    """Validate one CSV row. Returns True to stop parsing."""
    if not row or all(not c.strip() for c in row) or row[0].strip().startswith("#"):
        return False
    if lineno == 1 and row[0].strip().lower() == "mac":
        return False
    if len(row) < 2 or len(row) > 4:
        errors.append("Line %d: expected mac,vlan,description[,expires]." % lineno)
        return False
    try:
        mac = u.validate_mac(row[0].strip())
        u.validate_vlan(row[1].strip())
        vlan = int(row[1].strip())
        expires_at = parse_expiry_date(row[3]) if len(row) == 4 else None
    except (ValueError, TypeError) as e:
        errors.append("Line %d: %s" % (lineno, e))
        return False
    desc = row[2].strip()[:200] if len(row) >= 3 else ""
    if mac in seen:
        errors.append("Line %d: %s appears more than once." % (lineno, mac))
        return False
    seen.add(mac)
    records.append((mac, vlan, desc, expires_at))
    if len(records) > MAX_IMPORT:
        errors.append("Too many rows (limit %d)." % MAX_IMPORT)
        return True
    return False


@bp.route("/import", methods=["GET", "POST"])
@role_required("operator")
def import_csv():
    errors, result = [], None
    if request.method == "POST":
        f = request.files.get("file")
        text = request.form.get("text", "")
        if f and f.filename:
            try:
                text = f.read(1024 * 1024 + 1).decode("utf-8-sig")
            except UnicodeDecodeError:
                errors.append("The file must be UTF-8 text.")
        if not errors and not text.strip():
            errors.append("Choose a CSV file or paste rows.")
        mode = request.form.get("mode", "add")
        if not errors:
            records, errors = parse_csv(text)
        if not errors:
            added = updated = skipped = 0
            for mac, vlan, desc, expires_at in records:
                ex = db.query_one("SELECT id FROM mab_device WHERE mac=%s", (mac,))
                if ex and mode == "upsert":
                    # an empty expires column keeps the device's current expiry
                    db.execute("UPDATE mab_device SET vlan=%s, description=%s,"
                               " expires_at=coalesce(%s, expires_at), updated_at=now() WHERE id=%s",
                               (vlan, desc, expires_at, ex["id"]))
                    updated += 1
                elif ex:
                    skipped += 1
                else:
                    db.execute("INSERT INTO mab_device (mac, vlan, description, expires_at) VALUES (%s,%s,%s,%s)",
                               (mac, vlan, desc, expires_at))
                    db.execute("DELETE FROM mab_pending WHERE mac=%s", (mac,))
                    added += 1
            result = {"added": added, "updated": updated, "skipped": skipped}
            ev("mab.import", object_type="mab_device", detail=dict(result, mode=mode))
            flash("Import finished: %(added)d added, %(updated)d updated, %(skipped)d already present. "
                  "This is live now." % result, "success")
            return redirect(url_for("mab.index"))
        ev("mab.import", success=False, object_type="mab_device", detail={"errors": len(errors)})
    return render_template("mab/import.html", errors=errors[:50], more=max(0, len(errors) - 50)), (
        400 if errors else 200)


# ---------------------------------------------------------------- unknown devices
PENDING_PAGE = 100


def _default_vlan():
    v = get_settings().get("mab_default_vlan", "")
    return v if v.isdigit() else ""


@bp.route("/unknown")
@login_required
def pending():
    show_ignored = request.args.get("ignored") == "1"
    q = request.args.get("q", "").strip()[:100]
    rows = db.query("SELECT p.*, host(p.nas_ip) AS nas FROM mab_pending p WHERE ignored = %s"
                    " ORDER BY p.last_seen DESC", (show_ignored,))
    idx = ClientIndex.load()
    out = []
    qm = q.upper().replace(":", "-").replace(".", "")
    for r in rows:
        c = idx.find(r["nas"])
        r["switch_name"], r["client_id"] = (c["name"], c["id"]) if c else (None, None)
        if q and not (qm in r["mac"] or (r["nas"] or "").startswith(q) or q.lower() in (r["nas_port_id"] or "").lower()
                      or q.lower() in (r["switch_name"] or "").lower() or q.lower() in oui.vendor(r["mac"]).lower()):
            continue
        out.append(r)
        if len(out) >= PENDING_PAGE:
            break
    rows = out
    return render_template("mab/pending.html", rows=rows, q=q, show_ignored=show_ignored, counts=_counts(),
                           default_vlan=_default_vlan(), expiry_choices=EXPIRY_CHOICES)


def _pending_row(mac):
    u = unlang()
    try:
        mac = u.validate_mac(mac)
    except ValueError:
        abort(404)
    row = db.query_one("SELECT * FROM mab_pending WHERE mac=%s", (mac,))
    if row is None:
        abort(404)
    return row


def _back():
    return redirect(url_for("mab.pending", ignored="1" if request.form.get("from_ignored") else None))


@bp.route("/unknown/<mac>/approve", methods=["POST"])
@role_required("operator")
def approve(mac):
    p = _pending_row(mac)
    u = unlang()
    vlan = form_str("vlan", maxlen=8)
    desc = form_str("description", maxlen=200)
    try:
        u.validate_vlan(vlan)
        vlan = int(vlan)
    except (ValueError, TypeError):
        flash("%s: enter a VLAN between 1 and 4094." % p["mac"], "error")
        return _back()
    try:
        expires_at = expiry_from_days(request.form.get("expires_days", ""))
    except ValueError as e:
        flash(str(e), "error")
        return _back()
    if db.query_one("SELECT 1 FROM mab_device WHERE mac=%s", (p["mac"],)):
        db.execute("DELETE FROM mab_pending WHERE mac=%s", (p["mac"],))
        flash("%s is already registered." % p["mac"], "info")
        return _back()
    if not desc:
        where = " on %s %s" % (p["nas_ip"] or "", p["nas_port_id"] or "") if p["nas_ip"] else ""
        desc = ("Approved from the unknown-device queue" + where).strip()[:200]
    row = db.execute_returning(
        "INSERT INTO mab_device (mac, vlan, description, enabled, expires_at) VALUES (%s,%s,%s,true,%s) RETURNING id",
        (p["mac"], vlan, desc, expires_at))
    db.execute("DELETE FROM mab_pending WHERE mac=%s", (p["mac"],))
    ev("mab.approve", object_type="mab_device", object_id=row["id"],
       detail={"mac": p["mac"], "vlan": vlan, "attempts": p["attempts"],
               "nas_ip": str(p["nas_ip"]) if p["nas_ip"] else None, "nas_port_id": p["nas_port_id"],
               "expires_at": expires_at.isoformat() if expires_at else None})
    flash("%s approved into VLAN %d. The switch admits it at its next MAB attempt "
          "(usually within a minute). This is live now." % (p["mac"], vlan), "success")
    return _back()


@bp.route("/unknown/<mac>/ignore", methods=["POST"])
@role_required("operator")
def ignore(mac):
    p = _pending_row(mac)
    on = request.form.get("on", "1") == "1"
    db.execute("UPDATE mab_pending SET ignored=%s WHERE mac=%s", (on, p["mac"]))
    ev("mab.pending_ignore" if on else "mab.pending_unignore", object_type="mab_pending", detail={"mac": p["mac"]})
    flash(("%s hidden from the queue. It stays rejected." if on else "%s is back in the queue.") % p["mac"],
          "success")
    return _back()


@bp.route("/unknown/<mac>/dismiss", methods=["POST"])
@role_required("operator")
def dismiss(mac):
    p = _pending_row(mac)
    db.execute("DELETE FROM mab_pending WHERE mac=%s", (p["mac"],))
    ev("mab.pending_dismiss", object_type="mab_pending", detail={"mac": p["mac"]})
    flash("%s removed from the queue. It reappears if it tries again." % p["mac"], "success")
    return _back()


@bp.route("/unknown/default-vlan", methods=["POST"])
@role_required("operator")
def default_vlan():
    v = form_str("default_vlan", maxlen=8)
    if v:
        try:
            unlang().validate_vlan(v)
        except (ValueError, TypeError):
            flash("Default VLAN must be 1-4094 (or empty).", "error")
            return redirect(url_for("mab.pending"))
    old = _default_vlan()
    set_setting("mab_default_vlan", v)
    ev("setting.update", object_type="setting", object_id="mab_default_vlan", detail={"from": old, "to": v})
    flash("Default VLAN for approvals saved." if v else "Default VLAN cleared.", "success")
    return redirect(url_for("mab.pending"))
