"""RADIUS clients (NAS) CRUD. Changes take effect after Apply."""
import psycopg2
import psycopg2.errors
from flask import Blueprint, Response, abort, current_app, g, redirect, render_template, request, url_for

from .. import client_import as ci
from .. import db
from ..crypto import generate_radius_secret
from ..flashing import flash
from ..security import cfg, login_required, role_required, stepup_required
from ..services import get_settings, set_setting, unlang
from . import ev, form_bool, form_str
from .auth import inline_stepup

bp = Blueprint("clients", __name__, url_prefix="/clients")


def _radsec_settings():
    try:
        return unlang().validate_radsec_settings(get_settings()["radsec"])
    except ValueError:
        return dict(unlang().RADSEC_DEFAULTS)


@bp.context_processor
def _radsec_ctx():
    return {"radsec_enabled": _radsec_settings()["enabled"]}


TRANSPORTS = ("udp", "radsec")
TRISTATE = ("auto", "yes", "no")
NAS_TYPES = ("other", "cisco", "aruba", "juniper", "hp", "extreme", "fortinet", "paloalto")
KEY_LABELS = {"ok": "ok", "encrypted": "Encrypted key – not usable", "missing": "No key"}


def _get(cid):
    row = db.query_one("SELECT * FROM ui.radius_client WHERE id=%s", (cid,))
    if row is None:
        abort(404)
    return row


LIST_COLS = ("c.id, c.name, c.ipaddr, c.require_ma, c.limit_proxy_state, c.nas_type, c.description, c.enabled,"
             " c.updated_at, c.key_status, c.key_scope, c.dot1x_ports, c.is_switch, c.transport, c.radsec_peer_name,"
             " s.polled_at AS snmp_polled_at, s.reachable AS snmp_reachable, s.error AS snmp_error,"
             " s.sys_name AS snmp_sys_name, s.sys_descr AS snmp_sys_descr, s.dot1x_supported AS snmp_dot1x_supported,"
             " s.dot1x_ports AS snmp_dot1x_ports, s.radius_servers AS snmp_radius_servers")
LIST_FROM = " FROM ui.radius_client c LEFT JOIN ui.switch_status s ON s.client_id = c.id"


@bp.route("/")
@login_required
def index():
    q = request.args.get("q", "").strip()[:100]
    if q:
        rows = db.query("SELECT " + LIST_COLS + LIST_FROM + " WHERE c.name ILIKE %s OR c.ipaddr ILIKE %s"
                        " OR c.description ILIKE %s OR c.dot1x_ports ILIKE %s OR s.sys_name ILIKE %s ORDER BY c.name",
                        ("%" + q + "%",) * 5)
    else:
        rows = db.query("SELECT " + LIST_COLS + LIST_FROM + " ORDER BY c.name")
    mon = db.query_one("SELECT enabled, auto_update_ports FROM ui.snmp_profile WHERE id = 1")
    return render_template("clients/index.html", clients=rows, q=q, key_labels=KEY_LABELS, mon=mon)


def _parse_form(existing=None):
    u = unlang()
    errors = {}
    data = {
        "name": form_str("name", maxlen=63),
        "ipaddr": form_str("ipaddr", maxlen=64),
        "require_ma": form_str("require_ma") or "auto",
        "limit_proxy_state": form_str("limit_proxy_state") or "auto",
        "nas_type": form_str("nas_type") or "other",
        "description": form_str("description", maxlen=200),
        "enabled": form_bool("enabled"),
        "is_switch": form_bool("is_switch"),
        "key_scope": form_str("key_scope") or None,
        "dot1x_ports": form_str("dot1x_ports", maxlen=2000),
        "transport": form_str("transport") or "udp",
        "radsec_peer_name": form_str("radsec_peer_name", maxlen=300),
    }
    if data["transport"] not in TRANSPORTS:
        errors["transport"] = "Choose UDP or RadSec."
    secret_mode = request.form.get("secret_mode", "keep" if existing else "generate")
    for key, fn in (("name", u.validate_client_name), ("ipaddr", u.validate_ipaddr)):
        try:
            r = fn(data[key])
            if isinstance(r, str):
                data[key] = r
        except ValueError as e:
            errors[key] = str(e)
    if data["require_ma"] not in TRISTATE:
        errors["require_ma"] = "Choose auto, yes or no."
    if data["limit_proxy_state"] not in TRISTATE:
        errors["limit_proxy_state"] = "Choose auto, yes or no."
    if data["nas_type"] not in NAS_TYPES:
        errors["nas_type"] = "Choose a NAS type from the list."
    if data["key_scope"] not in (None, "server", "global"):
        errors["key_scope"] = "Choose server, global or none."
    if len(data["dot1x_ports"]) > ci.MAX_DOT1X:
        errors["dot1x_ports"] = "Use at most %d characters." % ci.MAX_DOT1X
    data["secret"] = None
    if data["transport"] == "radsec":
        # Certificate-based (RFC 6614 fixed secret): no shared secret to set, so no step-up.
        try:
            data["radsec_peer_name"] = u.validate_radsec_peer_name(data["radsec_peer_name"])
        except ValueError as e:
            errors["radsec_peer_name"] = str(e)
        data.update(key_status="ok", require_ma="auto", limit_proxy_state="auto")
        return data, errors, "none"
    data["radsec_peer_name"] = ""
    if secret_mode == "generate":
        data["secret"] = generate_radius_secret()
    elif secret_mode == "set":
        secret = request.form.get("secret", "")
        try:
            u.validate_secret(secret)
            data["secret"] = secret
        except ValueError as e:
            errors["secret"] = str(e)
    elif secret_mode != "keep" or not existing:
        errors["secret"] = "Choose how to set the shared secret."
    elif existing.get("transport") == "radsec" and not existing["secret"]:
        errors["secret"] = "This client has no shared secret yet (it used RadSec). Generate or enter one."
    data["key_status"] = "ok" if data["secret"] is not None or not existing else existing["key_status"]
    if data["enabled"] and data["key_status"] != "ok" and "secret" not in errors:
        errors["enabled"] = KEY_NOT_USABLE % KEY_LABELS[data["key_status"]]
    return data, errors, secret_mode


STEPUP_MSG = ("Setting or generating a shared secret requires confirming your identity. "
              "Enter your password and second factor below{}.")


def _secret_stepup(data, errors):
    """L-6: a secret change (set or generate) requires step-up for every role.
    Returns an HTTP status override (401) when step-up is missing or wrong."""
    if errors or data["secret"] is None or g.session.get("stepup_ok"):
        return None
    ok, attempted = inline_stepup(request.form)
    if ok:
        return None
    if g.get("user") is None:  # locked out by the failed attempt
        abort(401)
    data["secret"] = None
    errors["stepup"] = ("Verification failed. Check your password and second factor."
                        if attempted else STEPUP_MSG.format(
                            ", then re-enter the secret" if request.form.get("secret_mode") == "set" else ""))
    return 401


@bp.route("/new", methods=["GET", "POST"])
@role_required("operator")
def new():
    errors, data = {}, {"require_ma": "auto", "limit_proxy_state": "auto", "nas_type": "cisco", "enabled": True}
    if request.method == "POST":
        data, errors, mode = _parse_form()
        if not errors and db.query_one("SELECT 1 FROM ui.radius_client WHERE name=%s", (data["name"],)):
            errors["name"] = "A client with this name already exists."
        status = _secret_stepup(data, errors)
        if status:
            return render_template("clients/form.html", c=data, errors=errors, is_new=True, mode=mode,
                                   tristate=TRISTATE, nas_types=NAS_TYPES, key_labels=KEY_LABELS), status
        if not errors:
            row = db.execute_returning(
                "INSERT INTO ui.radius_client (name, ipaddr, secret, require_ma, limit_proxy_state,"
                " nas_type, description, enabled, key_status, key_scope, dot1x_ports, is_switch,"
                " transport, radsec_peer_name)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'ok',%s,%s,%s,%s,%s) RETURNING id",
                (data["name"], data["ipaddr"], data["secret"] or "", data["require_ma"],
                 data["limit_proxy_state"], data["nas_type"], data["description"], data["enabled"],
                 data["key_scope"], data["dot1x_ports"], data["is_switch"], data["transport"],
                 data["radsec_peer_name"]))
            ev("client.create", object_type="radius_client", object_id=row["id"],
               detail={"name": data["name"], "ipaddr": data["ipaddr"], "require_ma": data["require_ma"],
                       "limit_proxy_state": data["limit_proxy_state"], "nas_type": data["nas_type"],
                       "enabled": data["enabled"], "secret_mode": mode, "transport": data["transport"],
                       "radsec_peer_name": data["radsec_peer_name"]})
            if mode == "generate":
                # The creator needs the generated secret once to configure the NAS.
                flash("Client %s added. Apply changes to make it live." % data["name"], "success")
                return render_template("clients/secret.html", c=dict(data, id=row["id"]),
                                       secret=data["secret"], generated=True)
            flash("Client %s added. Apply changes to make it live." % data["name"], "success")
            return redirect(url_for("clients.index"))
    return render_template("clients/form.html", c=data, errors=errors, is_new=True,
                           tristate=TRISTATE, nas_types=NAS_TYPES, key_labels=KEY_LABELS), (400 if errors else 200)


@bp.route("/<int:cid>/edit", methods=["GET", "POST"])
@role_required("operator")
def edit(cid):
    existing = _get(cid)
    errors, data = {}, dict(existing)
    if request.method == "POST":
        data, errors, mode = _parse_form(existing)
        data["id"] = cid
        if not errors and db.query_one("SELECT 1 FROM ui.radius_client WHERE name=%s AND id<>%s",
                                       (data["name"], cid)):
            errors["name"] = "A client with this name already exists."
        status = _secret_stepup(data, errors)
        if status:
            return render_template("clients/form.html", c=data, errors=errors, is_new=False, mode=mode,
                                   tristate=TRISTATE, nas_types=NAS_TYPES, key_labels=KEY_LABELS), status
        if not errors:
            secret = data["secret"] if data["secret"] is not None else existing["secret"]
            try:
                with db.cursor() as cur:
                    cur.execute("SAVEPOINT client_edit")
                    cur.execute(
                        "UPDATE ui.radius_client SET name=%s, ipaddr=%s, secret=%s, require_ma=%s,"
                        " limit_proxy_state=%s, nas_type=%s, description=%s, enabled=%s, key_status=%s,"
                        " key_scope=%s, dot1x_ports=%s, is_switch=%s, transport=%s, radsec_peer_name=%s,"
                        " updated_at=now() WHERE id=%s",
                        (data["name"], data["ipaddr"], secret, data["require_ma"], data["limit_proxy_state"],
                         data["nas_type"], data["description"], data["enabled"], data["key_status"],
                         data["key_scope"], data["dot1x_ports"], data["is_switch"], data["transport"],
                         data["radsec_peer_name"], cid))
                    cur.execute("RELEASE SAVEPOINT client_edit")
            except psycopg2.errors.CheckViolation:
                db.execute("ROLLBACK TO SAVEPOINT client_edit")
                errors["enabled"] = KEY_NOT_USABLE % KEY_LABELS.get(data["key_status"], data["key_status"])
                data["secret"] = None
                return render_template("clients/form.html", c=data, errors=errors, is_new=False, mode=mode,
                                       tristate=TRISTATE, nas_types=NAS_TYPES, key_labels=KEY_LABELS), 400
            changed = {k: data[k] for k in ("name", "ipaddr", "require_ma", "limit_proxy_state", "nas_type",
                                             "description", "enabled", "key_status", "key_scope", "dot1x_ports", "is_switch",
                                             "transport", "radsec_peer_name")
                       if data[k] != existing[k]}
            ev("client.update", object_type="radius_client", object_id=cid,
               detail={"name": data["name"], "changed": changed,
                       "secret_changed": data["secret"] is not None})
            flash("Client %s saved. Apply changes to make it live." % data["name"], "success")
            if mode == "generate":
                return render_template("clients/secret.html", c=dict(data, id=cid),
                                       secret=data["secret"], generated=True)
            return redirect(url_for("clients.index"))
    status = db.query_one("SELECT * FROM ui.switch_status WHERE client_id = %s", (cid,))
    return render_template("clients/form.html", c=data, errors=errors, is_new=False, status=status,
                           tristate=TRISTATE, nas_types=NAS_TYPES, key_labels=KEY_LABELS), (400 if errors else 200)


@bp.route("/<int:cid>/delete", methods=["POST"])
@role_required("operator")
def delete(cid):
    row = _get(cid)
    db.execute("DELETE FROM ui.radius_client WHERE id=%s", (cid,))
    ev("client.delete", object_type="radius_client", object_id=cid,
       detail={"name": row["name"], "ipaddr": row["ipaddr"]})
    flash("Client %s deleted. Apply changes to remove it from FreeRADIUS." % row["name"], "success")
    return redirect(url_for("clients.index"))


@bp.route("/<int:cid>/secret", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def reveal(cid):
    """Show the shared secret. POST-only reveal so it is never in a GET URL/history."""
    row = _get(cid)
    if row["transport"] == "radsec":
        flash("%s uses RadSec: it authenticates with a certificate and has no shared secret." % row["name"], "info")
        return redirect(url_for("clients.index"))
    secret = None
    if request.method == "POST":
        secret = row["secret"]
        ev("client.secret_reveal", object_type="radius_client", object_id=cid, detail={"name": row["name"]})
    return render_template("clients/secret.html", c=row, secret=secret)


# ------------------------------------------------------------ RadSec listener
def _setting_text(value):
    return ("true" if value else "false") if isinstance(value, bool) else str(value)


@bp.route("/radsec", methods=["GET", "POST"])
@role_required("admin")
def radsec():
    """Server-wide RadSec (RADIUS over TLS) listener. Rendered into the clients file: Needs Apply."""
    u = unlang()
    current = _radsec_settings()
    form, errors = dict(current), []
    tls_clients = db.query("SELECT id, name, ipaddr, enabled, radsec_peer_name FROM ui.radius_client"
                           " WHERE transport = 'radsec' ORDER BY name")
    if request.method == "POST":
        form = {"enabled": form_bool("enabled"), "listen": form_str("listen", maxlen=64) or "*",
                "port": form_str("port", maxlen=6), "max_connections": form_str("max_connections", maxlen=6),
                "idle_timeout": form_str("idle_timeout", maxlen=6), "ocsp": form_bool("ocsp"),
                "ocsp_url": form_str("ocsp_url", maxlen=300)}
        try:
            new = u.validate_radsec_settings(form)
        except ValueError as e:
            errors.append(str(e))
        else:
            in_use = [c["name"] for c in tls_clients if c["enabled"]]
            if not new["enabled"] and in_use:
                errors.append("The listener cannot be turned off while enabled clients use RadSec (%s). "
                              "Disable those clients or switch them to UDP first." % ", ".join(in_use))
            else:
                changed = {k: new[k] for k in new if new[k] != current[k]}
                for k in new:
                    set_setting("radsec_" + k, _setting_text(new[k]))
                ev("radsec.settings", detail={"changed": changed})
                flash("RadSec settings saved. Apply changes to make them live." if changed
                      else "No changes.", "success" if changed else "info")
                return redirect(url_for("clients.radsec"))
    return render_template("clients/radsec.html", s=form, errors=errors, tls_clients=tls_clients,
                           cert_dir=u.CERT_DIR), (400 if errors else 200)


# ------------------------------------------------------------ enable toggle
KEY_NOT_USABLE = ("This client has no usable shared secret (%s). FreeRADIUS needs the plaintext shared "
                  "secret, so the client stays disabled until a plaintext key is entered or generated "
                  "on its edit page.")


@bp.route("/<int:cid>/enable", methods=["POST"])
@role_required("operator")
def set_enabled(cid):
    row = _get(cid)
    enable = request.form.get("enabled") == "1"
    if enable and row["key_status"] != "ok":
        flash(KEY_NOT_USABLE % KEY_LABELS[row["key_status"]], "error")
        return redirect(url_for("clients.index"))
    try:
        with db.cursor() as cur:
            cur.execute("SAVEPOINT client_enable")
            cur.execute("UPDATE ui.radius_client SET enabled=%s, updated_at=now() WHERE id=%s", (enable, cid))
            cur.execute("RELEASE SAVEPOINT client_enable")
    except psycopg2.errors.CheckViolation:
        db.execute("ROLLBACK TO SAVEPOINT client_enable")
        flash(KEY_NOT_USABLE % "key status not ok", "error")
        return redirect(url_for("clients.index"))
    ev("client.enable" if enable else "client.disable", object_type="radius_client", object_id=cid,
       detail={"name": row["name"]})
    flash("Client %s %s. Apply changes to make it live." % (row["name"], "enabled" if enable else "disabled"),
          "success")
    return redirect(url_for("clients.index"))


# ------------------------------------------------------------- CSV import
def _import_options(form):
    opts = {"existing": form.get("existing", "update"), "require_ma": form.get("require_ma", "auto"),
            "is_switch": form.get("is_switch") in ("1", "on", "true", "yes")}
    if opts["existing"] not in ("update", "skip"):
        opts["existing"] = "update"
    if opts["require_ma"] not in TRISTATE:
        opts["require_ma"] = "auto"
    return opts


def _existing_clients():
    return db.query("SELECT id, name, ipaddr, secret, enabled, key_status, key_scope, dot1x_ports, is_switch"
                    " FROM ui.radius_client ORDER BY id")


def _build_plan(text, opts, with_mode=False):
    """Parse + plan. Returns (items, errors) or, with_mode, (items, errors, header_found)."""
    try:
        rows = ci.parse_csv(text, unlang())
    except ci.ImportError_ as e:
        return (None, e.errors, None) if with_mode else (None, e.errors)
    items, errors = ci.plan(rows, _existing_clients(), opts["existing"] == "update", opts["require_ma"],
                            opts.get("is_switch", False))
    res = (None, errors) if errors else (items, [])
    return res + (rows.header_found,) if with_mode else res


@bp.route("/import/template.csv")
@login_required
def import_template():
    return Response(ci.TEMPLATE_CSV, mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="radius-clients-template.csv"'})


@bp.route("/import", methods=["GET", "POST"])
@role_required("operator")
def import_upload():
    opts = _import_options(request.form) if request.method == "POST" else {"existing": "update", "require_ma": "auto", "is_switch": True}
    errors = []
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            errors = ["Choose a CSV file to import."]
        else:
            raw = f.read(ci.MAX_BYTES + 1)
            try:
                text = ci.decode_upload(raw)
            except ci.ImportError_ as e:
                errors = e.errors
            else:
                items, errors, header_found = _build_plan(text, opts, with_mode=True)
                if not errors:
                    staging = cfg()["staging_dir"]
                    import_id = ci.save_pending(staging, current_app.config["RA_DATA_KEY"], g.session["id"],
                                                g.user["id"], {"text": text, "options": opts,
                                                               "fingerprint": ci.fingerprint(items, opts),
                                                               "filename": f.filename[:200]})
                    ev("client.import_preview", object_type="radius_client",
                       detail=dict(ci.counts(items), filename=f.filename[:200], **opts))
                    return render_template("clients/import_preview.html", items=items, counts=ci.counts(items),
                                           opts=opts, import_id=import_id, filename=f.filename[:200],
                                           header_found=header_found)
        ev("client.import_preview", success=False, object_type="radius_client", detail={"errors": len(errors)})
    return render_template("clients/import.html", errors=errors[:100], more=max(0, len(errors) - 100),
                           opts=opts, tristate=TRISTATE), (400 if errors else 200)


@bp.route("/import/confirm", methods=["POST"])
@role_required("operator")
def import_confirm():
    staging = cfg()["staging_dir"]
    import_id = request.form.get("import_id", "")
    payload = ci.load_pending(staging, current_app.config["RA_DATA_KEY"], g.session["id"], g.user["id"], import_id)
    if payload is None:
        flash("This import expired or was already used. Upload the file again.", "error")
        return redirect(url_for("clients.import_upload"))
    opts = payload["options"]
    items, errors = _build_plan(payload["text"], opts)
    if errors:
        ci.delete_pending(staging, import_id)
        return render_template("clients/import.html", errors=["The clients changed since the preview:"] + errors[:100],
                               more=max(0, len(errors) - 100), opts=opts, tristate=TRISTATE), 409
    if ci.fingerprint(items, opts) != payload["fingerprint"]:
        ci.delete_pending(staging, import_id)
        new_id = ci.save_pending(staging, current_app.config["RA_DATA_KEY"], g.session["id"], g.user["id"],
                                 {"text": payload["text"], "options": opts,
                                  "fingerprint": ci.fingerprint(items, opts), "filename": payload.get("filename", "")})
        return render_template("clients/import_preview.html", items=items, counts=ci.counts(items), opts=opts,
                               import_id=new_id, filename=payload.get("filename", ""),
                               error="The clients changed since the preview. Review the updated preview and confirm again."), 409
    if not g.session.get("stepup_ok"):
        ok, attempted = inline_stepup(request.form)
        if not ok:
            if g.get("user") is None:
                return redirect(url_for("auth.login"))
            return render_template("clients/import_preview.html", items=items, counts=ci.counts(items), opts=opts,
                                   import_id=import_id, filename=payload.get("filename", ""),
                                   error=("Verification failed. Check your password and second factor." if attempted
                                          else "Importing sets shared secrets. Confirm your identity to continue.")), 401
    created, updated = [], []
    try:
        with db.cursor() as cur:
            cur.execute("SAVEPOINT client_import")
            for it in items:
                if it["action"] == "new":
                    cur.execute(
                        "INSERT INTO ui.radius_client (name, ipaddr, secret, require_ma, nas_type, enabled,"
                        " key_status, key_scope, dot1x_ports, is_switch) VALUES (%s,%s,%s,%s,'other',%s,%s,%s,%s,%s)",
                        (it["hostname"], it["ip"], it["secret"] or "", it["require_ma"], it["enabled"],
                         it["key_status"], it["key_scope"], it["dot1x_ports"], it["is_switch"]))
                    created.append(it["hostname"])
                elif it["action"] == "update":
                    if it["secret"] is not None:
                        cur.execute("UPDATE ui.radius_client SET name=%s, ipaddr=%s, key_scope=%s, dot1x_ports=%s,"
                                    " is_switch=%s, secret=%s, key_status='ok', updated_at=now() WHERE id=%s",
                                    (it["hostname"], it["ip"], it["key_scope"], it["dot1x_ports"], it["is_switch"],
                                     it["secret"], it["id"]))
                    else:
                        cur.execute("UPDATE ui.radius_client SET name=%s, ipaddr=%s, key_scope=%s, dot1x_ports=%s,"
                                    " is_switch=%s, updated_at=now() WHERE id=%s",
                                    (it["hostname"], it["ip"], it["key_scope"], it["dot1x_ports"], it["is_switch"], it["id"]))
                    updated.append(it["hostname"])
            cur.execute("RELEASE SAVEPOINT client_import")
    except psycopg2.Error as e:
        db.execute("ROLLBACK TO SAVEPOINT client_import")
        ev("client.import", success=False, object_type="radius_client",
           detail={"error": type(e).__name__, **opts})
        return render_template("clients/import.html", errors=["Nothing was imported: the database refused the change "
                                                              "(%s). Upload the file again." % type(e).__name__],
                               more=0, opts=opts, tristate=TRISTATE), 409
    ci.delete_pending(staging, import_id)
    c = ci.counts(items)
    ev("client.import", object_type="radius_client",
       detail=dict(c, created=created, updated=updated, filename=payload.get("filename", ""),
                   secrets_set=sum(1 for it in items if it["action"] in ("new", "update") and it["secret"] is not None),
                   disabled_without_key=[it["hostname"] for it in items
                                         if it["action"] == "new" and it["key_status"] != "ok"], **opts))
    return render_template("clients/import_done.html", counts=c, created=created, updated=updated,
                           no_key=[it for it in items if it["action"] == "new" and it["key_status"] != "ok"])


@bp.route("/import/cancel", methods=["POST"])
@role_required("operator")
def import_cancel():
    ci.delete_pending(cfg()["staging_dir"], request.form.get("import_id", ""))
    flash("Import cancelled. Nothing was changed.", "info")
    return redirect(url_for("clients.index"))
