"""Integrations: second-factor providers for device admin logins (SPEC section 29).

Providers (ui.mfa_provider) reach FreeRADIUS through the clients file, so adding, changing
or removing one needs Apply. The policy (which logins need a second factor) and the
exemptions are read live by FreeRADIUS on every login. Admin + step-up for every change.
"""
import json
import re

from flask import Blueprint, abort, redirect, render_template, request, url_for

from .. import db, integrations as ig
from ..flashing import flash
from ..security import cfg, login_required, role_required, stepup_required
from ..services import SWITCH_GROUP, get_settings, load_clients, pending_state, unlang
from . import ev, form_bool, form_str

bp = Blueprint("integrations", __name__, url_prefix="/integrations")

_EXEMPT_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}")


def _fips():
    return bool(cfg()["require_fips"])


def _remote_allowed():
    # A remote server receives the password protected only by RADIUS's own MD5-based hiding
    # (RFC 2865); not offered in FIPS mode (SPEC section 29).
    return not _fips()


def _local_admins():
    return {r["username"].lower(): r["username"] for r in db.query(
        "SELECT DISTINCT username FROM radusergroup WHERE groupname = %s", (SWITCH_GROUP,))}


@bp.route("/")
@login_required
def index():
    providers = ig.load_providers()
    clients = {c["id"]: c["name"] for c in load_clients()}
    return render_template("integrations/index.html", providers=providers, policy=ig.load_policy(),
                           exempt=ig.load_exempt(), clients=clients, type_labels=ig.TYPE_LABELS,
                           kind_labels=ig.KIND_LABELS, in_use=ig.providers_in_use(),
                           remote_allowed=_remote_allowed(), fips=_fips(), s=get_settings())


# ---------------------------------------------------------------- remote RADIUS MFA servers
def _remote_form(existing):
    """Validate the remote server form. Returns (values, secret or None, errors)."""
    u = unlang()
    errors = {}
    v = {"id": existing["id"] if existing else form_str("id", maxlen=32).lower(),
         "label": form_str("label", maxlen=100),
         "address": form_str("address", maxlen=64),
         "port": form_str("port", maxlen=5) or "1812",
         "timeout": form_str("timeout", maxlen=2) or str(u.MFA_TIMEOUT_DEFAULT),
         "require_ma": "yes" if form_bool("require_ma") else "no",
         "enabled": form_bool("enabled")}
    if not existing:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", v["id"]):
            errors["id"] = "1-32 lower-case letters, digits or hyphens, starting with a letter."
        elif ig.get_provider(v["id"]):
            errors["id"] = "A provider with this id already exists."
    secret = request.form.get("secret", "")
    if secret or not existing:
        try:
            u.validate_secret(secret)
        except ValueError as e:
            errors["secret"] = str(e)
    try:
        checked = u.validate_mfa_provider(dict(v, type="radius-mfa", secret=secret if secret else "x" * 16))
        v.update(address=checked["address"], port=checked["port"], timeout=checked["timeout"])
    except ValueError as e:
        msg = str(e)
        key = "port" if "port" in msg else "timeout" if "timeout" in msg else "address"
        if key == "address" and "not a network" not in msg:
            msg = "Enter one IPv4 or IPv6 address, for example 192.0.2.50."
        errors.setdefault(key, msg.split(": ", 1)[-1])
    return v, (secret or None), errors


@bp.route("/remote/new", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def remote_new():
    if not _remote_allowed():
        abort(404)
    errors, v = {}, {"port": 1812, "timeout": unlang().MFA_TIMEOUT_DEFAULT, "require_ma": "yes", "enabled": True}
    if request.method == "POST":
        v, secret, errors = _remote_form(None)
        if not errors:
            settings = {"address": v["address"], "port": v["port"], "timeout": v["timeout"],
                        "require_ma": v["require_ma"]}
            db.execute("INSERT INTO ui.mfa_provider (id, type, label, enabled, settings, secrets_enc)"
                       " VALUES (%s, 'radius-mfa', %s, %s, %s::jsonb, %s)",
                       (v["id"], v["label"], v["enabled"], json.dumps(settings),
                        ig.encrypt_secrets(ig.data_key(), v["id"], {"secret": secret})))
            ev("integration.provider_create", object_type="mfa_provider", object_id=v["id"],
               detail=dict(settings, type="radius-mfa", enabled=v["enabled"], shared_key_set=True))
            flash("Remote MFA server %s added. Apply changes so FreeRADIUS can reach it." % v["id"], "success")
            return redirect(url_for("integrations.index"))
    return render_template("integrations/remote.html", v=v, errors=errors, is_new=True), (400 if errors else 200)


@bp.route("/<pid>/edit", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def remote_edit(pid):
    p = ig.get_provider(pid)
    if p is None or p["type"] != "radius-mfa" or not _remote_allowed():
        abort(404)
    errors = {}
    v = dict(p["settings"], id=p["id"], label=p["label"], enabled=p["enabled"])
    if request.method == "POST":
        v, secret, errors = _remote_form(p)
        if not errors and not v["enabled"] and _policy_uses(pid):
            errors["enabled"] = ("A second-factor rule uses this server. Choose another provider there, or"
                                 " turn the rule off, before you turn the server off.")
        if not errors:
            settings = {"address": v["address"], "port": v["port"], "timeout": v["timeout"],
                        "require_ma": v["require_ma"]}
            if secret:
                db.execute("UPDATE ui.mfa_provider SET secrets_enc=%s WHERE id=%s",
                           (ig.encrypt_secrets(ig.data_key(), pid, {"secret": secret}), pid))
            db.execute("UPDATE ui.mfa_provider SET label=%s, enabled=%s, settings=%s::jsonb, updated_at=now()"
                       " WHERE id=%s", (v["label"], v["enabled"], json.dumps(settings), pid))
            changed = {k: {"from": p["settings"].get(k), "to": settings[k]} for k in settings
                       if p["settings"].get(k) != settings[k]}
            if p["enabled"] != v["enabled"]:
                changed["enabled"] = {"from": p["enabled"], "to": v["enabled"]}
            if secret:
                changed["shared_key_updated"] = True
            ev("integration.provider_update", object_type="mfa_provider", object_id=pid, detail=changed)
            flash("Remote MFA server %s saved. Apply changes to send it to FreeRADIUS." % pid, "success")
            return redirect(url_for("integrations.index"))
    return render_template("integrations/remote.html", v=v, errors=errors, is_new=False), (400 if errors else 200)


def _policy_uses(pid):
    return db.query_one("SELECT 1 FROM ui.mfa_policy WHERE provider_id = %s AND enabled", (pid,)) is not None


@bp.route("/<pid>/delete", methods=["POST"])
@role_required("admin")
@stepup_required
def delete(pid):
    p = ig.get_provider(pid)
    if p is None:
        abort(404)
    if pid in ig.providers_in_use():
        flash("%s is chosen in the second-factor rules. Choose another provider there first." % pid, "error")
        return redirect(url_for("integrations.index"))
    db.execute("DELETE FROM ui.mfa_provider WHERE id = %s", (pid,))
    ev("integration.provider_delete", object_type="mfa_provider", object_id=pid, detail={"type": p["type"]})
    flash("%s removed. Apply changes to remove it from FreeRADIUS." % pid, "success")
    return redirect(url_for("integrations.index"))


# ---------------------------------------------------------------- policy
def _policy_form(providers, client_ids):
    errors = {}
    out = {}
    for kind in ig.ACCOUNT_KINDS:
        enabled = form_bool(kind + "_enabled")
        pid = form_str(kind + "_provider", maxlen=32) or None
        scope = form_str(kind + "_scope", maxlen=10) or "all"
        chosen = []
        for raw in request.form.getlist(kind + "_clients"):
            if raw.isdigit() and int(raw) in client_ids and int(raw) not in chosen:
                chosen.append(int(raw))
        if scope not in ("all", "selected"):
            errors[kind] = "Choose all clients or selected clients."
        p = providers.get(pid) if pid else None
        if pid and p is None:
            errors[kind] = "Choose a provider from the list."
        elif enabled and p is None:
            errors[kind] = "Choose the provider that asks for the second factor."
        elif enabled and not p["enabled"]:
            errors[kind] = "%s is turned off. Turn it on (and apply changes) first." % pid
        elif p and p["type"] == "radius-mfa" and kind == "local":
            errors[kind] = ("A remote MFA server checks the password itself, so it serves directory accounts"
                            " only. Local accounts need the Duo Authentication Proxy on this server.")
        elif p and p["type"] == "radius-mfa" and not _remote_allowed():
            errors[kind] = "Remote MFA servers are not available in FIPS mode."
        if enabled and scope == "selected" and not chosen:
            errors.setdefault(kind, "Select at least one client, or choose all clients.")
        out[kind] = {"enabled": enabled, "provider_id": pid, "client_scope": scope, "client_ids": chosen}
    admins = _local_admins()
    exempt, seen = [], set()
    for line in request.form.get("exempt", "").splitlines():
        name = line.strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        if not _EXEMPT_RE.fullmatch(name):
            errors["exempt"] = "%s is not a valid user name." % name[:64]
        elif name.lower() not in admins:
            errors["exempt"] = "%s is not a local device admin." % name
        else:
            exempt.append(admins[name.lower()])
    if len(exempt) > ig.EXEMPT_MAX:
        errors["exempt"] = "At most %d exempt accounts." % ig.EXEMPT_MAX
    return out, exempt, errors


@bp.route("/policy", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def policy():
    providers = {p["id"]: p for p in ig.load_providers()}
    clients = load_clients()
    client_ids = {c["id"] for c in clients}
    pol, exempt, errors = ig.load_policy(), ig.load_exempt(), {}
    if request.method == "POST":
        new, new_exempt, errors = _policy_form(providers, client_ids)
        if not errors:
            changed = {}
            for kind in ig.ACCOUNT_KINDS:
                a, b = pol[kind], new[kind]
                diff = {k: {"from": a[k], "to": b[k]} for k in ("enabled", "provider_id", "client_scope", "client_ids")
                        if a[k] != b[k]}
                if diff:
                    changed[kind] = diff
                db.execute("UPDATE ui.mfa_policy SET enabled=%s, provider_id=%s, client_scope=%s, updated_at=now()"
                           " WHERE account_kind=%s", (b["enabled"], b["provider_id"], b["client_scope"], kind))
                db.execute("DELETE FROM ui.mfa_policy_client WHERE account_kind=%s", (kind,))
                for cid in (b["client_ids"] if b["client_scope"] == "selected" else []):
                    db.execute("INSERT INTO ui.mfa_policy_client (account_kind, client_id) VALUES (%s, %s)", (kind, cid))
            if sorted(exempt, key=str.lower) != sorted(new_exempt, key=str.lower):
                changed["exempt"] = {"from": exempt, "to": new_exempt}
                db.execute("DELETE FROM ui.mfa_exempt")
                for name in new_exempt:
                    db.execute("INSERT INTO ui.mfa_exempt (username) VALUES (%s)", (name,))
            ev("integration.policy", object_type="mfa_policy", detail=changed)
            flash("Second-factor rules saved. They apply to the next device admin login.", "success")
            return redirect(url_for("integrations.index"))
        pol, exempt = new, new_exempt
    unapplied = bool(pending_state().get("pending")) if providers else False
    return render_template("integrations/policy.html", policy=pol, exempt=exempt, errors=errors,
                           providers=providers, clients=clients, kind_labels=ig.KIND_LABELS,
                           type_labels=ig.TYPE_LABELS, unapplied=unapplied,
                           exempt_max=ig.EXEMPT_MAX), (400 if errors else 200)
