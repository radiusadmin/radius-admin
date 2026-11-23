"""Integrations: second-factor providers for device admin logins (SPEC section 29).

Providers (ui.mfa_provider) reach FreeRADIUS through the clients file, so adding, changing
or removing one needs Apply. The policy (which logins need a second factor) and the
exemptions are read live by FreeRADIUS on every login. Admin + step-up for every change.
"""
import hashlib
import json
import os
import re
import tempfile

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, url_for

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


def timeout_hints(policy=None, all_clients=None):
    """The RADIUS timeout advice per vendor profile (SPEC section 29.4), for the enabled clients
    a second-factor rule covers (every enabled client while no rule is on, so the advice can be
    followed before the rules are turned on): [{id, label, text, commands, clients}], by label."""
    from .. import vendors
    policy = policy if policy is not None else ig.load_policy()
    all_clients = all_clients if all_clients is not None else load_clients()
    on = [p for p in policy.values() if p["enabled"]]
    if on and all(p["client_scope"] == "selected" for p in on):
        wanted = {cid for p in on for cid in p["client_ids"]}
    else:
        wanted = None
    cat = vendors.catalog()
    default_id = vendors.load_default_id(None, cat)
    out = {}
    for c in all_clients:
        if not c.get("enabled", True) or (wanted is not None and c["id"] not in wanted):
            continue
        try:
            prof = vendors.resolve(c.get("vendor_profile"), default_id, cat)
        except vendors.ProfileError:
            prof = vendors.default()
        text, commands = vendors.mfa_timeout_hint(prof)
        e = out.setdefault(prof["id"], {"id": prof["id"], "label": prof["label"], "text": text,
                                        "commands": commands, "clients": 0})
        e["clients"] += 1
    return sorted(out.values(), key=lambda e: e["label"].lower())


@bp.route("/")
@login_required
def index():
    providers = ig.load_providers()
    all_clients = load_clients()
    clients = {c["id"]: c["name"] for c in all_clients}
    policy = ig.load_policy()
    return render_template("integrations/index.html", providers=providers, policy=policy,
                           timeout_hints=timeout_hints(policy, all_clients),
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
    if p["type"] == "duo":
        flash("Duo is set up and removed on its own page.", "error")
        return redirect(url_for("integrations.duo"))
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
    # When the provider is down, FreeRADIUS rejects these logins (it does not stay silent), so
    # devices do not fall back to their own accounts: keep a break-glass account, or confirm.
    if out["local"]["enabled"] and not exempt and "exempt" not in errors and not form_bool("no_exempt_ok"):
        errors["exempt"] = ("Add a break-glass account here, or confirm below that no local account is exempt:"
                            " if the provider cannot be reached, every local device admin login is rejected.")
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
            if new["local"]["enabled"] and not new_exempt:
                changed["no_exempt_confirmed"] = True
            ev("integration.policy", object_type="mfa_policy", detail=changed)
            flash("Second-factor rules saved. They apply to the next device admin login.", "success")
            return redirect(url_for("integrations.index"))
        pol, exempt = new, new_exempt
    unapplied = bool(pending_state().get("pending")) if providers else False
    return render_template("integrations/policy.html", policy=pol, exempt=exempt, errors=errors,
                           providers=providers, clients=clients, kind_labels=ig.KIND_LABELS,
                           type_labels=ig.TYPE_LABELS, unapplied=unapplied,
                           exempt_max=ig.EXEMPT_MAX), (400 if errors else 200)


# ---------------------------------------------------------------- Duo on this server (SPEC section 29.2)
_DUO_FILE = re.compile(ig.DUO_FILE_RE)
_INTEGRATION_ACTIVE = ("queued", "installing", "removing")


def _helper(action, timeout=30, **params):
    from .. import helper_client
    try:
        return helper_client.call(cfg()["helper_socket"], action, timeout=timeout, **params)
    except helper_client.HelperError as e:
        return {"ok": False, "message": str(e)}


def _duo_files():
    """Duo source builds in integration_dir (downloaded or uploaded), newest version first."""
    try:
        names = os.listdir(cfg()["integration_dir"])
    except OSError:
        return []
    found = [(tuple(int(x) for x in m.group(1).split(".")), n) for n in names if (m := _DUO_FILE.fullmatch(n))]
    return [n for _, n in sorted(found, reverse=True)]


def _duo_enable_block(duo, build=None):
    """Why Duo cannot be turned on now, or None (SPEC section 29.3)."""
    if not duo.get("installed"):
        return "Install the Duo Authentication Proxy first."
    if _fips():
        if build is None:
            cat = _helper("integration_catalog")
            build = ig.build_check(duo.get("installed"), cat.get("entries") if cat.get("ok") else [])
        if not build["fips_capable"]:
            return ("FIPS mode: the installed build is not FIPS-capable in the signed catalog."
                    " Install a FIPS-capable build first.")
    return None


def _duo_disable_block():
    """Why Duo cannot be turned off now, or None: an enabled second-factor rule names it."""
    if _policy_uses(ig.DUO_ID):
        return "A second-factor rule uses Duo. Change the rule first."
    return None


def _duo_page(test=None, preflight=None, errors=None, status_code=200):
    from ..integration_fetch import read_status
    key = current_app.config["RA_DATA_KEY"]
    st = _helper("integration_status")
    duo = (st.get("integrations") or {}).get("duo") or {} if st.get("ok") else {}
    cat = _helper("integration_catalog")
    build = ig.build_check(duo.get("installed"), cat.get("entries") if cat.get("ok") else [])
    entries = [e for e in (cat.get("entries") or []) if e.get("provider") == "duo" and not e.get("withdrawn")]
    if _fips():
        entries = [e for e in entries if e.get("fips")]
    entries.sort(key=lambda e: tuple(int(x) for x in e["version"].split(".")), reverse=True)
    p = ig.get_provider(ig.DUO_ID)
    secrets = ig.duo_secrets(key, p) if p is not None else {}
    state = duo.get("state") or {}
    if p is not None and p["enabled"]:
        switch_lock = _duo_disable_block()
    elif not st.get("ok"):
        switch_lock = "The helper is not reachable, so the install state is unknown."
    else:
        switch_lock = _duo_enable_block(duo, build)
    return render_template(
        "integrations/duo.html", helper_ok=bool(st.get("ok")), helper_message=st.get("message", ""),
        duo=duo, build=build, state=state, running=state.get("state") in _INTEGRATION_ACTIVE, catalog=entries,
        catalog_serial=cat.get("serial", 0) if cat.get("ok") else None, catalog_message=cat.get("message", ""),
        fetch=read_status(cfg()["integration_dir"], "duo"), files=_duo_files(), provider=p,
        has_skey=bool(secrets.get("skey")), in_use=ig.DUO_ID in ig.providers_in_use(), test=test,
        switch_lock=switch_lock, preflight=preflight, errors=errors or {}, fips=_fips(), factors=unlang().DUO_FACTORS,
        upload_mib=ig.UPLOAD_MAX // (1024 * 1024)), status_code


@bp.route("/duo")
@login_required
def duo():
    return _duo_page()


@bp.route("/duo/status")
@login_required
def duo_status():
    """For the page's progress indicators: wait=fetch (the download) or wait=install (an
    install or removal)."""
    from ..integration_fetch import read_status
    if request.args.get("wait") == "fetch":
        f = read_status(cfg()["integration_dir"], "duo")
        busy = f.get("state") == "downloading"
        return jsonify(done=not busy, message="Downloading %s…" % f.get("file", "") if busy else "")
    st = _helper("integration_status")
    if not st.get("ok"):
        return jsonify(done=False, message="Waiting for the helper (%s)…" % st.get("message", ""))
    s = ((st.get("integrations") or {}).get("duo") or {}).get("state") or {}
    busy = s.get("state") in _INTEGRATION_ACTIVE
    msg = ("%s…" % (s.get("message") or "working")) if busy else ""
    return jsonify(done=not busy, message=msg[:1].upper() + msg[1:], state=s.get("state", ""))


@bp.route("/duo/log")
@login_required
def duo_log():
    """The install log from byte `offset` (helper integration_log), for the Details drop-down."""
    from .updates import clean_log
    raw = request.args.get("offset", "0")
    offset = int(raw) if raw.isdigit() and len(raw) <= 15 else 0
    r = _helper("integration_log", id="duo", offset=offset)
    if not r.get("ok"):
        return jsonify(available=False, running=False, message="The install log is not available: %s" % r.get("message", ""))
    state = r.get("state") or {}
    return jsonify(available=True, running=state.get("state") in _INTEGRATION_ACTIVE, name=r.get("log", ""),
                   offset=int(r.get("offset") or 0), skipped=int(r.get("skipped") or 0),
                   text=clean_log(r.get("text", "")), message=r.get("message", ""))


@bp.route("/duo/check", methods=["POST"])
@role_required("admin")
@stepup_required
def duo_check():
    p = ig.get_provider(ig.DUO_ID)
    params = {"id": "duo"}
    if p is not None and p["settings"].get("api_host"):
        params["api_host"] = p["settings"]["api_host"]
    r = _helper("integration_preflight", **params)
    # audited (rule 12): the check reaches Duo's API host through the helper
    detail = {"ready": bool(r.get("ready")),
              "failed": [str(c.get("check", ""))[:40] for c in (r.get("checks") or []) if not c.get("ok")][:20]}
    if "api_host" in params:
        detail["api_host"] = params["api_host"]
    if not r.get("ok"):
        detail["message"] = str(r.get("message", ""))[:300]
    ev("integration.preflight", success=bool(r.get("ok") and r.get("ready")), object_type="integration",
       object_id="duo", detail=detail)
    return _duo_page(preflight=r)


@bp.route("/duo/fetch", methods=["POST"])
@role_required("admin")
@stepup_required
def duo_fetch():
    version = form_str("version", maxlen=20)
    if not re.fullmatch(r"\d{1,4}\.\d{1,4}\.\d{1,4}", version):
        flash("Choose a version.", "error")
        return redirect(url_for("integrations.duo"))
    r = _helper("integration_fetch", id="duo", version=version)
    ev("integration.fetch", success=bool(r.get("ok")), object_type="integration", object_id="duo",
       detail={"version": version, "listed": r.get("listed"), "message": r.get("message", "")[:300]})
    if not r.get("ok"):
        flash("The download was not started: %s" % r.get("message"), "error")
    return redirect(url_for("integrations.duo"))


@bp.route("/duo/upload", methods=["POST"])
@role_required("admin")
@stepup_required
def duo_upload():
    f = request.files.get("build")
    name = os.path.basename((f.filename or "") if f else "")
    if f is None or not _DUO_FILE.fullmatch(name):
        flash("Choose Duo's source build, a file named like duoauthproxy-6.8.1-src.tgz.", "error")
        return redirect(url_for("integrations.duo"))
    d = cfg()["integration_dir"]
    fd, tmp = tempfile.mkstemp(prefix=".upload-", dir=d)
    size = 0
    h = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = f.stream.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > ig.UPLOAD_MAX:
                    raise ValueError("larger than %d MiB" % (ig.UPLOAD_MAX // (1024 * 1024)))
                h.update(chunk)
                out.write(chunk)
        if size == 0:
            raise ValueError("the file is empty")
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(d, name))
    except (OSError, ValueError) as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        flash("The upload was not saved: %s" % e, "error")
        return redirect(url_for("integrations.duo"))
    ev("integration.upload", object_type="integration", object_id="duo",
       detail={"file": name, "size": size, "sha256": h.hexdigest()})
    flash("%s uploaded (SHA-256 %s). Install it below." % (name, h.hexdigest()), "success")
    return redirect(url_for("integrations.duo"))


@bp.route("/duo/install", methods=["POST"])
@role_required("admin")
@stepup_required
def duo_install():
    name = form_str("file", maxlen=100)
    if not _DUO_FILE.fullmatch(name) or name not in _duo_files():
        flash("That build is not here any more. Download or upload it again.", "error")
        return redirect(url_for("integrations.duo"))
    params = {"id": "duo", "file": name, "actor": g.user["username"]}
    pasted = form_str("sha256", maxlen=80).lower()
    if pasted and not _fips():
        if not re.fullmatch(r"[0-9a-f]{64}", pasted):
            flash("The SHA-256 must be 64 hexadecimal digits.", "error")
            return redirect(url_for("integrations.duo"))
        if request.form.get("confirm_unverified") != "1":
            flash("Confirm that you compared the SHA-256 with the value Duo publishes.", "error")
            return redirect(url_for("integrations.duo"))
        params["sha256"] = pasted
    r = _helper("integration_install", timeout=120, **params)
    ev("integration.install_requested", success=bool(r.get("ok")), object_type="integration", object_id="duo",
       detail={"file": name, "verified": r.get("verified", ""), "sha256": r.get("sha256", ""),
               "message": r.get("message", "")[:300]})
    if not r.get("ok"):
        flash("The install was not started: %s" % r.get("message"), "error")
    return redirect(url_for("integrations.duo"))


@bp.route("/duo/settings", methods=["POST"])
@role_required("admin")
@stepup_required
def duo_settings():
    key = current_app.config["RA_DATA_KEY"]
    p = ig.ensure_duo(key)
    secrets = ig.duo_secrets(key, p)
    errors = {}
    s = {"ikey": form_str("ikey", maxlen=40).upper(), "api_host": form_str("api_host", maxlen=64).lower(),
         "failmode": "secure" if _fips() else (form_str("failmode", maxlen=10) or "secure"),
         "factors": ",".join(x for x in request.form.getlist("factors") if x in unlang().DUO_FACTORS) or "auto"}
    skey = form_str("skey", maxlen=64)
    enabled = form_bool("enabled")
    try:
        unlang().validate_duo_settings(dict(s, skey=skey or secrets.get("skey") or "", secret=secrets["secret"],
                                            primary_secret=secrets["primary_secret"]), _fips())
    except ValueError as e:
        msg = str(e)
        field = ("ikey" if "Integration key" in msg else "skey" if "Secret key" in msg
                 else "api_host" if "API hostname" in msg else "failmode" if "Fail mode" in msg else "factors")
        errors[field] = msg
    duo = ((_helper("integration_status").get("integrations") or {}).get("duo") or {})
    block = _duo_enable_block(duo) if enabled else _duo_disable_block() if p["enabled"] else None
    if block:
        errors["enabled"] = block
    if errors:
        return _duo_page(errors=errors, status_code=400)
    if skey:
        secrets["skey"] = skey
        db.execute("UPDATE ui.mfa_provider SET secrets_enc=%s WHERE id=%s",
                   (ig.encrypt_secrets(key, ig.DUO_ID, secrets), ig.DUO_ID))
    db.execute("UPDATE ui.mfa_provider SET settings=%s::jsonb, enabled=%s, updated_at=now() WHERE id=%s",
               (json.dumps(s), enabled, ig.DUO_ID))
    changed = {k: {"from": p["settings"].get(k), "to": v} for k, v in s.items() if p["settings"].get(k) != v}
    if p["enabled"] != enabled:
        changed["enabled"] = {"from": p["enabled"], "to": enabled}
    if skey:
        changed["duo_skey_updated"] = True
    ev("integration.configure", object_type="mfa_provider", object_id=ig.DUO_ID, detail=changed)
    flash("Duo settings saved. Apply changes to send them to the Duo proxy and FreeRADIUS.", "success")
    return redirect(url_for("integrations.duo"))


@bp.route("/duo/test", methods=["POST"])
@role_required("operator")
def duo_test():
    r = _helper("integration_test", timeout=150, id="duo")
    ev("integration.test", success=bool(r.get("ok") and r.get("passed")), object_type="integration", object_id="duo",
       detail={"message": r.get("message", "")[:300]})
    return _duo_page(test=r)


@bp.route("/duo/remove", methods=["POST"])
@role_required("admin")
@stepup_required
def duo_remove():
    p = ig.get_provider(ig.DUO_ID)
    if p is not None and p["enabled"]:
        flash("Turn the Duo provider off and apply the changes before you remove Duo.", "error")
        return redirect(url_for("integrations.duo"))
    r = _helper("integration_remove", id="duo", actor=g.user["username"])
    ev("integration.remove_requested", success=bool(r.get("ok")), object_type="integration", object_id="duo",
       detail={"message": r.get("message", "")[:300]})
    if not r.get("ok"):
        flash("Duo was not removed: %s" % r.get("message"), "error")
    return redirect(url_for("integrations.duo"))
