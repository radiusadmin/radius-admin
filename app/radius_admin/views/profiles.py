"""Device (vendor) profiles: the built-in ones, read-only, and custom ones created here, by
copying another profile, or imported from JSON; every profile can be exported as JSON
(SPEC section 26). Custom profiles are stored validated in ui.vendor_profile; the reply
attributes reach FreeRADIUS at the next Apply, CoA and SNMP port names use them at once."""
import json

from flask import Blueprint, Response, abort, g, redirect, render_template, request, url_for

from .. import coa, db, vendors, versions
from ..crypto import sha256_hex
from ..flashing import flash
from ..security import cfg, has_role, login_required, role_required
from ..services import get_settings
from . import ev, form_bool, form_str
from .auth import inline_stepup

bp = Blueprint("profiles", __name__, url_prefix="/profiles")

MAX_IMPORT = 64 * 1024
TEXT_FIELDS = ("id", "label", "description", "reply_vlan", "reply_admin", "reply_role", "coa_port", "coa_identify",
               "port_rules", "setup_accounting", "setup_coa") + tuple(
    "coa_%s_%s" % (a, k) for a in vendors.COA_ACTIONS for k in ("packet", "attrs"))
BOOL_FIELDS = ("mab_ethernet", "mab_wireless", "coa_send_port")


def _usage():
    """{profile id: number of clients naming it}, and the default profile's id."""
    rows = db.query("SELECT vendor_profile AS id, count(*) AS n FROM ui.radius_client"
                    " WHERE vendor_profile IS NOT NULL GROUP BY vendor_profile")
    return {r["id"]: r["n"] for r in rows}, get_settings()["default_vendor_profile"]


def _get(pid):
    p = vendors.catalog().get(pid)
    if p is None:
        abort(404)
    return p


def _form():
    f = {k: form_str(k, maxlen=4000) for k in TEXT_FIELDS}
    f.update({k: form_bool(k) for k in BOOL_FIELDS})
    return f


def _dictionary():
    """Attribute names of the FreeRADIUS dictionary this server uses, or None if not found."""
    try:
        rc = coa.find_radclient(cfg().get("radclient", ""))
        return vendors.dictionary_attributes(coa.find_dict_dir(rc, cfg().get("radius_dict_dir", "")))
    except coa.CoaError:
        return None


def _check(profile, errors):
    """Built-in id and dictionary checks shared by the form and the import."""
    if vendors.is_builtin(profile["id"]):
        errors["id"] = "%s is the id of a built-in profile; choose another." % profile["id"]
    names = _dictionary()
    for field, attr in vendors.unknown_attributes(profile, names) if names else ():
        errors.setdefault(field, "%s is not an attribute in this server's FreeRADIUS dictionary." % attr)


def _stepup(form_page, **ctx):
    """None when the step-up is current (or was just given with the form); else the page
    again with the step-up fields (401)."""
    if g.session.get("stepup_ok"):
        return None
    ok, attempted = inline_stepup(request.form)
    if ok:
        return None
    if g.get("user") is None:
        return redirect(url_for("auth.login"))
    ctx["error"] = ("Verification failed. Check your password and second factor." if attempted else
                    "Your confirmation expired. Confirm your identity to save; your entries are kept below.")
    return render_template(form_page, need_stepup=True, **ctx), 401


def _save(profile, replace):
    doc = json.dumps(profile, sort_keys=True)
    if replace:
        db.execute("UPDATE ui.vendor_profile SET doc = %s::jsonb, updated_at = now(), updated_by = %s WHERE id = %s",
                   (doc, g.user["username"], profile["id"]))
    else:
        db.execute("INSERT INTO ui.vendor_profile (id, doc, updated_by) VALUES (%s, %s::jsonb, %s)",
                   (profile["id"], doc, g.user["username"]))


def _saved_message(pid):
    used, default_id = _usage()
    if used.get(pid) or pid == default_id:
        return ("Profile %s saved. Apply changes to send its attributes to FreeRADIUS; session actions and port "
                "names use it right away." % pid)
    return "Profile %s saved. Choose it for a client (Clients → edit) to use it." % pid


def _report_url(profile):
    """Where to report a problem with a built-in profile (GitHub issue form)."""
    if not vendors.is_builtin(profile["id"]):
        return None
    try:
        version = versions.installed(cfg()["build_file"])["version"]
    except Exception:                   # no build file (a checkout): the reporter fills it in
        version = ""
    return vendors.report_url(profile, cfg().get("update_repo", ""), version)


def _audit_detail(profile, **extra):
    return dict({"label": profile["label"], "sha256": sha256_hex(vendors.export_json(profile))}, **extra)


@bp.route("/")
@login_required
def index():
    cat = vendors.catalog()
    used, default_id = _usage()
    rows = [{"p": cat[pid], "builtin": vendors.is_builtin(pid), "used": used.get(pid, 0), "default": pid == default_id,
             "report_url": _report_url(cat[pid])} for pid, _, _ in vendors.choices(cat)]
    return render_template("profiles/index.html", rows=rows)


@bp.route("/new", methods=["GET", "POST"])
@role_required("admin")
def new():
    if request.method == "GET":
        if not g.session.get("stepup_ok"):
            return redirect(url_for("auth.stepup", next=request.full_path))
        base = _get(request.args.get("from") or vendors.DEFAULT_ID)
        f = vendors.profile_to_form(base)
        f.update(id="", label=(base["label"] + " (copy)")[:64])
        return render_template("profiles/form.html", f=f, is_new=True, editable=True, errors={}, base=base)
    f = _form()
    resp = _stepup("profiles/form.html", f=f, is_new=True, editable=True, errors={})
    if resp:
        return resp
    profile, errors = vendors.form_to_profile(f)
    if profile:
        _check(profile, errors)
        if not errors and profile["id"] in vendors.custom_profiles():
            errors["id"] = "A custom profile %s already exists; choose another id." % profile["id"]
    if errors:
        ev("profile.create", success=False, object_type="vendor_profile", object_id=f["id"][:32],
           detail={"error": next(iter(errors.values()))[:300]})
        return render_template("profiles/form.html", f=f, is_new=True, editable=True, errors=errors), 400
    _save(profile, False)
    ev("profile.create", object_type="vendor_profile", object_id=profile["id"], detail=_audit_detail(profile))
    flash(_saved_message(profile["id"]), "success")
    return redirect(url_for("profiles.view", pid=profile["id"]))


@bp.route("/<pid>", methods=["GET", "POST"])
@login_required
def view(pid):
    profile = _get(pid)
    builtin = vendors.is_builtin(pid)
    editable = not builtin and has_role("admin")
    used, default_id = _usage()
    ctx = {"is_new": False, "editable": editable, "builtin": builtin, "profile": profile,
           "used": used.get(pid, 0), "is_default": pid == default_id, "report_url": _report_url(profile)}
    if request.method == "GET":
        if editable and not g.session.get("stepup_ok"):
            return redirect(url_for("auth.stepup", next=request.path))
        return render_template("profiles/form.html", f=vendors.profile_to_form(profile), errors={}, **ctx)
    if not editable:
        abort(403)
    f = _form()
    f["id"] = pid                       # the id names the profile in clients and settings: not renamed
    resp = _stepup("profiles/form.html", f=f, errors={}, **ctx)
    if resp:
        return resp
    new_profile, errors = vendors.form_to_profile(f)
    if new_profile:
        _check(new_profile, errors)
    if errors:
        ev("profile.update", success=False, object_type="vendor_profile", object_id=pid,
           detail={"error": next(iter(errors.values()))[:300]})
        return render_template("profiles/form.html", f=f, errors=errors, **ctx), 400
    if new_profile == profile:
        flash("No changes.", "info")
        return redirect(url_for("profiles.view", pid=pid))
    _save(new_profile, True)
    ev("profile.update", object_type="vendor_profile", object_id=pid,
       detail=_audit_detail(new_profile, sha256_before=sha256_hex(vendors.export_json(profile)),
                            clients=used.get(pid, 0), default=pid == default_id))
    flash(_saved_message(pid), "success")
    return redirect(url_for("profiles.view", pid=pid))


@bp.route("/<pid>/delete", methods=["POST"])
@role_required("admin")
def delete(pid):
    if vendors.is_builtin(pid) or pid not in vendors.custom_profiles():
        abort(404)
    if not g.session.get("stepup_ok"):
        flash("Confirm your identity, then delete the profile again.", "info")
        return redirect(url_for("auth.stepup", next=url_for("profiles.index")))
    used, default_id = _usage()
    if used.get(pid) or pid == default_id:
        why = []
        if used.get(pid):
            why.append("%d client%s use%s it" % (used[pid], "" if used[pid] == 1 else "s", "s" if used[pid] == 1 else ""))
        if pid == default_id:
            why.append("it is the default profile (Settings → Devices)")
        flash("Profile %s was not deleted: %s. Choose another profile there first." % (pid, " and ".join(why)), "error")
        ev("profile.delete", success=False, object_type="vendor_profile", object_id=pid,
           detail={"clients": used.get(pid, 0), "default": pid == default_id})
        return redirect(url_for("profiles.index"))
    db.execute("DELETE FROM ui.vendor_profile WHERE id = %s", (pid,))
    ev("profile.delete", object_type="vendor_profile", object_id=pid)
    flash("Profile %s deleted." % pid, "success")
    return redirect(url_for("profiles.index"))


@bp.route("/<pid>/export")
@login_required
def export(pid):
    profile = _get(pid)
    ev("profile.export", object_type="vendor_profile", object_id=pid, detail=_audit_detail(profile))
    return Response(vendors.export_json(profile), mimetype="application/json",
                    headers={"Content-Disposition": 'attachment; filename="%s.radius-admin-profile.json"' % pid})


@bp.route("/import", methods=["GET", "POST"])
@role_required("admin")
def import_profile():
    if request.method == "GET":
        if not g.session.get("stepup_ok"):
            return redirect(url_for("auth.stepup", next=request.path))
        return render_template("profiles/import.html", text="", replace=False, errors=[])
    text = request.form.get("json", "")
    up = request.files.get("file")
    if up and up.filename:
        raw = up.read(MAX_IMPORT + 1)
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            return render_template("profiles/import.html", text="", replace=False,
                                   errors=["The file is not UTF-8 text."]), 400
    replace = form_bool("replace")
    resp = _stepup("profiles/import.html", text=text[:MAX_IMPORT], replace=replace, errors=[])
    if resp:
        return resp
    errors = []
    if len(text.encode("utf-8")) > MAX_IMPORT:
        errors.append("The profile is larger than 64 KiB.")
    profile = None
    if not errors:
        try:
            doc = json.loads(text)
            if isinstance(doc, dict):
                doc["status"] = "unverified"        # only built-in profiles are marked tested
            profile = vendors.validate(doc)
        except ValueError as e:                     # json.JSONDecodeError and ProfileError
            errors.append("Not a usable profile: %s" % e)
    if profile:
        problems = {}
        _check(profile, problems)
        errors += list(problems.values())
        exists = profile["id"] in vendors.custom_profiles()
        if not errors and exists and not replace:
            errors.append("A custom profile %s already exists. Tick “Replace” to overwrite it, or change "
                          "\"id\" in the file." % profile["id"])
    if errors:
        ev("profile.import", success=False, object_type="vendor_profile",
           object_id=(profile or {}).get("id", "")[:32] or None, detail={"error": errors[0][:300]})
        return render_template("profiles/import.html", text=text, replace=replace, errors=errors), 400
    _save(profile, exists)
    ev("profile.import", object_type="vendor_profile", object_id=profile["id"],
       detail=_audit_detail(profile, replaced=exists))
    flash(_saved_message(profile["id"]), "success")
    return redirect(url_for("profiles.view", pid=profile["id"]))
