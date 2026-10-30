"""Apply changes (RADIUS clients + custom policy): render -> stage -> diff -> validate -> apply (helper) -> log. Rollback."""
import difflib
import re

from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import db, helper_client
from ..crypto import sha256_hex
from ..flashing import flash
from ..security import cfg, login_required, role_required, stepup_required
from ..services import (policy_format_upgrade, read_applied, render_all, restore_applied_from_history,
                        save_applied,
                        write_staging)
from . import ev

bp = Blueprint("apply", __name__, url_prefix="/apply")

BACKUP_RE = re.compile(r"^\d{8}T\d{6}Z$")


def _diff(old, new, name):
    old_lines = (old or "").splitlines(keepends=False)
    new_lines = (new or "").splitlines(keepends=False)
    lines = list(difflib.unified_diff(old_lines, new_lines, fromfile="applied/" + name,
                                      tofile="pending/" + name, lineterm="", n=3))
    out = []
    for ln in lines:
        if ln.startswith(("+++", "---")):
            kind = "file"
        elif ln.startswith("@@"):
            kind = "hunk"
        elif ln.startswith("+"):
            kind = "add"
        elif ln.startswith("-"):
            kind = "del"
        else:
            kind = "ctx"
        out.append((kind, ln))
    return out


def _mask_secrets(text):
    """Viewer/operator diff: hide shared secrets in the clients file."""
    return re.sub(r'(secret\s*=\s*)"[^"]*"', r'\1"********"', text or "")


def _call(action, **kw):
    try:
        return helper_client.call(cfg()["helper_socket"], action, timeout=cfg()["helper_timeout"], **kw)
    except helper_client.HelperError as e:
        return {"ok": False, "action": action, "message": str(e)}


def _log_apply(action, ok, message, policy_sha=None, clients_sha=None, backup_id=None):
    db.execute("INSERT INTO ui.apply_log (actor, action, policy_sha256, clients_sha256, success, message, backup_id)"
               " VALUES (%s,%s,%s,%s,%s,%s,%s)",
               (g.user["username"], action, policy_sha, clients_sha, ok, (message or "")[:2000], backup_id))


@bp.route("/")
@login_required
def index():
    render_error = None
    try:
        policy, clients = render_all()
    except Exception as e:
        policy = clients = None
        render_error = str(e)
    applied = read_applied()
    show_secrets = False  # diffs never show secrets; reveal is per client
    diffs = None
    if policy is not None:
        diffs = {
            "policy": _diff(applied["policy"], policy, "policy"),
            "clients": _diff(_mask_secrets(applied["clients"]) if not show_secrets else applied["clients"],
                             _mask_secrets(clients), "clients"),
        }
        if applied["clients"] is not None and applied["clients"] != clients and not diffs["clients"]:
            diffs["clients"] = [("ctx", "(only shared secrets changed)")]
    format_upgrade = policy_format_upgrade(applied["policy"], policy)
    history = db.query("SELECT id, at, actor, action, success, message, backup_id, policy_sha256, clients_sha256"
                       " FROM ui.apply_log ORDER BY id DESC LIMIT 25")
    backups = sorted({h["backup_id"] for h in history if h["backup_id"] and BACKUP_RE.match(h["backup_id"])},
                     reverse=True)
    from .dashboard import helper_status
    status = helper_status()
    if status.get("ok") and isinstance(status.get("backups"), list):
        backups = [b for b in status["backups"] if isinstance(b, str) and BACKUP_RE.match(b)]
    return render_template("apply/index.html", diffs=diffs, render_error=render_error, history=history,
                           backups=backups, have_applied=applied["policy"] is not None,
                           policy_sha=sha256_hex(policy) if policy is not None else None,
                           clients_sha=sha256_hex(clients) if clients is not None else None,
                           validation=None, status=status, format_upgrade=format_upgrade)


def _stage():
    policy, clients = render_all()
    write_staging(policy, clients)
    return policy, clients


@bp.route("/validate", methods=["POST"])
@role_required("operator")
def validate():
    try:
        policy, clients = _stage()
    except Exception as e:
        flash("The configuration could not be rendered: %s" % e, "error")
        return redirect(url_for("apply.index"))
    resp = _call("validate")
    ok = bool(resp.get("ok"))
    _log_apply("validate", ok, resp.get("message"), sha256_hex(policy), sha256_hex(clients))
    ev("config.validate", success=ok, object_type="config",
       detail={"policy_sha256": sha256_hex(policy), "clients_sha256": sha256_hex(clients),
               "message": (resp.get("message") or "")[:500]})
    output = resp.get("output")
    if isinstance(output, list):
        output = "\n".join(str(x) for x in output)
    return render_template("apply/result.html", action="validate", ok=ok, resp=resp, output=output or "")


@bp.route("/apply", methods=["POST"])
@role_required("operator")
@stepup_required
def apply():
    try:
        policy, clients = _stage()
    except Exception as e:
        flash("The configuration could not be rendered: %s" % e, "error")
        return redirect(url_for("apply.index"))
    ph, ch = sha256_hex(policy), sha256_hex(clients)
    expected = request.form.get("expected", "")
    if expected and expected != ph + ":" + ch:
        flash("The configuration changed while you were reviewing it. Review the new diff and apply again.",
              "error")
        return redirect(url_for("apply.index"))
    resp = _call("apply")
    ok = bool(resp.get("ok"))
    # Trust the hashes we staged; flag a mismatch reported by the helper.
    hp, hc = resp.get("policy_sha256"), resp.get("clients_sha256")
    if ok and ((hp and hp != ph) or (hc and hc != ch)):
        resp["message"] = (resp.get("message") or "") + " (warning: helper hash differs from staged hash)"
    backup_id = resp.get("backup_id") if isinstance(resp.get("backup_id"), str) else None
    _log_apply("apply", ok, resp.get("message"), ph, ch, backup_id)
    if ok:
        save_applied(policy, clients, backup_id=backup_id)
    ev("config.apply", success=ok, object_type="config",
       detail={"policy_sha256": ph, "clients_sha256": ch, "backup_id": backup_id,
               "rolled_back": bool(resp.get("rolled_back")), "message": (resp.get("message") or "")[:500]})
    output = resp.get("output")
    if isinstance(output, list):
        output = "\n".join(str(x) for x in output)
    return render_template("apply/result.html", action="apply", ok=ok, resp=resp, output=output or "")


@bp.route("/rollback", methods=["POST"])
@role_required("admin")
@stepup_required
def rollback():
    backup_id = request.form.get("backup_id", "")
    if not BACKUP_RE.match(backup_id):
        flash("Choose a valid backup.", "error")
        return redirect(url_for("apply.index"))
    resp = _call("rollback", backup_id=backup_id)
    ok = bool(resp.get("ok"))
    hp = resp.get("policy_sha256") if isinstance(resp.get("policy_sha256"), str) else None
    hc = resp.get("clients_sha256") if isinstance(resp.get("clients_sha256"), str) else None
    new_bid = resp.get("backup_id")
    new_bid = new_bid if isinstance(new_bid, str) and BACKUP_RE.match(new_bid) and new_bid != backup_id else None
    if ok:
        restored = restore_applied_from_history(backup_id, new_backup_id=new_bid)
        if restored and not (hp and hc):
            hp, hc = sha256_hex(restored[0]), sha256_hex(restored[1])
    msg = (resp.get("message") or "") + ("; previous files saved as backup %s" % new_bid if new_bid else "")
    _log_apply("rollback", ok, msg, hp, hc, backup_id)
    ev("config.rollback", success=ok, object_type="config",
       detail={"backup_id": backup_id, "new_backup_id": new_bid, "policy_sha256": hp, "clients_sha256": hc,
               "message": (resp.get("message") or "")[:500]})
    output = resp.get("output")
    if isinstance(output, list):
        output = "\n".join(str(x) for x in output)
    return render_template("apply/result.html", action="rollback", ok=ok, resp=resp, output=output or "")
