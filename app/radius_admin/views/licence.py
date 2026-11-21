"""Admin-only: Settings -> Licence (SPEC section 31). Records the licence case and an optional
signed licence file. Never locks anything and never contacts a server."""
from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import db, licence
from ..flashing import flash
from ..security import role_required, stepup_required
from . import ev

bp = Blueprint("licence", __name__)


def _read_upload():
    """(text, error) from the uploaded file or the pasted text."""
    up = request.files.get("file")
    if up and up.filename:
        raw = up.read(licence.MAX_FILE + 1)
        try:
            return raw.decode("utf-8-sig"), None
        except UnicodeDecodeError:
            return "", "The licence file is not text."
    return request.form.get("text", "")[:licence.MAX_FILE + 1], None


def _page(errors=None, code=200, choice=None):
    today = licence.today()
    st = licence.load_state()
    status = licence.status(st, today)
    if choice is None:
        choice = "free" if status["case"] == "free" else ("commercial" if status["case"] else "")
    return render_template("settings/licence.html", st=status, state=st, choices=licence.CHOICES, choice=choice,
                           trial=licence.trial_info(st, today), periods=licence.PERIODS, errors=errors or [],
                           history=_history(), licensing_url=licence.LICENSING_URL), code


def _history(limit=20):
    """Earlier answers, newest first, from the audit log (licence.declare)."""
    rows = db.query("SELECT at, actor, detail->>'from' AS old, detail->>'case' AS new FROM ui.audit_log"
                    " WHERE action = 'licence.declare' AND success ORDER BY id DESC LIMIT %s", (limit,))
    for r in rows:
        r["old_label"] = licence.CASES.get(r["old"] or "", "Not answered")
        r["new_label"] = licence.CASES.get(r["new"] or "", r["new"] or "")
    return rows


def _confirm(target, errors=None):
    """Changing an earlier answer: show the licence definitions and ask for an acknowledgement.
    target is the case being chosen: free or trial (a licence file needs no extra step)."""
    st = licence.load_state()
    return render_template("settings/licence_confirm.html", target=target, new=licence.CASES[target],
                           choice="free" if target == "free" else "commercial",
                           op="trial" if target == "trial" else "", old=licence.CASES.get(st["licence_case"], ""),
                           errors=errors or [], periods=licence.PERIODS,
                           licensing_url=licence.LICENSING_URL), 400 if errors else 200


def _declare(case, before, today, acknowledged=False):
    licence.declare(case, g.user["username"], today)
    detail = {"case": case, "from": before["licence_case"] or None}
    if acknowledged:
        detail["acknowledged"] = True
    if case in licence.PERIODS:
        detail["period_started"] = licence.load_state()[licence.PERIODS[case][1]]
    ev("licence.declare", object_type="setting", object_id="licence_case", detail=detail)


def _set_case(target, before, today):
    """Free use or the trial: confirm first when it changes an earlier answer."""
    changing = before["licence_case"] in licence.CASES and before["licence_case"] != target
    if changing and request.form.get("confirmed") != "1":
        return _confirm(target)
    if changing and request.form.get("acknowledge") != "1":
        return _confirm(target, ["Tick the box to confirm that this case applies."])
    if before["licence_case"] != target:
        _declare(target, before, today, acknowledged=changing)
    flash("Saved: %s." % licence.CASES[target], "success")
    return redirect(url_for("licence.index"))


def _install(before, today):
    """Commercial: install the licence file given, else keep a valid one already installed."""
    text, err = _read_upload()
    if not err and not text.strip():
        current = licence.status(before, today)["licence"]
        if current is None and before["licence_case"] == "trial" and not licence.trial_info(before, today)["ended"]:
            flash("The trial continues. Install your licence file when you have it.", "info")
            return redirect(url_for("licence.index"))
        if current is None:
            return _page(["Upload the licence file you received, or paste its contents. No licence yet? "
                          "Start the trial instead."], 400, "commercial")
        if before["licence_case"] != current["type"]:
            _declare(current["type"], before, today)
        flash("Saved: %s." % licence.CASES[current["type"]], "success")
        return redirect(url_for("licence.index"))
    lic = None
    if not err:
        try:
            lic = licence.parse(text)
        except licence.LicenceError as e:
            err = str(e)
    if err:
        ev("licence.file_upload", success=False, object_type="setting", object_id="licence_file",
           detail={"error": err[:300]})
        return _page([err], 400, "commercial")
    licence.store_file(text.strip() + "\n")
    if before["licence_case"] != lic["type"]:       # the file's type is the case
        _declare(lic["type"], before, today)
    ev("licence.file_upload", object_type="setting", object_id="licence_file",
       detail={"licence_id": lic["licence_id"], "type": lic["type"], "licensee": lic["licensee"],
               "expires": lic["expires"].isoformat() if lic["expires"] else None,
               "replaced": bool(before["licence_file"])})
    flash("Licence %s for %s installed." % (lic["licence_id"], lic["licensee"]), "success")
    return redirect(url_for("licence.index"))


@bp.route("/settings/licence", methods=["GET", "POST"])
@role_required("admin")
@stepup_required
def index():
    if request.method == "GET":
        return _page()
    action = request.form.get("action", "")
    today = licence.today()
    before = licence.load_state()
    if action == "save":
        choice = request.form.get("choice", "")
        if choice not in licence.CHOICES:
            return _page(["Choose how this server is licensed."], 400)
        if choice == "free":
            return _set_case("free", before, today)
        if request.form.get("op") == "trial":
            trial = licence.trial_info(before, today)
            if trial["ended"]:
                return _page(["The trial ended on %s and does not restart. Upload a licence file."
                              % trial["last"].isoformat()], 400, "commercial")
            return _set_case("trial", before, today)
        return _install(before, today)
    if action == "remove":
        if before["licence_file"]:
            licence.remove_file()
            ev("licence.file_remove", object_type="setting", object_id="licence_file")
            flash("Licence file removed.", "success")
        return redirect(url_for("licence.index"))
    return _page(["Unknown action."], 400)


@bp.route("/licence/notice/hide", methods=["POST"])
@role_required("admin")
def hide_notice():
    """Hide the dashboard reminder for SNOOZE_DAYS. A different reminder still shows."""
    today = licence.today()
    text, key = licence.dashboard_notice(today)
    if key and key == request.form.get("key", ""):
        licence.snooze(key, today)
        ev("licence.notice_hide", object_type="setting", object_id="licence_notice", detail={"notice": key})
    return redirect(url_for("dashboard.index"))
