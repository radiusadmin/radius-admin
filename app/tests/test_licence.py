"""Settings -> Licence (SPEC section 31): signed licence files, the declared case, reminders.
Nothing here may lock a feature; the tests check that too."""
import base64
import datetime
import json
import re

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from radius_admin import licence

D = datetime.date


def _key():
    return ec.generate_private_key(ec.SECP384R1())


@pytest.fixture
def signer(tmp_path, monkeypatch):
    """A throwaway signing key whose public half is the only one the app knows."""
    key = _key()
    kdir = tmp_path / "keys"
    kdir.mkdir()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (kdir / "test.pem").write_bytes(pem)
    monkeypatch.setattr(licence, "KEY_DIR", str(kdir))
    return key


@pytest.fixture(autouse=True)
def _unanswered(request):
    """Page tests here start with the licence question unanswered (conftest answers it)."""
    if "browser" in request.fixturenames:
        request.getfixturevalue("browser")          # after clean_db has seeded the answer
        conn = request.getfixturevalue("superconn")
        with conn.cursor() as cur:
            cur.execute("DELETE FROM ui.setting WHERE key = 'licence_case'")


def payload(**kw):
    p = {"product": "radius-admin", "licence_id": "RA-2026-0001", "type": "commercial",
         "licensee": "Example Corp", "tier": "50-249", "scope": "Unlimited servers and devices",
         "issued": "2026-11-01", "starts": "2026-11-01", "expires": "2027-10-31", "notes": ""}
    p.update(kw)
    return p


def sign(key, p, kid=None):
    sig = key.sign(licence.canonical(p), ec.ECDSA(hashes.SHA384()))
    return json.dumps({"format": 1, "key_id": kid or licence.key_id(key.public_key()), "payload": p,
                       "signature": base64.b64encode(sig).decode()})


# ----------------------------------------------------------------- file format
def test_valid_file_parses(signer):
    lic = licence.parse(sign(signer, payload()))
    assert lic["licence_id"] == "RA-2026-0001" and lic["licensee"] == "Example Corp"
    assert lic["starts"] == D(2026, 11, 1) and lic["expires"] == D(2027, 10, 31)


def test_shipped_key_is_p384_and_loads():
    keys = licence.load_public_keys()
    assert keys, "app/radius_admin/licence_keys/ must hold the production public key"
    for kid, k in keys.items():
        assert k.curve.name == "secp384r1" and len(kid) == 16


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d["payload"].update(licensee="Someone Else"), "signature is not valid"),
    (lambda d: d["payload"].update(expires="2099-12-31"), "signature is not valid"),
    (lambda d: d.update(signature=base64.b64encode(b"\x30\x00").decode()), "signature is not valid"),
    (lambda d: d.update(signature="not base64!"), "signature is not valid"),
    (lambda d: d.pop("signature"), "not signed"),
    (lambda d: d.update(format=2), "unknown format"),
    (lambda d: d.update(key_id="0123456789abcdef"), "key this version does not know"),
    (lambda d: d.update(key_id="../../etc/passwd"), "does not name its signing key"),
])
def test_tampered_or_incomplete_files_are_refused(signer, mutate, message):
    d = json.loads(sign(signer, payload()))
    mutate(d)
    with pytest.raises(licence.LicenceError, match=message):
        licence.parse(json.dumps(d))


def test_wrong_key_is_refused(signer):
    other = _key()
    text = sign(other, payload(), kid=licence.key_id(signer.public_key()))   # claims the known key
    with pytest.raises(licence.LicenceError, match="signature is not valid"):
        licence.parse(text)
    with pytest.raises(licence.LicenceError, match="does not know"):
        licence.parse(sign(other, payload()))


@pytest.mark.parametrize("p, message", [
    (payload(product="other-product"), "another product"),
    (payload(type="enterprise"), "unknown licence type"),
    (payload(licence_id="bad id with spaces"), "licence number"),
    (payload(licensee=" "), "licensee"),
    (payload(expires=None), "expiry"),
    (payload(expires="2027-02-30"), "expiry"),
    (payload(starts="2027-11-01", expires="2027-10-31"), "ends before it starts"),
    (payload(notes="x" * 1001), "invalid notes"),
])
def test_signed_but_unusable_payloads_are_refused(signer, p, message):
    with pytest.raises(licence.LicenceError, match=message):
        licence.parse(sign(signer, p))


def test_exception_without_end_date_is_valid(signer):
    lic = licence.parse(sign(signer, payload(type="exception", expires=None)))
    assert lic["expires"] is None


@pytest.mark.parametrize("text, message", [
    ("", "empty"), ("{not json", "not valid JSON"), ("[]", "unknown format"),
    ("x" * (licence.MAX_FILE + 1), "larger than"),
])
def test_malformed_input(signer, text, message):
    with pytest.raises(licence.LicenceError, match=message):
        licence.parse(text)


def test_non_p384_keys_are_ignored(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa
    k256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    rk = rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key()
    for name, k in (("a.pem", k256), ("b.pem", rk)):
        (tmp_path / name).write_bytes(k.public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo))
    (tmp_path / "c.pem").write_text("garbage")
    assert licence.load_public_keys(str(tmp_path)) == {}


# ----------------------------------------------------------------- status and reminders
def st(**kw):
    s = {k: "" for k in licence.SETTING_KEYS}
    s.update(kw)
    return s


def test_unanswered_has_no_dashboard_notice():
    s = licence.status(st(), D(2026, 12, 1))
    assert s["notice"] == "" and s["case"] == "" and "Not answered" in s["summary"]


def test_free_case_never_reminds():
    for day in (D(2026, 1, 1), D(2030, 1, 1)):
        s = licence.status(st(licence_case="free"), day)
        assert s["notice"] == "" and s["level"] == "ok" and "Free use" in s["summary"]


def test_two_choices_no_grace_period():
    assert list(licence.CHOICES) == ["free", "commercial"]
    assert "grace" not in licence.CASES and list(licence.PERIODS) == ["trial"]
    assert licence.CHOICES["free"].startswith("Free use")


def test_trial_info():
    assert licence.trial_info(st(), D(2026, 11, 1)) == {"started": None, "last": None, "left": 60, "ended": False}
    t = licence.trial_info(st(licence_trial_started="2026-11-01"), D(2026, 12, 30))
    assert t["last"] == D(2026, 12, 30) and t["left"] == 1 and not t["ended"]
    assert licence.trial_info(st(licence_trial_started="2026-11-01"), D(2026, 12, 31))["ended"]


@pytest.mark.parametrize("day, left, key", [
    (D(2026, 11, 1), 60, ""),            # day 1
    (D(2026, 12, 14), 17, ""),           # day 44
    (D(2026, 12, 15), 16, "trial-ending"),  # day 45
    (D(2026, 12, 30), 1, "trial-ending"),   # day 60, the last day
    (D(2026, 12, 31), 0, "trial-ended"),
    (D(2028, 6, 1), 0, "trial-ended"),   # persistent: no end
])
def test_trial_reminders(day, left, key):
    s = licence.status(st(licence_case="trial", licence_trial_started="2026-11-01"), day)
    assert s["period"]["last"] == D(2026, 12, 30) and s["period"]["left"] == left
    assert s["notice_key"] == key and bool(s["notice"]) == bool(key)
    if day > D(2026, 12, 30):
        assert "commercial licence" in s["summary"] and s["level"] == "warn"
        assert s["notice"].startswith("Trial ended on 2026-12-30")


def test_trial_ended_banner_cannot_be_hidden():
    state = st(licence_case="trial", licence_trial_started="2026-11-01",
               licence_notice_snoozed="trial-ended|2099-01-01")
    assert licence.status(state, D(2027, 2, 1))["notice"].startswith("Trial ended")


def test_commercial_licence_states(signer):
    text = sign(signer, payload())
    base = st(licence_case="commercial", licence_file=text)
    assert licence.status(base, D(2027, 3, 1))["notice"] == ""
    s = licence.status(base, D(2027, 10, 2))
    assert s["notice_key"] == "expiring-RA-2026-0001" and "29 days left" in s["notice"]
    s = licence.status(base, D(2027, 11, 15))
    assert s["notice_key"] == "expired-RA-2026-0001" and s["level"] == "warn"
    assert licence.status(base, D(2028, 1, 15))["notice"] == ""
    nofile = licence.status(st(licence_case="commercial"), D(2027, 3, 1))
    assert nofile["notice_key"] == "commercial-nofile"
    bad = licence.status(st(licence_case="commercial", licence_file=text.replace("Example Corp", "Evil")),
                         D(2027, 3, 1))
    assert bad["licence"] is None and "signature" in bad["file_error"] and bad["level"] == "warn"


# ----------------------------------------------------------------- pages
@pytest.fixture
def admin(browser, logged_in, superconn):
    from conftest import stepup
    user = logged_in("admin")
    stepup(browser, superconn, user)
    return user


def _audit(superconn, action):
    with superconn.cursor() as cur:
        cur.execute("SELECT success, detail FROM ui.audit_log WHERE action = %s ORDER BY id", (action,))
        return cur.fetchall()


def _settings(superconn):
    with superconn.cursor() as cur:
        cur.execute("SELECT key, value FROM ui.setting WHERE key LIKE 'licence%%'")
        return dict(cur.fetchall())


def _answer(superconn, case, **extra):
    with superconn.cursor() as cur:
        for k, v in dict(licence_case=case, **extra).items():
            cur.execute("INSERT INTO ui.setting (key, value) VALUES (%s, %s)"
                        " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (k, v))


def _confirm_change(browser, csrf, target):
    form = {"action": "save", "choice": "free"} if target == "free" else \
        {"action": "save", "choice": "commercial", "op": "trial"}
    r = browser.post("/settings/licence", form, csrf=csrf)
    t = browser.text(r)
    assert r.status_code == 200 and "Confirm change" in t
    if target == "trial":
        assert '<input type="hidden" name="op" value="trial">' in t
    return browser.post("/settings/licence", dict(form, confirmed="1", acknowledge="1"), csrf=csrf)


# --- the required first setup step
def test_admin_is_sent_to_the_prompt_until_answered(browser, logged_in, superconn):
    logged_in("admin")
    for path in ("/dashboard", "/clients/", "/settings", "/setup/"):
        r = browser.get(path)
        assert r.status_code == 302 and r.headers["Location"].endswith("/settings/licence"), path
    for path in ("/account/", "/static/app.css"):            # own account and assets stay reachable
        assert browser.get(path).status_code == 200, path
    _answer(superconn, "free")
    assert browser.get("/dashboard").status_code == 200


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_other_roles_are_never_sent_to_the_prompt(browser, logged_in, role):
    logged_in(role)
    t = browser.text(browser.get("/dashboard"))
    assert "licence-strip" not in t and "licence-banner" not in t
    assert "Business Source License 1.1" in t          # the footer is for everyone
    assert browser.get("/settings/licence").status_code == 403


def test_posts_are_not_redirected(browser, logged_in, superconn):
    """Only page loads go to the prompt; nothing an admin submits is blocked."""
    logged_in("admin")
    csrf = browser.csrf_from("/account/")
    r = browser.post("/licence/notice/hide", {"key": "x"}, csrf=csrf)
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")


def test_prompt_page_and_setup_step(browser, admin, superconn):
    t = browser.text(browser.get("/settings/licence"))
    assert "Before using the console, choose how this server is licensed" in t
    csrf = browser.csrf_from("/settings/licence")
    r = browser.post("/settings/licence", {"action": "save", "choice": "free"}, csrf=csrf)   # first answer
    assert r.status_code == 302 and _settings(superconn)["licence_case"] == "free"
    t = browser.text(browser.get("/setup/"))
    assert "Choose how this server is licensed" in t
    from radius_admin.views import setup as setup_v
    src = open(setup_v.__file__).read()
    assert '("licence", "Choose how this server is licensed", True' in src     # required, not skippable


# --- answering and changing
def test_trial_start_recorded_once_change_needs_confirmation(browser, admin, superconn, monkeypatch):
    monkeypatch.setattr(licence, "today", lambda: D(2026, 11, 1))
    csrf = browser.csrf_from("/settings/licence")
    r = browser.post("/settings/licence", {"action": "save", "choice": "commercial", "op": "trial"}, csrf=csrf)  # first: no confirm
    assert r.status_code == 302
    assert _settings(superconn)["licence_trial_started"] == "2026-11-01"
    monkeypatch.setattr(licence, "today", lambda: D(2026, 11, 20))
    r = browser.post("/settings/licence", {"action": "save", "choice": "free"}, csrf=csrf)
    t = browser.text(r)
    assert r.status_code == 200 and "Headcount" in t and 'name="acknowledge"' in t
    assert _settings(superconn)["licence_case"] == "trial"                        # nothing saved yet
    r = browser.post("/settings/licence", {"action": "save", "choice": "free", "confirmed": "1"}, csrf=csrf)
    assert r.status_code == 400 and "Tick the box" in browser.text(r)
    assert _settings(superconn)["licence_case"] == "trial"
    assert _confirm_change(browser, csrf, "free").status_code == 302
    assert _confirm_change(browser, csrf, "trial").status_code == 302
    browser.post("/settings/licence", {"action": "save", "choice": "commercial", "op": "trial"}, csrf=csrf)   # unchanged: not audited
    s = _settings(superconn)
    assert s["licence_case"] == "trial" and s["licence_trial_started"] == "2026-11-01"   # never resets
    rows = _audit(superconn, "licence.declare")
    assert [r[1]["case"] for r in rows] == ["trial", "free", "trial"]
    assert rows[0][1]["period_started"] == "2026-11-01" and "acknowledged" not in rows[0][1]
    assert rows[1][1]["from"] == "trial" and rows[1][1]["acknowledged"] is True
    t = browser.text(browser.get("/settings/licence"))
    assert "runs until 2026-12-30 (41 days left)" in t
    hist = t.split('id="lic-history"', 1)[1]
    assert hist.count("<tr>") == 4                       # header + three answers
    assert "Commercial trial" in hist and "Free use" in hist and "Not answered" in hist


def test_upload_valid_file_switches_to_commercial(browser, admin, superconn, signer, monkeypatch):
    monkeypatch.setattr(licence, "today", lambda: D(2027, 1, 1))
    csrf = browser.csrf_from("/settings/licence")
    r = browser.post("/settings/licence", {"action": "save", "choice": "commercial",
                                           "text": sign(signer, payload())}, csrf=csrf)
    assert r.status_code == 302
    s = _settings(superconn)
    assert s["licence_case"] == "commercial" and "RA-2026-0001" in s["licence_file"]
    ok, detail = _audit(superconn, "licence.file_upload")[-1]
    assert ok and detail["licence_id"] == "RA-2026-0001" and detail["expires"] == "2027-10-31"
    t = browser.text(browser.get("/settings/licence"))
    assert "valid until 2027-10-31" in t and "Example Corp" in t
    assert "licence-strip" not in browser.text(browser.get("/dashboard"))
    browser.post("/settings/licence", {"action": "remove"}, csrf=csrf)
    assert _settings(superconn)["licence_file"] == ""
    assert _audit(superconn, "licence.file_remove")


def test_upload_as_file_field(browser, admin, superconn, signer):
    import io
    csrf = browser.csrf_from("/settings/licence")
    data = {"action": "save", "choice": "commercial",
            "file": (io.BytesIO(sign(signer, payload()).encode()), "licence.json")}
    r = browser.post("/settings/licence", data, csrf=csrf, content_type="multipart/form-data")
    assert r.status_code == 302 and "RA-2026-0001" in _settings(superconn)["licence_file"]


def test_tampered_upload_is_refused_and_audited(browser, admin, superconn, signer):
    csrf = browser.csrf_from("/settings/licence")
    text = sign(signer, payload()).replace("50-249", "5000+")
    r = browser.post("/settings/licence", {"action": "save", "choice": "commercial", "text": text}, csrf=csrf)
    assert r.status_code == 400 and "signature is not valid" in browser.text(r)
    assert "licence_file" not in _settings(superconn) and "licence_case" not in _settings(superconn)
    ok, detail = _audit(superconn, "licence.file_upload")[-1]
    assert not ok and "signature" in detail["error"]


def test_licence_choice_needs_a_file_and_keeps_an_installed_one(browser, admin, superconn, signer, monkeypatch):
    monkeypatch.setattr(licence, "today", lambda: D(2027, 1, 1))
    csrf = browser.csrf_from("/settings/licence")
    r = browser.post("/settings/licence", {"action": "save", "choice": "commercial"}, csrf=csrf)
    assert r.status_code == 400 and "Upload the licence file" in browser.text(r)
    assert "licence_case" not in _settings(superconn)
    assert 'id="lic-file-box" class="licence-file">' in browser.text(r)    # fields stay open after the error
    browser.post("/settings/licence", {"action": "save", "choice": "commercial", "text": sign(signer, payload())},
                 csrf=csrf)
    assert _confirm_change(browser, csrf, "free").status_code == 302
    r = browser.post("/settings/licence", {"action": "save", "choice": "commercial"}, csrf=csrf)   # keeps the file
    assert r.status_code == 302 and _settings(superconn)["licence_case"] == "commercial"


def test_file_fields_hidden_unless_licence_is_chosen(browser, admin):
    t = browser.text(browser.get("/settings/licence"))
    assert 'id="lic-file-box" class="licence-file" hidden>' in t
    assert 'id="lic-trial-box" class="licence-trial" hidden>' in t
    assert 'data-reveal-box="lic-file-box lic-trial-box" data-reveal-value="commercial"' in t
    assert 'name="op" value="trial">Start the 60-day trial</button>' in t
    assert t.index('id="lic-trial-box"') < t.index('id="lic-file-box"')       # trial offer above the upload
    assert '<details class="licence-paste">' in t and "Paste the licence contents instead" in t   # collapsed
    assert "Choose…" in t and "employee count" not in t.lower()


def test_unknown_choice_is_refused(browser, admin, superconn):
    csrf = browser.csrf_from("/settings/licence")
    for bad in ("personal", "grace", "trial", "licensed", ""):
        r = browser.post("/settings/licence", {"action": "save", "choice": bad}, csrf=csrf)
        assert r.status_code == 400, bad
    assert "licence_case" not in _settings(superconn)


# --- reminders and the banner
def test_dashboard_reminder_and_hide(browser, logged_in, superconn, monkeypatch):
    _answer(superconn, "trial", licence_trial_started="2026-11-01")
    monkeypatch.setattr(licence, "today", lambda: D(2026, 12, 20))
    logged_in("admin")
    t = browser.text(browser.get("/dashboard"))
    assert 'class="panel licence-strip"' in t and "The trial ends on 2026-12-30" in t
    csrf = browser.csrf_from("/dashboard")
    browser.post("/licence/notice/hide", {"key": "expired-x"}, csrf=csrf)       # not the current one: ignored
    assert "licence-strip" in browser.text(browser.get("/dashboard"))
    browser.post("/licence/notice/hide", {"key": "trial-ending"}, csrf=csrf)
    assert "licence-strip" not in browser.text(browser.get("/dashboard"))
    assert _settings(superconn)["licence_notice_snoozed"] == "trial-ending|2027-01-19"


def test_trial_ended_banner_on_every_admin_page(browser, logged_in, superconn, monkeypatch):
    """After the trial: a banner on every admin page, no hide button, nothing locked."""
    _answer(superconn, "trial", licence_trial_started="2026-11-01")
    monkeypatch.setattr(licence, "today", lambda: D(2028, 1, 1))
    logged_in("admin")
    for path in ("/dashboard", "/clients/", "/rules/", "/settings", "/sessions/"):
        r = browser.get(path)
        assert r.status_code == 200, path
        t = browser.text(r)
        assert 'class="licence-banner"' in t and "Trial ended on 2026-12-30" in t, path
    assert "licence-strip" not in browser.text(browser.get("/dashboard"))     # not twice, not hideable
    csrf = browser.csrf_from("/dashboard")
    browser.post("/licence/notice/hide", {"key": "trial-ended"}, csrf=csrf)
    assert "Trial ended on 2026-12-30" in browser.text(browser.get("/clients/"))


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_trial_ended_banner_is_for_admins_only(browser, logged_in, superconn, monkeypatch, role):
    _answer(superconn, "trial", licence_trial_started="2026-11-01")
    monkeypatch.setattr(licence, "today", lambda: D(2028, 1, 1))
    logged_in(role)
    assert "licence-banner" not in browser.text(browser.get("/dashboard"))


def test_overview_links_to_licence(browser, logged_in, superconn):
    _answer(superconn, "free")
    logged_in("admin")
    assert 'href="/settings/licence"' in browser.text(browser.get("/settings/overview"))
    t = browser.text(browser.get("/dashboard"))
    assert re.search(r'<footer class="app-foot">.*Business Source License 1\.1', t, re.S)


def test_trial_is_offered_once_and_continues(browser, admin, superconn, monkeypatch):
    monkeypatch.setattr(licence, "today", lambda: D(2026, 11, 1))
    csrf = browser.csrf_from("/settings/licence")
    browser.post("/settings/licence", {"action": "save", "choice": "commercial", "op": "trial"}, csrf=csrf)
    monkeypatch.setattr(licence, "today", lambda: D(2026, 11, 20))
    t = browser.text(browser.get("/settings/licence"))
    assert "Trial: 41 days left" in t and 'value="trial">' not in t       # no trial button while it runs
    assert t.index("Trial: 41 days left") < t.index('id="lic-file-box"')
    assert '<option value="commercial" selected>' in t
    r = browser.post("/settings/licence", {"action": "save", "choice": "commercial", "op": "save"}, csrf=csrf)
    assert r.status_code == 302 and _settings(superconn)["licence_case"] == "trial"
    assert "The trial continues" in browser.text(browser.get("/settings/licence"))


def test_ended_trial_does_not_restart(browser, admin, superconn, monkeypatch):
    _answer(superconn, "free", licence_trial_started="2026-11-01")
    monkeypatch.setattr(licence, "today", lambda: D(2027, 3, 1))
    t = browser.text(browser.get("/settings/licence"))
    assert "The trial ended on 2026-12-30 and does not restart." in t and 'value="trial">' not in t
    csrf = browser.csrf_from("/settings/licence")
    r = browser.post("/settings/licence", {"action": "save", "choice": "commercial", "op": "trial",
                                           "confirmed": "1", "acknowledge": "1"}, csrf=csrf)
    assert r.status_code == 400 and "does not restart" in browser.text(r)
    assert _settings(superconn)["licence_case"] == "free"


def test_commercial_save_without_file_or_trial_asks_for_one(browser, admin, superconn):
    csrf = browser.csrf_from("/settings/licence")
    r = browser.post("/settings/licence", {"action": "save", "choice": "commercial", "op": "save"}, csrf=csrf)
    assert r.status_code == 400 and "Start the trial instead" in browser.text(r)
    assert "licence_case" not in _settings(superconn)
