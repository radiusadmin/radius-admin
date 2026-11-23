"""The Duo pages (SPEC section 29.2): status, download/upload/install through the helper,
settings, the Duo configuration staged and applied with FreeRADIUS's files."""
import io
import json
import os
import re

import pytest

from conftest import stepup

IKEY, SKEY, API = "DIAAAAAAAAAAAAAAAAAA", "S" * 40, "api-00000000.duosecurity.com"
SETTINGS_FORM = {"ikey": IKEY, "skey": SKEY, "api_host": API, "failmode": "secure", "factors": "auto"}


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


@pytest.fixture
def idir(app, tmp_path):
    d = tmp_path / "integrations"
    d.mkdir()
    app.config["RA"]["integration_dir"] = str(d)
    return d


def helper_of(browser):
    return browser.app.fake_helper


def audit(superconn, action):
    return [json.loads(d) for (d,) in q(superconn, "SELECT detail::text FROM ui.audit_log WHERE action=%s ORDER BY id",
                                        (action,))]


def admin(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    return u


def test_viewer_sees_state_without_actions(browser, superconn, logged_in, idir):
    logged_in("viewer")
    body = browser.text(browser.get("/integrations/duo"))
    assert "Duo Authentication Proxy" in body and "Installed" in body
    for action in ("Check this server", "Upload", "Connect to Duo", "Remove Duo"):
        assert action not in body
    assert "FIPS" not in body
    assert browser.post("/integrations/duo/fetch", {"version": "6.8.1"}, csrf_page="/integrations/").status_code in (302, 403)


def test_admin_page_lists_catalog_and_builds(browser, superconn, logged_in, idir):
    h = helper_of(browser)
    h.catalog = {"serial": 3, "source": "release", "message": "", "entries": [
        {"provider": "duo", "version": "6.8.1", "sha256": "b" * 64, "fips": False, "withdrawn": False},
        {"provider": "duo", "version": "6.7.0", "sha256": "c" * 64, "fips": False, "withdrawn": True}]}
    (idir / "duoauthproxy-6.8.1-src.tgz").write_bytes(b"x")
    (idir / "notes.txt").write_bytes(b"x")
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    assert "6.8.1" in body and "serial 3" in body and "6.7.0" not in body          # withdrawn hidden
    assert 'name="file" value="duoauthproxy-6.8.1-src.tgz"' in body and "notes.txt" not in body
    assert "Not in the signed catalog?" in body


def test_preflight_shows_the_checks(browser, superconn, logged_in, idir):
    admin(browser, superconn, logged_in)
    r = browser.post("/integrations/duo/check", csrf_page="/integrations/duo")
    assert r.status_code == 200 and "Ubuntu 24.04 LTS" in browser.text(r)
    # rule 12: the check (it contacts Duo's API host through the helper) is audited
    assert audit(superconn, "integration.preflight") == [{"ready": True, "failed": []}]


def test_preflight_audit_names_the_failed_checks(browser, superconn, logged_in, idir):
    admin(browser, superconn, logged_in)
    q(superconn, "INSERT INTO ui.mfa_provider (id, type, label, settings) VALUES ('duo', 'duo', 'Duo', %s)"
                 " ON CONFLICT (id) DO UPDATE SET settings = EXCLUDED.settings",
      ('{"api_host": "api-test.duosecurity.com"}',))
    r = browser.post("/integrations/duo/check", csrf_page="/integrations/duo")
    assert r.status_code == 200
    rows = q(superconn, "SELECT success, object_type, object_id, detail::text FROM ui.audit_log"
                        " WHERE action = 'integration.preflight'")
    assert len(rows) == 1 and rows[0][:3] == (False, "integration", "duo"), rows
    assert json.loads(rows[0][3]) == {"ready": False, "failed": ["api"], "api_host": "api-test.duosecurity.com"}


def test_fetch_and_install_go_to_the_helper(browser, superconn, logged_in, idir):
    h = helper_of(browser)
    u = admin(browser, superconn, logged_in)
    r = browser.post("/integrations/duo/fetch", {"version": "6.8.1"}, csrf_page="/integrations/duo")
    assert r.status_code == 302
    assert {"action": "integration_fetch", "id": "duo", "version": "6.8.1"}.items() <= h.requests[-1].items()
    assert browser.post("/integrations/duo/fetch", {"version": "6.8;x"}, csrf_page="/integrations/duo").status_code == 302
    assert h.requests[-1]["action"] != "integration_fetch" or h.requests[-1]["version"] == "6.8.1"
    (idir / "duoauthproxy-6.8.1-src.tgz").write_bytes(b"x")
    r = browser.post("/integrations/duo/install", {"file": "duoauthproxy-6.8.1-src.tgz"}, csrf_page="/integrations/duo")
    req = h.requests[-1]
    assert req["action"] == "integration_install" and req["file"] == "duoauthproxy-6.8.1-src.tgz"
    assert req["actor"] == u.username and "sha256" not in req
    assert audit(superconn, "integration.install_requested")[-1]["verified"] == "catalog"
    # a file that is not there is not sent
    n = len(h.requests)
    browser.post("/integrations/duo/install", {"file": "duoauthproxy-9.9.9-src.tgz"}, csrf_page="/integrations/duo")
    assert not any(r_["action"] == "integration_install" for r_ in h.requests[n:])


def test_install_with_an_entered_hash_needs_the_confirmation(browser, superconn, logged_in, idir):
    h = helper_of(browser)
    admin(browser, superconn, logged_in)
    (idir / "duoauthproxy-6.8.1-src.tgz").write_bytes(b"x")
    form = {"file": "duoauthproxy-6.8.1-src.tgz", "sha256": "A" * 64}
    n = len(h.requests)
    browser.post("/integrations/duo/install", form, csrf_page="/integrations/duo")
    assert not any(r_["action"] == "integration_install" for r_ in h.requests[n:])
    browser.post("/integrations/duo/install", dict(form, confirm_unverified="1"), csrf_page="/integrations/duo")
    assert h.requests[-1]["action"] == "integration_install" and h.requests[-1]["sha256"] == "a" * 64


def test_fips_mode_never_sends_an_entered_hash(app, browser, superconn, logged_in, idir):
    app.config["RA"]["require_fips"] = True
    h = helper_of(browser)
    admin(browser, superconn, logged_in)
    (idir / "duoauthproxy-6.8.1-src.tgz").write_bytes(b"x")
    body = browser.text(browser.get("/integrations/duo"))
    assert "Not in the signed catalog?" not in body and "FIPS mode" in body
    browser.post("/integrations/duo/install", {"file": "duoauthproxy-6.8.1-src.tgz", "sha256": "a" * 64,
                                               "confirm_unverified": "1"}, csrf_page="/integrations/duo")
    assert h.requests[-1]["action"] == "integration_install" and "sha256" not in h.requests[-1]


def test_upload_larger_than_the_global_limit(browser, superconn, logged_in, idir):
    admin(browser, superconn, logged_in)
    data = b"\x1f\x8b" + os.urandom(3 * 1024 * 1024)
    r = browser.post("/integrations/duo/upload", {"build": (io.BytesIO(data), "duoauthproxy-6.8.1-src.tgz")},
                     csrf_page="/integrations/duo", content_type="multipart/form-data")
    assert r.status_code == 302
    p = idir / "duoauthproxy-6.8.1-src.tgz"
    assert p.read_bytes() == data and oct(p.stat().st_mode & 0o777) == "0o640"
    assert audit(superconn, "integration.upload")[-1]["size"] == len(data)
    # other pages keep the 2 MiB limit
    r = browser.post("/integrations/policy", {"exempt": "x" * (3 * 1024 * 1024)}, csrf_page="/integrations/policy")
    assert r.status_code == 413


@pytest.mark.parametrize("name", ["evil.tgz", "../duoauthproxy-6.8.1-src.tgz", "duoauthproxy-6.8.1-src.tgz.sh"])
def test_upload_name_must_be_a_duo_build(browser, superconn, logged_in, idir, name):
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/upload", {"build": (io.BytesIO(b"x"), name)}, csrf_page="/integrations/duo",
                 content_type="multipart/form-data")
    assert [p.name for p in idir.iterdir()] in ([], ["duoauthproxy-6.8.1-src.tgz"]) and not (idir / "evil.tgz").exists()
    if name.startswith("../"):
        # the directory part is dropped: never written outside integration_dir
        assert not (idir.parent / "duoauthproxy-6.8.1-src.tgz").exists()


def test_settings_secret_key_encrypted_and_enable_needs_install(app, browser, superconn, logged_in, idir):
    from radius_admin import integrations as ig
    h = helper_of(browser)
    admin(browser, superconn, logged_in)
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    assert r.status_code == 400 and "Install the Duo Authentication Proxy first" in browser.text(r)
    r = browser.post("/integrations/duo/settings", SETTINGS_FORM, csrf_page="/integrations/duo")
    assert r.status_code == 302
    row = q(superconn, "SELECT type, enabled, settings::text, secrets_enc FROM ui.mfa_provider WHERE id='duo'")[0]
    assert row[0] == "duo" and row[1] is False and json.loads(row[2])["ikey"] == IKEY
    assert SKEY.encode() not in bytes(row[3])
    secrets = ig.decrypt_secrets(app.config["RA_DATA_KEY"], "duo", row[3])
    assert secrets["skey"] == SKEY and re.fullmatch(r"[A-Za-z0-9]{32}", secrets["secret"])
    assert secrets["primary_secret"] != secrets["secret"]
    d = audit(superconn, "integration.configure")[-1]
    assert d["duo_skey_updated"] is True and SKEY not in json.dumps(d)
    # saving again without the secret key keeps it and the generated secrets
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", factors="push"), csrf_page="/integrations/duo")
    again = ig.decrypt_secrets(app.config["RA_DATA_KEY"], "duo",
                               q(superconn, "SELECT secrets_enc FROM ui.mfa_provider WHERE id='duo'")[0][0])
    assert again == secrets
    h.duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", enabled="1"), csrf_page="/integrations/duo")
    assert r.status_code == 302 and q(superconn, "SELECT enabled FROM ui.mfa_provider WHERE id='duo'")[0][0] is True


@pytest.mark.parametrize("change,msg", [(dict(ikey="DI1"), "Integration key"), (dict(skey="short"), "Secret key"),
                                        (dict(api_host="evil.example.net"), "API hostname")])
def test_settings_validation(browser, superconn, logged_in, idir, change, msg):
    admin(browser, superconn, logged_in)
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, **change), csrf_page="/integrations/duo")
    assert r.status_code == 400 and msg in browser.text(r)


def test_duo_config_staged_and_applied(app, browser, superconn, logged_in, idir):
    from radius_admin import integrations as ig, unlang
    h = helper_of(browser)
    h.duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    page = browser.text(browser.get("/apply/"))
    assert "Duo Authentication Proxy" in page and "skey=********" in page and SKEY not in page
    m = re.search(r'name="expected" value="([^"]+)"', page)
    assert m and m.group(1).count(":") == 2 and not m.group(1).endswith(":")
    r = browser.post("/apply/apply", {"expected": m.group(1)}, csrf_page="/apply/")
    assert r.status_code == 200
    staging = app.config["RA"]["staging_dir"]
    staged = h.staged["provider-duo"][0]          # what the helper read; removed from staging since
    assert not os.path.exists(os.path.join(staging, "provider-duo"))
    secrets = ig.decrypt_secrets(app.config["RA_DATA_KEY"], "duo",
                                 q(superconn, "SELECT secrets_enc FROM ui.mfa_provider WHERE id='duo'")[0][0])
    assert staged == unlang.render_duo_config(dict(json.loads(q(superconn, "SELECT settings::text FROM ui.mfa_provider"
                                                                            " WHERE id='duo'")[0][0]), **secrets))
    assert "home_server radius_admin_mfa_duo" in h.staged["clients"][0]
    row = q(superconn, "SELECT providers_sha256 FROM ui.apply_log WHERE action='apply' ORDER BY id DESC LIMIT 1")[0][0]
    assert row and len(row) == 64
    with open(os.path.join(staging, "applied", "provider-duo")) as fh:     # sealed with the data key
        assert secrets["skey"] not in fh.read()
    with app.app_context():
        from radius_admin import services
        assert services.read_applied(staging)["providers"]["provider-duo"] == staged
    # nothing pending afterwards; turning Duo off removes its file from the next staging
    with app.test_request_context():
        from radius_admin import services
        assert services.pending_state()["pending"] is False
    q(superconn, "UPDATE ui.mfa_provider SET enabled=false WHERE id='duo'")
    page = browser.text(browser.get("/apply/"))
    m = re.search(r'name="expected" value="([^"]+)"', page)
    assert m.group(1).endswith(":")
    browser.post("/apply/apply", {"expected": m.group(1)}, csrf_page="/apply/")
    assert "provider-duo" not in h.staged


def test_duo_can_serve_local_accounts_in_the_rules(browser, superconn, logged_in, idir):
    h = helper_of(browser)
    h.duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    q(superconn, "INSERT INTO radusergroup (username, groupname, priority) VALUES ('breakglass', 'net-admins', 1)")
    r = browser.post("/integrations/policy", {"local_enabled": "1", "local_provider": "duo", "local_scope": "all",
                                              "directory_scope": "all", "exempt": "breakglass"},
                     csrf_page="/integrations/policy")
    assert r.status_code == 302
    assert q(superconn, "SELECT enabled, provider_id FROM ui.mfa_policy WHERE account_kind='local'")[0] == (True, "duo")
    # in use: cannot be turned off, nor removed through the providers table
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey=""), csrf_page="/integrations/duo")
    assert r.status_code == 400 and "rule uses Duo" in browser.text(r)
    browser.post("/integrations/duo/delete", csrf_page="/integrations/")
    assert q(superconn, "SELECT count(*) FROM ui.mfa_provider WHERE id='duo'")[0][0] == 1


def test_local_rule_needs_break_glass_or_confirmation(browser, superconn, logged_in, idir):
    """A Duo outage rejects (not drops) every local admin login the rule covers, so devices do not
    fall back to their own accounts: the local rule needs an exempt account or an explicit OK."""
    h = helper_of(browser)
    h.duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    form = {"local_enabled": "1", "local_provider": "duo", "local_scope": "all", "directory_scope": "all",
            "exempt": ""}
    r = browser.post("/integrations/policy", form, csrf_page="/integrations/policy")
    assert r.status_code == 400 and "break-glass" in browser.text(r)
    assert q(superconn, "SELECT enabled FROM ui.mfa_policy WHERE account_kind='local'")[0] == (False,)
    # the directory rule alone leaves local accounts alone: no exempt account needed
    r = browser.post("/integrations/policy", {"directory_enabled": "1", "directory_provider": "duo",
                                              "local_scope": "all", "directory_scope": "all", "exempt": ""},
                     csrf_page="/integrations/policy")
    assert r.status_code == 302, browser.text(r)
    # an explicit confirmation is accepted and audited
    r = browser.post("/integrations/policy", dict(form, no_exempt_ok="1"), csrf_page="/integrations/policy")
    assert r.status_code == 302, browser.text(r)
    assert q(superconn, "SELECT enabled FROM ui.mfa_policy WHERE account_kind='local'")[0] == (True,)
    d = audit(superconn, "integration.policy")[-1]
    assert d.get("no_exempt_confirmed") is True
    # clearing the last exempt account later needs the same confirmation
    q(superconn, "INSERT INTO radusergroup (username, groupname, priority) VALUES ('breakglass', 'net-admins', 1)")
    assert browser.post("/integrations/policy", dict(form, exempt="breakglass"),
                        csrf_page="/integrations/policy").status_code == 302
    r = browser.post("/integrations/policy", form, csrf_page="/integrations/policy")
    assert r.status_code == 400 and "break-glass" in browser.text(r)
    assert q(superconn, "SELECT username FROM ui.mfa_exempt") == [("breakglass",)]


def test_remove_and_test(browser, superconn, logged_in, idir):
    h = helper_of(browser)
    h.duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    browser.post("/apply/apply", {}, csrf_page="/apply/")          # Test needs an applied configuration
    r = browser.post("/integrations/duo/test", csrf_page="/integrations/duo")
    body = browser.text(r)
    assert "able to reach Duo" in body and audit(superconn, "integration.test")
    browser.post("/integrations/duo/remove", csrf_page="/integrations/duo")         # off, applied, removed
    assert h.requests[-1]["action"] == "integration_remove"


def test_status_and_log_json(browser, superconn, logged_in, idir):
    h = helper_of(browser)
    h.duo["state"] = {"state": "installing", "action": "install", "message": "building"}
    h.integration_log = "line one\nline two\n"
    logged_in("viewer")
    d = browser.get("/integrations/duo/status?wait=install").get_json()
    assert d["done"] is False and d["message"] == "Building…"
    d = browser.get("/integrations/duo/log").get_json()
    assert d["available"] and d["running"] and d["text"] == "line one\nline two\n"
    from radius_admin.integration_fetch import write_status
    write_status(str(idir), "duo", state="downloading", file="duoauthproxy-6.8.1-src.tgz")
    d = browser.get("/integrations/duo/status?wait=fetch").get_json()
    assert d["done"] is False and "duoauthproxy-6.8.1-src.tgz" in d["message"]


def test_integrations_page_has_duo_buttons(browser, superconn, logged_in, idir):
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/"))
    assert body.count('class="btn btn-primary" href="/integrations/duo">Set up Duo</a>') == 1
    assert 'class="btn btn-primary btn-small" href="/integrations/duo">Set up Duo</a>' in body
    browser.post("/integrations/duo/settings", SETTINGS_FORM, csrf_page="/integrations/duo")
    body = browser.text(browser.get("/integrations/"))
    assert 'class="btn btn-primary" href="/integrations/duo">Set up Duo' not in body      # set up: "Open" in the table
    assert 'href="/integrations/duo">Open</a>' in body


def test_page_follows_the_catalog_after_install(browser, superconn, logged_in, idir):
    """An entered-hash install counts as checked once a catalog lists its SHA-256, and a build
    the catalog withdrew is flagged (SPEC sections 29 and 29.4)."""
    h = helper_of(browser)
    h.duo.update(installed={"version": "6.9.0", "sha256": "d" * 64, "verified": "pasted-hash"},
                 service_active=True, listening=True)
    logged_in("viewer")
    body = browser.text(browser.get("/integrations/duo"))
    assert "Unverified: SHA-256 entered by an admin" in body and "does not list it yet" in body
    h.catalog = {"serial": 5, "source": "release", "message": "", "entries": [
        {"provider": "duo", "version": "6.9.0", "sha256": "d" * 64, "fips": False, "withdrawn": False}]}
    body = browser.text(browser.get("/integrations/duo"))
    assert "checked against the signed catalog" in body and "Unverified" not in body
    h.catalog["entries"][0]["withdrawn"] = True
    body = browser.text(browser.get("/integrations/duo"))
    assert "withdrawn from the signed catalog" in body and "withdrew this build" in body
    assert "checked against the signed catalog" not in body


def test_apply_with_a_duo_change_waits_longer(app, browser, superconn, logged_in, idir, monkeypatch):
    """SPEC section 29.4: an apply that restarts the Duo proxy too can take the helper ~180 s
    (both services failing and being restored); the portal then waits helper_duo_timeout, and
    gunicorn and nginx wait longer than that."""
    from radius_admin import helper_client
    waits = []
    real = helper_client.call

    def spy(sock, action, timeout=120, **kw):
        if action in ("apply", "rollback"):
            waits.append((action, timeout))
        return real(sock, action, timeout=timeout, **kw)
    monkeypatch.setattr(helper_client, "call", spy)
    helper_of(browser).duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    admin(browser, superconn, logged_in)
    page = browser.text(browser.get("/apply/"))
    assert "Applying…\"" in page                                    # nothing about Duo yet
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    page = browser.text(browser.get("/apply/"))
    assert "with Duo this can take a few minutes" in page
    browser.post("/apply/apply", {}, csrf_page="/apply/")           # Duo file changes: long wait
    browser.post("/apply/apply", {}, csrf_page="/apply/")           # unchanged: the usual wait
    assert waits == [("apply", 10), ("apply", 210), ("apply", 10)]
    bid = helper_of(browser).backups[0]
    browser.post("/apply/rollback", {"backup_id": bid}, csrf_page="/apply/")
    assert waits[-1] == ("rollback", 210)
    # the timeouts in front of the portal are longer than the longest helper wait
    from radius_admin.config import DEFAULTS
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "deploy")
    with open(os.path.join(root, "systemd", "radius-admin.service")) as fh:
        gunicorn = int(re.search(r"--timeout (\d+)", fh.read()).group(1))
    with open(os.path.join(root, "nginx", "radius-admin.conf")) as fh:
        nginx = int(re.search(r"proxy_read_timeout (\d+)s;", fh.read()).group(1))
    with open(os.path.join(root, "etc", "helper.conf.example")) as fh:
        h = dict(re.findall(r"(?m)^(lock_timeout|validate_timeout|restart_timeout|restart_wait) = (\d+)", fh.read()))
    worst = int(h["lock_timeout"]) + int(h["validate_timeout"]) + 4 * (int(h["restart_timeout"]) + int(h["restart_wait"]))
    assert worst < DEFAULTS["helper_duo_timeout"] < gunicorn and DEFAULTS["helper_duo_timeout"] < nginx


def test_fips_mode_turns_duo_on_only_with_a_fips_capable_build(app, browser, superconn, logged_in, idir):
    """SPEC section 29.4: in FIPS mode Duo can be turned on only when the installed build was
    installed in FIPS mode and the signed catalog lists it as FIPS-capable."""
    h = helper_of(browser)
    h.duo["installed"] = {"version": "6.8.1", "sha256": "b" * 64, "verified": "catalog", "fips": False}
    h.catalog = {"serial": 2, "source": "release", "message": "", "entries": [
        {"provider": "duo", "version": "6.8.1", "sha256": "b" * 64, "fips": False, "withdrawn": False}]}
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    assert "not FIPS-capable" not in body                            # standard mode: never mentioned
    assert not _has(_switch(body), "disabled")
    app.config["RA"]["require_fips"] = True
    body = browser.text(browser.get("/integrations/duo"))
    assert "FIPS mode: this build is not FIPS-capable" in body and "installed before FIPS mode" in body
    assert _has(_switch(body), "disabled") and 'id="enabled-locked"' in body                # with the reason
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    assert r.status_code == 400 and "Install a FIPS-capable build first" in browser.text(r)
    assert q(superconn, "SELECT enabled FROM ui.mfa_provider WHERE id='duo'") in ([], [(False,)])
    # saving with Duo off still works
    r = browser.post("/integrations/duo/settings", SETTINGS_FORM, csrf_page="/integrations/duo")
    assert r.status_code == 302
    h.catalog["entries"][0].update(fips=True, fips_tested=["ubuntu-24.04-pro-fips-updates"])
    h.duo["installed"]["fips"] = True
    body = browser.text(browser.get("/integrations/duo"))
    assert "not FIPS-capable" not in body and not _has(_switch(body), "disabled")
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    assert r.status_code == 302 and q(superconn, "SELECT enabled FROM ui.mfa_provider WHERE id='duo'") == [(True,)]


def test_checks_return_to_their_section(browser, superconn, logged_in, idir):
    """The server check and the connectivity check post to an address with the section's
    fragment, so the result page opens at the result instead of the top."""
    helper_of(browser).duo.update(installed={"version": "6.8.1", "verified": "catalog"}, service_active=True)
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    browser.post("/apply/apply", {}, csrf_page="/apply/")          # Test needs an applied configuration
    body = browser.text(browser.get("/integrations/duo"))
    assert 'action="/integrations/duo/check#duo-check"' in body and 'id="duo-check"' in body
    assert 'action="/integrations/duo/test#duo-test"' in body and 'id="duo-test"' in body
    body = browser.text(browser.post("/integrations/duo/test", {}, csrf_page="/integrations/duo"))
    assert 'id="duo-test"' in body and "The Auth Proxy was able to reach Duo" in body
    # the back link above the heading is a button
    assert '<a class="btn btn-quiet btn-small btn-back" href="/integrations/">Integrations</a>' in body


def _switch(body):
    """The Enabled/Disabled switch of the Duo provider (SPEC section 29.3)."""
    m = re.search(r'<input[^>]*role="switch"[^>]*>', body)
    assert m, "no switch on the page"
    return m.group(0)


def _has(tag, attr):
    return re.search(r"\s%s[\s>=]" % attr, tag) is not None


def _plain(body):
    return " ".join(re.sub(r"<[^>]+>", " ", body).split())


def test_provider_switch_shows_state_and_why_it_is_locked(browser, superconn, logged_in, idir):
    """SPEC section 29.3: Duo is turned on and off with a switch, a real checkbox with role=switch
    and visible Enabled/Disabled text. When the server would refuse the change the switch is
    disabled and the reason is next to it, instead of an error after Save."""
    h = helper_of(browser)
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    sw = _switch(body)
    assert 'type="checkbox"' in sw and 'name="enabled"' in sw and 'value="1"' in sw
    assert '<span class="switch-on">Enabled</span>' in body and '<span class="switch-off">Disabled</span>' in body
    # not installed: cannot be turned on
    assert not _has(sw, "checked") and _has(sw, "disabled")
    assert "enabled-locked" in sw and 'id="enabled-locked"' in body
    assert "Install the Duo Authentication Proxy first" in body
    # the helper does not answer: the install state is unknown
    h.fail_next["integration_status"] = {"message": "helper down"}
    body = browser.text(browser.get("/integrations/duo"))
    assert _has(_switch(body), "disabled") and "install state is unknown" in _plain(body).split("Second factors")[1]
    # installed: free to turn on
    h.duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    body = browser.text(browser.get("/integrations/duo"))
    sw = _switch(body)
    assert not _has(sw, "disabled") and not _has(sw, "checked") and 'id="enabled-locked"' not in body
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    assert r.status_code == 302
    sw = _switch(browser.text(browser.get("/integrations/duo")))
    assert _has(sw, "checked") and not _has(sw, "disabled")
    # a second-factor rule names Duo: locked on, and a save keeps it on
    q(superconn, "UPDATE ui.mfa_policy SET enabled=true, provider_id='duo' WHERE account_kind='directory'")
    body = browser.text(browser.get("/integrations/duo"))
    sw = _switch(body)
    assert _has(sw, "checked") and _has(sw, "disabled") and "A second-factor rule uses Duo" in body
    assert '<input type="hidden" name="enabled" value="1">' in body
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", enabled="1"),
                     csrf_page="/integrations/duo")
    assert r.status_code == 302 and q(superconn, "SELECT enabled FROM ui.mfa_provider WHERE id='duo'") == [(True,)]
    # the rule is off again: the switch can turn Duo off
    q(superconn, "UPDATE ui.mfa_policy SET enabled=false WHERE account_kind='directory'")
    body = browser.text(browser.get("/integrations/duo"))
    assert not _has(_switch(body), "disabled") and '<input type="hidden" name="enabled"' not in body


def test_secret_key_behind_change_once_set(app, browser, superconn, logged_in, idir):
    """SPEC section 29.3: before a secret key exists the page shows its input; once one is stored
    it shows "Secret key: set" and the input only behind "Change secret key" (no JavaScript)."""
    from radius_admin import integrations as ig
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    assert re.search(r'<input id="skey" name="skey" type="password"', body)
    assert "Change secret key" not in body and "Secret key: set" not in _plain(body)
    assert browser.post("/integrations/duo/settings", SETTINGS_FORM, csrf_page="/integrations/duo").status_code == 302
    body = browser.text(browser.get("/integrations/duo"))
    assert "Secret key: set" in _plain(body)
    d = re.search(r'<details class="secret-change"([^>]*)>(.*?)</details>', body, re.S)
    assert d and "open" not in d.group(1)
    assert "<summary>Change secret key</summary>" in d.group(2) and 'name="skey"' in d.group(2)
    assert body.count('name="skey"') == 1

    def stored():
        blob = q(superconn, "SELECT secrets_enc FROM ui.mfa_provider WHERE id='duo'")[0][0]
        return ig.decrypt_secrets(app.config["RA_DATA_KEY"], "duo", blob)["skey"]
    # saved without opening it: the stored key stays
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="", factors="push"),
                 csrf_page="/integrations/duo")
    assert stored() == SKEY and "duo_skey_updated" not in audit(superconn, "integration.configure")[-1]
    # a new key replaces it
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="T" * 40), csrf_page="/integrations/duo")
    assert stored() == "T" * 40 and audit(superconn, "integration.configure")[-1]["duo_skey_updated"] is True
    # a wrong new key: the details open with the error
    r = browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, skey="short"), csrf_page="/integrations/duo")
    assert r.status_code == 400
    d = re.search(r'<details class="secret-change"([^>]*)>(.*?)</details>', browser.text(r), re.S)
    assert d and "open" in d.group(1) and "Secret key must be" in d.group(2)
    assert stored() == "T" * 40


def test_upload_is_one_button_with_javascript(browser, superconn, logged_in, idir):
    """With JavaScript, one "Upload a build…" button picks the file and uploads it (the build only
    goes to Ready to install); without it, the file field and the Upload button as before."""
    admin(browser, superconn, logged_in)
    body = browser.text(browser.get("/integrations/duo"))
    form = re.search(r'<form method="post" action="/integrations/duo/upload"[^>]*>(.*?)</form>', body, re.S).group(1)
    assert re.search(r'<button type="button" class="btn js-only" data-pick-file="build"[^>]*>Upload a build…</button>', form)
    assert 'class="nojs-only"' in form and '<button class="btn" type="submit">Upload</button>' in form
    static = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "radius_admin", "static")
    css, js = (open(os.path.join(static, n)).read() for n in ("app.css", "app.js"))
    assert ".js .nojs-only" in css and "data-pick-file" in js


def test_state_banner_keeps_its_distance(browser, superconn, logged_in, idir):
    static = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "radius_admin", "static")
    assert re.search(r"\.kv \+ \.flash[^{]*\{[^}]*margin-top", open(os.path.join(static, "app.css")).read())
