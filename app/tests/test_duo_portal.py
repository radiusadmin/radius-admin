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
    with open(os.path.join(staging, "provider-duo")) as fh:
        staged = fh.read()
    secrets = ig.decrypt_secrets(app.config["RA_DATA_KEY"], "duo",
                                 q(superconn, "SELECT secrets_enc FROM ui.mfa_provider WHERE id='duo'")[0][0])
    assert staged == unlang.render_duo_config(dict(json.loads(q(superconn, "SELECT settings::text FROM ui.mfa_provider"
                                                                            " WHERE id='duo'")[0][0]), **secrets))
    with open(os.path.join(staging, "clients")) as fh:
        assert "home_server radius_admin_mfa_duo" in fh.read()
    row = q(superconn, "SELECT providers_sha256 FROM ui.apply_log WHERE action='apply' ORDER BY id DESC LIMIT 1")[0][0]
    assert row and len(row) == 64
    with open(os.path.join(staging, "applied", "provider-duo")) as fh:
        assert fh.read() == staged
    # nothing pending afterwards; turning Duo off removes its file from the next staging
    with app.test_request_context():
        from radius_admin import services
        assert services.pending_state()["pending"] is False
    q(superconn, "UPDATE ui.mfa_provider SET enabled=false WHERE id='duo'")
    page = browser.text(browser.get("/apply/"))
    m = re.search(r'name="expected" value="([^"]+)"', page)
    assert m.group(1).endswith(":")
    browser.post("/apply/apply", {"expected": m.group(1)}, csrf_page="/apply/")
    assert not os.path.exists(os.path.join(staging, "provider-duo"))


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


def test_remove_and_test(browser, superconn, logged_in, idir):
    h = helper_of(browser)
    h.duo["installed"] = {"version": "6.8.1", "verified": "catalog"}
    admin(browser, superconn, logged_in)
    browser.post("/integrations/duo/settings", dict(SETTINGS_FORM, enabled="1"), csrf_page="/integrations/duo")
    n = len(h.requests)
    browser.post("/integrations/duo/remove", csrf_page="/integrations/duo")
    assert not any(r_["action"] == "integration_remove" for r_ in h.requests[n:])      # still on
    q(superconn, "UPDATE ui.mfa_provider SET enabled=false WHERE id='duo'")
    browser.post("/integrations/duo/remove", csrf_page="/integrations/duo")
    assert h.requests[-1]["action"] == "integration_remove"
    r = browser.post("/integrations/duo/test", csrf_page="/integrations/duo")
    body = browser.text(r)
    assert "able to reach Duo" in body and audit(superconn, "integration.test")


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
