"""Updates (SPEC section 16): versions, the update check service, the Updates page."""
import hashlib
import json
import os

import pytest

from conftest import APP_DSN


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def set_update(superconn, **kv):
    for k, v in kv.items():
        q(superconn, "INSERT INTO ui.setting (key, value) VALUES (%s, %s)"
                     " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", ("update_" + k, str(v)))


# ======================================================================= versions
def test_version_order_and_channels():
    from radius_admin import versions as v
    order = ["0.1.0", "0.2.0-dev.3", "0.2.0-dev.14", "0.2.0-rc.1", "0.2.0-rc.2", "0.2.0", "0.2.1-dev.0", "1.0.0"]
    assert sorted(order, key=v.parse) == order
    assert v.newer("0.2.0-dev.14", "0.2.0-dev.9") and not v.newer("0.2.0-dev.9", "0.2.0")
    assert v.newer("0.1.0", "") and not v.newer("junk", "0.1.0")
    assert [v.channel_of(x) for x in ("0.2.0", "0.2.0-rc.1", "0.2.0-dev.1", "0.2")] == ["main", "testing", "dev", None]
    for bad in ("0.2", "v0.2.0", "0.2.0-beta.1", "0.2.0-dev", "0.2.0\n"):
        assert v.parse(bad) is None, bad


def test_installed_build(tmp_path):
    from radius_admin import versions as v
    p = tmp_path / "BUILD.json"
    assert v.installed(str(p))["version"] == ""
    p.write_text(json.dumps({"version": "0.2.0-dev.3", "channel": "dev", "commit": "abc"}))
    assert v.installed(str(p)) == {"version": "0.2.0-dev.3", "channel": "dev", "commit": "abc", "built": ""}
    p.write_text("[1, 2]")
    assert v.installed(str(p))["version"] == ""


def test_plan_picks_channel_builds():
    from radius_admin.updater import plan
    rels = [{"version": x, "channel": c} for x, c in
            (("0.1.0", "main"), ("0.2.0-dev.3", "dev"), ("0.2.0-dev.5", "dev"), ("0.2.0-rc.1", "testing"))]
    t, listed, down = plan(rels, "dev", {"version": "0.1.0", "channel": "main"})
    assert t["version"] == "0.2.0-dev.5" and [r["version"] for r in listed] == ["0.2.0-dev.5", "0.2.0-dev.3"]
    assert down is False
    assert plan(rels, "dev", {"version": "0.2.0-dev.5", "channel": "dev"}) == (None, [], False)
    t, listed, down = plan(rels, "main", {"version": "0.2.0-dev.5", "channel": "dev"})
    assert t["version"] == "0.1.0" and down is True          # switching channel to an older build
    assert plan(rels, "main", {"version": "0.1.0", "channel": "main"}) == (None, [], False)
    assert plan([], "main", {"version": "0.1.0"}) == (None, [], False)


def test_window():
    import datetime
    from radius_admin.updater import in_window
    sun3 = datetime.datetime(2026, 11, 1, 3, 20)               # a Sunday
    assert in_window(sun3, "sun", "3") and not in_window(sun3, "sun", "4")
    assert not in_window(sun3, "mon", "3") and in_window(sun3, "daily", "3")
    assert not in_window(sun3, "sun", "x")


def test_notes_html_escapes():
    from radius_admin.views.updates import notes_html
    h = str(notes_html("### Added\n- a `code` item\n  continued\n- <script>x</script>\n\nSome **bold** text."))
    assert "<h4>Added</h4>" in h and "<code>code</code>" in h and "item continued" in h
    assert "<script>" not in h and "&lt;script&gt;" in h and "<strong>bold</strong>" in h


# ======================================================================= update check service
BUNDLES = {}


class FakeGitHub:
    """Serves a release list and its assets in place of updater.http_get."""

    def __init__(self, versions_=("0.1.0", "0.2.0-dev.3", "0.2.0-dev.5"), restarts=(), broken=None):
        self.calls = []
        self.files = {}
        self.fail = None
        rels = []
        for v in versions_:
            bundle = ("bundle of %s" % v).encode() * 50
            name = "radius-admin-%s.tar.gz" % v
            man = {"format": 1, "product": "radius-admin", "version": v, "channel": "x",
                   "restarts_freeradius": v in restarts,
                   "bundle": {"name": name, "size": len(bundle), "sha384": hashlib.sha384(bundle).hexdigest()}}
            if broken == v:
                bundle = b"Z" + bundle[1:]
            base = "https://github.example.net/%s/" % v
            self.files.update({base + "manifest.json": json.dumps(man).encode(), base + "manifest.json.sig": b"sig",
                               base + name: bundle})
            rels.append({"tag_name": "v" + v, "draft": False, "published_at": "2026-11-0%dT00:00:00Z" % (len(rels) + 1),
                         "body": "- notes for %s" % v,
                         "assets": [{"name": n, "browser_download_url": base + n, "size": 1}
                                    for n in ("manifest.json", "manifest.json.sig", name)]})
        rels.append({"tag_name": "v9.9.9", "draft": True, "assets": []})        # drafts are ignored
        rels.append({"tag_name": "nightly", "assets": []})                       # not a version
        self.files["https://api.example.net/repos/radiusadmin/radius-admin/releases?per_page=100"] = json.dumps(rels).encode()

    def __call__(self, url, limit, accept="application/json", dest=None, digest=None):
        from radius_admin.updater import UpdateError
        self.calls.append(url)
        if self.fail:
            raise UpdateError(self.fail)
        body = self.files[url]
        if len(body) > limit:
            raise UpdateError("download larger than expected")
        if dest is None:
            return body
        if digest is not None:
            digest.update(body)
        with open(dest, "wb") as fh:
            fh.write(body)
        return len(body)


@pytest.fixture
def upd(app, tmp_path, monkeypatch, superconn):
    from radius_admin import db, updater
    gh = FakeGitHub()
    monkeypatch.setattr(updater, "http_get", gh)
    build = tmp_path / "BUILD.json"
    build.write_text(json.dumps({"version": "0.1.0", "channel": "main", "commit": "c" * 40}))
    d = tmp_path / "updates"
    d.mkdir()
    cfg = dict(app.config["RA"], update_api="https://api.example.net", update_repo="radiusadmin/radius-admin",
               update_dir=str(d), build_file=str(build))
    app.config["RA"]["build_file"] = str(build)
    conn = db.connect(APP_DSN)

    class U:
        pass
    u = U()
    u.gh, u.cfg, u.dir, u.build, u.conn = gh, cfg, d, build, conn
    u.run = lambda **kw: updater.check(cfg, conn, **kw)
    yield u
    conn.close()


def test_off_never_contacts_github(upd, superconn):
    set_update(superconn, mode="off", channel="dev")
    assert "off" in upd.run()
    assert upd.gh.calls == [] and q(superconn, "SELECT 1 FROM ui.update_check") == []


def test_check_lists_and_downloads_newest_on_channel(upd, superconn):
    set_update(superconn, mode="notify", channel="dev")
    assert "0.2.0-dev.5 available" in upd.run()
    row = q(superconn, "SELECT ok, latest_version, downgrade, downloaded, installed_version, releases"
                       " FROM ui.update_check")[0]
    assert row[:5] == (True, "0.2.0-dev.5", False, True, "0.1.0")
    assert [r["version"] for r in row[5]] == ["0.2.0-dev.5", "0.2.0-dev.3"]
    assert row[5][1]["notes"] == "- notes for 0.2.0-dev.3"
    assert sorted(os.listdir(upd.dir)) == ["0.2.0-dev.5"]
    assert sorted(os.listdir(upd.dir / "0.2.0-dev.5")) == ["manifest.json", "manifest.json.sig",
                                                          "radius-admin-0.2.0-dev.5.tar.gz"]


def test_notify_checks_once_a_day_unless_asked(upd, superconn):
    import datetime
    set_update(superconn, mode="notify", channel="dev")
    upd.run()
    n = len(upd.gh.calls)
    assert "less than a day" in upd.run() and len(upd.gh.calls) == n
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('update_check_requested', %s)", (later.isoformat(),))
    assert "available" in upd.run(utcnow=later + datetime.timedelta(seconds=1))
    assert len(upd.gh.calls) > n
    # a finished download is reused, not fetched again
    assert not any(c.endswith(".tar.gz") for c in upd.gh.calls[n:])


def test_switching_to_an_older_channel_offers_a_downgrade(upd, superconn):
    upd.build.write_text(json.dumps({"version": "0.2.0-dev.5", "channel": "dev"}))
    set_update(superconn, mode="notify", channel="main")
    upd.run()
    assert q(superconn, "SELECT latest_version, downgrade, restarts_freeradius FROM ui.update_check")[0] == (
        "0.1.0", True, True)


def test_download_not_matching_its_manifest_is_dropped(upd, superconn, monkeypatch):
    from radius_admin import updater
    monkeypatch.setattr(updater, "http_get", FakeGitHub(broken="0.2.0-dev.5"))
    set_update(superconn, mode="notify", channel="dev")
    assert "check failed" in upd.run()
    row = q(superconn, "SELECT ok, error, downloaded FROM ui.update_check")[0]
    assert row[0] is False and "does not match" in row[1] and row[2] is False
    assert os.listdir(upd.dir) == []


def test_github_errors_are_recorded(upd, superconn):
    upd.gh.fail = "cannot reach GitHub (timed out)"
    set_update(superconn, mode="notify", channel="main")
    upd.run()
    assert q(superconn, "SELECT ok, error FROM ui.update_check")[0] == (False, "cannot reach GitHub (timed out)")


def test_auto_installs_console_only_updates(upd, superconn, app):
    set_update(superconn, mode="auto", channel="dev")
    assert "install started" in upd.run()
    req = [r for r in app.fake_helper.requests if r["action"] == "update_install"]
    assert req == [{"action": "update_install", "version": "0.2.0-dev.5", "actor": "auto"}]
    assert q(superconn, "SELECT actor, success FROM ui.audit_log WHERE action = 'update.auto_install'") == [
        ("automatic update", True)]


def test_auto_waits_for_the_window_when_freeradius_restarts(upd, superconn, app, monkeypatch):
    import datetime
    from radius_admin import updater
    monkeypatch.setattr(updater, "http_get", FakeGitHub(restarts=("0.2.0-dev.3",)))
    set_update(superconn, mode="auto", channel="dev", window_day="sun", window_hour="3")
    tue = datetime.datetime(2026, 11, 3, 14, 0)
    assert "waiting for the maintenance window" in upd.run(now=tue)
    assert not [r for r in app.fake_helper.requests if r["action"] == "update_install"]
    sun = datetime.datetime(2026, 11, 8, 3, 10)
    assert "install started" in upd.run(now=sun)


def test_auto_never_retries_a_failed_install(upd, superconn, app):
    app.fake_helper.update_state = {"state": "rolled_back", "version": "0.2.0-dev.5"}
    set_update(superconn, mode="auto", channel="dev")
    assert "last attempt for this version is rolled_back" in upd.run()
    assert not [r for r in app.fake_helper.requests if r["action"] == "update_install"]


# ======================================================================= Updates page
def offer(superconn, version="0.2.0-dev.5", installed="0.1.0", channel="dev", downgrade=False, restarts=False):
    q(superconn, "INSERT INTO ui.update_check (id, ok, channel, installed_version, latest_version, downgrade,"
                 " restarts_freeradius, downloaded, releases) VALUES (1, true, %s, %s, %s, %s, %s, true, %s)"
                 " ON CONFLICT (id) DO UPDATE SET latest_version = EXCLUDED.latest_version",
      (channel, installed, version, downgrade, restarts,
       json.dumps([{"version": version, "published": "2026-11-02T00:00:00Z", "notes": "### Added\n- <b>new</b> thing",
                    "restarts_freeradius": restarts}])))


@pytest.fixture
def page(app, tmp_path, superconn):
    build = tmp_path / "BUILD.json"
    build.write_text(json.dumps({"version": "0.1.0", "channel": "main", "commit": "abcdef1234"}))
    app.config["RA"]["build_file"] = str(build)
    set_update(superconn, channel="dev", mode="notify")
    return build


def test_only_admins_see_updates(browser, logged_in, page):
    logged_in("operator")
    assert browser.get("/updates").status_code in (302, 403)


def test_page_shows_current_latest_and_notes(browser, superconn, logged_in, page):
    logged_in("admin")
    t = browser.text(browser.get("/updates"))
    assert "Not checked yet" in t and "Updates are not set up" not in t
    offer(superconn)
    t = browser.text(browser.get("/updates"))
    assert "0.1.0" in t and "0.2.0-dev.5" in t and "Install 0.2.0-dev.5" in t
    assert "&lt;b&gt;new&lt;/b&gt; thing" in t and "<b>new</b>" not in t
    assert 'title="Update available: 0.2.0-dev.5"' in t                   # nav badge
    assert "FIPS" not in t


def test_page_warns_when_the_key_is_missing(browser, logged_in, page, app, superconn):
    app.fake_helper.key_present = False
    offer(superconn)
    logged_in("admin")
    t = browser.text(browser.get("/updates"))
    assert "Updates are not set up on this server" in t and "Install 0.2.0-dev.5" not in t


def test_settings_validated_saved_audited(browser, superconn, logged_in, page, app):
    logged_in("admin")
    r = browser.post("/updates/settings", {"channel": "nightly", "mode": "auto", "window_day": "sun",
                                           "window_hour": "3"}, csrf_page="/updates")
    assert r.status_code == 302
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='update_channel'") == [("dev",)]
    for bad in ({"window_hour": "24"}, {"window_day": "someday"}, {"mode": "always"}):
        browser.post("/updates/settings", dict({"channel": "main", "mode": "auto", "window_day": "sun",
                                                "window_hour": "3"}, **bad), csrf_page="/updates")
        assert q(superconn, "SELECT value FROM ui.setting WHERE key='update_mode'") == [("notify",)], bad
    browser.post("/updates/settings", {"channel": "testing", "mode": "auto", "window_day": "daily",
                                       "window_hour": "22"}, csrf_page="/updates")
    got = dict(q(superconn, "SELECT key, value FROM ui.setting WHERE key LIKE %s", ("update_%",)))
    assert {k: got[k] for k in ("update_channel", "update_mode", "update_window_day", "update_window_hour")} == {
        "update_channel": "testing", "update_mode": "auto", "update_window_day": "daily", "update_window_hour": "22"}
    assert "update_check_requested" in got                                    # channel changed: check again
    assert [r["action"] for r in app.fake_helper.requests].count("update_check") == 1
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='update.settings' ORDER BY id DESC LIMIT 1")[0][0]
    assert d["channel"] == {"from": "dev", "to": "testing"}


def test_check_now(browser, superconn, logged_in, page, app):
    logged_in("admin")
    browser.post("/updates/check", {}, csrf_page="/updates")
    assert any(r["action"] == "update_check" for r in app.fake_helper.requests)
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE action='update.check'") == [(1,)]
    set_update(superconn, mode="off")
    app.fake_helper.requests.clear()
    browser.post("/updates/check", {}, csrf_page="/updates")
    assert not [r for r in app.fake_helper.requests if r["action"] == "update_check"]


def test_install_asks_the_helper_for_the_offered_build_only(browser, superconn, logged_in, page, app):
    u = logged_in("admin")
    offer(superconn)
    browser.post("/updates/install", {"version": "0.3.0"}, csrf_page="/updates")
    assert not [r for r in app.fake_helper.requests if r["action"] == "update_install"]
    browser.post("/updates/install", {"version": "0.2.0-dev.5"}, csrf_page="/updates")
    req = [r for r in app.fake_helper.requests if r["action"] == "update_install"]
    assert req == [{"action": "update_install", "version": "0.2.0-dev.5", "allow_downgrade": False,
                    "actor": u.username}]
    row = q(superconn, "SELECT success, detail FROM ui.audit_log WHERE action='update.install_requested'")[0]
    assert row[0] is True and row[1]["to"] == "0.2.0-dev.5" and row[1]["from"] == "0.1.0"
    t = browser.text(browser.get("/updates"))
    assert "Installing 0.2.0-dev.5" in t and 'http-equiv="refresh"' in t


def test_downgrade_needs_confirmation(browser, superconn, logged_in, page, app):
    logged_in("admin")
    offer(superconn, version="0.0.9", downgrade=True)
    t = browser.text(browser.get("/updates"))
    assert "older than the installed" in t and 'name="confirm_downgrade"' in t
    browser.post("/updates/install", {"version": "0.0.9"}, csrf_page="/updates")
    assert not [r for r in app.fake_helper.requests if r["action"] == "update_install"]
    browser.post("/updates/install", {"version": "0.0.9", "confirm_downgrade": "1"}, csrf_page="/updates")
    req = [r for r in app.fake_helper.requests if r["action"] == "update_install"]
    assert req and req[0]["allow_downgrade"] is True


def test_last_result_is_shown(browser, logged_in, page, app):
    app.fake_helper.update_state = {"state": "rolled_back", "version": "0.2.0-dev.5", "finished": "2026-11-02T10:00:00+00:00",
                                    "message": "the new release failed its health checks; rolled back"}
    logged_in("admin")
    t = browser.text(browser.get("/updates"))
    assert "rolled back" in t and "2026-11-02 10:00 UTC" in t
