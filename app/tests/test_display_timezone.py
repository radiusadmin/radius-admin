"""Display time zone in Settings: console and log times shown in a chosen IANA zone (default UTC)."""


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


BASE = {"admin_subnet": "192.0.2.0/24", "banner_text": "This system is for authorized use only. Testing."}


def add_auth(superconn, user, at):
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, authdate)"
                 " VALUES (%s, 'Access-Accept', 'eap-tls', '192.0.2.5', %s)", (user, at))


def set_zone(superconn, zone):
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('display_timezone', %s)"
                 " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (zone,))


def test_default_is_utc(browser, superconn, logged_in):
    logged_in("admin")
    add_auth(superconn, "host-a.example.net", "2026-07-01 12:00:00+00")
    t = browser.text(browser.get("/settings"))
    assert '<option value="UTC" selected>UTC</option>' in t
    t = browser.text(browser.get("/auth-log"))
    assert "<span>2026-07-01</span> <span>12:00:00 UTC</span>" in t


def test_save_zone_and_logs_follow_it(browser, superconn, logged_in):
    logged_in("admin")
    add_auth(superconn, "host-a.example.net", "2026-07-01 12:00:00+00")
    r = browser.post("/settings", dict(BASE, display_timezone="Europe/Berlin"))
    assert r.status_code == 302
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='display_timezone'") == [("Europe/Berlin",)]
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='settings.update' ORDER BY id DESC LIMIT 1")[0][0]
    assert d["display_timezone"] == {"from": "UTC", "to": "Europe/Berlin"}
    assert '<option value="Europe/Berlin" selected>' in browser.text(browser.get("/settings"))
    t = browser.text(browser.get("/auth-log"))
    assert "<span>2026-07-01</span> <span>14:00:00 CEST</span>" in t and "12:00:00 UTC" not in t
    t = browser.text(browser.get("/audit-log"))                 # the settings.update record itself
    assert " UTC</span>" not in t and ("CET</span>" in t or "CEST</span>" in t)


def test_unknown_zone_refused(browser, superconn, logged_in):
    logged_in("admin")
    for bad in ("Mars/Olympus", "../../etc/passwd", "", "Europe/Berlin\n"):
        r = browser.post("/settings", dict(BASE, display_timezone=bad))
        assert r.status_code == 400 and "Choose a time zone from the list." in browser.text(r), bad
    assert not q(superconn, "SELECT 1 FROM ui.setting WHERE key='display_timezone'")


def test_omitted_field_keeps_zone(browser, superconn, logged_in):
    logged_in("admin")
    set_zone(superconn, "America/New_York")
    browser.post("/settings", BASE)
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='display_timezone'") == [("America/New_York",)]


def test_invalid_stored_zone_falls_back_to_utc(browser, superconn, logged_in):
    logged_in("operator")
    add_auth(superconn, "host-a.example.net", "2026-07-01 12:00:00+00")
    set_zone(superconn, "Not/A_Zone")
    r = browser.get("/auth-log")
    assert r.status_code == 200 and "12:00:00 UTC" in browser.text(r)


def test_date_filter_uses_display_zone(browser, superconn, logged_in):
    """From/To are whole days in the display zone: 23:30 UTC on 1 July is 2 July in Berlin."""
    logged_in("operator")
    add_auth(superconn, "late-host.example.net", "2026-07-01 23:30:00+00")
    day2 = "/auth-log?since=2026-07-02&until=2026-07-02"
    day1 = "/auth-log?since=2026-07-01&until=2026-07-01"
    assert "late-host.example.net" not in browser.text(browser.get(day2))
    assert "late-host.example.net" in browser.text(browser.get(day1))
    set_zone(superconn, "Europe/Berlin")
    assert "late-host.example.net" in browser.text(browser.get(day2))
    assert "late-host.example.net" not in browser.text(browser.get(day1))
