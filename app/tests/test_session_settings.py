"""Console session limits editable in Settings: step-up window, idle timeout, session length."""


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def age_stepup(superconn, minutes):
    q(superconn, "UPDATE ui.session SET stepup_at = now() - make_interval(mins => %s)", (minutes,))


BASE = {"admin_subnet": "192.0.2.0/24", "banner_text": "This system is for authorized use only. Testing."}


def test_longer_stepup_window(browser, superconn, logged_in):
    logged_in("admin")
    t = browser.text(browser.get("/settings"))
    assert 'name="stepup_minutes" value="5"' in t and 'name="session_idle_minutes" value="15"' in t
    r = browser.post("/settings", dict(BASE, stepup_minutes="30", session_idle_minutes="60",
                                       session_absolute_hours="12"))
    assert r.status_code == 302
    assert dict(q(superconn, "SELECT key, value FROM ui.setting WHERE key IN"
                             " ('stepup_minutes','session_idle_minutes','session_absolute_hours')")) == {
        "stepup_minutes": "30", "session_idle_minutes": "60", "session_absolute_hours": "12"}
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='settings.update' ORDER BY id DESC LIMIT 1")[0][0]
    assert d["stepup_minutes"] == {"from": 5, "to": 30}
    age_stepup(superconn, 20)                                   # within 30 min: no re-confirmation
    assert browser.get("/settings").status_code == 200
    age_stepup(superconn, 31)
    r = browser.get("/settings")
    assert r.status_code == 302 and "/stepup" in r.headers["Location"]


def test_out_of_range_values_refused(browser, superconn, logged_in):
    logged_in("admin")
    for k, bad in (("stepup_minutes", "0"), ("stepup_minutes", "61"), ("session_idle_minutes", "4"),
                   ("session_absolute_hours", "25"), ("session_idle_minutes", "ten")):
        r = browser.post("/settings", dict(BASE, **{k: bad}))
        assert r.status_code == 400 and "Enter a whole number of" in browser.text(r), (k, bad)
    assert not q(superconn, "SELECT 1 FROM ui.setting WHERE key IN"
                            " ('stepup_minutes','session_idle_minutes','session_absolute_hours')")


def test_omitted_fields_keep_values(browser, superconn, logged_in):
    logged_in("admin")
    browser.post("/settings", dict(BASE, stepup_minutes="20"))
    browser.post("/settings", BASE)
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='stepup_minutes'") == [("20",)]


def test_idle_timeout_from_settings(browser, superconn, logged_in):
    logged_in("operator")
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('session_idle_minutes','5')")
    q(superconn, "UPDATE ui.session SET last_seen_at = now() - interval '6 minutes'")
    r = browser.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_stored_value_is_clamped(browser, superconn, logged_in):
    """A value outside the limits (edited in the database) can never widen the window."""
    logged_in("admin")
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('stepup_minutes','9999')")
    age_stepup(superconn, 61)
    assert browser.get("/settings").status_code == 302          # clamped to 60 minutes
