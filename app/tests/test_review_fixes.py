"""Regression tests for security review findings L-3, L-5, L-6, I-1, L-4."""
import re
import threading

import psycopg2
import pytest

from conftest import APP_DSN, Browser, fresh_code, login


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


# ------------------------------------------------------------------ L-3
def test_last_admin_race_serialized(app, superconn, make_user):
    """Two admins disabling each other concurrently must leave one enabled admin."""
    a = make_user(username="adm-a", role="admin")
    b = make_user(username="adm-b", role="admin")
    ba, bb = Browser(app, ip="192.0.2.11"), Browser(app, ip="192.0.2.12")
    login(ba, superconn, a)
    login(bb, superconn, b)
    ta, tb = ba.csrf_from("/ui-admins/"), bb.csrf_from("/ui-admins/")
    barrier = threading.Barrier(2)
    results = {}

    def run(br, tok, target, key):
        barrier.wait()
        try:
            results[key] = br.post("/ui-admins/%d/enable" % target, {"enabled": "0"}, csrf=tok).status_code
        except Exception as e:  # e.g. a deadlock surfacing as a server error: a failure, not a skip
            results[key] = repr(e)

    t1 = threading.Thread(target=run, args=(ba, ta, b.id, "a"))
    t2 = threading.Thread(target=run, args=(bb, tb, a.id, "b"))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert results == {"a": 302, "b": 302}, results     # both requests complete; one is refused
    n = q(superconn, "SELECT count(*) FROM ui.admin_user WHERE role='admin' AND enabled")[0][0]
    assert n == 1


def test_last_admin_lock_blocks_concurrent_transaction(app, superconn, make_user):
    """While another transaction holds the admin-change lock, a demotion waits for it."""
    a = make_user(username="adm-a", role="admin")
    b = make_user(username="adm-b", role="admin")
    br = Browser(app)
    login(br, superconn, a)
    tok = br.csrf_from("/ui-admins/")
    holder = psycopg2.connect(APP_DSN)
    done = threading.Event()
    try:
        with holder.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(7212002)")
            # The concurrent "other admin" demotes a while holding the lock.
            cur.execute("UPDATE ui.admin_user SET role='viewer' WHERE id=%s", (a.id,))

        def demote_b():
            br.post("/ui-admins/%d/role" % b.id, {"role": "viewer"}, csrf=tok)
            done.set()
        t = threading.Thread(target=demote_b)
        t.start()
        assert not done.wait(1.0), "request did not wait for the admin-change lock"
        holder.commit()
        t.join(10)
    finally:
        holder.close()
    # b must still be admin: after the lock released, a was no longer an enabled admin.
    assert q(superconn, "SELECT role FROM ui.admin_user WHERE id=%s", (b.id,)) == [("admin",)]


# ------------------------------------------------------------------ L-5
def test_csv_huge_field_is_form_error(browser, superconn, logged_in):
    logged_in("operator")
    big = "00-11-22-33-44-55,40," + '"' + "x" * (140 * 1024) + '"\n'
    r = browser.post("/mab/import", {"text": big, "mode": "add"})
    assert r.status_code == 400
    assert "not valid CSV" in browser.text(r)
    assert q(superconn, "SELECT count(*) FROM mab_device")[0][0] == 0


def test_csv_too_large_and_too_many_lines(browser, superconn, logged_in):
    from radius_admin.views import mab
    logged_in("operator")
    r = browser.post("/mab/import", {"text": "a" * (mab.MAX_IMPORT_BYTES + 10), "mode": "add"})
    assert r.status_code == 400 and "larger than 1 MiB" in browser.text(r)
    many = "#\n" * (mab.MAX_IMPORT_LINES + 5)
    r = browser.post("/mab/import", {"text": many, "mode": "add"})
    assert r.status_code == 400 and "Too many lines" in browser.text(r)


def test_csv_unterminated_quote(browser, superconn, logged_in):
    logged_in("operator")
    r = browser.post("/mab/import", {"text": '00-11-22-33-44-55,40,"unterminated\n', "mode": "add"})
    assert r.status_code in (302, 400)  # csv module may accept EOF-in-quote; must never be 500


# ------------------------------------------------------------------ L-6
CLIENT = {"name": "sw1", "ipaddr": "192.0.2.1", "nas_type": "cisco", "require_ma": "auto",
          "limit_proxy_state": "auto", "enabled": "1"}


def _expire(superconn):
    q(superconn, "UPDATE ui.session SET stepup_at = now() - interval '10 minutes'")


@pytest.mark.parametrize("role", ["operator", "admin"])
def test_secret_change_requires_stepup(browser, superconn, logged_in, role):
    u = logged_in(role)
    _expire(superconn)
    # Create with generated secret: refused without step-up, nothing stored, no secret shown.
    r = browser.post("/clients/new", dict(CLIENT, secret_mode="generate"))
    assert r.status_code == 401 and "stepup_password" in browser.text(r)
    assert q(superconn, "SELECT count(*) FROM ui.radius_client")[0][0] == 0
    # Wrong step-up
    r = browser.post("/clients/new", dict(CLIENT, secret_mode="generate", stepup_password="wrong-wrong-wrong",
                                          stepup_code="000000"))
    assert r.status_code == 401 and "Verification failed" in browser.text(r)
    # Correct inline step-up: created and secret shown once
    r = browser.post("/clients/new", dict(CLIENT, secret_mode="generate", stepup_password=u.password,
                                          stepup_code=fresh_code(superconn, u)))
    assert r.status_code == 200
    secret = q(superconn, "SELECT secret FROM ui.radius_client")[0][0]
    assert secret in browser.text(r)
    # Edit with an explicit secret after step-up lapses: refused, secret unchanged.
    _expire(superconn)
    r = browser.post("/clients/1/edit", dict(CLIENT, secret_mode="set", secret="Operator-Chosen-Secret-01"))
    assert r.status_code == 401
    assert q(superconn, "SELECT secret FROM ui.radius_client")[0][0] == secret
    assert "Operator-Chosen-Secret-01" not in browser.text(r)  # not echoed back
    # Regenerate on edit: refused without step-up
    r = browser.post("/clients/1/edit", dict(CLIENT, secret_mode="generate"))
    assert r.status_code == 401
    assert q(superconn, "SELECT secret FROM ui.radius_client")[0][0] == secret
    # Non-secret edits do not need step-up
    r = browser.post("/clients/1/edit", dict(CLIENT, secret_mode="keep", description="no step-up needed"))
    assert r.status_code == 302
    assert q(superconn, "SELECT description, secret FROM ui.radius_client")[0] == ("no step-up needed", secret)
    # Explicit secret with inline step-up works
    r = browser.post("/clients/1/edit", dict(CLIENT, secret_mode="set", secret="Operator-Chosen-Secret-01",
                                             stepup_password=u.password, stepup_code=fresh_code(superconn, u)))
    assert r.status_code == 302
    assert q(superconn, "SELECT secret FROM ui.radius_client")[0][0] == "Operator-Chosen-Secret-01"


def test_secret_change_ok_within_stepup_window(browser, superconn, logged_in):
    logged_in("operator")  # fresh sign-in counts as step-up
    r = browser.post("/clients/new", dict(CLIENT, secret_mode="generate"))
    assert r.status_code == 200
    assert "stepup_password" not in browser.text(browser.get("/clients/new"))


# ------------------------------------------------------------------ I-1
@pytest.mark.parametrize("target", [
    "/%2f/evil.com", "/%2F%2Fevil.com", "//evil.com", "/\\evil.com", "/%5cevil.com", "/%5C/evil",
    "/%252f/evil.com", "https://evil.com", "http:/evil.com", "javascript:alert(1)", "evil.com", "",
    "/a%0d%0aSet-Cookie:x=1", "/a\r\nb", "///evil.com", "/\tevil",
])
def test_safe_next_rejects(target):
    from radius_admin.security import safe_next
    assert safe_next(target) is None


@pytest.mark.parametrize("target", ["/", "/dashboard", "/clients/1/secret", "/apply/?x=1", "/auth-log?page=2&reply=Access-Reject"])
def test_safe_next_accepts(target):
    from radius_admin.security import safe_next
    assert safe_next(target) == target


def test_stepup_next_open_redirect(browser, superconn, logged_in):
    u = logged_in("viewer")
    r = browser.post("/stepup", {"password": u.password, "code": fresh_code(superconn, u), "next": "/%2f/evil.com"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")


# ------------------------------------------------------------------ L-4
def test_app_cannot_modify_apply_log_and_never_tries(app):
    import pathlib
    root = pathlib.Path(app.root_path)
    for p in root.rglob("*.py"):
        src = p.read_text()
        assert not re.search(r"(UPDATE|DELETE FROM)\s+ui\.apply_log", src, re.I), p
    c = psycopg2.connect(APP_DSN)
    try:
        with c.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute("UPDATE ui.apply_log SET message='x'")
    finally:
        c.close()
