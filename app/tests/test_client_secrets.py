"""RADIUS client shared secrets sealed at rest (SPEC section 3.2): ui.radius_client.secret_enc with
the data key, `secret` '' once sealed; plain values (older releases, scripts) still work and are
sealed by `cli seal-client-secrets`; `cli unseal-client-secrets` writes them back for a downgrade.
Staged files are removed once the helper has read them."""
import os
import re

import pytest

from conftest import APP_DSN, client_secrets, only_secret, stepup
from radius_admin import services
from radius_admin.crypto import DataKey

SECRET = "TestOnlySharedSecret0123456789"
CLIENT = {"name": "sw1", "ipaddr": "192.0.2.1", "nas_type": "cisco", "require_ma": "auto",
          "limit_proxy_state": "auto", "enabled": "1"}


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def stored(superconn):
    return q(superconn, "SELECT secret, secret_enc IS NOT NULL FROM ui.radius_client ORDER BY id")


def plain_client(superconn, name="sw1", ip="192.0.2.1", secret=SECRET, transport="udp"):
    return q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, transport) VALUES (%s, %s, %s, %s)"
             " RETURNING id", (name, ip, secret, transport))[0][0]


def rendered_clients(app):
    with app.app_context():
        return services.render_all()[1]


def cli_config(app, tmp_path):
    p = tmp_path / "ra.conf"
    p.write_text("[app]\nrequire_fips = false\ndb_dsn = %s\nkey_file = %s\nlog_syslog = false\n"
                 "pbkdf2_iterations = 1000\n" % (APP_DSN, app.config["RA"]["key_file"]))
    return str(p)


# ------------------------------------------------------------------ the portal writes sealed
def test_portal_stores_sealed_secrets(app, browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    r = browser.post("/clients/new", dict(CLIENT, secret_mode="set", secret=SECRET))
    assert r.status_code == 302, browser.text(r)
    assert stored(superconn) == [("", True)]
    raw = bytes(q(superconn, "SELECT secret_enc FROM ui.radius_client")[0][0])
    assert SECRET.encode() not in raw
    assert only_secret(superconn) == SECRET
    assert 'secret = "%s"' % SECRET in rendered_clients(app)
    # keep: unchanged; set: replaced, still sealed
    blob = raw
    browser.post("/clients/1/edit", dict(CLIENT, secret_mode="keep", description="x"))
    assert bytes(q(superconn, "SELECT secret_enc FROM ui.radius_client")[0][0]) == blob
    browser.post("/clients/1/edit", dict(CLIENT, secret_mode="set", secret=SECRET + "X"))
    assert stored(superconn) == [("", True)] and only_secret(superconn) == SECRET + "X"
    # the admin can still reveal it
    r = browser.post("/clients/1/secret", {}, csrf_page="/clients/1/secret")
    assert SECRET + "X" in browser.text(r)


def test_import_stores_sealed_secrets(app, browser, superconn, logged_in):
    from test_client_import import do_import
    u = logged_in("operator")
    stepup(browser, superconn, u)
    do_import(browser, "ip,secret,hostname,secret_type\r\n192.0.2.5,%s,sw-5,plaintext\r\n" % SECRET)
    assert stored(superconn) == [("", True)] and client_secrets(superconn) == {"sw-5": SECRET}


# ------------------------------------------------------------------ plain values and the CLI
def test_plain_secrets_still_work_and_are_sealed_by_the_cli(app, browser, superconn, logged_in, tmp_path, capsys):
    from radius_admin import cli
    plain_client(superconn)
    plain_client(superconn, "ap1", "203.0.113.5", "", "radsec")      # RadSec: no shared secret
    before = rendered_clients(app)
    assert 'secret = "%s"' % SECRET in before
    cfgp = cli_config(app, tmp_path)
    assert cli.main(["--config", cfgp, "seal-client-secrets"]) == 0
    assert "1 client shared secret(s) sealed" in capsys.readouterr().out
    assert stored(superconn) == [("", True), ("", False)]
    assert rendered_clients(app) == before                     # FreeRADIUS sees the same file
    assert q(superconn, "SELECT detail->>'clients' FROM ui.audit_log WHERE action='client.secrets_seal'") == [("1",)]
    assert cli.main(["--config", cfgp, "seal-client-secrets"]) == 0     # idempotent
    assert "0 client shared secret(s) sealed" in capsys.readouterr().out
    # a downgrade: written back in plain, secret_enc cleared, same file
    assert cli.main(["--config", cfgp, "unseal-client-secrets"]) == 0
    assert stored(superconn) == [(SECRET, False), ("", False)]
    assert rendered_clients(app) == before
    # a plain value written later (by an older release) wins over a stale sealed one
    assert cli.main(["--config", cfgp, "seal-client-secrets"]) == 0
    q(superconn, "UPDATE ui.radius_client SET secret = %s WHERE name = 'sw1'", (SECRET + "N",))
    assert client_secrets(superconn)["sw1"] == SECRET + "N"
    assert cli.main(["--config", cfgp, "seal-client-secrets"]) == 0
    assert stored(superconn)[0] == ("", True) and client_secrets(superconn)["sw1"] == SECRET + "N"


def test_unreadable_secrets(app, browser, superconn, logged_in, tmp_path, capsys):
    """A sealed secret from another data key: no render, no reveal, no silent loss."""
    from radius_admin import cli
    cid = plain_client(superconn)
    other = DataKey(os.urandom(32))
    q(superconn, "UPDATE ui.radius_client SET secret = '', secret_enc = %s WHERE id = %s",
      (services.seal_client_secret(SECRET, other)[1], cid))
    with app.app_context():
        with pytest.raises(Exception, match="cannot be read"):
            services.render_all()
    cfgp = cli_config(app, tmp_path)
    assert cli.main(["--config", cfgp, "unseal-client-secrets"]) == 1
    assert "cannot be read" in capsys.readouterr().err
    assert stored(superconn) == [("", True)]                    # nothing changed
    u = logged_in("admin")
    stepup(browser, superconn, u)
    r = browser.post("/clients/%d/secret" % cid, {}, csrf_page="/clients/")
    assert r.status_code == 302 and SECRET not in browser.text(browser.get("/clients/"))
    r = browser.post("/clients/%d/edit" % cid, dict(CLIENT, secret_mode="keep"))
    assert r.status_code == 400 and "cannot be read" in browser.text(r)
    r = browser.post("/clients/%d/edit" % cid, dict(CLIENT, secret_mode="set", secret=SECRET))
    assert r.status_code == 302 and only_secret(superconn) == SECRET
    # a disabled client with an unreadable secret does not block the others
    q(superconn, "UPDATE ui.radius_client SET secret = '', secret_enc = %s, enabled = false WHERE id = %s",
      (services.seal_client_secret(SECRET, other)[1], cid))
    plain_client(superconn, "sw2", "192.0.2.2")
    assert 'secret = "%s"' % SECRET in rendered_clients(app)


def test_coa_opens_sealed_secrets(app, superconn, monkeypatch):
    from radius_admin import coa, db, snmp_poller
    cid = plain_client(superconn)
    key = app.config["RA_DATA_KEY"]
    q(superconn, "UPDATE ui.radius_client SET secret = '', secret_enc = %s WHERE id = %s",
      (services.seal_client_secret(SECRET, key)[1], cid))
    q(superconn, "INSERT INTO ui.coa_request (client_id, action, calling_station_id, nas_ip, requested_by)"
                 " VALUES (%s, 'reauth', 'AA-BB-CC-00-00-01', '192.0.2.1', 'op')", (cid,))
    sent = []
    monkeypatch.setattr(snmp_poller, "coa_tool", lambda cfg: ("/x/radclient", "/x/dict", None))
    monkeypatch.setattr(coa, "send", lambda action, host, port, secret, *a, **kw: (sent.append(secret), (True, "ok"))[1])
    conn = db.connect(APP_DSN)
    try:
        snmp_poller.run_coa(conn, {}, None, key)
        conn.commit()
    finally:
        conn.close()
    assert sent == [SECRET]


# ------------------------------------------------------------------ staging
def test_staged_files_are_removed_after_the_helper_read_them(app, browser, superconn, logged_in):
    plain_client(superconn)
    u = logged_in("admin")
    stepup(browser, superconn, u)
    staging = app.config["RA"]["staging_dir"]
    for action in ("validate", "apply"):
        page = browser.text(browser.get("/apply/"))
        m = re.search(r'name="expected" value="([^"]+)"', page)
        r = browser.post("/apply/" + action, {"expected": m.group(1)} if action == "apply" else {},
                         csrf_page="/apply/")
        assert r.status_code == 200
        assert SECRET in app.fake_helper.staged["clients"][0]
        assert not [n for n in os.listdir(staging) if os.path.isfile(os.path.join(staging, n))], action


def test_clear_staging_leaves_a_newer_staged_file(app, tmp_path):
    base = str(tmp_path / "st")
    with app.app_context():
        services.write_staging("p1\n", "c1\n", base=base, providers={"provider-duo": "d1\n"})
        # another apply staged its own clients file in the meantime
        with open(os.path.join(base, "clients"), "w") as fh:
            fh.write("c2\n")
        services.clear_staging("p1\n", "c1\n", {"provider-duo": "d1\n"}, base=base)
    assert sorted(os.listdir(base)) == ["clients"]
