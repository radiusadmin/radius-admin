"""RadSec (RADIUS over TLS, RFC 6614): per-client transport, listener settings, rendering."""
import pytest

from radius_admin import unlang
from radius_admin.unlang import PolicyInputError

UDP = dict(name="sw1", ipaddr="192.0.2.11", secret="AbCdEfGhIjKlMnOpQrStUvWx12345678", enabled=True)
AP = dict(name="ap1", ipaddr="203.0.113.5", transport="radsec", radsec_peer_name="AP1.Example.net",
          nas_type="aruba", secret="", enabled=True)
ON = {"enabled": "true"}


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


# ------------------------------------------------------------------ rendering
def test_udp_only_output_unchanged():
    assert unlang.render_clients([UDP]) == unlang.render_clients([UDP], ON)
    assert "listen" not in unlang.render_clients([UDP], ON)


def test_radsec_clients_need_the_listener():
    off = unlang.render_clients([UDP, AP])
    assert "listen {" not in off and "ap1" not in off and "client sw1" in off
    on = unlang.render_clients([UDP, AP], ON)
    head, tls = on.split("\nclients radius_admin_radsec {\n")
    assert "client sw1 {" in head and "ap1" not in head
    assert "listen {" in head and "\tclients = radius_admin_radsec\n" in head
    assert "\t\tproto = tls\n" in tls and '\t\tsecret = "radsec"\n' in tls
    assert '\t\tradsec_peer_name = "ap1.example.net"\n' in tls        # compared lower-case
    assert "require_client_cert = yes" in head and 'tls_min_version = "1.2"' in head
    assert unlang.CERT_DIR + "/radius.key" in head and "ocsp" not in head
    # disabled RadSec clients only -> nothing rendered
    assert "listen" not in unlang.render_clients([UDP, dict(AP, enabled=False)], ON)


def test_listener_options():
    t = unlang.render_clients([AP, dict(AP, name="ap6", ipaddr="2001:db8::6", radsec_peer_name="")],
                              {"enabled": True, "listen": "198.51.100.1", "port": "12083", "ocsp": "true",
                               "ocsp_url": "http://pki.example.net:8080/ocsp", "idle_timeout": "60"})
    assert "\tipv4addr = 198.51.100.1\n\tport = 12083\n" in t and "idle_timeout = 60" in t
    assert "\t\tipv6addr = 2001:db8::6\n" in t and 'radsec_peer_name = ""' in t
    assert "override_cert_url = yes" in t and 'url = "http://pki.example.net:8080/ocsp"' in t
    t = unlang.render_clients([AP], {"enabled": True, "ocsp": True})
    assert "override_cert_url = no" in t and "\turl =" not in t


def test_same_address_udp_and_radsec_but_no_duplicates_within():
    unlang.render_clients([UDP, dict(AP, ipaddr=UDP["ipaddr"])], ON)
    with pytest.raises(PolicyInputError):
        unlang.render_clients([AP, dict(AP, name="ap2")], ON)


@pytest.mark.parametrize("bad", ['ap1"x', "${confdir}", "%{exec:/bin/id}", "a\\b", "x" * 254, "-ap", "ap\n1"])
def test_peer_name_validation(bad):
    with pytest.raises(PolicyInputError):
        unlang.validate_radsec_peer_name(bad)


@pytest.mark.parametrize("bad", [{"port": "0"}, {"port": "70000"}, {"listen": "anywhere"},
                                 {"listen": "192.0.2.0/24"}, {"idle_timeout": "1"}, {"max_connections": "0"},
                                 {"ocsp_url": "javascript:alert(1)"}, {"ocsp_url": 'http://x/"y'},
                                 {"ocsp_url": "http://x/${confdir}"}, {"enabled": "maybe"}])
def test_settings_validation(bad):
    with pytest.raises(PolicyInputError):
        unlang.validate_radsec_settings(dict(ON, **bad))


def test_policy_checks_the_connection_certificate():
    p = unlang.render_policy("")
    sec = p[p.index("radius_admin_radsec {"):p.index("radius_admin_postauth {")]
    assert '"%{client:proto}" == "tls"' in sec
    assert "%{listen:TLS-Client-Cert-Common-Name}" in sec and "%{listen:TLS-Client-Cert-Subject-Alt-Name-Dns}" in sec
    assert "reject" in sec and "%{sql:" not in sec        # no request data reaches SQL here


# ------------------------------------------------------------------ UI
FORM = {"name": "ap1", "ipaddr": "203.0.113.5", "transport": "radsec", "radsec_peer_name": "ap1.example.net",
        "nas_type": "aruba", "enabled": "1"}


def test_operator_adds_radsec_client_without_secret_or_stepup(app, browser, superconn, logged_in):
    logged_in("operator")
    r = browser.post("/clients/new", FORM)
    assert r.status_code == 302, browser.text(r)
    row = q(superconn, "SELECT transport, radsec_peer_name, secret, key_status FROM ui.radius_client")
    assert row == [("radsec", "ap1.example.net", "", "ok")]
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='client.create'")[0][0]
    assert d["transport"] == "radsec" and d["radsec_peer_name"] == "ap1.example.net"
    t = browser.text(browser.get("/clients/"))
    assert ">RadSec<" in t and "The RadSec listener is off." in t
    r = browser.get("/clients/%d/secret" % q(superconn, "SELECT id FROM ui.radius_client")[0][0])
    assert r.status_code == 403                               # operators never reveal secrets


def test_radsec_client_has_no_secret_to_reveal(browser, superconn, logged_in):
    from conftest import stepup
    u = logged_in("admin")
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, transport) VALUES ('ap1','203.0.113.5','','radsec')")
    cid = q(superconn, "SELECT id FROM ui.radius_client")[0][0]
    stepup(browser, superconn, u)
    r = browser.get("/clients/%d/secret" % cid)
    assert r.status_code == 302 and r.headers["Location"].endswith("/clients/")
    assert "has no shared secret" in browser.text(browser.get("/clients/"))
    assert not q(superconn, "SELECT 1 FROM ui.audit_log WHERE action='client.secret_reveal'")


def test_bad_peer_name_and_back_to_udp(browser, superconn, logged_in):
    logged_in("operator")
    r = browser.post("/clients/new", dict(FORM, radsec_peer_name='ap1" x'))
    assert r.status_code == 400 and "Certificate name must be" in browser.text(r)
    browser.post("/clients/new", FORM)
    cid = q(superconn, "SELECT id FROM ui.radius_client")[0][0]
    r = browser.post("/clients/%d/edit" % cid, dict(FORM, transport="udp", secret_mode="keep",
                                                    require_ma="auto", limit_proxy_state="auto"))
    assert r.status_code == 400 and "no shared secret yet" in browser.text(r)


def test_listener_settings(browser, superconn, logged_in):
    logged_in("admin")
    browser.post("/clients/new", FORM)
    r = browser.post("/clients/radsec", {"enabled": "1", "listen": "*", "port": "2083", "max_connections": "16",
                                         "idle_timeout": "30", "ocsp": "1", "ocsp_url": ""})
    assert r.status_code == 302
    assert dict(q(superconn, "SELECT key, value FROM ui.setting WHERE key LIKE %s", ("radsec_%",)))["radsec_enabled"] == "true"
    t = browser.text(browser.get("/clients/radsec"))
    assert "ap1.example.net" in t and "/certs/site/ca.pem" in t
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='radsec.settings'")[0][0]
    assert d["changed"]["enabled"] is True and d["changed"]["ocsp"] is True
    # the clients file now carries the listener; it is a pending change until Apply
    assert "Pending changes." in browser.text(browser.get("/clients/"))
    r = browser.post("/clients/radsec", {"listen": "*", "port": "2083", "max_connections": "16",
                                         "idle_timeout": "30"})
    assert r.status_code == 400 and "cannot be turned off while enabled clients use RadSec" in browser.text(r)
    r = browser.post("/clients/radsec", {"enabled": "1", "port": "0"})
    assert r.status_code == 400 and "Port must be" in browser.text(r)


def test_listener_settings_admin_only(browser, logged_in):
    logged_in("operator")
    assert browser.get("/clients/radsec").status_code == 403
