"""Second-factor providers for device admin logins (SPEC section 29): the SQL function
FreeRADIUS calls, the rendered clients file and policy, the Integrations page."""
import json

import pytest

from conftest import stepup
from radius_admin import unlang

PROXY_SECRET = "TestDuoProxySecret0123456"
PRIMARY_SECRET = "TestMfaPrimarySecret01234"
REMOTE_SECRET = "TestRemoteMfaSecret012345"


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def h(text):
    return text.encode().hex()


def mfa(superconn, user, client="sw1", kind="local"):
    return q(superconn, "SELECT radius_admin_mfa_hex(%s, %s, %s)", (h(user), h(client), kind))[0][0]


def provider(superconn, pid="duo", ptype="duo", enabled=True):
    q(superconn, "INSERT INTO ui.mfa_provider (id, type, enabled) VALUES (%s, %s, %s)", (pid, ptype, enabled))


def rule(superconn, kind, pid, enabled=True, scope="all"):
    q(superconn, "UPDATE ui.mfa_policy SET enabled=%s, provider_id=%s, client_scope=%s WHERE account_kind=%s",
      (enabled, pid, scope, kind))


def add_client(superconn, name, ip):
    return q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES (%s, %s, %s) RETURNING id",
             (name, ip, "TestSwitchSecret0123456789"))[0][0]


def add_device_admin(superconn, name):
    q(superconn, "INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, 'net-admins', 1)", (name,))


# ------------------------------------------------------------------ SQL
def test_mfa_off_by_default(superconn, clean_db):
    assert mfa(superconn, "netops1") == "off"
    assert mfa(superconn, "jroe", kind="directory") == "off"


def test_mfa_provider_per_account_kind(superconn, clean_db):
    provider(superconn, "duo", "duo")
    provider(superconn, "nps", "radius-mfa")
    rule(superconn, "local", "duo")
    rule(superconn, "directory", "nps")
    assert mfa(superconn, "netops1") == "duo:duo"
    assert mfa(superconn, "jroe", kind="directory") == "radius-mfa:nps"
    rule(superconn, "directory", "nps", enabled=False)
    assert mfa(superconn, "jroe", kind="directory") == "off"


def test_mfa_exempt_local_accounts_only_case_insensitive(superconn, clean_db):
    provider(superconn)
    rule(superconn, "local", "duo")
    rule(superconn, "directory", "duo")
    q(superconn, "INSERT INTO ui.mfa_exempt (username) VALUES ('BreakGlass')")
    assert mfa(superconn, "breakglass") == "exempt"
    assert mfa(superconn, "BREAKGLASS") == "exempt"
    assert mfa(superconn, "breakglass", kind="directory") == "duo:duo"     # the list is for local accounts
    assert mfa(superconn, "netops1") == "duo:duo"


def test_mfa_selected_clients(superconn, clean_db):
    provider(superconn)
    rule(superconn, "local", "duo", scope="selected")
    cid = add_client(superconn, "fw-edge", "192.0.2.20")
    add_client(superconn, "sw1", "192.0.2.21")
    assert mfa(superconn, "netops1", client="fw-edge") == "off"           # selected, none chosen yet
    q(superconn, "INSERT INTO ui.mfa_policy_client (account_kind, client_id) VALUES ('local', %s)", (cid,))
    assert mfa(superconn, "netops1", client="fw-edge") == "duo:duo"
    assert mfa(superconn, "netops1", client="sw1") == "off"
    assert mfa(superconn, "netops1", client="") == "off"
    q(superconn, "DELETE FROM ui.radius_client WHERE id = %s", (cid,))    # cascades
    assert q(superconn, "SELECT count(*) FROM ui.mfa_policy_client")[0][0] == 0


def test_mfa_provider_off_is_unavailable(superconn, clean_db):
    provider(superconn, enabled=False)
    rule(superconn, "local", "duo")
    assert mfa(superconn, "netops1") == "unavailable"


def test_mfa_rule_needs_provider(superconn, clean_db):
    import psycopg2
    with pytest.raises(psycopg2.Error):
        rule(superconn, "local", None)


@pytest.mark.parametrize("args", [(None, h("sw1"), "local"), ("", h("sw1"), "local"), ("zz", h("sw1"), "local"),
                                  (h("a") + "'", h("sw1"), "local"), ("00" * 254, h("sw1"), "local"),
                                  (h("a"), "zz", "local"), (h("a"), "00" * 64, "local"), (h("a"), h("sw1"), "other"),
                                  (h("a"), h("sw1"), None), (h("a"), None, "local")])
def test_mfa_malformed_is_null(superconn, clean_db, args):
    provider(superconn)
    rule(superconn, "local", "duo")
    assert q(superconn, "SELECT radius_admin_mfa_hex(%s, %s, %s)", args)[0][0] is None


@pytest.mark.parametrize("payload", ["x' OR '1'='1", "x'); DELETE FROM ui.mfa_policy; --", "\\047 OR 1=1 --",
                                     "%{User-Password}"])
def test_mfa_injection_is_inert(superconn, clean_db, payload):
    provider(superconn)
    rule(superconn, "local", "duo")
    assert mfa(superconn, payload) == "duo:duo"
    assert mfa(superconn, "netops1", client=payload) == "duo:duo"
    assert q(superconn, "SELECT count(*) FROM ui.mfa_policy")[0][0] == 2


def test_mfa_function_only_for_freeradius(superconn, clean_db):
    acl = q(superconn, "SELECT proacl::text FROM pg_proc WHERE proname = 'radius_admin_mfa_hex'")[0][0]
    entries = acl.strip("{}").split(",")
    assert "radius_fr=X" in acl and "radius_admin=X" not in acl and not any(e.startswith("=") for e in entries)


# ------------------------------------------------------------------ rendering
DUO = dict(id="duo", type="duo", enabled=True, secret=PROXY_SECRET, primary_secret=PRIMARY_SECRET)
NPS = dict(id="nps", type="radius-mfa", enabled=True, address="192.0.2.50", port=1812, secret=REMOTE_SECRET,
           timeout=30, require_ma="yes")


def test_render_mfa_empty_without_enabled_providers():
    assert unlang.render_mfa([]) == ""
    assert unlang.render_mfa([dict(DUO, enabled=False), dict(NPS, enabled=False)]) == ""


def test_render_mfa_duo_and_remote():
    out = unlang.render_mfa([NPS, DUO])
    assert out == unlang.render_mfa([DUO, NPS])                          # deterministic, sorted by id
    assert out.index("home_server radius_admin_mfa_duo") < out.index("home_server radius_admin_mfa_nps")
    assert "virtual_server = radius-admin-mfa-primary" in out and "ipv4addr = 127.0.0.1\n\tport = 18121" in out
    assert 'secret = "%s"' % PRIMARY_SECRET in out and 'secret = "%s"' % PROXY_SECRET in out
    assert "ipv4addr = 192.0.2.50\n\tport = 1812" in out and "response_window = 30" in out
    assert "status_check = none" in out and "realm radius_admin_mfa_nps {\n\tauth_pool = radius_admin_mfa_nps" in out


def test_render_mfa_remote_only_has_no_listener():
    out = unlang.render_mfa([NPS])
    assert "listen" not in out and "clients radius_admin_mfa" not in out


def test_render_mfa_ipv6():
    out = unlang.render_mfa([dict(NPS, address="2001:db8::5")])
    assert "ipv6addr = 2001:db8::5" in out


@pytest.mark.parametrize("bad,msg", [
    (dict(NPS, id="Bad_Id"), "Provider id"),
    (dict(NPS, type="other"), "type"),
    (dict(NPS, address="192.0.2.0/24"), "not a network"),
    (dict(NPS, address="radius.example.net"), ""),
    (dict(NPS, port=0), "port"),
    (dict(NPS, timeout=4), "timeout"),
    (dict(NPS, timeout=61), "timeout"),
    (dict(NPS, secret='short'), ""),
    (dict(NPS, secret='TestRemote"Secret012345'), ""),
    (dict(NPS, require_ma="auto"), "Message-Authenticator"),
    (dict(DUO, primary_secret=None), "password check"),
])
def test_render_mfa_refuses_bad_input(bad, msg):
    with pytest.raises(unlang.PolicyInputError) as e:
        unlang.render_mfa([bad])
    assert msg in str(e.value)


def test_render_mfa_one_duo_and_unique_ids():
    with pytest.raises(unlang.PolicyInputError):
        unlang.render_mfa([DUO, dict(DUO, id="duo2")])
    with pytest.raises(unlang.PolicyInputError):
        unlang.render_mfa([NPS, NPS])


def test_render_clients_appends_mfa():
    cl = [dict(name="sw1", ipaddr="192.0.2.10", secret="TestSwitchInSecret012345678", enabled=True)]
    plain = unlang.render_clients(cl)
    assert unlang.render_clients(cl, None, None, []) == plain
    assert unlang.render_clients(cl, None, None, [NPS]) == plain + unlang.render_mfa([NPS])


def test_policy_asks_mfa_with_hex_and_fails_closed():
    from radius_admin import vendors
    p = unlang.render_policy("", vendors.default(), [])
    assert ("radius_admin_mfa_hex('%{hex:User-Name}', '%{hex:control:Tmp-String-5}', 'local')" in p
            and "'directory')" in p)
    assert '&Proxy-To-Realm := "radius_admin_mfa_%{2}"' in p
    assert "its provider is turned off" in p and "could not determine whether this login needs a second factor" in p
    # %{...} comparisons never fail to evaluate; Class (octets) prints as 0x<hex>
    assert '"%{proxy-reply:Packet-Type}" == "Access-Accept"' in p
    assert '"%{proxy-reply:Class}" == "0x' + b"radius-admin:pap-admin".hex() + '"' in p
    assert "&proxy-reply:" not in p
    assert "radius_admin_mfa_primary_authorize {" in p and "radius_admin_mfa_primary_postauth {" in p
    # the provider's own reply attributes never reach the device
    assert "&reply: !* ANY" in p
    # no raw request data in SQL
    import re
    for call in re.findall(r"%\{sql:SELECT radius_admin_mfa_hex\([^)]*\)\}", p):
        assert "'%{User-Name}'" not in call


# ------------------------------------------------------------------ the page
def audit(superconn, action):
    return [json.loads(d) for (d,) in q(superconn, "SELECT detail::text FROM ui.audit_log WHERE action=%s ORDER BY id",
                                        (action,))]


REMOTE_FORM = {"id": "nps-mfa", "label": "NPS with the MFA extension", "address": "192.0.2.50", "port": "1812",
               "secret": REMOTE_SECRET, "timeout": "45", "require_ma": "1", "enabled": "1"}


def test_index_visible_to_viewer_without_changes(browser, superconn, logged_in):
    logged_in("viewer")
    r = browser.get("/integrations/")
    assert r.status_code == 200
    body = browser.text(r)
    assert "Second-factor rules" in body and "Add remote MFA server" not in body and "Change the rules" not in body
    assert "FIPS" not in body
    assert browser.get("/integrations/remote/new").status_code in (302, 403)
    assert browser.get("/integrations/policy").status_code in (302, 403)


def test_operator_cannot_change(browser, superconn, logged_in):
    logged_in("operator")
    assert browser.get("/integrations/remote/new").status_code in (302, 403)


def test_add_remote_server_encrypted_audited_and_pending(app, browser, superconn, logged_in):
    from radius_admin import services
    u = logged_in("admin")
    stepup(browser, superconn, u)
    r = browser.post("/integrations/remote/new", REMOTE_FORM)
    assert r.status_code == 302, browser.text(r)
    row = q(superconn, "SELECT type, enabled, settings::text, secrets_enc FROM ui.mfa_provider WHERE id='nps-mfa'")[0]
    assert row[0] == "radius-mfa" and row[1] is True
    assert json.loads(row[2]) == {"address": "192.0.2.50", "port": 1812, "timeout": 45, "require_ma": "yes"}
    assert REMOTE_SECRET.encode() not in bytes(row[3])
    d = audit(superconn, "integration.provider_create")
    assert d and d[0]["shared_key_set"] is True and REMOTE_SECRET not in json.dumps(d)
    with app.test_request_context():
        _, clients = services.render_all()
    assert "home_server radius_admin_mfa_nps-mfa" in clients and 'secret = "%s"' % REMOTE_SECRET in clients
    assert "response_window = 45" in clients


def test_add_remote_server_validation(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    for change, field in ((dict(id="Bad_Id"), "1-32 lower-case"), (dict(address="192.0.2.0/24"), "not a network"),
                          (dict(timeout="90"), "timeout"), (dict(secret="short"), ""), (dict(port="70000"), "port")):
        r = browser.post("/integrations/remote/new", dict(REMOTE_FORM, **change))
        assert r.status_code == 400 and field in browser.text(r), change
    assert q(superconn, "SELECT count(*) FROM ui.mfa_provider")[0][0] == 0


def test_edit_keeps_secret_when_empty(app, browser, superconn, logged_in):
    from radius_admin import integrations as ig
    u = logged_in("admin")
    stepup(browser, superconn, u)
    browser.post("/integrations/remote/new", REMOTE_FORM)
    r = browser.post("/integrations/nps-mfa/edit", dict(REMOTE_FORM, secret="", address="198.51.100.7"))
    assert r.status_code == 302, browser.text(r)
    blob = q(superconn, "SELECT secrets_enc FROM ui.mfa_provider WHERE id='nps-mfa'")[0][0]
    assert ig.decrypt_secrets(app.config["RA_DATA_KEY"], "nps-mfa", blob) == {"secret": REMOTE_SECRET}
    d = audit(superconn, "integration.provider_update")[-1]
    assert d["address"] == {"from": "192.0.2.50", "to": "198.51.100.7"} and "shared_key_updated" not in d
    browser.post("/integrations/nps-mfa/edit", dict(REMOTE_FORM, secret="TestRemoteMfaSecretNew99999"))
    assert audit(superconn, "integration.provider_update")[-1]["shared_key_updated"] is True


def test_secret_bound_to_provider_id(app, superconn, clean_db):
    from radius_admin import integrations as ig
    key = app.config["RA_DATA_KEY"]
    blob = ig.encrypt_secrets(key, "a", {"secret": REMOTE_SECRET})
    with pytest.raises(unlang.PolicyInputError):
        ig.decrypt_secrets(key, "b", blob)


def test_policy_rules_validation_and_save(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    browser.post("/integrations/remote/new", REMOTE_FORM)
    provider(superconn, "off-one", "radius-mfa", enabled=False)
    add_device_admin(superconn, "breakglass")
    base = {"local_scope": "all", "directory_scope": "all", "exempt": ""}
    # a remote server cannot check a local account's password
    r = browser.post("/integrations/policy", dict(base, local_enabled="1", local_provider="nps-mfa"))
    assert r.status_code == 400 and "directory accounts only" in browser.text(r)
    # a provider that is off
    r = browser.post("/integrations/policy", dict(base, directory_enabled="1", directory_provider="off-one"))
    assert r.status_code == 400 and "turned off" in browser.text(r)
    # selected clients, none chosen
    r = browser.post("/integrations/policy", dict(base, directory_enabled="1", directory_provider="nps-mfa",
                                                  directory_scope="selected"))
    assert r.status_code == 400 and "at least one client" in browser.text(r)
    # exempt names must be local device admins
    r = browser.post("/integrations/policy", dict(base, exempt="nosuchuser"))
    assert r.status_code == 400 and "not a local device admin" in browser.text(r)
    cid = add_client(superconn, "fw-edge", "192.0.2.20")
    r = browser.post("/integrations/policy", dict(base, directory_enabled="1", directory_provider="nps-mfa",
                                                  directory_scope="selected", directory_clients=str(cid),
                                                  exempt="BreakGlass\nbreakglass\n"))
    assert r.status_code == 302, browser.text(r)
    assert q(superconn, "SELECT enabled, provider_id, client_scope FROM ui.mfa_policy WHERE account_kind='directory'")[0] \
        == (True, "nps-mfa", "selected")
    assert q(superconn, "SELECT username FROM ui.mfa_exempt") == [("breakglass",)]
    assert mfa(superconn, "jroe", client="fw-edge", kind="directory") == "radius-mfa:nps-mfa"
    d = audit(superconn, "integration.policy")[-1]
    assert d["directory"]["enabled"] == {"from": False, "to": True} and d["exempt"]["to"] == ["breakglass"]


def test_provider_in_use_cannot_be_removed_or_turned_off(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    browser.post("/integrations/remote/new", REMOTE_FORM)
    rule(superconn, "directory", "nps-mfa")
    r = browser.post("/integrations/nps-mfa/delete", csrf_page="/integrations/")
    assert r.status_code == 302
    assert q(superconn, "SELECT count(*) FROM ui.mfa_provider")[0][0] == 1
    form = dict(REMOTE_FORM, secret="")
    form.pop("enabled")
    r = browser.post("/integrations/nps-mfa/edit", form)
    assert r.status_code == 400 and "before you turn the server off" in browser.text(r)
    rule(superconn, "directory", None, enabled=False)
    r = browser.post("/integrations/nps-mfa/delete", csrf_page="/integrations/")
    assert q(superconn, "SELECT count(*) FROM ui.mfa_provider")[0][0] == 0
    assert audit(superconn, "integration.provider_delete")


def test_fips_mode_hides_remote_servers(app, browser, superconn, logged_in):
    app.config["RA"]["require_fips"] = True
    u = logged_in("admin")
    stepup(browser, superconn, u)
    body = browser.text(browser.get("/integrations/"))
    assert "Add remote MFA server" not in body and "Not available in FIPS mode" in body
    assert browser.get("/integrations/remote/new").status_code == 404
    provider(superconn, "nps", "radius-mfa")
    r = browser.post("/integrations/policy", {"directory_enabled": "1", "directory_provider": "nps",
                                              "local_scope": "all", "directory_scope": "all", "exempt": ""})
    assert r.status_code == 400 and "not available in FIPS mode" in browser.text(r)


# ------------------------------------------------------------------ Duo configuration (SPEC section 29.2)
DUO_SETTINGS = dict(ikey="DIAAAAAAAAAAAAAAAAAA", skey="a" * 40, api_host="api-00000000.duosecurity.com",
                    secret=PROXY_SECRET, primary_secret=PRIMARY_SECRET)


def test_duo_config_rendering():
    txt = unlang.render_duo_config(DUO_SETTINGS)
    assert txt == unlang.render_duo_config(dict(DUO_SETTINGS))          # deterministic
    assert txt.startswith("; radius-admin")
    for line in ("host=127.0.0.1", "port=18121", "secret=" + PRIMARY_SECRET, "pass_through_attr_names=Class",
                 "radius_ip_1=127.0.0.1", "radius_secret_1=" + PROXY_SECRET, "interface=127.0.0.1", "port=18120",
                 "client=radius_client", "failmode=secure", "factors=auto",
                 "pass_through_attr_names=Message-Authenticator", "force_message_authenticator=true"):
        assert line + "\n" in txt, line
    assert "fips_mode" not in txt and "FIPS" not in txt


def test_duo_config_fips_mode():
    txt = unlang.render_duo_config(dict(DUO_SETTINGS, failmode="safe"), fips=True)
    assert "fips_mode=true\n" in txt and "failmode=secure\n" in txt


@pytest.mark.parametrize("bad,msg", [
    (dict(ikey="DI123"), "Integration key"),
    (dict(ikey="XXAAAAAAAAAAAAAAAAAA"), "Integration key"),
    (dict(skey="short"), "Secret key"),
    (dict(api_host="api-x.duosecurity.com.example.net"), "API hostname"),
    (dict(api_host="evil.example.net"), "API hostname"),
    (dict(secret="has;semicolon0123456"), "Duo proxy secret"),
    (dict(primary_secret="short"), "Password check secret"),
    (dict(failmode="open"), "Fail mode"),
    (dict(factors="sms"), "Factors"),
    (dict(factors="push,push"), "Factors"),
])
def test_duo_settings_refused(bad, msg):
    with pytest.raises(unlang.PolicyInputError) as e:
        unlang.render_duo_config(dict(DUO_SETTINGS, **bad))
    assert msg in str(e.value)


def test_duo_config_matches_the_helper_grammar():
    import importlib.machinery
    import importlib.util
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "..", "helper", "radius-admin-helper")
    loader = importlib.machinery.SourceFileLoader("ra_helper_for_test", path)
    spec = importlib.util.spec_from_loader("ra_helper_for_test", loader)
    h = importlib.util.module_from_spec(spec)
    loader.exec_module(h)
    for fips in (False, True):
        found = h.check_duo_config(unlang.render_duo_config(dict(DUO_SETTINGS, factors="push,phone"), fips).encode(), fips)
        assert found["radius_server_auto"]["factors"] == "push,phone"


def test_cli_records_integration_outcome(app, superconn, monkeypatch):
    from radius_admin import cli
    monkeypatch.setenv("RADIUS_ADMIN_CONFIG", "")
    monkeypatch.setattr(cli, "load_config", lambda path: dict(app.config["RA"]))
    assert cli.main(["record-integration", "--id", "duo", "--action", "install", "--result", "done",
                     "--version", "6.8.1", "--message", "installed 6.8.1", "--actor", "alice"]) == 0
    row = q(superconn, "SELECT action, success, actor, object_id, detail::text FROM ui.audit_log"
                       " WHERE action = 'integration.install'")[0]
    assert row[:4] == ("integration.install", True, "alice", "duo") and json.loads(row[4])["version"] == "6.8.1"
