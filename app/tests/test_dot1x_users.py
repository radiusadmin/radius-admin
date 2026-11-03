"""802.1X with a username and password: local users, the live SQL decision functions,
the setting and the policy contract (SPEC section 18). FreeRADIUS behaviour itself is
covered by the bench (tests/freeradius/run-tests.py, ttls_cases)."""
import datetime
import json
import re

import pytest

from conftest import stepup

PW = "Dot1x-User-Pass-2026"


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def hx(s):
    return s.encode().hex()


def add_user(superconn, name="j.doe", groups=("Wired-Office",), enabled=True, expires="NULL"):
    from radius_admin.crypto import fr_pbkdf2_hash
    q(superconn, "INSERT INTO ui.dot1x_user (username, password_hash, groups, enabled, expires_at)"
                 " VALUES (%s, %s, %s, %s, " + expires + ")",
      (name, fr_pbkdf2_hash(PW, 1000), list(groups), enabled))


def ttls_on(superconn, on=True):
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('dot1x_ttls', %s)"
                 " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", ("true" if on else "false",))


# ------------------------------------------------------------------ SQL decision functions
def test_user_lookup_function(app, superconn):
    add_user(superconn)
    add_user(superconn, "d.off", enabled=False)
    add_user(superconn, "e.old", expires="now() - interval '1 hour'")
    f = lambda arg: q(superconn, "SELECT radius_admin_dot1x_user_hex(%s)", (arg,))[0][0]  # noqa: E731
    assert f(hx("j.doe")) == "off"                       # off by default
    ttls_on(superconn)
    assert f(hx("j.doe")).startswith("{X-PBKDF2}HMACSHA2+256:")
    assert f(hx("J.Doe")).startswith("{X-PBKDF2}")       # not case-sensitive
    assert f(hx("d.off")) == "disabled" and f(hx("e.old")) == "expired" and f(hx("nobody")) == "unknown"
    for bad in ("", "zz", "6a2", "j.doe", "00" * 65, None):
        assert f(bad) is None, bad
    assert f(hx("j.doe' OR '1'='1")) == "unknown"
    # directory accounts: a name that is not a local user goes to the directory; local wins
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('dot1x_ttls_directory', 'true')")
    assert f(hx("nobody")) == "directory" and f(hx("jroe@example.net")) == "directory"
    assert f(hx("j.doe")).startswith("{X-PBKDF2}") and f(hx("d.off")) == "disabled"
    assert f("zz") is None
    ttls_on(superconn, False)
    assert f(hx("j.doe")) == "off" and f(hx("nobody")) == "off"


def test_vlan_function_uses_the_access_rules(app, superconn):
    q(superconn, "INSERT INTO ui.access_rule (id, priority, connection, ssid, ad_group, vlan) VALUES"
                 " (1, 10, 'wired', NULL, 'Wired-Office', 500), (2, 10, 'wireless', 'Example_Main', 'WIFI-OFFICE', 530)")
    add_user(superconn, groups=("wired-office", "WIFI-OFFICE"))
    add_user(superconn, "k.smith", groups=("Lab-Only",))
    add_user(superconn, "d.off", enabled=False)
    f = lambda u, wired, csi="": q(superconn, "SELECT radius_admin_dot1x_vlan_rule_hex(%s, %s, %s)",  # noqa: E731
                                   (hx(u), wired, hx(csi)))[0][0]
    assert f("j.doe", True) is None                      # setting off
    ttls_on(superconn)
    assert f("j.doe", True) == "500:1"
    assert f("j.doe", False, "AA-BB-CC-DD-EE-FF:Example_Main") == "530:2"
    assert f("j.doe", False, "AA-BB-CC-DD-EE-FF:Guest") is None
    assert f("k.smith", True) is None and f("d.off", True) is None and f("nobody", True) is None
    assert q(superconn, "SELECT radius_admin_dot1x_vlan_rule_hex('zz', true, '')")[0][0] is None


def test_least_privilege(app, superconn):
    rows = q(superconn, "SELECT has_function_privilege('radius_fr', 'radius_admin_dot1x_user_hex(text)', 'EXECUTE'),"
                        " has_function_privilege('radius_fr', 'radius_admin_dot1x_vlan_rule_hex(text,boolean,text)', 'EXECUTE'),"
                        " has_function_privilege('radius_admin', 'radius_admin_dot1x_user_hex(text)', 'EXECUTE'),"
                        " has_table_privilege('radius_fr', 'ui.dot1x_user', 'SELECT'),"
                        " has_table_privilege('radius_admin', 'ui.dot1x_user', 'SELECT')")[0]
    assert rows == (True, True, False, False, True)


@pytest.mark.parametrize("method", ["ttls-pap", "ttls-ldap"])
def test_mab_ignores_a_mac_that_used_a_password(app, superconn, method):
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, callingstationid, authdate)"
                 " VALUES ('j.doe', 'Access-Accept', %s, 'aa-bb-cc-00-00-78', now())", (method,))
    assert q(superconn, "SELECT radius_admin_mab_hex('AA-BB-CC-00-00-78', '', '')")[0][0] == "certificate"
    assert q(superconn, "SELECT count(*) FROM mab_pending")[0][0] == 0


# ------------------------------------------------------------------ console
def test_lifecycle_and_audit(browser, superconn, logged_in):
    from radius_admin.crypto import fr_pbkdf2_verify
    q(superconn, "INSERT INTO ui.access_rule (priority, connection, ad_group, vlan) VALUES (10, 'wired', 'Wired-Office', 500)")
    logged_in("operator")
    page = browser.text(browser.get("/dot1x-users/"))
    assert "turned off" in page and "No 802.1X users" in page
    r = browser.post("/dot1x-users/new", {"username": "j.doe", "password": PW, "confirm": PW,
                                          "groups": "Wired-Office, Lab-Only, wired-office", "enabled": "1",
                                          "description": "Visiting engineer"})
    assert r.status_code == 302, browser.text(r)[-1500:]
    uid, h, groups, enabled = q(superconn, "SELECT id, password_hash, groups, enabled FROM ui.dot1x_user")[0]
    assert fr_pbkdf2_verify(PW, h) and groups == ["Wired-Office", "Lab-Only"] and enabled
    assert q(superconn, "SELECT count(*) FROM radcheck")[0][0] == 0      # never a switch-admin row
    page = browser.text(browser.get("/dot1x-users/"))
    assert "j.doe" in page and "Visiting engineer" in page and "No enabled access rule uses this group" in page
    # duplicates (any case), bad input
    for data, field in ((dict(username="J.DOE"), "already exists"), (dict(username="bad user"), "Username must be"),
                        (dict(groups="Wired;Office"), ""), (dict(confirm=PW + "x"), "do not match"),
                        (dict(password="short", confirm="short"), "at least"),
                        (dict(expires="2001-01-01"), "in the past")):
        form = {"username": "x.new", "password": PW, "confirm": PW, "groups": "Wired-Office", "enabled": "1"}
        form.update(data)
        r = browser.post("/dot1x-users/new", form)
        assert r.status_code == 400 and field in browser.text(r), data
    assert q(superconn, "SELECT count(*) FROM ui.dot1x_user")[0][0] == 1
    # edit: groups, disable, expiry
    r = browser.post("/dot1x-users/%d/edit" % uid, {"groups": "Wired-Office", "expires": "2099-12-31",
                                                    "description": ""})
    assert r.status_code == 302
    groups, enabled, expires = q(superconn, "SELECT groups, enabled, expires_at FROM ui.dot1x_user")[0]
    assert groups == ["Wired-Office"] and enabled is False
    assert expires.astimezone(datetime.timezone.utc) == datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc)
    # new password
    r = browser.post("/dot1x-users/%d/password" % uid, {"password": PW + "-2", "confirm": PW + "-2"})
    assert r.status_code == 302
    assert fr_pbkdf2_verify(PW + "-2", q(superconn, "SELECT password_hash FROM ui.dot1x_user")[0][0])
    browser.post("/dot1x-users/%d/delete" % uid, {}, csrf_page="/dot1x-users/")
    assert q(superconn, "SELECT count(*) FROM ui.dot1x_user")[0][0] == 0
    acts = q(superconn, "SELECT action, object_id, coalesce(detail::text, '') FROM ui.audit_log"
                        " WHERE action LIKE 'dot1x_user.%%' ORDER BY id")
    assert [a for a, _, _ in acts] == ["dot1x_user.create", "dot1x_user.update", "dot1x_user.credential_reset",
                                       "dot1x_user.delete"]
    assert all(o == "j.doe" for _, o, _ in acts)
    assert json.loads(acts[1][2])["enabled"] == {"from": True, "to": False}
    dump = " ".join(d for _, _, d in acts)
    assert PW not in dump and "X-PBKDF2" not in dump


def test_rbac(browser, superconn, logged_in):
    add_user(superconn)
    logged_in("viewer")
    assert browser.get("/dot1x-users/").status_code == 200
    for p in ("/dot1x-users/new", "/dot1x-users/1/edit", "/dot1x-users/1/password"):
        assert browser.get(p).status_code == 403, p
    tok = browser.csrf_from("/dot1x-users/")
    assert browser.post("/dot1x-users/new", {"username": "x", "password": PW, "confirm": PW}, csrf=tok).status_code == 403
    assert browser.post("/dot1x-users/1/delete", {}, csrf=tok).status_code == 403
    assert q(superconn, "SELECT count(*) FROM ui.dot1x_user")[0][0] == 1


def test_setting_admin_only_audited(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    form = {"admin_subnet": "192.0.2.0/24", "banner_text": "Authorized use only. Testing banner text.",
            "dot1x_ttls": "1"}
    assert browser.post("/settings", form).status_code == 302
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='dot1x_ttls'") == [("true",)]
    page = browser.text(browser.get("/dot1x-users/"))
    assert "turned off" not in page and "Directory accounts are accepted" not in page
    browser.post("/settings", dict(form, dot1x_ttls_directory="1"))
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='dot1x_ttls_directory'") == [("true",)]
    assert "Directory accounts are accepted" in browser.text(browser.get("/dot1x-users/"))
    form.pop("dot1x_ttls")
    browser.post("/settings", form)
    assert q(superconn, "SELECT key, value FROM ui.setting WHERE key LIKE 'dot1x%%' ORDER BY key") == [
        ("dot1x_ttls", "false"), ("dot1x_ttls_directory", "false")]
    details = [json.loads(d) for (d,) in q(superconn, "SELECT detail::text FROM ui.audit_log"
                                                      " WHERE action='settings.update' ORDER BY id")]
    assert [d["dot1x_ttls"]["to"] for d in details if "dot1x_ttls" in d] == [True, False]
    assert [d["dot1x_ttls_directory"]["to"] for d in details if "dot1x_ttls_directory" in d] == [True, False]


def test_auth_log_method_and_hints(browser, superconn, logged_in):
    from radius_admin import insight
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, reason, authdate) VALUES"
                 " ('j.doe', 'Access-Reject', 'ttls-pap', 'radius-admin: wrong password for 802.1X user', now()),"
                 " ('host/pc1.example.net', 'Access-Accept', 'eap-tls', NULL, now())")
    logged_in("viewer")
    t = browser.text(browser.get("/auth-log?method=ttls-pap"))
    assert "j.doe" in t and "host/pc1.example.net" not in t
    rid = q(superconn, "SELECT id FROM radpostauth WHERE username='j.doe'")[0][0]
    t = browser.text(browser.get("/auth-log/%d" % rid))
    assert "802.1X username and password (EAP-TTLS, local user)" in t and "Wrong password for this 802.1X user" in t
    assert "Not checked: the login was refused before the access rules" in t and "No rule matched" not in t
    for reason, want in (("username and password sign-in (EAP-TTLS) is turned off", "Turn it on in Settings"),
                         ("802.1X user is disabled", "Enable it"), ("802.1X user has expired", "new expiry"),
                         ("no such 802.1X user", "not the outer"), ("only PAP is accepted inside EAP-TTLS", "PAP"),
                         ("no enabled access rule matches the user's groups for this connection", "user's groups"),
                         ("MAB not used: this device authenticates with 802.1X", "not offered for MAB"),
                         ("the directory refused the password (wrong password, or a disabled, locked or expired "
                          "account)", "locked out"),
                         ("no such 802.1X user (not a local user, not found in the directory)", "userPrincipalName"),
                         ("the directory could not be searched for this user", "domain controllers")):
        assert want in insight.reason_hint("radius-admin: " + reason), reason


def test_auth_log_directory_groups(browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.access_rule (id, priority, connection, ad_group, vlan) VALUES (7, 10, 'wired', 'Wired-Office', 500)")
    groups = ",".join("," + g.encode().hex() for g in ("Wired-Office", "Staff")).replace(",,", ",")
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, vlan, rule_id, ad_groups_hex, authdate) VALUES"
                 " ('jroe', 'Access-Accept', 'ttls-ldap', '500', 7, %s, now())", (groups,))
    logged_in("viewer")
    assert "jroe" in browser.text(browser.get("/auth-log?method=ttls-ldap"))
    t = browser.text(browser.get("/auth-log/1"))
    assert "EAP-TTLS, directory account" in t and "Directory groups seen (2)" in t and "Staff" in t
    assert "matched" in t and "Wired-Office" in t


# ------------------------------------------------------------------ policy contract
@pytest.fixture
def policy():
    from radius_admin import unlang
    return unlang.render_policy("")


def test_inner_tunnel_reads_only_the_local_users(policy):
    inner = policy[policy.index("radius_admin_inner_authorize {"):policy.index("radius_admin_inner_postauth {")]
    assert "%{sql:SELECT radius_admin_dot1x_user_hex('%{hex:User-Name}')}" in inner
    assert "radcheck" not in inner and "SQL-Group" not in inner
    # no module call here: the directory is asked by the inner site
    assert not re.search(r"^\s*-?ldap(_user)?(\.\w+)?\s*$", inner, re.M)
    assert "&Password-With-Header := &control:Tmp-String-0" in inner
    assert inner.count("\treject\n") == 2             # not PAP; no usable hash
    post = policy[policy.index("radius_admin_inner_postauth {"):policy.index("radius_admin_inner_reject {")]
    assert "update outer.session-state" in post and '&Tmp-String-1 := "ttls-pap"' in post


def test_outer_branch_needs_the_inner_marker(policy):
    pa = policy[policy.index("radius_admin_postauth {"):]
    ttls = pa[pa.index("# 802.1X with a username and password"):pa.index("# 802.1X EAP-TLS")]
    assert ('elsif (&EAP-Message && &session-state:Tmp-String-1 && (&session-state:Tmp-String-1 == "ttls-pap"'
            ' || &session-state:Tmp-String-1 == "ttls-ldap" || &session-state:Tmp-String-1 == "peap"'
            ' || &session-state:Tmp-String-1 == "peap-ldap") && &session-state:Stripped-User-Name)') in ttls
    assert pa.index("# Switch/device admin logins") < pa.index("# 802.1X with a username") < pa.index("# 802.1X EAP-TLS")
    assert ("%{sql:SELECT radius_admin_dot1x_vlan_rule_hex('%{hex:control:Stripped-User-Name}', "
            "%{control:Tmp-String-7}, '%{control:Tmp-String-8}')}") in ttls
    assert '"%{control:Tmp-String-8}" =~ /^([0-9a-f]{2})*$/' in ttls
    assert "&session-state:Tmp-String-1 !* ANY" not in ttls   # removed with update session-state
    assert "\t\t\t&Tmp-String-1 !* ANY\n\t\t\t&Stripped-User-Name !* ANY\n" in ttls
    assert ttls.rstrip().endswith("\t\t\treject\n\t\t}\n\t}")


def test_inner_tunnel_directory_branch(policy):
    inner = policy[policy.index("radius_admin_inner_authorize {"):policy.index("radius_admin_inner_postauth {")]
    d = inner[inner.index('elsif (&control:Tmp-String-0 && &control:Tmp-String-0 == "directory")'):]
    d = d[:d.index("\telse {")]
    assert '&Tmp-String-1 := "ttls-ldap"' in d and "reject" not in d and "ldap" not in d.replace("ttls-ldap", "").replace("ldap_user", "")
    post = policy[policy.index("radius_admin_inner_postauth {"):policy.index("radius_admin_inner_reject {")]
    assert "&Tmp-String-7 += &control:Tmp-String-9[*]" in post and "%{hex:control:Tmp-String-9[0]}" in post
    assert '"%{control:Tmp-String-3}" !~ /^(,[0-9a-f]+)*$/' in post
    assert "&Tmp-String-3 := &control:Tmp-String-3" in post
    ttls = policy[policy.index("# 802.1X with a username and password"):policy.index("# 802.1X EAP-TLS")]
    assert ('(&control:Tmp-String-1 == "ttls-ldap" || &control:Tmp-String-1 == "peap-ldap")'
            ' && "%{control:Tmp-String-3}" =~ /^(,[0-9a-f]+)*$/ && "%{control:Tmp-String-8}" =~ /^([0-9a-f]{2})*$/') in ttls
    assert "%{sql:SELECT radius_admin_vlan_rule_hex(%{control:Tmp-String-7}, '%{control:Tmp-String-8}', '%{control:Tmp-String-3}')}" in ttls
    assert "\t\t\t&Tmp-String-3 !* ANY\n" in ttls     # the groups leave session-state with the marker


def test_ldap_user_section_reuses_the_main_ldap_settings():
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "..", "freeradius", "mods-available", "ldap")
    text = open(path).read()
    main, user = text.index("\nldap {\n"), text.index("\nldap ldap_user {\n")
    assert main < user                       # references resolve while the file is read
    sec = text[user:]
    for key in ("server", "port", "identity", "password", "base_dn"):
        assert re.search(r"^\t%s = \$\{modules\.ldap\.%s\}$" % (key, key), sec, re.M), key
    assert "REDACTED" not in sec and "update {" not in sec
    assert "(!(objectClass=computer))" in sec and "sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}}" in sec


# ------------------------------------------------------------------ PEAP-MSCHAPv2 (SPEC section 20)
def test_nt_hash_vectors():
    from radius_admin.crypto import nt_hash
    assert nt_hash("") == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert nt_hash("password") == "8846f7eaee8fb117ad06bdd830b7586c"
    assert nt_hash("Password1") == "64f12cddaa88057e06a81b54e73b949b"
    assert len(nt_hash("x" * 128)) == 32 and nt_hash("x" * 128) != nt_hash("x" * 127)   # several MD4 blocks


def test_nt_hash_function(app, superconn):
    from radius_admin.crypto import nt_hash
    add_user(superconn)
    add_user(superconn, "k.smith")
    add_user(superconn, "d.off", enabled=False)
    add_user(superconn, "e.old", expires="now() - interval '1 hour'")
    q(superconn, "UPDATE ui.dot1x_user SET nt_hash = %s WHERE username <> 'k.smith'", (nt_hash(PW),))
    f = lambda arg: q(superconn, "SELECT radius_admin_dot1x_nt_hex(%s)", (arg,))[0][0]  # noqa: E731
    assert f(hx("j.doe")) == "off"
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('dot1x_peap', 'true')")
    assert f(hx("j.doe")) == "0x" + nt_hash(PW) and f(hx("J.DOE")) == "0x" + nt_hash(PW)
    assert f(hx("k.smith")) == "nopeap" and f(hx("d.off")) == "disabled" and f(hx("e.old")) == "expired"
    assert f(hx("nobody")) == "unknown" and f("zz") is None and f(None) is None
    # directory accounts over PEAP: not local -> the domain controller decides; local still wins
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('dot1x_peap_directory', 'true')")
    assert f(hx("nobody")) == "directory" and f(hx("k.smith")) == "nopeap" and f(hx("d.off")) == "disabled"
    q(superconn, "UPDATE ui.setting SET value='false' WHERE key='dot1x_peap_directory'")
    # only PEAP on: the VLAN function still answers for local users
    q(superconn, "INSERT INTO ui.access_rule (id, priority, connection, ad_group, vlan) VALUES (1, 10, 'wired', 'Wired-Office', 500)")
    assert q(superconn, "SELECT radius_admin_dot1x_vlan_rule_hex(%s, true, '')", (hx("j.doe"),))[0][0] == "500:1"
    rows = q(superconn, "SELECT has_function_privilege('radius_fr', 'radius_admin_dot1x_nt_hex(text)', 'EXECUTE'),"
                        " has_function_privilege('radius_admin', 'radius_admin_dot1x_nt_hex(text)', 'EXECUTE')")[0]
    assert rows == (True, False)
    with pytest.raises(Exception):
        q(superconn, "UPDATE ui.dot1x_user SET nt_hash = 'not-a-hash'")


def test_allow_peap_forms(browser, superconn, logged_in):
    from radius_admin.crypto import nt_hash
    logged_in("operator")
    form = {"username": "j.doe", "password": PW, "confirm": PW, "groups": "Wired-Office", "enabled": "1"}
    assert browser.post("/dot1x-users/new", dict(form, allow_peap="1")).status_code == 302
    assert browser.post("/dot1x-users/new", dict(form, username="k.smith")).status_code == 302
    rows = dict(q(superconn, "SELECT username, nt_hash FROM ui.dot1x_user"))
    assert rows == {"j.doe": nt_hash(PW), "k.smith": None}
    page = browser.text(browser.get("/dot1x-users/"))
    assert page.count("This user may also sign in with PEAP-MSCHAPv2") == 1 and nt_hash(PW) not in page
    jid, kid = (q(superconn, "SELECT id FROM ui.dot1x_user WHERE username=%s", (u,))[0][0] for u in ("j.doe", "k.smith"))
    # edit: allowing needs a password; unticking removes the hash
    r = browser.post("/dot1x-users/%d/edit" % kid, {"groups": "Wired-Office", "enabled": "1", "allow_peap": "1"})
    assert r.status_code == 400 and "set a new password" in browser.text(r)
    assert nt_hash(PW) not in browser.text(browser.get("/dot1x-users/%d/edit" % jid))
    assert browser.post("/dot1x-users/%d/edit" % jid, {"groups": "Wired-Office", "enabled": "1"}).status_code == 302
    assert q(superconn, "SELECT nt_hash FROM ui.dot1x_user WHERE id=%s", (jid,))[0][0] is None
    # a new password with the box ticked stores the new hash
    r = browser.post("/dot1x-users/%d/password" % kid, {"password": PW + "-2", "confirm": PW + "-2", "allow_peap": "1"})
    assert r.status_code == 302
    assert q(superconn, "SELECT nt_hash FROM ui.dot1x_user WHERE id=%s", (kid,))[0][0] == nt_hash(PW + "-2")
    acts = q(superconn, "SELECT action, detail::text FROM ui.audit_log WHERE action LIKE 'dot1x_user.%%' ORDER BY id")
    assert [json.loads(d).get("peap") for _, d in acts if d] == [True, False, {"from": True, "to": False}, True]
    dump = " ".join(d or "" for _, d in acts)
    assert nt_hash(PW) not in dump and nt_hash(PW + "-2") not in dump


def test_peap_setting_and_fips_mode(app, browser, superconn, logged_in):
    from radius_admin.services import fips_peap_off
    u = logged_in("admin")
    stepup(browser, superconn, u)
    form = {"admin_subnet": "192.0.2.0/24", "banner_text": "Authorized use only. Testing banner text."}
    assert "Also allow PEAP" in browser.text(browser.get("/settings"))
    browser.post("/settings", dict(form, dot1x_peap="1"))
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='dot1x_peap'") == [("true",)]
    assert "Allow PEAP" in browser.text(browser.get("/dot1x-users/new"))
    t = browser.text(browser.get("/settings"))
    assert "directory accounts over PEAP" in t and "deploy/ad-join.sh" in t
    browser.post("/settings", dict(form, dot1x_peap="1", dot1x_peap_directory="1"))
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='dot1x_peap_directory'") == [("true",)]
    assert "Directory accounts are accepted" in browser.text(browser.get("/dot1x-users/"))
    browser.post("/settings", dict(form, dot1x_peap="1"))
    # FIPS mode: no PEAP anywhere, refused when posted, switched off at start-up
    app.config["RA"]["require_fips"] = True
    assert "PEAP" not in browser.text(browser.get("/settings"))
    assert "PEAP" not in browser.text(browser.get("/dot1x-users/new"))
    q(superconn, "UPDATE ui.setting SET value='false' WHERE key='dot1x_peap'")
    browser.post("/settings", dict(form, dot1x_peap="1"))
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='dot1x_peap'") == [("false",)]
    r = browser.post("/dot1x-users/new", {"username": "f.user", "password": PW, "confirm": PW, "groups": "G",
                                          "enabled": "1", "allow_peap": "1"})
    assert r.status_code == 302 and q(superconn, "SELECT nt_hash FROM ui.dot1x_user")[0][0] is None
    q(superconn, "UPDATE ui.setting SET value='true' WHERE key='dot1x_peap'")
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('dot1x_peap_directory', 'true')"
                 " ON CONFLICT (key) DO UPDATE SET value='true'")
    fips_peap_off(app.config["RA"]["db_dsn"])
    assert q(superconn, "SELECT key, value FROM ui.setting WHERE key LIKE 'dot1x_peap%%' ORDER BY key") == [
        ("dot1x_peap", "false"), ("dot1x_peap_directory", "false")]
    actor, detail = q(superconn, "SELECT actor, detail::text FROM ui.audit_log ORDER BY id DESC LIMIT 1")[0]
    assert actor == "system:fips" and set(json.loads(detail)) == {"dot1x_peap", "dot1x_peap_directory"}
    fips_peap_off(app.config["RA"]["db_dsn"])          # nothing to do: no second record
    assert q(superconn, "SELECT count(*) FROM ui.audit_log WHERE actor='system:fips'")[0][0] == 1


def test_peap_hints_and_log(browser, superconn, logged_in):
    from radius_admin import insight
    for reason, want in (("username and password sign-in with PEAP is turned off", "PEAP is turned off"),
                         ("PEAP is not allowed for this 802.1X user", "Allow PEAP ticked"),
                         ("only EAP-MSCHAPv2 is accepted inside PEAP", "EAP-MSCHAPv2")):
        assert want in insight.reason_hint("radius-admin: " + reason), reason
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, vlan, authdate) VALUES"
                 " ('j.doe', 'Access-Accept', 'peap', '500', now())")
    logged_in("viewer")
    assert "j.doe" in browser.text(browser.get("/auth-log?method=peap"))
    assert "PEAP-MSCHAPv2, local user" in browser.text(browser.get("/auth-log/1"))


def test_peap_policy_contract(policy):
    pa = policy[policy.index("radius_admin_peap_authorize {"):policy.index("radius_admin_peap_postauth {")]
    assert "%{sql:SELECT radius_admin_dot1x_nt_hex('%{hex:User-Name}')}" in pa
    assert "&control:Tmp-String-0 =~ /^0x[0-9a-f]{32}$/" in pa and '&NT-Password := "%{control:Tmp-String-0}"' in pa
    assert "radcheck" not in pa and "SQL-Group" not in pa and pa.count("\treject\n") == 2
    post = policy[policy.index("radius_admin_peap_postauth {"):]
    post = post[:post.index("}\n\n") + 2]
    assert "update outer.session-state" in post and '&Tmp-String-1 := "peap"' in post
    rej = policy[policy.index("radius_admin_reject {"):]
    rej = rej[:rej.index("\n}\n") + 3]
    assert "&session-state:Tmp-String-4 =~ /^(ttls-pap|ttls-ldap|peap|peap-ldap)$/" in rej and "!&control:Tmp-String-1" in rej
    ttls = policy[policy.index("# 802.1X with a username and password"):policy.index("# 802.1X EAP-TLS")]
    assert '&session-state:Tmp-String-1 == "peap"' in ttls
    assert '(&control:Tmp-String-1 == "ttls-pap" || &control:Tmp-String-1 == "peap")' in ttls


# ------------------------------------------------------------------ PEAP with directory accounts (SPEC section 21)
def test_peap_directory_policy_contract(policy):
    pa = policy[policy.index("radius_admin_peap_authorize {"):policy.index("radius_admin_peap_postauth {")]
    local = pa[pa.index("=~ /^0x[0-9a-f]{32}$/"):pa.index('== \"directory\"') if '== \"directory\"' in pa else pa.index('"directory")')]
    assert "&MS-CHAP-Use-NTLM-Auth := No" in local          # local users never reach the domain controller
    d = pa[pa.index('&control:Tmp-String-0 == "directory")'):pa.index("\telse {", pa.index('== "directory")'))]
    assert '&Tmp-String-1 := "peap-ldap"' in d and "reject" not in d and "NT-Password" not in d
    post = policy[policy.index("radius_admin_peap_postauth {"):policy.index("radius_admin_postauth {")]
    assert '&Tmp-String-1 := "peap-ldap"' in post and "%{hex:control:Tmp-String-9[0]}" in post
    ttls = policy[policy.index("# 802.1X with a username and password"):policy.index("# 802.1X EAP-TLS")]
    assert '&session-state:Tmp-String-1 == "peap-ldap"' in ttls
    assert '(&control:Tmp-String-1 == "ttls-ldap" || &control:Tmp-String-1 == "peap-ldap") && "%{control:Tmp-String-3}"' in ttls
    assert "/^(ttls-pap|ttls-ldap|peap|peap-ldap)$/" in policy


def test_peap_directory_freeradius_files():
    import os
    fr = os.path.join(os.path.dirname(__file__), "..", "..", "freeradius")
    mschap = open(os.path.join(fr, "mods-available", "mschap")).read()
    lines = [ln.strip() for ln in mschap.splitlines() if ln.strip().startswith("ntlm_auth =")]
    assert lines == ['ntlm_auth = "/usr/bin/ntlm_auth --request-nt-key --allow-mschapv2 --username=%{%{mschap:User-Name}:-None}'
                     ' --challenge=%{%{mschap:Challenge}:-00} --nt-response=%{%{mschap:NT-Response}:-00}"']
    site = open(os.path.join(fr, "sites-available", "radius-admin-peap")).read()
    assert '&Stripped-User-Name := "%{mschap:User-Name}"' in site and "ldap_user" in site
    assert site.index("ldap_user") < site.index("radius_admin_inner_eap {")
    ldap = open(os.path.join(fr, "mods-available", "ldap")).read()
    assert "sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}}" in ldap


def test_peap_directory_label(browser, superconn, logged_in):
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, vlan, authdate) VALUES"
                 " ('jroe', 'Access-Accept', 'peap-ldap', '500', now())")
    logged_in("viewer")
    assert "jroe" in browser.text(browser.get("/auth-log?method=peap-ldap"))
    t = browser.text(browser.get("/auth-log/1"))
    assert "PEAP-MSCHAPv2, directory account" in t and "Directory groups seen" in t

