"""Device admins (formerly switch admins) with directory accounts (SPEC section 28): the SQL
functions FreeRADIUS calls, the generated policy, the settings, the page and its old address."""
import json
import os

import psycopg2
import pytest

from conftest import SUPER_DSN, stepup


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def h(text):
    return text.encode().hex()


def groups_hex(*names):
    return "".join("," + h(n) for n in names)


def set_dir(superconn, on, groups=""):
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('admin_directory', %s), ('admin_directory_groups', %s)"
                 " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", ("true" if on else "false", groups))


def directory_hex(superconn, arg):
    return q(superconn, "SELECT radius_admin_admin_directory_hex(%s)", (arg,))[0][0]


def group_hex(superconn, arg):
    return q(superconn, "SELECT radius_admin_admin_group_hex(%s)", (arg,))[0][0]


SETTINGS_FORM = {"admin_subnet": "192.0.2.0/24", "banner_text": "Authorized use only. Testing banner text."}


# ------------------------------------------------------------------ SQL
def test_directory_hex_off_by_default_and_needs_groups(superconn, clean_db):
    assert directory_hex(superconn, h("jroe")) == "off"            # setting missing
    set_dir(superconn, False, "Network-Admins")
    assert directory_hex(superconn, h("jroe")) == "off"
    set_dir(superconn, True, "")
    assert directory_hex(superconn, h("jroe")) == "off"            # on, but no group configured
    set_dir(superconn, True, " \n\n  ")
    assert directory_hex(superconn, h("jroe")) == "off"
    set_dir(superconn, True, "Network-Admins")
    assert directory_hex(superconn, h("jroe")) == "directory"
    assert directory_hex(superconn, h("jroe@example.net")) == "directory"


def test_directory_hex_local_account_wins(superconn, clean_db):
    set_dir(superconn, True, "Network-Admins")
    q(superconn, "INSERT INTO radcheck (username, attribute, op, value) VALUES ('netops1','Password-With-Header',':=','x')")
    q(superconn, "INSERT INTO radusergroup (username, groupname, priority) VALUES ('helper1','helpdesk',1)")
    assert directory_hex(superconn, h("netops1")) == "local"
    assert directory_hex(superconn, h("NetOps1")) == "local"       # case-insensitive, like the directory
    assert directory_hex(superconn, h("helper1")) == "local"       # any local row, even outside net-admins
    set_dir(superconn, False)
    assert directory_hex(superconn, h("netops1")) == "local"


@pytest.mark.parametrize("bad", [None, "", "a", "zz", "6a72oe", "'; DROP TABLE radcheck; --", "00" * 254,
                                 h("x") + "'", "6a\\27"])
def test_directory_hex_rejects_malformed(superconn, clean_db, bad):
    set_dir(superconn, True, "Network-Admins")
    assert directory_hex(superconn, bad) is None


@pytest.mark.parametrize("payload", ["x' OR '1'='1", "x'); DELETE FROM radcheck; --", "\\047 OR 1=1 --",
                                     "%{User-Password}", "a\nb"])
def test_directory_hex_injection_is_inert(superconn, clean_db, payload):
    set_dir(superconn, True, "Network-Admins")
    q(superconn, "INSERT INTO radcheck (username, attribute, op, value) VALUES ('netops1','Password-With-Header',':=','x')")
    assert directory_hex(superconn, h(payload)) == "directory"     # just a name nobody has locally
    assert q(superconn, "SELECT count(*) FROM radcheck")[0][0] == 1


def test_group_hex_matching(superconn, clean_db):
    set_dir(superconn, True, "Network-Admins\nFirewall Ops\n")
    assert group_hex(superconn, groups_hex("Domain Users", "network-admins")) is True    # case-insensitive
    assert group_hex(superconn, groups_hex("FIREWALL OPS")) is True
    assert group_hex(superconn, groups_hex("Domain Users", "Network-Admins-Old")) is False
    assert group_hex(superconn, "") is False                                            # no groups at all
    assert group_hex(superconn, "x") is False                                           # too-long group marker
    assert group_hex(superconn, groups_hex("Network-Admins") + ",zz") is False          # malformed item
    assert group_hex(superconn, None) is False
    set_dir(superconn, False, "Network-Admins")
    assert group_hex(superconn, groups_hex("Network-Admins")) is False                  # turned off
    set_dir(superconn, True, "")
    assert group_hex(superconn, groups_hex("Network-Admins")) is False                  # nothing configured


@pytest.mark.parametrize("name", ["Guests,Network-Admins", "Network-Admins' OR '1'='1", "Network-Admins\n",
                                  " Network-Admins", "Network-Admins)(cn=*"])
def test_group_hex_needs_the_exact_name(superconn, clean_db, name):
    # a comma, quote or blank inside a directory group name never makes it match another group
    set_dir(superconn, True, "Network-Admins")
    assert group_hex(superconn, groups_hex(name)) is False


def test_functions_granted_to_freeradius_only(superconn, clean_db):
    def can(role, fn):
        return q(superconn, "SELECT has_function_privilege(%s, %s, 'EXECUTE')", (role, fn))[0][0]
    for fn in ("radius_admin_admin_directory_hex(text)", "radius_admin_admin_group_hex(text)"):
        assert can("radius_fr", fn) and not can("radius_admin", fn), fn
    assert not can("radius_fr", "radius_admin_admin_directory_groups()")
    assert not can("radius_admin", "radius_admin_admin_directory_groups()")


def test_migration_is_idempotent_and_keeps_settings(superconn, clean_db):
    set_dir(superconn, True, "Network-Admins")
    path = os.path.join(os.path.dirname(__file__), "..", "..", "sql", "100-device-admins.sql")
    sql = open(path).read()
    conn = psycopg2.connect(SUPER_DSN)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            assert cur.fetchone()[0] == q(superconn, "SELECT current_database()")[0][0]
            cur.execute(sql)
            cur.execute(sql)
    finally:
        conn.close()
    assert q(superconn, "SELECT key, value FROM ui.setting WHERE key LIKE 'admin_directory%%' ORDER BY key") == [
        ("admin_directory", "true"), ("admin_directory_groups", "Network-Admins")]


# ------------------------------------------------------------------ policy
def _policy():
    from radius_admin import unlang
    return unlang.render_policy()


def test_policy_authorize_asks_the_directory_only_after_the_subnet():
    p = _policy()
    a = p[p.index("radius_admin_admin_authorize {"):p.index("radius_admin_inner_authorize {")]
    # the user name reaches SQL only as hex
    assert "radius_admin_admin_directory_hex('%{hex:User-Name}')" in a
    assert "'%{User-Name}'" not in a
    assert a.index("radius_admin_admin_source_ok_hex") < a.index("ldap_user\n") < a.index("&Auth-Type := ldap_user")
    assert '&Tmp-String-1 := "admin-ldap"' in a
    assert "!&EAP-Message && (!&NAS-Port-Type || &NAS-Port-Type != Ethernet) && !&Called-Station-Id" in a
    assert "&User-Password" in a and "!&control:Auth-Type" in a
    assert "&Tmp-String-9 += &control:ldap_user-LDAP-Group[*]" in a
    assert a.count("reject\n") == 3      # outside the subnet, not in the directory, directory unreachable


def test_policy_postauth_requires_a_directory_group():
    p = _policy()
    adm = p[p.index("# Device admin logins"):p.index("# 802.1X with a username and password")]
    d = adm[adm.index('elsif (&control:Tmp-String-1 == "admin-ldap")'):adm.index('elsif (SQL-Group == "net-admins")')]
    assert "radius_admin_admin_group_hex('%{control:Tmp-String-3}')" in d
    assert '"%{control:Tmp-String-3}" =~ /^(,[0-9a-f]+)*$/' in d
    assert "%{hex:control:Tmp-String-9[0]}" in d
    assert "not in a device admin group" in d
    assert '&Cisco-AVPair += "shell:priv-lvl=15"' in d
    # the subnet check comes before either kind of account
    assert adm.index("outside the management subnet") < adm.index('elsif (&control:Tmp-String-1 == "admin-ldap")')
    # a local login never inherits the directory marker, and the marker is only kept, not set here
    assert 'if (!&control:Tmp-String-1 || &control:Tmp-String-1 != "admin-ldap")' in adm


def test_policy_reject_names_a_refused_directory_password():
    p = _policy()
    r = p[p.index("radius_admin_reject {"):p.index("radius_admin_peap_authorize {")]
    assert ('&control:Tmp-String-1 == "admin-ldap" && (!&Module-Failure-Message || '
            '&Module-Failure-Message =~ /(Bind credentials incorrect|Invalid credentials)/)') in r
    assert "the directory refused the password" in r


def test_default_site_calls_the_policy_and_has_auth_type_ldap_user():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "freeradius", "sites-available", "default")
    text = open(path).read()
    authz = text[text.index("\nauthorize {"):text.index("\nauthenticate {")]
    auth = text[text.index("\nauthenticate {"):text.index("\npreacct {")]
    assert authz.index("-sql\n") < authz.index("radius_admin_admin_authorize\n") < authz.index("\tpap\n")
    assert "Auth-Type ldap_user {\n\t\tldap_user\n\t}" in auth


# ------------------------------------------------------------------ settings
def test_settings_directory_accounts_admin_only_audited(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    page = browser.text(browser.get("/settings"))
    assert "Device admin logins" in page and "Directory groups allowed to log in" in page
    # on without a group: refused
    r = browser.post("/settings", dict(SETTINGS_FORM, admin_directory="1", admin_directory_groups=" \r\n"))
    assert r.status_code == 400 and "at least one directory group" in browser.text(r)
    assert q(superconn, "SELECT count(*) FROM ui.setting WHERE key LIKE 'admin_directory%%'")[0][0] == 0
    # invalid group name: refused
    r = browser.post("/settings", dict(SETTINGS_FORM, admin_directory="1", admin_directory_groups="Ops\r\nbad;name"))
    assert r.status_code == 400 and "bad;name" in browser.text(r)
    # accepted: trimmed, blank lines dropped, duplicates (any case) once
    r = browser.post("/settings", dict(SETTINGS_FORM, admin_directory="1",
                                       admin_directory_groups=" Network-Admins \r\n\r\nFirewall Ops\r\nnetwork-admins"))
    assert r.status_code == 302
    assert q(superconn, "SELECT key, value FROM ui.setting WHERE key LIKE 'admin_directory%%' ORDER BY key") == [
        ("admin_directory", "true"), ("admin_directory_groups", "Network-Admins\nFirewall Ops")]
    assert directory_hex(superconn, h("jroe")) == "directory"
    page = browser.text(browser.get("/settings"))
    assert "Network-Admins\nFirewall Ops" in page
    # off again; the groups are kept for later
    browser.post("/settings", dict(SETTINGS_FORM, admin_directory_groups="Network-Admins\r\nFirewall Ops"))
    assert q(superconn, "SELECT value FROM ui.setting WHERE key='admin_directory'") == [("false",)]
    assert directory_hex(superconn, h("jroe")) == "off"
    details = [json.loads(d) for (d,) in q(superconn, "SELECT detail::text FROM ui.audit_log"
                                                      " WHERE action='settings.update' ORDER BY id")]
    assert [d["admin_directory"]["to"] for d in details if "admin_directory" in d] == [True, False]
    assert [d["admin_directory_groups"]["to"] for d in details if "admin_directory_groups" in d] == [
        ["Network-Admins", "Firewall Ops"]]


def test_settings_too_many_groups(browser, superconn, logged_in):
    u = logged_in("admin")
    stepup(browser, superconn, u)
    many = "\n".join("Group-%d" % i for i in range(51))
    r = browser.post("/settings", dict(SETTINGS_FORM, admin_directory="1", admin_directory_groups=many))
    assert r.status_code == 400 and "at most 50" in browser.text(r)


def test_settings_forbidden_for_operator(browser, superconn, logged_in):
    logged_in("operator")
    tok = browser.csrf_from("/dashboard")
    r = browser.post("/settings", dict(SETTINGS_FORM, admin_directory="1", admin_directory_groups="Ops"), csrf=tok)
    assert r.status_code == 403
    assert q(superconn, "SELECT count(*) FROM ui.setting WHERE key LIKE 'admin_directory%%'")[0][0] == 0


# ------------------------------------------------------------------ page, rename, old address
def test_device_admins_page_shows_directory_state(browser, superconn, logged_in):
    logged_in("viewer")
    t = browser.text(browser.get("/device-admins/"))
    assert "Device admins" in t and "Only the local accounts below can log in." in t
    assert "Switch admin" not in t
    set_dir(superconn, True, "Network-Admins\nFirewall Ops")
    t = browser.text(browser.get("/device-admins/"))
    assert "Members of" in t and "Network-Admins" in t and "Firewall Ops" in t
    assert "An admin can change this in Settings." in t
    nav = browser.text(browser.get("/dashboard"))
    assert "Device admins" in nav and "Switch admins" not in nav


def test_old_address_redirects(browser, superconn, logged_in):
    logged_in("operator")
    r = browser.get("/switch-admins/")
    assert r.status_code == 308 and r.headers["Location"].endswith("/device-admins/")
    r = browser.get("/switch-admins/new?x=1")
    assert r.status_code == 308 and r.headers["Location"].endswith("/device-admins/new?x=1")
    pw = "Device-Admin-Pass-2026"
    tok = browser.csrf_from("/device-admins/new")
    r = browser.post("/switch-admins/new", {"username": "netops2", "password": pw, "confirm": pw}, csrf=tok)
    assert r.status_code == 308 and r.headers["Location"].endswith("/device-admins/new")
    assert q(superconn, "SELECT count(*) FROM radcheck")[0][0] == 0      # the redirect itself changes nothing


def test_setup_checklist_counts_directory_groups(browser, superconn, logged_in):
    logged_in("admin")
    t = browser.text(browser.get("/setup/"))
    assert "Add device admin accounts (or accept directory accounts)" in t and "0 device admins" in t
    set_dir(superconn, True, "Network-Admins")
    assert "0 device admins, plus directory groups" in browser.text(browser.get("/setup/"))


# ------------------------------------------------------------------ logs and reports
def test_auth_log_directory_admin_login(browser, superconn, logged_in):
    from radius_admin import insight
    set_dir(superconn, True, "Network-Admins")
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, reason, ad_groups_hex, authdate) VALUES"
                 " ('jroe', 'Access-Accept', 'admin-ldap', NULL, %s, now()),"
                 " ('nogroup', 'Access-Reject', 'admin-ldap',"
                 "  'radius-admin: the directory account is not in a device admin group', %s, now())",
      (groups_hex("Domain Users", "Network-Admins"), groups_hex("Domain Users")))
    logged_in("viewer")
    assert "admin-ldap" in browser.text(browser.get("/auth-log?method=admin-ldap"))
    ok_id, rej_id = [i for (i,) in q(superconn, "SELECT id FROM radpostauth ORDER BY id")]
    t = browser.text(browser.get("/auth-log/%d" % ok_id))
    assert "Device admin login (directory account)" in t and "Device admin groups" in t
    assert 'Network-Admins <span class="tag tag-ok">allowed</span>' in t
    assert 'Domain Users <span class="tag tag-ok">' not in t
    t = browser.text(browser.get("/auth-log/%d" % rej_id))
    assert "Domain Users" in t and "tag-ok\">allowed" not in t
    assert "none of the directory groups allowed" in insight.reason_hint(
        "radius-admin: the directory account is not in a device admin group")


def test_privileged_report_lists_directory_groups(browser, superconn, logged_in):
    set_dir(superconn, True, "Network-Admins")
    u = logged_in("admin")
    stepup(browser, superconn, u)
    t = browser.text(browser.get("/reports/privileged"))
    assert "device admin directory group (RADIUS)" in t and "Network-Admins" in t
    assert "Directory accounts for device admin logins are accepted" in t
