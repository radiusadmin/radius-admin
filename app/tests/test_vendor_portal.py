"""Custom device profiles in the portal (SPEC section 26): list, create by copying, edit,
delete, JSON export and import, and their use by clients, Apply, the sessions page and the
CSV import."""
import html
import io
import json
import re

import pytest

from conftest import BASE_URL, ORIGIN
from test_client_import import do_import
from test_operations import _client, _session, q
from test_vendor_clients import _render

GENERIC = "generic-rfc"


def _form_of(browser, path):
    """The profile form's fields as the page shows them (text, textareas, selects, checkboxes)."""
    t = browser.text(browser.get(path))
    f = {}
    for name, value in re.findall(r'<input id="[^"]+" name="([^"]+)" value="([^"]*)"', t):
        f[name] = value.replace("&amp;", "&").replace("&#34;", '"').replace("&#39;", "'")
    for name, value in re.findall(r'<textarea id="[^"]+" name="([^"]+)"[^>]*>([^<]*)</textarea>', t):
        f[name] = value.replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&").replace("&#39;", "'")
    for name, body in re.findall(r'<select id="[^"]+" name="([^"]+)"[^>]*>(.*?)</select>', t, re.S):
        m = re.search(r'<option value="([^"]*)" selected', body)
        f[name] = m.group(1) if m else ""
    for name in re.findall(r'<input type="checkbox" name="([^"]+)" value="1" checked', t):
        f[name] = "1"
    return f


def _create(browser, base=GENERIC, **changes):
    f = _form_of(browser, "/profiles/new?from=" + base)
    f.update(changes)
    return browser.post("/profiles/new", f, csrf_page="/profiles/new?from=" + base)


def _doc(superconn, pid):
    rows = q(superconn, "SELECT doc FROM ui.vendor_profile WHERE id = %s", (pid,))
    return rows[0][0] if rows else None


ARUBA = {"id": "aruba-cx", "label": "Aruba CX (lab)",
         "reply_admin": "Aruba-Admin-Role := root", "reply_role": "Aruba-User-Role := {role}"}


# ----------------------------------------------------------------------- list and built-in profiles
def test_list_and_builtin_profiles_are_read_only(app, browser, superconn, logged_in):
    logged_in("viewer")
    t = browser.text(browser.get("/profiles/"))
    assert "Device profiles" in t and "Cisco Catalyst 1200/1300" in t and "Generic (RFC standard attributes)" in t
    assert t.count('<span class="tag tag-ok">Built-in</span>') == 2 and "tested on hardware" not in t
    assert "New profile" not in t and "Import JSON" not in t and "Export JSON" in t
    links = re.findall(r'href="(https://github.com/[^"]+)"', t)
    assert len(links) == 2 and all("/radiusadmin/radius-admin/issues/new?template=device-profile.yml&amp;" in u
                                   for u in links)
    assert "profile=cisco-c1300" in links[0] + links[1] and "profile=generic-rfc" in links[0] + links[1]
    t = browser.text(browser.get("/profiles/cisco-c1300"))
    assert "Cisco-AVPair += shell:priv-lvl=15" in t and " disabled" in t and "Save profile" not in t
    assert browser.get("/profiles/no-such").status_code == 404
    browser.c = browser.app.test_client()
    logged_in("admin")
    t = browser.text(browser.get("/profiles/cisco-c1300"))
    assert "Built-in profiles cannot be changed" in t and "Copy to a new profile" in t
    r = browser.post("/profiles/cisco-c1300", {"label": "x"}, csrf_page="/profiles/cisco-c1300")
    assert r.status_code == 403
    for path in ("/profiles/new", "/profiles/import"):
        browser.c = browser.app.test_client()
        logged_in("operator", username="op-" + path[-3:])
        assert browser.get(path).status_code == 403


# ----------------------------------------------------------------------- create, edit, delete
def test_create_a_profile_by_copying(app, browser, superconn, logged_in, monkeypatch):
    from radius_admin.views import profiles
    monkeypatch.setattr(profiles, "_dictionary", lambda: None)          # no dictionary check here
    logged_in("admin")
    f = _form_of(browser, "/profiles/new?from=" + GENERIC)
    assert f["id"] == "" and f["label"] == "Generic (RFC standard attributes) (copy)"
    assert f["reply_vlan"].splitlines()[0] == "Tunnel-Type := VLAN" and f["mab_wireless"] == "1"
    r = _create(browser, **ARUBA)
    assert r.status_code == 302 and r.headers["Location"].endswith("/profiles/aruba-cx"), browser.text(r)[:2000]
    doc = _doc(superconn, "aruba-cx")
    assert doc["status"] == "unverified" and doc["reply"]["role"] == [
        {"attr": "Aruba-User-Role", "op": ":=", "value": "{role}"}]
    assert doc["coa"]["disconnect"] == {"packet": "disconnect", "attrs": []} and doc["coa"]["bounce"] is None
    a = q(superconn, "SELECT object_id, detail->>'label' FROM ui.audit_log WHERE action = 'profile.create'")
    assert a == [("aruba-cx", "Aruba CX (lab)")]
    t = browser.text(browser.get(r.headers["Location"]))
    assert "Choose it for a client" in t and "Custom profile" in t
    assert "Aruba CX (lab)" in browser.text(browser.get("/profiles/"))


@pytest.mark.parametrize("changes,field_message", [
    ({"id": "cisco-c1300"}, "is the id of a built-in profile"),
    ({"id": "Bad Id"}, "id: 1-32 lower-case letters"),
    ({"reply_admin": "Exec-Program := /bin/sh"}, "Exec-Program cannot be set by a vendor profile"),
    ({"reply_vlan": "Tunnel-Type := VLAN"}, "must place {vlan} in one attribute"),
    ({"reply_vlan": "Tunnel-Type = VLAN"}, "Line 1: write Attribute := value"),
    ({"reply_role": 'Filter-Id := x"y'}, "values are 1-247 printable characters"),
    ({"coa_port": "0"}, "a UDP port from 1 to 65535"),
    ({"coa_bounce_attrs": "HP-Bounce = 1"}, "Choose a packet type, or remove the attributes."),
    ({"port_rules": "no arrow here"}, "Line 1: write regular-expression => format."),
    ({"port_rules": "( => x"}, "not a valid regular expression"),
    ({"mab_ethernet": "", "mab_wireless": ""}, "mab.port_types"),
])
def test_create_refuses_bad_input(app, browser, superconn, logged_in, monkeypatch, changes, field_message):
    from radius_admin.views import profiles
    monkeypatch.setattr(profiles, "_dictionary", lambda: None)
    logged_in("admin")
    f = _form_of(browser, "/profiles/new?from=" + GENERIC)
    f.update(dict(ARUBA, **changes))
    f = {k: v for k, v in f.items() if v != ""}         # unticked boxes are not sent
    r = browser.post("/profiles/new", f, csrf_page="/profiles/new")
    assert r.status_code == 400 and field_message in html.unescape(browser.text(r)), browser.text(r)[-3000:]
    assert not q(superconn, "SELECT 1 FROM ui.vendor_profile")
    assert q(superconn, "SELECT success FROM ui.audit_log WHERE action = 'profile.create'") == [(False,)]


def test_dictionary_check(app, browser, superconn, logged_in, monkeypatch):
    from radius_admin.views import profiles
    monkeypatch.setattr(profiles, "_dictionary", lambda: {"tunnel-type", "tunnel-medium-type", "tunnel-private-group-id",
                                                          "service-type", "aruba-admin-role"})
    logged_in("admin")
    r = _create(browser, **ARUBA)
    assert r.status_code == 400
    assert "Aruba-User-Role is not an attribute in this server&#39;s FreeRADIUS dictionary" in browser.text(r)


def test_edit_and_delete(app, browser, superconn, logged_in, monkeypatch):
    from radius_admin.views import profiles
    monkeypatch.setattr(profiles, "_dictionary", lambda: None)
    logged_in("admin")
    assert _create(browser, **ARUBA).status_code == 302
    f = _form_of(browser, "/profiles/aruba-cx")
    assert f["reply_admin"] == "Aruba-Admin-Role := root"
    f["reply_admin"] = "Aruba-Admin-Role := read-only"
    f["id"] = "renamed"                                  # ignored: the id cannot change
    r = browser.post("/profiles/aruba-cx", f, csrf_page="/profiles/aruba-cx")
    assert r.status_code == 302 and _doc(superconn, "aruba-cx")["reply"]["admin_full"][0]["value"] == "read-only"
    assert not _doc(superconn, "renamed")
    r = browser.post("/profiles/aruba-cx", f, csrf_page="/profiles/aruba-cx")
    assert "No changes." in browser.text(browser.get(r.headers["Location"]))
    d = q(superconn, "SELECT detail FROM ui.audit_log WHERE action = 'profile.update' AND success")[0][0]
    assert d["sha256"] != d["sha256_before"] and d["clients"] == 0
    # in use: not deleted
    cid = _client(superconn)
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = 'aruba-cx' WHERE id = %s", (cid,))
    r = browser.post("/profiles/aruba-cx/delete", {}, csrf_page="/profiles/")
    assert "1 client uses it" in browser.text(browser.get(r.headers["Location"])) and _doc(superconn, "aruba-cx")
    q(superconn, "UPDATE ui.radius_client SET vendor_profile = NULL")
    q(superconn, "INSERT INTO ui.setting (key, value) VALUES ('default_vendor_profile', 'aruba-cx')")
    r = browser.post("/profiles/aruba-cx/delete", {}, csrf_page="/profiles/")
    assert "it is the default profile" in browser.text(browser.get(r.headers["Location"]))
    q(superconn, "DELETE FROM ui.setting WHERE key = 'default_vendor_profile'")
    r = browser.post("/profiles/aruba-cx/delete", {}, csrf_page="/profiles/")
    assert r.status_code == 302 and not _doc(superconn, "aruba-cx")
    assert browser.post("/profiles/cisco-c1300/delete", {}, csrf_page="/profiles/").status_code == 404
    assert q(superconn, "SELECT success FROM ui.audit_log WHERE action = 'profile.delete' ORDER BY id") == [
        (False,), (False,), (True,)]


# ----------------------------------------------------------------------- export and import
def test_export_and_import(app, browser, superconn, logged_in, monkeypatch):
    from radius_admin import vendors
    from radius_admin.views import profiles
    monkeypatch.setattr(profiles, "_dictionary", lambda: None)
    logged_in("admin")
    r = browser.get("/profiles/generic-rfc/export")
    assert r.status_code == 200 and r.mimetype == "application/json"
    assert 'filename="generic-rfc.radius-admin-profile.json"' in r.headers["Content-Disposition"]
    doc = json.loads(r.get_data(as_text=True))
    assert vendors.validate(doc) == vendors.builtin(GENERIC)
    assert q(superconn, "SELECT object_id FROM ui.audit_log WHERE action = 'profile.export'") == [("generic-rfc",)]

    def imp(text, **extra):
        return browser.post("/profiles/import", dict({"json": text}, **extra), csrf_page="/profiles/import")

    r = imp(json.dumps(doc))
    assert r.status_code == 400 and "is the id of a built-in profile" in browser.text(r)
    doc.update(id="lab-ap", label="Lab AP", status="supported")
    r = imp(json.dumps(doc))
    assert r.status_code == 302 and _doc(superconn, "lab-ap")["status"] == "unverified"   # never marked tested
    r = imp(json.dumps(dict(doc, label="Lab AP v2")))
    assert r.status_code == 400 and "Tick “Replace”" in browser.text(r)
    r = imp(json.dumps(dict(doc, label="Lab AP v2")), replace="1")
    assert r.status_code == 302 and _doc(superconn, "lab-ap")["label"] == "Lab AP v2"
    for bad, message in (("{", "Not a usable profile"), ("[]", "Not a usable profile"),
                         (json.dumps(dict(doc, id="x2", extra=1)), "unknown field"),
                         (json.dumps(dict(doc, id="x3", reply={"vlan": [], "admin_full": []})), "reply.vlan"),
                         ("x" * (64 * 1024 + 1), "larger than 64 KiB")):
        r = imp(bad)
        assert r.status_code == 400 and message in browser.text(r), message
    # a file upload works too
    tok = browser.csrf_from("/profiles/import")
    up = json.dumps(dict(doc, id="lab-ap-file")).encode()
    r = browser.c.post("/profiles/import", base_url=BASE_URL, content_type="multipart/form-data",
                       headers={"Origin": ORIGIN, "X-Real-IP": browser.ip},
                       data={"csrf_token": tok, "file": (io.BytesIO(up), "lab.json")})
    assert r.status_code == 302, r.get_data(as_text=True)[:2000]
    assert _doc(superconn, "lab-ap-file")
    acts = q(superconn, "SELECT success, detail->>'replaced' FROM ui.audit_log WHERE action = 'profile.import' AND success"
                        " ORDER BY id")
    assert acts == [(True, "false"), (True, "true"), (True, "false")]


def test_a_stored_profile_that_no_longer_validates_is_left_out(app, superconn):
    from radius_admin import vendors
    good = dict(vendors.builtin(GENERIC), id="ok-one", status="unverified")
    bad = dict(good, id="bad-one", reply={"vlan": [], "admin_full": []})
    for d in (good, bad):
        q(superconn, "INSERT INTO ui.vendor_profile (id, doc) VALUES (%s, %s::jsonb)", (d["id"], json.dumps(d)))
    with app.app_context():
        cat = vendors.catalog()
    assert "ok-one" in cat and "bad-one" not in cat and "cisco-c1300" in cat


# ----------------------------------------------------------------------- custom profiles in use
def test_clients_and_apply_use_a_custom_profile(app, browser, superconn, logged_in, monkeypatch):
    from radius_admin.views import profiles
    monkeypatch.setattr(profiles, "_dictionary", lambda: None)
    logged_in("admin")
    assert _create(browser, **dict(ARUBA, coa_bounce_packet="", coa_reauth_packet="coa",
                                   coa_reauth_attrs="Aruba-Port-Bounce-Host = 1")).status_code == 302
    cid = _client(superconn)
    t = browser.text(browser.get("/clients/%d/edit" % cid))
    assert '<option value="aruba-cx"' in t and "Aruba CX (lab) (custom)" in t
    r = browser.post("/clients/%d/edit" % cid, {"name": "sw1", "ipaddr": "192.0.2.10", "secret_mode": "keep",
                                                 "enabled": "1", "vendor_profile": "aruba-cx"},
                     csrf_page="/clients/%d/edit" % cid)
    assert r.status_code == 302 and q(superconn, "SELECT vendor_profile FROM ui.radius_client") == [("aruba-cx",)]
    policy, clients = _render(app)
    assert "radius_admin_profile = aruba-cx" in clients
    assert '"%{client:radius_admin_profile}" == "aruba-cx"' in policy
    assert "&Aruba-Admin-Role := root" in policy and "&Aruba-User-Role := &control:Tmp-String-4" in policy
    t = browser.text(browser.get("/profiles/aruba-cx"))
    assert "used by 1 client" in t
    # the sessions page offers what the custom profile has
    sid = _session(superconn)
    row = re.search(r'data-session="%d">(.*?)</tr>' % sid, browser.text(browser.get("/sessions/")), re.S).group(1)
    assert "Re-authenticate" in row and "Bounce port" not in row and "Disconnect" in row
    # the default can be a custom profile
    r = browser.post("/settings", {"admin_subnet": "192.0.2.0/24", "banner_text": "This system is for authorized use only.",
                                   "default_vendor_profile": "aruba-cx"})
    assert r.status_code == 302
    assert q(superconn, "SELECT value FROM ui.setting WHERE key = 'default_vendor_profile'") == [("aruba-cx",)]
    # and the CSV import accepts its id
    do_import(browser, "ip,secret,hostname,secret_type,vendor_profile\r\n"
                       "192.0.2.41,Example-Plaintext-Key-0041,sw-41,plaintext,aruba-cx\r\n")
    assert q(superconn, "SELECT vendor_profile FROM ui.radius_client WHERE name = 'sw-41'") == [("aruba-cx",)]


def test_report_a_problem_only_for_builtin_profiles(app, browser, superconn, logged_in, monkeypatch):
    from radius_admin.views import profiles
    monkeypatch.setattr(profiles, "_dictionary", lambda: None)
    logged_in("admin")
    t = browser.text(browser.get("/profiles/generic-rfc"))
    m = re.search(r'<a class="btn btn-quiet" href="(https://github.com/[^"]+)" target="_blank" rel="noopener noreferrer">'
                  r'Report a problem', t)
    assert m and "title=Device+profile+generic-rfc%3A+" in m.group(1) and "&amp;version=" in m.group(1)
    assert "do not include secrets, host names or addresses" in t
    assert _create(browser, **ARUBA).status_code == 302
    t = browser.text(browser.get("/profiles/aruba-cx"))
    assert "Report a problem" not in t and "github.com" not in t
    assert browser.text(browser.get("/profiles/")).count("Report a problem<span") == 2
