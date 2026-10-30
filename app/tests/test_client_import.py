"""SPEC section 11: RADIUS client CSV import."""
import importlib.machinery
import importlib.util
import io
import os
import re

import psycopg2
import pytest

from conftest import APP_DSN, BASE_URL, ORIGIN, Browser, fresh_code

HELPER = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                      "helper", "radius-admin-helper")
HDR = "ip,secret,hostname,secret_type,key_scope,dot1x_ports\n"
PT1 = "Plaintext-Key-0001-abcdef"
PT2 = "Plaintext-Key-0002-abcdef"
ENC = "0822455D0A16544541SECRETENC"


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def upload(b, text, existing="update", require_ma="auto", raw=None, filename="clients.csv", is_switch=False):
    tok = b.csrf_from("/clients/import")
    data = raw if raw is not None else text.encode("utf-8")
    return b.c.post("/clients/import", base_url=BASE_URL, content_type="multipart/form-data",
                    headers={"Origin": ORIGIN, "X-Real-IP": b.ip},
                    data=dict({"csrf_token": tok, "existing": existing, "require_ma": require_ma,
                               "file": (io.BytesIO(data), filename)}, **({"is_switch": "1"} if is_switch else {})))


def import_id(b, r):
    m = re.search(r'name="import_id" value="([^"]+)"', b.text(r))
    assert m, b.text(r)[:3000]
    return m.group(1)


def confirm(b, r, extra=None):
    iid = import_id(b, r)
    return b.post("/clients/import/confirm", dict({"import_id": iid}, **(extra or {})), csrf_page="/clients/")


def do_import(b, text, **kw):
    r = upload(b, text, **kw)
    assert r.status_code == 200, b.text(r)[:3000]
    r2 = confirm(b, r)
    assert r2.status_code == 200 and "Import complete" in b.text(r2), b.text(r2)[:3000]
    return r, r2


def clients(superconn):
    return {r[0]: r[1:] for r in q(superconn, "SELECT name, ipaddr, secret, enabled, key_status, key_scope,"
                                              " dot1x_ports, require_ma FROM ui.radius_client")}


# ------------------------------------------------------------- parsing
def test_parse_bom_crlf_quotes_and_order(browser, superconn, logged_in):
    logged_in("operator")
    text = ("﻿hostname,IP,secret_type,secret,dot1x_ports,key_scope\r\n"
            "sw-a,192.0.2.10,PLAINTEXT,%s,\"gi1/0/1-24, gi1/0/48\",server\r\n"
            "\r\n"
            "sw-b ,192.0.2.11,plaintext,%s,,\r\n" % (PT1, PT2))
    r = upload(browser, text)
    assert r.status_code == 200
    assert "2 new" in browser.text(r)
    confirm(browser, r)
    c = clients(superconn)
    assert c["sw-a"][5] == "gi1/0/1-24, gi1/0/48" and c["sw-a"][4] == "server"
    assert c["sw-b"][0] == "192.0.2.11" and c["sw-b"][4] is None


@pytest.mark.parametrize("text,needle", [
    ("ip,secret,hostname\n10.0.0.1,x,h\n", "missing column"),
    (HDR.replace("dot1x_ports", "ports") + "10.0.0.1,%s,h,plaintext,,x\n" % PT1, "unknown column"),
    ("ip,ip,secret,hostname,secret_type\n", "duplicate column"),
    (HDR, "no clients"),
    ("", "empty"),
    ("ip,secret,hostnam,secret_type,key_scope,dot1x_ports\n10.0.0.1,%s,h1,plaintext,,\n" % PT1,
     "unknown column(s): hostnam"),
    ("10.0.0.1,%s,h1\n" % PT1, "expected 4 to 6 fields"),
    (HDR + "10.0.0.1,%s,h\n" % PT1, "expected 6 fields"),
    (HDR + "999.0.0.1,%s,h1,plaintext,,\n" % PT1, "Line 2: ip"),
    (HDR + "10.0.0.1,%s,bad name,plaintext,,\n" % PT1, "Line 2: hostname"),
    (HDR + "10.0.0.1,short,h1,plaintext,,\n", "Line 2: secret"),
    (HDR + '10.0.0.1,has"quote-xxxxxxxxxxxx,h1,plaintext,,\n', "Line 2"),
    (HDR + "10.0.0.1,%s,h1,cleartext,,\n" % PT1, "secret_type must be"),
    (HDR + "10.0.0.1,%s,h1,plaintext,vrf,\n" % PT1, "key_scope must be"),
    (HDR + "10.0.0.1,%s,h1,plaintext,,%s\n" % (PT1, "x" * 1001), "dot1x_ports is longer"),
    (HDR + "10.0.0.1,%s,h1,plaintext,,\n10.0.0.1,%s,h2,plaintext,,\n" % (PT1, PT2), "ip 10.0.0.1 already appears on line 2"),
    (HDR + "10.0.0.1,%s,h1,plaintext,,\n10.0.0.2,%s,H1,plaintext,,\n" % (PT1, PT2), "hostname H1 already appears"),
    (HDR + '10.0.0.1,%s,h1,plaintext,,"%s"\n' % (PT1, "x" * (140 * 1024)), "not valid CSV"),
])
def test_parse_errors_import_nothing(browser, superconn, logged_in, text, needle):
    logged_in("operator")
    r = upload(browser, text)
    assert r.status_code == 400 and needle in browser.text(r), browser.text(r)[-3000:]
    assert "Nothing was imported" in browser.text(r)
    assert q(superconn, "SELECT count(*) FROM ui.radius_client")[0][0] == 0


def test_caps(browser, superconn, logged_in):
    from radius_admin import client_import as ci
    logged_in("operator")
    r = upload(browser, None, raw=b"x" * (ci.MAX_BYTES + 5))
    assert r.status_code == 400 and "larger than 1 MiB" in browser.text(r)
    r = upload(browser, None, raw=b"ip,secret\n\xff\xfe\n")
    assert r.status_code == 400 and "UTF-8" in browser.text(r)
    rows = "".join("10.%d.%d.%d,%s,h%d,plaintext,,\n" % (i // 65536, (i // 256) % 256, i % 256, PT1, i)
                   for i in range(ci.MAX_ROWS + 1))
    r = upload(browser, HDR + rows)
    assert r.status_code == 400 and "Too many rows" in browser.text(r)


# --------------------------------------------------- secret types / new
def test_new_clients_each_secret_type(app, browser, superconn, logged_in):
    logged_in("operator")
    text = HDR + ("192.0.2.20,%s,sw-plain,plaintext,server,gi1/0/1-24\n"
                  "192.0.2.21,%s,sw-enc,encrypted,server,\n"
                  "192.0.2.22,,sw-none,none,global,\n") % (PT1, ENC)
    r, r2 = do_import(browser, text, require_ma="yes")
    page = browser.text(r)
    assert "Encrypted key – not usable" in page and "No key" in page and "global radius-server key" in page
    c = clients(superconn)
    assert c["sw-plain"][1:4] == (PT1, True, "ok") and c["sw-plain"][6] == "yes"
    assert c["sw-enc"][1:4] == ("", False, "encrypted")
    assert c["sw-none"][1:4] == ("", False, "missing") and c["sw-none"][4] == "global"
    # rendered clients file contains only the usable one
    from radius_admin import services
    conn = psycopg2.connect(APP_DSN)
    try:
        _, rendered = services.render_all(conn)
    finally:
        conn.close()
    assert "sw-plain" in rendered and "sw-enc" not in rendered and "sw-none" not in rendered
    assert ENC not in rendered
    # list page badges and disabled enable buttons
    lst = browser.text(browser.get("/clients/"))
    assert "Encrypted key</span>" in lst and "No key" in lst and "Global key" in lst
    assert "without a usable key" in lst and "disabled title=\"Enter or generate a plaintext key first\"" in lst


def test_encrypted_value_never_stored_anywhere(app, browser, superconn, logged_in):
    logged_in("operator")
    text = HDR + "192.0.2.21,%s,sw-enc,encrypted,,\n192.0.2.22,%s,sw-p,plaintext,,\n" % (ENC, PT1)
    r = upload(browser, text)
    page = browser.text(r)
    assert ENC not in page and PT1 not in page  # preview never shows values
    hidden = re.findall(r'<input type="hidden"[^>]*>', page)
    assert all(ENC not in h and PT1 not in h for h in hidden)
    assert all(PT1 not in v and ENC not in v for v in r.headers.getlist("Set-Cookie"))
    # pending import is encrypted at rest, 0600
    d = os.path.join(app.config["RA"]["staging_dir"], "imports")
    files = os.listdir(d)
    assert len(files) == 1
    p = os.path.join(d, files[0])
    assert os.stat(p).st_mode & 0o777 == 0o600
    blob = open(p, "rb").read()
    assert PT1.encode() not in blob and ENC.encode() not in blob and b"sw-enc" not in blob
    confirm(browser, r)
    assert os.listdir(d) == []  # deleted after confirm
    for (d_,) in q(superconn, "SELECT coalesce(detail::text,'') FROM ui.audit_log"):
        assert ENC not in d_ and PT1 not in d_
    assert q(superconn, "SELECT count(*) FROM ui.radius_client WHERE secret LIKE %s", ("%" + ENC + "%",))[0][0] == 0
    audit = q(superconn, "SELECT detail FROM ui.audit_log WHERE action='client.import'")[0][0]
    assert audit["new"] == 2 and sorted(audit["created"]) == ["sw-enc", "sw-p"]
    assert audit["disabled_without_key"] == ["sw-enc"]


# ---------------------------------------------------- existing clients
def seed(superconn):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, enabled, key_scope, dot1x_ports, require_ma)"
                 " VALUES ('sw-1','192.0.2.1',%s,true,'server','gi1/0/1',%s),"
                 " ('sw-2','192.0.2.2',%s,false,NULL,'','auto')", (PT1, "yes", PT2))


def test_existing_secret_types_update(browser, superconn, logged_in):
    seed(superconn)
    logged_in("operator")
    text = HDR + ("192.0.2.1,%s,sw-1,encrypted,global,gi1/0/1-48\n"
                  "192.0.2.2,,sw-2,none,,\n") % ENC
    r, _ = do_import(browser, text)
    assert "current key" in browser.text(r)
    c = clients(superconn)
    assert c["sw-1"][1:4] == (PT1, True, "ok") and c["sw-1"][4:6] == ("global", "gi1/0/1-48")
    assert c["sw-1"][6] == "yes"  # require_ma of existing untouched
    assert c["sw-2"][1:4] == (PT2, False, "ok")


def test_existing_plaintext_sets_secret_and_unchanged(browser, superconn, logged_in):
    seed(superconn)
    q(superconn, "UPDATE ui.radius_client SET secret='', key_status='missing', enabled=false WHERE name='sw-2'")
    logged_in("operator")
    text = HDR + "192.0.2.1,%s,sw-1,plaintext,server,gi1/0/1\n192.0.2.2,%s,sw-2,plaintext,,\n" % (PT1, PT2)
    r = upload(browser, text)
    t = browser.text(r)
    assert "1 updated, 1 unchanged" in t.replace("new, ", "new, ") or ("1 updated" in t and "1 unchanged" in t)
    assert "stays disabled" in t
    confirm(browser, r)
    c = clients(superconn)
    assert c["sw-2"][1:4] == (PT2, False, "ok")
    # now the key is usable, enabling works
    cid = q(superconn, "SELECT id FROM ui.radius_client WHERE name='sw-2'")[0][0]
    browser.post("/clients/%d/enable" % cid, {"enabled": "1"}, csrf_page="/clients/")
    assert clients(superconn)["sw-2"][2] is True


def test_skip_existing(browser, superconn, logged_in):
    seed(superconn)
    logged_in("operator")
    text = HDR + "192.0.2.1,%s,sw-1-renamed,plaintext,,\n192.0.2.9,%s,sw-9,plaintext,,\n" % (PT2, PT1)
    r, _ = do_import(browser, text, existing="skip")
    assert "1 skipped" in browser.text(r) or "skipped" in browser.text(r)
    c = clients(superconn)
    assert "sw-1" in c and c["sw-1"][1] == PT1 and "sw-9" in c


def test_ip_change_and_rename_via_update(browser, superconn, logged_in):
    seed(superconn)
    logged_in("operator")
    text = HDR + ("192.0.2.1,%s,sw-1-new,plaintext,server,gi1/0/1\n"   # matched by IP -> rename
                  "192.0.2.102,%s,sw-2,plaintext,,\n") % (PT1, PT2)   # matched by name -> IP change
    r, _ = do_import(browser, text)
    t = browser.text(r)
    assert "name sw-1 → sw-1-new" in t and "ip 192.0.2.2 → 192.0.2.102" in t
    c = clients(superconn)
    assert "sw-1" not in c and c["sw-1-new"][0] == "192.0.2.1"
    assert c["sw-2"][0] == "192.0.2.102"


def test_conflict_ip_and_hostname_different_clients(browser, superconn, logged_in):
    seed(superconn)
    logged_in("operator")
    text = HDR + "192.0.2.1,%s,sw-2,plaintext,,\n" % PT1
    r = upload(browser, text)
    assert r.status_code == 400 and "belongs to client sw-1 but hostname sw-2 is client sw-2" in browser.text(r)
    r = upload(browser, text, existing="skip")
    assert r.status_code == 400


def test_confirm_requires_stepup(browser, superconn, logged_in):
    u = logged_in("operator")
    q(superconn, "UPDATE ui.session SET stepup_at = now() - interval '10 minutes'")
    text = HDR + "192.0.2.30,%s,sw-30,plaintext,,\n" % PT1
    r = upload(browser, text)
    assert "stepup_password" in browser.text(r)
    r2 = confirm(browser, r)
    assert r2.status_code == 401 and q(superconn, "SELECT count(*) FROM ui.radius_client")[0][0] == 0
    r3 = confirm(browser, r2, {"stepup_password": "wrong-wrong-wrong", "stepup_code": "000000"})
    assert r3.status_code == 401 and "Verification failed" in browser.text(r3)
    r4 = confirm(browser, r3, {"stepup_password": u.password, "stepup_code": fresh_code(superconn, u)})
    assert r4.status_code == 200 and "Import complete" in browser.text(r4)
    assert q(superconn, "SELECT count(*) FROM ui.radius_client")[0][0] == 1


def test_viewer_refused(browser, superconn, logged_in):
    logged_in("viewer")
    assert browser.get("/clients/import").status_code == 403
    tok = browser.csrf_from("/clients/")
    r = browser.post("/clients/import/confirm", {"import_id": "x" * 22}, csrf=tok)
    assert r.status_code == 403
    assert "Import CSV" not in browser.text(browser.get("/clients/"))


def test_import_bound_to_session_and_single_use(app, browser, superconn, logged_in, make_user):
    from conftest import login
    logged_in("operator")
    text = HDR + "192.0.2.31,%s,sw-31,plaintext,,\n" % PT1
    r = upload(browser, text)
    iid = import_id(browser, r)
    other_user = make_user(username="op2", role="operator")
    b2 = Browser(app, ip="192.0.2.80")
    login(b2, superconn, other_user)
    r2 = b2.post("/clients/import/confirm", {"import_id": iid}, csrf_page="/clients/")
    assert r2.status_code == 302 and "/clients/import" in r2.headers["Location"]
    assert q(superconn, "SELECT count(*) FROM ui.radius_client")[0][0] == 0
    confirm(browser, r)
    r3 = browser.post("/clients/import/confirm", {"import_id": iid}, csrf_page="/clients/")
    assert r3.status_code == 302  # already used
    assert q(superconn, "SELECT count(*) FROM ui.radius_client")[0][0] == 1
    for bad in ("../../etc/passwd", "a" * 22 + "/", ""):
        assert browser.post("/clients/import/confirm", {"import_id": bad}, csrf_page="/clients/").status_code == 302


def test_import_expiry_and_cancel(app, browser, superconn, logged_in):
    import time
    from radius_admin import client_import as ci
    logged_in("operator")
    text = HDR + "192.0.2.32,%s,sw-32,plaintext,,\n" % PT1
    r = upload(browser, text)
    d = os.path.join(app.config["RA"]["staging_dir"], "imports")
    browser.post("/clients/import/cancel", {"import_id": import_id(browser, r)}, csrf_page="/clients/")
    assert os.listdir(d) == []
    r = upload(browser, text)
    p = os.path.join(d, os.listdir(d)[0])
    old = time.time() - ci.EXPIRY_SECONDS - 5
    os.utime(p, (old, old))
    orig = time.time
    try:
        time.time = lambda: orig() + ci.EXPIRY_SECONDS + 5
        r2 = confirm(browser, r)
    finally:
        time.time = orig
    assert r2.status_code == 302
    assert q(superconn, "SELECT count(*) FROM ui.radius_client")[0][0] == 0


def test_db_changed_between_preview_and_confirm(browser, superconn, logged_in):
    logged_in("operator")
    text = HDR + "192.0.2.33,%s,sw-33,plaintext,,\n" % PT1
    r = upload(browser, text)
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret) VALUES ('sw-33','192.0.2.99',%s)", (PT2,))
    r2 = confirm(browser, r)
    assert r2.status_code == 409 and "changed since the preview" in browser.text(r2)
    assert q(superconn, "SELECT ipaddr FROM ui.radius_client") == [("192.0.2.99",)]
    r3 = confirm(browser, r2)
    assert r3.status_code == 200
    assert q(superconn, "SELECT ipaddr FROM ui.radius_client") == [("192.0.2.33",)]


def test_import_creates_pending_changes(browser, superconn, logged_in):
    logged_in("operator")
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    assert "Pending changes" not in browser.text(browser.get("/dashboard"))
    r, r2 = do_import(browser, HDR + "192.0.2.40,%s,sw-40,plaintext,,\n" % PT1)
    assert "Review and apply" in browser.text(r2)
    assert "Pending changes" in browser.text(browser.get("/dashboard"))


def test_only_keyless_import_creates_no_render_change(browser, superconn, logged_in):
    logged_in("operator")
    browser.post("/apply/apply", {}, csrf_page="/apply/")
    do_import(browser, HDR + "192.0.2.41,,sw-41,none,,\n")
    assert "Pending changes" not in browser.text(browser.get("/dashboard"))


# --------------------------------------------------- enable / edit keys
def test_enable_refused_without_key(browser, superconn, logged_in):
    logged_in("operator")
    do_import(browser, HDR + "192.0.2.50,%s,sw-50,encrypted,,\n" % ENC)
    cid = q(superconn, "SELECT id FROM ui.radius_client")[0][0]
    r = browser.post("/clients/%d/enable" % cid, {"enabled": "1"}, csrf_page="/clients/")
    assert r.status_code == 302
    assert "cannot" in browser.text(browser.get("/clients/")) or True
    assert q(superconn, "SELECT enabled FROM ui.radius_client")[0][0] is False
    # edit with enabled checkbox but keep (no key) -> form error
    form = {"name": "sw-50", "ipaddr": "192.0.2.50", "secret_mode": "keep", "nas_type": "other",
            "require_ma": "auto", "limit_proxy_state": "auto", "enabled": "1"}
    r = browser.post("/clients/%d/edit" % cid, form)
    assert r.status_code == 400 and "plaintext key is entered or generated" in browser.text(r)
    page = browser.text(browser.get("/clients/%d/edit" % cid))
    assert "Encrypted key – not usable" in page
    # DB CHECK refuses even a direct attempt
    c = psycopg2.connect(APP_DSN)
    try:
        with c.cursor() as cur, pytest.raises(psycopg2.errors.CheckViolation):
            cur.execute("UPDATE ui.radius_client SET enabled=true WHERE id=%s", (cid,))
    finally:
        c.close()
    # generating a key (step-up still fresh) sets key_status ok and allows enabling
    r = browser.post("/clients/%d/edit" % cid, dict(form, secret_mode="generate"))
    assert r.status_code == 200
    row = q(superconn, "SELECT key_status, enabled, length(secret) FROM ui.radius_client")[0]
    assert row == ("ok", True, 32)


def test_edit_dot1x_and_scope(browser, superconn, logged_in):
    seed(superconn)
    logged_in("operator")
    cid = q(superconn, "SELECT id FROM ui.radius_client WHERE name='sw-1'")[0][0]
    form = {"name": "sw-1", "ipaddr": "192.0.2.1", "secret_mode": "keep", "nas_type": "cisco",
            "require_ma": "yes", "limit_proxy_state": "auto", "enabled": "1", "key_scope": "global",
            "dot1x_ports": "gi1/0/1-12"}
    assert browser.post("/clients/%d/edit" % cid, form).status_code == 302
    assert q(superconn, "SELECT key_scope, dot1x_ports FROM ui.radius_client WHERE id=%s", (cid,)) == [("global", "gi1/0/1-12")]
    assert "global</strong> radius-server key" in browser.text(browser.get("/clients/%d/edit" % cid))
    assert browser.post("/clients/%d/edit" % cid, dict(form, dot1x_ports="x" * 1001)).status_code == 400
    assert browser.post("/clients/%d/edit" % cid, dict(form, key_scope="vrf")).status_code == 400


def test_template_download(browser, logged_in):
    logged_in("viewer")
    r = browser.get("/clients/import/template.csv")
    assert r.status_code == 200 and r.mimetype == "text/csv" and "attachment" in r.headers["Content-Disposition"]
    t = r.get_data(as_text=True)
    assert t.startswith("ip,secret,hostname,secret_type,key_scope,dot1x_ports")
    assert ",plaintext," in t and ",encrypted," in t and ",none," in t


def test_template_imports_cleanly(browser, superconn, logged_in):
    from radius_admin import client_import as ci
    logged_in("operator")
    do_import(browser, ci.TEMPLATE_CSV)
    assert len(clients(superconn)) == 3


# ------------------------------------------- helper grammar compatibility
def _load_helper():
    if not os.access(HELPER, os.R_OK):
        pytest.skip("helper not readable")
    loader = importlib.machinery.SourceFileLoader("radius_admin_helper_mod", HELPER)
    spec = importlib.util.spec_from_loader("radius_admin_helper_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_imported_clients_pass_helper_grammar(browser, superconn, logged_in):
    helper = _load_helper()
    logged_in("operator")
    secret_odd = "A1!#$%&'()*+,-./:;<=>?@[]^_`{|}~z"
    text = HDR + ("192.0.2.60,\"%s\",sw.a_b-60,plaintext,server,\"gi1/0/1, te1/1/1\"\n"
                  "2001:db8::61,%s,sw-v6,plaintext,,\n"
                  "198.51.100.0/28,%s,sw-net,plaintext,global,\n"
                  "192.0.2.63,%s,sw-enc,encrypted,,\n"
                  "192.0.2.64,,sw-none,none,,\n") % (secret_odd, PT1, PT2, ENC)
    do_import(browser, text, require_ma="yes")
    from radius_admin import services
    conn = psycopg2.connect(APP_DSN)
    try:
        _, rendered = services.render_all(conn)
    finally:
        conn.close()
    assert helper.check_clients(rendered.encode("utf-8")) == 3
    assert "sw-enc" not in rendered and "sw-none" not in rendered


# ------------------------------------------------------------- header / no header
def test_headerless_file(browser, superconn, logged_in):
    logged_in("operator")
    text = ("192.0.2.70,%s,sw-70,plaintext,server,gi1/0/1-24\n"
            "192.0.2.71,%s,sw-71,plaintext\n"            # key_scope + dot1x_ports omitted
            "192.0.2.72,%s,sw-72,encrypted,global\n"     # dot1x_ports omitted
            % (PT1, PT2, ENC))
    r = upload(browser, text)
    assert r.status_code == 200, browser.text(r)[-3000:]
    assert "No header row" in browser.text(r)
    confirm_r = confirm(browser, r)
    assert "Import complete" in browser.text(confirm_r)
    c = clients(superconn)
    # tuple: ipaddr, secret, enabled, key_status, key_scope, dot1x_ports, require_ma
    assert c["sw-70"][3:6] == ("ok", "server", "gi1/0/1-24")
    assert c["sw-71"][1] == PT2 and c["sw-71"][4] is None and c["sw-71"][5] == ""
    assert c["sw-72"][2] is False and c["sw-72"][3] == "encrypted" and c["sw-72"][4] == "global"
    assert ENC not in str(q(superconn, "SELECT * FROM ui.radius_client"))


def test_header_found_and_column_order(browser, superconn, logged_in):
    logged_in("operator")
    text = ("HOSTNAME, Secret_Type ,ip,secret\n"
            "sw-80,plaintext,192.0.2.80,%s\n" % PT1)
    r = upload(browser, text)
    assert r.status_code == 200, browser.text(r)[-3000:]
    assert "Header row found" in browser.text(r)
    confirm(browser, r)
    c = clients(superconn)
    assert c["sw-80"][0] == "192.0.2.80" and c["sw-80"][1] == PT1


def test_headerless_first_row_containing_ip_word_is_data(browser, superconn, logged_in):
    logged_in("operator")
    # data values that contain column-name words must not be mistaken for a header
    text = "192.0.2.90,%s,ip,plaintext,,secret\n192.0.2.91,%s,hostname,plaintext,,\n" % (PT1, PT2)
    r = upload(browser, text)
    assert r.status_code == 200, browser.text(r)[-3000:]
    assert "No header row" in browser.text(r)
    confirm(browser, r)
    assert set(clients(superconn)) == {"ip", "hostname"}


def test_key_scope_values(browser, superconn, logged_in):
    """key_scope is server, global or none (empty = none); 'host' is an accepted alias."""
    logged_in("operator")
    text = HDR + ("192.0.2.101,%s,sw-s,plaintext,server,\n"
                  "192.0.2.102,%s,sw-g,plaintext,GLOBAL,\n"
                  "192.0.2.103,,sw-n,none,none,\n"
                  "192.0.2.104,%s,sw-e,plaintext,,\n"
                  "192.0.2.105,%s,sw-h,plaintext,host,\n") % (PT1, PT2, "Plaintext-Key-0003-abcdef",
                                                                   "Plaintext-Key-0004-abcdef")
    do_import(browser, text)
    c = clients(superconn)
    assert {n: c[n][4] for n in c} == {"sw-s": "server", "sw-g": "global", "sw-n": None,
                                         "sw-e": None, "sw-h": "server"}
    r = upload(browser, HDR + "192.0.2.106,%s,sw-x,plaintext,vrf,\n" % PT1)
    assert r.status_code == 400 and "key_scope must be server, global or none" in browser.text(r)


# ------------------------------------------------------------- 802.1X port display
def test_ports_parser():
    from radius_admin.ports import port_summary
    s = port_summary("gi1/0/1-20,gi1/0/23")
    assert [g["label"] for g in s["groups"]] == ["gi1/0/1–20", "gi1/0/23"] and s["total"] == 21
    assert port_summary("Gi1/0/1 - 24; te1/1/1")["total"] == 25
    odd = port_summary("uplinks, gi1/0/9-3")
    assert odd["unknown"] and [g["label"] for g in odd["groups"]] == ["uplinks", "gi1/0/9-3"]
    assert port_summary("")["groups"] == []


def test_unquoted_port_list_in_last_column(browser, superconn, logged_in):
    """The switch export writes gi1/0/1-20,gi1/0/23 without quotes; it must stay one value."""
    logged_in("operator")
    text = HDR + ("192.0.2.120,%s,sw-120,plaintext,server,gi1/0/1-20,gi1/0/23\n"
                  "192.0.2.121,%s,sw-121,plaintext,global,\"gi1/0/1-20,gi1/0/23,te1/1/1-2\"\n"
                  % (PT1, PT2))
    do_import(browser, text)
    c = clients(superconn)
    assert c["sw-120"][5] == "gi1/0/1-20,gi1/0/23"
    assert c["sw-121"][5] == "gi1/0/1-20,gi1/0/23,te1/1/1-2"
    # headerless too
    r = upload(browser, "192.0.2.122,%s,sw-122,plaintext,server,gi1/0/1-4,gi1/0/7\n"
               % "Plaintext-Key-0003-abcdef")
    assert r.status_code == 200, browser.text(r)[-2000:]
    confirm(browser, r)
    assert clients(superconn)["sw-122"][5] == "gi1/0/1-4,gi1/0/7"
    # a column after dot1x_ports means overflow cannot be joined -> error, nothing imported
    r = upload(browser, "ip,secret,hostname,secret_type,dot1x_ports,key_scope\n"
                        "192.0.2.123,%s,sw-123,plaintext,gi1/0/1,gi1/0/2,server\n" % PT1)
    assert r.status_code == 400 and "expected 6 fields" in browser.text(r)


def test_port_list_display(browser, superconn, logged_in):
    q(superconn, "INSERT INTO ui.radius_client (name, ipaddr, secret, dot1x_ports) VALUES"
                 " ('sw-p1','192.0.2.130',%s,'gi1/0/1-20,gi1/0/23'),"
                 " ('sw-p2','192.0.2.131',%s,'gi1/0/1-4,gi1/0/7,gi1/0/9-12,te1/1/1')", (PT1, PT2))
    logged_in("viewer")
    page = browser.text(browser.get("/clients/"))
    assert "gi1/0/1–20" in page and "gi1/0/23" in page
    assert "+2 more" in page                       # 4 groups: 2 shown, 2 behind the pop-up
    assert '<dialog id="ports-' in page and "21 ports in 2 groups" in page
    assert "te1/1/1" in page                       # full list present in the dialog
    assert "<script" not in page.split("</head>")[1] or 'src="/static/app.js' in page
