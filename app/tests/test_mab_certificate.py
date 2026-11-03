"""MACs that authenticated with a certificate (EAP-TLS Access-Accept) are never offered for MAB
approval: radius_admin_mab_hex() does not queue them and the unknown-device views hide them."""
from radius_admin import insight


def q(superconn, sql, params=()):
    with superconn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def cert_auth(superconn, csi, reply="Access-Accept", method="eap-tls"):
    q(superconn, "INSERT INTO radpostauth (username, reply, authmethod, nasipaddress, callingstationid)"
                 " VALUES ('host/pc1.example.net', %s, %s, '192.0.2.5', %s)", (reply, method, csi))


def mab(superconn, mac):
    return q(superconn, "SELECT radius_admin_mab_hex(%s, 'c0000205', '')", (mac,))[0][0]


def pending(superconn, mac):
    return q(superconn, "SELECT count(*) FROM mab_pending WHERE mac = %s", (mac,))[0][0]


def test_certificate_mac_not_queued(superconn, clean_db):
    for n, csi in enumerate(("aa-bb-cc-00-01-01", "AA:BB:CC:00:01:02", "aabb.cc00.0103", "AABBCC000104")):
        mac = "AA-BB-CC-00-01-0%d" % (n + 1)
        cert_auth(superconn, csi)
        assert mab(superconn, mac) == "certificate", csi
        assert pending(superconn, mac) == 0, csi


def test_queued_before_certificate_is_removed(superconn, clean_db):
    mac = "AA-BB-CC-00-01-11"
    assert mab(superconn, mac) == "unknown" and pending(superconn, mac) == 1
    cert_auth(superconn, mac)
    assert q(superconn, "SELECT count(*) FROM mab_pending_open WHERE mac = %s", (mac,))[0][0] == 0
    assert mab(superconn, mac) == "certificate" and pending(superconn, mac) == 0


def test_rejected_or_other_methods_still_queued(superconn, clean_db):
    cert_auth(superconn, "AA-BB-CC-00-01-21", reply="Access-Reject")       # certificate refused
    cert_auth(superconn, "AA-BB-CC-00-01-22", method="mab")                # an earlier MAB accept
    for mac in ("AA-BB-CC-00-01-21", "AA-BB-CC-00-01-22"):
        assert mab(superconn, mac) == "unknown" and pending(superconn, mac) == 1, mac


def test_registered_device_keeps_its_vlan(superconn, clean_db):
    q(superconn, "INSERT INTO mab_device (mac, vlan, enabled) VALUES ('AA-BB-CC-00-01-31', 130, true)")
    cert_auth(superconn, "AA-BB-CC-00-01-31")
    assert mab(superconn, "AA-BB-CC-00-01-31") == "130"


def test_unknown_page_and_counts_hide_certificate_macs(browser, superconn, logged_in):
    logged_in("operator")
    q(superconn, "INSERT INTO mab_pending (mac, nas_ip) VALUES ('AA-BB-CC-00-01-41', '192.0.2.5'),"
                 " ('AA-BB-CC-00-01-42', '192.0.2.5')")
    cert_auth(superconn, "aa:bb:cc:00:01:41")
    t = browser.text(browser.get("/mab/unknown"))
    assert "AA-BB-CC-00-01-42" in t and "AA-BB-CC-00-01-41" not in t
    t = browser.text(browser.get("/dashboard"))
    assert "<strong>1</strong> unknown devices" in t                    # dashboard tile
    assert '1<span class="sr-only"> unknown devices' in t              # navigation badge
    aid = q(superconn, "SELECT id FROM radpostauth WHERE callingstationid = 'aa:bb:cc:00:01:41'")[0][0]
    assert "unknown-device queue" not in browser.text(browser.get("/auth-log/%d" % aid))


def test_reason_hint_for_certificate_device():
    hint = insight.reason_hint("radius-admin: MAB not used: this device authenticates with a certificate",
                               "Access-Reject")
    assert hint and "certificate" in hint
