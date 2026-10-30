#!/usr/bin/env python3
"""Render policy.d/radius-admin and radius-admin-clients.conf for the test bench with
app/radius_admin/unlang.py. Since SPEC section 10 the policy does not contain rules or
settings (they are read live from ui.* by SQL functions); SEED_RULES is used by
run-tests.py to fill ui.access_rule.
Usage: render.py <policy-out> <clients-out>"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "app"))
from radius_admin import unlang  # noqa: E402

SEED_RULES = [  # (id, priority, connection, ssid, ad_group, vlan) - SPEC section 8
    (1, 10, "wired", None, "Wired-Support", 510),
    (2, 20, "wired", None, "Wired-Office", 500),
    (3, 30, "wired", None, "Wired-Utility", 520),
    (4, 10, "wireless", "Example_Main_Test", "Wireless-Office-Test", 530),
    (5, 10, "wireless", "Example_Admin", "WIRELESS-SUPPORT", 510),
    (6, 10, "wireless", "Example_Main", "WIRELESS-OFFICE", 530),
]
TEST_CLIENTS = [
    # name, ipaddr, secret, require_ma
    ("wifi-aps", "203.0.113.201", "TestWifiApsSecret0123456789", "yes"),
    ("sw-192-0-2-10", "192.0.2.10", "TestSwitchInSecret012345678", "auto"),
    # A switch registered OUTSIDE the admin subnet, to prove the subnet check.
    ("sw-outside-10", "198.51.100.10", "TestSwitchOutSecret01234567", "auto"),
]
# RadSec: an access point at 127.0.0.1 (radsecproxy in the bench) that must present the
# certificate named pc1.example.net; revocation checked against the bench OCSP responder.
RADSEC_CLIENT = dict(name="ap-radsec", ipaddr="127.0.0.1", transport="radsec",
                     radsec_peer_name="pc1.example.net", nas_type="other", secret="", enabled=True)
RADSEC = {"enabled": True, "port": 2083, "ocsp": True, "ocsp_url": "http://pki.example.net:8080/ocsp"}


def main():
    pos = [a for a in sys.argv[1:] if not a.startswith("--")]
    clients = [dict(name=n, ipaddr=a, secret=s, require_ma=m, limit_proxy_state="auto",
                    nas_type="other", enabled=True) for n, a, s, m in TEST_CLIENTS]
    with open(pos[0], "w") as fh:
        fh.write(unlang.render_policy(""))
    with open(pos[1], "w") as fh:
        fh.write(unlang.render_clients(clients + [RADSEC_CLIENT], RADSEC))


if __name__ == "__main__":
    main()
