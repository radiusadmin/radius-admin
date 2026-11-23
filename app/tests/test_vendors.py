"""Vendor profiles (radius_admin.vendors, SPEC section 26): validation, export/import, and
their use by the policy renderer, the CoA sender and the SNMP port names. No database."""
import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from radius_admin import coa, snmp, unlang, vendors  # noqa: E402
from radius_admin.vendors import ProfileError  # noqa: E402


def c1300():
    return copy.deepcopy(vendors.builtin("cisco-c1300"))


# ------------------------------------------------------------------ built-in profiles
def test_builtin_profiles_load_and_match_their_file_names():
    ids = vendors.builtin_ids()
    assert vendors.DEFAULT_ID in ids
    for pid in ids:
        assert vendors.builtin(pid)["id"] == pid
    assert vendors.default() is vendors.builtin(vendors.DEFAULT_ID)


@pytest.mark.parametrize("pid", ["missing", "../vendors", "Cisco-C1300", "", None])
def test_unknown_builtin_is_refused(pid):
    with pytest.raises(ProfileError):
        vendors.builtin(pid)


def test_catalyst_1300_profile_keeps_the_original_behaviour():
    p = vendors.default()
    assert [e["attr"] for e in p["reply"]["vlan"]] == ["Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id"]
    assert p["reply"]["admin_full"] == [{"attr": "Cisco-AVPair", "op": "+=", "value": "shell:priv-lvl=15"}]
    assert p["coa"]["port"] == 1700 and p["coa"]["identify"] == "mac-then-session"
    assert [p["coa"][a]["packet"] for a in vendors.COA_ACTIONS] == ["coa", "coa", "disconnect"]


def test_catalyst_iosxe_profile():
    p = vendors.builtin("cisco-iosxe")
    assert p["status"] == "supported" and p["mab"]["port_types"] == ["Ethernet"]
    assert p["reply"]["vlan"] == vendors.default()["reply"]["vlan"]
    assert p["reply"]["admin_full"] == [{"attr": "Cisco-AVPair", "op": "+=", "value": "shell:priv-lvl=15"}]
    assert p["reply"]["role"] == []
    assert p["coa"]["port"] == 1700 and p["coa"]["identify"] == "session-and-mac"
    assert p["coa"]["send_nas_port_id"] is False
    assert p["coa"]["reauth"]["attrs"] == [{"attr": "Cisco-AVPair", "value": "subscriber:command=reauthenticate"}]
    assert p["coa"]["bounce"]["attrs"] == [{"attr": "Cisco-AVPair", "value": "subscriber:command=bounce-host-port"}]
    assert p["coa"]["disconnect"] == {"packet": "disconnect", "attrs": []}


def test_catalyst_iosxe_mfa_timeout_is_set_per_server():
    # per-server values override the global radius-server ones on IOS-XE (SPEC section 29.4)
    text, is_commands = vendors.mfa_timeout_hint(vendors.builtin("cisco-iosxe"))
    assert is_commands
    assert text.splitlines() == ["radius server <this RADIUS server's name on the switch>",
                                 " timeout 30", " retransmit 2", " exit"]


@pytest.mark.parametrize("ifname,nas_port_id", [
    ("Gi1/0/5", "GigabitEthernet1/0/5"), ("Te1/1/1", "TenGigabitEthernet1/1/1"), ("Fa0", "FastEthernet0"),
    ("Gi2/0/48", "GigabitEthernet2/0/48"), ("gi1/0/5", "gi1/0/5"), ("Vl10", "Vl10"), ("Po1", "Po1"),
    ("Tw1/0/1", "Tw1/0/1")])
def test_catalyst_iosxe_port_names(ifname, nas_port_id):
    assert vendors.port_name(vendors.builtin("cisco-iosxe"), ifname) == nas_port_id


def test_catalyst_iosxe_coa_names_the_session_by_id_and_mac_without_port():
    p = vendors.builtin("cisco-iosxe")
    text = coa.build_request("bounce", "192.0.2.5", "0000000A", "AA-BB-CC-00-00-01", "GigabitEthernet1/0/5", profile=p)
    lines = text.splitlines()
    assert lines[:3] == ['Acct-Session-Id = "0000000A"', 'Calling-Station-Id = "AA-BB-CC-00-00-01"',
                         "NAS-IP-Address = 192.0.2.5"]
    assert "NAS-Port-Id" not in text
    assert 'Cisco-AVPair = "subscriber:command=bounce-host-port"' in lines


def test_catalyst_iosxe_alongside_the_default_adds_no_policy_branches():
    assert unlang.render_policy("", vendors.default(), [vendors.builtin("cisco-iosxe")]) == \
        unlang.render_policy("", vendors.default(), [])


# ------------------------------------------------------------------ export / import
def test_export_import_round_trip():
    text = vendors.export_json(vendors.default())
    assert json.loads(text)["format"] == vendors.FORMAT
    assert vendors.import_json(text) == vendors.default()
    assert vendors.export_json(vendors.import_json(text)) == text      # stable output


@pytest.mark.parametrize("text", ["", "{", "[]", "null", '"x"', "{\"format\": 1}"])
def test_import_refuses_non_profiles(text):
    with pytest.raises(ProfileError):
        vendors.import_json(text)


# ------------------------------------------------------------------ validation
def _with(path, value):
    doc = c1300()
    node = doc
    for k in path[:-1]:
        node = node[k]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return doc


@pytest.mark.parametrize("path,value", [
    (("format",), 2), (("format",), True), (("format",), KeyError),
    (("id",), "Has Space"), (("id",), "x" * 33), (("id",), "../etc"),
    (("label",), ""), (("label",), "line\nbreak"),
    (("status",), "tested"),
    (("extra",), 1),
    (("reply", "other"), []),
    (("reply", "admin_full"), KeyError), (("reply", "admin_full"), []), (("reply", "vlan"), []),
    (("coa", "port"), 0), (("coa", "port"), 70000), (("coa", "port"), True), (("coa", "port"), "1700"),
    (("coa", "identify"), "whatever"),
    (("coa", "send_nas_port_id"), "yes"),
    (("coa", "reauth"), {"packet": "accounting", "attrs": []}),
    (("snmp", "port_names"), [{"match": "(", "format": "x"}]),
    (("snmp", "port_names"), [{"match": "(a)", "format": "{2}"}]),
    (("snmp", "port_names"), [{"match": "a", "format": "a b"}]),
    (("snmp", "port_names"), [{"match": "a", "format": "x", "ignore_case": "yes"}]),
    (("snmp", "port_names"), [{"match": "a" * 201, "format": "x"}]),
])
def test_validate_refuses_bad_fields(path, value):
    with pytest.raises(ProfileError):
        vendors.validate(_with(path, value))


@pytest.mark.parametrize("attr", [
    "Exec-Program", "exec-program-wait", "Auth-Type", "Post-Auth-Type", "Tmp-String-0", "Module-Failure-Message",
    "Cleartext-Password", "NT-Password", "Attr-26", "Vendor-9-Attr-1", "Cisco-Attr-1", "Message-Authenticator",
    "Proxy-To-Realm", "EAP-Message", "Calling-Station-Id", "Event-Timestamp", "1Bad", "Bad Name", "Bad\"Name", "",
])
def test_profiles_cannot_set_internal_or_raw_attributes(attr):
    with pytest.raises(ProfileError):
        vendors.validate(_with(("reply", "admin_full"), [{"attr": attr, "op": "+=", "value": "x"}]))
    with pytest.raises(ProfileError):
        vendors.validate(_with(("coa", "reauth"), {"packet": "coa", "attrs": [{"attr": attr, "value": "x"}]}))


@pytest.mark.parametrize("value", [
    'x"', "a\\b", "%{exec:/bin/sh}", "${confdir}", "`id`", "two\nlines", "tab\there", "", "x" * 248,
    "{vlan} suffix", "{other}", "café",
])
def test_values_cannot_escape_their_string(value):
    with pytest.raises(ProfileError):
        vendors.validate(_with(("reply", "admin_full"), [{"attr": "Cisco-AVPair", "op": "+=", "value": value}]))


def test_placeholders_only_where_they_mean_something():
    with pytest.raises(ProfileError):       # no VLAN placeholder: the VLAN would never be sent
        vendors.validate(_with(("reply", "vlan"), [{"attr": "Tunnel-Type", "op": ":=", "value": "VLAN"}]))
    with pytest.raises(ProfileError):
        vendors.validate(_with(("reply", "admin_full"), [{"attr": "Cisco-AVPair", "op": "+=", "value": "{vlan}"}]))
    with pytest.raises(ProfileError):
        vendors.validate(_with(("coa", "bounce"), {"packet": "coa", "attrs": [{"attr": "Cisco-AVPair", "value": "{vlan}"}]}))
    with pytest.raises(ProfileError):
        vendors.validate(_with(("reply", "vlan", 0, "op"), "=="))


def test_too_many_attributes_or_rules():
    many = [{"attr": "Cisco-AVPair", "op": "+=", "value": "a=%d" % i} for i in range(vendors.MAX_ATTRS + 1)]
    with pytest.raises(ProfileError):
        vendors.validate(_with(("reply", "admin_full"), many))
    rules = [{"match": "a", "format": "b"}] * (vendors.MAX_PORT_RULES + 1)
    with pytest.raises(ProfileError):
        vendors.validate(_with(("snmp", "port_names"), rules))


# ------------------------------------------------------------------ policy rendering
def test_policy_takes_reply_attributes_from_the_profile():
    p = c1300()
    p["reply"]["admin_full"] = [{"attr": "Aruba-Admin-Role", "op": ":=", "value": "root"},
                                {"attr": "Service-Type", "op": ":=", "value": "Administrative-User"}]
    p["reply"]["vlan"] = [{"attr": "Tunnel-Type", "op": ":=", "value": "VLAN"},
                          {"attr": "Tunnel-Medium-Type", "op": ":=", "value": "IEEE-802"},
                          {"attr": "Tunnel-Private-Group-Id", "op": ":=", "value": "{vlan}"},
                          {"attr": "Egress-VLANID", "op": "+=", "value": "0x31000000"}]
    text = unlang.render_policy("", p)
    assert "Cisco-AVPair" not in text
    assert "\t\t\t\t\t&Aruba-Admin-Role := root\n\t\t\t\t\t&Service-Type := Administrative-User\n" in text
    assert text.count("&Egress-VLANID += 0x31000000\n") == 3          # MAB, password 802.1X, EAP-TLS
    assert text.count("&Tunnel-Private-Group-Id := &control:Tmp-String-0\n") == 3
    assert text != unlang.render_policy("")


def test_policy_default_profile_is_the_catalyst_1300():
    text = unlang.render_policy("")
    assert unlang.render_policy("", vendors.default()) == text
    assert '\t\t\t\t\t&Cisco-AVPair += "shell:priv-lvl=15"\n' in text
    assert "\t\t\t&Tunnel-Private-Group-Id := &control:Tmp-String-0\n" in text      # MAB
    assert text.count("\t\t\t\t&Tunnel-Private-Group-Id := &control:Tmp-String-0\n") == 2


def test_policy_revalidates_a_profile_passed_in():
    p = c1300()
    p["reply"]["admin_full"] = [{"attr": "Cisco-AVPair", "op": "+=", "value": 'x"\n\t\texec'}]
    with pytest.raises(ProfileError):
        unlang.render_policy("", p)


# ------------------------------------------------------------------ CoA
def test_coa_attributes_come_from_the_profile():
    p = c1300()
    p["coa"]["reauth"] = {"packet": "coa", "attrs": [{"attr": "HP-Port-Bounce-Host", "value": "12"},
                                                     {"attr": "Cisco-AVPair", "value": "x=y z"}]}
    p["coa"]["send_nas_port_id"] = False
    p = vendors.validate(p)
    req = coa.build_request("reauth", "192.0.2.10", "0000002A", "AA-BB-CC-00-00-01", "gi1/0/4", profile=p)
    assert "HP-Port-Bounce-Host = 12\n" in req and 'Cisco-AVPair = "x=y z"\n' in req
    assert "subscriber:command" not in req and "NAS-Port-Id" not in req
    req = coa.build_request("disconnect", "192.0.2.10", "", "AA-BB-CC-00-00-01", "gi1/0/4", profile=p)
    assert "Cisco-AVPair" not in req and "HP-Port" not in req


def test_coa_action_the_device_lacks_is_refused():
    p = c1300()
    p["coa"]["bounce"] = None
    p = vendors.validate(p)
    with pytest.raises(coa.CoaError, match="no bounce action"):
        coa.build_request("bounce", "192.0.2.10", "", "AA-BB-CC-00-00-01", "", profile=p)
    ok, msg = coa.send("bounce", "192.0.2.10", 3799, "x" * 20, "", "/bin/false", "/nonexistent", profile=p)
    assert not ok and "no bounce action" in msg


def test_coa_default_profile_requests_unchanged():
    req = coa.build_request("bounce", "192.0.2.10", "", "AA-BB-CC-00-00-01", "gi1/0/4")
    assert 'Cisco-AVPair = "subscriber:command=bounce-host-port"\n' in req
    req = coa.build_request("reauth", "192.0.2.10", "", "AA-BB-CC-00-00-01", "gi1/0/4")
    assert 'Cisco-AVPair = "subscriber:command=reauthenticate"\n' in req
    with pytest.raises(coa.CoaError, match="unknown action"):
        coa.build_request("shutdown", "192.0.2.10", "", "AA-BB-CC-00-00-01", "")


# ------------------------------------------------------------------ SNMP port names
def test_port_name_rules_come_from_the_profile():
    p = c1300()
    p["snmp"]["port_names"] = [{"match": "GigabitEthernet([0-9/]+)", "format": "Gi{1}"},
                               {"match": "(ge|xe)-([0-9/]+)", "ignore_case": True, "format": "{1:upper}-{2}.0"}]
    p = vendors.validate(p)
    assert snmp.cli_port_name("GigabitEthernet1/0/7", p) == "Gi1/0/7"
    assert snmp.cli_port_name(" ge-0/0/1 ", p) == "GE-0/0/1.0"
    assert snmp.cli_port_name("gi4", p) == "gi4"                 # no rule matches: name as reported
    assert snmp.cli_port_name("gi4") == "gi1/0/4"                # default profile: Catalyst 1300 rule
    assert snmp.cli_port_name("TE12") == "te1/0/12" and snmp.cli_port_name("gi") == "gi"


# ------------------------------------------------------------------ Generic RFC profile
def generic():
    return vendors.builtin("generic-rfc")


def test_generic_profile_uses_standard_attributes_only():
    p = generic()
    assert p["status"] == "unverified"
    assert p["reply"]["admin_full"] == [{"attr": "Service-Type", "op": ":=", "value": "Administrative-User"}]
    assert [e["attr"] for e in p["reply"]["vlan"]] == ["Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id"]
    assert p["coa"]["port"] == 3799 and p["coa"]["identify"] == "session-and-mac"
    assert p["coa"]["reauth"] is None and p["coa"]["bounce"] is None
    assert p["coa"]["disconnect"] == {"packet": "disconnect", "attrs": []}
    assert p["snmp"]["port_names"] == []
    text = vendors.export_json(p)
    assert "Cisco" not in text and vendors.import_json(text) == p


def test_generic_policy():
    text = unlang.render_policy("", generic())
    assert "Cisco-AVPair" not in text
    assert "\t\t\t\tupdate reply {\n\t\t\t\t\t&Service-Type := Administrative-User\n\t\t\t\t}\n" in text
    assert text.count("&Tunnel-Private-Group-Id := &control:Tmp-String-0\n") == 3
    # beyond the Catalyst 1300 policy: the admin attribute, wireless MAB and the rule's role
    assert text.count("(&NAS-Port-Type == Wireless-802.11)") == 2
    assert text.count("&Filter-Id := &control:Tmp-String-4\n") == 2
    assert "%{client:radius_admin_profile}" not in text                 # one profile: no branches


def test_generic_disconnect_names_session_and_station():
    req = coa.build_request("disconnect", "192.0.2.10", "0000002A", "AA-BB-CC-00-00-01", "1/1/4", profile=generic())
    names = [ln.split(" = ")[0] for ln in req.splitlines()]
    assert names == ["Acct-Session-Id", "Calling-Station-Id", "NAS-Port-Id", "NAS-IP-Address", "Event-Timestamp",
                     "Message-Authenticator"]
    req = coa.build_request("disconnect", "192.0.2.10", "0000002A", "", "", profile=generic())
    assert 'Acct-Session-Id = "0000002A"' in req and "Calling-Station-Id" not in req
    req = coa.build_request("disconnect", "192.0.2.10", "", "AA-BB-CC-00-00-01", "", profile=generic())
    assert "Acct-Session-Id" not in req and "Calling-Station-Id" in req
    with pytest.raises(coa.CoaError, match="unexpected characters"):    # sent, so it is checked
        coa.build_request("disconnect", "192.0.2.10", 'bad"id', "AA-BB-CC-00-00-01", "", profile=generic())
    with pytest.raises(coa.CoaError, match="not a MAC"):
        coa.build_request("disconnect", "192.0.2.10", "0000002A", "not-a-mac", "", profile=generic())
    with pytest.raises(coa.CoaError, match="neither"):
        coa.build_request("disconnect", "192.0.2.10", "", "", "", profile=generic())
    for action in ("reauth", "bounce"):
        with pytest.raises(coa.CoaError, match="no %s action" % action):
            coa.build_request(action, "192.0.2.10", "0000002A", "AA-BB-CC-00-00-01", "", profile=generic())


def test_generic_port_names_are_kept_as_reported():
    for name in ("gi4", "1/1/4", "ge-0/0/1", "GigabitEthernet1/0/7"):
        assert snmp.cli_port_name(name, generic()) == name


def test_generic_disconnect_reaches_an_rfc5176_device():
    """radclient -> a simulated RFC 5176 server: the Disconnect-Request names the session."""
    from fake_coa import FakeSwitch
    prefix = os.environ.get("RADIUS_ADMIN_TEST_FR_PREFIX", "")
    rc = next((c for c in ([os.path.join(prefix, "bin", "radclient")] if prefix else []) + ["/usr/bin/radclient"]
               if os.access(c, os.X_OK)), None)
    if not rc:
        pytest.skip("radclient not available (set RADIUS_ADMIN_TEST_FR_PREFIX to a FreeRADIUS install prefix)")
    sw = FakeSwitch("Plaintext-Key-0002-abcdef")
    try:
        req = coa.build_request("disconnect", "127.0.0.1", "0000002C", "AA-BB-CC-00-00-03", "1/1/4", profile=generic())
        ok, msg = coa.send("disconnect", "127.0.0.1", sw.port, "Plaintext-Key-0002-abcdef", req, rc,
                           coa.find_dict_dir(rc), profile=generic())
        assert ok and "Disconnect-ACK" in msg, msg
        (got,) = sw.requests
        assert got["code"] == "Disconnect-Request" and got["auth_ok"] and got["msg_auth_ok"]
        assert got["attrs"]["Acct-Session-Id"] == "0000002C" and got["attrs"]["Calling-Station-Id"] == "AA-BB-CC-00-00-03"
        assert got["attrs"]["NAS-Port-Id"] == "1/1/4" and got["cisco"] == []
    finally:
        sw.close()


# ------------------------------------------------------------------ a profile per client
def test_policy_branches_only_where_attributes_differ():
    text = unlang.render_policy("", vendors.default(), [generic()])
    # VLAN attributes are the same in both profiles: no branch there; the admin attribute (1),
    # the MAB port types (authorize and post-auth: 2) and the role attributes (2) differ; the admin
    # attribute is added for local and for directory device admins (SPEC section 28) and after a
    # second-factor provider's accept, Duo and remote (SPEC section 29: 2 more)
    assert text.count("%{client:radius_admin_profile}") == 8
    assert text.count("\t\t\tupdate reply {\n\t\t\t\t&Tunnel-Type := VLAN\n") == 2         # unbranched
    assert ('\t\t\t\tif ("%{client:radius_admin_profile}" == "generic-rfc") {\n'
            "\t\t\t\t\tupdate reply {\n\t\t\t\t\t\t&Service-Type := Administrative-User\n\t\t\t\t\t}\n\t\t\t\t}\n"
            "\t\t\t\telse {\n\t\t\t\t\tupdate reply {\n"
            '\t\t\t\t\t\t&Cisco-AVPair += "shell:priv-lvl=15"\n\t\t\t\t\t}\n\t\t\t\t}\n') in text
    # the default itself, repeated, or given twice adds nothing
    assert unlang.render_policy("", vendors.default(), [vendors.default()]) == unlang.render_policy("")
    assert unlang.render_policy("", vendors.default(), [generic(), generic()]) == text


def test_policy_groups_profiles_with_the_same_attributes():
    a = copy.deepcopy(generic())
    a["id"] = "aaa-copy"
    b = c1300()
    b["id"] = "zzz-vlan"
    b["reply"]["vlan"] = b["reply"]["vlan"] + [{"attr": "Egress-VLANID", "op": "+=", "value": "0x31000000"}]
    text = unlang.render_policy("", vendors.default(), [generic(), b, a])
    assert ('if ("%{client:radius_admin_profile}" == "aaa-copy" || "%{client:radius_admin_profile}" == "generic-rfc")'
            in text)
    assert text.count('if ("%{client:radius_admin_profile}" == "zzz-vlan")') == 3     # MAB, password, EAP-TLS
    assert text.count("&Egress-VLANID += 0x31000000") == 3


def test_default_profile_can_be_another_one():
    text = unlang.render_policy("", generic(), [vendors.default()])
    assert text.index("Cisco-AVPair") < text.index("Administrative-User")     # default in the else branch
    assert '== "cisco-c1300"' in text


def test_clients_file_names_profiles_other_than_the_default():
    clients = [dict(name="a", ipaddr="192.0.2.1", secret="x" * 20, vendor_profile="generic-rfc"),
               dict(name="b", ipaddr="192.0.2.2", secret="x" * 20, vendor_profile="cisco-c1300"),
               dict(name="c", ipaddr="192.0.2.3", secret="x" * 20),
               dict(name="t", ipaddr="192.0.2.4", transport="radsec", vendor_profile="generic-rfc")]
    text = unlang.render_clients(clients, {"enabled": True})
    assert text.count("radius_admin_profile") == 2
    assert "\tnas_type = other\n\tradius_admin_profile = generic-rfc\n\trequire_message_authenticator" in text
    assert "\t\tnas_type = other\n\t\tradius_admin_profile = generic-rfc\n\t\tradsec_peer_name" in text
    text = unlang.render_clients(clients, {"enabled": True}, "generic-rfc")
    assert "radius_admin_profile = cisco-c1300" in text and "radius_admin_profile = generic-rfc" not in text
    for bad in ("Generic", "x y", "a\n}", "../x", "-x"):
        with pytest.raises(unlang.PolicyInputError):
            unlang.render_clients([dict(clients[0], vendor_profile=bad)])


def test_setup_text_is_checked():
    for good in ({"accounting": "line one\n line two\tx"}, {}, {"coa": None}):
        vendors.validate(dict(c1300(), setup=good))
    for bad in ({"radius": "x"}, {"coa": ""}, {"coa": "x" * 1501}, {"coa": "bell\x07"}, {"coa": 5}, "text"):
        with pytest.raises(ProfileError):
            vendors.validate(dict(c1300(), setup=bad))


def test_choices_and_resolve():
    assert [c[0] for c in vendors.choices()][0] == vendors.DEFAULT_ID
    assert vendors.resolve(None)["id"] == vendors.DEFAULT_ID
    assert vendors.resolve(None, "generic-rfc")["id"] == "generic-rfc"
    assert vendors.resolve("generic-rfc", "cisco-c1300")["id"] == "generic-rfc"
    with pytest.raises(ProfileError):
        vendors.resolve("missing")
    assert vendors.supports(generic(), "disconnect") and not vendors.supports(generic(), "bounce")


# ------------------------------------------------------------------ wireless MAB and roles
def test_mab_port_types_and_role_list_are_checked():
    assert c1300()["mab"] == {"port_types": ["Ethernet"]} and c1300()["reply"]["role"] == []
    assert generic()["mab"] == {"port_types": ["Ethernet", "Wireless-802.11"]}
    assert generic()["reply"]["role"] == [{"attr": "Filter-Id", "op": ":=", "value": "{role}"}]
    doc = c1300()
    del doc["mab"]
    del doc["reply"]["role"]
    p = vendors.validate(doc)                          # both optional, with these defaults
    assert p["mab"] == {"port_types": ["Ethernet"]} and p["reply"]["role"] == []
    assert vendors.validate(_with(("mab", "port_types"), ["Wireless-802.11", "Ethernet"]))["mab"]["port_types"] == \
        ["Ethernet", "Wireless-802.11"]                # stored in a fixed order
    for bad in ([], ["Ethernet", "Ethernet"], ["Virtual"], "Ethernet", [1]):
        with pytest.raises(ProfileError):
            vendors.validate(_with(("mab", "port_types"), bad))
    with pytest.raises(ProfileError):                  # a role list must use the role
        vendors.validate(_with(("reply", "role"), [{"attr": "Filter-Id", "op": ":=", "value": "x"}]))
    with pytest.raises(ProfileError):                  # and {role} only there
        vendors.validate(_with(("reply", "admin_full"), [{"attr": "Filter-Id", "op": ":=", "value": "{role}"}]))
    with pytest.raises(ProfileError):
        vendors.validate(_with(("mab", "other"), 1))


def test_wireless_mab_only_for_profiles_that_accept_it():
    default_only = unlang.render_policy("")
    assert "Wireless-802.11" not in default_only
    text = unlang.render_policy("", vendors.default(), [generic()])
    cond = ('&NAS-Port-Type && ((&NAS-Port-Type == Ethernet) || (&NAS-Port-Type == Wireless-802.11 && '
            '("%{client:radius_admin_profile}" == "generic-rfc")))')
    assert text.count("!&EAP-Message && " + cond + " && &User-Name") == 2      # authorize and post-auth
    # a wireless-capable default: everyone except the Ethernet-only profiles named in the clients file
    text = unlang.render_policy("", generic(), [vendors.default()])
    assert text.count('(&NAS-Port-Type == Wireless-802.11 && !("%{client:radius_admin_profile}" == "cisco-c1300"))') == 2
    text = unlang.render_policy("", generic(), [])
    assert text.count("&NAS-Port-Type && ((&NAS-Port-Type == Ethernet) || (&NAS-Port-Type == Wireless-802.11)) &&") == 2


def test_role_attributes_follow_the_profile():
    assert "radius_admin_rule_role" not in unlang.render_policy("")          # no profile sends roles
    text = unlang.render_policy("", vendors.default(), [generic()])
    assert text.count('&Tmp-String-4 := "%{sql:SELECT radius_admin_rule_role(%{control:Tmp-String-6})}"') == 2
    assert text.count("if (&control:Tmp-String-6 && &control:Tmp-String-6 =~ /^[0-9]{1,10}$/) {") == 2
    assert text.count("&Filter-Id := &control:Tmp-String-4\n") == 2                # password and EAP-TLS 802.1X
    assert "\t\t\t\t\telse {\n\t\t\t\t\t\tnoop\n\t\t\t\t\t}\n" in text             # the Catalyst sends none
    text = unlang.render_policy("", generic(), [])
    assert text.count("\t\t\t\t\tupdate reply {\n\t\t\t\t\t\t&Filter-Id := &control:Tmp-String-4\n") == 2


def test_role_value_is_only_ever_a_checked_attribute_reference():
    text = unlang.render_policy("", generic(), [])
    for line in text.splitlines():
        if "Tmp-String-4" in line and "Filter-Id" in line:
            assert line.strip() == "&Filter-Id := &control:Tmp-String-4"
    assert "&control:Tmp-String-4 =~ /^[A-Za-z0-9._-]{1,64}$/" in text


# ------------------------------------------------------------------ the portal's profile form
def test_form_round_trip_of_the_builtin_profiles():
    for pid in vendors.builtin_ids():
        p = vendors.builtin(pid)
        q, errors = vendors.form_to_profile(vendors.profile_to_form(p))
        assert errors == {} and dict(q, status=p["status"]) == p


def test_form_lines():
    f = vendors.profile_to_form(c1300())
    assert f["port_rules"] == "(gi|te|fa|tw|fo|hu)([0-9]+) => {1:lower}1/0/{2} (ignore case)"
    assert f["coa_reauth_attrs"] == "Cisco-AVPair = subscriber:command=reauthenticate"
    f.update(port_rules="  ge-([0-9/]+)  =>  GE{1}  \n\n  x(.) => {1}  ", reply_role="\n Filter-Id  :=  {role} \n",
             coa_bounce_packet="", coa_bounce_attrs="")
    p, errors = vendors.form_to_profile(f)
    assert errors == {} and p["status"] == "unverified" and p["coa"]["bounce"] is None
    assert p["snmp"]["port_names"] == [{"match": "ge-([0-9/]+)", "format": "GE{1}", "ignore_case": False},
                                       {"match": "x(.)", "format": "{1}", "ignore_case": False}]
    assert p["reply"]["role"] == [{"attr": "Filter-Id", "op": ":=", "value": "{role}"}]
    for field, value, where in (("reply_admin", "Cisco-AVPair == x", "reply_admin"),
                                ("coa_reauth_attrs", "no equals sign", "coa_reauth"),
                                ("port_rules", "x =>", "port_rules"),
                                ("coa_port", "17oo", "coa_port"),
                                ("label", "", "label")):
        p, errors = vendors.form_to_profile(dict(f, **{field: value}))
        assert p is None and list(errors) == [where], (field, errors)


def test_dictionary_attributes(tmp_path):
    (tmp_path / "dictionary").write_text("$INCLUDE dictionary.rfc2865\nATTRIBUTE\tLocal-Thing\t3000\tstring\n")
    (tmp_path / "dictionary.rfc2865").write_text("ATTRIBUTE\tFilter-Id\t11\tstring\nVALUE\tService-Type\tLogin-User\t1\n")
    (tmp_path / "other.txt").write_text("ATTRIBUTE\tNot-Read\t1\tstring\n")
    names = vendors.dictionary_attributes(str(tmp_path))
    assert names == {"local-thing", "filter-id"}
    assert vendors.dictionary_attributes(str(tmp_path / "missing")) is None
    assert vendors.unknown_attributes(generic(), names) == [
        ("reply_vlan", "Tunnel-Type"), ("reply_vlan", "Tunnel-Medium-Type"), ("reply_vlan", "Tunnel-Private-Group-Id"),
        ("reply_admin", "Service-Type")]


def test_catalog_lookups_without_a_database():
    custom = dict(generic(), id="lab-ap", label="Lab AP", status="unverified")
    cat = {"cisco-c1300": vendors.default(), "generic-rfc": generic(), "lab-ap": custom}
    assert vendors.resolve("lab-ap", None, cat) is custom
    assert vendors.resolve(None, "lab-ap", cat) is custom
    with pytest.raises(ProfileError):
        vendors.resolve("lab-ap")                        # not a built-in profile
    assert vendors.choices(cat)[-1] == ("lab-ap", "Lab AP (custom)", "unverified")
    assert vendors.is_builtin("generic-rfc") and not vendors.is_builtin("lab-ap") and not vendors.is_builtin("../x")


def test_report_url():
    u = vendors.report_url(generic(), "radiusadmin/radius-admin", "0.2.3")
    assert u == ("https://github.com/radiusadmin/radius-admin/issues/new?template=device-profile.yml"
                 "&title=Device+profile+generic-rfc%3A+&profile=generic-rfc&version=0.2.3")
    assert vendors.report_url(generic(), "radiusadmin/radius-admin", None).endswith("&version=")
    for bad in ("", "no-slash", "a/b/c", "x/y z", "https://evil.example.com/x", None):
        assert vendors.report_url(generic(), bad, "1") is None


def test_issue_form_has_the_fields_the_link_fills():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        ".github", "ISSUE_TEMPLATE", vendors.ISSUE_TEMPLATE)
    text = open(path).read()
    for field in ("profile", "version"):
        assert "\n    id: %s\n" % field in text
    assert "do **not** paste shared secrets" in text
