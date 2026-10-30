#!/usr/bin/env python3
"""Functional test bench for the radius-admin FreeRADIUS configuration.

Runs as root in a sandbox (NOT on the production server). See README.md.

  run-tests.py --prefix <freeradius install prefix> --bench <workdir>
               [--eapol-test <path to eapol_test>]

Steps: build test PKI (if missing) -> start slapd (AD emulation) and an OCSP responder
-> build raddb from freeradius/ deliverables + unlang.py output -> seed PostgreSQL
test rows -> radiusd -XC -> radiusd -X -> radclient / eapol_test cases -> check
radpostauth rows. Exit status 0 only if every case passed.
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BIND_PW = "Test-Bind-Pw-1234"
SW_IN = ("192.0.2.10", "TestSwitchInSecret012345678")      # switch in admin subnet
SW_OUT = ("198.51.100.10", "TestSwitchOutSecret01234567")      # switch outside admin subnet
WIFI = ("203.0.113.201", "TestWifiApsSecret0123456789")     # wifi-aps (require_ma yes)
ADMIN_PW = "Correct-Horse-Battery-1"
LEGACY_PW = "Legacy-Crypt-Pass-1"
TEST_USERS = ("t-admin1", "t-admin2", "t-notgroup", "t-legacy")
MACS = {"AA-BB-CC-00-00-01": (120, True), "AA-BB-CC-00-00-02": (130, False)}

results = []


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)


def psql(sql):
    r = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-X", "-q", "-t", "-A",
                        "-v", "ON_ERROR_STOP=1", "-d", "radius", "-c", sql],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("psql failed: " + r.stderr)
    return r.stdout.strip()


def q(s):
    return "'" + s.replace("'", "''") + "'"


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("  -- " + detail) if detail and not ok else ""))


# ----------------------------------------------------------------------------- setup
def sandbox_prereqs():
    """Idempotent sandbox setup: hosts entries for the emulated DC/OCSP host and the
    loopback addresses used as RADIUS client sources."""
    with open("/etc/hosts") as fh:
        hosts = fh.read()
    if "dc01.example.net" not in hosts:
        with open("/etc/hosts", "a") as fh:
            fh.write("127.0.0.1 dc01.example.net pki.example.net\n")
    if "radius.example.net" not in hosts:   # RadSec clients check the server certificate name
        with open("/etc/hosts", "a") as fh:
            fh.write("127.0.0.1 radius.example.net\n")
    have = sh(["ip", "-4", "addr", "show", "dev", "lo"]).stdout
    for ip in (SW_IN[0], SW_OUT[0], WIFI[0]):
        if " %s/" % ip not in have:
            subprocess.run(["ip", "addr", "add", ip + "/32", "dev", "lo"], check=True)


def seed_db():
    pbkdf2 = sh([sys.executable, os.path.join(HERE, "pbkdf2_hash.py"), ADMIN_PW, "600000"]).stdout.strip()
    assert pbkdf2.startswith("{X-PBKDF2}HMACSHA2+256:"), pbkdf2
    legacy = sh(["openssl", "passwd", "-6", "-stdin"], input=LEGACY_PW).stdout.strip()  # sha512crypt
    assert legacy.startswith("$6$"), legacy
    users = ",".join(q(u) for u in TEST_USERS)
    psql("BEGIN;"
         "DELETE FROM radcheck WHERE username IN (%s);"
         "DELETE FROM radusergroup WHERE username IN (%s);"
         "DELETE FROM mab_device WHERE mac LIKE 'AA-BB-CC-00-00-%%';"
         "DELETE FROM mab_pending;"
         "DELETE FROM radpostauth;"
         "INSERT INTO radcheck (username, attribute, op, value) VALUES"
         " ('t-admin1','Password-With-Header',':=',%s),"
         " ('t-admin2','Password-With-Header',':=',%s),"
         " ('t-notgroup','Password-With-Header',':=',%s),"
         " ('t-legacy','Crypt-Password',':=',%s);"
         "INSERT INTO radusergroup (username, groupname, priority) VALUES"
         " ('t-admin1','net-admins',1),('t-admin2','net-admins',1),('t-legacy','net-admins',1),"
         " ('t-notgroup','helpdesk',1);"
         "INSERT INTO mab_device (mac, vlan, description, enabled) VALUES"
         " ('AA-BB-CC-00-00-01',120,'printer',true),('AA-BB-CC-00-00-02',130,'disabled cam',false);"
         "INSERT INTO mab_device (mac, vlan, description, enabled, expires_at) VALUES"
         " ('AA-BB-CC-00-00-03',140,'expired guest',true,now() - interval '1 hour'),"
         " ('AA-BB-CC-00-00-04',150,'temporary',true,now() + interval '1 day');"
         "COMMIT;" % (users, users, q(pbkdf2), q(pbkdf2), q(pbkdf2), q(legacy)))
    seed_live_policy()


def seed_live_policy(priv15=False):
    """ui.access_rule = SPEC section 8 seed rules; ui.setting defaults.
    The bench owns these tables in the sandbox database."""
    sys.dont_write_bytecode = True
    sys.path.insert(0, HERE)
    from render import SEED_RULES
    rows = ",".join("(%d,%d,%s,%s,%s,%d,true)" % (i, p, q(c), "NULL" if s is None else q(s), q(g), v)
                    for i, p, c, s, g, v in SEED_RULES)
    psql("BEGIN;"
         "DELETE FROM ui.access_rule;"
         "INSERT INTO ui.access_rule (id, priority, connection, ssid, ad_group, vlan, enabled) VALUES %s;"
         "INSERT INTO ui.access_rule (id, priority, connection, ssid, ad_group, vlan, enabled) VALUES"
         " (50, 50, 'wired', NULL, 'Zz Many 300', 88, true),"
         " (51, 50, 'wired', NULL, 'O''Brien Lab', 89, true);"
         "SELECT setval('ui.access_rule_id_seq', 100);"
         "UPDATE ui.setting SET value = '192.0.2.0/24' WHERE key = 'admin_subnet';"
         "UPDATE ui.setting SET value = %s WHERE key = 'admin_priv15';"
         "COMMIT;" % (rows, q("true" if priv15 else "false")))


def set_priv15(on):
    psql("UPDATE ui.setting SET value = %s WHERE key = 'admin_priv15'" % q("true" if on else "false"))


def start_ocsp(bench):
    pki = os.path.join(bench, "pki")
    log = open(os.path.join(bench, "ocsp.log"), "w")
    p = subprocess.Popen(["openssl", "ocsp", "-index", "index.txt", "-port", "8080",
                          "-rsigner", "ocsp.pem", "-rkey", "ocsp.key", "-CA", "issuing.pem",
                          "-ignore_err"], cwd=pki, stdout=log, stderr=subprocess.STDOUT)
    time.sleep(1.0)
    if p.poll() is not None:
        raise RuntimeError("OCSP responder failed to start, see ocsp.log")
    return p


def traverse_ok(*paths):
    """radiusd drops to user freerad: it must be able to traverse to the prefix and bench
    (sandbox scratch directories are often 0700 and may be reset)."""
    for top in paths:
        d = os.path.abspath(top)
        while d != "/":
            st = os.stat(d)
            if not st.st_mode & 0o001:
                os.chmod(d, st.st_mode | 0o001)
            d = os.path.dirname(d)


def keep_traversable(paths, stop_evt):
    """Some sandboxes reset scratch directory modes while we run; keep re-applying o+x."""
    while not stop_evt.is_set():
        try:
            traverse_ok(*paths)
        except OSError:
            pass
        stop_evt.wait(0.1)


def start_radiusd(prefix, raddb, logname):
    traverse_ok(prefix, raddb)
    log = open(logname, "w")
    # -X is "-sfxx -l stdout"; drop -s: TLS (RadSec) listeners need the thread pool,
    # which is also how production runs.
    p = subprocess.Popen([os.path.join(prefix, "sbin", "radiusd"), "-fxx", "-l", "stdout", "-d", raddb],
                         stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        time.sleep(0.2)
        with open(logname) as fh:
            txt = fh.read()
        if "Ready to process requests" in txt:
            return p
        if p.poll() is not None:
            break
    raise RuntimeError("radiusd did not start, see " + logname)


def stop(p):
    if p and p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


# ----------------------------------------------------------------------------- clients
def radclient(prefix, client, attrs, server="127.0.0.1:1812"):
    src, secret = client
    lines = list(attrs) + ["Packet-Src-IP-Address = %s" % src, "Message-Authenticator = 0x00"]
    r = subprocess.run([os.path.join(prefix, "bin", "radclient"), "-x", "-r", "1", "-t", "5",
                        "-D", os.path.join(prefix, "share", "freeradius"),
                        server, "auth", secret],
                       input=",\n".join(lines) + "\n", capture_output=True, text=True)
    out = r.stdout + r.stderr
    if "Received Access-Accept" in out:
        code = "accept"
    elif "Received Access-Reject" in out:
        code = "reject"
    else:
        code = "none"
    return code, out


def eapol(eapol_test, bench, client, method, cert=None, extra=(), identity=None, port=1812):
    src, secret = client
    pki = os.path.join(bench, "pki")
    conf = ["network={", "\tkey_mgmt=IEEE8021X", "\teapol_flags=0", "\teap=%s" % method]
    if method == "TLS":
        conf += ['\tidentity="host/%s.example.net"' % (identity or cert.replace("-chain", "")),
                 '\tca_cert="%s/ca.pem"' % pki,
                 '\tclient_cert="%s/%s.pem"' % (pki, cert),
                 '\tprivate_key="%s/%s.key"' % (pki, cert.replace("-chain", ""))]
    elif method in ("PEAP", "TTLS"):
        conf += ['\tidentity="t-admin1"', '\tpassword="%s"' % ADMIN_PW,
                 '\tca_cert="%s/ca.pem"' % pki,
                 '\tphase2="%s"' % ("auth=MSCHAPV2" if method == "PEAP" else "auth=PAP")]
    elif method == "MD5":
        conf += ['\tidentity="t-admin1"', '\tpassword="%s"' % ADMIN_PW]
    conf.append("}")
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False, dir=bench) as fh:
        fh.write("\n".join(conf) + "\n")
        path = fh.name
    try:
        cmd = [eapol_test, "-c", path, "-a", "127.0.0.1", "-p", str(port), "-s", secret, "-A", src,
               "-t", "10", "-r", "0"]
        for e in extra:
            cmd += ["-N", e]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(path)
    out = r.stdout + r.stderr
    code = "accept" if "Access-Accept" in out and r.returncode == 0 else (
        "reject" if "Access-Reject" in out else "none")
    return code, out


def vlan_of(out):
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Tunnel-Private-Group-Id"):
            return line.split("=", 1)[1].strip().strip('"').split(":")[-1].strip('"')
        if "Attribute 81 (Tunnel-Private-Group-Id)" in line or "Tunnel-Private-Group-ID" in line:
            pass
    # eapol_test prints raw attributes: "Attribute 81 (Tunnel-Private-Group-Id) length=5" followed by
    # "Value: 3230" style hex on the next line in some versions; fall back to scanning.
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "Attribute 81 " in line and i + 1 < len(lines) and "Value:" in lines[i + 1]:
            hexv = lines[i + 1].split("Value:")[1].strip().replace(" ", "")
            try:
                raw = bytes.fromhex(hexv)
            except ValueError:
                return None
            if raw and raw[0] < 0x20:  # tag octet
                raw = raw[1:]
            return raw.decode("ascii", "replace")
    return None


def has_priv15(out):
    return "shell:priv-lvl=15" in out


# ----------------------------------------------------------------------------- cases
def pap_cases(prefix, priv15):
    sfx = " [priv15=%s]" % ("on" if priv15 else "off")
    base = ['NAS-IP-Address = %s' % SW_IN[0], 'Service-Type = Login-User']
    code, out = radclient(prefix, SW_IN, base + ['User-Name = "t-admin1"', 'User-Password = "%s"' % ADMIN_PW])
    record("PAP admin, PBKDF2, from 192.0.2.0/24 -> Accept" + sfx, code == "accept", out[-600:])
    record("PAP admin reply has Cisco-AVPair priv-lvl=15 iff setting on" + sfx, has_priv15(out) == priv15, out[-600:])
    code, out = radclient(prefix, SW_IN, base + ['User-Name = "t-admin1"', 'User-Password = "wrong-password"'])
    record("PAP admin wrong password -> Reject" + sfx, code == "reject", out[-400:])
    code, out = radclient(prefix, SW_IN, base + ['User-Name = "t-notgroup"', 'User-Password = "%s"' % ADMIN_PW])
    record("PAP user not in net-admins -> Reject" + sfx, code == "reject", out[-400:])
    code, out = radclient(prefix, SW_OUT, ['NAS-IP-Address = %s' % SW_OUT[0], 'User-Name = "t-admin1"',
                                         'User-Password = "%s"' % ADMIN_PW])
    record("PAP admin from switch outside admin subnet -> Reject" + sfx, code == "reject", out[-400:])
    code, out = radclient(prefix, SW_IN, base + ['User-Name = "t-legacy"', 'User-Password = "%s"' % LEGACY_PW])
    record("PAP legacy Crypt-Password ($6$) -> Accept" + sfx, code == "accept", out[-400:])
    code, out = radclient(prefix, SW_IN, base + ['User-Name = "nosuchuser"', 'User-Password = "%s"' % ADMIN_PW])
    record("PAP unknown user -> Reject" + sfx, code == "reject", out[-400:])
    code, out = radclient(prefix, SW_IN, base + ['User-Name = "t-admin1"', 'CHAP-Password = "%s"' % ADMIN_PW])
    record("CHAP (removed) -> Reject" + sfx, code == "reject", out[-400:])


def mab_cases(prefix):
    eth = ['NAS-IP-Address = %s' % SW_IN[0], 'NAS-Port-Type = Ethernet', 'Service-Type = Call-Check',
           'NAS-Port-Id = "gi1/0/7"']
    for fmt in ("aabbcc000001", "AA-BB-CC-00-00-01", "aabb.cc00.0001", "aa:bb:cc:00:00:01", "AABBCC000001"):
        code, out = radclient(prefix, SW_IN, eth + ['User-Name = "%s"' % fmt, 'User-Password = "%s"' % fmt,
                                                   'Calling-Station-Id = "AA-BB-CC-00-00-01"'])
        record("MAB registered MAC as %s -> Accept VLAN 120" % fmt,
               code == "accept" and 'Tunnel-Private-Group-Id:0 = "120"' in out
               and "Tunnel-Type:0 = VLAN" in out and "Tunnel-Medium-Type:0 = IEEE-802" in out, out[-600:])
    code, out = radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc000001"', 'User-Password = "aabbcc000001"'])
    record("MAB registered MAC without Calling-Station-Id -> Accept", code == "accept", out[-400:])
    code, out = radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc0000ff"', 'User-Password = "aabbcc0000ff"',
                                               'Calling-Station-Id = "AA-BB-CC-00-00-FF"'])
    record("MAB unknown MAC -> Reject", code == "reject", out[-400:])
    pend = psql("SELECT attempts||'|'||coalesce(host(nas_ip),'')||'|'||coalesce(nas_port_id,'') FROM mab_pending"
                " WHERE mac='AA-BB-CC-00-00-FF'")
    record("MAB unknown MAC -> queued in mab_pending with switch address and port",
           pend.startswith("1|%s|gi1/0/7" % SW_IN[0]), pend)
    radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc0000ff"', 'User-Password = "aabbcc0000ff"',
                                   'Calling-Station-Id = "AA-BB-CC-00-00-FF"'])
    pend = psql("SELECT attempts FROM mab_pending WHERE mac='AA-BB-CC-00-00-FF'")
    record("MAB unknown MAC again -> attempts counted, one queue row", pend.strip() == "2", pend)
    code, out = radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc000003"', 'User-Password = "aabbcc000003"',
                                               'Calling-Station-Id = "AA-BB-CC-00-00-03"'])
    record("MAB expired registration -> Reject", code == "reject", out[-400:])
    code, out = radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc000004"', 'User-Password = "aabbcc000004"',
                                               'Calling-Station-Id = "AA-BB-CC-00-00-04"'])
    record("MAB registration expiring tomorrow -> Accept VLAN 150",
           code == "accept" and 'Tunnel-Private-Group-Id:0 = "150"' in out, out[-400:])
    queued = psql("SELECT string_agg(mac, ',' ORDER BY mac) FROM mab_pending")
    record("MAB known devices (disabled/expired) are never queued", queued.strip() == "AA-BB-CC-00-00-FF", queued)
    code, out = radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc000002"', 'User-Password = "aabbcc000002"',
                                               'Calling-Station-Id = "AA-BB-CC-00-00-02"'])
    record("MAB disabled device -> Reject", code == "reject", out[-400:])
    code, out = radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc000001"', 'User-Password = "aabbcc000001"',
                                               'Calling-Station-Id = "AA-BB-CC-00-00-09"'])
    record("MAB Calling-Station-Id mismatch -> Reject", code == "reject", out[-400:])
    code, out = radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc000001"', 'User-Password = "aabbcc000001"',
                                               'Calling-Station-Id = "garbage"'])
    record("MAB Calling-Station-Id not a MAC -> Reject", code == "reject", out[-400:])
    code, out = radclient(prefix, SW_IN, ['NAS-IP-Address = %s' % SW_IN[0], 'User-Name = "aabbcc000001"',
                                         'User-Password = "aabbcc000001"'])
    record("MAC-shaped user without NAS-Port-Type=Ethernet is not MAB -> Reject", code == "reject", out[-400:])
    code, out = radclient(prefix, SW_IN, eth + ['User-Name = "aabbcc0000011"', 'User-Password = "x"'])
    record("13-hex-digit user name is not MAB -> Reject", code == "reject", out[-400:])


def log_tail_since(logname, mark):
    with open(logname) as fh:
        fh.seek(mark)
        return fh.read()


def eap_cases(eapol_test, bench, logname):
    wired = ["61:d:15"]  # NAS-Port-Type = Ethernet
    ssid = lambda s: ["30:s:AA-BB-CC-DD-EE-FF:%s" % s, "61:d:19"]  # noqa: E731
    cases = [
        ("EAP-TLS wired pc1 (Wired-Office) -> VLAN 500", SW_IN, "pc1", wired, "accept", "500"),
        ("EAP-TLS wired pc2 (Wired-Support + Wired-Office, priority) -> VLAN 510", SW_IN, "pc2", wired, "accept", "510"),
        ("EAP-TLS wired pc3 (Wired-Utility) -> VLAN 520", SW_IN, "pc3", wired, "accept", "520"),
        ("EAP-TLS wired pc4 (no group) -> Reject", SW_IN, "pc4", wired, "reject", None),
        ("EAP-TLS wired from switch outside admin subnet pc1 -> VLAN 500", SW_OUT, "pc1", wired, "accept", "500"),
        ("EAP-TLS SSID Example_Main_Test pc1 -> VLAN 530", WIFI, "pc1", ssid("Example_Main_Test"), "accept", "530"),
        ("EAP-TLS SSID Example_Main pc1 -> VLAN 530", WIFI, "pc1", ssid("Example_Main"), "accept", "530"),
        ("EAP-TLS SSID Example_Admin pc2 -> VLAN 510", WIFI, "pc2", ssid("Example_Admin"), "accept", "510"),
        ("EAP-TLS SSID Example_Admin pc1 (not in WIRELESS-SUPPORT) -> Reject", WIFI, "pc1", ssid("Example_Admin"), "reject", None),
        ("EAP-TLS SSID Example_Main pc2 (not in WIRELESS-OFFICE) -> Reject", WIFI, "pc2", ssid("Example_Main"), "reject", None),
        ("EAP-TLS unknown SSID -> Reject", WIFI, "pc1", ssid("Guest"), "reject", None),
        ("EAP-TLS SSID suffix trick 'XExample_Admin' -> Reject", WIFI, "pc2", ssid("XExample_Admin"), "reject", None),
        ("EAP-TLS no port type and no SSID (admin branch) -> Reject", WIFI, "pc1", ["61:d:0"], "reject", None),
        ("EAP-TLS wired pc1 sending Issuing CA in chain -> VLAN 500", SW_IN, "pc1-chain", wired, "accept", "500"),
        ("EAP-TLS wired pc6 NESTED group 'R&D Lab (Bldg-2)' in Wired-Utility -> VLAN 520", SW_IN, "pc6", wired,
         "accept", "520"),
        ("EAP-TLS wired pc7 group named 'Guests,Wired-Support' (comma injection) -> Reject", SW_IN, "pc7", wired,
         "reject", None),
        ("EAP-TLS wired pc8 in 300 groups, matching one is LAST -> VLAN 88", SW_IN, "pc8", wired, "accept", "88"),
        ("EAP-TLS wired pc9 groups \"Evil\\047,NULL) UNION..\" + \"O'Brien Lab\" -> literal match VLAN 89",
         SW_IN, "pc9", wired, "accept", "89"),
        ("EAP-TLS wired pc9 with rule for \"Evil'...\" (de-escaped form) only -> Reject (no \\047 decoding)",
         SW_IN, "pc9-noobrien", wired, "reject", None),
        ("EAP-TLS cert without DNS SAN -> Reject", SW_IN, "nosan", wired, "reject", None),
        ("EAP-TLS cert from unknown CA -> Reject", SW_IN, "rogue", wired, "reject", None),
        ("EAP-TLS revoked cert (OCSP) -> Reject", SW_IN, "pc5", wired, "reject", None),
    ]
    for name, client, cert, extra, want, want_vlan in cases:
        if cert == "pc9-noobrien":
            # A rule naming the DE-ESCAPED form of pc9's evil group must not match:
            # proves directory values reach SQL byte-for-byte (no \047 -> ' decoding).
            psql("UPDATE ui.access_rule SET enabled = false WHERE id = 51;"
                 "INSERT INTO ui.access_rule (id, priority, connection, ad_group, vlan) VALUES "
                 "(52, 1, 'wired', 'evil'',null) union all select ''999'' --', 77)")
            cert = "pc9"
        elif name.startswith("EAP-TLS wired pc9 groups"):
            pass
        if "no port type" in name:
            # eapol_test always adds NAS-Port-Type; strip by overriding with an unused value is not
            # equivalent, so send Virtual(5) which is "!= Ethernet" and no Called-Station-Id.
            extra = ["61:d:5"]
        mark = os.path.getsize(logname)
        code, out = eapol(eapol_test, bench, client, "TLS", cert=cert, extra=extra)
        log = log_tail_since(logname, mark)
        ok = code == want
        if ok and want_vlan is not None:
            ok = vlan_of(out) == want_vlan
        if "OCSP" in name:
            ok = ok and "Cert status: revoked" in log
        elif cert != "rogue":
            # every other case must have had a successful OCSP check (responder reachable)
            ok = ok and "Cert status: good" in log
        record(name, ok, "got %s vlan=%s" % (code, vlan_of(out)))
        if "(no \\047 decoding)" in name:
            psql("DELETE FROM ui.access_rule WHERE id = 52; UPDATE ui.access_rule SET enabled = true WHERE id = 51")
    for m in ("PEAP", "TTLS", "MD5"):
        code, out = eapol(eapol_test, bench, SW_IN, m, extra=wired)
        record("EAP-%s (removed) -> Reject / not accepted" % m, code != "accept", "got " + code)


INJECTION_PAYLOADS = [
    "x\\047,NULL) UNION ALL SELECT \\047999\\047 ORDER BY 1 NULLS LAST --",
    "x\\x27) UNION ALL SELECT \\x27999\\x27 --",
    "x\\\\'); SELECT pg_sleep(5); --",
    "x'); DELETE FROM ui.access_rule; --",
    "Example_Admin' OR '1'='1",
    "x%{exec:/bin/id}",
    "x\\n'); DELETE FROM radcheck; --",
    "x\\000') UNION SELECT '999' --",
]


def tables_fingerprint():
    return psql("SELECT (SELECT count(*)||':'||coalesce(max(id),0)||':'||coalesce(sum(vlan),0) FROM ui.access_rule)"
                "||'/'||(SELECT count(*) FROM radcheck)||'/'||(SELECT count(*) FROM mab_device)")


def injection_cases(eapol_test, bench, prefix, logname):
    """Request/directory data must reach SQL only as hex: payloads are rejected or
    matched literally, never executed (FreeRADIUS un-escapes %{sql:} arguments)."""
    before = tables_fingerprint()
    wifi_pc2 = lambda csi: eapol(eapol_test, bench, WIFI, "TLS", cert="pc2",  # noqa: E731
                                 extra=["30:s:" + csi, "61:d:19"])
    for i, pl in enumerate(INJECTION_PAYLOADS):
        mark = os.path.getsize(logname)
        t0 = time.time()
        code, out = wifi_pc2("AA-BB-CC-DD-EE-FF:" + pl)
        log = log_tail_since(logname, mark)
        sqls = [ln for ln in log.splitlines() if re.search(r"Executing select query: SELECT radius_admin_vlan(_rule)?_hex\(", ln)]
        hex_only = bool(sqls) and all(re.search(r"radius_admin_vlan(_rule)?_hex\((true|false), '([0-9a-f]*)', '(,[0-9a-f]+)*'\)$",
                                                ln.split("Executing select query: ")[1]) for ln in sqls)
        record("INJECTION #%d in Called-Station-Id -> Reject, SQL args hex-only, no side effect" % i,
               code == "reject" and hex_only and vlan_of(out) is None and time.time() - t0 < 5
               and tables_fingerprint() == before, "%s hex_only=%s %r" % (code, hex_only, pl))
    code, out = wifi_pc2("AA-BB-CC-DD-EE-FF:Example_Admin")
    record("INJECTION control: plain SSID Example_Admin for pc2 still -> 510", code == "accept" and vlan_of(out) == "510")
    # NAS-Port-Type is an integer attribute: arbitrary text cannot be sent; numeric
    # values other than Ethernet(15) go the wireless way and need an SSID.
    code, out = eapol(eapol_test, bench, SW_IN, "TLS", cert="pc1", extra=["61:d:4294967295"])
    record("INJECTION: NAS-Port-Type unknown value 0xffffffff -> Reject", code == "reject", code)
    for pl in ("t-admin1'; DELETE FROM radcheck; --", "t-admin1\\047; DELETE FROM radcheck; --",
               "t-admin1\\' OR \\'1\\'=\\'1"):
        code, out = radclient(prefix, SW_IN, ['NAS-IP-Address = %s' % SW_IN[0],
                                             'User-Name = "%s"' % pl.replace('"', '\\"'),
                                             'User-Password = "%s"' % ADMIN_PW])
        record("INJECTION in PAP User-Name %r -> Reject, tables intact" % pl,
               code == "reject" and tables_fingerprint() == before, out[-300:])
    for pl in ("aabbcc000001' OR '1'='1", "aabbcc000001\\047 OR 1=1 --"):
        code, out = radclient(prefix, SW_IN, ['NAS-IP-Address = %s' % SW_IN[0], 'NAS-Port-Type = Ethernet',
                                             'User-Name = "%s"' % pl, 'User-Password = "x"'])
        record("INJECTION in MAB User-Name %r -> Reject" % pl, code == "reject" and tables_fingerprint() == before,
               out[-300:])


def live_cases(eapol_test, bench, prefix, logname):
    """With radiusd RUNNING: edit ui.* and check the NEXT request reflects it."""
    pid_before = sh(["pgrep", "-f", "sbin/radiusd -fxx"]).stdout.split()
    wired = ["61:d:15"]

    def eap(cert, extra=wired):
        code, out = eapol(eapol_test, bench, SW_IN, "TLS", cert=cert, extra=extra)
        return code, vlan_of(out)

    psql("UPDATE ui.access_rule SET vlan = 222 WHERE ad_group = 'Wired-Office'")
    record("LIVE: change Wired-Office VLAN 500 -> 222, next pc1 auth -> 222", eap("pc1") == ("accept", "222"))
    psql("UPDATE ui.access_rule SET enabled = false WHERE ad_group = 'Wired-Office'")
    record("LIVE: disable Wired-Office rule, next pc1 auth -> Reject", eap("pc1")[0] == "reject")
    psql("INSERT INTO ui.access_rule (priority, connection, ssid, ad_group, vlan) "
         "VALUES (5, 'wired', NULL, 'WIRELESS-OFFICE', 333)")
    record("LIVE: add wired rule for WIRELESS-OFFICE (prio 5), next pc1 auth -> 333", eap("pc1") == ("accept", "333"))
    psql("UPDATE ui.access_rule SET priority = 1 WHERE ad_group = 'Wired-Support'")
    record("LIVE: pc2 still Wired-Support 510 (priority order kept)", eap("pc2") == ("accept", "510"))
    psql("INSERT INTO ui.access_rule (priority, connection, ssid, ad_group, vlan) "
         "VALUES (1, 'wireless', 'Guest Net-2.4', 'wired-office', 444)")
    record("LIVE: new SSID 'Guest Net-2.4' (space/dot/dash, case-insensitive group) -> 444",
           eap("pc1", ["30:s:AA-BB-CC-DD-EE-FF:Guest Net-2.4", "61:d:19"]) == ("accept", "444"))
    record("LIVE: SSID 'GuestXNet-2.4' does not match -> Reject",
           eap("pc1", ["30:s:AA-BB-CC-DD-EE-FF:GuestXNet-2.4", "61:d:19"])[0] == "reject")
    seed_live_policy()
    record("LIVE: rules restored, pc1 -> 500", eap("pc1") == ("accept", "500"))

    admin = ['NAS-IP-Address = %s' % SW_IN[0], 'User-Name = "t-admin1"', 'User-Password = "%s"' % ADMIN_PW]
    psql("UPDATE ui.setting SET value = '198.51.100.0/24' WHERE key = 'admin_subnet'")
    record("LIVE: admin_subnet -> 198.51.100.0/24, admin from the inside switch -> Reject", radclient(prefix, SW_IN, admin)[0] == "reject")
    code, _ = radclient(prefix, SW_OUT, ['NAS-IP-Address = %s' % SW_OUT[0]] + admin[1:])
    record("LIVE: admin_subnet -> 198.51.100.0/24, admin from the outside switch -> Accept", code == "accept")
    psql("UPDATE ui.setting SET value = '192.0.2.10/32' WHERE key = 'admin_subnet'")
    record("LIVE: admin_subnet /32 of the switch -> Accept", radclient(prefix, SW_IN, admin)[0] == "accept")
    psql("UPDATE ui.setting SET value = '192.0.2.0/24' WHERE key = 'admin_subnet'")
    set_priv15(True)
    code, out = radclient(prefix, SW_IN, admin)
    record("LIVE: priv15 on -> Accept with shell:priv-lvl=15", code == "accept" and has_priv15(out))
    set_priv15(False)
    code, out = radclient(prefix, SW_IN, admin)
    record("LIVE: priv15 off -> Accept without priv-lvl", code == "accept" and not has_priv15(out))
    pid_after = sh(["pgrep", "-f", "sbin/radiusd -fxx"]).stdout.split()
    record("LIVE: radiusd was not restarted during live changes", pid_before and pid_before == pid_after,
           "%s %s" % (pid_before, pid_after))


def db_down_cases(eapol_test, bench, prefix):
    """PostgreSQL stopped -> everything that needs a live decision is rejected."""
    subprocess.run(["pg_ctlcluster", "16", "main", "stop", "-m", "fast"], check=True)
    try:
        code, out = eapol(eapol_test, bench, SW_IN, "TLS", cert="pc1", extra=["61:d:15"])
        record("DB DOWN: EAP-TLS wired pc1 -> Reject (fail closed)", code == "reject", code)
        code, out = radclient(prefix, SW_IN, ['NAS-IP-Address = %s' % SW_IN[0], 'User-Name = "t-admin1"',
                                             'User-Password = "%s"' % ADMIN_PW])
        record("DB DOWN: PAP admin -> Reject (fail closed)", code == "reject", out[-300:])
        code, out = radclient(prefix, SW_IN, ['NAS-IP-Address = %s' % SW_IN[0], 'NAS-Port-Type = Ethernet',
                                             'User-Name = "aabbcc000001"', 'User-Password = "aabbcc000001"'])
        record("DB DOWN: MAB -> Reject (fail closed)", code == "reject", out[-300:])
    finally:
        subprocess.run(["pg_ctlcluster", "16", "main", "start"], check=True)
        for _ in range(50):
            if sh(["pg_isready", "-q"]).returncode == 0:
                break
            time.sleep(0.2)


# ----------------------------------------------------------------------------- RadSec
# radsecproxy (Ubuntu package, bench only) plays the access point: radclient/eapol_test
# talk UDP to it and it forwards over RadSec (TLS, TCP 2083) to radiusd with the given
# client certificate. render.py configures client ap-radsec at 127.0.0.1 expecting the
# certificate name pc1.example.net.
RADSEC_PORT = 2083
PROXY_SECRET = "TestRadsecProxySecret0123"     # UDP leg inside the bench only
PROXIES = {"pc1": 18121, "pc2": 18122, "rogue": 18123, "pc5": 18124}


def start_radsecproxy(bench, cert, port):
    pki = os.path.join(bench, "pki")
    d = os.path.join(bench, "radsecproxy")
    os.makedirs(d, exist_ok=True)
    conf = os.path.join(d, cert + ".conf")
    with open(conf, "w") as fh:
        fh.write("ListenUDP 127.0.0.1:%d\nLogLevel 3\nLogDestination file://%s/%s.log\n"
                 "tls bench {\n\tCACertificateFile %s/ca.pem\n\tCertificateFile %s/%s.pem\n"
                 "\tCertificateKeyFile %s/%s.key\n}\n"
                 "client bench-udp {\n\thost 127.0.0.1\n\ttype udp\n\tsecret %s\n}\n"
                 "server radius-admin {\n\thost radius.example.net\n\tport %d\n\ttype tls\n\ttls bench\n"
                 "\tsecret radsec\n\tStatusServer off\n}\n"
                 "realm * {\n\tserver radius-admin\n}\n"
                 % (port, d, cert, pki, pki, cert, pki, cert, PROXY_SECRET, RADSEC_PORT))
    out = open(os.path.join(d, cert + ".out"), "w")
    p = subprocess.Popen(["radsecproxy", "-f", "-c", conf], stdout=out, stderr=subprocess.STDOUT)
    for _ in range(50):
        time.sleep(0.1)
        if ":%d " % port in sh(["ss", "-lun"]).stdout:
            return p
        if p.poll() is not None:
            break
    raise RuntimeError("radsecproxy (%s) did not start, see %s/%s.out" % (cert, d, cert))


def tls_probe(bench, cert="pc1", source=None, version=None):
    """Raw TLS handshake to the RadSec port. Returns (negotiated version or None, error text)."""
    import socket
    import ssl
    pki = os.path.join(bench, "pki")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE            # the server is what is being tested
    ctx.load_cert_chain(os.path.join(pki, cert + ".pem"), os.path.join(pki, cert + ".key"))
    if version is not None:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        ctx.minimum_version = ctx.maximum_version = version
    try:
        raw = socket.create_connection(("127.0.0.1", RADSEC_PORT), timeout=5,
                                       source_address=(source, 0) if source else None)
        with ctx.wrap_socket(raw) as s:
            s.settimeout(3)
            ver = s.version()
            try:
                closed = s.recv(1) == b""          # the server hangs up on refused clients
            except (socket.timeout, ssl.SSLError, OSError):
                closed = False
            return (None, "closed after handshake") if closed else (ver, "")
    except (OSError, ssl.SSLError) as e:
        return None, str(e)


def radsec_cases(eapol_test, bench, prefix):
    import ssl

    def via(cert):
        """(radclient client tuple, UDP address of the radsecproxy using this certificate)"""
        return ("127.0.0.1", PROXY_SECRET), "127.0.0.1:%d" % PROXIES[cert]
    eth =['NAS-IP-Address = 127.0.0.1', 'NAS-Port-Type = Ethernet', 'Service-Type = Call-Check',
           'User-Name = "aabbcc000001"', 'User-Password = "aabbcc000001"',
           'Calling-Station-Id = "AA-BB-CC-00-00-01"']
    procs = []
    try:
        for cert, port in PROXIES.items():
            procs.append(start_radsecproxy(bench, cert, port))
        client, server = via("pc1")
        code, out = radclient(prefix, client, eth, server=server)
        record("RADSEC: MAB over RadSec with the expected certificate -> Accept VLAN 120",
               code == "accept" and 'Tunnel-Private-Group-Id:0 = "120"' in out, out[-500:])
        code, out = eapol(eapol_test, bench, client, "TLS", cert="pc2", extra=["61:d:15"], port=PROXIES["pc1"])
        record("RADSEC: EAP-TLS pc2 inside the pc1 RadSec connection -> pc2's VLAN 510",
               code == "accept" and vlan_of(out) == "510", code + " " + str(vlan_of(out)))
        cn = psql("SELECT coalesce(cert_cn,'') FROM radpostauth WHERE username='host/pc2.example.net'"
                  " AND reply='Access-Accept' ORDER BY id DESC LIMIT 1").strip()
        record("RADSEC: the logged client certificate is the EAP-TLS one (pc2), not the connection's (pc1)",
               "pc2" in cn and "pc1" not in cn, cn)
        client, server = via("pc2")
        code, out = radclient(prefix, client, eth, server=server)
        reason = psql("SELECT coalesce(reason,'') FROM radpostauth WHERE username='aabbcc000001'"
                      " ORDER BY id DESC LIMIT 1").strip()
        record("RADSEC: certificate name other than the client's expected name -> Reject",
               code == "reject" and "RadSec certificate does not match" in reason, code + " " + reason)
        for cert, why in (("rogue", "certificate from an untrusted CA"), ("pc5", "revoked certificate (OCSP)")):
            client, server = via(cert)
            code, out = radclient(prefix, client, eth, server=server)
            record("RADSEC: %s -> no answer (TLS refused)" % why, code == "none", code)
        ver, err = tls_probe(bench, version=ssl.TLSVersion.TLSv1_2)
        record("RADSEC: TLS 1.2 handshake accepted", ver == "TLSv1.2", err)
        ver, err = tls_probe(bench, version=ssl.TLSVersion.TLSv1_3)
        record("RADSEC: TLS 1.3 handshake accepted", ver == "TLSv1.3", err)
        ver, err = tls_probe(bench, version=ssl.TLSVersion.TLSv1_1)
        record("RADSEC: TLS 1.1 refused by the server", ver is None and "NO_PROTOCOLS_AVAILABLE" not in err, err)
        ver, err = tls_probe(bench, source=SW_IN[0])
        record("RADSEC: connection from an address that is not a RadSec client -> refused", ver is None, err)
    finally:
        for p in procs:
            stop(p)


def sql_args_audit(logname):
    """Every radius_admin_*_hex() call in the debug log must carry hex-only arguments
    (the MAB MAC argument is the policy-built AA-BB-CC-DD-EE-FF form)."""
    pat_src = re.compile(r"radius_admin_admin_source_ok_hex\('([0-9a-f]*)'\)$")
    pat_mab = re.compile(r"SELECT radius_admin_mab_hex\('[0-9A-F]{2}(-[0-9A-F]{2}){5}', '([0-9a-f]{8})?', '([0-9a-f]{2})*'\)$")
    bad, n, kinds = [], 0, set()
    with open(logname, errors="replace") as fh:
        for ln in fh:
            if "Executing select query:" not in ln:
                continue
            q_ = ln.split("Executing select query: ", 1)[1].rstrip("\n")
            m = re.search(r"radius_admin_vlan(_rule)?_hex\(", q_)
            if m:
                n += 1
                kinds.add(m.group(0))
                fn = m.group(0)[:-1]
                if not q_.startswith("SELECT %s(" % fn):
                    bad.append(q_[:160])
                    continue
                full = re.fullmatch(r"SELECT %s\((true|false), '[0-9a-f]*', '(,[0-9a-f]+)*'\)" % fn, q_)
                # the debug log cuts very long lines (~10 KB); the visible part must
                # still be a hex-only prefix of the same shape
                cut = re.fullmatch(r"SELECT %s\((true|false), '[0-9a-f]*', '(,[0-9a-f]+)*,?[0-9a-f]*" % fn, q_)
                if not (full or (len(q_) > 8000 and cut)):
                    bad.append(q_[:160])
            elif "radius_admin_admin_source_ok_hex(" in q_:
                n += 1
                if not pat_src.search(q_):
                    bad.append(q_[:160])
            elif "radius_admin_mab_hex(" in q_:
                n += 1
                kinds.add("mab")
                if not pat_mab.search(q_):
                    bad.append(q_[:160])
            elif ("radius_admin_vlan(" in q_ or "radius_admin_admin_source_ok(" in q_
                  or "FROM mab_device" in q_):
                bad.append("non-hex function or direct table query used: " + q_[:120])
    record("AUDIT: all %d live-policy SQL calls in the log carry hex-only arguments" % n, n > 20 and not bad,
           str(bad[:3]))
    record("AUDIT: the policy uses radius_admin_vlan_rule_hex and radius_admin_mab_hex",
           "radius_admin_vlan_rule_hex(" in kinds and "mab" in kinds and "radius_admin_vlan_hex(" not in kinds,
           str(sorted(kinds)))


def postauth_checks():
    rows = psql("SELECT username||'|'||coalesce(reply,'')||'|'||coalesce(authmethod,'')||'|'||"
                "coalesce(vlan,'')||'|'||coalesce(certsan,'')||'|'||coalesce(host(nasipaddress),'')||'|'||"
                "coalesce(nasporttype,'') FROM radpostauth ORDER BY id")
    rows = [r.split("|") for r in rows.splitlines() if r]
    record("radpostauth has rows", len(rows) > 10, str(len(rows)))
    cols = psql("SELECT string_agg(column_name, ',') FROM information_schema.columns "
                "WHERE table_name='radpostauth'")
    record("radpostauth has no password column", "pass" not in cols.split(","), cols)
    dump = psql("SELECT coalesce(string_agg(t::text, E'\\n'), '') FROM radpostauth t")
    leaked = [p for p in (ADMIN_PW, LEGACY_PW, "wrong-password") if p in dump]
    record("no password text anywhere in radpostauth", not leaked, str(leaked))

    def find(user, reply, method, vlan=None):
        for r in rows:
            if r[0] == user and r[1] == reply and r[2] == method and (vlan is None or r[3] == vlan):
                return r
        return None
    record("radpostauth: pap-admin Accept logged", find("t-admin1", "Access-Accept", "pap-admin") is not None)
    record("radpostauth: pap-admin Reject logged (REJECT path)", find("t-admin1", "Access-Reject", "pap-admin") is not None)
    record("radpostauth: mab Accept with vlan 120", find("aabbcc000001", "Access-Accept", "mab", "120") is not None)
    record("radpostauth: mab Reject logged", find("aabbcc0000ff", "Access-Reject", "mab") is not None)
    r = find("host/pc1.example.net", "Access-Accept", "eap-tls", "500")
    record("radpostauth: eap-tls Accept with vlan 500 and certsan", r is not None and r[4] == "pc1.example.net",
           str(r))
    record("radpostauth: eap-tls Reject logged", find("host/pc4.example.net", "Access-Reject", "eap-tls") is not None)
    record("radpostauth: nasipaddress recorded", all(r[5] for r in rows), str([r for r in rows if not r[5]][:2]))
    detail = psql("SELECT coalesce(rule_id::text,'')||'|'||coalesce(cert_cn,'')||'|'||coalesce(cert_issuer,'')||'|'||"
                  "coalesce(cert_serial,'')||'|'||coalesce(cert_expiry,'')||'|'||coalesce(ad_groups_hex,'')||'|'||"
                  "coalesce(cert_subject,'') FROM radpostauth WHERE username='host/pc1.example.net'"
                  " AND reply='Access-Accept' AND vlan='500' ORDER BY id LIMIT 1").split("|")
    rule_vlan = psql("SELECT id FROM ui.access_rule WHERE vlan=500 AND connection='wired' AND enabled"
                  " ORDER BY priority, id LIMIT 1").strip()
    record("radpostauth detail: eap-tls Accept records the access rule that assigned the VLAN",
           len(detail) == 7 and detail[0] == rule_vlan, str(detail[:1]) + " rule " + rule_vlan)
    record("radpostauth detail: client certificate CN, issuer, serial, expiry and subject recorded",
           len(detail) == 7 and all(detail[1:5]) and detail[6], str(detail))
    groups = []
    if len(detail) == 7 and detail[5]:
        try:
            groups = [bytes.fromhex(h).decode() for h in detail[5].split(",")[1:]]
        except ValueError:
            groups = ["<bad hex>"]
    record("radpostauth detail: AD groups recorded (hex list decodes to group names)",
           any(g.lower() == "wired-office" or g.lower().startswith("wired") for g in groups), str(groups[:5]))

    def reason(user, reply="Access-Reject"):
        return psql("SELECT coalesce(reason,'') FROM radpostauth WHERE username=%s AND reply=%s ORDER BY id DESC"
                    " LIMIT 1" % (q(user), q(reply))).strip()
    for user, want in (("aabbcc0000ff", "not registered"), ("aabbcc000002", "disabled"),
                       ("aabbcc000003", "expired"), ("t-notgroup", "not in group net-admins"),
                       ("host/pc4.example.net", "no enabled access rule")):
        got = reason(user)
        record("radpostauth reason for %s contains %r" % (user, want), want in got, got)
    got = psql("SELECT coalesce(reason,'') FROM radpostauth WHERE authmethod='pap-admin' AND reply='Access-Reject'"
               " AND reason LIKE '%%management subnet%%' LIMIT 1").strip()
    record("radpostauth reason: admin login from outside the management subnet", bool(got), got)
    got = psql("SELECT count(*) FROM radpostauth WHERE nasportid = 'gi1/0/7'").strip()
    record("radpostauth detail: NAS-Port-Id recorded", got not in ("", "0"), got)
    record("radpostauth: 'other' fallback used for unknown user",
           find("nosuchuser", "Access-Reject", "pap-admin") is not None or
           any(r[2] == "other" for r in rows), "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", required=True)
    ap.add_argument("--bench", required=True)
    ap.add_argument("--eapol-test")
    a = ap.parse_args()
    bench = os.path.abspath(a.bench)
    os.makedirs(bench, exist_ok=True)
    keeper_stop = threading.Event()
    threading.Thread(target=keep_traversable, args=((a.prefix, bench), keeper_stop), daemon=True).start()
    if not os.path.exists(os.path.join(bench, "pki", "ca.pem")):
        subprocess.run([os.path.join(HERE, "make-test-pki.sh"), os.path.join(bench, "pki")], check=True)
    sandbox_prereqs()
    subprocess.run(["pkill", "-f", "slapd -f %s/slapd" % bench])
    subprocess.run([os.path.join(HERE, "start-slapd.sh"), bench, BIND_PW], check=True)
    ocsp = start_ocsp(bench)
    raddb = os.path.join(bench, "raddb")
    rad = None
    try:
        seed_db()
        subprocess.run([os.path.join(HERE, "build-raddb.sh"), a.prefix, bench, BIND_PW], check=True,
                       stdout=subprocess.DEVNULL)
        traverse_ok(a.prefix, raddb)
        r = sh([os.path.join(a.prefix, "sbin", "radiusd"), "-XC", "-d", raddb])
        record("radiusd -XC", "Configuration appears to be OK" in r.stdout + r.stderr, (r.stdout + r.stderr)[-800:])
        logname = os.path.join(bench, "radiusd-base.log")
        rad = start_radiusd(a.prefix, raddb, logname)
        for priv15 in (False, True):
            set_priv15(priv15)  # live setting, no restart
            pap_cases(a.prefix, priv15)
        set_priv15(False)
        mab_cases(a.prefix)
        if a.eapol_test:
            eap_cases(a.eapol_test, bench, logname)
            injection_cases(a.eapol_test, bench, a.prefix, logname)
            live_cases(a.eapol_test, bench, a.prefix, logname)
            radsec_cases(a.eapol_test, bench, a.prefix)
            db_down_cases(a.eapol_test, bench, a.prefix)
            # Recovery without restart: the sql pool retries after pool.retry_delay
            # (30 s, unchanged from the original config).
            time.sleep(31)
            code, out = eapol(a.eapol_test, bench, SW_IN, "TLS", cert="pc1", extra=["61:d:15"])
            record("DB back (after pool retry_delay 30 s): EAP-TLS pc1 -> VLAN 500, no restart",
                   code == "accept" and vlan_of(out) == "500", code)
        else:
            record("EAP-TLS cases (eapol_test not given) - NOT RUN", False)
        stop(rad)
        rad = None
        sql_args_audit(os.path.join(bench, "radiusd-base.log"))
        postauth_checks()
    finally:
        keeper_stop.set()
        stop(rad)
        stop(ocsp)
        subprocess.run(["pkill", "-f", "slapd -f %s/slapd" % bench])
    failed = [r for r in results if not r[1]]
    print("\n%d passed, %d failed" % (len(results) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
