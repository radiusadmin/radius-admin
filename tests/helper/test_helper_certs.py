"""Certificates managed in the portal (SPEC section 30): the staged `certificates` file, its
checks, validation on a copy, apply with backup and rollback, the portal's TLS files and the
read-only cert_status action. Uses the fake services of test_helper.py; certificates and keys
are throwaway ones made with openssl for each test. Run as root."""
import json
import os
import subprocess

import pytest

from test_helper import FREERAD, _write, env  # noqa: F401  (fixture)

OCSP_EAP = """eap {
\tdefault_eap_type = tls
\ttls-config tls-common {
\t\tprivate_key_file = __RADDB__/certs/site/radius.key
\t\tcertificate_file = __RADDB__/certs/site/radius.pem
\t\tca_file = __RADDB__/certs/site/ca.pem
\t\tocsp {
\t\t\tenable = no
\t\t\toverride_cert_url = yes
\t\t\turl = "http://ocsp.example.net/ocsp"
\t\t}
\t}
}
"""

FAKE_RADIUSD_CERTS = r"""#!/bin/sh
log="__ROOT__/radiusd.log"
if [ "$1" = "-v" ]; then echo "radiusd: FreeRADIUS Version 3.2.10 (fake)"; exit 0; fi
dir=""
while [ $# -gt 0 ]; do case "$1" in -d) dir="$2"; shift;; esac; shift; done
# the candidate certificates are checked in the copy, never the live ones
if grep -q "__RADDB__/certs/site/" "$dir/mods-available/eap" 2>/dev/null; then echo "eap points at the live certs"; exit 1; fi
[ -f "$dir/certs/site/radius.pem" ] && sha256sum "$dir/certs/site/radius.pem" | cut -c1-64 > "__ROOT__/checked.sha"
echo "Configuration appears to be OK"
exit 0
"""

FAKE_SYSTEMCTL_CERTS = r"""#!/bin/sh
echo "systemctl $*" >> "__ROOT__/systemctl.log"
case "$1" in
  restart) echo active > "__ROOT__/svc"; exit 0;;
  reload) [ -e "__ROOT__/failreload" ] && exit 1; echo active > "__ROOT__/nginx"; exit 0;;
  is-active)
    st="__ROOT__/svc"; case "$*" in *nginx*) st="__ROOT__/nginx";; esac
    [ "$(cat "$st" 2>/dev/null)" = active ]; exit $?;;
esac
exit 1
"""

FAKE_SYSTEMD_RUN = r"""#!/bin/sh
echo "systemd-run $*" >> "__ROOT__/systemd-run.log"
while [ $# -gt 0 ]; do case "$1" in --*) shift;; *) break;; esac; done
exec "$@"
"""

FAKE_NGINX = r"""#!/bin/sh
echo "nginx $*" >> "__ROOT__/nginx.log"
if [ -e "__ROOT__/failnginx" ]; then echo "nginx: [emerg] SSL_CTX_use_PrivateKey failed"; exit 1; fi
exit 0
"""


def ossl(*args, data=None):
    p = subprocess.run(["openssl"] + list(args), input=data, capture_output=True, check=True)
    return p.stdout


class Pki:
    """A throwaway CA and certificates issued by it."""

    def __init__(self, d):
        self.d = d
        os.makedirs(d, exist_ok=True)
        self.ca_key, self.ca = self.make("ca", "/CN=Example Test CA", ca=True)

    def path(self, name):
        return os.path.join(self.d, name)

    def make(self, name, subj, ca=False, san=None, key="ec:P-384", days=30, eku="serverAuth", issuer=True,
             start=None):
        k = self.path(name + ".key")
        if key.startswith("rsa:"):
            ossl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:" + key[4:], "-out", k)
        else:
            ossl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + key[3:], "-out", k)
        ext = self.path(name + ".ext")
        lines = ["basicConstraints = critical, CA:%s" % ("TRUE" if ca else "FALSE")]
        if ca:
            lines.append("keyUsage = critical, keyCertSign, cRLSign")
        else:
            if eku:
                lines.append("extendedKeyUsage = " + eku)
            if san:
                lines.append("subjectAltName = " + san)
        with open(ext, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        crt = self.path(name + ".pem")
        if ca or not issuer:
            ossl("req", "-x509", "-new", "-key", k, "-subj", subj, "-days", str(days), "-sha384",
                 "-addext", lines[0], *(["-addext", lines[1]] if ca else []), "-out", crt)
        else:
            csr = self.path(name + ".csr")
            ossl("req", "-new", "-key", k, "-subj", subj, "-out", csr)
            ossl("x509", "-req", "-in", csr, "-CA", self.path("ca.pem"), "-CAkey", self.path("ca.key"),
                 "-set_serial", "0x" + os.urandom(8).hex(), "-days", str(days), "-sha384", "-extfile", ext,
                 "-out", crt)
        return open(k).read(), open(crt).read()


@pytest.fixture
def cenv(env):  # noqa: F811
    root = env.root
    bindir = os.path.join(root, "bin")
    for name, text in (("radiusd", FAKE_RADIUSD_CERTS), ("systemctl", FAKE_SYSTEMCTL_CERTS), ("nginx", FAKE_NGINX),
                       ("systemd-run", FAKE_SYSTEMD_RUN)):
        _write(os.path.join(bindir, name), text.replace("__ROOT__", root).replace("__RADDB__", env.raddb))
    eap = os.path.join(env.raddb, "mods-available", "eap")
    _write(eap, OCSP_EAP.replace("__RADDB__", env.raddb), 0o640)
    os.chown(eap, 0, env.freerad.pw_gid)
    env.tls = os.path.join(root, "tls")
    os.makedirs(env.tls, 0o700)
    os.makedirs(os.path.join(root, "sites-enabled"))
    env.site = os.path.join(root, "sites-enabled", "radius-admin")
    with open(env.conf, "a") as fh:
        fh.write("nginx = %s/nginx\nsystemd_run = %s/systemd-run\nportal_tls_dir = %s\nportal_verify_tls = false\n"
                 % (bindir, bindir, env.tls))
    env.pki = Pki(os.path.join(root, "pki"))
    env.stage()
    return env


def portal_site(env):
    _write(env.site, "server {\n    listen 192.0.2.10:443 ssl;\n    server_name radius.example.net;\n}\n", 0o644)
    for name, data, mode in (("server.crt", "OLD CERT\n", 0o644), ("server.key", "OLD KEY\n", 0o600)):
        _write(os.path.join(env.tls, name), data, mode)
    _write(os.path.join(root_of(env), "nginx"), "active\n", 0o644)


def root_of(env):
    return env.root


def stage_certs(env, doc):
    p = os.path.join(env.staging, "certificates")
    if os.path.lexists(p):
        os.unlink(p)
    with open(p, "w") as fh:
        fh.write(json.dumps(dict({"format": 1}, **doc)))
    os.chown(p, env.stager.pw_uid, env.stager.pw_gid)
    os.chmod(p, 0o600)


def server(env, name="srv", **kw):
    kw.setdefault("san", "DNS:radius.example.net")
    key, crt = env.pki.make(name, "/CN=radius.example.net", **kw)
    return {"cert": crt, "key": key}


def site_file(env, name):
    return os.path.join(env.raddb, "certs", "site", name)


def read(p):
    with open(p) as fh:
        return fh.read()


def test_cert_status_empty(cenv):
    r = cenv.call({"action": "cert_status"})
    assert r["ok"] and r["eap_server"] is None and r["client_ca"] is None
    assert r["eap_ocsp"] == {"enable": False, "url": "http://ocsp.example.net/ocsp"}
    assert r["portal_configured"] is False and r["portal_server"] is None


def test_validate_checks_candidate_in_copy_and_changes_nothing(cenv):
    s = server(cenv)
    stage_certs(cenv, {"eap_server": s, "client_ca": cenv.pki.ca})
    r = cenv.call({"action": "validate"})
    assert r["ok"], r
    assert r["certificates_changed"] == ["eap_ca", "eap_cert", "eap_key"]
    assert not os.path.exists(site_file(cenv, "radius.pem"))
    import hashlib
    assert read(os.path.join(cenv.root, "checked.sha")).strip() == hashlib.sha256(s["cert"].strip().encode() + b"\n").hexdigest()


def test_apply_installs_and_rollback_removes(cenv):
    s = server(cenv)
    stage_certs(cenv, {"eap_server": s, "client_ca": cenv.pki.ca})
    r = cenv.call({"action": "apply"})
    assert r["ok"], r
    assert r["certificates_changed"] == ["eap_ca", "eap_cert", "eap_key"] and r["certificates_sha256"]
    for n in ("radius.pem", "radius.key", "ca.pem"):
        st = os.stat(site_file(cenv, n))
        assert (st.st_uid, st.st_gid, st.st_mode & 0o777) == (0, cenv.freerad.pw_gid, 0o640)
    assert read(site_file(cenv, "radius.key")).strip() == s["key"].strip()
    st = cenv.call({"action": "cert_status"})
    assert st["eap_server"][0]["subject"] == "CN=radius.example.net"
    assert st["eap_server"][0]["key"] in ("ECDSA P-384", "ECDSA secp384r1")
    assert st["client_ca"][0]["ca"] is True and "PRIVATE KEY" not in json.dumps(st)
    # the same staged file again changes nothing
    r2 = cenv.call({"action": "validate"})
    assert r2["ok"] and r2["certificates_changed"] == []
    # rollback to the backup taken before: the files did not exist then
    rb = cenv.call({"action": "rollback", "backup_id": r["backup_id"]})
    assert rb["ok"], rb
    assert not os.path.exists(site_file(cenv, "radius.pem")) and not os.path.exists(site_file(cenv, "ca.pem"))


@pytest.mark.parametrize("case,why", [
    ("mismatch", "does not belong"), ("rsa2048", "not allowed"), ("expired", "expired"),
    ("ca_as_server", "CA certificate"), ("client_eku", "server authentication"),
    ("encrypted", "unencrypted"), ("junk", "only PEM"), ("not_ca_bundle", "not a CA"),
    ("section", "unknown section"), ("ocsp_url", "http(s) URL"), ("ocsp_nourl", "responder URL"),
])
def test_bad_certificates_refused(cenv, case, why):
    pki = cenv.pki
    if case == "mismatch":
        a, b = server(cenv, "a"), server(cenv, "b")
        doc = {"eap_server": {"cert": a["cert"], "key": b["key"]}}
    elif case == "rsa2048":
        doc = {"eap_server": server(cenv, key="rsa:2048")}
    elif case == "expired":
        key, crt = pki.make("old", "/CN=radius.example.net", san="DNS:radius.example.net", days=-1)
        doc = {"eap_server": {"cert": crt, "key": key}}
    elif case == "ca_as_server":
        doc = {"eap_server": {"cert": pki.ca, "key": pki.ca_key}}
    elif case == "client_eku":
        doc = {"eap_server": server(cenv, eku="clientAuth")}
    elif case == "encrypted":
        s = server(cenv)
        enc = ossl("pkey", "-aes256", "-passout", "pass:Example-Pass-1", data=s["key"].encode()).decode()
        doc = {"eap_server": {"cert": s["cert"], "key": enc}}
    elif case == "junk":
        s = server(cenv)
        doc = {"eap_server": {"cert": s["cert"] + "\n$INCLUDE /etc/shadow\n", "key": s["key"]}}
    elif case == "not_ca_bundle":
        doc = {"client_ca": server(cenv)["cert"]}
    elif case == "section":
        doc = {"eap_server": server(cenv), "radsec": "x"}
    elif case == "ocsp_url":
        doc = {"eap_ocsp": {"enable": True, "url": "ldap://ocsp.example.net"}}
    else:
        doc = {"eap_ocsp": {"enable": True, "url": ""}}
    stage_certs(cenv, doc)
    for action in ("validate", "apply"):
        r = cenv.call({"action": action})
        assert r["ok"] is False and why in r["message"], (action, r)
    assert not os.path.exists(site_file(cenv, "radius.pem"))


def test_ocsp_setting_applied_and_rolled_back(cenv):
    eap = os.path.join(cenv.raddb, "mods-available", "eap")
    before = read(eap)
    stage_certs(cenv, {"eap_ocsp": {"enable": True, "url": "http://ocsp2.example.net:8080/ocsp"}})
    r = cenv.call({"action": "apply"})
    assert r["ok"] and r["certificates_changed"] == ["eap_conf"], r
    after = read(eap)
    assert "\t\t\tenable = yes\n" in after and 'url = "http://ocsp2.example.net:8080/ocsp"' in after
    assert after.replace("enable = yes", "enable = no").replace("ocsp2.example.net:8080", "ocsp.example.net") == before
    st = os.stat(eap)
    assert (st.st_uid, st.st_gid, st.st_mode & 0o777) == (0, cenv.freerad.pw_gid, 0o640)
    assert cenv.call({"action": "cert_status"})["eap_ocsp"] == {"enable": True, "url": "http://ocsp2.example.net:8080/ocsp"}
    rb = cenv.call({"action": "rollback", "backup_id": r["backup_id"]})
    assert rb["ok"] and read(eap) == before


def test_portal_certificate_applied_with_nginx_reload(cenv):
    portal_site(cenv)
    s = server(cenv, "portal")
    stage_certs(cenv, {"portal_server": s, "client_ca": cenv.pki.ca})
    r = cenv.call({"action": "apply"})
    assert r["ok"], r
    assert r["certificates_changed"] == ["eap_ca", "portal_ca", "portal_cert", "portal_key"]
    assert read(os.path.join(cenv.tls, "server.key")).strip() == s["key"].strip()
    assert os.stat(os.path.join(cenv.tls, "server.key")).st_mode & 0o777 == 0o600
    assert os.stat(os.path.join(cenv.tls, "server.crt")).st_mode & 0o777 == 0o644
    assert "nginx -t" in read(os.path.join(cenv.root, "nginx.log"))
    # nginx -t runs outside the helper's sandbox, as a transient unit
    assert "--wait --pipe" in read(os.path.join(cenv.root, "systemd-run.log"))
    assert "systemctl reload nginx.service" in read(os.path.join(cenv.root, "systemctl.log"))
    st = cenv.call({"action": "cert_status"})
    assert st["portal_configured"] and st["portal_server_name"] == "radius.example.net"
    assert st["portal_server"][0]["san"] == ["DNS:radius.example.net"]


def test_portal_certificate_must_name_the_portal(cenv):
    portal_site(cenv)
    stage_certs(cenv, {"portal_server": server(cenv, "other", san="DNS:other.example.net")})
    r = cenv.call({"action": "apply"})
    assert r["ok"] is False and "does not name radius.example.net" in r["message"]
    assert read(os.path.join(cenv.tls, "server.crt")) == "OLD CERT\n"


def test_portal_without_site_refused(cenv):
    stage_certs(cenv, {"portal_server": server(cenv)})
    r = cenv.call({"action": "validate"})
    assert r["ok"] is False and "portal's nginx site" in r["message"]


@pytest.mark.parametrize("fail", ["failnginx", "failreload"])
def test_portal_failure_restores_everything(cenv, fail):
    portal_site(cenv)
    _write(os.path.join(cenv.root, fail), "", 0o644)
    s = server(cenv, "portal")
    stage_certs(cenv, {"portal_server": s, "eap_server": server(cenv, "eap")})
    r = cenv.call({"action": "apply"})
    assert r["ok"] is False and r["rolled_back"] is True, r
    assert "portal did not take" in r["message"]
    assert read(os.path.join(cenv.tls, "server.crt")) == "OLD CERT\n"
    assert read(os.path.join(cenv.tls, "server.key")) == "OLD KEY\n"
    assert not os.path.exists(site_file(cenv, "radius.pem"))
    assert cenv.live("policy") == b"# old policy\n"
