"""tools/integrations/duo-fips-check.py (SPEC section 29.4): the maintainer's FIPS check of a Duo
build, with a fake source file, a fake installed tree and fake openssl / Python programs."""
import hashlib
import hmac
import importlib.util
import io
import json
import os
import stat
import tarfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.normpath(os.path.join(HERE, "..", "..", "tools", "integrations", "duo-fips-check.py"))
KEY = bytes.fromhex("f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813")
SO = b"\x7fELF fake provider\x00OpenSSL FIPS Provider\x00\x00\x003.1.2\x00more" + b"\x01" * 64


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("duo_fips_check", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cnf(so, mac=None):
    mac = mac or hmac.new(KEY, so, hashlib.sha256).hexdigest().upper()
    return ("openssl_conf = openssl_init\n[fips_sect]\nactivate = 1\n# comment\nmodule-mac = %s\n"
            "[openssl_init]\nproviders = provider_sect\n" % ":".join(mac[i:i + 2] for i in range(0, 64, 2))).encode()


def tarball(path, files, top="duoauthproxy-6.8.1-src"):
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo("%s/%s" % (top, name) if not name.startswith("/") else name[1:])
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return str(path)


def script(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_parsers(tool):
    assert tool.module_mac(cnf(SO).decode()) == hmac.new(KEY, SO, hashlib.sha256).hexdigest()
    assert tool.module_mac("[other]\nmodule-mac = AA\n") is None
    assert tool.provider_version(SO) == "3.1.2" and tool.provider_version(b"nothing") is None
    out = ("Providers:\n  default\n    name: OpenSSL Default Provider\n    version: 3.0.13\n    status: active\n"
           "  fips\n    name: OpenSSL FIPS Provider\n    version: 3.0.9\n    status: active\n")
    assert tool.providers(out)["fips"] == {"name": "OpenSSL FIPS Provider", "version": "3.0.9", "status": "active"}


def test_source_intact_and_tampered(tool, tmp_path):
    good = tarball(tmp_path / "good.tgz", {
        "pkgs/fips_modules/amd64/fips.so": SO, "pkgs/fips_modules/amd64/openssl.cnf": cnf(SO),
        "pkgs/fips_modules/aarch64/fips.so": SO + b"x", "pkgs/fips_modules/aarch64/openssl.cnf": cnf(SO),
        "pkgs/cryptography-43.0.1-cp37-abi3-manylinux_2_17_x86_64.whl": b"w", "Makefile": b"all:\n"})
    rep = tool.Report()
    res = tool.check_source(good, rep, arch="amd64")
    by = {c["check"]: c for c in rep.checks}
    assert by["R3"]["ok"] is True and "FIPS provider 3.1.2" in by["R3"]["detail"]
    assert by["R3-aarch64"]["ok"] is False and by["R3-aarch64"]["required"] is False   # other arch: info only
    assert res["amd64"]["sha256"] == hashlib.sha256(SO).hexdigest()
    assert rep.facts["duo_version"] == "6.8.1" and "manylinux" in rep.facts["cryptography_wheels"]
    rep = tool.Report()
    tool.check_source(good, rep, arch="aarch64")
    assert not rep.passed()
    bad = tarball(tmp_path / "bad.tgz", {"pkgs/fips_modules/amd64/fips.so": SO + b"patched",
                                         "pkgs/fips_modules/amd64/openssl.cnf": cnf(SO)})
    rep = tool.Report()
    tool.check_source(bad, rep, arch="amd64")
    assert [c["ok"] for c in rep.checks if c["check"] == "R3"] == [False] and "DOES NOT MATCH" in rep.text()
    none = tarball(tmp_path / "none.tgz", {"Makefile": b"all:\n"})
    rep = tool.Report()
    tool.check_source(none, rep, arch="amd64")
    assert "no pkgs/fips_modules" in rep.text() and not rep.passed()
    two = tarball(tmp_path / "two.tgz", {"Makefile": b"", "/other/x": b""})
    rep = tool.Report()
    assert tool.check_source(two, rep, arch="amd64") is None and not rep.passed()


def test_host(tool, tmp_path):
    proc = tmp_path / "fips_enabled"
    proc.write_text("1\n")
    ossl = script(tmp_path / "openssl", 'if [ "$1" = version ]; then echo "OpenSSL 3.0.13"; exit 0; fi\n'
                                        'printf "Providers:\\n  fips\\n    name: OpenSSL FIPS Provider\\n'
                                        '    version: 3.0.9\\n    status: active\\n"\n')
    rep = tool.Report()
    tool.check_host(rep, proc=str(proc), openssl=ossl)
    assert [(c["check"], c["ok"]) for c in rep.checks] == [("R1", True), ("R2", True)]
    proc.write_text("0\n")
    rep = tool.Report()
    tool.check_host(rep, proc=str(proc), openssl=str(tmp_path / "missing"))
    assert [(c["check"], c["ok"]) for c in rep.checks] == [("R1", False), ("R2", False)]


def _installed(tmp_path, so=SO, probe=None):
    d = tmp_path / "duo"
    (d / "usr/local/openssl").mkdir(parents=True)
    (d / "usr/local/bin").mkdir(parents=True)
    (d / "usr/local/openssl/fips.so").write_bytes(so)
    (d / "usr/local/openssl/openssl.cnf").write_bytes(cnf(SO))
    probe = probe or {"openssl": "OpenSSL 3.3.2", "fips": True, "sha256": "ok", "md5": "refused (InternalError)"}
    script(d / "usr/local/bin/python3", "echo '%s'\n" % json.dumps(probe))
    return d


def test_installed(tool, tmp_path):
    ossl = script(tmp_path / "openssl", 'test -n "$OPENSSL_CONF" || exit 1\nprintf "Providers:\\n  fips\\n'
                                        '    name: OpenSSL FIPS Provider\\n    version: 3.1.2\\n    status: active\\n"\n')
    d = _installed(tmp_path)
    rep = tool.Report()
    tool.check_installed(rep, str(d), source={tool.machine_arch(): {"sha256": hashlib.sha256(SO).hexdigest()}},
                         openssl=ossl)
    by = {c["check"]: c for c in rep.checks}
    assert by["R3i"]["ok"] and "same file as in the source" in by["R3i"]["detail"]
    assert by["R4"]["ok"] and "3.1.2" in by["R4"]["detail"]
    assert by["R5"]["ok"] and "MD5 refused" in by["R5"]["detail"]
    assert by["R6"]["ok"] is None and by["M1"]["required"] is False and rep.passed()
    # a different provider file than the source's, MD5 still working, provider not loading
    d2 = _installed(tmp_path / "b", so=SO, probe={"openssl": "x", "fips": True, "sha256": "ok", "md5": "ok"})
    rep = tool.Report()
    tool.check_installed(rep, str(d2), source={tool.machine_arch(): {"sha256": "0" * 64}},
                         openssl=script(tmp_path / "bad-openssl", "echo 'error: self test failed'; exit 1\n"))
    by = {c["check"]: c for c in rep.checks}
    assert (by["R3i"]["ok"], by["R4"]["ok"], by["R5"]["ok"]) == (False, False, False)
    assert "NOT the file from the source" in by["R3i"]["detail"] and not rep.passed()


def test_running_config_and_log(tool, tmp_path, monkeypatch):
    d = tmp_path / "duo"
    (d / "conf").mkdir(parents=True)
    (d / "log").mkdir()
    (d / "conf/authproxy.cfg").write_text("; radius-admin\n[main]\nfips_mode=true\n[radius_server_auto]\n"
                                          "failmode=secure\n")
    (d / "log/authproxy.log").write_text("x [duoauthproxy.lib.log#info] FIPS mode is not enabled\n"
                                         "y [duoauthproxy.lib.log#info] FIPS mode is enabled\n")
    monkeypatch.setattr(tool, "run", lambda argv, env=None, timeout=60: (
        0, "UNCONN 0 0 127.0.0.1:18120 0.0.0.0:*\n") if argv[0] == "ss" else (0, ""))
    rep = tool.Report()
    tool.check_running(rep, str(d))
    assert rep.checks[-1]["ok"] is True and "FIPS mode is enabled" in rep.checks[-1]["detail"]
    with open(d / "log/authproxy.log", "a") as fh:
        fh.write("z [duoauthproxy.lib.log#info] FIPS mode is not enabled\n")
    rep = tool.Report()
    tool.check_running(rep, str(d))
    assert rep.checks[-1]["ok"] is False
    (d / "conf/authproxy.cfg").write_text("[main]\n[radius_server_auto]\nfailmode=safe\n")
    rep = tool.Report()
    tool.check_running(rep, str(d))
    assert rep.checks[-1]["ok"] is False and "fips_mode=(missing) failmode=safe" in rep.checks[-1]["detail"]


def test_main_exit_status_and_json(tool, tmp_path, capsys):
    good = tarball(tmp_path / "good.tgz", {"pkgs/fips_modules/%s/fips.so" % tool.machine_arch(): SO,
                                           "pkgs/fips_modules/%s/openssl.cnf" % tool.machine_arch(): cnf(SO)})
    out = tmp_path / "r.json"
    assert tool.main(["source", good, "--json", str(out)]) == 0
    r = json.loads(out.read_text())
    assert r["passed"] is True and r["facts"]["duo_version"] == "6.8.1"
    with pytest.raises(SystemExit) as e:
        tool.main(["all"])
    assert e.value.code == 2
    assert tool.main(["installed", "--duo-dir", str(tmp_path / "nothing")]) == 1
    capsys.readouterr()
