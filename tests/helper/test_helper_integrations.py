"""Root helper: second-factor provider installs (SPEC section 29) -- the signed catalog, the
integration_* actions and their refusals. Builds are laid out in integration_dir as the fetch
unit or the portal makes them: owned by the portal user (here the staging owner)."""
import hashlib
import json
import os
import subprocess

import pytest

from test_helper import STAGER, _write, env  # noqa: F401  (env is a fixture)

FAKE_SYSTEMCTL = r"""#!/bin/sh
echo "systemctl $*" >> "__ROOT__/systemctl.log"
case "$1" in
  start)
    [ -e "__ROOT__/startfail" ] && exit 1
    exit 0;;
  is-active)
    case "$2" in
      *integration-install*) s=$(cat "__ROOT__/unitstate" 2>/dev/null || echo inactive);;
      duoauthproxy.service) s=$(cat "__ROOT__/duostate" 2>/dev/null || echo inactive);;
      *) s=$(cat "__ROOT__/svc" 2>/dev/null || echo inactive);;
    esac
    echo "$s"; [ "$s" = active ]; exit $?;;
esac
exit 1
"""

FAKE_SS = r"""#!/bin/sh
if [ "$2" = -lun ] && [ -e "__ROOT__/duolisten" ]; then
  echo 'UNCONN 0 0 127.0.0.1:18120 0.0.0.0:*'
fi
echo 'UNCONN 0 0 0.0.0.0:1812 0.0.0.0:* users:(("radiusd",pid=42,fd=7))'
"""

BUILD = b"duo build bytes " * 64
NAME = "duoauthproxy-6.7.0-src.tgz"


def _openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


@pytest.fixture
def ienv(env):  # noqa: F811
    e = env
    e.keys = os.path.join(e.root, "keys")
    os.makedirs(e.keys)
    for name in ("key", "other"):
        _openssl("ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", os.path.join(e.keys, name + ".pem"))
    e.pub = os.path.join(e.keys, "pub.pem")
    _openssl("pkey", "-in", os.path.join(e.keys, "key.pem"), "-pubout", "-out", e.pub)
    os.chmod(e.pub, 0o644)
    e.idir = os.path.join(e.root, "integrations")
    os.makedirs(e.idir)
    os.chown(e.idir, e.stager.pw_uid, e.stager.pw_gid)
    e.opt = os.path.join(e.root, "opt-integrations")
    os.makedirs(e.opt)
    e.catalog = os.path.join(e.opt, "catalog.json")
    e.logs = os.path.join(e.root, "logs")
    os.makedirs(e.logs)
    e.duo = os.path.join(e.root, "duoauthproxy")
    e.fips = os.path.join(e.root, "fips_enabled")
    _write(e.fips, "0\n", 0o644)
    e.build = os.path.join(e.root, "BUILD.json")
    _write(e.build, json.dumps({"version": "0.3.0", "channel": "dev"}), 0o644)
    _write(os.path.join(e.root, "bin", "systemctl"), FAKE_SYSTEMCTL.replace("__ROOT__", e.root))
    _write(os.path.join(e.root, "bin", "ss"), FAKE_SS.replace("__ROOT__", e.root))
    with open(e.conf, "a") as fh:
        fh.write(f"""update_pubkey = {e.pub}
build_file = {e.build}
fips_file = {e.fips}
integration_dir = {e.idir}
integration_owner = {STAGER}
integration_catalog = {e.catalog}
integration_max_mib = 1
integration_log_dir = {e.logs}
duo_dir = {e.duo}
""")
    return e


def entry(version="6.7.0", data=BUILD, **kw):
    name = "duoauthproxy-%s-src.tgz" % version
    e = {"provider": "duo", "version": version, "file": name, "url": "https://dl.duosecurity.com/" + name,
         "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "fips": False, "fips_tested": [],
         "withdrawn": False}
    e.update(kw)
    return e


def ship(e, entries=(), serial=1, key="key", sign=True, raw=None):
    """Lay out the catalog this release ships (root-owned), signed with `key`."""
    data = raw if raw is not None else json.dumps({"format": 1, "serial": serial, "entries": list(entries)},
                                                  sort_keys=True).encode()
    with open(e.catalog, "wb") as fh:
        fh.write(data)
    os.chmod(e.catalog, 0o644)
    sig = e.catalog + ".sig"
    if sign:
        with open(sig, "wb") as fh:
            fh.write(_openssl("dgst", "-sha384", "-sign", os.path.join(e.keys, key + ".pem"), data=data))
        os.chmod(sig, 0o644)
    elif os.path.exists(sig):
        os.unlink(sig)


def upload(e, name=NAME, data=BUILD, owner=None):
    p = os.path.join(e.idir, name)
    with open(p, "wb") as fh:
        fh.write(data)
    uid = e.stager.pw_uid if owner is None else owner
    os.chown(p, uid, e.stager.pw_gid)
    return p


def started(e):
    try:
        return [ln.split()[-1] for ln in open(os.path.join(e.root, "systemctl.log")) if ln.startswith("systemctl start")]
    except FileNotFoundError:
        return []


def istate(e):
    with open(os.path.join(e.work, "integration-state.json")) as fh:
        return json.load(fh)


# ------------------------------------------------------------------ catalog
def test_no_catalog(ienv):
    r = ienv.call({"action": "integration_catalog"})
    assert r["ok"] and r["serial"] == 0 and r["entries"] == [] and r["source"] == "none"


def test_signed_catalog_is_read_and_kept(ienv):
    ship(ienv, [entry()], serial=3)
    r = ienv.call({"action": "integration_catalog"})
    assert r["ok"] and r["serial"] == 3 and r["source"] == "release" and r["entries"][0]["version"] == "6.7.0"
    assert os.path.exists(os.path.join(ienv.work, "integrations-catalog.json"))
    assert r["fips_enabled"] is False


@pytest.mark.parametrize("how", ["unsigned", "other key"])
def test_unverified_catalog_is_ignored(ienv, how):
    ship(ienv, [entry()], serial=3, sign=how != "unsigned", key="other")
    r = ienv.call({"action": "integration_catalog"})
    assert r["ok"] and r["serial"] == 0 and "not signed with the pinned key" in r["message"]


def test_older_catalog_never_replaces_a_newer_one(ienv):
    ship(ienv, [entry(withdrawn=True)], serial=5)
    assert ienv.call({"action": "integration_catalog"})["serial"] == 5
    ship(ienv, [entry()], serial=4)                     # a downgrade ships the older catalog
    r = ienv.call({"action": "integration_catalog"})
    assert r["serial"] == 5 and r["entries"][0]["withdrawn"] is True and "older than the one kept" in r["message"]
    ship(ienv, [entry(version="6.8.0", data=b"x" * 10)], serial=5)    # same serial, other content
    r = ienv.call({"action": "integration_catalog"})
    assert r["serial"] == 5 and r["entries"][0]["version"] == "6.7.0" and "differs" in r["message"]


@pytest.mark.parametrize("bad", [
    {"url": "https://evil.example.net/duoauthproxy-6.7.0-src.tgz"},
    {"file": "duoauthproxy-6.7.1-src.tgz"},
    {"provider": "other"},
    {"sha256": "AB" * 32},
    {"size": 0},
    {"fips": "yes"},
    {"fips_tested": ["has space"]},
    {"min_radius_admin": "1.x"},
])
def test_invalid_catalog_entry_refused(ienv, bad):
    ship(ienv, [entry(**bad)], serial=2)
    r = ienv.call({"action": "integration_catalog"})
    assert r["ok"] is False and "catalog" in r["message"]


def test_catalog_must_be_root_owned(ienv):
    ship(ienv, [entry()])
    os.chown(ienv.catalog, ienv.stager.pw_uid, 0)
    r = ienv.call({"action": "integration_catalog"})
    assert r["ok"] is False and "owned by root" in r["message"]


# ------------------------------------------------------------------ install
def test_install_catalog_build(ienv):
    ship(ienv, [entry()])
    upload(ienv)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME, "actor": "alice"})
    assert r["ok"], r
    assert r["verified"] == "catalog" and r["version"] == "6.7.0"
    assert started(ienv) == ["radius-admin-integration-install@duo.service"]
    st = istate(ienv)["duo"]
    assert st["state"] == "queued" and st["actor"] == "alice" and st["verified"] == "catalog"
    work = os.path.join(ienv.work, "integration", "duo")
    with open(os.path.join(work, "request.json")) as fh:
        req = json.load(fh)
    assert req == {"id": "duo", "version": "6.7.0", "file": NAME, "sha256": hashlib.sha256(BUILD).hexdigest(),
                   "size": len(BUILD), "verified": "catalog", "fips": False, "catalog_serial": 1}
    with open(os.path.join(work, NAME), "rb") as fh:
        assert fh.read() == BUILD
    assert oct(os.stat(work).st_mode & 0o777) == "0o700" and os.stat(work).st_uid == 0


def test_install_unlisted_needs_the_entered_hash(ienv):
    ship(ienv, [])
    upload(ienv)
    h = hashlib.sha256(BUILD).hexdigest()
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "not in the signed catalog" in r["message"] and h in r["message"]
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME, "sha256": "0" * 64})
    assert r["ok"] is False and "not the one entered" in r["message"]
    assert started(ienv) == [] and not os.path.exists(os.path.join(ienv.work, "integration", "duo"))
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME, "sha256": h})
    assert r["ok"] and r["verified"] == "pasted-hash"
    assert istate(ienv)["duo"]["verified"] == "pasted-hash"


def test_install_without_any_catalog_uses_the_entered_hash(ienv):
    upload(ienv)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME,
                   "sha256": hashlib.sha256(BUILD).hexdigest()})
    assert r["ok"] and r["verified"] == "pasted-hash"


def test_fips_mode_accepts_only_fips_catalog_builds(ienv):
    _write(ienv.fips, "1\n", 0o644)
    h = hashlib.sha256(BUILD).hexdigest()
    upload(ienv)
    ship(ienv, [])
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME, "sha256": h})
    assert r["ok"] is False and "FIPS" in r["message"]
    ship(ienv, [entry()], serial=2)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "FIPS-capable" in r["message"]
    ship(ienv, [entry(fips=True, fips_tested=["ubuntu-24.04-pro-fips"])], serial=3)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] and r["verified"] == "catalog"
    assert started(ienv) == ["radius-admin-integration-install@duo.service"]


def test_install_withdrawn_or_too_new_refused(ienv):
    upload(ienv)
    ship(ienv, [entry(withdrawn=True)])
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "withdrawn" in r["message"]
    ship(ienv, [entry(min_radius_admin="0.4.0")], serial=2)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "needs radius-admin 0.4.0" in r["message"]
    assert started(ienv) == []


def test_install_renamed_file_matching_another_version_refused(ienv):
    ship(ienv, [entry()])
    upload(ienv, name="duoauthproxy-6.8.0-src.tgz")
    r = ienv.call({"action": "integration_install", "id": "duo", "file": "duoauthproxy-6.8.0-src.tgz"})
    assert r["ok"] is False and "only partly" in r["message"]


@pytest.mark.parametrize("req,msg", [
    ({"id": "other", "file": NAME}, "unknown integration"),
    ({"id": "duo", "file": "../" + NAME}, "invalid file name"),
    ({"id": "duo", "file": "evil.tgz"}, "invalid file name"),
    ({"id": "duo", "file": NAME + "\n"}, "invalid file name"),
    ({"id": "duo", "file": NAME, "sha256": "ABC"}, "invalid SHA-256"),
    ({"id": "duo", "file": NAME, "sha256": "0" * 64 + "\n"}, "invalid SHA-256"),
    ({"id": ["duo"], "file": NAME}, "unknown integration"),
])
def test_install_request_validation(ienv, req, msg):
    upload(ienv)
    r = ienv.call(dict(req, action="integration_install"))
    assert r["ok"] is False and msg in r["message"]


def test_install_file_checks(ienv):
    ship(ienv, [entry()])
    p = upload(ienv, owner=0)                                  # not the portal user's
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "owned by the portal user" in r["message"]
    os.unlink(p)
    target = upload(ienv, name="other.bin")
    os.symlink(target, p)                                      # a symlink
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False
    os.unlink(p)
    os.link(target, p)                                         # a second hard link
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "single-linked" in r["message"]
    os.unlink(p)
    upload(ienv, data=b"x" * (1024 * 1024 + 1))                # larger than integration_max_mib
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "too large" in r["message"]
    os.unlink(p)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "missing" in r["message"]
    assert started(ienv) == []


def test_install_dir_must_belong_to_the_portal_user(ienv):
    ship(ienv, [entry()])
    upload(ienv)
    os.chown(ienv.idir, 0, 0)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "must belong to" in r["message"]


def test_install_refused_while_one_runs_and_failed_start_recorded(ienv):
    ship(ienv, [entry()])
    upload(ienv)
    assert ienv.call({"action": "integration_install", "id": "duo", "file": NAME})["ok"]
    _write(os.path.join(ienv.root, "unitstate"), "active\n", 0o644)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and "already running" in r["message"]
    os.unlink(os.path.join(ienv.root, "unitstate"))
    _write(os.path.join(ienv.root, "startfail"), "", 0o644)
    r = ienv.call({"action": "integration_install", "id": "duo", "file": NAME})
    assert r["ok"] is False and istate(ienv)["duo"]["state"] == "failed"


# ------------------------------------------------------------------ fetch, status, preflight, log
def test_fetch_starts_the_download_unit(ienv):
    ship(ienv, [entry()])
    r = ienv.call({"action": "integration_fetch", "id": "duo", "version": "6.7.0"})
    assert r["ok"] and r["listed"] is True
    r = ienv.call({"action": "integration_fetch", "id": "duo", "version": "6.9.9"})
    assert r["ok"] and r["listed"] is False
    assert started(ienv) == ["radius-admin-integration-fetch@duo-6.7.0.service",
                             "radius-admin-integration-fetch@duo-6.9.9.service"]


@pytest.mark.parametrize("version", ["6.7", "6.7.0;x", "6.7.0\n", "../6.7.0", 670])
def test_fetch_bad_version(ienv, version):
    r = ienv.call({"action": "integration_fetch", "id": "duo", "version": version})
    assert r["ok"] is False and started(ienv) == []


def test_fetch_refusals(ienv):
    ship(ienv, [entry(withdrawn=True)])
    r = ienv.call({"action": "integration_fetch", "id": "duo", "version": "6.7.0"})
    assert r["ok"] is False and "withdrawn" in r["message"]
    _write(ienv.fips, "1\n", 0o644)
    r = ienv.call({"action": "integration_fetch", "id": "duo", "version": "6.9.9"})
    assert r["ok"] is False and "FIPS" in r["message"]
    assert started(ienv) == []


def test_status(ienv):
    r = ienv.call({"action": "integration_status"})
    assert r["ok"] and r["integrations"]["duo"]["installed"] == {} and r["integrations"]["duo"]["service_active"] is False
    os.makedirs(ienv.duo)
    _write(os.path.join(ienv.duo, ".radius-admin"),
           json.dumps({"version": "6.7.0", "verified": "catalog", "sha256": "a" * 64, "junk": 1}), 0o644)
    _write(os.path.join(ienv.root, "duostate"), "active\n", 0o644)
    _write(os.path.join(ienv.root, "duolisten"), "", 0o644)
    d = ienv.call({"action": "integration_status"})["integrations"]["duo"]
    assert d["installed"] == {"version": "6.7.0", "verified": "catalog", "sha256": "a" * 64}
    assert d["service_active"] is True and d["listening"] is True


def test_status_marks_a_vanished_install_failed(ienv):
    ship(ienv, [entry()])
    upload(ienv)
    assert ienv.call({"action": "integration_install", "id": "duo", "file": NAME})["ok"]
    d = ienv.call({"action": "integration_status"})["integrations"]["duo"]
    assert d["state"]["state"] == "failed" and "stopped without finishing" in d["state"]["message"]


def test_preflight(ienv):
    r = ienv.call({"action": "integration_preflight", "id": "duo"})
    assert r["ok"] and {c["check"] for c in r["checks"]} >= {"disk", "os"}
    for bad in ("evil.example.net", "api-x.duosecurity.com.evil.example.net", "api-x.duosecurity.com\n", 5):
        r = ienv.call({"action": "integration_preflight", "id": "duo", "api_host": bad})
        assert r["ok"] is False and "invalid API hostname" in r["message"]


def test_log(ienv):
    name = "integration-duo-20261120T120000Z.log"
    path = os.path.join(ienv.logs, name)
    _write(path, "line one\nline two\n", 0o644)
    os.chown(path, 0, 0)
    os.makedirs(ienv.work, exist_ok=True)
    with open(os.path.join(ienv.work, "integration-state.json"), "w") as fh:
        json.dump({"duo": {"state": "done", "log": path}}, fh)
    r = ienv.call({"action": "integration_log", "id": "duo"})
    assert r["ok"] and r["text"] == "line one\nline two\n" and r["log"] == name
    r = ienv.call({"action": "integration_log", "id": "duo", "offset": 9})
    assert r["text"] == "line two\n"
    with open(os.path.join(ienv.work, "integration-state.json"), "w") as fh:
        json.dump({"duo": {"state": "done", "log": ienv.conf}}, fh)
    r = ienv.call({"action": "integration_log", "id": "duo"})
    assert r["ok"] is False and "not an install log" in r["message"]
