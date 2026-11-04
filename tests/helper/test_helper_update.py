"""Helper update actions (SPEC section 16): update_status, update_check, update_install.

Same harness as test_helper.py (the real helper, a socketpair, fake systemctl). Downloads
are made like the update check service makes them: owned by the update user (here the
staging owner `daemon`), signed with a throwaway ECDSA P-384 key.
"""
import hashlib
import json
import os
import shutil
import subprocess

import pytest

from test_helper import STAGER, _write, env  # noqa: F401  (env is a fixture)

FAKE_SYSTEMCTL_UPD = r"""#!/bin/sh
echo "systemctl $*" >> "__ROOT__/systemctl.log"
case "$1" in
  start)
    [ -e "__ROOT__/startfail" ] && exit 1
    exit 0;;
  is-active)
    case "$2" in
      *update-install*) s=$(cat "__ROOT__/unitstate" 2>/dev/null || echo inactive); echo "$s"
                        [ "$s" = active ]; exit $?;;
    esac
    [ "$(cat "__ROOT__/svc" 2>/dev/null)" = active ]; exit $?;;
esac
exit 1
"""


def _openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


@pytest.fixture
def uenv(env):  # noqa: F811
    e = env
    e.updates = os.path.join(e.root, "updates")
    e.keys = os.path.join(e.root, "keys")
    e.build = os.path.join(e.root, "BUILD.json")
    os.makedirs(e.updates)
    os.chown(e.updates, e.stager.pw_uid, e.stager.pw_gid)
    os.makedirs(e.keys)
    for name in ("key", "other"):
        _openssl("ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out",
                 os.path.join(e.keys, name + ".pem"))
    e.pub = os.path.join(e.keys, "pub.pem")
    _openssl("pkey", "-in", os.path.join(e.keys, "key.pem"), "-pubout", "-out", e.pub)
    os.chmod(e.pub, 0o644)
    _write(e.build, json.dumps({"version": "0.1.0", "channel": "main", "commit": "c" * 40}), 0o644)
    _write(os.path.join(e.root, "bin", "systemctl"), FAKE_SYSTEMCTL_UPD.replace("__ROOT__", e.root))
    with open(e.conf, "a") as fh:
        fh.write(f"""update_dir = {e.updates}
update_owner = {STAGER}
update_pubkey = {e.pub}
build_file = {e.build}
update_max_mib = 1
""")
    return e


def download(e, version, *, key="key", bundle=b"bundle-bytes " * 100, manifest=None,
             tamper_manifest=False, tamper_bundle=False):
    """Lay out <update_dir>/<version>/ as the check service would."""
    d = os.path.join(e.updates, version)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    name = "radius-admin-%s.tar.gz" % version
    man = {"format": 1, "product": "radius-admin", "version": version, "channel": "dev",
           "commit": "a" * 40, "created": "2026-11-02T00:00:00Z", "restarts_freeradius": False,
           "bundle": {"name": name, "size": len(bundle), "sha384": hashlib.sha384(bundle).hexdigest()},
           "notes": "- test"}
    man.update(manifest or {})
    raw = json.dumps(man, sort_keys=True).encode()
    sig = _openssl("dgst", "-sha384", "-sign", os.path.join(e.keys, key + ".pem"), data=raw)
    if tamper_manifest:
        raw = raw.replace(b"- test", b"- evil")
    files = {"manifest.json": raw, "manifest.json.sig": sig,
             name: (b"X" + bundle[1:]) if tamper_bundle == "flip" else
             bundle + (b"x" if tamper_bundle else b"")}
    for n, data in files.items():
        p = os.path.join(d, n)
        with open(p, "wb") as fh:
            fh.write(data)
        os.chown(p, e.stager.pw_uid, e.stager.pw_gid)
    os.chown(d, e.stager.pw_uid, e.stager.pw_gid)
    return d


def started(e):
    try:
        return [ln.split()[-1] for ln in open(os.path.join(e.root, "systemctl.log"))
                if ln.startswith("systemctl start")]
    except FileNotFoundError:
        return []


def state(e):
    with open(os.path.join(e.work, "update-state.json")) as fh:
        return json.load(fh)


# ----------------------------------------------------------------------------- status/check

def test_update_status_reports_build_and_key(uenv):
    r = uenv.call({"action": "update_status"})
    assert r["ok"] and r["installed"]["version"] == "0.1.0"
    assert r["key_present"] is True and len(r["key_fingerprint"]) == 64
    assert r["state"] == {}


def test_update_status_without_usable_key(uenv):
    os.chmod(uenv.pub, 0o666)            # group/world-writable: not trusted
    assert uenv.call({"action": "update_status"})["key_present"] is False
    os.unlink(uenv.pub)
    assert uenv.call({"action": "update_status"})["key_present"] is False


def test_update_check_starts_the_check_unit(uenv):
    r = uenv.call({"action": "update_check"})
    assert r["ok"], r
    assert started(uenv) == ["radius-admin-update-check.service"]


# ----------------------------------------------------------------------------- install

def test_install_verified_update(uenv):
    download(uenv, "0.2.0-dev.3")
    r = uenv.call({"action": "update_install", "version": "0.2.0-dev.3", "actor": "netadmin"})
    assert r["ok"], r
    assert started(uenv) == ["radius-admin-update-install@0.2.0-dev.3.service"]
    st = state(uenv)
    assert st["state"] == "queued" and st["from"] == "0.1.0" and st["actor"] == "netadmin"
    assert st["restarts_freeradius"] is False and st["channel"] == "dev"
    copy = os.path.join(uenv.work, "update", "0.2.0-dev.3", "bundle.tar.gz")
    s = os.stat(copy)
    assert s.st_uid == 0 and s.st_mode & 0o777 == 0o600
    assert open(copy, "rb").read() == b"bundle-bytes " * 100


@pytest.mark.parametrize("kw,msg", [
    ({"tamper_manifest": True}, "signature does not verify"),
    ({"key": "other"}, "signature does not verify"),
    ({"tamper_bundle": "flip"}, "does not match its signed SHA-384"),
    ({"tamper_bundle": True}, "too large"),
    ({"manifest": {"version": "0.3.0"}}, "does not describe version"),
    ({"manifest": {"product": "other"}}, "does not describe version"),
])
def test_install_refuses_unverified_downloads(uenv, kw, msg):
    download(uenv, "0.2.0", **kw)
    r = uenv.call({"action": "update_install", "version": "0.2.0"})
    assert r["ok"] is False and msg in r["message"], r
    assert started(uenv) == []
    assert not os.path.exists(os.path.join(uenv.work, "update"))


def test_install_refuses_downgrade_unless_allowed(uenv):
    download(uenv, "0.1.0-rc.4")
    r = uenv.call({"action": "update_install", "version": "0.1.0-rc.4"})
    assert r["ok"] is False and "not newer" in r["message"]
    download(uenv, "0.1.0")
    assert uenv.call({"action": "update_install", "version": "0.1.0"})["ok"] is False
    r = uenv.call({"action": "update_install", "version": "0.1.0-rc.4", "allow_downgrade": True})
    assert r["ok"] is True, r
    # "true" as a string is not consent
    download(uenv, "0.0.9")
    r = uenv.call({"action": "update_install", "version": "0.0.9", "allow_downgrade": "true"})
    assert r["ok"] is False


@pytest.mark.parametrize("version", ["../../etc", "0.2", "0.2.0-beta.1", "0.2.0;id", "", "0.2.0\n"])
def test_install_rejects_bad_versions(uenv, version):
    r = uenv.call({"action": "update_install", "version": version})
    assert r["ok"] is False and "invalid version" in r["message"]


def test_install_needs_a_download(uenv):
    r = uenv.call({"action": "update_install", "version": "0.9.0"})
    assert r["ok"] is False and "not been downloaded" in r["message"]


def test_install_refuses_files_not_owned_by_the_update_user(uenv):
    d = download(uenv, "0.2.0")
    os.chown(os.path.join(d, "radius-admin-0.2.0.tar.gz"), 0, 0)
    r = uenv.call({"action": "update_install", "version": "0.2.0"})
    assert r["ok"] is False and "owned by the update user" in r["message"]


def test_install_refuses_symlinked_manifest(uenv):
    d = download(uenv, "0.2.0")
    os.rename(os.path.join(d, "manifest.json"), os.path.join(d, "real.json"))
    os.symlink("real.json", os.path.join(d, "manifest.json"))
    r = uenv.call({"action": "update_install", "version": "0.2.0"})
    assert r["ok"] is False and started(uenv) == []


def test_install_refuses_oversized_bundle(uenv):
    download(uenv, "0.2.0", bundle=b"x" * (1024 * 1024 + 1))   # update_max_mib = 1
    r = uenv.call({"action": "update_install", "version": "0.2.0"})
    assert r["ok"] is False and "does not describe version" in r["message"]


def test_install_without_key_is_refused(uenv):
    download(uenv, "0.2.0")
    os.unlink(uenv.pub)
    r = uenv.call({"action": "update_install", "version": "0.2.0"})
    assert r["ok"] is False and "not set up" in r["message"]


def test_install_refuses_while_another_runs(uenv):
    download(uenv, "0.2.0")
    assert uenv.call({"action": "update_install", "version": "0.2.0"})["ok"]
    _write(os.path.join(uenv.root, "unitstate"), "active\n", 0o644)
    download(uenv, "0.3.0")
    r = uenv.call({"action": "update_install", "version": "0.3.0"})
    assert r["ok"] is False and "already running" in r["message"]


def test_status_marks_a_vanished_install_as_failed(uenv):
    download(uenv, "0.2.0")
    assert uenv.call({"action": "update_install", "version": "0.2.0"})["ok"]
    st = state(uenv)
    st["state"] = "installing"
    _write(os.path.join(uenv.work, "update-state.json"), json.dumps(st), 0o600)
    r = uenv.call({"action": "update_status"})           # unit is inactive
    assert r["state"]["state"] == "failed" and "without a result" in r["state"]["message"]


def test_failed_unit_start_is_recorded(uenv):
    download(uenv, "0.2.0")
    _write(os.path.join(uenv.root, "startfail"), "", 0o644)
    r = uenv.call({"action": "update_install", "version": "0.2.0"})
    assert r["ok"] is False and "could not start" in r["message"]
    assert state(uenv)["state"] == "failed"


# ----------------------------------------------------------------------------- install log

LOGNAME = "update-0.2.0-20261104T120000Z.log"


@pytest.fixture
def lenv(uenv):
    uenv.logs = os.path.join(uenv.root, "logs")
    os.makedirs(uenv.logs)
    with open(uenv.conf, "a") as fh:
        fh.write("update_log_dir = %s\n" % uenv.logs)
    return uenv


def _log_state(e, name=LOGNAME, directory=None, text=None, state_="installing"):
    os.makedirs(e.work, mode=0o700, exist_ok=True)
    path = os.path.join(directory or e.logs, name)
    _write(os.path.join(e.work, "update-state.json"),
           json.dumps({"state": state_, "version": "0.2.0", "log": path, "message": "installing"}), 0o600)
    if text is not None:
        with open(path, "wb") as fh:
            fh.write(text)
        os.chmod(path, 0o600)
    return path


def test_update_log_before_any_install(lenv):
    r = lenv.call({"action": "update_log"})
    assert r["ok"] and r["text"] == "" and r["log"] == "" and r["state"] == {}


def test_update_log_reads_from_an_offset_in_whole_lines(lenv):
    _write(os.path.join(lenv.root, "unitstate"), "active\n", 0o644)
    _log_state(lenv, text=b"one\ntwo\nthr")
    r = lenv.call({"action": "update_log"})
    assert r["ok"], r
    assert r["text"] == "one\ntwo\n" and r["offset"] == 8 and r["size"] == 11 and r["skipped"] == 0
    assert r["log"] == LOGNAME and r["state"]["state"] == "installing"
    with open(os.path.join(lenv.logs, LOGNAME), "ab") as fh:
        fh.write(b"ee\n\xff\n")
    r = lenv.call({"action": "update_log", "offset": 8})
    assert r["text"] == "three\n�\n" and r["offset"] == 16
    assert lenv.call({"action": "update_log", "offset": 16})["text"] == ""
    r = lenv.call({"action": "update_log", "offset": 999})       # another file: from the start
    assert r["text"].startswith("one\n") and r["offset"] == 16


def test_update_log_sends_only_the_tail_of_a_long_log(lenv):
    _log_state(lenv, text=b"".join(b"line %06d\n" % i for i in range(20000)), state_="done")
    r = lenv.call({"action": "update_log"})
    assert r["ok"] and r["skipped"] > 0 and len(r["text"].encode()) <= 64 * 1024
    assert r["text"].endswith("line 019999\n") and r["offset"] == r["size"]


def test_update_log_marks_a_vanished_install_as_failed(lenv):
    _log_state(lenv, text=b"x\n")                         # unit inactive, state installing
    r = lenv.call({"action": "update_log"})
    assert r["ok"] and r["state"]["state"] == "failed"


@pytest.mark.parametrize("offset", [-1, "5", True, 1.5, 2 ** 60])
def test_update_log_refuses_a_bad_offset(lenv, offset):
    _log_state(lenv, text=b"x\n")
    r = lenv.call({"action": "update_log", "offset": offset})
    assert r["ok"] is False and "offset" in r["message"]


def test_update_log_refuses_other_files(lenv):
    secret = os.path.join(lenv.root, LOGNAME)
    _log_state(lenv, directory=lenv.root, text=b"not a log\n")     # outside update_log_dir
    r = lenv.call({"action": "update_log"})
    assert r["ok"] is False and "not an install log" in r["message"]
    _log_state(lenv, name="helper.conf", text=b"x\n")             # not an install log name
    assert lenv.call({"action": "update_log"})["ok"] is False
    _log_state(lenv, name="../" + LOGNAME)
    assert lenv.call({"action": "update_log"})["ok"] is False
    link = _log_state(lenv)
    os.symlink(secret, link)                                      # symlink: not followed
    r = lenv.call({"action": "update_log"})
    assert r["ok"] is False and "not a log" not in r.get("text", "")
    os.unlink(link)
    _log_state(lenv, text=b"x\n")
    os.chown(link, lenv.stager.pw_uid, lenv.stager.pw_gid)         # not owned by root
    r = lenv.call({"action": "update_log"})
    assert r["ok"] is False and "owned by root" in r["message"]


def test_update_log_of_a_removed_file(lenv):
    _log_state(lenv)
    r = lenv.call({"action": "update_log"})
    assert r["ok"] and r["text"] == "" and "gone" in r["message"]
