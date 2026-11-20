"""Root helper: the Duo Authentication Proxy's configuration (SPEC section 29.2) -- staged as
provider-duo, checked, installed with FreeRADIUS's files, restored with them -- and the
integration_remove / integration_test actions."""
import json
import os
import sys

import pytest

from test_helper import FREERAD, GOOD_CLIENTS, GOOD_POLICY, STAGER, _write, env  # noqa: F401

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "app"))
from radius_admin import unlang  # noqa: E402

FAKE_SYSTEMCTL = r"""#!/bin/sh
echo "systemctl $*" >> "__ROOT__/systemctl.log"
case "$1" in
  restart)
    if [ "$2" = duoauthproxy.service ]; then
      if [ -e "__ROOT__/duofail" ]; then echo inactive > "__ROOT__/duostate"; exit 1; fi
      echo active > "__ROOT__/duostate"; exit 0
    fi
    if grep -q FAILSTART "__ROOT__/raddb/policy.d/radius-admin" 2>/dev/null; then
      echo inactive > "__ROOT__/svc"; exit 1
    fi
    echo active > "__ROOT__/svc"; exit 0;;
  start) exit 0;;
  is-active)
    shift; [ "$1" = --quiet ] && shift
    case "$1" in
      duoauthproxy.service) s=$(cat "__ROOT__/duostate" 2>/dev/null || echo inactive);;
      *integration*) s=inactive;;
      *) s=$(cat "__ROOT__/svc" 2>/dev/null || echo inactive);;
    esac
    echo "$s"; [ "$s" = active ]; exit $?;;
esac
exit 1
"""

FAKE_SS = r"""#!/bin/sh
if [ "$(cat "__ROOT__/svc" 2>/dev/null)" = active ]; then
  echo 'UNCONN 0 0 0.0.0.0:1812 0.0.0.0:* users:(("radiusd",pid=42,fd=7))'
fi
if [ "$(cat "__ROOT__/duostate" 2>/dev/null)" = active ]; then
  echo 'UNCONN 0 0 127.0.0.1:18120 0.0.0.0:*'
fi
"""

SETTINGS = dict(ikey="DIAAAAAAAAAAAAAAAAAA", skey="a" * 40, api_host="api-00000000.duosecurity.com",
                secret="TestDuoProxySecret0123456", primary_secret="TestMfaPrimarySecret01234")
DUO = unlang.render_duo_config(SETTINGS).encode()
OLD_DUO = b"; Duo sample\n[radius_server_auto]\nikey=\n"


@pytest.fixture
def denv(env):  # noqa: F811
    e = env
    e.duo = os.path.join(e.root, "duoauthproxy")
    os.makedirs(os.path.join(e.duo, "conf"))
    e.duocfg = os.path.join(e.duo, "conf", "authproxy.cfg")
    with open(e.duocfg, "wb") as fh:
        fh.write(OLD_DUO)
    os.chown(e.duocfg, e.stager.pw_uid, 0)          # the Duo installer: service user, mode 0640
    os.chmod(e.duocfg, 0o640)
    _write(os.path.join(e.duo, ".radius-admin"), json.dumps({"version": "6.8.1", "verified": "catalog"}), 0o644)
    e.fips = os.path.join(e.root, "fips_enabled")
    _write(e.fips, "0\n", 0o644)
    _write(os.path.join(e.root, "bin", "systemctl"), FAKE_SYSTEMCTL.replace("__ROOT__", e.root))
    _write(os.path.join(e.root, "bin", "ss"), FAKE_SS.replace("__ROOT__", e.root))
    with open(e.conf, "a") as fh:
        fh.write("duo_dir = %s\nfips_file = %s\n" % (e.duo, e.fips))
    return e


def stage_duo(e, data=DUO):
    p = os.path.join(e.staging, "provider-duo")
    if os.path.lexists(p):
        os.unlink(p)
    with open(p, "wb") as fh:
        fh.write(data)
    os.chown(p, e.stager.pw_uid, e.stager.pw_gid)
    os.chmod(p, 0o600)


def duo_live(e):
    with open(e.duocfg, "rb") as fh:
        return fh.read()


def restarts(e):
    try:
        return [ln.split()[2] for ln in open(os.path.join(e.root, "systemctl.log")) if ln.startswith("systemctl restart")]
    except FileNotFoundError:
        return []


def test_apply_installs_duo_config_first(denv):
    denv.stage()
    stage_duo(denv)
    r = denv.call({"action": "apply"})
    assert r["ok"] is True, r
    assert duo_live(denv) == DUO and r["duo_sha256"]
    st = os.stat(denv.duocfg)
    assert st.st_uid == denv.stager.pw_uid and st.st_gid == 0 and oct(st.st_mode & 0o777) == "0o640"
    assert restarts(denv) == ["duoauthproxy.service", "freeradius"]
    assert denv.live("policy") == GOOD_POLICY and "listening on 127.0.0.1:18120" in r["message"]


def test_unchanged_duo_config_does_not_restart_the_proxy(denv):
    denv.stage()
    stage_duo(denv)
    assert denv.call({"action": "apply"})["ok"]
    os.unlink(os.path.join(denv.root, "systemctl.log"))
    r = denv.call({"action": "apply"})
    assert r["ok"] and restarts(denv) == ["freeradius"]


def test_without_staged_duo_config_the_proxy_is_left_alone(denv):
    denv.stage()
    r = denv.call({"action": "apply"})
    assert r["ok"] and duo_live(denv) == OLD_DUO and restarts(denv) == ["freeradius"] and "duo_sha256" not in r


def test_duo_failing_to_start_restores_its_config_and_leaves_freeradius(denv):
    denv.stage()
    stage_duo(denv)
    _write(os.path.join(denv.root, "duofail"), "", 0o644)
    r = denv.call({"action": "apply"})
    assert r["ok"] is False and r["rolled_back"] is True and "did not start" in r["message"]
    assert duo_live(denv) == OLD_DUO
    assert denv.live("policy") == b"# old policy\n" and "freeradius" not in restarts(denv)


def test_freeradius_failing_restores_both(denv):
    denv.stage(policy=GOOD_POLICY + b"# FAILSTART\n")
    stage_duo(denv)
    r = denv.call({"action": "apply"})
    assert r["ok"] is False and r["rolled_back"] is True
    assert duo_live(denv) == OLD_DUO and denv.live("policy") == b"# old policy\n"


def test_rollback_restores_the_duo_config(denv):
    import time
    denv.stage()
    stage_duo(denv)
    first = denv.call({"action": "apply"})          # backup 1 holds Duo's sample
    assert first["ok"]
    time.sleep(1.1)
    newer = DUO.replace(b"failmode=secure", b"failmode=safe")
    stage_duo(denv, newer)
    second = denv.call({"action": "apply"})         # backup 2 holds DUO
    assert second["ok"] and duo_live(denv) == newer
    time.sleep(1.1)
    r = denv.call({"action": "rollback", "backup_id": second["backup_id"]})
    assert r["ok"], r
    assert duo_live(denv) == DUO
    time.sleep(1.1)
    # back to before Duo was configured: Duo's sample is not put back, FreeRADIUS is
    r = denv.call({"action": "rollback", "backup_id": first["backup_id"]})
    assert r["ok"], r
    assert duo_live(denv) == DUO and denv.live("policy") == b"# old policy\n"


@pytest.mark.parametrize("bad", [
    DUO.replace(b"; radius-admin", b"; someone"),                           # header
    DUO.replace(b"host=127.0.0.1", b"host=198.51.100.7"),                   # primary auth elsewhere
    DUO.replace(b"interface=127.0.0.1", b"interface=0.0.0.0"),              # listening on every address
    DUO.replace(b"[radius_client]", b"[ad_client]"),                        # another section
    DUO + b"\n[http_proxy]\nport=3128\n",
    DUO.replace(b"factors=auto", b"factors=auto\nexempt_ou_1=OU=x"),        # unknown key
    DUO.replace(b"failmode=secure", b"failmode=open"),
    DUO.replace(b"api_host=api-00000000.duosecurity.com", b"api_host=evil.example.net"),
    DUO.replace(b"force_message_authenticator=true\n", b""),                # required key missing
    DUO.replace(b"secret=TestMfaPrimarySecret01234", b"secret=Test;Mfa#Primary0123"),
    DUO.replace(b"port=18121", b"port=99"),
    DUO + b"[main]\nlog_auth_events=true\n",                                # duplicate section
])
def test_duo_grammar_refusals(denv, bad):
    denv.stage()
    stage_duo(denv, bad)
    r = denv.call({"action": "validate"})
    assert r["ok"] is False
    r = denv.call({"action": "apply"})
    assert r["ok"] is False and duo_live(denv) == OLD_DUO and denv.live("policy") == b"# old policy\n"


def test_fips_mode_needs_fips_mode_and_failmode_secure(denv):
    _write(denv.fips, "1\n", 0o644)
    denv.stage()
    stage_duo(denv)                                                  # rendered without fips_mode
    assert denv.call({"action": "apply"})["ok"] is False
    stage_duo(denv, unlang.render_duo_config(dict(SETTINGS, failmode="safe"), fips=True).encode())
    r = denv.call({"action": "apply"})
    assert r["ok"] is True, r
    assert b"fips_mode=true" in duo_live(denv) and b"failmode=secure" in duo_live(denv)


def test_duo_config_without_duo_installed_is_refused(denv):
    os.unlink(os.path.join(denv.duo, ".radius-admin"))
    denv.stage()
    stage_duo(denv)
    r = denv.call({"action": "apply"})
    assert r["ok"] is False and "not installed" in r["message"]


def test_staged_duo_symlink_refused(denv):
    denv.stage()
    other = os.path.join(denv.staging, "other")
    with open(other, "wb") as fh:
        fh.write(DUO)
    os.chown(other, denv.stager.pw_uid, denv.stager.pw_gid)
    os.symlink(other, os.path.join(denv.staging, "provider-duo"))
    assert denv.call({"action": "apply"})["ok"] is False


# ------------------------------------------------------------------ remove, test
def test_remove_refused_while_freeradius_uses_duo(denv):
    with open(os.path.join(denv.raddb, "radius-admin-clients.conf"), "wb") as fh:
        fh.write(GOOD_CLIENTS + b"\nlisten {\n\ttype = auth\n\tvirtual_server = radius-admin-mfa-primary\n}\n")
    r = denv.call({"action": "integration_remove", "id": "duo"})
    assert r["ok"] is False and "apply the changes first" in r["message"]


def test_remove_starts_the_remove_unit(denv):
    r = denv.call({"action": "integration_remove", "id": "duo", "actor": "alice"})
    assert r["ok"], r
    log = open(os.path.join(denv.root, "systemctl.log")).read()
    assert "start --no-block radius-admin-integration-remove@duo.service" in log
    with open(os.path.join(denv.work, "integration-state.json")) as fh:
        st = json.load(fh)["duo"]
    assert st["action"] == "remove" and st["actor"] == "alice" and st["version"] == "6.8.1"


def test_remove_of_a_foreign_install_refused(denv):
    os.unlink(os.path.join(denv.duo, ".radius-admin"))
    r = denv.call({"action": "integration_remove", "id": "duo"})
    assert r["ok"] is False and "not installed by radius-admin" in r["message"]


def test_connectivity_tool_output_redacted(denv):
    d = os.path.join(denv.duo, "usr", "local", "bin")
    os.makedirs(d)
    tool = os.path.join(d, "authproxy_connectivity_tool")
    _write(tool, "#!/bin/sh\necho 'Testing section radius_server_auto'\necho 'skey=SHOULDNOTSHOW'\n"
                 "echo 'The Auth Proxy was able to reach Duo'\nexit 0\n", 0o755)
    r = denv.call({"action": "integration_test", "id": "duo"})
    assert r["ok"] and r["passed"] is True and "able to reach Duo" in r["output"] and "SHOULDNOTSHOW" not in r["output"]
    os.chmod(tool, 0o777)
    r = denv.call({"action": "integration_test", "id": "duo"})
    assert r["ok"] is False and "only root can change" in r["message"]
