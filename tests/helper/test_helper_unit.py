"""The helper's systemd unit (deploy/systemd/radius-admin-helper@.service) runs it with
ProtectSystem=strict: every path the helper writes must be in ReadWritePaths, or the write fails
with "Read-only file system" on a real server (the tests here run the helper without systemd).
Found on a lab VM: applying a Duo configuration (and Duo's connectivity test) failed."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UNIT = os.path.join(ROOT, "deploy", "systemd", "radius-admin-helper@.service")
HELPER = os.path.join(ROOT, "helper", "radius-admin-helper")


def _rw_paths():
    with open(UNIT) as fh:
        text = fh.read()
    assert re.search(r"^ProtectSystem=strict$", text, re.M)
    paths = []
    for m in re.finditer(r"^ReadWritePaths=(.*)$", text, re.M):
        paths += [p.lstrip("-") for p in m.group(1).split()]
    return paths


def _covered(path, rw):
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in rw)


def _default_duo_dir():
    with open(HELPER) as fh:
        m = re.search(r'^\s*"duo_dir":\s*"([^"]+)"', fh.read(), re.M)
    return m.group(1)


def test_duo_dirs_the_helper_writes_are_writable_in_its_unit():
    duo = _default_duo_dir()
    rw = _rw_paths()
    # apply/rollback install conf/authproxy.cfg (atomic write in conf/)
    assert _covered(os.path.join(duo, "conf"), rw), "%s/conf is read-only for the helper" % duo
    # nothing more of the Duo tree: its programs stay read-only for the helper, and its log/ is
    # written only by the connectivity tool's own transient unit
    for p in (duo, os.path.join(duo, "usr"), os.path.join(duo, "log")):
        assert not _covered(p, rw), "%s must stay read-only for the helper" % p


def test_optional_duo_paths_do_not_break_a_server_without_duo():
    with open(UNIT) as fh:
        line = next(ln for ln in fh if ln.startswith("ReadWritePaths="))
    duo = _default_duo_dir()
    for p in line.split("=", 1)[1].split():
        if p.lstrip("-").startswith(duo):
            assert p.startswith("-"), "%s must be optional ('-'): Duo is not installed everywhere" % p
