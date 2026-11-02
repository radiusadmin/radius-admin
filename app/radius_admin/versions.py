"""Build versions and update channels (SPEC section 16).

A build is X.Y.Z (main, stable), X.Y.Z-rc.N (testing) or X.Y.Z-dev.N (dev). For the same
X.Y.Z, dev builds sort before release candidates, which sort before the release.
"""
import json
import re

VERSION_RE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?:-(dev|rc)\.(\d{1,6}))?\Z")
CHANNELS = ("main", "testing", "dev")
CHANNEL_LABELS = {"main": "main (stable releases)", "testing": "testing (release candidates)",
                  "dev": "dev (development builds)"}
_RANK = {"dev": 0, "rc": 1, None: 2}
BUILD_FILE = "/opt/radius-admin/BUILD.json"


def parse(version):
    """Sort key for a version string, or None if it is not one."""
    m = VERSION_RE.match(version or "")
    if not m:
        return None
    x, y, z, pre, n = m.groups()
    return int(x), int(y), int(z), _RANK[pre], int(n or 0)


def newer(a, b):
    """True if version a is newer than version b (an unparsable b counts as oldest)."""
    ka, kb = parse(a), parse(b)
    return ka is not None and (kb is None or ka > kb)


def channel_of(version):
    m = VERSION_RE.match(version or "")
    if not m:
        return None
    return {"dev": "dev", "rc": "testing", None: "main"}[m.group(4)]


def installed(path=BUILD_FILE):
    """The installed build as recorded by the installer: version, channel, commit, built."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {k: str(data.get(k) or "") for k in ("version", "channel", "commit", "built")}
