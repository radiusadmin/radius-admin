"""Download of a second-factor provider build (SPEC section 29):

    python3 -m radius_admin.integration_fetch <provider>-<version>

Run by radius-admin-integration-fetch@<provider>-<version>.service, which the root helper
starts (action integration_fetch), as radius-admin with the update check's sandbox. It
downloads only from the provider's fixed address, into integration_dir, and reports in
integration_dir/fetch-<provider>.json. It trusts nothing it downloads: the root helper
checks the build against the signed catalog (or a SHA-256 the admin entered) before
anything is installed. A build the catalog lists is checked here too, so a broken download
is reported at once.
"""
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from .config import ConfigError, load_config

# Where each provider's builds come from. The file name and the address are fixed here and
# in the root helper; nothing else is ever downloaded.
PROVIDERS = {
    "duo": {"file": "duoauthproxy-%s-src.tgz", "url_prefix": "https://dl.duosecurity.com/",
            "host": "dl.duosecurity.com"},
}
MAX_BUILD = 128 * 1024 * 1024
MAX_CATALOG = 256 * 1024
INSTANCE_RE = re.compile(r"([a-z][a-z0-9]{0,31})-(\d{1,4}\.\d{1,4}\.\d{1,4})")


class FetchError(Exception):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def write_status(directory, pid, **status):
    """integration_dir/fetch-<provider>.json, replaced atomically (0640)."""
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".fetch-%s." % pid)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(dict(status, updated=_now()), fh, sort_keys=True)
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(directory, "fetch-%s.json" % pid))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_status(directory, pid):
    try:
        with open(os.path.join(directory, "fetch-%s.json" % pid), encoding="utf-8") as fh:
            st = json.load(fh)
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def catalog_entry(path, pid, version):
    """The catalog's entry for this build, or None (the catalog is read unverified: it only
    decides whether the download can be checked here; the helper verifies it)."""
    try:
        with open(path, "rb") as fh:
            cat = json.loads(fh.read(MAX_CATALOG + 1))
    except (OSError, ValueError):
        return None
    for e in cat.get("entries", []) if isinstance(cat, dict) else []:
        if isinstance(e, dict) and e.get("provider") == pid and e.get("version") == version:
            return e
    return None


def download(url, host, dest, limit, digest):
    req = urllib.request.Request(url, headers={"User-Agent": "radius-admin-integration-fetch"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            final = urllib.parse.urlsplit(resp.geturl())
            if final.scheme != "https" or final.hostname != host:
                raise FetchError("the download was redirected away from %s" % host)
            total = 0
            with open(dest, "wb") as fh:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise FetchError("the download is larger than expected")
                    digest.update(chunk)
                    fh.write(chunk)
            return total
    except urllib.error.HTTPError as e:
        raise FetchError("%s answered %s %s" % (host, e.code, e.reason)) from None
    except urllib.error.URLError as e:
        raise FetchError("cannot reach %s (%s)" % (host, e.reason)) from None


def fetch(cfg, instance):
    m = INSTANCE_RE.fullmatch(instance or "")
    if m is None or m.group(1) not in PROVIDERS:
        raise FetchError("invalid instance %r (expected <provider>-<X.Y.Z>)" % instance)
    pid, version = m.group(1), m.group(2)
    prov = PROVIDERS[pid]
    directory = cfg["integration_dir"]
    name = prov["file"] % version
    entry = catalog_entry(cfg["integration_catalog"], pid, version)
    if entry is not None and entry.get("file") != name:
        raise FetchError("the catalog names another file for %s %s" % (pid, version))
    limit = entry["size"] if entry is not None and isinstance(entry.get("size"), int) else MAX_BUILD
    write_status(directory, pid, state="downloading", version=version, file=name, started=_now(),
                 listed=entry is not None)
    part = os.path.join(directory, ".%s.part" % name)
    digest = hashlib.sha256()
    try:
        size = download(prov["url_prefix"] + name, prov["host"], part, min(limit, MAX_BUILD), digest)
        h = digest.hexdigest()
        if entry is not None and (size != entry.get("size") or h != entry.get("sha256")):
            raise FetchError("the download does not match the catalog (SHA-256 %s, %d bytes)" % (h, size))
        os.chmod(part, 0o640)
        os.replace(part, os.path.join(directory, name))
    except BaseException as e:
        try:
            os.unlink(part)
        except OSError:
            pass
        write_status(directory, pid, state="failed", version=version, file=name, finished=_now(),
                     listed=entry is not None, message=str(e) if isinstance(e, FetchError) else "download failed")
        raise
    for other in os.listdir(directory):          # keep one build per provider
        if other != name and re.fullmatch(re.escape(prov["file"]).replace("%s", r"[0-9.]+"), other):
            os.unlink(os.path.join(directory, other))
    write_status(directory, pid, state="done", version=version, file=name, finished=_now(),
                 listed=entry is not None, size=size, sha256=h,
                 message="downloaded%s" % ("" if entry is not None else "; not in the catalog"))
    return "%s %s downloaded (%d bytes, SHA-256 %s)" % (pid, version, size, h)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python3 -m radius_admin.integration_fetch <provider>-<version>", file=sys.stderr)
        return 2
    try:
        cfg = load_config(None)
        print(fetch(cfg, argv[0]))
    except (ConfigError, FetchError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
