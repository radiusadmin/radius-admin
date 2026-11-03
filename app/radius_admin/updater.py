"""Update check (SPEC section 16):  python3 -m radius_admin.updater check

Run hourly by radius-admin-update-check.timer as radius-admin; the only radius-admin
component with outbound HTTPS, and only while it runs. It lists the signed builds published
as GitHub releases, picks the newest one on the chosen channel, downloads its manifest,
signature and bundle to update_dir/<version>/ and records the result in ui.update_check.
It never trusts what it downloads: the root helper verifies the signature and hashes before
anything is installed.

Modes: off (never contacts GitHub), notify (checks once a day, or when an admin asks),
auto (as notify, checked every hour, and installs by itself: at once when FreeRADIUS does
not restart, otherwise in the weekly window). A failed or rolled-back install of a version
is never retried automatically.
"""
import datetime
import hashlib
import json
import os
import shutil
import sys
import urllib.error
import urllib.request

from . import audit, db, helper_client, versions
from .config import ConfigError, load_config
from .services import get_settings

MANIFEST, SIGNATURE = "manifest.json", "manifest.json.sig"
MAX_API = 4 * 1024 * 1024
MAX_MANIFEST = 256 * 1024
MAX_SIGNATURE = 1024
MAX_BUNDLE = 256 * 1024 * 1024
MODES = ("off", "notify", "auto")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun", "daily")
NOTIFY_INTERVAL = datetime.timedelta(hours=23)
LISTED = 20                      # newer builds whose notes are shown


class UpdateError(Exception):
    pass


def http_get(url, limit, accept="application/json", dest=None, digest=None):
    """GET an https URL (redirects stay on https). Returns the body, or writes it to dest."""
    if not url.startswith("https://"):
        raise UpdateError("refusing a non-https URL")
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "radius-admin-updater"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            if not resp.geturl().startswith("https://"):
                raise UpdateError("redirected to a non-https URL")
            if dest is None:
                body = resp.read(limit + 1)
                if len(body) > limit:
                    raise UpdateError("response too large")
                return body
            total = 0
            with open(dest, "wb") as fh:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise UpdateError("download larger than expected")
                    if digest is not None:
                        digest.update(chunk)
                    fh.write(chunk)
            return total
    except urllib.error.HTTPError as e:
        raise UpdateError("GitHub answered %s %s" % (e.code, e.reason)) from None
    except urllib.error.URLError as e:
        raise UpdateError("cannot reach GitHub (%s)" % e.reason) from None


def list_releases(cfg):
    """Published builds with all three assets: version, channel, published, notes, assets."""
    url = "%s/repos/%s/releases?per_page=100" % (cfg["update_api"].rstrip("/"), cfg["update_repo"])
    try:
        data = json.loads(http_get(url, MAX_API, "application/vnd.github+json"))
    except ValueError:
        raise UpdateError("GitHub sent an unreadable release list") from None
    out = []
    for r in data if isinstance(data, list) else []:
        if not isinstance(r, dict) or r.get("draft"):
            continue
        tag = str(r.get("tag_name") or "")
        v = tag[1:] if tag.startswith("v") else ""
        if versions.parse(v) is None:
            continue
        assets = {a.get("name"): {"url": str(a.get("browser_download_url") or ""), "size": a.get("size")}
                  for a in r.get("assets") or [] if isinstance(a, dict)}
        bundle = "radius-admin-%s.tar.gz" % v
        if not all(n in assets for n in (MANIFEST, SIGNATURE, bundle)):
            continue
        out.append({"version": v, "channel": versions.channel_of(v), "bundle": bundle,
                    "published": str(r.get("published_at") or ""), "notes": str(r.get("body") or "")[:20000],
                    "assets": assets})
    return out


def plan(releases, channel, installed):
    """(target, listed, downgrade): the build to offer on `channel`, the builds whose notes
    to show (newest first), and whether the target is older than the installed build
    (only offered when switching to another channel)."""
    on = sorted((r for r in releases if r["channel"] == channel),
                key=lambda r: versions.parse(r["version"]), reverse=True)
    if not on:
        return None, [], False
    cur = installed.get("version", "")
    newer = [r for r in on if versions.newer(r["version"], cur)]
    if newer:
        return newer[0], newer[:LISTED], False
    cur_channel = installed.get("channel") or versions.channel_of(cur)
    if on[0]["version"] != cur and cur_channel != channel:
        return on[0], [on[0]], True
    return None, [], False


def _manifest(raw, version):
    try:
        m = json.loads(raw)
    except ValueError:
        raise UpdateError("the manifest of %s is not JSON" % version) from None
    b = m.get("bundle") if isinstance(m, dict) else None
    if not (isinstance(b, dict) and m.get("version") == version
            and b.get("name") == "radius-admin-%s.tar.gz" % version
            and isinstance(b.get("size"), int) and 0 < b["size"] <= MAX_BUNDLE):
        raise UpdateError("the manifest of %s does not describe it" % version)
    return m


def download(cfg, rel):
    """Fetch the target's manifest, signature and bundle into update_dir/<version>/ and drop
    other downloads. Returns the (unverified) manifest."""
    base = cfg["update_dir"]
    v = rel["version"]
    final = os.path.join(base, v)
    try:
        with open(os.path.join(final, MANIFEST), "rb") as fh:
            m = _manifest(fh.read(MAX_MANIFEST + 1), v)
        h = hashlib.sha384()
        with open(os.path.join(final, m["bundle"]["name"]), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() == m["bundle"].get("sha384") and os.path.exists(os.path.join(final, SIGNATURE)):
            _prune(base, keep=v)
            return m
    except (OSError, UpdateError):
        pass
    part = os.path.join(base, ".%s.part" % v)
    shutil.rmtree(part, ignore_errors=True)
    os.makedirs(part, mode=0o750)
    try:
        a = rel["assets"]
        raw = http_get(a[MANIFEST]["url"], MAX_MANIFEST, "application/octet-stream")
        m = _manifest(raw, v)
        with open(os.path.join(part, MANIFEST), "wb") as fh:
            fh.write(raw)
        http_get(a[SIGNATURE]["url"], MAX_SIGNATURE, "application/octet-stream",
                 dest=os.path.join(part, SIGNATURE))
        h = hashlib.sha384()
        size = http_get(a[rel["bundle"]]["url"], m["bundle"]["size"], "application/octet-stream",
                        dest=os.path.join(part, rel["bundle"]), digest=h)
        if size != m["bundle"]["size"] or h.hexdigest() != m["bundle"].get("sha384"):
            raise UpdateError("the download of %s does not match its manifest" % v)
        shutil.rmtree(final, ignore_errors=True)
        os.rename(part, final)
    except BaseException:
        shutil.rmtree(part, ignore_errors=True)
        raise
    _prune(base, keep=v)
    return m


def _prune(base, keep):
    for name in os.listdir(base):
        if name != keep:
            shutil.rmtree(os.path.join(base, name), ignore_errors=True)


def release_restarts(rel):
    """restarts_freeradius from a release's manifest (display only; unverified)."""
    try:
        raw = http_get(rel["assets"][MANIFEST]["url"], MAX_MANIFEST, "application/octet-stream")
        return _manifest(raw, rel["version"]).get("restarts_freeradius") is not False
    except UpdateError:
        return True


def in_window(now, day, hour):
    try:
        hour = int(hour)
    except ValueError:
        return False
    return now.hour == hour and (day == "daily" or DAYS[now.weekday()] == day)


def _save(conn, **row):
    cols = ("checked_at", "ok", "error", "channel", "installed_version", "latest_version",
            "downgrade", "restarts_freeradius", "downloaded", "releases")
    vals = [row.get("checked_at") or datetime.datetime.now(datetime.timezone.utc), row["ok"],
            (row.get("error") or "")[:2000], row.get("channel") or "", (row.get("installed_version") or "")[:40],
            (row.get("latest_version") or "")[:40], bool(row.get("downgrade")),
            bool(row.get("restarts_freeradius")), bool(row.get("downloaded")),
            json.dumps(row.get("releases") or [])]
    db.execute("INSERT INTO ui.update_check (id, %s) VALUES (1, %s) ON CONFLICT (id) DO UPDATE SET %s"
               % (", ".join(cols), ", ".join(["%s"] * len(cols)),
                  ", ".join("%s = EXCLUDED.%s" % (c, c) for c in cols)), vals, conn=conn)


def last_check(conn=None):
    return db.query_one_optional("SELECT * FROM ui.update_check WHERE id = 1", conn=conn)


def check(cfg, conn, now=None, utcnow=None):
    """One run of the service. Returns a short summary (also printed by main)."""
    s = get_settings(conn)["update"]
    utcnow = utcnow or datetime.datetime.now(datetime.timezone.utc)
    now = now or datetime.datetime.now()
    mode, channel = s["mode"], s["channel"]
    if mode not in MODES or channel not in versions.CHANNELS:
        return "invalid update settings (%s, %s): nothing done" % (mode, channel)
    if mode == "off":
        return "updates are off: GitHub not contacted"
    last = last_check(conn)
    try:
        requested = datetime.datetime.fromisoformat(s.get("requested") or "")
    except ValueError:
        requested = None
    due = (last is None or last["channel"] != channel or mode == "auto"
           or utcnow - last["checked_at"] >= NOTIFY_INTERVAL
           or (requested is not None and requested > last["checked_at"]))
    if not due:
        return "checked less than a day ago"
    installed = versions.installed(cfg["build_file"])
    row = {"checked_at": utcnow, "channel": channel, "installed_version": installed["version"]}
    target = None
    try:
        releases = list_releases(cfg)
        target, listed, downgrade = plan(releases, channel, installed)
        notes = []
        for r in listed:
            notes.append({"version": r["version"], "published": r["published"], "notes": r["notes"],
                          "restarts_freeradius": True if downgrade else release_restarts(r)})
        restarts = any(n["restarts_freeradius"] for n in notes)
        if target:
            download(cfg, target)
        row.update(ok=True, latest_version=target["version"] if target else "", downgrade=downgrade,
                   restarts_freeradius=restarts, downloaded=bool(target), releases=notes)
    except (UpdateError, OSError) as e:
        target = None
        row.update(ok=False, error=str(e))
    _save(conn, **row)
    conn.commit()
    if not row["ok"]:
        return "check failed: %s" % row["error"]
    if not target:
        return "up to date (%s on %s)" % (installed["version"] or "unknown", channel)
    summary = "%s available (installed %s)" % (target["version"], installed["version"] or "unknown")
    if mode == "auto" and not row["downgrade"]:
        summary += "; " + auto_install(cfg, conn, target["version"], row["restarts_freeradius"], now)
    return summary


def auto_install(cfg, conn, version, restarts, now):
    s = get_settings(conn)["update"]
    if restarts and not in_window(now, s["window_day"], s["window_hour"]):
        return "it restarts FreeRADIUS: waiting for the maintenance window"
    try:
        st = helper_client.call(cfg["helper_socket"], "update_status", timeout=30).get("state") or {}
    except helper_client.HelperError as e:
        return "helper unavailable (%s)" % e
    if st.get("version") == version and st.get("state") in ("failed", "rolled_back", "queued", "installing"):
        return "not installing automatically: the last attempt for this version is %s" % st["state"]
    try:
        r = helper_client.call(cfg["helper_socket"], "update_install", timeout=120,
                               version=version, actor="auto")
    except helper_client.HelperError as e:
        r = {"ok": False, "message": str(e)}
    audit.write("update.auto_install", success=bool(r.get("ok")), actor="automatic update",
                object_type="update", object_id=version,
                detail={"version": version, "message": str(r.get("message", ""))[:300]}, conn=conn)
    conn.commit()
    return "install started" if r.get("ok") else "install refused: %s" % r.get("message")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["check"]:
        print("usage: python3 -m radius_admin.updater check", file=sys.stderr)
        return 2
    try:
        cfg = load_config(None)
    except ConfigError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    audit.configure_syslog(cfg["log_syslog"])
    conn = db.connect(cfg["db_dsn"])
    try:
        msg = check(cfg, conn)
    finally:
        conn.close()
    print(msg)
    audit.log_syslog("update check: " + msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
