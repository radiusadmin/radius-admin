"""Hash-chained audit log (SPEC section 3.2) + syslog.

hash = sha256_hex(prev_hash + canonical_json(fields)), fields = every column
except id and hash. Inserts are serialized with pg_advisory_xact_lock(7212001).
"""
import datetime
import ipaddress
import json
import syslog

from . import db
from .crypto import sha256_hex

AUDIT_LOCK_KEY = 7212001
GENESIS = "0" * 64
FIELDS = ("at", "actor", "actor_ip", "action", "object_type", "object_id",
          "detail", "success", "prev_hash")

_syslog_enabled = True
_syslog_opened = False

# Keys that must never be written to the audit log / syslog.
_SENSITIVE = ("password", "secret", "code", "token", "totp", "csrf")


def configure_syslog(enabled: bool):
    """openlog never fails even without /dev/log; messages are then dropped."""
    global _syslog_enabled, _syslog_opened
    _syslog_enabled = enabled
    if enabled and not _syslog_opened:
        syslog.openlog("radius-admin", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        _syslog_opened = True


def log_syslog(message: str, priority=syslog.LOG_INFO):
    if not _syslog_enabled:
        return
    try:
        syslog.syslog(priority, message.replace("\n", " ")[:2000])
    except Exception:  # pragma: no cover - logging must never break the app
        pass


def _norm_ip(ip):
    if ip in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(ip).split("/")[0]))
    except ValueError:
        return None


def _norm_at(at):
    if isinstance(at, str):
        at = datetime.datetime.fromisoformat(at)
    return at.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def scrub(detail):
    """Drop keys that look like secrets; recursively."""
    if isinstance(detail, dict):
        out = {}
        for k, v in detail.items():
            if any(s in str(k).lower() for s in _SENSITIVE):
                continue
            out[str(k)] = scrub(v)
        return out
    if isinstance(detail, (list, tuple)):
        return [scrub(v) for v in detail]
    if isinstance(detail, float):
        return str(detail)  # floats are not canonical across jsonb round trip
    return detail


def canonical(row: dict) -> str:
    obj = {
        "at": _norm_at(row["at"]),
        "actor": row.get("actor"),
        "actor_ip": _norm_ip(row.get("actor_ip")),
        "action": row["action"],
        "object_type": row.get("object_type"),
        "object_id": None if row.get("object_id") is None else str(row["object_id"]),
        "detail": row.get("detail"),
        "success": bool(row["success"]),
        "prev_hash": row["prev_hash"],
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(row: dict) -> str:
    return sha256_hex(row["prev_hash"] + canonical(row))


def write(action, success=True, actor=None, actor_ip=None, object_type=None,
          object_id=None, detail=None, conn=None):
    """Append one audit record inside the caller's transaction and log to syslog."""
    detail = scrub(detail) if detail is not None else None
    # Round-trip so the hashed form equals what jsonb returns.
    if detail is not None:
        detail = json.loads(json.dumps(detail, sort_keys=True))
    with db.cursor(conn) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_KEY,))
        cur.execute("SELECT hash FROM ui.audit_log ORDER BY id DESC LIMIT 1")
        last = cur.fetchone()
        prev = last["hash"] if last else GENESIS
        cur.execute("SELECT clock_timestamp() AS now")
        at = cur.fetchone()["now"]
        row = {
            "at": at, "actor": actor, "actor_ip": _norm_ip(actor_ip), "action": action,
            "object_type": object_type,
            "object_id": None if object_id is None else str(object_id),
            "detail": detail, "success": bool(success), "prev_hash": prev,
        }
        row["hash"] = compute_hash(row)
        cur.execute(
            "INSERT INTO ui.audit_log (at, actor, actor_ip, action, object_type, object_id,"
            " detail, success, prev_hash, hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (row["at"], row["actor"], row["actor_ip"], row["action"], row["object_type"],
             row["object_id"], None if detail is None else json.dumps(detail),
             row["success"], row["prev_hash"], row["hash"]))
    log_syslog("audit action=%s success=%s actor=%s ip=%s object=%s:%s detail=%s" % (
        action, "yes" if success else "no", actor or "-", row["actor_ip"] or "-",
        object_type or "-", object_id or "-",
        json.dumps(detail, sort_keys=True) if detail is not None else "{}"),
        syslog.LOG_INFO if success else syslog.LOG_WARNING)
    return row["hash"]


def verify_chain(conn=None, batch=2000):
    """Walk the whole chain. Returns (ok, count, first_bad_id, message)."""
    prev = GENESIS
    count = 0
    last_id = 0
    while True:
        rows = db.query(
            "SELECT id, at, actor, host(actor_ip) AS actor_ip, action, object_type, object_id,"
            " detail, success, prev_hash, hash FROM ui.audit_log WHERE id > %s ORDER BY id LIMIT %s",
            (last_id, batch), conn=conn)
        if not rows:
            break
        for r in rows:
            if r["prev_hash"] != prev:
                return False, count, r["id"], "record %d: prev_hash does not link to the previous record" % r["id"]
            if compute_hash(r) != r["hash"]:
                return False, count, r["id"], "record %d: content does not match its hash" % r["id"]
            prev = r["hash"]
            count += 1
            last_id = r["id"]
    return True, count, None, "%d records verified" % count
