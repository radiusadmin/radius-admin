"""RADIUS client CSV import (SPEC section 11): parsing, planning, pending-import storage.

Flow: upload -> parse_csv() (whole file, any error = nothing imported) -> plan()
against the current DB -> preview -> confirm (step-up) -> plan() again -> execute().

Between preview and confirm the uploaded CSV text is kept server-side only:
AES-256-GCM (the app data key) in <staging_dir>/imports/<id> (0600), with the
associated data binding it to the import id, session id and user id. It expires
after 15 minutes and is deleted on confirm or cancel. No secret ever travels in a
hidden form field or cookie; the form carries only the random import id.
"""
import csv
import io
import ipaddress
import json
import os
import re
import time

from .crypto import constant_time_eq, random_token, sha256_hex

MAX_BYTES = 1024 * 1024
MAX_ROWS = 5000
MAX_DOT1X = 1000
EXPIRY_SECONDS = 15 * 60
REQUIRED_COLS = ("ip", "secret", "hostname", "secret_type")
OPTIONAL_COLS = ("key_scope", "dot1x_ports", "is_switch")
IGNORED_COLS = ()
SECRET_TYPES = ("plaintext", "encrypted", "none")
IMPORT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")

TEMPLATE_CSV = (
    "ip,secret,hostname,secret_type,key_scope,dot1x_ports\r\n"
    "192.0.2.11,Example-Plaintext-Key-0001,sw-example-01,plaintext,server,gi1/0/1-24\r\n"
    "192.0.2.12,0822455D0A16544541,sw-example-02,encrypted,global,gi1/0/1-48\r\n"
    "192.0.2.13,,sw-example-03,none,none,\r\n"
)

WARN_GLOBAL = ("Uses the switch's global radius-server key: rotating it on the switch changes the key "
               "for every RADIUS server configured there.")


STANDARD_ORDER = ("ip", "secret", "hostname", "secret_type", "key_scope", "dot1x_ports")


class ParsedRows(list):
    """The parsed rows, plus whether the file had a header row."""
    header_found = True


def classify_first_row(cells):
    """'header' if every non-empty cell is a known column name, 'data' if none is, else
    'bad-header' (a header with a typo/unknown column -- reported, never read as data)."""
    names = [c.strip().lower() for c in cells]
    known = set(REQUIRED_COLS + OPTIONAL_COLS)
    hits = sum(1 for n in names if n in known)
    nonempty = sum(1 for n in names if n)
    if hits and hits == nonempty:
        return "header"

    def _is_ip(v):
        try:
            ipaddress.ip_network(v.strip(), strict=False)
            return True
        except ValueError:
            return False
    if any(_is_ip(c) for c in cells):
        return "data"   # a real header never contains an address
    if hits >= 2:
        return "bad-header"
    return "data"


class ImportError_(Exception):
    """Carries a list of human-readable errors."""

    def __init__(self, errors):
        super().__init__("; ".join(errors))
        self.errors = errors


def decode_upload(raw: bytes) -> str:
    if len(raw) > MAX_BYTES:
        raise ImportError_(["The file is larger than 1 MiB. Split it into smaller files."])
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImportError_(["The file must be UTF-8 text (save it as CSV UTF-8)."]) from None


def _netkey(addr):
    return str(ipaddress.ip_network(addr, strict=False))


def parse_csv(text, u):
    """Return list of row dicts (secret included) or raise ImportError_ with all errors."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ImportError_(["The file is larger than 1 MiB. Split it into smaller files."])
    if text.startswith("﻿"):
        text = text[1:]
    errors, rows = [], []
    reader = csv.reader(io.StringIO(text, newline=""))
    header = None
    header_found = True
    seen_ip, seen_name = {}, {}
    try:
        for row in reader:
            lineno = reader.line_num
            if not row or all(not c.strip() for c in row):
                continue
            if header is None:
                kind = classify_first_row(row)
                if kind == "data":
                    # No header row: columns in the standard order; key_scope and
                    # dot1x_ports may be omitted at the end of the row.
                    header = list(STANDARD_ORDER)
                    header_found = False
                else:
                    header = [c.strip().lower() for c in row]
                    unknown = [c for c in header if c not in REQUIRED_COLS + OPTIONAL_COLS + IGNORED_COLS]
                    missing = [c for c in REQUIRED_COLS if c not in header]
                    dup = sorted({c for c in header if header.count(c) > 1})
                    if unknown:
                        errors.append("Line %d: unknown column(s): %s." % (lineno, ", ".join(unknown)))
                    if missing:
                        errors.append("Line %d: missing column(s): %s. The header must be "
                                      "ip,secret,hostname,secret_type,key_scope,dot1x_ports." % (lineno, ", ".join(missing)))
                    if dup:
                        errors.append("Line %d: duplicate column(s): %s." % (lineno, ", ".join(dup)))
                    if errors:
                        raise ImportError_(errors)
                    continue
            if not header_found and 4 <= len(row) < 6:
                row = list(row) + [""] * (6 - len(row))
            # dot1x_ports exported unquoted (gi1/0/1-20,gi1/0/23) splits into extra fields;
            # when it is the last column, join the overflow back into it.
            if header[-1] == "dot1x_ports" and len(row) > len(header):
                row = list(row[:len(header) - 1]) + [",".join(row[len(header) - 1:])]
            if len(rows) >= MAX_ROWS:
                errors.append("Too many rows (limit %d)." % MAX_ROWS)
                break
            if len(row) != len(header):
                if header_found:
                    errors.append("Line %d: expected %d fields, found %d." % (lineno, len(header), len(row)))
                else:
                    errors.append("Line %d: expected 4 to 6 fields (ip,secret,hostname,secret_type"
                                  "[,key_scope[,dot1x_ports]]), found %d." % (lineno, len(row)))
                continue
            f = dict(zip(header, row))
            rec = {"line": lineno, "errors": []}
            rec["hostname"] = f["hostname"].strip()
            try:
                u.validate_client_name(rec["hostname"])
            except ValueError as e:
                rec["errors"].append("hostname: %s" % e)
            try:
                rec["ip"] = u.validate_ipaddr(f["ip"].strip())
            except ValueError as e:
                rec["ip"] = f["ip"].strip()
                rec["errors"].append("ip: %s" % e)
            st = f["secret_type"].strip().lower()
            rec["secret_type"] = st
            rec["secret"] = None
            if st not in SECRET_TYPES:
                rec["errors"].append("secret_type must be plaintext, encrypted or none.")
            elif st == "plaintext":
                try:
                    u.validate_secret(f["secret"])
                    rec["secret"] = f["secret"]
                except ValueError as e:
                    rec["errors"].append("secret: %s" % e)
            # encrypted / none: the value is never kept (not usable by FreeRADIUS).
            rec["secret_ignored"] = st in ("encrypted", "none") and bool(f["secret"].strip())
            scope = f.get("key_scope", "").strip().lower()
            # server = the switch has a per-server key for this RADIUS server;
            # global = it uses its global radius-server key; none/empty = no key.
            # ("host" is accepted as an older spelling of "server".)
            scope = {"host": "server", "none": ""}.get(scope, scope)
            if scope not in ("", "server", "global"):
                rec["errors"].append("key_scope must be server, global or none.")
            rec["key_scope"] = scope or None
            ports = f.get("dot1x_ports", "")
            if len(ports) > MAX_DOT1X:
                rec["errors"].append("dot1x_ports is longer than %d characters." % MAX_DOT1X)
            if any(ord(c) < 0x20 and c not in "\t" for c in ports):
                rec["errors"].append("dot1x_ports contains control characters.")
            rec["dot1x_ports"] = ports
            sw = f.get("is_switch", "").strip().lower()
            if sw in ("yes", "y", "true", "1", "switch"):
                rec["is_switch"] = True
            elif sw in ("no", "n", "false", "0"):
                rec["is_switch"] = False
            elif sw == "":
                rec["is_switch"] = None          # not given: new clients use the import option
            else:
                rec["errors"].append("is_switch must be yes or no.")
            if not rec["errors"]:
                k = _netkey(rec["ip"])
                if k in seen_ip:
                    rec["errors"].append("ip %s already appears on line %d." % (rec["ip"], seen_ip[k]))
                else:
                    seen_ip[k] = lineno
                n = rec["hostname"].lower()
                if n in seen_name:
                    rec["errors"].append("hostname %s already appears on line %d." % (rec["hostname"], seen_name[n]))
                else:
                    seen_name[n] = lineno
            for e in rec["errors"]:
                errors.append("Line %d: %s" % (lineno, e))
            rows.append(rec)
    except csv.Error as e:
        errors.append("Line %d: not valid CSV (%s)." % (reader.line_num, str(e)[:100]))
    if header is None and not errors:
        errors.append("The file is empty. It needs at least one client.")
    elif header is not None and not rows and not errors:
        errors.append("The file has a header row but no clients.")
    if errors:
        raise ImportError_(errors)
    out = ParsedRows(rows)
    out.header_found = header_found
    return out


def plan(rows, existing, update_existing, new_require_ma, new_is_switch=False):
    """Match rows to existing clients and decide an action per row.

    existing: list of DB rows (id, name, ipaddr, secret, enabled, key_status, key_scope, dot1x_ports).
    Returns (items, errors). Items never expose secrets except via item["secret"] (used by execute)."""
    by_ip, by_name = {}, {}
    for c in existing:
        try:
            by_ip.setdefault(_netkey(c["ipaddr"]), c)
        except ValueError:
            pass
        by_name[c["name"]] = c
    items, errors = [], []
    for r in rows:
        a = by_ip.get(_netkey(r["ip"]))
        b = by_name.get(r["hostname"])
        if a is not None and b is not None and a["id"] != b["id"]:
            errors.append("Line %d: ip %s belongs to client %s but hostname %s is client %s (%s). "
                          "Fix the file or the existing clients first."
                          % (r["line"], r["ip"], a["name"], r["hostname"], b["name"], b["ipaddr"]))
            continue
        cur = a or b
        it = {"line": r["line"], "hostname": r["hostname"], "ip": r["ip"], "secret_type": r["secret_type"],
              "key_scope": r["key_scope"], "dot1x_ports": r["dot1x_ports"], "is_switch": r.get("is_switch"),
              "warnings": [], "changes": [],
              "secret": None}
        if r["secret_ignored"]:
            it["warnings"].append("The %s value in the file was ignored and not stored." % r["secret_type"])
        if r["key_scope"] == "global":
            it["warnings"].append(WARN_GLOBAL)
        if cur is None:
            it["action"] = "new"
            it["require_ma"] = new_require_ma
            if it["is_switch"] is None:
                it["is_switch"] = bool(new_is_switch)
            if r["secret_type"] == "plaintext":
                it.update(secret=r["secret"], key_status="ok", enabled=True)
            else:
                it.update(key_status="encrypted" if r["secret_type"] == "encrypted" else "missing", enabled=False)
                it["warnings"].append(
                    ("Encrypted key – not usable. " if r["secret_type"] == "encrypted" else "No key. ")
                    + "FreeRADIUS needs the plaintext shared secret; the client is created disabled until "
                      "a plaintext key is entered or generated.")
        else:
            it["id"], it["current_name"], it["current_ip"] = cur["id"], cur["name"], cur["ipaddr"]
            if not update_existing:
                it["action"] = "skip"
            else:
                if cur["name"] != r["hostname"]:
                    it["changes"].append("name %s → %s" % (cur["name"], r["hostname"]))
                if _netkey(cur["ipaddr"]) != _netkey(r["ip"]) or cur["ipaddr"] != r["ip"]:
                    it["changes"].append("ip %s → %s" % (cur["ipaddr"], r["ip"]))
                if cur["key_scope"] != r["key_scope"]:
                    it["changes"].append("key scope %s → %s" % (cur["key_scope"] or "–", r["key_scope"] or "–"))
                if (cur["dot1x_ports"] or "") != r["dot1x_ports"]:
                    it["changes"].append("802.1X ports")
                if it["is_switch"] is None:
                    it["is_switch"] = cur.get("is_switch", False)
                elif it["is_switch"] != cur.get("is_switch", False):
                    it["changes"].append("switch (SNMP monitoring) %s" % ("on" if it["is_switch"] else "off"))
                it["key_status"] = cur["key_status"]
                if r["secret_type"] == "plaintext":
                    if cur["key_status"] != "ok" or not constant_time_eq(cur["secret"] or "", r["secret"]):
                        it["changes"].append("shared secret")
                        it["secret"] = r["secret"]
                        it["key_status"] = "ok"
                    if not cur["enabled"]:
                        it["warnings"].append("The client stays disabled; enable it after review.")
                else:
                    it["warnings"].append(
                        "%s: the current key%s and enabled state are kept." % (
                            "Encrypted key – not usable" if r["secret_type"] == "encrypted" else "No key in file",
                            "" if cur["key_status"] == "ok" else " status (%s)" % cur["key_status"]))
                it["action"] = "update" if it["changes"] else "unchanged"
        items.append(it)
    # After all updates, no two clients may share a name or address.
    if not errors:
        final_name, final_ip = {}, {}
        touched = {it["id"] for it in items if it.get("id") and it["action"] == "update"}
        for c in existing:
            if c["id"] not in touched:
                final_name[c["name"]] = c["name"]
                try:
                    final_ip[_netkey(c["ipaddr"])] = c["name"]
                except ValueError:
                    pass
        for it in items:
            if it["action"] not in ("new", "update"):
                continue
            k = _netkey(it["ip"])
            if it["hostname"] in final_name or k in final_ip:
                errors.append("Line %d: after the import, %s (%s) would clash with existing client %s."
                              % (it["line"], it["hostname"], it["ip"],
                                 final_name.get(it["hostname"]) or final_ip.get(k)))
            final_name[it["hostname"]] = it["hostname"]
            final_ip[k] = it["hostname"]
    return items, errors


def fingerprint(items, options):
    """Digest of what the preview showed (no secret values; only whether a secret changes)."""
    view = [{k: it.get(k) for k in ("line", "action", "id", "hostname", "ip", "key_status", "key_scope",
                                     "dot1x_ports", "is_switch", "changes", "enabled")} | {"secret_change": it["secret"] is not None}
            for it in items]
    return sha256_hex(json.dumps({"items": view, "options": options}, sort_keys=True))


def counts(items):
    c = {"new": 0, "update": 0, "unchanged": 0, "skip": 0}
    for it in items:
        c[it["action"]] += 1
    return c


# ------------------------------------------------------- pending storage
def _dir(staging):
    d = os.path.join(staging, "imports")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _aad(import_id, session_id, user_id):
    return ("radius-admin client-import v1 id=%s session=%d user=%d" % (import_id, session_id, user_id)).encode()


def purge_expired(staging):
    d = _dir(staging)
    now = time.time()
    for name in os.listdir(d):
        p = os.path.join(d, name)
        try:
            if now - os.lstat(p).st_mtime > EXPIRY_SECONDS:
                os.unlink(p)
        except OSError:
            pass


def save_pending(staging, datakey, session_id, user_id, payload):
    purge_expired(staging)
    import_id = random_token(16)
    payload = dict(payload, created=time.time())
    blob = datakey.encrypt(json.dumps(payload).encode(), _aad(import_id, session_id, user_id))
    path = os.path.join(_dir(staging), import_id)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
    return import_id


def load_pending(staging, datakey, session_id, user_id, import_id):
    """Return payload or None (unknown, expired, other session, tampered)."""
    if not isinstance(import_id, str) or not IMPORT_ID_RE.match(import_id):
        return None
    path = os.path.join(_dir(staging), import_id)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            blob = fh.read(4 * MAX_BYTES)
        payload = json.loads(datakey.decrypt(blob, _aad(import_id, session_id, user_id)))
    except (OSError, ValueError, Exception):  # InvalidTag is not a ValueError
        return None
    if time.time() - payload.get("created", 0) > EXPIRY_SECONDS:
        delete_pending(staging, import_id)
        return None
    return payload


def delete_pending(staging, import_id):
    if isinstance(import_id, str) and IMPORT_ID_RE.match(import_id):
        try:
            os.unlink(os.path.join(_dir(staging), import_id))
        except OSError:
            pass
