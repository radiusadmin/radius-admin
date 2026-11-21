"""Licence declaration and signed licence files (SPEC section 30).

Nothing here locks a feature, makes anything read-only, touches RADIUS or contacts a server.
The admin records which case applies (free use, commercial trial, commercial licence or
written exception); the answer is a required first setup step; for a commercial licence or an
exception the admin may upload a licence file signed by the project. The portal shows the
status and, to admins only, a few gentle reminders.

Licence file (JSON, at most MAX_FILE bytes):

    {"format": 1, "key_id": "<16 hex>", "payload": {...},
     "signature": "<base64 DER ECDSA P-384 / SHA-384 signature of canonical(payload)>"}

canonical(payload) is json.dumps(payload, sort_keys=True, separators=(",", ":"),
ensure_ascii=True) encoded as ASCII. Payload keys: product ("radius-admin"), licence_id,
type ("commercial" | "exception"), licensee, tier, scope, issued, starts, expires (ISO dates;
expires may be null for an exception without end), notes. The signing key's public half
ships in licence_keys/<key_id>.pem; several keys may be present (rotation).
"""
import base64
import datetime
import hashlib
import json
import os
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import db

PRODUCT = "radius-admin"
FORMAT = 1
MAX_FILE = 16384
KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licence_keys")

CASES = {
    "free": "Free use",
    "trial": "Commercial trial",
    "commercial": "Commercial licence",
    "exception": "Written exception",
}
# What the admin chooses on the Licence page. "commercial" then offers two actions: install the
# licence file (the case becomes the file's type, commercial or exception) or start the trial.
CHOICES = {
    "free": "Free use: personal, or an organization with fewer than 50 people",
    "commercial": "Commercial: organization with 50 or more people",
}
FREE_CASES = ("free",)
FILE_CASES = ("commercial", "exception")
# case -> (days, setting that records the first day, days before the end when reminders start)
# The 90-day grace period for an organization that reached 50 people lives in the licence and
# the commercial agreement only; the portal does not track headcount or a grace clock.
PERIODS = {"trial": (60, "licence_trial_started", 16)}    # reminders from day 45
EXPIRY_NOTICE_DAYS = 30        # licence files: remind this many days before the end ...
AFTER_END_NOTICE_DAYS = 30     # ... and, on the dashboard, for this many days after it ends
PERSISTENT_NOTICES = ("trial-ended",)   # shown on every admin page until the answer changes; never hidden
SNOOZE_DAYS = 30
TYPES = ("commercial", "exception")
LICENCE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
KEY_ID_RE = re.compile(r"[0-9a-f]{16}")
TEXT_LIMITS = {"licensee": 200, "tier": 64, "scope": 300, "notes": 1000}
LICENSING_URL = "https://radiusadmin.net/#licence"


def today():
    """Today's date in UTC (tests replace this)."""
    return datetime.datetime.now(datetime.timezone.utc).date()


class LicenceError(ValueError):
    """The licence file cannot be used; the message is safe to show to the admin."""


# ----------------------------------------------------------------- signing format
def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def key_id(public_key):
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def load_public_keys(directory=None):
    """{key_id: public key} for every P-384 key in the key directory; other files are ignored."""
    directory = directory or KEY_DIR
    keys = {}
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return keys
    for name in names:
        if not name.endswith(".pem"):
            continue
        try:
            with open(os.path.join(directory, name), "rb") as f:
                k = serialization.load_pem_public_key(f.read())
        except (OSError, ValueError):
            continue
        if isinstance(k, ec.EllipticCurvePublicKey) and k.curve.name == "secp384r1":
            keys[key_id(k)] = k
    return keys


def _date(v, field, allow_none=False):
    if v is None and allow_none:
        return None
    if not isinstance(v, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        raise LicenceError("The licence file has no valid %s date." % field)
    try:
        return datetime.date.fromisoformat(v)
    except ValueError:
        raise LicenceError("The licence file has no valid %s date." % field) from None


def parse(text, keys=None):
    """The verified licence as a dict (dates as datetime.date), or LicenceError.

    Checks, in order: size, JSON, format, signature against a shipped key, then the payload
    (product, fields, dates). The payload is looked at only after the signature verifies."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            raise LicenceError("The licence file is not text.") from None
    if not text or not text.strip():
        raise LicenceError("The licence file is empty.")
    if len(text.encode("utf-8")) > MAX_FILE:
        raise LicenceError("The licence file is larger than %d bytes." % MAX_FILE)
    try:
        doc = json.loads(text)
    except ValueError:
        raise LicenceError("The licence file is not valid JSON.") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise LicenceError("This is not a radius-admin licence file (unknown format).")
    payload, sig, kid = doc.get("payload"), doc.get("signature"), doc.get("key_id")
    if not isinstance(payload, dict):
        raise LicenceError("The licence file has no licence details.")
    if not isinstance(sig, str) or not sig:
        raise LicenceError("The licence file is not signed.")
    if not isinstance(kid, str) or not KEY_ID_RE.fullmatch(kid):
        raise LicenceError("The licence file does not name its signing key.")
    keys = load_public_keys() if keys is None else keys
    pub = keys.get(kid)
    if pub is None:
        raise LicenceError("The licence file was signed with a key this version does not know.")
    try:
        raw = base64.b64decode(sig, validate=True)
        pub.verify(raw, canonical(payload), ec.ECDSA(hashes.SHA384()))
    except (ValueError, InvalidSignature):
        raise LicenceError("The licence file's signature is not valid: the file was changed or not "
                           "issued for radius-admin.") from None
    if payload.get("product") != PRODUCT:
        raise LicenceError("The licence file is for another product.")
    lid = payload.get("licence_id")
    if not isinstance(lid, str) or not LICENCE_ID_RE.fullmatch(lid):
        raise LicenceError("The licence file has no valid licence number.")
    if payload.get("type") not in TYPES:
        raise LicenceError("The licence file has an unknown licence type.")
    out = {"licence_id": lid, "type": payload["type"], "key_id": kid}
    for k, limit in TEXT_LIMITS.items():
        v = payload.get(k, "")
        if v is None:
            v = ""
        if not isinstance(v, str) or len(v) > limit:
            raise LicenceError("The licence file has an invalid %s." % k)
        out[k] = v
    if not out["licensee"].strip():
        raise LicenceError("The licence file does not name the licensee.")
    out["issued"] = _date(payload.get("issued"), "issue")
    out["starts"] = _date(payload.get("starts"), "start")
    out["expires"] = _date(payload.get("expires"), "expiry", allow_none=payload["type"] == "exception")
    if out["expires"] is not None and out["expires"] < out["starts"]:
        raise LicenceError("The licence file ends before it starts.")
    return out


# ----------------------------------------------------------------- stored state
SETTING_KEYS = ("licence_case", "licence_trial_started", "licence_file",
                "licence_declared_by", "licence_declared_at", "licence_notice_snoozed")


def load_state(conn=None):
    rows = db.query("SELECT key, value FROM ui.setting WHERE key = ANY(%s)", (list(SETTING_KEYS),), conn=conn)
    raw = {r["key"]: r["value"] for r in rows}
    return {k: raw.get(k, "") for k in SETTING_KEYS}


def _put(key, value, conn=None):
    db.execute("INSERT INTO ui.setting (key, value, updated_at) VALUES (%s, %s, now())"
               " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
               (key, value), conn=conn)


def declare(case, actor, today, conn=None):
    """Record the case. The first day of the trial is recorded the first time
    it is chosen and kept from then on, so switching away and back does not restart it."""
    if case not in CASES:
        raise ValueError("unknown licence case")
    st = load_state(conn)
    if case in PERIODS and not st[PERIODS[case][1]]:
        _put(PERIODS[case][1], today.isoformat(), conn=conn)
    _put("licence_case", case, conn=conn)
    _put("licence_declared_by", actor or "", conn=conn)
    _put("licence_declared_at", today.isoformat(), conn=conn)
    _put("licence_notice_snoozed", "", conn=conn)


def store_file(text, conn=None):
    _put("licence_file", text, conn=conn)
    _put("licence_notice_snoozed", "", conn=conn)


def remove_file(conn=None):
    _put("licence_file", "", conn=conn)


def snooze(notice_key, today, conn=None):
    _put("licence_notice_snoozed", "%s|%s" % (notice_key, (today + datetime.timedelta(days=SNOOZE_DAYS)).isoformat()),
         conn=conn)


# ----------------------------------------------------------------- status
def _iso(v):
    try:
        return datetime.date.fromisoformat(v) if v else None
    except ValueError:
        return None


def status(state, today, keys=None):
    """What the Licence page and the dashboard show, from the stored state and today's date.

    Returns {"case", "label", "level" (ok | info | warn), "summary", "detail", "notice",
    "notice_key", "licence", "file_error", "period"}. "notice" is the one-line admin reminder
    for the dashboard, or "" when none is due."""
    case = state.get("licence_case", "")
    out = {"case": case, "label": CASES.get(case, "Not declared"), "level": "ok", "summary": "",
           "detail": "", "notice": "", "notice_key": "", "licence": None, "file_error": "", "period": None}
    text = state.get("licence_file", "")
    if text:
        try:
            out["licence"] = parse(text, keys)
        except LicenceError as e:
            out["file_error"] = str(e)
    if case not in CASES:
        out.update(level="info", summary="Not answered yet: choose how this server is licensed.")
    elif case in FREE_CASES:
        out["summary"] = "Free use: personal, or an organization with fewer than 50 people (self-declared)."
    elif case in PERIODS:
        days, key, warn_before = PERIODS[case]
        start = _iso(state.get(key, "")) or today
        end = start + datetime.timedelta(days=days)        # first day after the period
        last = end - datetime.timedelta(days=1)
        left = (end - today).days
        word = "trial"
        out["period"] = {"start": start, "last": last, "days": days, "left": max(left, 0)}
        if left > 0:
            out["summary"] = "The %d-day %s started on %s and runs until %s (%d day%s left)." % (
                days, word, start.isoformat(), last.isoformat(), left, "" if left == 1 else "s")
            if left <= warn_before:
                out.update(level="warn", notice="The %s ends on %s (%d day%s left). Organizations with 50 or "
                           "more people need a commercial licence for production use after it." % (
                               word, last.isoformat(), left, "" if left == 1 else "s"),
                           notice_key="%s-ending" % case)
        else:
            out.update(level="warn", summary="The %d-day %s ended on %s. Production use now needs a commercial "
                       "licence." % (days, word, last.isoformat()))
            out.update(notice="Trial ended on %s. Upload a licence on the Licence page (organizations with 50 or "
                       "more people need one for production use)." % last.isoformat(), notice_key="trial-ended")
    else:  # commercial / exception
        lic = out["licence"]
        what = "commercial licence" if case == "commercial" else "written exception"
        if lic is None:
            out.update(level="warn", summary=("The licence file is not valid: " + out["file_error"]) if text else
                       "No licence file has been uploaded.",
                       notice="Upload the %s file on the Licence page." % what, notice_key="%s-nofile" % case)
        elif lic["starts"] > today:
            out.update(level="info", summary="Licence %s for %s starts on %s." % (
                lic["licence_id"], lic["licensee"], lic["starts"].isoformat()))
        elif lic["expires"] is None:
            out["summary"] = "Licence %s for %s, without end date." % (lic["licence_id"], lic["licensee"])
        else:
            left = (lic["expires"] - today).days
            if left >= 0:
                out["summary"] = "Licence %s for %s, valid until %s." % (
                    lic["licence_id"], lic["licensee"], lic["expires"].isoformat())
                if left < EXPIRY_NOTICE_DAYS:
                    out.update(level="warn", notice="Licence %s ends on %s (%d day%s left). Contact licensing to "
                               "renew it." % (lic["licence_id"], lic["expires"].isoformat(), left,
                                              "" if left == 1 else "s"), notice_key="expiring-" + lic["licence_id"])
            else:
                out.update(level="warn", summary="Licence %s for %s ended on %s." % (
                    lic["licence_id"], lic["licensee"], lic["expires"].isoformat()))
                if -left <= AFTER_END_NOTICE_DAYS:
                    out.update(notice="Licence %s ended on %s. Contact licensing to renew it." % (
                        lic["licence_id"], lic["expires"].isoformat()), notice_key="expired-" + lic["licence_id"])
    snoozed = state.get("licence_notice_snoozed", "")
    if out["notice"] and "|" in snoozed and out["notice_key"] not in PERSISTENT_NOTICES:
        k, until = snoozed.split("|", 1)
        u = _iso(until)
        if k == out["notice_key"] and u is not None and today < u:
            out["notice"] = ""
    return out


def dashboard_notice(today, conn=None):
    """(text, key) of the hideable admin reminder for the dashboard, or ("", ""). Persistent
    notices are shown by banner() on every admin page instead."""
    st = status(load_state(conn), today)
    if st["notice_key"] in PERSISTENT_NOTICES:
        return "", ""
    return st["notice"], st["notice_key"]


def banner(today, conn=None):
    """The persistent admin banner text (every page), or ""."""
    st = status(load_state(conn), today)
    return st["notice"] if st["notice_key"] in PERSISTENT_NOTICES else ""


def trial_info(state, today):
    """{"started", "last", "left", "ended"} of the trial (started None when never chosen)."""
    days = PERIODS["trial"][0]
    start = _iso(state.get("licence_trial_started", ""))
    if start is None:
        return {"started": None, "last": None, "left": days, "ended": False}
    last = start + datetime.timedelta(days=days - 1)
    left = (last - today).days + 1
    return {"started": start, "last": last, "left": max(left, 0), "ended": left <= 0}


def answered(conn=None):
    """True once an admin has recorded a case (the required first setup step)."""
    row = db.query_one_optional("SELECT value FROM ui.setting WHERE key = 'licence_case'", conn=conn)
    return bool(row and row["value"] in CASES)


# Pages an admin may open before answering: the licence page itself, signing in and out,
# step-up, their own account (password, MFA), single sign-on and static files.
PROMPT_EXEMPT_PREFIXES = ("licence.", "auth.", "account.", "sso.")


def prompt_redirect_needed(endpoint, method, user, session):
    """Send a fully signed-in admin to the licence prompt while it is unanswered (GET only).
    Never applies to operators, viewers, RADIUS or the API of any other page's POST."""
    if method != "GET" or not endpoint or endpoint == "static" or endpoint.startswith(PROMPT_EXEMPT_PREFIXES):
        return False
    if not user or user.get("role") != "admin" or not session or not session.get("mfa_ok"):
        return False
    if user.get("must_change_password"):
        return False
    try:
        return not answered()
    except Exception:      # never lock anyone out over this
        return False
