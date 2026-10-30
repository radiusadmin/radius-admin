"""MFA verification and account lockout bookkeeping."""
from flask import current_app

from . import db
from .crypto import totp_verify
from .security import cert_matches, cfg, client_ip


def totp_aad(user_id):
    return b"radius-admin totp v1 user=%d" % user_id


def decrypt_totp(user):
    if not user.get("totp_secret_enc"):
        return None
    return current_app.config["RA_DATA_KEY"].decrypt(bytes(user["totp_secret_enc"]), totp_aad(user["id"]))


def encrypt_totp(user_id, secret):
    return current_app.config["RA_DATA_KEY"].encrypt(secret, totp_aad(user_id))


def check_totp(user, code):
    """Verify code with replay protection; on success persist the step atomically."""
    key = decrypt_totp(user)
    if key is None:
        return False
    step = totp_verify(key, code, user.get("totp_last_step"))
    if step is None:
        return False
    # Conditional update guards against two concurrent uses of the same code.
    n = db.execute("UPDATE ui.admin_user SET totp_last_step=%s WHERE id=%s AND"
                   " (totp_last_step IS NULL OR totp_last_step < %s)", (step, user["id"], step))
    return n == 1


def verify_second_factor(user, code):
    """Verify the user's enrolled factor. Returns (ok, method)."""
    if user.get("mfa_method") == "cert":
        return cert_matches(user), "cert"
    if user.get("mfa_method") == "totp":
        return check_totp(user, code), "totp"
    return False, None


# --------------------------------------------------------------- lockout
def ip_throttled():
    c = cfg()
    ip = client_ip()
    if not ip:
        return False
    row = db.query_one(
        "SELECT count(*) AS n FROM ui.login_attempt WHERE ip = %s AND NOT success"
        " AND at > now() - make_interval(mins => %s)", (ip, c["ip_failure_window_minutes"]))
    return row["n"] >= c["ip_failure_limit"]


def record_attempt(username, success):
    db.execute("INSERT INTO ui.login_attempt (ip, username, success) VALUES (%s,%s,%s)",
               (client_ip(), (username or "")[:64], success))


def is_locked(user):
    row = db.query_one("SELECT locked_until IS NOT NULL AND locked_until > now() AS locked"
                       " FROM ui.admin_user WHERE id=%s", (user["id"],))
    return bool(row and row["locked"])


def register_failure(user):
    """Increment failure count; lock when threshold reached. Returns True if now locked."""
    c = cfg()
    row = db.execute_returning(
        "UPDATE ui.admin_user SET failed_count = failed_count + 1,"
        " locked_until = CASE WHEN failed_count + 1 >= %s"
        "   THEN now() + make_interval(mins => %s) ELSE locked_until END"
        " WHERE id=%s RETURNING failed_count, locked_until IS NOT NULL AND locked_until > now() AS locked",
        (c["lockout_threshold"], c["lockout_minutes"], user["id"]))
    if row and row["locked"]:
        # Count restarts after the lock period.
        db.execute("UPDATE ui.admin_user SET failed_count = 0 WHERE id=%s", (user["id"],))
        db.execute("DELETE FROM ui.session WHERE user_id=%s AND NOT mfa_ok", (user["id"],))
        return True
    return False


def register_success(user):
    db.execute("UPDATE ui.admin_user SET failed_count=0, locked_until=NULL, last_login_at=now(),"
               " last_login_ip=%s WHERE id=%s", (client_ip(), user["id"]))
