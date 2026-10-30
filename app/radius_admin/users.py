"""UI admin user operations shared by views and the CLI."""
from . import db
from .crypto import generate_temp_password, hash_password
from .policy import check_ui_password

USERNAME_RE = r"^[a-z0-9._-]{2,64}$"


def get_by_username(username, conn=None):
    return db.query_one("SELECT * FROM ui.admin_user WHERE username = %s", (username,), conn=conn)


def get_by_id(uid, conn=None):
    return db.query_one("SELECT * FROM ui.admin_user WHERE id = %s", (uid,), conn=conn)


def create_user(username, role, display_name="", iterations=600000, conn=None):
    """Create a user with a random temporary password. Returns (id, temp_password)."""
    import re
    if not re.match(USERNAME_RE, username or ""):
        raise ValueError("Username must be 2-64 characters: lowercase letters, digits, . _ -")
    if role not in ("viewer", "operator", "admin"):
        raise ValueError("Role must be viewer, operator or admin.")
    if get_by_username(username, conn=conn):
        raise ValueError("A user named %s already exists." % username)
    temp = generate_temp_password()
    h = hash_password(temp, iterations)
    row = db.execute_returning(
        "INSERT INTO ui.admin_user (username, display_name, role, password_hash, must_change_password)"
        " VALUES (%s,%s,%s,%s,true) RETURNING id", (username, display_name[:200], role, h), conn=conn)
    db.execute("INSERT INTO ui.password_history (user_id, password_hash) VALUES (%s,%s)",
               (row["id"], h), conn=conn)
    return row["id"], temp


def reset_password_temp(uid, iterations=600000, conn=None):
    temp = generate_temp_password()
    h = hash_password(temp, iterations)
    db.execute("UPDATE ui.admin_user SET password_hash=%s, must_change_password=true,"
               " password_changed_at=now(), failed_count=0, locked_until=NULL, updated_at=now()"
               " WHERE id=%s", (h, uid), conn=conn)
    db.execute("INSERT INTO ui.password_history (user_id, password_hash) VALUES (%s,%s)", (uid, h), conn=conn)
    db.execute("DELETE FROM ui.session WHERE user_id=%s", (uid,), conn=conn)
    return temp


def history_hashes(uid, n, conn=None):
    rows = db.query("SELECT password_hash FROM ui.password_history WHERE user_id=%s"
                    " ORDER BY id DESC LIMIT %s", (uid, n), conn=conn)
    return [r["password_hash"] for r in rows]


def change_password(user, new_password, cfg, conn=None):
    """Validate against policy + history and store. Returns list of problems."""
    problems = check_ui_password(new_password, user["username"], cfg["password_min_length"],
                                 history_hashes(user["id"], cfg["password_history"], conn=conn),
                                 user["password_hash"])
    if problems:
        return problems
    h = hash_password(new_password, cfg["pbkdf2_iterations"])
    db.execute("UPDATE ui.admin_user SET password_hash=%s, must_change_password=false,"
               " password_changed_at=now(), updated_at=now() WHERE id=%s", (h, user["id"]), conn=conn)
    db.execute("INSERT INTO ui.password_history (user_id, password_hash) VALUES (%s,%s)",
               (user["id"], h), conn=conn)
    # Trim history beyond what the policy needs.
    db.execute("DELETE FROM ui.password_history WHERE user_id=%s AND id NOT IN ("
               " SELECT id FROM ui.password_history WHERE user_id=%s ORDER BY id DESC LIMIT %s)",
               (user["id"], user["id"], max(cfg["password_history"], 1)), conn=conn)
    return []


def enabled_admin_count(conn=None):
    return db.query_one("SELECT count(*) AS n FROM ui.admin_user WHERE role='admin' AND enabled",
                        conn=conn)["n"]
