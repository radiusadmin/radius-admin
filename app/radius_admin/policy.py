"""Password policies for UI admins and switch admins."""
import re

from .crypto import verify_password

# Printable ASCII, no space restrictions for UI passwords.
_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")
SWITCH_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def _classes(pw):
    return sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))


def check_ui_password(password, username, min_length=15, history_hashes=(), current_hash=None):
    """Return a list of human-readable problems (empty = acceptable)."""
    problems = []
    if len(password) < min_length:
        problems.append("Use at least %d characters." % min_length)
    if len(password) > 128:
        problems.append("Use at most 128 characters.")
    if not _PRINTABLE.match(password or " "):
        problems.append("Use printable characters only (letters, digits, punctuation, spaces).")
    if _classes(password) < 3:
        problems.append("Mix at least three of: lowercase, uppercase, digits, symbols.")
    if username and username.lower() in password.lower():
        problems.append("Do not include your username.")
    if not problems:
        for h in ([current_hash] if current_hash else []) + list(history_hashes):
            if verify_password(password, h):
                problems.append("Choose a password you have not used recently.")
                break
    return problems


def check_switch_password(password, min_length=15):
    problems = []
    if len(password) < min_length:
        problems.append("Use at least %d characters." % min_length)
    if len(password) > 128:
        problems.append("Use at most 128 characters (RADIUS PAP limit).")
    if any(c in password for c in ('"', "\\", "\n", "\r")):
        problems.append('Do not use double quotes ("), backslashes (\\) or line breaks.')
    elif not _PRINTABLE.match(password or " "):
        problems.append("Use printable ASCII characters only.")
    return problems


def validate_switch_username(name):
    if not SWITCH_USERNAME_RE.match(name or ""):
        raise ValueError("Username must be 1-64 characters: letters, digits, . _ @ -")
    return name
