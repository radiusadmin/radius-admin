"""Command line: python3 -m radius_admin.cli <command>

  create-admin --username U --role R [--display-name N]   prints a one-time temporary password
  reset-password --username U [--reset-mfa]               account recovery: new one-time temporary
                                                            password, unlocks, re-enables, ends sessions
  unlock --username U                                       clear a lockout (failed sign-ins)
  reset-mfa --username U                                    remove the two-factor method (re-enrol at sign-in)
  render --out-dir DIR                                      writes policy + clients (0600)
  verify-audit                                              verifies the audit hash chain
  check-fips                                                reports FIPS state (exit 1 if not FIPS)
"""
import argparse
import os
import sys

from . import audit, db
from .config import ConfigError, load_config
from .crypto import fips_status, sha256_hex


def _conn(cfg):
    return db.connect(cfg["db_dsn"])


def cmd_create_admin(cfg, args):
    from .users import create_user
    conn = _conn(cfg)
    try:
        uid, temp = create_user(args.username, args.role, args.display_name or "",
                                cfg["pbkdf2_iterations"], conn=conn)
        audit.write("ui_admin.create", actor="cli:" + (os.environ.get("SUDO_USER") or os.environ.get("USER") or "?"),
                    object_type="admin_user", object_id=uid,
                    detail={"username": args.username, "role": args.role, "via": "cli"}, conn=conn)
        conn.commit()
    except ValueError as e:
        conn.rollback()
        print("error: %s" % e, file=sys.stderr)
        return 2
    finally:
        conn.close()
    print("Created %s (%s). One-time temporary password (change required at first sign-in):"
          % (args.username, args.role))
    print(temp)
    return 0


def _actor():
    return "cli:" + (os.environ.get("SUDO_USER") or os.environ.get("USER") or "?")


def _recover(cfg, args, action):
    """Console account recovery. Whoever can run this already has root on the server;
    every use is written to the audit log and syslog like any UI change."""
    from .users import get_by_username, reset_password_temp
    conn = _conn(cfg)
    try:
        u = get_by_username(args.username.strip().lower(), conn=conn)
        if not u:
            print("error: no UI account named %r" % args.username, file=sys.stderr)
            return 2
        uid = u["id"]
        detail = {"username": u["username"], "via": "cli"}
        temp = None
        if action == "reset-password":
            temp = reset_password_temp(uid, cfg["pbkdf2_iterations"], conn=conn)
            db.execute("UPDATE ui.admin_user SET enabled=true, updated_at=now() WHERE id=%s",
                       (uid,), conn=conn)
            detail["reenabled"] = not u["enabled"]
        elif action == "unlock":
            db.execute("UPDATE ui.admin_user SET failed_count=0, locked_until=NULL, updated_at=now()"
                       " WHERE id=%s", (uid,), conn=conn)
        if action == "reset-mfa" or getattr(args, "reset_mfa", False):
            db.execute("UPDATE ui.admin_user SET mfa_method=NULL, totp_secret_enc=NULL,"
                       " totp_last_step=NULL, cert_sha256=NULL, cert_subject=NULL, updated_at=now()"
                       " WHERE id=%s", (uid,), conn=conn)
            db.execute("DELETE FROM ui.session WHERE user_id=%s", (uid,), conn=conn)
            detail["mfa_reset"] = True
        audit.write({"reset-password": "ui_admin.reset_password", "unlock": "ui_admin.unlock",
                     "reset-mfa": "ui_admin.reset_mfa"}[action], actor=_actor(),
                    object_type="admin_user", object_id=uid, detail=detail, conn=conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    if action == "reset-password":
        print("%s: password reset, account unlocked%s, all sessions ended%s."
              % (u["username"], " and re-enabled" if detail["reenabled"] else "",
                 ", two-factor removed" if detail.get("mfa_reset") else ""))
        print("One-time temporary password (change required at next sign-in):")
        print(temp)
    elif action == "unlock":
        print("%s: unlocked." % u["username"])
    else:
        print("%s: two-factor removed; a new method must be enrolled at next sign-in." % u["username"])
    return 0


def cmd_reset_password(cfg, args):
    return _recover(cfg, args, "reset-password")


def cmd_unlock(cfg, args):
    return _recover(cfg, args, "unlock")


def cmd_reset_mfa(cfg, args):
    return _recover(cfg, args, "reset-mfa")


def cmd_render(cfg, args):
    from . import services
    conn = _conn(cfg)
    try:
        policy, clients = services.render_all(conn)
    finally:
        conn.close()
    os.makedirs(args.out_dir, mode=0o700, exist_ok=True)
    old = os.umask(0o077)
    try:
        services.write_staging(policy, clients, base=args.out_dir)
    finally:
        os.umask(old)
    print("policy  sha256=%s  %s" % (sha256_hex(policy), os.path.join(args.out_dir, "policy")))
    print("clients sha256=%s  %s" % (sha256_hex(clients), os.path.join(args.out_dir, "clients")))
    return 0


def cmd_verify_audit(cfg, args):
    conn = _conn(cfg)
    try:
        ok, count, bad, msg = audit.verify_chain(conn=conn)
    finally:
        conn.close()
    print(("OK: " if ok else "FAILED: ") + msg)
    return 0 if ok else 1


def cmd_check_fips(cfg, args):
    st = fips_status()
    print("kernel fips_enabled : %s" % st["kernel"])
    print("OpenSSL FIPS mode   : %s" % st["openssl"])
    print("OpenSSL version     : %s" % st["openssl_version"])
    print("require_fips        : %s" % cfg["require_fips"])
    print("result              : %s" % ("FIPS OK" if st["ok"] else "NOT IN FIPS MODE"))
    return 0 if st["ok"] else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m radius_admin.cli", description="radius-admin tools")
    p.add_argument("--config", help="config file (default: $RADIUS_ADMIN_CONFIG or /etc/radius-admin/radius-admin.conf)")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("create-admin", help="create a UI account with a temporary password")
    a.add_argument("--username", required=True)
    a.add_argument("--role", required=True, choices=["viewer", "operator", "admin"])
    a.add_argument("--display-name", default="")
    rp = sub.add_parser("reset-password", help="account recovery: one-time temporary password, unlock")
    rp.add_argument("--username", required=True)
    rp.add_argument("--reset-mfa", action="store_true", help="also remove the two-factor method")
    ul = sub.add_parser("unlock", help="clear a sign-in lockout")
    ul.add_argument("--username", required=True)
    rm = sub.add_parser("reset-mfa", help="remove the two-factor method")
    rm.add_argument("--username", required=True)
    r = sub.add_parser("render", help="render policy and clients files from the database")
    r.add_argument("--out-dir", required=True)
    sub.add_parser("verify-audit", help="verify the audit log hash chain")
    sub.add_parser("check-fips", help="report FIPS status")
    args = p.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    audit.configure_syslog(cfg["log_syslog"])
    if args.cmd != "check-fips" and cfg["require_fips"] and not fips_status()["ok"]:
        print("error: FIPS mode required but not active (see check-fips)", file=sys.stderr)
        return 3
    return {"create-admin": cmd_create_admin, "reset-password": cmd_reset_password,
            "unlock": cmd_unlock, "reset-mfa": cmd_reset_mfa, "render": cmd_render, "verify-audit": cmd_verify_audit,
            "check-fips": cmd_check_fips}[args.cmd](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
