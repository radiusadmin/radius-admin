#!/usr/bin/python3
"""Migrate the FreeRADIUS SQLite database and RADIUS clients to PostgreSQL (radius-admin).

Run as root on the RADIUS server, AFTER sql/00..30 have been loaded and BEFORE
FreeRADIUS is switched to the PostgreSQL configuration:

    sudo /usr/bin/python3 migrate_sqlite_to_pg.py --dry-run
    sudo /usr/bin/python3 migrate_sqlite_to_pg.py

What it does, in ONE PostgreSQL transaction (all or nothing):
  * copies radcheck, radreply, radgroupcheck, radgroupreply, radusergroup, nas, radacct
    (ids preserved, sequences fixed with setval);
  * copies radpostauth history WITHOUT the password column ("pass" is never read
    into the INSERT; the new table has no such column);
  * parses clients.conf (+ $INCLUDE files such as switches.conf, relative to --raddb)
    into ui.radius_client (localhost / loopback clients are skipped: the new
    clients.conf keeps `client localhost` itself);
  * inserts the SPEC section 8 seed access rules if ui.access_rule is empty and makes
    sure the ui.setting defaults exist.
Refuses to run if any target table already has rows, unless --force (which REPLACES
the contents of those tables). --dry-run does everything and then rolls back.
Secrets and passwords are never printed.

Only python3 stdlib + python3-psycopg2 (apt). Compatible with Python 3.12.
"""
import argparse
import datetime
import ipaddress
import os
import pwd
import re
import sqlite3
import sys

try:
    import psycopg2
except ImportError:  # pragma: no cover
    sys.exit("ERROR: python3-psycopg2 is required (apt install python3-psycopg2)")

DEFAULT_SQLITE = "/var/lib/freeradius/sqlite/freeradius.db"
DEFAULT_RADDB = "/etc/freeradius"
DEFAULT_DSN = "dbname=radius host=/var/run/postgresql user=postgres"

# SPEC section 8 seed rules: (priority, connection, ssid, ad_group, vlan). Inserted in
# this order so that ids reproduce the original SSID group order.
SEED_RULES = [
    (10, "wired", None, "Wired-Support", 510),
    (20, "wired", None, "Wired-Office", 500),
    (30, "wired", None, "Wired-Utility", 520),
    (10, "wireless", "Example_Main_Test", "Wireless-Office-Test", 530),
    (10, "wireless", "Example_Admin", "WIRELESS-SUPPORT", 510),
    (10, "wireless", "Example_Main", "WIRELESS-OFFICE", 530),
]
SEED_SETTINGS = [
    ("admin_subnet", "192.0.2.0/24"),
    ("admin_priv15", "false"),
    ("custom_policy", ""),
    ("banner_text", "This system is for authorized use only. Activity on this system is monitored and "
                    "recorded. By continuing, you consent to this monitoring and acknowledge that "
                    "unauthorized use may result in disciplinary action and/or civil and criminal penalties."),
]

# (table, id column, sequence) copied with ids preserved
SIMPLE_TABLES = [
    ("radcheck", "id", "radcheck_id_seq"),
    ("radreply", "id", "radreply_id_seq"),
    ("radgroupcheck", "id", "radgroupcheck_id_seq"),
    ("radgroupreply", "id", "radgroupreply_id_seq"),
    ("radusergroup", "id", "radusergroup_id_seq"),
    ("nas", "id", "nas_id_seq"),
    ("radacct", "radacctid", "radacct_radacctid_seq"),
    ("radpostauth", "id", "radpostauth_id_seq"),
]
TARGET_TABLES = [t for t, _, _ in SIMPLE_TABLES] + ["ui.radius_client"]

# Never copied, whatever the source schema looks like.
FORBIDDEN_COLUMNS = {"pass", "password", "user_password", "userpassword"}

CLIENT_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,63}")
NAS_TYPE_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
TRISTATE = {"yes": "yes", "no": "no", "auto": "auto", "true": "yes", "false": "no"}
CLIENT_KEYS_USED = {"ipaddr", "ipv4addr", "ipv6addr", "netmask", "secret", "shortname", "nas_type",
                    "require_message_authenticator", "limit_proxy_state"}


class MigrationError(Exception):
    pass


# =============================================================================== helpers
def log(msg=""):
    print(msg, flush=True)


def warn(warnings, msg):
    warnings.append(msg)


def pg_columns(cur, table):
    schema, name = ("public", table) if "." not in table else table.split(".", 1)
    cur.execute("SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position", (schema, name))
    return {r[0]: r[1] for r in cur.fetchall()}


def sqlite_columns(sq, table):
    try:
        rows = sq.execute('PRAGMA table_info("%s")' % table).fetchall()
    except sqlite3.DatabaseError:
        return []
    return [r[1].lower() for r in rows]


def to_timestamp(v, colname, warnings, counters):
    """SQLite stores epoch integers (accounting) or local-time text ('%S.%M', post-auth)."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        if v <= 0:
            return None
        return datetime.datetime.fromtimestamp(v, tz=datetime.timezone.utc)
    s = str(v).strip()
    if not s or s.startswith("0000-00-00"):
        return None
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return datetime.datetime.fromtimestamp(float(s), tz=datetime.timezone.utc)
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            naive = datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
        return naive.astimezone()  # FreeRADIUS wrote server local time
    try:
        d = datetime.datetime.fromisoformat(s)
        return d if d.tzinfo else d.astimezone()
    except ValueError:
        counters["bad_timestamp"] = counters.get("bad_timestamp", 0) + 1
        return None


def to_inet(v, counters, not_null=False):
    s = "" if v is None else str(v).strip()
    if s:
        try:
            ipaddress.ip_interface(s)
            return s
        except ValueError:
            counters["bad_inet"] = counters.get("bad_inet", 0) + 1
    return "0.0.0.0" if not_null else None


def to_int(v, counters):
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        counters["bad_int"] = counters.get("bad_int", 0) + 1
        return None


def convert(value, pg_type, col, not_null, warnings, counters):
    if pg_type in ("timestamp with time zone", "timestamp without time zone"):
        ts = to_timestamp(value, col, warnings, counters)
        if ts is None and not_null:
            counters["unparsable_required_timestamp_(set_to_1970-01-01)"] = \
                counters.get("unparsable_required_timestamp_(set_to_1970-01-01)", 0) + 1
            ts = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        return ts
    if pg_type == "inet":
        return to_inet(value, counters, not_null)
    if pg_type in ("integer", "bigint", "smallint"):
        return to_int(value, counters)
    if value is None:
        return "" if not_null else None
    return str(value)


# ======================================================================= clients parser
_TOKEN_RE = re.compile(r"""
    (?P<ws>[ \t\r]+) |
    (?P<nl>\n) |
    (?P<comment>\#[^\n]*) |
    (?P<lb>\{) | (?P<rb>\}) |
    (?P<op>[:+\-]?=) |
    (?P<dq>"(?:[^"\\\n]|\\.)*") |
    (?P<sq>'(?:[^'\\\n]|\\.)*') |
    (?P<word>[^\s{}"'#=]+)
""", re.X)


def _unquote(tok_type, text):
    body = text[1:-1]
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            n = body[i + 1]
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _tokenize(text, path):
    toks, line, pos = [], 1, 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise MigrationError("%s:%d: cannot parse near %r" % (path, line, text[pos:pos + 20]))
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "nl":
            toks.append(("nl", None, line))
            line += 1
        elif kind in ("ws", "comment"):
            pass
        elif kind in ("dq", "sq"):
            toks.append(("str", (kind, _unquote(kind, val), val), line))
        else:
            toks.append((kind, val, line))
        pos = m.end()
    toks.append(("nl", None, line))
    return toks


def parse_clients_file(path, raddb, warnings, seen_files=None, depth=0):
    """Return a list of dicts {name, keys{...}, file, line} for every top-level client."""
    if depth > 8:
        raise MigrationError("$INCLUDE nesting too deep at %s" % path)
    seen_files = seen_files if seen_files is not None else set()
    real = os.path.realpath(path)
    if real in seen_files:
        raise MigrationError("$INCLUDE loop at %s" % path)
    seen_files.add(real)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    toks = _tokenize(text, path)
    clients, i = [], 0

    def skip_section(j):
        depth_ = 1
        while j < len(toks) and depth_:
            if toks[j][0] == "lb":
                depth_ += 1
            elif toks[j][0] == "rb":
                depth_ -= 1
            j += 1
        if depth_:
            raise MigrationError("%s: unbalanced braces" % path)
        return j

    while i < len(toks):
        kind, val, line = toks[i]
        if kind == "nl":
            i += 1
            continue
        if kind == "word" and val in ("$INCLUDE", "$-INCLUDE"):
            arg = toks[i + 1]
            if arg[0] not in ("word", "str"):
                raise MigrationError("%s:%d: $INCLUDE without a file name" % (path, line))
            target = arg[1] if arg[0] == "word" else arg[1][1]
            if "${" in target:
                raise MigrationError("%s:%d: $INCLUDE with variables is not supported: %s" % (path, line, target))
            if not os.path.isabs(target):
                target = os.path.join(raddb, target)
            if os.path.isdir(target):
                files = sorted(os.path.join(target, f) for f in os.listdir(target)
                               if not f.startswith(".") and os.path.isfile(os.path.join(target, f)))
            elif os.path.exists(target):
                files = [target]
            elif val == "$-INCLUDE":
                files = []
            else:
                raise MigrationError("%s:%d: included file not found: %s" % (path, line, target))
            for f in files:
                clients += parse_clients_file(f, raddb, warnings, seen_files, depth + 1)
            i += 2
            continue
        if kind == "word" and val == "client":
            if i + 2 >= len(toks) or toks[i + 1][0] not in ("word", "str") or toks[i + 2][0] != "lb":
                raise MigrationError("%s:%d: malformed client block" % (path, line))
            name = toks[i + 1][1] if toks[i + 1][0] == "word" else toks[i + 1][1][1]
            keys, j = {}, i + 3
            while True:
                if j >= len(toks):
                    raise MigrationError("%s:%d: client %s not terminated" % (path, line, name))
                k, v, ln = toks[j]
                if k == "nl":
                    j += 1
                    continue
                if k == "rb":
                    j += 1
                    break
                if k == "word" and j + 1 < len(toks) and toks[j + 1][0] == "lb":
                    warn(warnings, "client %s (%s:%d): subsection '%s { }' not imported"
                         % (name, os.path.basename(path), ln, v))
                    j = skip_section(j + 2)
                    continue
                if k == "word" and j + 2 < len(toks) and toks[j + 1][0] == "op":
                    vk, vv, _ = toks[j + 2]
                    if vk == "word":
                        value, quoting = vv, "bare"
                    elif vk == "str":
                        value, quoting = vv[1], vv[0]
                    else:
                        raise MigrationError("%s:%d: missing value for %s" % (path, ln, v))
                    if quoting in ("bare", "dq") and "${" in (vv if vk == "word" else vv[2]):
                        raise MigrationError("%s:%d: client %s key %s uses a ${...} reference; "
                                             "resolve it by hand before migrating" % (path, ln, name, v))
                    keys[v] = value
                    j += 3
                    continue
                if k == "word":  # bare flag
                    keys[v] = ""
                    j += 1
                    continue
                raise MigrationError("%s:%d: unexpected token in client %s" % (path, ln, name))
            clients.append({"name": name, "keys": keys, "file": path, "line": line})
            i = j
            continue
        if kind == "word" and i + 1 < len(toks) and toks[i + 1][0] == "lb":
            warn(warnings, "%s:%d: top-level section '%s' ignored" % (os.path.basename(path), line, val))
            i = skip_section(i + 2)
            continue
        if kind == "word" and i + 1 < len(toks) and toks[i + 1][0] == "word" and i + 2 < len(toks) \
                and toks[i + 2][0] == "lb":
            warn(warnings, "%s:%d: top-level section '%s %s' ignored"
                 % (os.path.basename(path), line, val, toks[i + 1][1]))
            i = skip_section(i + 3)
            continue
        raise MigrationError("%s:%d: unexpected '%s' at top level" % (path, line, val))
    return clients


def secret_problem(secret):
    if not secret:
        return "empty secret"
    for ch in secret:
        if ord(ch) < 0x21 or ord(ch) > 0x7E:
            return "secret contains whitespace, control or non-ASCII characters"
        if ch in '"\\':
            return 'secret contains " or \\'
    if "${" in secret:
        return "secret contains ${"
    return None


def client_rows(parsed, warnings):
    rows, names, addrs = [], set(), {}
    skipped = []
    for c in parsed:
        name, k, src = c["name"], c["keys"], os.path.basename(c["file"])
        addr_keys = [x for x in ("ipaddr", "ipv4addr", "ipv6addr") if x in k]
        if len(addr_keys) > 1:
            raise MigrationError("client %s (%s): more than one of ipaddr/ipv4addr/ipv6addr" % (name, src))
        raw = k[addr_keys[0]] if addr_keys else name  # v1 style: client <address> { }
        raw = raw.strip()
        if "netmask" in k and "/" not in raw:
            raw = "%s/%s" % (raw, k["netmask"])
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise MigrationError("client %s (%s): address %r is not an IP address/network "
                                 "(host names are not supported by radius-admin)" % (name, src, raw))
        if net.network_address.is_loopback or name.startswith("localhost"):
            skipped.append(name)
            continue
        if str(net.network_address) != raw.split("/")[0] and net.prefixlen != net.max_prefixlen:
            warn(warnings, "client %s: host bits cleared, %s -> %s" % (name, raw, net))
        if net.prefixlen == 0:
            raise MigrationError("client %s (%s): /0 network is not allowed" % (name, src))
        ipaddr = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
        if not CLIENT_NAME_RE.fullmatch(name):
            raise MigrationError("client name %r (%s) does not match ^[A-Za-z0-9._-]{1,63}$" % (name, src))
        if name in names:
            raise MigrationError("duplicate client name %s" % name)
        if ipaddr in addrs:
            raise MigrationError("clients %s and %s have the same address %s" % (addrs[ipaddr], name, ipaddr))
        names.add(name)
        addrs[ipaddr] = name
        secret = k.get("secret")
        problem = secret_problem(secret or "")
        if problem:
            raise MigrationError("client %s (%s): %s; set a new secret on the device and in %s first"
                                 % (name, src, problem, src))
        if len(secret) < 16:
            warn(warnings, "client %s: shared secret shorter than 16 characters (rotate it in the UI)" % name)
        ma = TRISTATE.get(k.get("require_message_authenticator", "auto").lower())
        lps = TRISTATE.get(k.get("limit_proxy_state", "auto").lower())
        if ma is None or lps is None:
            raise MigrationError("client %s: require_message_authenticator/limit_proxy_state must be "
                                 "yes, no or auto" % name)
        nas_type = k.get("nas_type", "other") or "other"
        if not NAS_TYPE_RE.fullmatch(nas_type):
            warn(warnings, "client %s: nas_type %r replaced by 'other'" % (name, nas_type))
            nas_type = "other"
        dropped = sorted(set(k) - CLIENT_KEYS_USED)
        if dropped:
            warn(warnings, "client %s: settings not imported: %s" % (name, ", ".join(dropped)))
        rows.append({"name": name, "ipaddr": ipaddr, "secret": secret, "require_ma": ma,
                     "limit_proxy_state": lps, "nas_type": nas_type,
                     "description": "Imported from %s" % src})
    return rows, skipped


# ========================================================================== migration
def read_sqlite(path):
    if not os.path.exists(path):
        raise MigrationError("SQLite database not found: %s" % path)
    sq = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    sq.row_factory = sqlite3.Row
    data = {}
    for table, _, _ in SIMPLE_TABLES:
        cols = sqlite_columns(sq, table)
        if not cols:
            data[table] = ([], [])
            continue
        sel = [c for c in cols if c not in FORBIDDEN_COLUMNS]
        rows = sq.execute('SELECT %s FROM "%s"' % (", ".join('"%s"' % c for c in sel), table)).fetchall()
        data[table] = (sel, [tuple(r) for r in rows])
    sq.close()
    return data


def target_counts(cur):
    counts = {}
    for t in TARGET_TABLES:
        cur.execute("SELECT count(*) FROM %s" % t)
        counts[t] = cur.fetchone()[0]
    return counts


def copy_table(cur, table, idcol, seq, src_cols, rows, warnings, summary):
    pgcols = pg_columns(cur, table)
    if not pgcols:
        raise MigrationError("target table %s does not exist (load sql/ first)" % table)
    cur.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' "
                "AND table_name=%s AND is_nullable='NO'", (table,))
    not_null = {r[0] for r in cur.fetchall()}
    cols = [c for c in src_cols if c in pgcols and c not in FORBIDDEN_COLUMNS]
    missing = [c for c in src_cols if c not in pgcols]
    if missing:
        warn(warnings, "%s: source columns without a target, not copied: %s" % (table, ", ".join(missing)))
    counters = {}
    idx = [src_cols.index(c) for c in cols]
    out = []
    for r in rows:
        vals = []
        for c, i in zip(cols, idx):
            vals.append(convert(r[i], pgcols[c], c, c in not_null, warnings, counters))
        out.append(vals)
    if table == "nas":  # shortname NOT NULL in postgres, optional in sqlite
        si = cols.index("shortname") if "shortname" in cols else None
        ni = cols.index("nasname") if "nasname" in cols else None
        if si is not None and ni is not None:
            for v in out:
                if not v[si]:
                    v[si] = v[ni]
    if out:
        sql = "INSERT INTO %s (%s) VALUES (%s)" % (table, ", ".join(cols), ", ".join(["%s"] * len(cols)))
        cur.executemany(sql, out)
    if idcol in cols:
        cur.execute("SELECT setval(%%s, GREATEST((SELECT COALESCE(max(%s), 0) FROM %s), 1), "
                    "(SELECT count(*) > 0 FROM %s))" % (idcol, table, table), (seq,))
    for k, n in counters.items():
        warn(warnings, "%s: %d value(s) with %s replaced by NULL/default" % (table, n, k.replace("_", " ")))
    summary.append((table, len(out), ", ".join(cols) if table == "radpostauth" else None))


def drop_to_postgres_if_root(dsn):
    """Peer auth for user=postgres needs OS user postgres. Inputs are already read."""
    if os.geteuid() != 0:
        return False
    m = re.search(r"(?:^|\s)user=(\S+)", dsn)
    host = re.search(r"(?:^|\s)host=(\S+)", dsn)
    if not m or m.group(1) != "postgres" or (host and not host.group(1).startswith("/")):
        return False
    pw = pwd.getpwnam("postgres")
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    os.chdir("/")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sqlite", default=DEFAULT_SQLITE)
    ap.add_argument("--raddb", default=DEFAULT_RADDB)
    ap.add_argument("--dsn", default=DEFAULT_DSN)
    ap.add_argument("--clients-file", default=None, help="default: <raddb>/clients.conf")
    ap.add_argument("--dry-run", action="store_true", help="do everything, then roll back")
    ap.add_argument("--force", action="store_true",
                    help="REPLACE the contents of target tables that already have rows")
    a = ap.parse_args(argv)
    warnings, summary = [], []
    clients_file = a.clients_file or os.path.join(a.raddb, "clients.conf")

    try:
        # ---- read every input first (as root), then drop privileges
        data = read_sqlite(a.sqlite)
        parsed = parse_clients_file(clients_file, a.raddb, warnings)
        crows, skipped = client_rows(parsed, warnings)
        dropped = drop_to_postgres_if_root(a.dsn)

        conn = psycopg2.connect(a.dsn)
        conn.autocommit = False
        cur = conn.cursor()
        cur.execute("SET LOCAL lock_timeout = '10s'")
        cur.execute("LOCK TABLE %s IN EXCLUSIVE MODE" % ", ".join(TARGET_TABLES + ["ui.access_rule", "ui.setting"]))
        counts = target_counts(cur)
        nonempty = {t: n for t, n in counts.items() if n}
        if nonempty and not a.force:
            raise MigrationError("target tables already contain data (%s); refusing. Use --force to "
                                 "REPLACE their contents." % ", ".join("%s=%d" % kv for kv in nonempty.items()))
        if nonempty:
            for t in nonempty:
                cur.execute("DELETE FROM %s" % t)
            warn(warnings, "--force: replaced existing rows in " + ", ".join(sorted(nonempty)))

        for table, idcol, seq in SIMPLE_TABLES:
            cols, rows = data[table]
            if not cols:
                warn(warnings, "%s: table not found in SQLite, skipped" % table)
                summary.append((table, 0, None))
                continue
            copy_table(cur, table, idcol, seq, cols, rows, warnings, summary)

        for r in crows:
            cur.execute("INSERT INTO ui.radius_client (name, ipaddr, secret, require_ma, limit_proxy_state, "
                        "nas_type, description, enabled) VALUES (%s,%s,%s,%s,%s,%s,%s,true)",
                        (r["name"], r["ipaddr"], r["secret"], r["require_ma"], r["limit_proxy_state"],
                         r["nas_type"], r["description"]))

        cur.execute("SELECT count(*) FROM ui.access_rule")
        rules_inserted = 0
        if cur.fetchone()[0] == 0:
            for prio, conn_t, ssid, group, vlan in SEED_RULES:
                cur.execute("INSERT INTO ui.access_rule (priority, connection, ssid, ad_group, vlan, description,"
                            " enabled) VALUES (%s,%s,%s,%s,%s,%s,true)",
                            (prio, conn_t, ssid, group, vlan, "Migrated from the original site policy"))
                rules_inserted += 1
        else:
            warn(warnings, "ui.access_rule is not empty: seed rules NOT inserted")
        for key, value in SEED_SETTINGS:
            cur.execute("INSERT INTO ui.setting (key, value) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
                        (key, value))

        # ---- sanity: no password column exists in radpostauth
        if FORBIDDEN_COLUMNS & set(pg_columns(cur, "radpostauth")):
            raise MigrationError("radpostauth in PostgreSQL has a password column; load sql/10 first")

        if a.dry_run:
            conn.rollback()
        else:
            conn.commit()
        conn.close()
    except psycopg2.Error as e:
        # Only the primary message: DETAIL ("Failing row contains ...") could include secrets.
        diag = getattr(e, "diag", None)
        msg = (diag.message_primary if diag is not None and diag.message_primary else
               str(e).strip().splitlines()[0] if str(e).strip() else e.__class__.__name__)
        log("ERROR: PostgreSQL: %s" % msg)
        log("Nothing was changed in PostgreSQL.")
        return 2
    except (MigrationError, sqlite3.Error, OSError) as e:
        log("ERROR: %s" % (str(e).strip() or e.__class__.__name__))
        log("Nothing was changed in PostgreSQL.")
        return 2

    log("radius-admin SQLite -> PostgreSQL migration%s" % (" (DRY RUN: rolled back)" if a.dry_run else ""))
    log("  source sqlite : %s" % a.sqlite)
    log("  clients from  : %s (+ $INCLUDEs)" % clients_file)
    log("  target        : %s%s" % (re.sub(r"password=\S+", "password=***", a.dsn),
                                    " (as OS user postgres)" if dropped else ""))
    log("")
    for table, n, cols in summary:
        log("  %-16s %7d rows%s" % (table, n, ("  [columns: %s; password NOT copied]" % cols) if cols else ""))
    by_src = {}
    for r in crows:
        by_src[r["description"]] = by_src.get(r["description"], 0) + 1
    log("  %-16s %7d clients (%s)" % ("ui.radius_client", len(crows),
                                      ", ".join("%s: %d" % kv for kv in sorted(by_src.items())) or "none"))
    if skipped:
        log("  skipped clients (kept in clients.conf): %s" % ", ".join(skipped))
    log("  %-16s %7d seed rules inserted" % ("ui.access_rule", rules_inserted))
    if warnings:
        log("")
        log("Warnings:")
        for w in warnings:
            log("  - " + w)
    log("")
    log("Secrets were copied but not displayed. %s" % ("No changes were committed." if a.dry_run else "Committed."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
