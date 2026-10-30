#!/bin/bash
# radius-admin installer (idempotent). Run from the repository checkout as root.
#
#   sudo ./deploy/install.sh [options]                  run all phases in order
#   sudo ./deploy/install.sh --phase nginx [--phase …]  run selected phase(s)
#
# Phases (in order):
#   preflight  read-only checks (deploy/preflight.sh); aborts on blocking failures
#   packages   apt install from the configured mirror
#   users      OS users/groups, directories, AES key (openssl rand 32)
#   postgres   pg_hba/pg_ident/listen_addresses, roles, schema (sql/*.sql)
#   migrate    SQLite -> PostgreSQL (deploy/migrate_sqlite_to_pg.py); needs --confirm-migrate
#   freeradius backup /etc/freeradius, install freeradius/ files, disable modules,
#              remove inner-tunnel, render+install policy/clients, radiusd -XC.
#              Does NOT restart FreeRADIUS unless --restart-freeradius.
#   app        code to /opt/radius-admin, configs, helper, systemd units (enabled, started)
#   site       with answers: /etc/radius-admin/site.yaml and the portal certificate
#              (self-signed, CSR for your CA, or existing files)
#   nginx      TLS site on <management IP>:443 (needs /etc/radius-admin/tls/server.{key,crt})
#   firewall   nftables table: 443 only from the admin subnet (+ ufw rule if ufw is active)
#   bootstrap  create the first UI administrator (with answers) or print how to
#
# Run with no options on a terminal to be asked the set-up questions.
#
# Options:
#   -i, --interactive       ask the set-up questions (server name, subnet, certificate, first admin)
#   --answers FILE          take the answers from FILE (format: deploy/answers.sh; site.yaml works)
#   --print-answers         with --answers/--interactive: check and print the answers, install nothing
#   --phase NAME            run only this phase (repeatable, or comma-separated)
#   --from NAME             run this phase and all following ones
#   --confirm-migrate       allow the migrate phase to run
#   --restart-freeradius    restart FreeRADIUS at the end of the freeradius phase
#   --listen-ip IP          nginx bind address (default: detected address in admin net)
#   --admin-net CIDR        default 192.0.2.0/24
#   --server-name NAME      default radius.example.net
#   --resolver "IP [IP]"    DNS for nginx OCSP lookups (default: resolvectl/resolv.conf)
#   --sqlite PATH           default /var/lib/freeradius/sqlite/freeradius.db
#   --skip-preflight        do not abort on preflight failures (not recommended)
#   -y, --yes               do not ask for confirmation
set -euo pipefail
umask 022
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC=$(cd "$HERE/.." && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=answers.sh
. "$HERE/answers.sh"

ALL_PHASES=(preflight packages users postgres migrate freeradius app site nginx firewall bootstrap)
PHASES=()
FROM=""
CONFIRM_MIGRATE=0
RESTART_FR=0
LISTEN_IP=""
RESOLVER=""
SKIP_PREFLIGHT=0
ASSUME_YES=0
INTERACTIVE=0
ANSWERS=""
PRINT_ANSWERS=0
USE_ANSWERS=0
CSR_PENDING=0
[[ $# -eq 0 && -t 0 ]] && INTERACTIVE=1

OPT=/opt/radius-admin
ETC=/etc/radius-admin
LIB=/var/lib/radius-admin
STAGING=$LIB/staging
HELPER_DIR=/var/lib/radius-admin-helper
HELPER_BIN=/usr/local/libexec/radius-admin/radius-admin-helper
TS=$(date -u +%Y%m%dT%H%M%SZ)

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --phase) IFS=, read -r -a _p <<<"$2"; PHASES+=("${_p[@]}"); shift 2 ;;
        --from) FROM=$2; shift 2 ;;
        --confirm-migrate) CONFIRM_MIGRATE=1; shift ;;
        --restart-freeradius) RESTART_FR=1; shift ;;
        --listen-ip) LISTEN_IP=$2; shift 2 ;;
        --admin-net) RA_ADMIN_NET=$2; shift 2 ;;
        --server-name) RA_SERVER_NAME=$2; shift 2 ;;
        --resolver) RESOLVER=$2; shift 2 ;;
        --sqlite) RA_SQLITE_DB=$2; shift 2 ;;
        --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -i|--interactive) INTERACTIVE=1; shift ;;
        --answers) ANSWERS=$2; shift 2 ;;
        --print-answers) PRINT_ANSWERS=1; shift ;;
        -h|--help) usage 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage 2 ;;
    esac
done
require_root

if (( INTERACTIVE )) || [[ -n $ANSWERS ]]; then
    USE_ANSWERS=1
    if [[ -n $ANSWERS ]]; then ans_load "$ANSWERS"; fi
    ans_defaults
    if (( INTERACTIVE )); then ans_interactive; fi
    ans_validate
    RA_SERVER_NAME=${ANS[server_name]}; RA_ADMIN_NET=${ANS[admin_net]}
    LISTEN_IP=${ANS[listen_ip]}; RESOLVER=${ANS[resolver]}
    if (( PRINT_ANSWERS )); then ans_print; exit 0; fi
    if (( INTERACTIVE )); then
        say ""; ans_print | sed '1d; s/^/    /'
        confirm "Install with these settings?" || die "aborted"
    fi
elif (( PRINT_ANSWERS )); then
    die "--print-answers needs --answers FILE or --interactive"
fi

valid_phase() { local p; for p in "${ALL_PHASES[@]}"; do [[ $p == "$1" ]] && return 0; done; return 1; }
if [[ -n $FROM ]]; then
    valid_phase "$FROM" || die "unknown phase $FROM"
    on=0
    for p in "${ALL_PHASES[@]}"; do [[ $p == "$FROM" ]] && on=1; (( on )) && PHASES+=("$p"); done
fi
if [[ ${#PHASES[@]} -eq 0 ]]; then PHASES=("${ALL_PHASES[@]}"); fi
for p in "${PHASES[@]}"; do valid_phase "$p" || die "unknown phase '$p' (valid: ${ALL_PHASES[*]})"; done
want() { local p; for p in "${PHASES[@]}"; do [[ $p == "$1" ]] && return 0; done; return 1; }

confirm() {
    (( ASSUME_YES )) && return 0
    local a
    read -r -p "$1 [y/N] " a || true
    [[ $a == y || $a == Y || $a == yes ]]
}

# install FILE with owner/mode only if content differs (prints what changed)
put() { # put SRC DST OWNER:GROUP MODE
    local src=$1 dst=$2 og=$3 mode=$4
    if [[ -e $dst ]] && cmp -s "$src" "$dst"; then
        chown "$og" "$dst"; chmod "$mode" "$dst"
        return 1
    fi
    install -o "${og%%:*}" -g "${og##*:}" -m "$mode" "$src" "$dst"
    info "installed $dst"
    return 0
}

FR_SVC=""
RADIUSD=""
detect_fr() {
    [[ -n $FR_SVC && -n $RADIUSD ]] && return 0
    FR_SVC=$(detect_fr_service || true)
    [[ -n $FR_SVC ]] || die "FreeRADIUS systemd unit not found (freeradius.service / radiusd.service)"
    RADIUSD=$(detect_radiusd "$FR_SVC" || true)
    [[ -n $RADIUSD ]] || die "radiusd binary not found"
}

fr_check() { # fr_check RADDB -> runs radiusd -XC as root (radiusd parses config as root and
             # drops to "user = freerad" itself, like the service does), prints tail on failure
    local d=$1 out
    if out=$(timeout 90 "$RADIUSD" -XC -d "$d" 2>&1) \
        && grep -q 'Configuration appears to be OK' <<<"$out"; then
        return 0
    fi
    printf '%s\n' "$out" | tail -n 40 | sed 's/^/    | /' >&2
    return 1
}

app_env() { # run a command as radius-admin with the app environment
    runuser -u radius-admin -- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
        "RADIUS_ADMIN_CONFIG=$ETC/radius-admin.conf" "PYTHONPATH=$OPT/app" \
        PYTHONDONTWRITEBYTECODE=1 "$@"
}

# ------------------------------------------------------------------------------ phases

phase_preflight() {
    hdr "Phase preflight (read-only)"
    if ! "$HERE/preflight.sh" --sqlite "$RA_SQLITE_DB" --admin-net "$RA_ADMIN_NET"; then
        if (( SKIP_PREFLIGHT )); then
            warn "preflight reported blocking failures; continuing because of --skip-preflight"
        else
            die "preflight reported blocking failures (fix them, or re-run with --skip-preflight)"
        fi
    fi
}

phase_packages() {
    hdr "Phase packages"
    # python3-pysaml2 + xmlsec1: portal single sign-on (SAML signature checks)
    local pkgs=(postgresql nginx python3-flask python3-psycopg2 gunicorn python3-cryptography
                python3-qrcode python3-pysaml2 xmlsec1 nftables libpq5 sqlite3 snmp ieee-data ldap-utils)
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
    ok "packages installed: ${pkgs[*]}"
    # Debian's nginx package enables a port-80 default site; we never want it on this host.
    if [[ -L /etc/nginx/sites-enabled/default ]]; then
        rm -f /etc/nginx/sites-enabled/default
        info "disabled nginx default site (port 80)"
        systemctl reload nginx 2>/dev/null || true
    fi
}

phase_users() {
    hdr "Phase users/dirs/keys"
    getent group radius-admin >/dev/null || { groupadd --system radius-admin; info "group radius-admin created"; }
    getent group radius-admin-web >/dev/null || { groupadd --system radius-admin-web; info "group radius-admin-web created"; }
    if ! id radius-admin >/dev/null 2>&1; then
        useradd --system --gid radius-admin --home-dir "$LIB" --no-create-home \
            --shell /usr/sbin/nologin --comment "radius-admin web UI" radius-admin
        info "user radius-admin created"
    fi
    if id www-data >/dev/null 2>&1; then
        if ! id -nG www-data | tr ' ' '\n' | grep -qx radius-admin-web; then
            usermod -a -G radius-admin-web www-data; info "www-data added to radius-admin-web"
        fi
    else
        warn "www-data does not exist yet (install nginx, then re-run --phase users)"
    fi
    id freerad >/dev/null 2>&1 || die "OS user freerad missing"

    install -d -o root -g root -m 0755 "$OPT" "$OPT/app" /usr/local/libexec/radius-admin
    install -d -o root -g radius-admin -m 0750 "$ETC"
    install -d -o root -g radius-admin -m 0750 "$ETC/keys"
    install -d -o root -g root -m 0700 "$ETC/tls"
    install -d -o radius-admin -g radius-admin -m 0750 "$LIB"
    install -d -o radius-admin -g radius-admin -m 0700 "$STAGING"
    install -d -o root -g root -m 0711 "$HELPER_DIR"
    install -d -o root -g root -m 0700 "$HELPER_DIR/backups" "$RA_BACKUP_DIR"
    install -d -o root -g adm -m 0750 /var/log/radius-admin
    ok "directories"

    local key=$ETC/keys/data.key
    if [[ -s $key ]]; then
        [[ $(stat -c %s "$key") -eq 32 ]] || die "$key exists but is not 32 bytes; refusing to touch it"
        chown radius-admin:radius-admin "$key"; chmod 0400 "$key"
        ok "data key present (kept)"
    else
        local tmp
        tmp=$(mktemp "$ETC/keys/.data.key.XXXXXX")
        ( umask 077; openssl rand -out "$tmp" 32 )
        [[ $(stat -c %s "$tmp") -eq 32 ]] || { rm -f "$tmp"; die "openssl rand failed"; }
        chown radius-admin:radius-admin "$tmp"; chmod 0400 "$tmp"
        mv -n "$tmp" "$key"
        ok "generated 256-bit data key $key with OpenSSL DRBG (back it up offline: losing it invalidates all TOTP enrolments)"
    fi
}

edit_pg_file() { # edit_pg_file FILE SNIPPET MODE(prepend|append)
    python3 - "$1" "$2" "$3" <<'PY'
import os, re, sys
path, snip_path, mode = sys.argv[1:4]
snip = open(snip_path).read().rstrip("\n") + "\n"
text = open(path).read()
begin, end = "# BEGIN radius-admin", "# END radius-admin"
norm = lambda l: " ".join(l.split())
ours = {norm(l) for l in snip.splitlines() if l.strip() and not l.lstrip().startswith("#")}
# drop an existing managed block and any loose duplicates of our lines
text = re.sub(r"(?ms)^# BEGIN radius-admin.*?^# END radius-admin[^\n]*\n?(\n(?=\S))?", "", text)
lines = [l for l in text.splitlines(True) if norm(l) not in ours]
if mode == "prepend":
    # insert before the first non-comment, non-blank line (i.e. before any generic rule)
    for i, l in enumerate(lines):
        if l.strip() and not l.lstrip().startswith("#"):
            break
    else:
        i = len(lines)
    lines[i:i] = [snip, "\n"]
else:
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.append(snip)
new = "".join(lines)
if new != open(path).read():
    st = os.stat(path)
    tmp = path + ".radius-admin.tmp"
    with open(tmp, "w") as fh:
        fh.write(new)
    os.chown(tmp, st.st_uid, st.st_gid); os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, path)
    print("changed")
PY
}

phase_postgres() {
    hdr "Phase postgres"
    local cdir; cdir=$(pg_conf_dir)
    [[ -d $cdir ]] || die "PostgreSQL $RA_PG_VERSION cluster $RA_PG_CLUSTER not found ($cdir); install package postgresql"
    local unit="postgresql@$RA_PG_VERSION-$RA_PG_CLUSTER.service"
    systemctl enable --now "$unit" >/dev/null 2>&1 || systemctl start postgresql
    local changed=0 restart=0
    install -d -o postgres -g postgres -m 0755 "$cdir/conf.d"
    if put "$HERE/postgres/radius-admin.conf" "$cdir/conf.d/radius-admin.conf" postgres:postgres 0644; then restart=1; fi
    for f in pg_hba pg_ident; do
        cp -n "$cdir/$f.conf" "$cdir/$f.conf.pre-radius-admin" 2>/dev/null || true
    done
    if [[ $(edit_pg_file "$cdir/pg_hba.conf" "$HERE/postgres/pg_hba.conf.snippet" prepend) == changed ]]; then changed=1; info "pg_hba.conf updated"; fi
    if [[ $(edit_pg_file "$cdir/pg_ident.conf" "$HERE/postgres/pg_ident.conf.snippet" append) == changed ]]; then changed=1; info "pg_ident.conf updated"; fi
    if (( restart )); then
        info "restarting PostgreSQL (listen_addresses changed; FreeRADIUS is not yet using it)"
        systemctl restart "$unit"
    elif (( changed )); then
        systemctl reload "$unit"
    fi
    for _ in $(seq 1 30); do runuser -u postgres -- pg_isready -q -h /var/run/postgresql && break; sleep 1; done
    runuser -u postgres -- pg_isready -q -h /var/run/postgresql || die "PostgreSQL not ready"
    local la; la=$(psql_su -At -c 'SHOW listen_addresses')
    if [[ -z $la ]]; then ok "PostgreSQL listens on the unix socket only"; else warn "listen_addresses = '$la' (expected '')"; fi

    # The SQL files are fed on stdin (opened by root here), not passed with -f: psql runs
    # as the postgres user, which usually cannot read the unpacked package directory
    # (e.g. under a 0750 home directory).
    local f
    for f in "$SRC"/sql/[0-9][0-9]-*.sql; do
        if [[ $(basename "$f") == 00-* ]]; then
            psql_su -d postgres <"$f" >/dev/null
        else
            psql_su -d radius <"$f" >/dev/null
        fi
        ok "loaded $(basename "$f")"
    done
    local u r
    for u in freerad:radius_fr radius-admin:radius_admin; do
        r=$(runuser -u "${u%%:*}" -- psql -XAtq "dbname=radius host=/var/run/postgresql user=${u##*:}" -c 'SELECT current_user' 2>&1 || true)
        if [[ $r == "${u##*:}" ]]; then ok "peer auth ${u%%:*} -> ${u##*:}"; else bad "peer auth ${u%%:*} -> ${u##*:} failed: $r"; fi
    done
    if runuser -u nobody -- psql -XAtq "dbname=radius host=/var/run/postgresql user=radius_admin" -c 'SELECT 1' >/dev/null 2>&1; then
        bad "user nobody could log in as radius_admin -- check pg_hba.conf"
    else
        ok "other OS users cannot use the radius roles"
    fi
    (( FAILURES == 0 )) || die "postgres phase failed"
}

phase_migrate() {
    hdr "Phase migrate (SQLite -> PostgreSQL)"
    if (( ! CONFIRM_MIGRATE )); then
        warn "skipped: re-run with --phase migrate --confirm-migrate inside the maintenance window"
        return 0
    fi
    local mig=$HERE/migrate_sqlite_to_pg.py
    [[ -f $mig ]] || die "$mig not found"
    [[ -r $RA_SQLITE_DB ]] || die "SQLite DB $RA_SQLITE_DB not readable"
    # consistent snapshot of the SQLite DB first (sqlite3 .backup, root-only)
    local snap=$RA_BACKUP_DIR/freeradius-sqlite-$TS.db
    sqlite3 "file:$RA_SQLITE_DB?mode=ro" ".backup '$snap'"
    chmod 0600 "$snap"
    info "SQLite snapshot $snap (contains cleartext passwords in radpostauth.pass: shred it with the original after verification)"
    # migrate_sqlite_to_pg.py (FR engineer) runs as root: it reads the SQLite snapshot and
    # clients.conf (+ $INCLUDE switches.conf), then drops to the postgres user itself and
    # writes everything in ONE transaction. Dry run first (rolls back), then for real.
    local args=(--sqlite "$snap" --raddb "$RA_RADDB")
    info "dry run: migrate_sqlite_to_pg.py ${args[*]} --dry-run"
    "$RA_PYTHON" -I "$mig" "${args[@]}" --dry-run || die "migration dry run failed (nothing changed)"
    info "migrating: migrate_sqlite_to_pg.py ${args[*]}"
    "$RA_PYTHON" -I "$mig" "${args[@]}" || die "migration failed (transaction rolled back; FreeRADIUS configuration not changed)"
    ok "migration finished"
}

carry_over_secrets() { # carry_over_secrets STAGED_DIR : copy live secrets over 'REDACTED' placeholders
    python3 - "$1" "$RA_RADDB" <<'PY'
import os, re, sys
staged, live = sys.argv[1:3]
def sub_line(rel, pattern):
    s_path, l_path = os.path.join(staged, rel), os.path.join(live, rel)
    if not os.path.exists(s_path):
        return
    text = open(s_path).read()
    if "REDACTED" not in text:
        return
    ltext = open(l_path).read() if os.path.exists(l_path) else ""
    m = re.search(pattern, ltext, re.M)
    if not m or "REDACTED" in m.group(0):
        sys.exit("cannot carry over secret for %s: not found in live %s" % (rel, l_path))
    new, n = re.subn(pattern, lambda _: m.group(0), text, count=1, flags=re.M)
    if n != 1:
        sys.exit("placeholder pattern not found in %s" % s_path)
    open(s_path, "w").write(new)
    print("  [INFO] kept existing secret in %s" % rel)
sub_line("mods-available/ldap", r"^[ \t]*password[ \t]*=.*$")

# Site-specific LDAP connection settings are kept from the live file too: the bind
# account (identity), the search base and the server line(s) may have been changed on the
# server after the first install (e.g. a renamed service account). Installing the
# package's values would make FreeRADIUS fail to start (AD bind error 52e).
def keep_ldap_settings():
    rel = "mods-available/ldap"
    s_path, l_path = os.path.join(staged, rel), os.path.join(live, rel)
    if not (os.path.exists(s_path) and os.path.exists(l_path)):
        return
    text, ltext = open(s_path).read(), open(l_path).read()
    for key in ("identity", "base_dn"):
        rx = r"^[ \t]*%s[ \t]*=.*$" % key
        lm, sm = re.search(rx, ltext, re.M), re.search(rx, text, re.M)
        if lm and sm and lm.group(0) != sm.group(0):
            text = text[:sm.start()] + lm.group(0) + text[sm.end():]
            print("  [INFO] kept the live %s in %s" % (key, rel))
    srx = r"^[ \t]*server[ \t]*=.*$"
    live_servers = re.findall(srx, ltext, re.M)
    staged_servers = list(re.finditer(srx, text, re.M))
    if live_servers and staged_servers and live_servers != [m.group(0) for m in staged_servers]:
        first = staged_servers[0]
        out, pos = [], 0
        for m in staged_servers:
            out.append(text[pos:m.start()])
            if m is first:
                out.append("\n".join(live_servers))
            pos = m.end() + (1 if m is not first and text[m.end():m.end() + 1] == "\n" else 0)
        out.append(text[pos:])
        text = "".join(out)
        print("  [INFO] kept the live server line(s) in %s" % rel)
    open(s_path, "w").write(text)
keep_ldap_settings()
# clients.conf: the secret inside `client localhost { ... }`
s_path = os.path.join(staged, "clients.conf")
if os.path.exists(s_path) and "REDACTED" in open(s_path).read():
    rx = r"(client[ \t]+localhost[ \t]*\{[^}]*?^[ \t]*secret[ \t]*=)([^\n]*)$"
    lt = open(os.path.join(live, "clients.conf")).read()
    m = re.search(rx, lt, re.M | re.S)
    if not m or "REDACTED" in m.group(2) or not m.group(2).strip():
        sys.exit("cannot find the secret of `client localhost` in the live clients.conf; "
                 "refusing to install clients.conf (fix by hand, nothing changed)")
    t = re.sub(rx, lambda x: x.group(1) + m.group(2), open(s_path).read(), count=1, flags=re.M | re.S)
    open(s_path, "w").write(t)
    print("  [INFO] kept existing localhost client secret in clients.conf")
for root, _, files in os.walk(staged):
    for f in files:
        for ln in open(os.path.join(root, f), errors="replace"):
            if "REDACTED" in ln and not ln.lstrip().startswith("#"):
                sys.exit("placeholder REDACTED left in %s" % os.path.join(root, f))
PY
}

ldap_bind_check() { # ldap_bind_check FILE : log in to AD with the identity/password FreeRADIUS will use
    # radiusd -XC never contacts AD, so a wrong bind account or password only shows when
    # FreeRADIUS restarts (rlm_ldap "Invalid credentials", data 52e) -- and then it will not
    # start at all. Test the login before anything is installed.
    local f=$1
    if ! command -v ldapwhoami >/dev/null 2>&1; then
        warn "ldapwhoami not installed (apt install ldap-utils): AD bind account NOT tested before install"
        return 0
    fi
    local out rc
    out=$(python3 - "$f" "$RA_RADDB" <<'PY'
import re, subprocess, sys, os, tempfile
f, raddb = sys.argv[1:3]
t = open(f).read()
def val(key):
    m = re.search(r"^[ \t]*%s[ \t]*=[ \t]*(?:'([^']*)'|\"([^\"]*)\"|(\S+))" % key, t, re.M)
    return None if not m else next(g for g in m.groups() if g is not None)
server, ident, pw = val("server"), val("identity"), val("password")
ca = val("ca_file")
if not (server and ident and pw is not None):
    print("SKIP could not read server/identity/password"); sys.exit(0)
if ca:
    ca = ca.replace("${certdir}", os.path.join(raddb, "certs")).replace("${confdir}", raddb)
uri = server if "://" in server else "ldaps://" + server
fd, pf = tempfile.mkstemp(); os.write(fd, pw.encode()); os.close(fd)
env = dict(os.environ, LDAPTLS_REQCERT="demand")
if ca and os.path.exists(ca):
    env["LDAPTLS_CACERT"] = ca
try:
    r = subprocess.run(["ldapwhoami", "-x", "-H", uri, "-D", ident, "-y", pf], capture_output=True, text=True,
                       timeout=20, env=env)
    msg = (r.stdout + r.stderr).strip().replace("\n", " ")[:300]
    print(("OK " if r.returncode == 0 else ("BADCRED " if "Invalid credentials" in msg else "FAIL ")) + msg)
except Exception as e:
    print("FAIL %s" % e)
finally:
    os.unlink(pf)
PY
)
    rc=$?
    case $out in
        OK*) ok "AD bind with the LDAP service account works" ;;
        BADCRED*) die "AD rejects the LDAP bind account/password in mods-available/ldap ($out). FreeRADIUS would not start with it; nothing was changed. Fix identity/password in $RA_RADDB/mods-available/ldap first." ;;
        SKIP*) warn "AD bind not tested: ${out#SKIP }" ;;
        *) warn "AD bind test inconclusive (rc $rc): ${out#FAIL } -- check that FreeRADIUS starts after the next Apply" ;;
    esac
}

install_app_code() {
    local tmp
    tmp=$(mktemp -d "$OPT/.app.XXXXXX")
    cp -r "$SRC/app/radius_admin" "$tmp/radius_admin"
    find "$tmp" -name '__pycache__' -type d -prune -exec rm -rf {} +
    find "$tmp" -type d -exec chmod 0755 {} +
    find "$tmp" -type f -exec chmod 0644 {} +
    chown -R root:root "$tmp"
    "$RA_PYTHON" -m compileall -q "$tmp/radius_admin" >/dev/null || true
    if [[ -d $OPT/app/radius_admin ]] && diff -rq -x __pycache__ "$tmp/radius_admin" "$OPT/app/radius_admin" >/dev/null; then
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$OPT/app/radius_admin.old"
    if [[ -d $OPT/app/radius_admin ]]; then mv "$OPT/app/radius_admin" "$OPT/app/radius_admin.old"; fi
    mv "$tmp/radius_admin" "$OPT/app/radius_admin"
    rm -rf "$tmp" "$OPT/app/radius_admin.old"
    info "application code installed in $OPT/app"
    return 0
}

install_app_config() {
    if [[ ! -e $ETC/radius-admin.conf ]]; then
        install -o root -g radius-admin -m 0640 "$HERE/etc/radius-admin.conf.example" "$ETC/radius-admin.conf"
        sed -i "s|^# server_name = .*|server_name = $RA_SERVER_NAME|" "$ETC/radius-admin.conf"
        info "created $ETC/radius-admin.conf"
    else
        chown root:radius-admin "$ETC/radius-admin.conf"; chmod 0640 "$ETC/radius-admin.conf"
    fi
}

phase_freeradius() {
    hdr "Phase freeradius"
    detect_fr
    info "service $FR_SVC, binary $RADIUSD"
    local lib; lib=$(detect_fr_libdir "$RADIUSD" || true)
    [[ -n $lib && -e $lib/rlm_sql_postgresql.so ]] || die "rlm_sql_postgresql.so not found in ${lib:-<unknown libdir>}; rebuild FreeRADIUS with libpq-dev (RUNBOOK 'Prerequisites')"
    psql_su -d radius -At -c 'SELECT 1 FROM ui.access_rule LIMIT 1' >/dev/null 2>&1 \
        || die "database radius not initialised (run --phase postgres)"
    local nrules; nrules=$(psql_su -d radius -At -c 'SELECT count(*) FROM ui.access_rule')
    (( nrules > 0 )) || die "ui.access_rule is empty -- run the migrate phase first (--phase migrate --confirm-migrate); refusing to install a policy that rejects every EAP user"

    # 1. full backup of the current configuration (this tarball IS the rollback)
    local tarball=$RA_BACKUP_DIR/freeradius-$TS.tar.gz
    tar -C / --numeric-owner -czpf "$tarball" "${RA_RADDB#/}"
    chmod 0600 "$tarball"
    ok "backup $tarball ($(du -h "$tarball" | cut -f1))"

    # 2. build the candidate files in a staging copy and carry over live secrets
    local work; work=$(mktemp -d /tmp/radius-admin-fr.XXXXXX)
    trap 'rm -rf "$work"' RETURN
    (cd "$SRC/freeradius" && find . -type f ! -path './diffs/*' ! -name 'modules-to-disable.txt' -print0 \
        | xargs -0 -I{} install -D -m 0600 {} "$work/{}")
    carry_over_secrets "$work" || die "could not carry over secrets; nothing changed"
    ldap_bind_check "$work/mods-available/ldap"

    # 3. render policy + clients from the database (as the app would)
    install_app_code || true
    install_app_config
    local rdir; rdir=$(mktemp -d "$STAGING/.render.XXXXXX")
    chown radius-admin:radius-admin "$rdir"
    if ! app_env "$RA_PYTHON" -m radius_admin.cli render --out-dir "$rdir"; then
        rm -rf "$rdir"
        die "radius_admin.cli render failed; nothing in $RA_RADDB changed"
    fi
    [[ -s $rdir/policy && -s $rdir/clients ]] || { rm -rf "$rdir"; die "render produced no files"; }
    install -D -m 0600 "$rdir/policy" "$work/policy.d/radius-admin"
    install -D -m 0600 "$rdir/clients" "$work/radius-admin-clients.conf"
    # keep them as the app's staged state so the UI starts with "nothing pending" diffs
    install -o radius-admin -g radius-admin -m 0600 "$rdir/policy" "$STAGING/policy"
    install -o radius-admin -g radius-admin -m 0600 "$rdir/clients" "$STAGING/clients"
    rm -rf "$rdir"

    # 4. install
    local f rel dst
    while IFS= read -r -d '' f; do
        rel=${f#"$work"/}
        dst=$RA_RADDB/$rel
        install -d -o root -g freerad -m 0750 "$(dirname "$dst")"
        if [[ -e $dst ]]; then
            # keep existing ownership/mode of files we replace
            install -o "$(stat -c %u "$dst")" -g "$(stat -c %g "$dst")" -m "$(stat -c %a "$dst")" "$f" "$dst"
        else
            install -o root -g freerad -m 0640 "$f" "$dst"
        fi
    done < <(find "$work" -type f -print0)
    for rel in policy.d/radius-admin radius-admin-clients.conf; do
        chown root:freerad "$RA_RADDB/$rel"; chmod 0640 "$RA_RADDB/$rel"
    done
    ok "installed FreeRADIUS configuration files"

    local m
    while read -r m; do
        m=${m%%#*}; m=${m//[[:space:]]/}
        [[ -z $m ]] && continue
        [[ $m =~ ^[A-Za-z0-9_.-]+$ ]] || { warn "ignoring odd module name '$m'"; continue; }
        if [[ -L $RA_RADDB/mods-enabled/$m ]]; then rm -f "$RA_RADDB/mods-enabled/$m"; info "disabled module $m"; fi
    done < "$SRC/freeradius/modules-to-disable.txt"
    if [[ -L $RA_RADDB/sites-enabled/inner-tunnel ]]; then
        rm -f "$RA_RADDB/sites-enabled/inner-tunnel"; info "removed sites-enabled/inner-tunnel"
    fi
    [[ -L $RA_RADDB/mods-enabled/sql ]] || ln -s ../mods-available/sql "$RA_RADDB/mods-enabled/sql"
    if [[ -d $RA_RADDB/policy.d ]]; then chmod o-w "$RA_RADDB/policy.d"; fi

    # 5. validate; on failure restore the tarball (the running daemon is untouched)
    if fr_check "$RA_RADDB"; then
        ok "radiusd -XC: configuration appears to be OK"
    else
        bad "radiusd -XC failed; restoring $tarball"
        restore_raddb "$tarball"
        die "freeradius phase failed; previous configuration restored (service was not restarted)"
    fi
    if (( RESTART_FR )); then
        systemctl restart "$FR_SVC.service"
        for _ in $(seq 1 15); do
            systemctl is-active --quiet "$FR_SVC.service" && ss -H -lun | awk '{print $4}' | grep -q ':1812$' && break
            sleep 1
        done
        if systemctl is-active --quiet "$FR_SVC.service" && ss -H -lun | awk '{print $4}' | grep -q ':1812$'; then
            ok "$FR_SVC restarted and listening on UDP 1812"
        else
            bad "$FR_SVC did not come up; restoring $tarball"
            restore_raddb "$tarball"
            systemctl restart "$FR_SVC.service" || true
            die "restart failed; previous configuration restored and restarted"
        fi
    else
        warn "FreeRADIUS NOT restarted (running daemon still uses the old config). Restart in the maintenance window: systemctl restart $FR_SVC  (or re-run with --restart-freeradius)"
    fi
    say "  Rollback for this change: sudo $HERE/rollback.sh --tarball $tarball"
}

restore_raddb() {
    local tarball=$1 keep
    keep="$RA_RADDB.failed-$TS"
    mv "$RA_RADDB" "$keep"; chmod 0700 "$keep"
    tar -C / --numeric-owner -xzpf "$tarball"
    info "restored $RA_RADDB (failed tree kept at $keep, mode 0700)"
}

phase_app() {
    hdr "Phase app"
    detect_fr
    install_app_code || ok "application code unchanged"
    install -d -o root -g root -m 0755 "$OPT/docs"
    for f in README.md docs/RUNBOOK.md docs/SECURITY.md; do
        if [[ -f $SRC/$f ]]; then install -m 0644 "$SRC/$f" "$OPT/docs/$(basename "$f")"; fi
    done
    install_app_config
    put "$SRC/helper/radius-admin-helper" "$HELPER_BIN" root:root 0755 || true

    # helper.conf (root:root 0644): detected service name / radiusd path
    local hc=$ETC/helper.conf tmp
    tmp=$(mktemp)
    sed -e "s#^service = .*#service = $FR_SVC#" -e "s#^radiusd = .*#radiusd = $RADIUSD#" \
        -e "s#^raddb = .*#raddb = $RA_RADDB#" "$HERE/etc/helper.conf.example" > "$tmp"
    if [[ -e $hc ]]; then
        if ! cmp -s "$tmp" "$hc"; then
            local cur_s cur_r
            cur_s=$(sed -n 's/^service *= *//p' "$hc"); cur_r=$(sed -n 's/^radiusd *= *//p' "$hc")
            if [[ $cur_s != "$FR_SVC" || $cur_r != "$RADIUSD" ]]; then
                warn "$hc has service=$cur_s radiusd=$cur_r but detection found $FR_SVC / $RADIUSD (kept; edit by hand if wrong)"
            else
                info "$hc differs from the template (kept; local edits)"
            fi
        fi
        chown root:root "$hc"; chmod 0644 "$hc"
    else
        install -o root -g root -m 0644 "$tmp" "$hc"; info "created $hc"
    fi
    rm -f "$tmp"

    local u reload=0
    for u in radius-admin.service radius-admin-helper.socket radius-admin-helper@.service; do
        if put "$HERE/systemd/$u" "/etc/systemd/system/$u" root:root 0644; then reload=1; fi
    done
    if put "$HERE/firewall/radius-admin-firewall.service" /etc/systemd/system/radius-admin-firewall.service root:root 0644; then reload=1; fi
    # SNMP monitor: network access only to the management subnet
    local snmpu; snmpu=$(mktemp)
    sed -e "s#@ADMIN_NET@#$RA_ADMIN_NET#g" "$HERE/systemd/radius-admin-snmp.service" > "$snmpu"
    if grep -v '^[[:space:]]*#' "$snmpu" | grep -qE '@[A-Z_]+@'; then rm -f "$snmpu"; die "unrendered placeholder in radius-admin-snmp.service"; fi
    if put "$snmpu" /etc/systemd/system/radius-admin-snmp.service root:root 0644; then reload=1; fi
    rm -f "$snmpu"
    if (( reload )); then systemctl daemon-reload; fi
    if command -v rsyslogd >/dev/null 2>&1; then
        if put "$HERE/rsyslog/30-radius-admin.conf" /etc/rsyslog.d/30-radius-admin.conf root:root 0644; then
            systemctl restart rsyslog
        fi
        put "$HERE/logrotate/radius-admin" /etc/logrotate.d/radius-admin root:root 0644 || true
    else
        warn "rsyslog not installed: logs remain in the journal only (journalctl -t radius-admin -t radius-admin-helper)"
    fi

    systemctl enable --now radius-admin-helper.socket >/dev/null
    if ! command -v snmpget >/dev/null 2>&1; then
        warn "Net-SNMP tools missing (apt install snmp): switch monitoring will report errors"
    fi
    # Disconnect / re-authenticate use radclient from the FreeRADIUS build (SPEC section 13)
    local rc_found="" d
    for d in /usr/local/bin /usr/bin /usr/local/sbin /usr/sbin /opt/freeradius/bin "$(dirname "$RADIUSD")" \
             "$(dirname "$(dirname "$RADIUSD")")/bin"; do
        if [[ -x $d/radclient ]]; then rc_found=$d/radclient; break; fi
    done
    if [[ -n $rc_found ]]; then
        ok "radclient found: $rc_found (disconnect / re-authenticate available)"
        if [[ $rc_found != /usr/local/bin/radclient && $rc_found != /usr/bin/radclient && \
              $rc_found != /usr/local/sbin/radclient && $rc_found != /usr/sbin/radclient && \
              $rc_found != /opt/freeradius/bin/radclient ]] && ! grep -q '^radclient *=' "$ETC/radius-admin.conf"; then
            warn "radclient is not in a standard path: add 'radclient = $rc_found' to $ETC/radius-admin.conf [app]"
        fi
    else
        warn "radclient not found: session disconnect / re-authenticate will be unavailable (install it with the FreeRADIUS build)"
    fi
    if [[ ! -s /usr/share/ieee-data/oui.csv ]]; then
        warn "ieee-data missing (apt install ieee-data): MAC vendor names will not be shown"
    fi
    systemctl enable radius-admin-snmp.service >/dev/null
    systemctl restart radius-admin-snmp.service
    if systemctl is-active --quiet radius-admin-snmp.service; then
        ok "radius-admin-snmp.service running (alerts, session actions; switch polling once enabled in the UI)"
    else
        journalctl -u radius-admin-snmp.service -n 20 --no-pager >&2 || true
        warn "radius-admin-snmp.service is not running (the web UI is unaffected)"
    fi
    systemctl enable radius-admin.service >/dev/null
    systemctl restart radius-admin.service
    for _ in $(seq 1 20); do [[ -S /run/radius-admin/app.sock ]] && break; sleep 1; done
    if systemctl is-active --quiet radius-admin.service && [[ -S /run/radius-admin/app.sock ]]; then
        ok "radius-admin.service running ($(stat -c '%A %U:%G' /run/radius-admin/app.sock) app.sock)"
    else
        journalctl -u radius-admin.service -n 30 --no-pager >&2 || true
        die "radius-admin.service failed to start"
    fi
    local code
    # Test as www-data: that is who nginx connects as, so this proves the socket
    # permissions as well as the app.
    code=$(runuser -u www-data -- curl -s -o /dev/null -w '%{http_code}' --unix-socket /run/radius-admin/app.sock \
        -H "Host: $RA_SERVER_NAME" -H 'X-Real-IP: 127.0.0.1' "http://$RA_SERVER_NAME/login" || true)
    if [[ $code =~ ^(200|302|303)$ ]]; then
        ok "app answers /login for www-data (HTTP $code)"
    else
        die "www-data (nginx) cannot reach the app: HTTP $code -- check: ls -ld /run/radius-admin; sudo ls -l /run/radius-admin; id www-data"
    fi
    local st
    st=$(printf '{"action":"status"}\n' | runuser -u radius-admin -- "$RA_PYTHON" -c '
import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect("/run/radius-admin-helper.sock")
s.sendall(sys.stdin.buffer.read()); print(s.recv(65536).decode().strip())' 2>&1 || true)
    if [[ $st == *'"ok":true'* ]]; then ok "helper reachable by radius-admin: $st"; else warn "helper status failed: $st"; fi
}

phase_nginx() {
    hdr "Phase nginx"
    local ip=${LISTEN_IP:-$(detect_vlan_ip "$RA_ADMIN_NET" || true)}
    [[ -n $ip ]] || die "no address in $RA_ADMIN_NET found; pass --listen-ip"
    local res=${RESOLVER:-$(detect_resolvers || true)}
    [[ -n $res ]] || die "no DNS resolver detected; pass --resolver \"IP [IP]\""
    local key=$ETC/tls/server.key crt=$ETC/tls/server.crt
    [[ -s $key ]] || die "$key missing: run deploy/make-csr.sh, have pki.example.net issue the certificate"
    [[ -s $crt ]] || die "$crt missing: install the issued certificate (leaf first, then the site intermediate) at $crt"
    chown root:root "$key" "$crt"; chmod 0600 "$key"; chmod 0644 "$crt"
    [[ $(openssl x509 -in "$crt" -noout -pubkey | openssl sha256) == "$(openssl pkey -in "$key" -pubout | openssl sha256)" ]] \
        || die "$crt does not match $key"
    openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:$RA_SERVER_NAME" \
        || die "$crt has no subjectAltName DNS:$RA_SERVER_NAME"
    openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null || warn "$crt expires within 30 days"
    local ca=$RA_RADDB/certs/site/ca.pem
    [[ -s $ca ]] || die "$ca missing (site CA bundle for client certificates)"
    put "$ca" "$ETC/tls/client-ca.pem" root:root 0644 || true
    if ! openssl verify -CAfile "$ETC/tls/client-ca.pem" -untrusted "$crt" "$crt" >/dev/null 2>&1; then
        warn "server certificate does not verify against the site CA bundle (wrong issuer or missing intermediate in server.crt?)"
    fi
    getent hosts "$RA_OCSP_HOST" >/dev/null || die "$RA_OCSP_HOST does not resolve; nginx would refuse ssl_ocsp_responder"

    local tmp; tmp=$(mktemp)
    sed -e "s#@LISTEN_IP@#$ip#g" -e "s#@SERVER_NAME@#$RA_SERVER_NAME#g" -e "s#@ADMIN_NET@#$RA_ADMIN_NET#g" \
        -e "s#@RESOLVER@#$res#g" -e "s#@OCSP_URL@#$RA_OCSP_URL#g" "$HERE/nginx/radius-admin.conf" > "$tmp"
    if grep -v '^[[:space:]]*#' "$tmp" | grep -qE '@[A-Z_]+@'; then
        die "unrendered placeholder in nginx config: $(grep -v '^[[:space:]]*#' "$tmp" | grep -oE '@[A-Z_]+@' | sort -u | tr '\n' ' ')"
    fi
    local site=/etc/nginx/sites-available/radius-admin old=""
    if [[ -e $site ]]; then old=$(mktemp); cp -p "$site" "$old"; fi
    put "$tmp" "$site" root:root 0644 || true
    rm -f "$tmp"
    ln -sfn "$site" /etc/nginx/sites-enabled/radius-admin
    if [[ -L /etc/nginx/sites-enabled/default ]]; then rm -f /etc/nginx/sites-enabled/default; info "disabled nginx default site (port 80)"; fi
    if ! nginx -t 2>&1 | sed 's/^/    | /'; then :; fi
    if nginx -t >/dev/null 2>&1; then
        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl reload-or-restart nginx
        ok "nginx serving https://$RA_SERVER_NAME on $ip:443 (resolver $res)"
        if [[ -n $old ]]; then rm -f "$old"; fi
    else
        if [[ -n $old ]]; then cp -p "$old" "$site"; rm -f "$old"; else rm -f /etc/nginx/sites-enabled/radius-admin; fi
        die "nginx -t failed; previous site restored"
    fi
    if ss -H -ltn | awk '{print $4}' | grep -qE '(^|[^0-9])(0\.0\.0\.0|\*|\[::\]):80$'; then
        warn "something still listens on TCP port 80 (another nginx site?)"
    fi
}

phase_firewall() {
    hdr "Phase firewall"
    local ip=${LISTEN_IP:-$(detect_vlan_ip "$RA_ADMIN_NET" || true)}
    [[ -n $ip ]] || die "no address in $RA_ADMIN_NET found; pass --listen-ip"
    local fw; fw=$(detect_firewall)
    info "active host firewall: $fw"
    local tmp; tmp=$(mktemp)
    sed -e "s#@LISTEN_IP@#$ip#g" -e "s#@ADMIN_NET@#$RA_ADMIN_NET#g" "$HERE/firewall/radius-admin.nft" > "$tmp"
    nft -c -f "$tmp" || die "nft rejected the generated rules"
    put "$tmp" "$ETC/firewall.nft" root:root 0644 || true
    rm -f "$tmp"
    if put "$HERE/firewall/radius-admin-firewall.service" /etc/systemd/system/radius-admin-firewall.service root:root 0644; then
        systemctl daemon-reload
    fi
    systemctl enable radius-admin-firewall.service >/dev/null
    systemctl restart radius-admin-firewall.service
    ok "nftables table inet radius_admin: TCP 443 on $ip only from $RA_ADMIN_NET"
    case $fw in
        ufw)
            if ! ufw status | grep -qE "^$ip 443/tcp +ALLOW +$RA_ADMIN_NET"; then
                ufw allow proto tcp from "$RA_ADMIN_NET" to "$ip" port 443 comment 'radius-admin UI' >/dev/null
                info "ufw: allowed 443/tcp from $RA_ADMIN_NET to $ip"
            fi
            if ufw status | grep -qE '^(80|80/tcp) +ALLOW'; then warn "ufw allows port 80 -- not needed by radius-admin"; fi
            ;;
        nftables)
            if nft list ruleset | grep -A3 'hook input' | grep -q 'policy drop' ; then
                warn "an nftables input chain with policy drop exists (/etc/nftables.conf). Add there: tcp dport 443 ip saddr $RA_ADMIN_NET ip daddr $ip accept"
            fi
            ;;
        iptables)
            warn "legacy iptables rules present; make sure they allow tcp/443 from $RA_ADMIN_NET (the radius_admin nft table enforces the restriction)"
            ;;
        none)
            info "no other firewall active: radius_admin table is the only filter (RADIUS/SSH unaffected)"
            ;;
    esac
}

phase_site() {
    hdr "Phase site"
    if (( ! USE_ANSWERS )); then
        info "no answers given (--answers / --interactive): site.yaml and certificate unchanged"
        return 0
    fi
    install -d -o root -g root -m 0755 "$ETC"
    install -d -o root -g root -m 0700 "$ETC/tls"
    local tmp; tmp=$(mktemp)
    ans_print > "$tmp"
    put "$tmp" "$ETC/site.yaml" root:root 0640 || true
    rm -f "$tmp"
    local key=$ETC/tls/server.key crt=$ETC/tls/server.crt
    case ${ANS[tls]} in
        self-signed)
            if [[ -s $key && -s $crt ]]; then
                info "portal certificate exists ($crt): kept"
            else
                # ECDSA P-384 / SHA-384: FIPS-approved; replace it later with one from your CA
                openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -nodes -days 825 \
                    -subj "/CN=$RA_SERVER_NAME" -addext "subjectAltName=DNS:$RA_SERVER_NAME,IP:$LISTEN_IP" \
                    -addext "extendedKeyUsage=serverAuth" -keyout "$key" -out "$crt" 2>/dev/null \
                    || die "could not create a self-signed certificate"
                chmod 0600 "$key"; chmod 0644 "$crt"
                warn "self-signed portal certificate created for $RA_SERVER_NAME: browsers will warn until you replace it"
            fi ;;
        csr)
            if [[ -s $crt ]]; then
                info "portal certificate exists ($crt): kept"
            else
                "$HERE/make-csr.sh" --name "$RA_SERVER_NAME" --ip "$LISTEN_IP" --dir "$ETC/tls"
                CSR_PENDING=1
            fi ;;
        existing)
            put "${ANS[tls_cert]}" "$crt" root:root 0644 || true
            put "${ANS[tls_key]}" "$key" root:root 0600 || true ;;
    esac
    ok "site settings in $ETC/site.yaml"
}

phase_bootstrap() {
    hdr "Bootstrap: first administrator"
    if (( USE_ANSWERS )) && [[ -n ${ANS[admin_username]:-} ]]; then
        local out
        if out=$(app_env python3 -m radius_admin.cli create-admin --username "${ANS[admin_username]}" --role admin 2>&1); then
            printf '%s\n' "$out" | sed 's/^/    /'
            say "  Browse from a host in $RA_ADMIN_NET to https://$RA_SERVER_NAME/ , sign in with this"
            say "  one-time password, choose your own and set up two-factor authentication."
            say "  The setup checklist on the dashboard lists what to configure next."
            return 0
        elif grep -q "already exists" <<<"$out"; then
            info "administrator ${ANS[admin_username]} already exists: unchanged"
            return 0
        fi
        printf '%s\n' "$out" | sed 's/^/    | /' >&2
        die "could not create administrator ${ANS[admin_username]}"
    fi
    cat <<EOF
  Create the first UI administrator (prints a one-time temporary password):

    sudo -u radius-admin env RADIUS_ADMIN_CONFIG=$ETC/radius-admin.conf PYTHONPATH=$OPT/app \\
        python3 -m radius_admin.cli create-admin --username <name> --role admin

  Then browse from a host in $RA_ADMIN_NET to https://$RA_SERVER_NAME/ , acknowledge the
  banner, sign in, change the password and enrol TOTP (or a client certificate).

  Other checks:
    sudo -u radius-admin env RADIUS_ADMIN_CONFIG=$ETC/radius-admin.conf PYTHONPATH=$OPT/app python3 -m radius_admin.cli check-fips
    sudo -u radius-admin env RADIUS_ADMIN_CONFIG=$ETC/radius-admin.conf PYTHONPATH=$OPT/app python3 -m radius_admin.cli verify-audit
EOF
}

# ------------------------------------------------------------------------------ main

say "${C_BLD}radius-admin installer${C_OFF} -- phases: ${PHASES[*]}"
if want freeradius || want migrate; then
    say "This changes the FreeRADIUS configuration/database. Use a maintenance window."
    confirm "Continue?" || die "aborted"
fi
for p in "${ALL_PHASES[@]}"; do
    want "$p" || continue
    case $p in
        preflight) phase_preflight ;;
        packages) phase_packages ;;
        users) phase_users ;;
        postgres) phase_postgres ;;
        migrate) phase_migrate ;;
        freeradius) phase_freeradius ;;
        app) phase_app ;;
        site) phase_site
              if (( CSR_PENDING )); then
                  hdr "Waiting for the portal certificate"
                  say "  Submit $ETC/tls/server.csr to your CA, install the issued certificate (leaf first,"
                  say "  then intermediates) as $ETC/tls/server.crt, then continue with:"
                  say "    sudo $0 --answers $ETC/site.yaml --from nginx"
                  exit 0
              fi ;;
        nginx) phase_nginx ;;
        firewall) phase_firewall ;;
        bootstrap) phase_bootstrap ;;
    esac
done
hdr "Done"
if (( WARNINGS > 0 )); then say "  $WARNINGS warning(s) above -- review them."; fi
exit 0
