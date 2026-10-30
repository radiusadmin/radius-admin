#!/bin/bash
# radius-admin preflight: READ-ONLY report of everything the installer depends on.
# Changes nothing. Exit status: 0 = no blocking problems, 1 = blocking problems found.
#
#   sudo ./deploy/preflight.sh [--sqlite PATH] [--admin-net CIDR]
set -euo pipefail
umask 077
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

while [[ $# -gt 0 ]]; do
    case $1 in
        --sqlite) RA_SQLITE_DB=$2; shift 2 ;;
        --admin-net) RA_ADMIN_NET=$2; shift 2 ;;
        -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done
require_root

hdr "System"
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ ${VERSION_ID:-} == 24.04 ]]; then ok "$PRETTY_NAME"; else warn "untested OS: ${PRETTY_NAME:-unknown} (target Ubuntu 24.04)"; fi
fi
info "kernel $(uname -r)"
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo none)
if [[ $PYV == 3.12 ]]; then ok "python3 $PYV"; else warn "python3 is $PYV (target 3.12)"; fi

hdr "FIPS"
FIPS=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)
if [[ $FIPS == 1 ]]; then ok "kernel FIPS mode on (/proc/sys/crypto/fips_enabled = 1)"; else bad "kernel FIPS mode OFF (/proc/sys/crypto/fips_enabled = $FIPS)"; fi
info "$(openssl version 2>/dev/null || echo 'openssl: not found')"
if openssl list -providers 2>/dev/null | grep -qi fips; then ok "OpenSSL FIPS provider loaded"; else bad "OpenSSL FIPS provider not active"; fi
if python3 -c 'import _hashlib,sys; sys.exit(0 if _hashlib.get_fips_mode()==1 else 1)' 2>/dev/null; then
    ok "Python hashlib reports FIPS mode"
else
    bad "Python _hashlib.get_fips_mode() != 1 (app refuses to start with require_fips=true)"
fi
if command -v pro >/dev/null 2>&1; then
    PRO=$(pro status 2>/dev/null || true)
    if grep -Eq '^fips-updates +yes +enabled' <<<"$PRO"; then
        warn "Ubuntu Pro stream is fips-updates: packages carry security fixes that are NOT (yet) part of the CMVP-validated module versions. For strict FIPS 140 validated status use the 'fips' stream (see docs/SECURITY.md)."
    elif grep -Eq '^fips +yes +enabled' <<<"$PRO"; then
        ok "Ubuntu Pro stream: fips (validated module versions)"
    else
        warn "neither fips nor fips-updates shows as enabled in 'pro status'"
    fi
else
    warn "'pro' command not found; cannot determine FIPS stream"
fi

hdr "FreeRADIUS"
SVC=$(detect_fr_service || true)
if [[ -n $SVC ]]; then
    ok "systemd unit: $SVC.service ($(systemctl is-active "$SVC.service" 2>/dev/null || true), $(systemctl is-enabled "$SVC.service" 2>/dev/null || true))"
else
    bad "no freeradius.service or radiusd.service unit found"
fi
RADIUSD=$(detect_radiusd "$SVC" || true)
if [[ -n $RADIUSD ]]; then
    ok "radiusd binary: $RADIUSD"
    VER=$("$RADIUSD" -v 2>/dev/null | head -n1 || true)
    info "${VER:-version unknown}"
    [[ $VER == *3.2.10* ]] || warn "expected FreeRADIUS 3.2.10"
    if "$RADIUSD" -v 2>/dev/null | grep -q WITH_VERIFY_PTR; then warn "radiusd is a developer build (WITH_VERIFY_PTR): rebuild with --disable-developer for production"; fi
    for f in "$(dirname "$(dirname "$RADIUSD")")"/src/freeradius*/config.log /usr/local/src/freeradius*/config.log; do
        [[ ! -r $f ]] || info "configure flags ($f): $(sed -n 's/^  \$ \(.*configure.*\)/\1/p' "$f" | head -n1)"
    done
    if strings "$RADIUSD" 2>/dev/null | grep -qi 'fips'; then info "radiusd binary references FIPS (built with FIPS workaround support)"; fi
    LIBDIR=$(detect_fr_libdir "$RADIUSD" || true)
    if [[ -n $LIBDIR ]]; then
        info "module dir: $LIBDIR"
        if [[ -e $LIBDIR/rlm_sql_postgresql.so ]]; then
            ok "rlm_sql_postgresql.so present"
            if ldd "$LIBDIR/rlm_sql_postgresql.so" 2>/dev/null | grep -q 'not found'; then
                bad "rlm_sql_postgresql.so has unresolved libraries (install libpq5): $(ldd "$LIBDIR/rlm_sql_postgresql.so" | grep 'not found' | tr -s ' ' | tr '\n' ';')"
            fi
        else
            bad "rlm_sql_postgresql.so MISSING in $LIBDIR. Rebuild FreeRADIUS: apt install libpq-dev; in the original source tree re-run ./configure with the SAME flags (incl. --enable-fips-workaround), check 'rlm_sql_postgresql ... OK' in the output, then make && make install. See docs/RUNBOOK.md."
        fi
        if [[ -e $LIBDIR/rlm_sql_sqlite.so ]]; then info "rlm_sql_sqlite.so present (needed for rollback)"; fi
        # LDAPS to AD: which TLS library does libldap use? (Ubuntu: GnuTLS -> outside the
        # OpenSSL FIPS provider; see docs/SECURITY.md section 1.1 exception 5)
        if [[ -e $LIBDIR/rlm_ldap.so ]]; then
            LDAPLIB=$(ldd "$LIBDIR/rlm_ldap.so" 2>/dev/null | awk '/libldap/ {print $3}' | head -n1)
            TLSLIB=$( { ldd "$LIBDIR/rlm_ldap.so"; if [[ -n $LDAPLIB ]]; then ldd "$LDAPLIB"; fi; } 2>/dev/null \
                | grep -oE 'lib(gnutls|ssl|crypto)\.so[.0-9]*' | sort -u | tr '\n' ' ')
            if grep -q gnutls <<<"$TLSLIB"; then
                warn "rlm_ldap -> ${LDAPLIB:-libldap} uses GnuTLS ($TLSLIB): LDAPS to AD is NOT protected by the OpenSSL FIPS provider and cipher_list does not apply. Restrict the DC (Schannel) to TLS1.2+/AES-GCM and verify whether this GnuTLS is a FIPS-validated module in your Ubuntu Pro stream (docs/SECURITY.md)."
            else
                info "rlm_ldap TLS libraries: ${TLSLIB:-unknown} (libldap ${LDAPLIB:-not found})"
            fi
        fi
    else
        warn "could not locate the FreeRADIUS module directory"
    fi
    if [[ -d $RA_RADDB ]] && id freerad >/dev/null 2>&1; then
        # Run as root, exactly like the service: radiusd parses its config files as root
        # (some, e.g. switches.conf, are root-only) and drops to "user = freerad" itself
        # before instantiating modules.
        if OUT=$(timeout 60 "$RADIUSD" -XC -d "$RA_RADDB" 2>&1) && grep -q 'appears to be OK' <<<"$OUT"; then
            ok "current configuration passes radiusd -XC"
        else
            bad "current configuration FAILS radiusd -XC: $(tail -n 3 <<<"$OUT" | tr '\n' ' ')"
        fi
    fi
else
    bad "radiusd binary not found (command -v radiusd freeradius)"
fi
if id freerad >/dev/null 2>&1; then ok "user freerad exists ($(id freerad))"; else bad "user freerad missing"; fi
if [[ -d $RA_RADDB ]]; then ok "raddb $RA_RADDB"; else bad "raddb $RA_RADDB missing"; fi

if [[ -d $RA_RADDB ]]; then
    SQLMOD=$RA_RADDB/mods-available/sql
    if [[ -r $SQLMOD ]]; then info "sql module: $(grep -E '^\s*(dialect|driver)\s*=' "$SQLMOD" | tr -s ' \t' ' ' | tr '\n' ' ')"; fi
    [[ ! -L $RA_RADDB/sites-enabled/inner-tunnel ]] || info "sites-enabled/inner-tunnel is enabled (installer removes it; EAP-TLS only)"
    CLIENTS=0
    for f in "$RA_RADDB/clients.conf" "$RA_RADDB/switches.conf" "$RA_RADDB/radius-admin-clients.conf"; do
        [[ -r $f ]] || continue
        n=$(grep -cE '^\s*client\s+\S+\s*\{' "$f" || true)
        info "$(basename "$f"): $n client(s)"
        CLIENTS=$((CLIENTS + n))
    done
    info "total RADIUS clients defined: $CLIENTS"
    AUTH=$RA_RADDB/mods-config/files/authorize
    if [[ -r $AUTH ]] && grep -Eq '^(bob|doug)\b' "$AUTH"; then
        warn "test accounts present in $AUTH: $(grep -Eo '^(bob|doug)\b' "$AUTH" | tr '\n' ' ')(Cleartext-Password) -- removed by the installer"
    fi
    CERTS=$RA_RADDB/certs
    TEST=()
    for f in ca.key ca.pem ca.der ca.crl server.key server.pem server.p12 server.crt client.key client.pem client.p12 client.crt 'user@example.org.pem' 'user@example.org.p12' 01.pem 02.pem passwords.mk; do
        if [[ -e $CERTS/$f ]]; then TEST+=("$f"); fi
    done
    if [[ ${#TEST[@]} -gt 0 ]]; then
        warn "FreeRADIUS bootstrap TEST CA material in $CERTS (incl. private keys): ${TEST[*]} -- remove after cut-over (RUNBOOK 'Clean-up')"
    fi
    if [[ -r $CERTS/site/ca.pem ]]; then
        ok "site CA bundle $CERTS/site/ca.pem ($(grep -c 'BEGIN CERTIFICATE' "$CERTS/site/ca.pem") certs)"
    else
        bad "$CERTS/site/ca.pem missing (needed for EAP-TLS and nginx client-cert CA)"
    fi
    if [[ -r $CERTS/site/radius.pem ]]; then
        info "EAP server cert $(openssl x509 -in "$CERTS/site/radius.pem" -noout -subject -enddate 2>/dev/null | tr '\n' ' ')"
    fi
    if grep -Eq '^\s*ldap_debug\s*=\s*0x[0-9a-fA-F]*[1-9a-fA-F]' "$RA_RADDB/mods-available/ldap" 2>/dev/null; then
        warn "ldap_debug is enabled in mods-available/ldap (set to 0x0000 by the installer)"
    fi
fi

hdr "SQLite database"
if [[ -r $RA_SQLITE_DB ]]; then
    ok "$RA_SQLITE_DB ($(du -h "$RA_SQLITE_DB" | cut -f1))"
    python3 - "$RA_SQLITE_DB" <<'PY' || warn "could not inspect SQLite database"
import sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
def n(sql):
    try:
        return db.execute(sql).fetchone()[0]
    except sqlite3.Error as e:
        return "n/a (%s)" % e
for t in ("radcheck", "radusergroup", "radreply", "radgroupreply", "radpostauth", "radacct", "nas"):
    print("  [INFO] %-13s %s rows" % (t, n("SELECT count(*) FROM %s" % t)))
p = n("SELECT count(*) FROM radpostauth WHERE pass IS NOT NULL AND pass <> ''")
if isinstance(p, int) and p > 0:
    print("  [WARN] radpostauth.pass is non-empty in %d rows: the SQLite DB contains CLEARTEXT"
          " passwords. It is NOT migrated; shred the file after cut-over and rotate the"
          " affected switch-admin passwords (RUNBOOK 'Secure disposal')." % p)
print("  [INFO] radcheck attributes: %s" % ", ".join(
    "%s x%d" % r for r in db.execute("SELECT attribute, count(*) FROM radcheck GROUP BY 1")))
PY
else
    warn "SQLite DB $RA_SQLITE_DB not readable (migration needs it)"
fi

hdr "Network"
VIP=$(detect_vlan_ip "$RA_ADMIN_NET" || true)
if [[ -n $VIP ]]; then ok "address in admin network $RA_ADMIN_NET: $VIP ($(ip -o -4 addr show | awk -v a="$VIP" 'index($4, a"/")==1 {print $2}'))"; else bad "no local IPv4 address inside $RA_ADMIN_NET (nginx must bind to it; pass --listen-ip to install.sh)"; fi
info "UDP listeners 1812/1813: $(ss -H -lun 2>/dev/null | awk '$4 ~ /:(1812|1813)$/ {print $4}' | tr '\n' ' ')"
TCP=$(ss -H -ltn 2>/dev/null | awk '$4 ~ /:(80|443|5432)$/ {print $4}' | tr '\n' ' ')
info "TCP listeners on 80/443/5432: ${TCP:-none}"
FW=$(detect_firewall)
info "host firewall in use: $FW"
[[ $FW != none ]] || warn "no active host firewall detected; installer adds an nftables table restricting 443 only"
RES=$(detect_resolvers || true)
if [[ -n $RES ]]; then ok "DNS resolvers for nginx OCSP: $RES"; else warn "no DNS resolver found (pass --resolver to install.sh)"; fi
if getent hosts "$RA_OCSP_HOST" >/dev/null; then ok "$RA_OCSP_HOST resolves ($(getent hosts "$RA_OCSP_HOST" | awk '{print $1}' | head -n1))"; else bad "$RA_OCSP_HOST does not resolve: nginx refuses to start with ssl_ocsp_responder pointing at an unresolvable host"; fi
if getent hosts "$RA_SERVER_NAME" >/dev/null; then info "$RA_SERVER_NAME -> $(getent hosts "$RA_SERVER_NAME" | awk '{print $1}' | head -n1)"; else warn "$RA_SERVER_NAME does not resolve on this host (DNS record needed for admins)"; fi

hdr "Existing components"
for p in nginx postgresql postgresql-16 python3-flask python3-psycopg2 gunicorn python3-cryptography python3-qrcode python3-pysaml2 xmlsec1 nftables; do
    s=$(dpkg-query -W -f='${Status} ${Version}' "$p" 2>/dev/null || true)
    if [[ $s == "install ok installed"* ]]; then
        info "$p installed (${s##* })"
    else
        c=$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/ {print $2}')
        if [[ -n $c && $c != "(none)" ]]; then info "$p not installed (candidate $c from mirror)"; else bad "$p not installed and not available from apt"; fi
    fi
done
if command -v pg_lsclusters >/dev/null 2>&1; then
    info "PostgreSQL clusters: $(pg_lsclusters --no-header 2>/dev/null | awk '{print $1"/"$2" port "$3" "$4}' | tr '\n' ';')"
    if pg_lsclusters --no-header 2>/dev/null | grep -q online; then
        DBS=$(runuser -u postgres -- psql -XAtq -c "SELECT string_agg(datname, ',') FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')" 2>/dev/null || true)
        info "existing databases: ${DBS:-none}"
    fi
fi
if [[ -e /etc/nginx/sites-enabled ]]; then info "nginx sites enabled: $(find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null)"; fi
for u in radius-admin.service radius-admin-helper.socket; do
    systemctl list-unit-files --no-legend "$u" 2>/dev/null | grep -q . && info "$u already installed ($(systemctl is-active "$u" 2>/dev/null || true))"
done
[[ ! -e /etc/radius-admin/tls/server.crt ]] || info "UI certificate: $(openssl x509 -in /etc/radius-admin/tls/server.crt -noout -subject -enddate 2>/dev/null | tr '\n' ' ')"
[[ -e /etc/radius-admin/tls/server.crt ]] || info "UI certificate not yet installed (deploy/make-csr.sh, then place the issued cert at /etc/radius-admin/tls/server.crt)"

hdr "Disk"
for d in / /var /var/lib/postgresql /var/backups; do
    [[ -d $d ]] || continue
    avail=$(df -Pk "$d" | awk 'NR==2 {print $4}')
    if (( avail < 2097152 )); then warn "$d: only $((avail / 1024)) MiB free (want >= 2 GiB)"; else ok "$d: $((avail / 1024)) MiB free"; fi
done

hdr "Summary"
say "  warnings: $WARNINGS   blocking failures: $FAILURES"
if (( FAILURES > 0 )); then
    say "  Resolve the [FAIL] items before running install.sh."
    exit 1
fi
exit 0
