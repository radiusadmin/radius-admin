#!/bin/bash
# Prepare a throwaway Ubuntu 24.04 machine (CI runner or sandbox VM) for the test suites.
# Run as root. NEVER on a server that matters: it changes pg_hba, /etc/hosts and AppArmor,
# drops and creates databases, and adds loopback addresses.
#   tools/ci/setup.sh [REPO]        REPO = checkout readable by the postgres user (default /srv/radius-admin)
set -euo pipefail
REPO=${1:-/srv/radius-admin}
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q --no-install-recommends \
    build-essential libtalloc-dev libssl-dev libpq-dev libldap-dev pkg-config dpkg-dev \
    libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
    postgresql-16 sqlite3 slapd ldap-utils snmp snmpd radsecproxy \
    python3 python3-flask python3-psycopg2 python3-cryptography python3-qrcode python3-pytest \
    python3-pysaml2 xmlsec1 ieee-data gunicorn shellcheck openssl gnupg curl ca-certificates iproute2 procps
# the tests start their own slapd / snmpd / radsecproxy
systemctl disable --now slapd snmpd radsecproxy >/dev/null 2>&1 || true
# AppArmor (CI runners enforce it): the packaged profiles keep slapd and snmpd out of the
# test directories, so unload them on this throwaway machine.
for p in usr.sbin.slapd usr.sbin.snmpd; do
    if [[ -f /etc/apparmor.d/$p ]] && command -v apparmor_parser >/dev/null; then
        apparmor_parser -R "/etc/apparmor.d/$p" 2>/dev/null || true
    fi
done

id freerad >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin freerad

# PostgreSQL 16 with the peer mapping from SPEC section 3
pg_lsclusters -h | grep -q '^16 *main' || pg_createcluster 16 main
pg_ctlcluster 16 main status >/dev/null 2>&1 || pg_ctlcluster 16 main start
PGC=/etc/postgresql/16/main
if ! grep -q 'map=radiusmap' $PGC/pg_hba.conf; then
    { grep -vE '^\s*(#|$)' "$REPO/deploy/postgres/pg_hba.conf.snippet"; cat $PGC/pg_hba.conf; } > /tmp/pg_hba.new
    install -o postgres -g postgres -m 640 /tmp/pg_hba.new $PGC/pg_hba.conf
fi
grep -q '^radiusmap' $PGC/pg_ident.conf || grep -vE '^\s*(#|$)' "$REPO/deploy/postgres/pg_ident.conf.snippet" >> $PGC/pg_ident.conf
pg_ctlcluster 16 main reload
P() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 "$@"; }
P -d postgres < "$REPO/sql/00-roles.sql"
for db in radius radius_apptest; do               # bench / app tests
    P -d postgres -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db OWNER radius_owner"
    for f in "$REPO"/sql/[1-9]0-*.sql; do P -d $db < "$f" >/dev/null; done
done

# bench host names and loopback source addresses
grep -q dc01.example.net /etc/hosts || echo '127.0.0.1 dc01.example.net pki.example.net radius.example.net' >> /etc/hosts
for a in 192.0.2.10 198.51.100.10 203.0.113.201; do ip addr add $a/32 dev lo 2>/dev/null || true; done

# SNMP test agent on 127.0.0.1:161 (app/tests/README_snmpd.txt)
if ! pgrep -x snmpd >/dev/null; then
    D=/var/tmp/snmpd-test; mkdir -p $D/persist
    printf 'rouser radmon authpriv .1\nsysName test-switch-01\nsysDescr Test agent\ncreateUser radmon SHA-256 "AuthPass-Test-1" AES "PrivPass-Test-2"\n' > $D/snmpd.conf
    snmpd -C -c $D/snmpd.conf -p $D/pid --persistentDir=$D/persist -Lf $D/log udp:127.0.0.1:161
fi
echo "sandbox ready (repo $REPO)"
