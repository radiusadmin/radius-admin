#!/bin/bash
# Build a test raddb mirroring the production layout from:
#   - the stock 3.2.10 raddb installed with the test build (<prefix>/etc/raddb)
#   - the radius-admin deliverables in freeradius/
#   - a generated policy.d/radius-admin + radius-admin-clients.conf (unlang.py)
#   - the throwaway test PKI
# Usage: build-raddb.sh <prefix> <benchdir> <ldap-bind-password>
set -euo pipefail
PREFIX=${1:?prefix}; B=${2:?benchdir}; PW=${3:?bindpw}
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
FR=$ROOT/freeradius
R=$B/raddb
rm -rf "$R"; cp -a "$PREFIX/etc/raddb" "$R"
# --- deliverables
cp "$FR/mods-available/sql"  "$R/mods-available/sql"
cp "$FR/mods-available/eap"  "$R/mods-available/eap"
cp "$FR/mods-available/ldap" "$R/mods-available/ldap"
cp "$FR/mods-config/sql/main/postgresql/queries.conf" "$R/mods-config/sql/main/postgresql/queries.conf"
cp "$FR/sites-available/default" "$R/sites-available/default"
cp "$FR/clients.conf" "$R/clients.conf"
cp "$FR/mods-config/files/authorize" "$R/mods-config/files/authorize"
# --- enabled modules = production list minus modules-to-disable.txt
PROD="always attr_filter chap date detail detail.log digest dpsk dynamic_clients eap echo exec expiration expr files ldap linelog logintime mschap ntlm_auth pap passwd preprocess proxy_rate_limit radutmp realm replicate sql sradutmp totp unix unpack utf8"
rm -f "$R"/mods-enabled/*
for m in $PROD; do
  grep -qx "$m" <(grep -v '^#' "$FR/modules-to-disable.txt") && continue
  ln -s "../mods-available/$m" "$R/mods-enabled/$m"
done
rm -f "$R"/sites-enabled/*
ln -s ../sites-available/default "$R/sites-enabled/default"   # inner-tunnel removed
# --- production absolute paths -> bench paths (test-only substitution)
sed -i "s|/etc/freeradius/certs/site/|$R/certs/site/|g" "$R/mods-available/eap"
sed -i "s|^\tpassword = 'REDACTED'|\tpassword = '$PW'|" "$R/mods-available/ldap"
grep -q "password = '$PW'" "$R/mods-available/ldap"
# OpenLDAP has no LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941): a search using it
# returns nothing. The test slapd emulates it with slapo-nestgroup on a plain member= filter.
sed -i 's|membership_filter = "(member:1.2.840.113556.1.4.1941:=%{control:Ldap-UserDn})"|membership_filter = "(member=%{control:Ldap-UserDn})"|' "$R/mods-available/ldap"
grep -q 'membership_filter = "(member=%{control:Ldap-UserDn})"' "$R/mods-available/ldap"
# --- sandbox without IPv6: drop the two "ipv6addr = ::" listeners (bench copy only)
if [ ! -e /proc/net/if_inet6 ]; then
  python3 - "$R/sites-available/default" <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().split("\n"); out = []; i = 0
while i < len(L):
    if L[i] == "listen {":
        j = i
        while L[j] != "}":
            j += 1
        blk = L[i:j + 1]
        if any(x.strip().startswith("ipv6addr = ::") for x in blk):
            out += ["#" + x for x in blk]; i = j + 1; continue
    out.append(L[i]); i += 1
open(p, "w").write("\n".join(out))
PY
fi
# --- certs (production layout certs/site/)
mkdir -p "$R/certs/site"
cp "$B/pki/ca.pem" "$R/certs/site/ca.pem"
cat "$B/pki/server.pem" "$B/pki/issuing.pem" > "$R/certs/site/radius.pem"
cp "$B/pki/server.key" "$R/certs/site/radius.key"
# --- generated files (as the helper would install them)
python3 "$HERE/render.py" "$R/policy.d/radius-admin" "$R/radius-admin-clients.conf"
sed -i "s|/etc/freeradius/certs/site/|$R/certs/site/|g" "$R/radius-admin-clients.conf"   # RadSec listener
# --- run as the unprivileged test user mapped to radius_fr
sed -i 's/^#\tuser = radius$/\tuser = freerad/; s/^#\tgroup = radius$/\tgroup = freerad/' "$R/radiusd.conf"
grep -q '^	user = freerad' "$R/radiusd.conf"
mkdir -p "$PREFIX/var/log/radius" "$PREFIX/var/run/radiusd"
chown -R freerad:freerad "$PREFIX/var/log/radius" "$PREFIX/var/run/radiusd"
chown -R root:freerad "$R"; chmod -R g+rX,o-rwx "$R"
echo "raddb ready: $R"
