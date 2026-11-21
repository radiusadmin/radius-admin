#!/bin/bash
# The freeradius phase on a new (blank) server: FreeRADIUS never configured by radius-admin and
# nothing to migrate. It must install a working, default-deny configuration without the site
# settings an existing server carries over (directory, EAP certificates, localhost secret, OCSP),
# and later updates must keep that state. Sandbox only, as root (needs the freerad group).
#
#   tests/installer/test_blank_server.sh [FR_PREFIX]
#
# With a FreeRADIUS build (FR_PREFIX, else $RADIUS_ADMIN_TEST_FR_PREFIX) the staged files are
# installed into a copy of its stock raddb with install.sh's own functions, checked with
# radiusd -XC and started for real; that part needs PostgreSQL with the bench database
# "radius" (SPEC section 3) and free UDP ports 1812/1813.
set -uo pipefail
umask 022
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL=$ROOT/deploy/install.sh
FR_PREFIX=${1:-${RADIUS_ADMIN_TEST_FR_PREFIX:-}}
[[ $EUID -eq 0 ]] || { echo "run as root (sandbox)"; exit 2; }
getent group freerad >/dev/null || { echo "no freerad group (sandbox prerequisites: tests/freeradius/README.md)"; exit 2; }
W=$(mktemp -d)
chmod 0711 "$W"   # radiusd reads the raddb copy below as freerad
RPID=""
trap '[[ -n $RPID ]] && kill "$RPID" 2>/dev/null; rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# shellcheck source=../../deploy/lib.sh
. "$ROOT/deploy/lib.sh"
# the functions under test, as install.sh defines them (install.sh itself runs its phases)
for f in carry_over_secrets fr_blank access_rules_check ldap_is_off ldap_directory_off \
         fr_localhost_secret fr_eap_ocsp eap_certs fr_install_staged; do
    eval "$(sed -n "/^$f() {/,/^}/p" "$INSTALL")"
    declare -F "$f" >/dev/null || { echo "$f not found in $INSTALL"; exit 2; }
done
eval "$(grep '^RA_LDAP_OFF_MARK=' "$INSTALL")"
# SRC is read by fr_install_staged (modules-to-disable.txt)
# shellcheck disable=SC2034
SRC=$ROOT
TPL=$ROOT/freeradius
export RA_RADDB=$W/live RA_SQLITE_DB=$W/freeradius.db
mkdir -p "$RA_RADDB/mods-available"
in_pool() { # in_pool FILE N : the Nth pool { } of FILE
    awk -v n="$2" '/^[ \t]*pool[ \t]*\{/ { c++ } c == n { print } c == n && /^[ \t]*\}/ { exit }' "$1"
}
stage() { # stage : a fresh staged copy of freeradius/ (as the freeradius phase builds it)
    rm -rf "$W/work"
    (cd "$TPL" && find . -type f ! -path './diffs/*' ! -name 'modules-to-disable.txt' -print0 \
        | xargs -0 -I{} install -D -m 0600 {} "$W/work/{}")
}

# ------------------------------------------------------------------ which server is new
fr_blank && pass "no radius-admin policy and no SQLite database: a new server" || fail "empty raddb not new"
mkdir -p "$RA_RADDB/policy.d"; : > "$RA_RADDB/policy.d/radius-admin"
fr_blank && fail "installed server taken for a new one" || pass "a server radius-admin configured is not new"
rm -f "$RA_RADDB/policy.d/radius-admin"; : > "$RA_SQLITE_DB"
fr_blank && fail "server with a SQLite database to migrate taken for a new one" || pass "a server with a SQLite database to migrate is not new"
out=$( (access_rules_check 0) 2>&1) && fail "empty rules accepted while a migration is pending" \
    || { [[ $out == *"migrate phase first"* ]] && pass "empty rules refused while a SQLite database waits for migration" \
         || fail "empty rules message: $out"; }
rm -f "$RA_SQLITE_DB"
out=$( (access_rules_check 0) 2>&1) && [[ $out == *"no access rules yet"* ]] \
    && pass "empty rules on a new server: warning, not refused" || fail "empty rules on a new server: $out"
(access_rules_check 3) >/dev/null 2>&1 && pass "rules present: accepted" || fail "rules present refused"

# ------------------------------------------------------------------ LDAP without a directory
# a stock FreeRADIUS ldap module (no bind password): what a new server has
sed -e "s#^\([[:space:]]*\)password[[:space:]]*=.*#\1\#password = mypass#" -e "s#^\([[:space:]]*\)identity[[:space:]]*=.*#\1\#identity = 'cn=admin,dc=example,dc=org'#" \
    -e "s#^\([[:space:]]*server[[:space:]]*=[[:space:]]*\)'ldaps://dc01.example.net'#\1'localhost'#" \
    "$TPL/mods-available/ldap" > "$RA_RADDB/mods-available/ldap"
printf 'client localhost {\n\tipaddr = 127.0.0.1\n\tsecret = testing123\n}\n' > "$RA_RADDB/clients.conf"
stage
out=$(carry_over_secrets "$W/work" 2>&1) && fail "stock ldap module carried over without a password" \
    || pass "without the new-server handling the stock ldap module stops the phase ($(tail -1 <<<"$out" | cut -c1-60))"
stage
ldap_directory_off "$W/work/mods-available/ldap" && fr_localhost_secret "$W/work" >/dev/null
S=$W/work/mods-available/ldap
if out=$(carry_over_secrets "$W/work" 2>&1); then pass "new server: the staged files need nothing from the stock ones"
else fail "carry over on a new server: $out"; fi
if ldap_is_off "$S" && grep -qE "^[[:space:]]*password = ''$" "$S" \
    && grep -qE "^[[:space:]]*server = 'ldaps://directory.invalid'$" "$S" \
    && in_pool "$S" 1 | grep -qE '^[[:space:]]*start = 0$' && in_pool "$S" 1 | grep -qE '^[[:space:]]*min = 0$' \
    && grep -qE "^[[:space:]]*identity = 'CN=RADIUS LDAP Bind" "$S" \
    && diff <(in_pool "$S" 2) <(in_pool "$TPL/mods-available/ldap" 2) >/dev/null; then
    pass "no directory: marker, empty password, unresolvable server, no connections at start, nothing taken from the stock file"
else fail "ldap module without a directory: $(grep -nE "radius-admin:|password =|server =|start =|identity =" "$S" | head -8 | tr '\n' ' ')"; fi
sec=$(sed -n 's/^[[:space:]]*secret[[:space:]]*=[[:space:]]*\([0-9a-f]\{48\}\)$/\1/p' "$W/work/clients.conf")
[[ -n $sec ]] && pass "new server: a random localhost secret instead of the stock testing123" \
    || fail "localhost secret: $(grep secret "$W/work/clients.conf")"

# an update while the live module is still without a directory keeps it that way
cp "$S" "$W/off.ldap"; cp "$S" "$RA_RADDB/mods-available/ldap"
printf 'client localhost {\n\tsecret = %s\n}\n' "$sec" > "$RA_RADDB/clients.conf"
stage
ldap_is_off "$RA_RADDB/mods-available/ldap" && ldap_directory_off "$W/work/mods-available/ldap"
if carry_over_secrets "$W/work" >/dev/null 2>&1 && cmp -s "$S" "$W/off.ldap" \
    && grep -qx "    secret = $sec" "$W/work/clients.conf"; then
    pass "update without a directory: module stays without one, localhost secret kept"
else fail "update without a directory: $(diff "$S" "$W/off.ldap" | head -5)"; fi
# the admin set up the directory and deleted the marker: an ordinary carry-over from then on
sed -e "/$RA_LDAP_OFF_MARK/d" -e "s#^\([[:space:]]*password[[:space:]]*=\).*#\1 'Bind-Pass-Example-1'#" \
    -e "s#^\([[:space:]]*server[[:space:]]*=[[:space:]]*\)'ldaps://directory.invalid'#\1'ldaps://dc02.example.net'#" \
    "$W/off.ldap" > "$RA_RADDB/mods-available/ldap"
stage
if ! ldap_is_off "$RA_RADDB/mods-available/ldap" && carry_over_secrets "$W/work" >/dev/null 2>&1 \
    && grep -q "password = 'Bind-Pass-Example-1'" "$S" && grep -q "'ldaps://dc02.example.net'" "$S" \
    && ! ldap_is_off "$S" && in_pool "$S" 1 | grep -q 'start = ${thread\[pool\].start_servers}'; then
    pass "directory configured by hand: its settings are carried over and the pool starts as shipped"
else fail "configured directory not carried over: $(grep -nE 'password =|server =|start =' "$S" | head -4 | tr '\n' ' ')"; fi
printf 'client localhost {\n\tsecret = Site-Localhost-Secret-1\n}\n' > "$RA_RADDB/clients.conf"
stage
fr_localhost_secret "$W/work" >/dev/null
grep -q 'secret = REDACTED' "$W/work/clients.conf" && pass "a live localhost secret other than the stock one is left to the carry-over" \
    || fail "own localhost secret replaced"

# ------------------------------------------------------------------ OCSP of a new server
ocsp_block() { awk '/^[ \t]*ocsp[ \t]*\{/ { o = 1 } o { print } o && /^[ \t]*\}/ { exit }' "$1"; }
stage
E=$W/work/mods-available/eap
fr_eap_ocsp "$E" ""
ocsp_block "$E" | grep -qE '^[[:space:]]*enable = no$' && ! ocsp_block "$E" | grep -qE '^[[:space:]]*enable = yes' \
    && pass "no responder: EAP OCSP off" || fail "EAP OCSP not off: $(ocsp_block "$E" | grep -E 'enable|url =')"
stage
fr_eap_ocsp "$E" "http://ocsp.example.net/ocsp"
ocsp_block "$E" | grep -qE '^[[:space:]]*enable = yes$' && ocsp_block "$E" | grep -qx '[[:space:]]*url = "http://ocsp.example.net/ocsp"' \
    && pass "responder given: EAP OCSP on with that URL" || fail "EAP OCSP with URL: $(ocsp_block "$E" | grep -E 'enable|url =')"

# ------------------------------------------------------------------ EAP certificates
D=$RA_RADDB/certs/site
eap_certs self-signed "" "" "" radius.example.net >"$W/certs.out" 2>&1
if [[ $(stat -c '%U:%G %a' "$D/radius.key" "$D/radius.pem" "$D/ca.pem" 2>/dev/null | sort -u) == "root:freerad 640" ]] \
    && openssl x509 -in "$D/radius.pem" -noout -text | grep -q 'NIST CURVE: P-384' \
    && openssl x509 -in "$D/radius.pem" -noout -ext subjectAltName | grep -q 'DNS:radius.example.net' \
    && openssl x509 -in "$D/radius.pem" -noout -ext extendedKeyUsage | grep -q 'TLS Web Server Authentication' \
    && openssl verify -purpose sslserver -CAfile "$D/ca.pem" "$D/radius.pem" >/dev/null 2>&1 \
    && [[ -z $(find "$RA_RADDB" "$W" -name 'ca.key') ]] && grep -q "replace them" "$W/certs.out"; then
    pass "self-signed: ECDSA P-384 server certificate from a throwaway CA whose key is gone, root:freerad 0640, warning"
else fail "self-signed EAP certificates: $(cat "$W/certs.out")"; fi
before=$(sha256sum "$D/radius.pem")
eap_certs self-signed "" "" "" radius.example.net >/dev/null 2>&1
[[ $(sha256sum "$D/radius.pem") == "$before" ]] && pass "certificates already there are kept" || fail "certificates replaced"
rm -f "$D/radius.key"
eap_certs self-signed "" "" "" radius.example.net >/dev/null 2>&1 && fail "incomplete certs/site accepted" \
    || pass "an incomplete certs/site is refused"
rm -rf "$D"
# the site's own files (eap_tls: existing)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -days 30 -subj "/CN=Example Test CA" \
    -keyout "$W/own-ca.key" -out "$W/own-ca.pem" >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -days 30 -subj "/CN=radius.example.net" \
    -keyout "$W/own.key" -out "$W/own.pem" >/dev/null 2>&1
eap_certs existing "$W/own.pem" "$W/own-ca.key" "$W/own-ca.pem" radius.example.net >/dev/null 2>&1 \
    && fail "certificate with a key that does not match accepted" || pass "a key that does not match the certificate is refused"
[[ ! -e $D/radius.pem ]] && pass "nothing installed after a refusal" || fail "files left after a refusal"
if eap_certs existing "$W/own.pem" "$W/own.key" "$W/own-ca.pem" radius.example.net >/dev/null 2>&1 \
    && cmp -s "$W/own.pem" "$D/radius.pem" && cmp -s "$W/own.key" "$D/radius.key" && cmp -s "$W/own-ca.pem" "$D/ca.pem"; then
    pass "existing: the site's certificate, key and client CA are installed"
else fail "existing EAP certificates not installed"; fi

# ------------------------------------------------------------------ portal without OCSP
render_nginx_site "$ROOT/deploy/nginx/radius-admin.conf" "$W/site" 192.0.2.10 radius.example.net 192.0.2.0/24 192.0.2.53 ""
if ! grep -v '^[[:space:]]*#' "$W/site" | grep -qE 'ssl_ocsp|@[A-Z_]+@' && grep -q 'ssl_verify_client optional' "$W/site"; then
    pass "portal site without a responder: no OCSP directives, client certificates still optional"
else fail "nginx site without OCSP: $(grep -nE 'ssl_ocsp|@[A-Z_]+@' "$W/site")"; fi
render_nginx_site "$ROOT/deploy/nginx/radius-admin.conf" "$W/site" 192.0.2.10 radius.example.net 192.0.2.0/24 192.0.2.53 http://ocsp.example.net/ocsp
grep -qE '^[[:space:]]*ssl_ocsp_responder http://ocsp.example.net/ocsp;' "$W/site" && grep -qE '^[[:space:]]*ssl_ocsp leaf;' "$W/site" \
    && pass "portal site with a responder: OCSP for client certificates" || fail "nginx site with OCSP"

# ------------------------------------------------------------------ the real thing
if [[ -z $FR_PREFIX || ! -x $FR_PREFIX/sbin/radiusd ]]; then
    echo "SKIP: no FreeRADIUS build (pass FR_PREFIX or set RADIUS_ADMIN_TEST_FR_PREFIX): radiusd checks not run"
else
    R=$W/raddb
    cp -dR --preserve=mode,timestamps "$FR_PREFIX/etc/raddb" "$R"
    sed -i 's/^#\tuser = radius$/\tuser = freerad/; s/^#\tgroup = radius$/\tgroup = freerad/' "$R/radiusd.conf"
    export RA_RADDB=$R
    fr_blank && pass "stock raddb of the build: a new server" || fail "stock raddb not taken for a new server"
    stage
    ldap_directory_off "$W/work/mods-available/ldap" && fr_localhost_secret "$W/work" >/dev/null \
        && fr_eap_ocsp "$W/work/mods-available/eap" "" && carry_over_secrets "$W/work" >/dev/null \
        && pass "staged files prepared for the stock raddb" || fail "staging for the stock raddb"
    mkdir -p "$W/work/policy.d"
    PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tests/freeradius/render.py" "$W/work/policy.d/radius-admin" "$W/work/radius-admin-clients.conf" >/dev/null
    eap_certs self-signed "" "" "" radius.example.net >/dev/null 2>&1
    fr_install_staged "$W/work" >/dev/null
    # production absolute paths -> this copy (test-only substitution, as the bench does)
    sed -i "s|/etc/freeradius/certs/site/|$R/certs/site/|g" "$R/mods-available/eap" "$R/radius-admin-clients.conf"
    if [[ ! -e /proc/net/if_inet6 ]]; then   # sandbox without IPv6: drop the "ipv6addr = ::" listeners
        python3 - "$R/sites-available/default" <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().split("\n"); out = []; i = 0
while i < len(L):
    if L[i] == "listen {":
        j = i
        while L[j] != "}":
            j += 1
        if any(x.strip().startswith("ipv6addr = ::") for x in L[i:j + 1]):
            out += ["#" + x for x in L[i:j + 1]]; i = j + 1; continue
    out.append(L[i]); i += 1
open(p, "w").write("\n".join(out))
PY
    fi
    chown -R root:freerad "$R"; chmod -R g+rX,o-rwx "$R"
    mkdir -p "$FR_PREFIX/var/log/radius" "$FR_PREFIX/var/run/radiusd"
    chown -R freerad:freerad "$FR_PREFIX/var/log/radius" "$FR_PREFIX/var/run/radiusd"
    if out=$(timeout 90 "$FR_PREFIX/sbin/radiusd" -XC -d "$R" 2>&1) && grep -q 'Configuration appears to be OK' <<<"$out"; then
        pass "radiusd -XC: the new-server configuration is valid"
    else fail "radiusd -XC: $(tail -n 15 <<<"$out")"; fi
    "$FR_PREFIX/sbin/radiusd" -fxx -l stdout -d "$R" > "$W/radiusd.log" 2>&1 &
    RPID=$!
    for _ in $(seq 1 30); do grep -q 'Ready to process requests' "$W/radiusd.log" && break; sleep 1; done
    if grep -q 'Ready to process requests' "$W/radiusd.log"; then
        pass "radiusd starts without a directory"
        sec=$(sed -n 's/^[[:space:]]*secret[[:space:]]*=[[:space:]]*\([0-9a-f]\{48\}\)$/\1/p' "$R/clients.conf")
        out=$(printf 'User-Name = "nobody"\nUser-Password = "Not-A-Password-1"\nMessage-Authenticator = 0x00\n' \
              | timeout 20 "$FR_PREFIX/bin/radclient" -r 1 -t 10 -x 127.0.0.1:1812 auth "$sec" 2>&1)
        [[ $out == *"Access-Reject"* ]] && pass "answers on the new localhost secret (unknown user rejected)" \
            || fail "radclient: $(tail -n 5 <<<"$out")"
    else
        fail "radiusd did not start: $(grep -iE 'error|fail' "$W/radiusd.log" | tail -n 8)"
    fi
    kill "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null; RPID=""
fi

echo
if (( fails )); then echo "$fails FAILED"; exit 1; fi
echo "ALL NEW-SERVER TESTS PASSED"
