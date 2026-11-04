#!/bin/bash
# Upgrades keep the live LDAP connection settings (CLAUDE.md rule 10): install.sh's
# carry_over_secrets merges the live mods-available/ldap into the staged template, and
# ldap_bind_check tests the bind with the CA file FreeRADIUS will use. Fixtures only (example
# values in a temporary directory); needs python3, no FreeRADIUS and no directory server.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL=$ROOT/deploy/install.sh
TEMPLATE=$ROOT/freeradius/mods-available/ldap
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# shellcheck source=../../deploy/lib.sh
. "$ROOT/deploy/lib.sh"
# the two functions under test, as install.sh defines them (install.sh itself runs its phases)
eval "$(sed -n '/^carry_over_secrets() {/,/^}/p' "$INSTALL")"
eval "$(sed -n '/^ldap_bind_check() {/,/^}/p' "$INSTALL")"
declare -F carry_over_secrets ldap_bind_check >/dev/null || { echo "functions not found in $INSTALL"; exit 2; }

export RA_RADDB=$W/live
STAGED=$W/staged
# live_ldap SED... : the installed file = the template with a password and the given edits
live_ldap() {
    rm -rf "$RA_RADDB" "$STAGED"
    mkdir -p "$RA_RADDB/mods-available" "$STAGED/mods-available"
    cp "$TEMPLATE" "$STAGED/mods-available/ldap"
    sed -e "s#^\([[:space:]]*password[[:space:]]*=\).*#\1 'Bind-Pass-Example-1'#" "$@" "$TEMPLATE" \
        > "$RA_RADDB/mods-available/ldap"
}
merged() { carry_over_secrets "$STAGED" 2>&1; }
S=$STAGED/mods-available/ldap
# the first tls { } (the ldap module) and the one that references it (ldap_user)
tls_main() { awk '/^[ \t]*tls[ \t]*\{/ { n++ } n == 1 { print } n == 1 && /^[ \t]*\}/ { exit }' "$S"; }
tls_user() { awk '/^[ \t]*tls[ \t]*\{/ { n++ } n == 2 { print } n == 2 && /^[ \t]*\}/ { exit }' "$S"; }
active() { grep -Ev '^[[:space:]]*#' | grep -E "^[[:space:]]*$1[[:space:]]*="; }

# 1. same as the package: only the password is carried over, nothing else touched
live_ldap
out=$(merged)
if [[ $out == *"kept existing secret"* && $out != *"TLS"* ]] \
    && diff <(grep -v '^[[:space:]]*password' "$S") <(grep -v '^[[:space:]]*password' "$TEMPLATE") >/dev/null; then
    pass "live file as shipped: only the password is carried over"
else fail "unchanged live file: $out"; fi

# 2. the directory CA is elsewhere on this server (the 0.2.0 upgrade failure)
live_ldap -e "s#^\([[:space:]]*ca_file[[:space:]]*=\).*site/ca.pem#\1 /etc/ssl/certs/example-directory-ca.pem#"
out=$(merged)
if [[ $out == *"kept the live LDAP TLS setting(s) ca_file"* ]] \
    && tls_main | active ca_file | grep -q '/etc/ssl/certs/example-directory-ca.pem' \
    && ! grep -q 'site/ca.pem' <(grep -Ev '^[[:space:]]*#' "$S") \
    && tls_user | active ca_file | grep -qF '${modules.ldap.tls.ca_file}'; then
    pass "a live ca_file path is kept; ldap_user still follows it"
else fail "live ca_file: $out"; tls_main; fi

# 3. CA directory instead of a file, STARTTLS on port 389, another require_cert
live_ldap -e 's#^\([[:space:]]*\)ca_file\([[:space:]]*=\).*site/ca.pem#\1ca_path\2 /etc/ssl/certs#' \
          -e 's#^\([[:space:]]*port[[:space:]]*=\)[[:space:]]*636#\1 389#' \
          -e 's#^\([[:space:]]*require_cert[[:space:]]*=\).*demand.*#\1 '"'"'allow'"'"'\n\t\tstart_tls = yes#'
out=$(merged)
if [[ $out == *"kept the live port"* ]] && active port <"$S" | head -1 | grep -q 389 \
    && tls_main | active ca_path | grep -q '/etc/ssl/certs' \
    && ! tls_main | active ca_file >/dev/null \
    && tls_main | active start_tls | grep -q yes \
    && tls_main | active require_cert | grep -q allow \
    && ! tls_user | active ca_file >/dev/null \
    && tls_user | active ca_path | grep -qF '${modules.ldap.tls.ca_path}' \
    && tls_main | active tls_min_version | grep -q '1.2'; then
    pass "ca_path, STARTTLS, port and require_cert are kept; ldap_user follows; TLS minimum stays"
else fail "ca_path/start_tls/port: $out"; tls_main; tls_user; fi

# 4. the bind test names a CA file that does not exist instead of "Can't contact LDAP server"
mkdir -p "$W/bin"
printf '#!/bin/sh\necho "dn:CN=RADIUS LDAP Bind CA=$LDAPTLS_CACERT"\n' > "$W/bin/ldapwhoami"
chmod 0755 "$W/bin/ldapwhoami"
live_ldap
out=$(PATH=$W/bin:$PATH ldap_bind_check "$RA_RADDB/mods-available/ldap" 2>&1)
[[ $out == *"ca_file $RA_RADDB/certs/site/ca.pem does not exist"* ]] \
    && pass "bind test reports a missing CA file by name" || fail "bind test, missing CA: $out"
mkdir -p "$RA_RADDB/certs/site" && : > "$RA_RADDB/certs/site/ca.pem"
out=$(PATH=$W/bin:$PATH ldap_bind_check "$RA_RADDB/mods-available/ldap" 2>&1)
[[ $out == *"AD bind with the LDAP service account works"* ]] \
    && pass "bind test uses the CA file when it exists" || fail "bind test, CA present: $out"

echo
if (( fails )); then echo "$fails FAILED"; exit 1; fi
echo "ALL LDAP CARRY-OVER TESTS PASSED"
