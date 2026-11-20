#!/bin/bash
# Upgrades keep the live EAP certificate and OCSP settings: install.sh's carry_over_secrets
# merges the live mods-available/eap (tls-config tls-common, its ocsp { }) into the staged
# template. Without it an upgrade that runs the freeradius phase points EAP-TLS at the
# template's certs/site files and the placeholder OCSP responder, and every EAP-TLS login is
# rejected ("Couldn't connect to OCSP responder"). Fixtures only (example values in a
# temporary directory); needs python3, no FreeRADIUS.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL=$ROOT/deploy/install.sh
TEMPLATE=$ROOT/freeradius/mods-available/eap
LDAP_TEMPLATE=$ROOT/freeradius/mods-available/ldap
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# shellcheck source=../../deploy/lib.sh
. "$ROOT/deploy/lib.sh"
eval "$(sed -n '/^carry_over_secrets() {/,/^}/p' "$INSTALL")"
declare -F carry_over_secrets >/dev/null || { echo "carry_over_secrets not found in $INSTALL"; exit 2; }

export RA_RADDB=$W/live
STAGED=$W/staged
S=$STAGED/mods-available/eap
# live_eap SED... : the installed eap = the template with the given edits (the ldap module
# goes along so the LDAP carry-over has its password)
live_eap() {
    rm -rf "$RA_RADDB" "$STAGED"
    mkdir -p "$RA_RADDB/mods-available" "$STAGED/mods-available"
    cp "$TEMPLATE" "$S"
    cp "$LDAP_TEMPLATE" "$STAGED/mods-available/ldap"
    sed -e "s#^\([[:space:]]*password[[:space:]]*=\).*#\1 'Bind-Pass-Example-1'#" "$LDAP_TEMPLATE" \
        > "$RA_RADDB/mods-available/ldap"
    if (($#)); then sed "$@" "$TEMPLATE"; else cat "$TEMPLATE"; fi > "$RA_RADDB/mods-available/eap"
}
merged() { carry_over_secrets "$STAGED" 2>&1; }
# the active lines of tls-config tls-common outside its sub-sections, and of its ocsp { }
tls_top() {
    awk '/^[ \t]*tls-config[ \t]+tls-common[ \t]*\{/ { on = 1; d = 0 }
         on { c = $0; sub(/^[ \t]+/, "", c)
              if (c ~ /^#/) next
              if (c ~ /\{[ \t]*$/) { d++; next }
              if (c ~ /^\}/) { d--; if (d == 0) exit; next }
              if (d == 1) print }' "$S"
}
ocsp() { awk '/^[ \t]*ocsp[ \t]*\{/ { on = 1; next } on && /^[ \t]*\}/ { exit } on && !/^[ \t]*#/' "$S"; }
has() { grep -qE "^[[:space:]]*$1[[:space:]]*=[[:space:]]*$2[[:space:]]*$"; }

SITE=/etc/freeradius/certs/example-site
OCSP=http://ocsp.example.net:8080/ocsp

# 1. live file as shipped: nothing to keep, staged eap unchanged
live_eap
out=$(merged)
if [[ $out != *"EAP"* && $out != *"OCSP"* ]] && cmp -s "$S" "$TEMPLATE"; then
    pass "live eap as shipped: the staged eap is the template"
else fail "unchanged live eap: $out"; diff "$TEMPLATE" "$S" | head; fi

# 2. the incident: site certificate directory and the site's OCSP responder, in a live file
#    from an older release (no EAP-TTLS / PEAP blocks yet)
live_eap -e "s#/etc/freeradius/certs/site/#$SITE/#" \
         -e "s#^\([[:space:]]*url[[:space:]]*=\).*pki.example.net.*#\1 \"$OCSP\"#" \
         -e '/radius-admin: EAP-TTLS with PAP inside/,/^[[:space:]]*}/d'
out=$(merged)
if [[ $out == *"kept the live EAP TLS setting(s) private_key_file, certificate_file, ca_file"* \
      && $out == *"kept the live OCSP setting(s) url"* ]] \
    && tls_top | has private_key_file "$SITE/radius.key" \
    && tls_top | has certificate_file "$SITE/radius.pem" \
    && tls_top | has ca_file "$SITE/ca.pem" \
    && ocsp | has url "\"$OCSP\"" && ocsp | has enable yes && ocsp | has override_cert_url yes \
    && ! grep -Ev '^[[:space:]]*#' "$S" | grep -qE 'certs/site/|pki\.example\.net'; then
    pass "live certificate paths and OCSP responder are kept"
else fail "site paths / OCSP url: $out"; diff "$TEMPLATE" "$S" | head -20; fi
# the rest of the file is the new release's: the TTLS block the live file lacked, TLS minimum
if grep -q 'virtual_server = "radius-admin-inner"' "$S" && tls_top | has tls_min_version '"1.2"' \
    && tls_top | grep -q 'cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384'; then
    pass "new blocks and the shipped TLS minimum and ciphers stay"
else fail "new release content lost"; fi

# 3. OCSP off on this server, a CRL check, a key password and a CA directory
live_eap -e "/^[[:space:]]*ocsp[[:space:]]*{/,/^[[:space:]]*}/ s#^\([[:space:]]*enable[[:space:]]*=\).*#\1 no#" \
         -e 's#^\([[:space:]]*\)\#[[:space:]]*softfail[[:space:]]*=.*#\1softfail = yes#' \
         -e 's#^\([[:space:]]*\)private_key_file[[:space:]]*=.*#&\n\1private_key_password = Key-Pass-Example-1#' \
         -e 's#^\([[:space:]]*\)\#[[:space:]]*check_crl[[:space:]]*=.*#\1check_crl = yes#' \
         -e 's#^\([[:space:]]*\)ca_file[[:space:]]*=.*#\1ca_path = /etc/ssl/example-cas#'
out=$(merged)
if ocsp | has enable no && ocsp | has softfail yes \
    && tls_top | has private_key_password Key-Pass-Example-1 \
    && tls_top | has check_crl yes \
    && tls_top | has ca_path /etc/ssl/example-cas && ! tls_top | grep -qE '^[[:space:]]*ca_file[[:space:]]*=' \
    && [[ $out != *"Key-Pass-Example-1"* ]] \
    && awk '/^[ \t]*cache[ \t]*\{/,/^[ \t]*\}/' "$S" | grep -qE '^[[:space:]]*enable[[:space:]]*=[[:space:]]*no'; then
    pass "OCSP off, softfail, CRL check, key password and CA directory are kept (password not printed)"
else fail "ocsp off / key password / ca_path: $out"; diff "$TEMPLATE" "$S" | head -30; fi

# 4. no ocsp { } at all on this server (FreeRADIUS: no OCSP): the staged block is turned off
live_eap -e '/^[[:space:]]*ocsp[[:space:]]*{/,/^[[:space:]]*}/d'
out=$(merged)
if [[ $out == *"kept the live OCSP setting(s)"* ]] && ! ocsp | grep -qE '^[[:space:]]*enable[[:space:]]*=[[:space:]]*yes' \
    && ! ocsp | grep -qE '^[[:space:]]*url[[:space:]]*='; then
    pass "a live eap without ocsp { } keeps OCSP off"
else fail "no live ocsp block: $out"; ocsp; fi

# 5. a stock FreeRADIUS eap (fresh install, never installed by radius-admin): nothing is taken
#    from it, the template's settings are installed
live_eap -e '/radius-admin/d' -e "s#/etc/freeradius/certs/site/radius.pem#\${certdir}/server.pem#" \
         -e "/^[[:space:]]*ocsp[[:space:]]*{/,/^[[:space:]]*}/ s#^\([[:space:]]*enable[[:space:]]*=\).*#\1 no#"
out=$(merged)
if [[ $out != *"EAP"* && $out != *"OCSP"* ]] && cmp -s "$S" "$TEMPLATE"; then
    pass "a stock (non radius-admin) eap is not merged"
else fail "stock eap merged: $out"; diff "$TEMPLATE" "$S" | head; fi

echo
if (( fails )); then echo "$fails FAILED"; exit 1; fi
echo "ALL EAP CARRY-OVER TESTS PASSED"
