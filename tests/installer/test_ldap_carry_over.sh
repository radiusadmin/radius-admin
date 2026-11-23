#!/bin/bash
# Upgrades keep the live LDAP connection settings: install.sh's
# carry_over_secrets merges the live mods-available/ldap into the staged template, and
# ldap_bind_check tests the bind with the CA file FreeRADIUS will use. fr_package_ldap_check
# tests the directory login with a new radius-admin-freeradius package's ra-ldapwhoami before
# the package is installed. Fixtures only (example values in a temporary directory, fake
# ldapwhoami scripts); needs python3 and dpkg-deb, no FreeRADIUS and no directory server.
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
for fn in ldap_bind_check ldap_bind_try ldap_bind_tool ldap_is_off fr_package_ldap_check; do
    eval "$(sed -n "/^$fn() {/,/^}/p" "$INSTALL")"
done
eval "$(grep '^RA_LDAP_OFF_MARK=' "$INSTALL")"
# install.sh's defaults for what the functions read (no bundled package here, check on)
export RA_BUNDLED_LDAPWHOAMI=$W/no-bundled-package SKIP_LDAP_CHECK=0
declare -F carry_over_secrets ldap_bind_check ldap_bind_try ldap_bind_tool ldap_is_off fr_package_ldap_check >/dev/null \
    || { echo "functions not found in $INSTALL"; exit 2; }

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

# 5. ldap_bind_check prefers the bundled package's ra-ldapwhoami (the library rlm_ldap uses)
# fake tools: FAKE_NEW / FAKE_REF = ok | tls | badcred
fake() { # fake FILE VAR
    mkdir -p "$(dirname "$1")"
    cat > "$1" <<EOF
#!/bin/sh
case "\$$2" in
    ok) echo "dn:CN=RADIUS LDAP Bind,OU=Service Accounts,DC=example,DC=net ($2)"; exit 0 ;;
    badcred) echo "ldap_bind: Invalid credentials (49)"; exit 49 ;;
    *) echo "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1) additional info: error:0A000086:SSL routines::certificate verify failed"; exit 255 ;;
esac
EOF
    chmod 0755 "$1"
}
fake "$W/bin/ldapwhoami" FAKE_REF
fake "$W/bundled/ra-ldapwhoami" FAKE_NEW
out=$(FAKE_NEW=ok FAKE_REF=tls RA_BUNDLED_LDAPWHOAMI=$W/bundled/ra-ldapwhoami PATH=$W/bin:$PATH \
      ldap_bind_check "$RA_RADDB/mods-available/ldap" 2>&1)
[[ $out == *"AD bind with the LDAP service account works"* ]] \
    && pass "bind test uses the bundled ra-ldapwhoami when it is installed" || fail "bundled tool not used: $out"
out=$(FAKE_REF=ok RA_BUNDLED_LDAPWHOAMI=$W/none PATH=$W/bin:$PATH ldap_bind_check "$RA_RADDB/mods-available/ldap" 2>&1)
[[ $out == *"AD bind with the LDAP service account works"* ]] \
    && pass "without the bundled package the system ldapwhoami is used" || fail "system tool: $out"

# 6. fr_package_ldap_check: the new package's ra-ldapwhoami, extracted from the .deb
mkpkg() { # mkpkg NAME [with-tool]
    local d=$W/pkg-$1
    rm -rf "$d"; mkdir -p "$d/DEBIAN"
    printf 'Package: radius-admin-freeradius\nVersion: 3.2.10-2~test\nArchitecture: all\nMaintainer: test <test@example.net>\nDescription: test\n' \
        > "$d/DEBIAN/control"
    [[ ${2:-} == with-tool ]] && fake "$d/opt/radius-admin-freeradius/libexec/ra-ldapwhoami" FAKE_NEW
    dpkg-deb --root-owner-group --build "$d" "$W/$1.deb" >/dev/null
}
mkpkg new with-tool
mkpkg old
check() { (RA_BUNDLED_LDAPWHOAMI=$W/none PATH=$W/bin:$PATH fr_package_ldap_check "$@") 2>&1; }
out=$(FAKE_NEW=ok FAKE_REF=ok check "$W/new.deb"); rc=$?
[[ $rc == 0 && $out == *"logs in to the directory"* ]] \
    && pass "upgrade check: the new package logs in, install goes ahead" || fail "new ok: rc $rc $out"
out=$(FAKE_NEW=tls FAKE_REF=ok check "$W/new.deb"); rc=$?
[[ $rc != 0 && $out == *"works with the FreeRADIUS installed now but not with the new package"* && $out == *"certificate verify failed"* && $out == *"Nothing was changed"* ]] \
    && pass "upgrade check: refused when only the new package's OpenSSL cannot log in" || fail "new tls, ref ok: rc $rc $out"
out=$(FAKE_NEW=tls FAKE_REF=tls check "$W/new.deb"); rc=$?
[[ $rc == 0 && $out == *"inconclusive"* ]] \
    && pass "upgrade check: directory unreachable for both is a warning, not a stop" || fail "both fail: rc $rc $out"
out=$(FAKE_NEW=badcred FAKE_REF=ok check "$W/new.deb"); rc=$?
[[ $rc != 0 && $out == *"rejects the LDAP bind account"* ]] \
    && pass "upgrade check: a rejected bind account stops the install" || fail "badcred: rc $rc $out"
out=$(FAKE_NEW=tls FAKE_REF=ok SKIP_LDAP_CHECK=1 check "$W/new.deb"); rc=$?
[[ $rc == 0 && $out == *"--skip-ldap-check"* ]] \
    && pass "upgrade check: --skip-ldap-check skips it with a warning" || fail "skip: rc $rc $out"
out=$(FAKE_NEW=tls FAKE_REF=ok check "$W/old.deb"); rc=$?
[[ $rc == 0 && $out != *"FAIL"* ]] \
    && pass "upgrade check: a package without ra-ldapwhoami is not tested" || fail "old package: rc $rc $out"
cp "$TEMPLATE" "$RA_RADDB/mods-available/ldap"
printf '\n# %s\n' "$RA_LDAP_OFF_MARK" >> "$RA_RADDB/mods-available/ldap"
out=$(FAKE_NEW=tls FAKE_REF=ok check "$W/new.deb"); rc=$?
[[ $rc == 0 ]] && pass "upgrade check: no directory configured, nothing to test" || fail "directory off: rc $rc $out"
rm -f "$RA_RADDB/mods-available/ldap"
out=$(FAKE_NEW=tls FAKE_REF=ok check "$W/new.deb"); rc=$?
[[ $rc == 0 ]] && pass "upgrade check: a new server without mods-available/ldap is not tested" || fail "no ldap file: rc $rc $out"

echo
if (( fails )); then echo "$fails FAILED"; exit 1; fi
echo "ALL LDAP CARRY-OVER TESTS PASSED"
