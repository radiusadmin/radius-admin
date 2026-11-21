#!/bin/bash
# Installer answers (deploy/answers.sh + install.sh --answers/--interactive/--print-answers)
# and the "site" phase. Sandbox only, as root: writes /etc/radius-admin and refuses to run
# when that directory already exists (never on an installed server).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL=$ROOT/deploy/install.sh
ETC=/etc/radius-admin
[[ $EUID -eq 0 ]] || { echo "run as root (sandbox)"; exit 2; }
[[ -e $ETC ]] && { echo "$ETC exists: refusing (sandbox only)"; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W" "$ETC"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
LOCAL_IP=$(ip -o -4 addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}')
LOCAL_IP=${LOCAL_IP:-127.0.0.1}
# no installed monitor unit to take switch networks from (tests below point it at a file)
export RA_SNMP_UNIT=$W/no-such-unit
# crypto mode: a host whose kernel is not in FIPS mode, and no installed radius-admin.conf
echo 0 > "$W/fips_enabled"
export RA_FIPS_ENABLED_FILE=$W/fips_enabled RA_APP_CONF=$W/no-such-radius-admin.conf

good() {
    cat > "$W/a.yaml" <<EOF
# site answers
server_name: radius.example.net
admin_net: 192.0.2.0/24
listen_ip: 192.0.2.10
resolver: "192.0.2.53 192.0.2.54"
tls: self-signed
admin_username: netadmin
EOF
}

good
out=$("$INSTALL" --answers "$W/a.yaml" --print-answers 2>&1)
if [[ $? -eq 0 ]] && grep -qx 'server_name: radius.example.net' <<<"$out" \
    && grep -qx 'resolver: "192.0.2.53 192.0.2.54"' <<<"$out" && grep -qx 'admin_username: netadmin' <<<"$out"; then
    pass "valid answers file is accepted and printed back"
else fail "valid answers file: $out"; fi
"$INSTALL" --answers <(grep -v '^#' <<<"$out") --print-answers >/dev/null 2>&1 \
    && pass "printed answers are themselves a valid answers file" || fail "printed answers do not round-trip"

bad() { # bad DESCRIPTION SED-EXPRESSION|APPEND-LINE
    good
    if [[ $2 == s/* ]]; then sed -i "$2" "$W/a.yaml"; else echo "$2" >> "$W/a.yaml"; fi
    if "$INSTALL" --answers "$W/a.yaml" --print-answers >"$W/out" 2>&1; then
        fail "$1 was accepted"
    else pass "$1 is refused ($(tail -1 "$W/out" | sed 's/^.*: //' | cut -c1-70))"; fi
}
bad "unknown key" "colour: blue"
bad "duplicate key" "tls: csr"
bad "server name without a domain" "s/^server_name: .*/server_name: radius/"
bad "server name with shell characters" 's/^server_name: .*/server_name: "x.example.net;reboot"/'
bad "subnet with host bits" "s#^admin_net: .*#admin_net: 192.0.2.10/24#"
bad "/0 subnet" "s#^admin_net: .*#admin_net: 0.0.0.0/0#"
bad "listen address that is not an IP" "s/^listen_ip: .*/listen_ip: eth0/"
bad "resolver that is not an IP" 's/^resolver: .*/resolver: "192.0.2.53 dns.example.net"/'
bad "unknown certificate choice" "s/^tls: .*/tls: acme/"
bad "existing certificate without files" "s/^tls: .*/tls: existing/"
bad "username with capitals" "s/^admin_username: .*/admin_username: NetAdmin/"
bad "line that is not key: value" "just text"
bad "switch network with host bits" "switch_nets: 198.51.100.7/24"
bad "/0 switch network" "switch_nets: \"192.0.2.0/24 0.0.0.0/0\""
bad "switch networks with shell characters" "switch_nets: \"192.0.2.0/24;reboot\""
bad "crypto mode other than on/off" "fips: maybe"

# crypto mode: standard mode by default; FIPS mode only on a host whose kernel runs in FIPS
# mode; the installed require_fips always wins (an update never changes it)
good
grep -qx 'fips: off' <<<"$out" && pass "standard mode is the default (fips: off)" || fail "fips default: $out"
echo 'fips: on' >> "$W/a.yaml"
if "$INSTALL" --answers "$W/a.yaml" --print-answers >"$W/out" 2>&1; then
    fail "FIPS mode accepted on a host whose kernel is not in FIPS mode"
elif grep -q "kernel is not in FIPS mode" "$W/out"; then pass "FIPS mode refused on a non-FIPS host, with a clear message"
else fail "FIPS refusal message: $(tail -1 "$W/out")"; fi
good
"$INSTALL" --answers "$W/a.yaml" --fips --print-answers >/dev/null 2>&1 \
    && fail "--fips accepted on a non-FIPS host" || pass "--fips refused on a non-FIPS host"
"$INSTALL" --answers "$W/a.yaml" --fips --standard-mode --print-answers >/dev/null 2>&1 \
    && fail "--fips with --standard-mode accepted" || pass "--fips and --standard-mode exclude each other"
echo 1 > "$W/fips_on"
grep -qx 'fips: on' <(RA_FIPS_ENABLED_FILE=$W/fips_on "$INSTALL" --answers "$W/a.yaml" --fips --print-answers 2>&1) \
    && pass "--fips accepted on a host whose kernel runs in FIPS mode" || fail "--fips on a FIPS host"
echo 'fips: on' >> "$W/a.yaml"
grep -qx 'fips: off' <("$INSTALL" --answers "$W/a.yaml" --standard-mode --print-answers 2>&1) \
    && pass "--standard-mode overrides the answers" || fail "--standard-mode ignored"
printf '[app]\nrequire_fips = false\n' > "$W/live-off.conf"
lo=$(RA_APP_CONF=$W/live-off.conf RA_FIPS_ENABLED_FILE=$W/fips_on "$INSTALL" --answers "$W/a.yaml" --print-answers 2>&1)
grep -qx "fips: off" <<<"$lo" && grep -q "ignored: this server is installed with fips: off" <<<"$lo" \
    && pass "answers on an installed server keep its require_fips (standard mode)" || fail "live standard mode not kept: $lo"
good
printf '[app]\nrequire_fips = true\n' > "$W/live-on.conf"
grep -qx 'fips: on' <(RA_APP_CONF=$W/live-on.conf "$INSTALL" --answers "$W/a.yaml" --print-answers 2>&1) \
    && pass "answers on an installed server keep its require_fips (FIPS mode)" || fail "live FIPS mode not kept"

# preflight: in standard mode the FIPS checks never block; in FIPS mode they do
pf_fips_fails() { grep -E '\[FAIL\].*(FIPS|fips|_hashlib)' "$1"; }
good
"$INSTALL" --answers "$W/a.yaml" --phase preflight -y --skip-preflight >"$W/pf.out" 2>&1
if grep -q '== Crypto mode ==' "$W/pf.out" && grep -q 'standard mode' "$W/pf.out" && ! pf_fips_fails "$W/pf.out" >/dev/null; then
    pass "standard-mode answers: preflight on a non-FIPS host has no FIPS failures"
else fail "standard-mode preflight: $(pf_fips_fails "$W/pf.out" || tail -3 "$W/pf.out")"; fi
"$ROOT/deploy/preflight.sh" --fips-mode on >"$W/pf.out" 2>&1
pf_fips_fails "$W/pf.out" | grep -q 'kernel FIPS mode OFF' \
    && pass "FIPS-mode preflight on a non-FIPS host blocks" || fail "FIPS-mode preflight did not block"
RA_APP_CONF=$W/live-on.conf "$ROOT/deploy/preflight.sh" >"$W/pf.out" 2>&1
pf_fips_fails "$W/pf.out" | grep -q 'kernel FIPS mode OFF' \
    && pass "preflight without --fips-mode follows the installed require_fips" || fail "preflight ignored the live require_fips"

# radius-admin.conf for a first install: require_fips from the chosen mode
(
    # shellcheck source=../../deploy/lib.sh
    . "$ROOT/deploy/lib.sh"
    ex=$ROOT/deploy/etc/radius-admin.conf.example
    render_app_conf "$ex" "$W/c.conf" radius.example.net off || exit 1
    grep -qx 'require_fips = false' "$W/c.conf" && grep -qx 'server_name = radius.example.net' "$W/c.conf" || exit 1
    RA_APP_CONF=$W/c.conf; [[ $(live_fips) == off ]] || exit 1
    render_app_conf "$ex" "$W/c.conf" radius.example.net on || exit 1
    grep -qx 'require_fips = true' "$W/c.conf" && [[ $(live_fips) == on ]] || exit 1
    [[ $(grep -c '^require_fips' "$W/c.conf") == 1 ]]
) && pass "radius-admin.conf written with require_fips for the chosen mode" || fail "render_app_conf / live_fips"

# switch networks (where the monitor may send SNMP and CoA): default admin_net, a list
# in the answers, else what the installed unit allows, and --switch-nets on the command line
good
grep -qx 'switch_nets: 192.0.2.0/24' <<<"$out" \
    && pass "switch networks default to the management subnet" || fail "switch_nets default: $out"
echo 'switch_nets: "198.51.100.0/24 2001:db8:5::/48"' >> "$W/a.yaml"
grep -qx 'switch_nets: "198.51.100.0/24 2001:db8:5::/48"' <("$INSTALL" --answers "$W/a.yaml" --print-answers 2>&1) \
    && pass "a list of switch networks (IPv4 and IPv6) is accepted" || fail "switch_nets list not accepted"
good
printf '[Service]\nIPAddressDeny=any\nIPAddressAllow=198.51.100.0/24\nIPAddressAllow=203.0.113.0/24\n' > "$W/unit"
grep -qx 'switch_nets: "198.51.100.0/24 203.0.113.0/24"' \
    <(RA_SNMP_UNIT=$W/unit "$INSTALL" --answers "$W/a.yaml" --print-answers 2>&1) \
    && pass "switch networks are kept from the installed monitor unit" || fail "live switch networks not kept"
grep -qx 'switch_nets: 203.0.113.0/24' \
    <(RA_SNMP_UNIT=$W/unit "$INSTALL" --answers "$W/a.yaml" --switch-nets 203.0.113.0/24 --print-answers 2>&1) \
    && pass "--switch-nets overrides the answers" || fail "--switch-nets ignored"

# the monitor unit is rendered with exactly those networks, and bad input never reaches it
(
    # shellcheck source=../../deploy/lib.sh
    . "$ROOT/deploy/lib.sh"
    tmpl=$ROOT/deploy/systemd/radius-admin-snmp.service
    render_snmp_unit "$tmpl" "$W/r.service" "192.0.2.0/24 2001:db8:5::/48" || exit 1
    grep -qx 'IPAddressAllow=192.0.2.0/24 2001:db8:5::/48' "$W/r.service" || exit 1
    ! grep -v '^[[:space:]]*#' "$W/r.service" | grep -qE '@[A-Z_]+@' || exit 1
    RA_SNMP_UNIT=$W/r.service; [[ $(live_switch_nets) == "192.0.2.0/24 2001:db8:5::/48" ]] || exit 1
    for b in "" "192.0.2.0/24 x#y" "0.0.0.0/0" "192.0.2.5/24"; do
        if render_snmp_unit "$tmpl" "$W/b.service" "$b" >/dev/null 2>&1; then exit 1; fi
    done
) && pass "monitor unit rendered with the switch networks; bad networks refused" \
  || fail "render_snmp_unit / live_switch_nets"

"$INSTALL" --print-answers >/dev/null 2>&1 && fail "--print-answers without answers accepted" \
    || pass "--print-answers needs --answers or --interactive"

# interactive: answers piped to the questions; Enter keeps the defaults
out=$(printf 'portal.example.net\n198.51.100.0/24\n198.51.100.7\n\n198.51.100.53\n\nops-admin\n\n' \
      | "$INSTALL" --interactive --print-answers 2>&1)
if grep -qx 'server_name: portal.example.net' <<<"$out" && grep -qx 'admin_net: 198.51.100.0/24' <<<"$out" \
    && grep -qx 'switch_nets: 198.51.100.0/24' <<<"$out" \
    && grep -qx 'tls: self-signed' <<<"$out" && grep -qx 'admin_username: ops-admin' <<<"$out" \
    && grep -qx 'fips: off' <<<"$out"; then
    pass "interactive questions take typed answers and defaults"
else fail "interactive: $out"; fi

# site phase: site.yaml + self-signed ECDSA P-384 certificate for the server name
good
sed -i "s/^listen_ip: .*/listen_ip: $LOCAL_IP/" "$W/a.yaml"
if "$INSTALL" --answers "$W/a.yaml" --phase site -y >"$W/site.out" 2>&1; then
    pass "site phase runs"
else fail "site phase: $(tail -5 "$W/site.out")"; fi
[[ $(stat -c '%U:%G %a' "$ETC/site.yaml" 2>/dev/null) == "root:root 640" ]] && grep -qx 'tls: self-signed' "$ETC/site.yaml" \
    && pass "site.yaml written root:root 0640" || fail "site.yaml missing or wrong mode"
c=$ETC/tls/server.crt
if openssl x509 -in "$c" -noout -text 2>/dev/null | grep -q 'NIST CURVE: P-384' \
    && openssl x509 -in "$c" -noout -ext subjectAltName | grep -q 'DNS:radius.example.net' \
    && [[ $(stat -c '%a' "$ETC/tls/server.key") == 600 ]]; then
    pass "self-signed certificate: ECDSA P-384, SAN radius.example.net, key 0600"
else fail "self-signed certificate not as expected"; fi
before=$(sha256sum "$c")
"$INSTALL" --answers "$W/a.yaml" --phase site -y >/dev/null 2>&1
[[ $(sha256sum "$c") == "$before" ]] && pass "re-running keeps the existing certificate" || fail "certificate was replaced"

echo
if (( fails )); then echo "$fails FAILED"; exit 1; fi
echo "ALL INSTALLER TESTS PASSED"
