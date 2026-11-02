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
out=$(printf 'portal.example.net\n198.51.100.0/24\n198.51.100.7\n\n198.51.100.53\n\nops-admin\n' \
      | "$INSTALL" --interactive --print-answers 2>&1)
if grep -qx 'server_name: portal.example.net' <<<"$out" && grep -qx 'admin_net: 198.51.100.0/24' <<<"$out" \
    && grep -qx 'switch_nets: 198.51.100.0/24' <<<"$out" \
    && grep -qx 'tls: self-signed' <<<"$out" && grep -qx 'admin_username: ops-admin' <<<"$out"; then
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
