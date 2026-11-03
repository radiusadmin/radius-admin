#!/bin/bash
# install.sh without answers (what update.sh runs): the portal settings come from this host
# (site.yaml, else the installed nginx site, else the firewall table), never from the example
# defaults, and explicit options still win. Sandbox only, as root: the files read are fixtures
# under a temporary directory; refuses to run when /etc/radius-admin exists (an installed server).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL=$ROOT/deploy/install.sh
[[ $EUID -eq 0 ]] || { echo "run as root (sandbox)"; exit 2; }
[[ -e /etc/radius-admin ]] && { echo "/etc/radius-admin exists: refusing (sandbox only)"; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W" /etc/radius-admin' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
export RA_SITE_YAML=$W/site.yaml RA_NGINX_SITE=$W/nginx.conf RA_FIREWALL_NFT=$W/firewall.nft
reset() { rm -f "$RA_SITE_YAML" "$RA_NGINX_SITE" "$RA_FIREWALL_NFT"; }
settings() { "$INSTALL" --print-settings "$@" 2>&1; }
has() { grep -qxF -- "$1" <<<"$2"; }

# the installed files, rendered from the templates the way install.sh does
nginx_site() { # nginx_site LISTEN_IP SERVER_NAME ADMIN_NET RESOLVER OCSP_URL
    sed -e "s#@LISTEN_IP@#$1#g" -e "s#@SERVER_NAME@#$2#g" -e "s#@ADMIN_NET@#$3#g" \
        -e "s#@RESOLVER@#$4#g" -e "s#@OCSP_URL@#$5#g" "$ROOT/deploy/nginx/radius-admin.conf" > "$RA_NGINX_SITE"
}
nft_table() { # nft_table LISTEN_IP ADMIN_NET
    sed -e "s#@LISTEN_IP@#$1#g" -e "s#@ADMIN_NET@#$2#g" "$ROOT/deploy/firewall/radius-admin.nft" > "$RA_FIREWALL_NFT"
}
site_yaml() {
    cat > "$RA_SITE_YAML" <<EOF
# radius-admin site settings (written by deploy/install.sh; reuse with --answers)
server_name: portal.example.org
admin_net: 203.0.113.0/24
listen_ip: 203.0.113.7
resolver: "203.0.113.53 203.0.113.54"
tls: self-signed
admin_username: netadmin
EOF
}

reset
out=$(settings)
has 'admin_net: 192.0.2.0/24 (default)' "$out" \
    && pass "nothing installed: the example default, marked as such" || fail "no live settings: $out"

nginx_site 198.51.100.7 portal.example.net 198.51.100.0/24 "198.51.100.53 198.51.100.54" http://ocsp.example.net/ocsp
out=$(settings)
if has "server_name: portal.example.net ($RA_NGINX_SITE)" "$out" \
    && has "admin_net: 198.51.100.0/24 ($RA_NGINX_SITE)" "$out" \
    && has "listen_ip: 198.51.100.7 ($RA_NGINX_SITE)" "$out" \
    && has "resolver: 198.51.100.53 198.51.100.54 ($RA_NGINX_SITE)" "$out" \
    && has "ocsp_url: http://ocsp.example.net/ocsp ($RA_NGINX_SITE)" "$out"; then
    pass "no site.yaml: every setting is kept from the installed nginx site"
else fail "settings from the nginx site: $out"; fi

rm -f "$RA_NGINX_SITE"
nft_table 198.51.100.8 198.51.100.0/25
out=$(settings)
has "admin_net: 198.51.100.0/25 ($RA_FIREWALL_NFT)" "$out" && has "listen_ip: 198.51.100.8 ($RA_FIREWALL_NFT)" "$out" \
    && pass "no nginx site: subnet and address are kept from the firewall table" || fail "settings from nft: $out"

nginx_site 198.51.100.7 portal.example.net 198.51.100.0/24 198.51.100.53 http://ocsp.example.net/ocsp
site_yaml
out=$(settings)
if has "server_name: portal.example.org ($RA_SITE_YAML)" "$out" && has "admin_net: 203.0.113.0/24 ($RA_SITE_YAML)" "$out" \
    && has "listen_ip: 203.0.113.7 ($RA_SITE_YAML)" "$out" \
    && has "resolver: 203.0.113.53 203.0.113.54 ($RA_SITE_YAML)" "$out" \
    && has "ocsp_url: http://ocsp.example.net/ocsp ($RA_NGINX_SITE)" "$out"; then
    pass "site.yaml comes first; the OCSP responder (not in site.yaml) from nginx"
else fail "settings from site.yaml: $out"; fi

echo 'some_future_key: x' >> "$RA_SITE_YAML"
has "admin_net: 203.0.113.0/24 ($RA_SITE_YAML)" "$(settings)" \
    && pass "a key this release does not know (site.yaml of a newer one) is skipped" || fail "unknown key in site.yaml"
site_yaml
out=$(settings --admin-net 192.0.2.0/24 --listen-ip 192.0.2.10 --server-name radius.example.net --resolver 192.0.2.53)
if has 'admin_net: 192.0.2.0/24 (option)' "$out" && has 'listen_ip: 192.0.2.10 (option)' "$out" \
    && has 'server_name: radius.example.net (option)' "$out" && has 'resolver: 192.0.2.53 (option)' "$out"; then
    pass "options win over site.yaml"
else fail "options vs site.yaml: $out"; fi
out=$(RA_OCSP_URL=http://ocsp.example.com/ocsp settings)
has 'ocsp_url: http://ocsp.example.com/ocsp (option)' "$out" \
    && pass "RA_OCSP_URL in the environment wins over the nginx site" || fail "RA_OCSP_URL: $out"

out=$("$INSTALL" --answers "$RA_SITE_YAML" --admin-net 198.51.100.0/24 --listen-ip 198.51.100.7 --print-answers 2>&1)
has 'admin_net: 198.51.100.0/24' "$out" && has 'listen_ip: 198.51.100.7' "$out" \
    && pass "options win over an answers file" || fail "options vs answers: $out"

# a damaged live value is refused, not used (nor replaced by the example)
site_yaml; sed -i 's#^admin_net: .*#admin_net: 203.0.113.7/24#' "$RA_SITE_YAML"
settings >"$W/out" && fail "site.yaml subnet with host bits accepted" \
    || pass "site.yaml subnet with host bits is refused ($(tail -1 "$W/out" | cut -c1-70))"
rm -f "$RA_SITE_YAML"
nginx_site 198.51.100.7 portal.example.net "198.51.100.0/24;reboot" 198.51.100.53 http://ocsp.example.net/ocsp
settings >/dev/null && fail "nginx allow with shell characters accepted" || pass "nginx allow with shell characters is refused"
nginx_site 198.51.100.7 portal.example.net 198.51.100.0/24 198.51.100.53 'http://x.example.net/a$b'
settings >/dev/null && fail "OCSP URL with a dollar sign accepted" || pass "OCSP URL that would break the template is refused"

# phases that render the portal's access rules (an update with nginx/firewall changes)
reset
out=$("$INSTALL" --phase nginx -y 2>&1)
[[ $out == *"management subnet unknown"* ]] \
    && pass "nginx phase with no known subnet stops instead of using the example" || fail "nginx with nothing known: $out"
nginx_site 198.51.100.7 portal.example.net 198.51.100.0/24 198.51.100.53 http://ocsp.example.net/ocsp
out=$("$INSTALL" --phase nginx -y 2>&1)
# stops later, at the missing portal certificate: nothing is installed in the sandbox
[[ $out == *"management subnet 198.51.100.0/24 ($RA_NGINX_SITE)"* && $out == *"server.key missing"* \
    && $out != *"192.0.2."* ]] \
    && pass "update-style nginx phase uses the installed subnet and address" || fail "nginx phase: $out"

# site.yaml follows what nginx/firewall now run, so the next update does not revert an option
site_yaml
(
    # shellcheck source=../../deploy/lib.sh
    . "$ROOT/deploy/lib.sh"
    # shellcheck source=../../deploy/answers.sh
    . "$ROOT/deploy/answers.sh"
    ans_record "$RA_SITE_YAML" admin_net 198.51.100.0/24 listen_ip 198.51.100.7 resolver "" >/dev/null
    grep -qx 'admin_net: 198.51.100.0/24' "$RA_SITE_YAML" && grep -qx 'listen_ip: 198.51.100.7' "$RA_SITE_YAML" \
        && grep -qx 'resolver: "203.0.113.53 203.0.113.54"' "$RA_SITE_YAML" \
        && grep -qx 'admin_username: netadmin' "$RA_SITE_YAML" && grep -qx 'tls: self-signed' "$RA_SITE_YAML" || exit 1
    [[ $(stat -c '%U:%G %a' "$RA_SITE_YAML") == "root:root 640" ]] || exit 1
    m=$(stat -c %Y.%i "$RA_SITE_YAML"); sleep 1
    ans_record "$RA_SITE_YAML" admin_net 198.51.100.0/24 >/dev/null
    [[ $(stat -c %Y.%i "$RA_SITE_YAML") == "$m" ]] || exit 1
    rm -f "$RA_SITE_YAML"; ans_record "$RA_SITE_YAML" admin_net 198.51.100.0/24 >/dev/null
    [[ ! -e $RA_SITE_YAML ]] || exit 1
) && pass "site.yaml records the subnet and address in use, keeps the rest, is not created" \
  || fail "ans_record: $(cat "$RA_SITE_YAML" 2>/dev/null)"

echo
if (( fails )); then echo "$fails FAILED"; exit 1; fi
echo "ALL LIVE SETTINGS TESTS PASSED"
