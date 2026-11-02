# shellcheck shell=bash
# Shared functions for install.sh / preflight.sh / rollback.sh. Source only.
# Nothing in here changes the system.

RA_RADDB=${RA_RADDB:-/etc/freeradius}
RA_SQLITE_DB=${RA_SQLITE_DB:-/var/lib/freeradius/sqlite/freeradius.db}
RA_ADMIN_NET=${RA_ADMIN_NET:-192.0.2.0/24}
RA_SERVER_NAME=${RA_SERVER_NAME:-radius.example.net}
RA_OCSP_URL=${RA_OCSP_URL:-http://pki.example.net:8080/ocsp}
RA_OCSP_HOST=${RA_OCSP_HOST:-pki.example.net}
RA_BACKUP_DIR=${RA_BACKUP_DIR:-/var/backups/radius-admin}
RA_PG_VERSION=${RA_PG_VERSION:-16}
RA_PG_CLUSTER=${RA_PG_CLUSTER:-main}
# interpreter for the app/CLI (Ubuntu 24.04: /usr/bin/python3 = 3.12, matches apt modules)
RA_PYTHON=${RA_PYTHON:-/usr/bin/python3}

if [[ -t 1 ]]; then
    C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLD=$'\e[1m'; C_OFF=$'\e[0m'
else
    C_RED=; C_GRN=; C_YEL=; C_BLD=; C_OFF=
fi
WARNINGS=0
FAILURES=0

say()   { printf '%s\n' "$*"; }
hdr()   { printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$C_OFF"; }
ok()    { printf '  %s[ OK ]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
info()  { printf '  [INFO] %s\n' "$*"; }
warn()  { printf '  %s[WARN]%s %s\n' "$C_YEL" "$C_OFF" "$*"; WARNINGS=$((WARNINGS + 1)); }
bad()   { printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_OFF" "$*"; FAILURES=$((FAILURES + 1)); }
die()   { printf '%sERROR:%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "must be run as root (sudo $0 ...)"
}

# FreeRADIUS systemd unit: freeradius.service or radiusd.service (prefer enabled/active).
detect_fr_service() {
    local u best=""
    for u in freeradius radiusd; do
        if systemctl list-unit-files --no-legend "$u.service" 2>/dev/null | grep -q "^$u.service"; then
            if systemctl is-active --quiet "$u.service" || systemctl is-enabled --quiet "$u.service"; then
                printf '%s\n' "$u"; return 0
            fi
            [[ -z $best ]] && best=$u
        fi
    done
    [[ -n $best ]] && { printf '%s\n' "$best"; return 0; }
    return 1
}

# radiusd binary: from the unit's ExecStart, else PATH, else common custom-build paths.
detect_radiusd() {
    local svc=${1:-} p
    if [[ -n $svc ]]; then
        p=$(systemctl show -p ExecStart --value "$svc.service" 2>/dev/null \
            | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1)
        if [[ -n $p && -x $p && $(basename "$p") =~ ^(radiusd|freeradius)$ ]]; then
            printf '%s\n' "$p"; return 0
        fi
    fi
    for p in $(command -v radiusd freeradius 2>/dev/null) /usr/local/sbin/radiusd /usr/sbin/radiusd /usr/sbin/freeradius; do
        [[ -x $p ]] && { printf '%s\n' "$p"; return 0; }
    done
    return 1
}

# The bundled radius-admin-freeradius package in DIR for this distribution release and
# architecture (newest version if several), built by tools/package/build-freeradius-deb.sh.
detect_bundled_fr() {
    local dir=$1 dist arch
    # shellcheck disable=SC1091
    dist=$(. /etc/os-release && printf '%s%s' "$ID" "$VERSION_ID")
    arch=$(dpkg --print-architecture 2>/dev/null) || return 1
    compgen -G "$dir/radius-admin-freeradius_*~${dist}_$arch.deb" | sort -V | tail -n1 | grep .
}

# Directory holding rlm_*.so of the build that $1 (radiusd) belongs to.
detect_fr_libdir() {
    local radiusd=$1 d rp prefix
    rp=$(readelf -d "$radiusd" 2>/dev/null | sed -n 's/.*R\(UN\)\{0,1\}PATH.*\[\(.*\)\]/\2/p' | head -n1)
    prefix=$(dirname "$(dirname "$radiusd")")
    local IFS=:
    for d in $rp "$prefix/lib/freeradius" "$prefix/lib" "$prefix/lib64/freeradius" \
             /usr/lib/freeradius /usr/lib/x86_64-linux-gnu/freeradius /usr/local/lib/freeradius /usr/local/lib; do
        [[ -n $d && -e $d/rlm_sql.so ]] && { printf '%s\n' "$d"; return 0; }
    done
    return 1
}

# This host's IPv4 address inside the admin network (first match).
detect_vlan_ip() {
    local net=${1:-$RA_ADMIN_NET}
    ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | while read -r a; do
        if python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)' "$a" "$net"; then
            printf '%s\n' "$a"
        fi
    done | head -n1
}

# Networks radius-admin-snmp may reach (SNMP, CoA), from the installed unit: an update runs
# install.sh without answers and must keep them. Prints them space separated, or fails.
RA_SNMP_UNIT=${RA_SNMP_UNIT:-/etc/systemd/system/radius-admin-snmp.service}
live_switch_nets() {
    [[ -r $RA_SNMP_UNIT ]] || return 1
    local n
    n=$(awk '/^[[:space:]]*IPAddressAllow=/ { sub(/^[^=]*=/, ""); l = ($0 == "") ? "" : l " " $0 }
             END { $0 = l; $1 = $1; print }' "$RA_SNMP_UNIT")
    [[ -n $n ]] && printf '%s\n' "$n"
}

# render_snmp_unit TEMPLATE DST "NET [NET...]": the monitor unit, allowed only those networks
render_snmp_unit() {
    local tmpl=$1 dst=$2 nets=$3 list
    read -r -a list <<<"$nets"
    [[ ${#list[@]} -gt 0 ]] || { warn "no switch networks given"; return 1; }
    if ! python3 -I -c 'import ipaddress, sys
for n in sys.argv[1:]:
    assert ipaddress.ip_network(n, strict=True).prefixlen > 0' "${list[@]}" 2>/dev/null; then
        warn "switch networks '$nets' are not all networks in CIDR form (no host bits, not /0)"; return 1
    fi
    sed -e "s#@SWITCH_NETS@#${list[*]}#g" "$tmpl" > "$dst"
}

# Portal settings as installed on this host. An update runs install.sh with phases and -y but
# no answers and must keep them, not fall back to the example defaults above. live_nginx KEY /
# live_nft KEY print server_name, admin_net, listen_ip, resolver or ocsp_url, or fail.
RA_SITE_YAML=${RA_SITE_YAML:-/etc/radius-admin/site.yaml}
RA_NGINX_SITE=${RA_NGINX_SITE:-/etc/nginx/sites-available/radius-admin}
RA_FIREWALL_NFT=${RA_FIREWALL_NFT:-/etc/radius-admin/firewall.nft}
live_nginx() {
    [[ -r $RA_NGINX_SITE ]] || return 1
    local v
    v=$(awk -v k="$1" '{ sub(/#.*/, ""); sub(/;[[:space:]]*$/, "") }
        k == "server_name" && $1 == "server_name" { print $2; exit }
        k == "admin_net" && $1 == "allow" { print $2; exit }
        k == "listen_ip" && $1 == "listen" && $2 ~ /:443$/ { sub(/:443$/, "", $2); print $2; exit }
        k == "ocsp_url" && $1 == "ssl_ocsp_responder" { print $2; exit }
        k == "resolver" && $1 == "resolver" {
            l = ""; for (i = 2; i <= NF && $i !~ /=/; i++) l = l (l == "" ? "" : " ") $i; print l; exit }' \
        "$RA_NGINX_SITE")
    [[ -n $v ]] && printf '%s\n' "$v"
}
live_nft() {
    [[ -r $RA_FIREWALL_NFT ]] || return 1
    local v
    v=$(awk -v k="$1" '/tcp dport 443/ && / accept/ { for (i = 1; i < NF; i++) {
            if (k == "admin_net" && $i == "saddr") { print $(i + 1); exit }
            if (k == "listen_ip" && $i == "daddr") { print $(i + 1); exit } } }' "$RA_FIREWALL_NFT")
    [[ -n $v ]] && printf '%s\n' "$v"
}

# DNS servers usable by nginx `resolver` (IPv4, real upstreams preferred over the stub).
detect_resolvers() {
    local r=""
    if command -v resolvectl >/dev/null 2>&1; then
        r=$(resolvectl dns 2>/dev/null | sed 's/^[^:]*://' | tr ' ' '\n' \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | tr '\n' ' ')
    fi
    if [[ -z ${r// /} ]]; then
        r=$(awk '$1=="nameserver" && $2 ~ /^[0-9.]+$/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u | tr '\n' ' ')
    fi
    r=${r%% }
    [[ -n $r ]] && printf '%s\n' "$r"
}

# Which host firewall is in charge: ufw | nftables | iptables | none
detect_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        echo ufw
    elif systemctl is-active --quiet nftables.service 2>/dev/null; then
        echo nftables
    elif command -v nft >/dev/null 2>&1 && [[ -n $(nft list tables 2>/dev/null) ]]; then
        echo nftables
    elif command -v iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -q '^-A'; then
        echo iptables
    else
        echo none
    fi
}

pg_conf_dir() { printf '/etc/postgresql/%s/%s\n' "$RA_PG_VERSION" "$RA_PG_CLUSTER"; }

psql_su() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 "$@"; }
