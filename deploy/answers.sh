#!/bin/bash
# Installer answers: interactive questions or an answers file (sourced by install.sh).
#
# Answers file (the same format install.sh writes to /etc/radius-admin/site.yaml), one
# "key: value" per line, # comments allowed, values optionally in double quotes:
#   server_name: radius.example.net       FQDN of the portal (TLS certificate name)
#   admin_net: 192.0.2.0/24               management subnet allowed to reach the portal
#   listen_ip: 192.0.2.10                 portal address (default: this host's address in admin_net)
#   resolver: "192.0.2.53 192.0.2.54"     DNS resolvers for nginx OCSP lookups (default: detected)
#   tls: self-signed                      self-signed | csr | existing
#   tls_cert: /path/server.crt            tls: existing only (leaf first, then intermediates)
#   tls_key: /path/server.key             tls: existing only
#   admin_username: admin                 first portal administrator (created with a one-time password)
# shellcheck shell=bash

ANS_KEYS=(server_name admin_net listen_ip resolver tls tls_cert tls_key admin_username)
declare -A ANS=()

ans_load() { # ans_load FILE
    local file=$1 line key val n=0
    [[ -r $file ]] || die "answers file $file is not readable"
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! $line =~ ^([a-z_]+):[[:space:]]*(.*[^[:space:]])?[[:space:]]*$ ]]; then
            die "$file line $n: expected 'key: value'"
        fi
        key=${BASH_REMATCH[1]}; val=${BASH_REMATCH[2]:-}
        if [[ $val =~ ^\"(.*)\"$ ]]; then val=${BASH_REMATCH[1]}; fi
        [[ " ${ANS_KEYS[*]} " == *" $key "* ]] || die "$file line $n: unknown key '$key' (known: ${ANS_KEYS[*]})"
        [[ -z ${ANS[$key]+x} ]] || die "$file line $n: '$key' given twice"
        ANS[$key]=$val
    done < "$file"
}

_ans_py() { # _ans_py CHECK VALUE [VALUE2]: stdlib-only validators
    "${RA_PYTHON:-/usr/bin/python3}" -I - "$@" <<'PY'
import ipaddress, re, sys
what, v = sys.argv[1], sys.argv[2]
try:
    if what == "net":
        n = ipaddress.ip_network(v, strict=True)
        assert n.prefixlen > 0
    elif what == "ip":
        ipaddress.ip_address(v)
    elif what == "ip_in_net":
        assert ipaddress.ip_address(v) in ipaddress.ip_network(sys.argv[3], strict=False)
    elif what == "net_of":                         # 192.0.2.10/24 -> 192.0.2.0/24
        print(ipaddress.ip_interface(v).network)
    elif what == "fqdn":
        assert re.fullmatch(r"(?=.{4,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", v)
    elif what == "user":
        assert re.fullmatch(r"[a-z0-9._-]{2,64}", v)
except (ValueError, AssertionError):
    sys.exit(1)
PY
}

ans_defaults() {
    local host net
    host=$(hostname -f 2>/dev/null || true)
    _ans_py fqdn "$host" || host=$RA_SERVER_NAME
    : "${ANS[server_name]:=$host}"
    if [[ -z ${ANS[admin_net]:-} ]]; then
        net=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4; exit}')
        net=$([[ -n $net ]] && _ans_py net_of "$net" || true)
        ANS[admin_net]=${net:-$RA_ADMIN_NET}
    fi
    : "${ANS[listen_ip]:=$(detect_vlan_ip "${ANS[admin_net]}" 2>/dev/null || true)}"
    : "${ANS[resolver]:=$(detect_resolvers 2>/dev/null || true)}"
    : "${ANS[tls]:=self-signed}"
    : "${ANS[admin_username]:=admin}"
}

_ask() { # _ask KEY "Question" -> reads stdin (a terminal, or a pipe in tests)
    local key=$1 q=$2 v
    read -r -p "  $q [${ANS[$key]:-}]: " v || true
    [[ -n $v ]] && ANS[$key]=$v
    return 0
}

ans_interactive() {
    say "${C_BLD}Set-up questions${C_OFF} (Enter accepts the value in brackets)"
    _ask server_name "Server name (FQDN of the portal)"
    _ask admin_net "Management subnet allowed to reach the portal (CIDR)"
    [[ -z ${ANS[listen_ip]:-} ]] && ANS[listen_ip]=$(detect_vlan_ip "${ANS[admin_net]}" 2>/dev/null || true)
    _ask listen_ip "Portal listen address"
    _ask resolver "DNS resolvers (space separated)"
    say "  Portal certificate: self-signed (replace later), csr (for your CA), existing (files you have)"
    _ask tls "Portal certificate"
    if [[ ${ANS[tls]} == existing ]]; then
        _ask tls_cert "Certificate file (leaf first, then intermediates)"
        _ask tls_key "Private key file"
    fi
    _ask admin_username "First administrator username"
}

ans_validate() {
    _ans_py fqdn "${ANS[server_name]:-}" || die "server_name '${ANS[server_name]:-}' is not a fully qualified host name"
    _ans_py net "${ANS[admin_net]:-}" || die "admin_net '${ANS[admin_net]:-}' is not a network in CIDR form (no host bits, not /0)"
    _ans_py ip "${ANS[listen_ip]:-}" || die "listen_ip '${ANS[listen_ip]:-}' is not an IP address (and none was found in ${ANS[admin_net]})"
    _ans_py ip_in_net "${ANS[listen_ip]}" "${ANS[admin_net]}" \
        || warn "listen_ip ${ANS[listen_ip]} is outside admin_net ${ANS[admin_net]}"
    ip -o addr show 2>/dev/null | grep -qw -- "${ANS[listen_ip]}" \
        || warn "listen_ip ${ANS[listen_ip]} is not configured on this host"
    local r
    [[ -n ${ANS[resolver]:-} ]] || die "resolver: no DNS resolver given or detected"
    for r in ${ANS[resolver]}; do _ans_py ip "$r" || die "resolver '$r' is not an IP address"; done
    case ${ANS[tls]:-} in
        self-signed|csr) [[ -z ${ANS[tls_cert]:-}${ANS[tls_key]:-} ]] || die "tls_cert/tls_key are only used with tls: existing" ;;
        existing)
            [[ -r ${ANS[tls_cert]:-} ]] || die "tls_cert '${ANS[tls_cert]:-}' is not a readable file"
            [[ -r ${ANS[tls_key]:-} ]] || die "tls_key '${ANS[tls_key]:-}' is not a readable file" ;;
        *) die "tls must be self-signed, csr or existing (got '${ANS[tls]:-}')" ;;
    esac
    _ans_py user "${ANS[admin_username]:-}" || die "admin_username must be 2-64 characters: lowercase letters, digits, . _ -"
}

ans_print() {
    local k
    printf '# radius-admin site settings (written by deploy/install.sh; reuse with --answers)\n'
    for k in "${ANS_KEYS[@]}"; do
        [[ -n ${ANS[$k]:-} ]] || continue
        if [[ ${ANS[$k]} == *" "* ]]; then printf '%s: "%s"\n' "$k" "${ANS[$k]}"; else printf '%s: %s\n' "$k" "${ANS[$k]}"; fi
    done
}
