#!/bin/bash
# Installer answers: interactive questions or an answers file (sourced by install.sh).
#
# Answers file (the same format install.sh writes to /etc/radius-admin/site.yaml), one
# "key: value" per line, # comments allowed, values optionally in double quotes:
#   server_name: radius.example.net       FQDN of the portal (TLS certificate name)
#   admin_net: 192.0.2.0/24               management subnet allowed to reach the portal
#   listen_ip: 192.0.2.10                 portal address (default: this host's address in admin_net)
#   switch_nets: "192.0.2.0/24 198.51.100.0/24"   networks the monitor may reach for SNMP and
#                                         CoA (default: what the installed monitor allows, else admin_net)
#   resolver: "192.0.2.53 192.0.2.54"     DNS resolvers for nginx OCSP lookups (default: detected)
#   tls: self-signed                      self-signed | csr | existing
#   tls_cert: /path/server.crt            tls: existing only (leaf first, then intermediates)
#   tls_key: /path/server.key             tls: existing only
#   admin_username: admin                 first portal administrator (created with a one-time password)
#   eap_tls: self-signed                  802.1X (EAP) server certificate of a new server:
#                                         self-signed (throwaway, replace it) | existing (files below)
#   eap_cert: /path/radius.pem            eap_tls: existing only: server certificate (leaf)
#   eap_key: /path/radius.key             eap_tls: existing only: its private key
#   eap_ca: /path/ca.pem                  eap_tls: existing only: CA(s) that issue client certificates
#   ocsp_url: http://ocsp.example.net/ocsp   OCSP responder for client certificates (portal and, on a
#                                         new server, EAP-TLS); none by default. A server that already
#                                         runs keeps its EAP certificates and OCSP settings.
#   fips: off                             off (standard mode, the default) | on (FIPS mode: needs a
#                                         host whose kernel runs in FIPS mode). Written to
#                                         require_fips on the first install; an update keeps the live value
# shellcheck shell=bash

ANS_KEYS=(server_name admin_net listen_ip switch_nets resolver tls tls_cert tls_key admin_username fips
          eap_tls eap_cert eap_key eap_ca ocsp_url)
declare -A ANS=()

ans_load() { # ans_load FILE [ARRAY]: into ANS, or the associative ARRAY (site.yaml as installed:
    # unknown keys are skipped there, since a newer release may have written it before a rollback)
    local file=$1 line key val n=0
    local -n _ans_to=${2:-ANS}
    [[ -r $file ]] || die "answers file $file is not readable"
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! $line =~ ^([a-z_]+):[[:space:]]*(.*[^[:space:]])?[[:space:]]*$ ]]; then
            die "$file line $n: expected 'key: value'"
        fi
        key=${BASH_REMATCH[1]}; val=${BASH_REMATCH[2]:-}
        if [[ $val =~ ^\"(.*)\"$ ]]; then val=${BASH_REMATCH[1]}; fi
        if [[ " ${ANS_KEYS[*]} " != *" $key "* ]]; then
            [[ -n ${2:-} ]] && continue
            die "$file line $n: unknown key '$key' (known: ${ANS_KEYS[*]})"
        fi
        [[ -z ${_ans_to[$key]+x} ]] || die "$file line $n: '$key' given twice"
        _ans_to[$key]=$val
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
    elif what == "url":                            # nginx ssl_ocsp_responder
        assert re.fullmatch(r"https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?", v)
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
        net=$(primary_ipv4_cidr)
        net=$([[ -n $net ]] && _ans_py net_of "$net" || true)
        ANS[admin_net]=${net:-$RA_ADMIN_NET}
    fi
    : "${ANS[listen_ip]:=$(detect_vlan_ip "${ANS[admin_net]}" 2>/dev/null || true)}"
    : "${ANS[switch_nets]:=$(live_switch_nets || true)}"
    : "${ANS[resolver]:=$(detect_resolvers 2>/dev/null || true)}"
    : "${ANS[tls]:=self-signed}"
    : "${ANS[admin_username]:=admin}"
    : "${ANS[fips]:=off}"
    : "${ANS[eap_tls]:=self-signed}"
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
    : "${ANS[switch_nets]:=${ANS[admin_net]}}"
    _ask switch_nets "Switch networks the monitor may reach for SNMP and CoA (CIDR, space separated)"
    _ask resolver "DNS resolvers (space separated)"
    say "  Portal certificate: self-signed (replace later), csr (for your CA), existing (files you have)"
    _ask tls "Portal certificate"
    if [[ ${ANS[tls]} == existing ]]; then
        _ask tls_cert "Certificate file (leaf first, then intermediates)"
        _ask tls_key "Private key file"
    fi
    _ask admin_username "First administrator username"
    say "  Crypto mode: off = standard mode; on = FIPS mode (the host kernel must run in FIPS mode)"
    _ask fips "FIPS mode (on/off)"
    say "  802.1X (EAP) server certificate, used when FreeRADIUS is set up for the first time:"
    say "  existing (you have the certificate, key and client CA files) or self-signed (made now, replace it later)"
    _ask eap_tls "EAP certificate"
    if [[ ${ANS[eap_tls]} == existing ]]; then
        _ask eap_cert "EAP server certificate file"
        _ask eap_key "Its private key file"
        _ask eap_ca "CA file for client certificates"
    fi
    _ask ocsp_url "OCSP responder URL for client certificates (empty: no revocation check)"
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
    : "${ANS[switch_nets]:=${ANS[admin_net]}}"
    for r in ${ANS[switch_nets]}; do
        _ans_py net "$r" || die "switch_nets: '$r' is not a network in CIDR form (no host bits, not /0)"
    done
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
    [[ ${ANS[fips]:-} == on || ${ANS[fips]:-} == off ]] || die "fips must be on or off (got '${ANS[fips]:-}')"
    case ${ANS[eap_tls]:-} in
        self-signed) [[ -z ${ANS[eap_cert]:-}${ANS[eap_key]:-}${ANS[eap_ca]:-} ]] || die "eap_cert/eap_key/eap_ca are only used with eap_tls: existing" ;;
        existing)
            local f
            for f in eap_cert eap_key eap_ca; do
                [[ -r ${ANS[$f]:-} ]] || die "$f '${ANS[$f]:-}' is not a readable file"
            done ;;
        *) die "eap_tls must be self-signed or existing (got '${ANS[eap_tls]:-}')" ;;
    esac
    [[ -z ${ANS[ocsp_url]:-} ]] || _ans_py url "${ANS[ocsp_url]}" || die "ocsp_url '${ANS[ocsp_url]}' is not an http(s) URL"
}

ans_print() {
    local k
    printf '# radius-admin site settings (written by deploy/install.sh; reuse with --answers)\n'
    for k in "${ANS_KEYS[@]}"; do
        [[ -n ${ANS[$k]:-} ]] || continue
        if [[ ${ANS[$k]} == *" "* ]]; then printf '%s: "%s"\n' "$k" "${ANS[$k]}"; else printf '%s: %s\n' "$k" "${ANS[$k]}"; fi
    done
}

# ans_record FILE KEY VALUE [KEY VALUE...]: set those keys in an existing answers file
# (site.yaml) and keep the others, so that the next run without answers (an update) uses
# what nginx and the firewall now run. Empty values are left as they are.
ans_record() {
    local file=$1 tmp; shift
    [[ -f $file ]] || return 0
    tmp=$(mktemp)
    if ! (
        ANS=()
        ans_load "$file"
        while (( $# >= 2 )); do [[ -n $2 ]] && ANS[$1]=$2; shift 2; done
        ans_print
    ) > "$tmp"; then
        rm -f "$tmp"; warn "could not update $file"; return 0
    fi
    if cmp -s "$tmp" "$file"; then rm -f "$tmp"; return 0; fi
    install -o root -g root -m 0640 "$tmp" "$file"
    rm -f "$tmp"
    info "updated $file"
}
