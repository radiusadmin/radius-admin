#!/bin/bash
# Re-running the installer on a new server after a first run stopped part way (found by a fresh
# WSL install): the set-up questions when no answers were saved, preflight on the package's stock
# FreeRADIUS configuration, and a PostgreSQL cluster that is not on port 5432.
# Sandbox only, as root. Writes nothing outside a temporary directory.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL=$ROOT/deploy/install.sh
[[ $EUID -eq 0 ]] || { echo "run as root (sandbox)"; exit 2; }
command -v script >/dev/null || { echo "script(1) missing (util-linux)"; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# nothing installed: no saved answers, no portal site, no monitor unit, no app config
export RA_SITE_YAML=$W/no-site.yaml RA_NGINX_SITE=$W/no-nginx-site RA_SNMP_UNIT=$W/no-unit \
       RA_APP_CONF=$W/no-radius-admin.conf RA_FIPS_ENABLED_FILE=$W/fips_enabled
echo 0 > "$W/fips_enabled"
ANSWERS_IN='portal.example.net\n198.51.100.0/24\n198.51.100.7\n\n198.51.100.53\n\nops-admin\n\n\n\n'

on_tty() { # on_tty INPUT CMD... : run CMD on a pseudo-terminal (stdin is a terminal), INPUT typed
    local input=$1; shift
    printf "$input" | script -qec "$(printf '%q ' "$@")" /dev/null 2>&1
}

# --- 1. no saved answers, on a terminal, with other options: the questions are asked
out=$(on_tty "$ANSWERS_IN" "$INSTALL" --skip-preflight --print-answers)
if grep -q 'Set-up questions' <<<"$out" && grep -q 'server_name: portal.example.net' <<<"$out"; then
    pass "no saved answers + options on a terminal: the set-up questions are asked"
else fail "no questions with options: $(tr '\r\n' '  ' <<<"$out" | cut -c1-300)"; fi

# --- 2. saved answers (site.yaml): no questions, the saved answers are used
cat > "$W/site.yaml" <<'EOF'
server_name: radius.example.net
admin_net: 192.0.2.0/24
listen_ip: 192.0.2.10
switch_nets: 192.0.2.0/24
resolver: 192.0.2.53
tls: self-signed
admin_username: netadmin
eap_tls: self-signed
EOF
out=$(RA_SITE_YAML=$W/site.yaml on_tty "" "$INSTALL" --skip-preflight --print-answers)
if ! grep -q 'Set-up questions' <<<"$out"; then
    pass "saved answers in site.yaml: no questions"
else fail "questions despite site.yaml: $(tr '\r\n' '  ' <<<"$out" | cut -c1-200)"; fi

# --- 3. only phases that need no answers: no questions
out=$(on_tty "" "$INSTALL" --skip-preflight --phase preflight)
if ! grep -q 'Set-up questions' <<<"$out"; then
    pass "--phase preflight alone: no questions"
else fail "questions for --phase preflight"; fi

# --- 4. not a terminal (updates, scripts): never asked, and the error names --interactive
out=$("$INSTALL" --skip-preflight --print-answers </dev/null 2>&1)
if ! grep -q 'Set-up questions' <<<"$out" && grep -q -- '--interactive' <<<"$out"; then
    pass "no terminal: no questions; the error mentions --interactive"
else fail "no-terminal case: $(tail -2 <<<"$out")"; fi
grep -q 'management subnet unknown.*--interactive' "$INSTALL" \
    && pass "nginx phase error mentions --interactive" || fail "nginx phase error does not mention --interactive"

# --- 5. preflight on the package's stock FreeRADIUS configuration of a new server
mkdir -p "$W/bin" "$W/raddb"
cat > "$W/bin/radiusd" <<'EOF'
#!/bin/bash
case " $* " in
    *" -v "*) echo "FreeRADIUS Version 3.2.10, for host x86_64-pc-linux-gnu" ;;
    *" -XC "*) echo "rlm_eap_tls: Failed initializing SSL context"; echo "Instantiation failed for module \"eap\""; exit 1 ;;
esac
EOF
chmod 755 "$W/bin/radiusd"
id freerad >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin freerad
pf() { PATH=$W/bin:$PATH RA_RADDB=$W/raddb "$ROOT/deploy/preflight.sh" --sqlite "$W/no.db" 2>&1; }
out=$(pf)
if ! grep -q 'FAILS radiusd -XC' <<<"$out" && grep -q 'INFO.*radiusd -XC.*new server' <<<"$out"; then
    pass "new server: the stock configuration failing radiusd -XC is INFO, not a failure"
else fail "new server -XC: $(grep -i 'radiusd -XC' <<<"$out" | head -2)"; fi
mkdir -p "$W/raddb/policy.d" && touch "$W/raddb/policy.d/radius-admin"
out=$(pf)
grep -q 'FAIL.*FAILS radiusd -XC' <<<"$out" \
    && pass "configured server: radiusd -XC failing still blocks" || fail "configured server -XC not a failure"

# --- 5b. preflight on its own reads this host's settings, not the example defaults
# shellcheck source=../../deploy/lib.sh
. "$ROOT/deploy/lib.sh"
cidr=$(primary_ipv4_cidr || true)
if [[ -n $cidr ]]; then
    net=$(python3 -I -c 'import ipaddress, sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$cidr")
    printf 'server_name: portal.example.net\nadmin_net: %s\n' "$net" > "$W/site-pf.yaml"
    out=$(PATH=$W/bin:$PATH RA_RADDB=$W/raddb RA_SITE_YAML=$W/site-pf.yaml RA_NGINX_SITE=$W/none RA_FIREWALL_NFT=$W/none \
          "$ROOT/deploy/preflight.sh" --sqlite "$W/no.db" 2>&1)
    if grep -q "OK.*address in admin network $net" <<<"$out" && grep -q 'portal.example.net' <<<"$out" \
        && grep -q "settings from $W/site-pf.yaml" <<<"$out" && ! grep -q '192.0.2.0/24\|radius.example.net' <<<"$out"; then
        pass "preflight alone: management subnet and server name from site.yaml, not the example defaults"
    else fail "preflight alone: $(grep -E 'admin network|example|settings from' <<<"$out" | head -4)"; fi
    out=$(PATH=$W/bin:$PATH RA_RADDB=$W/raddb RA_SITE_YAML=$W/none RA_NGINX_SITE=$W/none RA_FIREWALL_NFT=$W/none \
          "$ROOT/deploy/preflight.sh" --sqlite "$W/no.db" 2>&1)
    grep -q 'example default' <<<"$out" \
        && pass "preflight alone on a new server: says the subnet is the example default" || fail "no default note: $(grep -E 'admin network|settings' <<<"$out" | head -3)"
else
    echo "SKIP: no global IPv4 address for the preflight settings test"
fi

# --- 6. PostgreSQL cluster port
# shellcheck source=../../deploy/lib.sh
. "$ROOT/deploy/lib.sh"
C=$W/pg/16/main
mkdir -p "$C/conf.d"
printf '#port = 5433\nport = 5433\t\t\t# (change requires restart)\n' > "$C/postgresql.conf"
[[ $(pg_cluster_port "$C") == 5433 ]] && pass "pg_cluster_port reads postgresql.conf" || fail "port: $(pg_cluster_port "$C")"
printf "port = 5432\n" > "$C/conf.d/zz.conf"
[[ $(pg_cluster_port "$C") == 5432 ]] && pass "pg_cluster_port: conf.d overrides postgresql.conf" || fail "conf.d: $(pg_cluster_port "$C")"
rm "$C/conf.d/zz.conf"; printf 'max_connections = 100\n' > "$C/postgresql.conf"
[[ $(pg_cluster_port "$C") == 5432 ]] && pass "pg_cluster_port: no port set means 5432" || fail "default: $(pg_cluster_port "$C")"
printf 'port = 5433\n' > "$C/postgresql.conf"
eval "$(sed -n '/^pg_port_check() {/,/^}/p' "$INSTALL")"
msg=$( die() { echo "$*"; exit 1; }; pg_port_check "$C" ) && fail "port 5433 accepted" \
    || { grep -q '5433' <<<"$msg" && grep -q 'pg_conftool 16 main set port 5432' <<<"$msg" \
         && pass "cluster on 5433: stops with the port and the command that fixes it" || fail "message: $msg"; }
printf 'port = 5432\n' > "$C/postgresql.conf"
( die() { echo "$*"; exit 1; }; pg_port_check "$C" ) >/dev/null && pass "cluster on 5432: accepted" || fail "5432 refused"
grep -q 'pg_log_tail' "$INSTALL" && grep -q 'PostgreSQL not ready.*pg_log_tail\|pg_log_tail.*PostgreSQL not ready' "$INSTALL" \
    && pass "readiness failure prints the end of PostgreSQL's log" || fail "readiness failure prints no log"

echo
if (( fails )); then echo "$fails FAILED"; exit 1; fi
echo "ALL RE-RUN TESTS PASSED"
