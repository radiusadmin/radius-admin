#!/bin/bash
# radius-admin -- diagnose which radius-admin-helper@.service sandbox setting stops
# `radiusd -XC` (read-only: runs the config check on the LIVE /etc/freeradius, which
# changes nothing). Run as root:  sudo ./deploy/diag-helper-sandbox.sh
#
# 1. runs `radiusd -XC` in a transient unit with ALL the helper's sandbox settings;
# 2. if that fails, re-runs it once per setting with that ONE setting removed and
#    reports which removal makes it pass.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

UNIT=/etc/systemd/system/radius-admin-helper@.service
[[ -f $UNIT ]] || { echo "$UNIT not found" >&2; exit 1; }
RADIUSD=$(sed -n 's/^[[:space:]]*radiusd[[:space:]]*=[[:space:]]*//p' /etc/radius-admin/helper.conf | head -n1)
RADDB=$(sed -n 's/^[[:space:]]*raddb[[:space:]]*=[[:space:]]*//p' /etc/radius-admin/helper.conf | head -n1)
RADIUSD=${RADIUSD:-/usr/sbin/radiusd}
RADDB=${RADDB:-/etc/freeradius}

# sandbox properties from the installed unit (everything except exec/IO/identity lines)
mapfile -t PROPS < <(grep -E '^[A-Z][A-Za-z]+=' "$UNIT" \
    | grep -vE '^(Type|ExecStart|StandardInput|StandardOutput|StandardError|SyslogIdentifier|Description|Documentation|CollectMode|TimeoutStartSec)=')

run_check() { # args: properties...
    local args=() p
    for p in "$@"; do args+=(-p "$p"); done
    systemd-run --quiet --wait --pipe --collect "${args[@]}" \
        "$RADIUSD" -XC -d "$RADDB" 2>&1 | tail -n 3
}

echo "radiusd: $RADIUSD   raddb: $RADDB"
echo "== 1. with all ${#PROPS[@]} helper sandbox settings"
out=$(run_check "${PROPS[@]}" || true)
printf '%s\n' "$out" | sed 's/^/   | /'
if grep -q 'appears to be OK' <<<"$out"; then
    echo "PASS with the full sandbox -- the problem is not the sandbox."
    exit 0
fi

echo "== 2. removing one setting at a time"
for i in "${!PROPS[@]}"; do
    rest=("${PROPS[@]:0:i}" "${PROPS[@]:i+1}")
    out=$(run_check "${rest[@]}" || true)
    if grep -q 'appears to be OK' <<<"$out"; then
        echo "   PASS without: ${PROPS[$i]}"
    else
        echo "   fail without: ${PROPS[$i]}"
    fi
done
echo "== 3. kernel/LSM notes"
sed 's/^/   lsm: /' /sys/kernel/security/lsm 2>/dev/null || true
aa-status 2>/dev/null | grep -iE 'radius|freeradius' | sed 's/^/   apparmor: /' || true
journalctl -k -n 50 --no-pager 2>/dev/null | grep -iE 'apparmor|audit.*(radius|freeradius)' | tail -n 5 | sed 's/^/   kernel: /' || true
