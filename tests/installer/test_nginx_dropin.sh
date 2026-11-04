#!/bin/bash
# The nginx.service drop-in (deploy/systemd/nginx.service.d/radius-admin.conf): nginx resolves
# the OCSP responder when it starts and a failed lookup is fatal, so the drop-in makes it wait
# for the network and retry. Checks the drop-in, that the nginx phase installs it, and that
# update.sh runs the nginx phase when it changes. Touches nothing outside a temp directory.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DROPIN=$ROOT/deploy/systemd/nginx.service.d/radius-admin.conf
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# --- the drop-in
if [[ -f $DROPIN ]]; then pass "drop-in is shipped"; else fail "drop-in $DROPIN missing"; fi
for kv in "After=network-online.target nss-lookup.target" "Wants=network-online.target" \
          "StartLimitIntervalSec=0" "Restart=on-failure" "RestartSec=30s"; do
    grep -qx "$kv" "$DROPIN" 2>/dev/null && pass "drop-in sets $kv" || fail "drop-in lacks $kv"
done
sect() { awk -v s="[$1]" '/^\[/{in_s=($0==s)} in_s && $0 !~ /^\[/' "$DROPIN" 2>/dev/null; }
sect Unit | grep -q '^StartLimitIntervalSec=0$' && sect Service | grep -q '^Restart=on-failure$' \
    && pass "StartLimitIntervalSec in [Unit], Restart in [Service]" || fail "settings in the wrong section"
if command -v systemd-analyze >/dev/null 2>&1; then
    # the drop-in appended to a stand-in unit (repeated sections merge as in a drop-in)
    { printf '[Unit]\nDescription=stand-in for nginx.service\n[Service]\nExecStart=/bin/true\n'
      cat "$DROPIN"; } > "$W/ra-nginx-dropin-check.service" 2>/dev/null
    out=$(systemd-analyze verify --man=no "$W/ra-nginx-dropin-check.service" 2>&1)
    grep -qiE 'unknown|invalid|failed to parse' <<<"$out" \
        && fail "systemd-analyze: $out" || pass "systemd accepts the drop-in's settings"
fi

# --- install.sh: the nginx phase installs it (before the site, with a daemon-reload)
body=$(awk '/^phase_nginx\(\)/,/^}/' "$ROOT/deploy/install.sh")
put_ln=$(grep -n 'put "$HERE/systemd/nginx.service.d/radius-admin.conf" /etc/systemd/system/nginx.service.d/radius-admin.conf root:root 0644' <<<"$body" | cut -d: -f1)
site_ln=$(grep -n '"$HERE/nginx/radius-admin.conf"' <<<"$body" | cut -d: -f1)
[[ -n $put_ln && -n $site_ln ]] && (( put_ln < site_ln )) \
    && pass "phase_nginx installs the drop-in before it renders the site" || fail "phase_nginx does not install the drop-in first"
grep -q 'install -d -m 0755 /etc/systemd/system/nginx.service.d' <<<"$body" \
    && pass "phase_nginx creates nginx.service.d 0755" || fail "phase_nginx does not create nginx.service.d"
[[ -n $put_ln ]] && sed -n "$((put_ln + 1))p" <<<"$body" | grep -q 'systemctl daemon-reload' \
    && pass "phase_nginx reloads systemd when the drop-in changed" || fail "no daemon-reload after the drop-in"

# --- update.sh: the nginx phase runs when the drop-in changes (the real function and line)
fn=$(awk '/^changed\(\) \{/,/^}/' "$ROOT/deploy/update.sh")
ln=$(grep -E '^[[:space:]]*if changed deploy/nginx.*phases\+=\(nginx\)' "$ROOT/deploy/update.sh")
nginx_phase() { # nginx_phase CUR NEW -> prints "nginx" when update.sh would run the phase
    # shellcheck disable=SC2034  # cur, new: read by the eval-ed changed() from update.sh
    local cur=$1 new=$2 phases=()
    eval "$fn"; eval "$ln"
    printf '%s' "${phases[*]}"
}
mkrel() { mkdir -p "$1/deploy/nginx" "$1/deploy/systemd/nginx.service.d"
          echo site > "$1/deploy/nginx/radius-admin.conf"; cp "$DROPIN" "$1/deploy/systemd/nginx.service.d/" 2>/dev/null; }
mkrel "$W/a"; mkrel "$W/b"
[[ -z $(nginx_phase "$W/a" "$W/b") ]] && pass "update: no nginx phase when nothing changed" || fail "update: nginx phase without a change"
echo '# changed' >> "$W/b/deploy/systemd/nginx.service.d/radius-admin.conf"
[[ $(nginx_phase "$W/a" "$W/b") == nginx ]] && pass "update: nginx phase when only the drop-in changed" \
    || fail "update: drop-in change does not run the nginx phase"
rm -rf "$W/a/deploy/systemd/nginx.service.d"; mkrel "$W/c"
[[ $(nginx_phase "$W/a" "$W/c") == nginx ]] && pass "update: nginx phase from a release without the drop-in" \
    || fail "update: upgrade from a release without the drop-in skips the nginx phase"
grep -q 'deploy/systemd/nginx.service.d' <(sed -n '1,/^set -E/p' "$ROOT/deploy/update.sh") \
    && pass "update.sh header lists the drop-in for the nginx phase" || fail "update.sh header not updated"

echo
if ((fails)); then echo "$fails check(s) failed"; exit 1; fi
echo "all nginx drop-in checks passed"
