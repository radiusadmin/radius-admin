#!/bin/bash
# deploy/update-install.sh: the checks it makes before it touches anything. Sandbox only, as
# root: writes a log under /var/log/radius-admin. A full install needs an installed server.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
UI=$ROOT/deploy/update-install.sh
[[ $EUID -eq 0 ]] || { echo "run as root (sandbox)"; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
export RA_HELPER_WORK=$W RA_BACKUP_DIR=$W/backups
st() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$W/update-state.json" "$1"; }
prep() { # prep VERSION MANIFEST_VERSION [tamper]
    rm -rf "$W/update"; mkdir -p "$W/update/$1"
    printf 'bundle' > "$W/update/$1/bundle.tar.gz"
    local h; h=$(sha384sum "$W/update/$1/bundle.tar.gz" | cut -d' ' -f1)
    printf '{"version": "%s", "restarts_freeradius": false, "bundle": {"sha384": "%s"}}' "$2" "$h" > "$W/update/$1/manifest.json"
    if [[ ${3:-} == tamper ]]; then printf 'x' >> "$W/update/$1/bundle.tar.gz"; fi
    printf '{"state": "queued", "version": "%s", "from": "0.1.0", "actor": "netadmin"}' "$1" > "$W/update-state.json"
}

"$UI" '0.2.0;id' >/dev/null 2>&1; [[ $? -eq 2 ]] && pass "refuses a malformed version" || fail "malformed version accepted"
printf '{"state": "queued", "version": "0.2.0"}' > "$W/update-state.json"
"$UI" 0.2.0 >/dev/null 2>&1
[[ $? -ne 0 && $(st state) == failed && $(st message) == *"verified copy is missing"* ]] \
    && pass "no verified copy: fails without installing" || fail "missing copy: $(cat "$W/update-state.json")"
prep 0.2.0 0.3.0
"$UI" 0.2.0 >/dev/null 2>&1
[[ $(st state) == failed && $(st message) == *"another version"* ]] \
    && pass "a manifest for another version is refused" || fail "version mismatch: $(st message)"
prep 0.2.0 0.2.0 tamper
"$UI" 0.2.0 >/dev/null 2>&1
[[ $(st state) == failed && $(st message) == *"no longer matches"* && ! -e $W/update/0.2.0 ]] \
    && pass "a copy changed after verification is refused and removed" || fail "tampered copy: $(st message)"
[[ ! -e $W/backups ]] && pass "nothing was backed up or installed in any of these cases" || fail "backups were made"
[[ $(st actor) == netadmin && -n $(st finished) ]] && pass "the state keeps who asked and when it ended" \
    || fail "state: $(cat "$W/update-state.json")"

echo; (( fails == 0 )) && echo "all update-install checks passed" || echo "$fails check(s) FAILED"
exit $(( fails > 0 ))
