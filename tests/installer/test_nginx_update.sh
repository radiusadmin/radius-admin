#!/bin/bash
# nginx security floor (RA_NGINX_MIN_VERSION in deploy/lib.sh): the version comparison, the
# installer's nginx-update phase (upgrade from the mirror when a fixed build is available, restart
# a running nginx), update.sh adding that phase, and preflight reporting it. apt, dpkg-query,
# systemctl and nginx are stubs; nothing outside a temp directory is touched.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# --- stubs: state lives in $W/st/*, every call is logged to $W/calls
mkdir -p "$W/bin" "$W/st"
cat > "$W/bin/dpkg-query" <<'EOF'
#!/bin/bash
v=$(cat "$ST/installed" 2>/dev/null)
[[ -n $v ]] || exit 1
printf 'install ok installed %s' "$v"
EOF
cat > "$W/bin/apt-cache" <<'EOF'
#!/bin/bash
printf 'nginx:\n  Installed: (none)\n  Candidate: %s\n' "$(cat "$ST/candidate" 2>/dev/null || echo '(none)')"
EOF
cat > "$W/bin/apt-get" <<'EOF'
#!/bin/bash
echo "apt-get $* NEEDRESTART_SUSPEND=${NEEDRESTART_SUSPEND:-}" >> "$CALLS"
case " $* " in
    *" update "*) [[ -f $ST/after_update ]] && cp "$ST/after_update" "$ST/candidate" ;;
    *" install "*) cp "$ST/candidate" "$ST/installed" ;;
esac
exit 0
EOF
cat > "$W/bin/systemctl" <<'EOF'
#!/bin/bash
echo "systemctl $*" >> "$CALLS"
[[ $1 == is-active ]] && exit "$(cat "$ST/active")"
exit 0
EOF
cat > "$W/bin/nginx" <<'EOF'
#!/bin/bash
exit "$(cat "$ST/nginx_t")"
EOF
chmod +x "$W/bin"/*
export ST=$W/st CALLS=$W/calls PATH=$W/bin:$PATH

# shellcheck source=../../deploy/lib.sh
. "$ROOT/deploy/lib.sh"
MIN=${RA_NGINX_MIN_VERSION:-}
[[ -n $MIN ]] && pass "RA_NGINX_MIN_VERSION is set ($MIN)" || fail "RA_NGINX_MIN_VERSION missing from lib.sh"

# --- nginx_version_ok
for v in "1.24.0-2ubuntu7.20" "1.24.0-2ubuntu7.21" "1.24.0-2ubuntu8" "1.30.7-1~noble"; do
    nginx_version_ok "$v" && pass "$v is accepted" || fail "$v should be accepted"
done
for v in "1.24.0-2ubuntu7.19" "1.24.0-2ubuntu7" "1.22.1-9+deb12u10" ""; do
    nginx_version_ok "$v" && fail "'$v' should be refused" || pass "'$v' is refused"
done

# --- phase_nginx_update (extracted from install.sh, run in a subshell like the installer: set -e)
eval "$(awk '/^phase_nginx_update\(\)/,/^}/' "$ROOT/deploy/install.sh")"
declare -F phase_nginx_update >/dev/null && pass "install.sh defines phase_nginx_update" || fail "install.sh has no phase_nginx_update"
OLD=1.24.0-2ubuntu7.19 NEW=1.24.0-2ubuntu7.20
# run_case INSTALLED CANDIDATE AFTER_UPDATE ACTIVE(0/1) NGINX_T(0/1): sets rc, out, calls
run_case() {
    rm -f "$ST"/* "$CALLS"; touch "$CALLS"
    printf '%s' "$1" > "$ST/installed"; [[ -n $2 ]] && printf '%s' "$2" > "$ST/candidate"
    [[ -n $3 ]] && printf '%s' "$3" > "$ST/after_update"
    echo "$4" > "$ST/active"; echo "$5" > "$ST/nginx_t"
    out=$( (set -euo pipefail; phase_nginx_update) 2>&1); rc=$?
    calls=$(cat "$CALLS")
}
has()  { grep -q -- "$1" <<<"$calls"; }

run_case "$NEW" "$NEW" "" 0 0
[[ $rc == 0 && -z $calls ]] && pass "current nginx: nothing installed, no apt or systemctl call" || fail "current nginx: rc=$rc calls=[$calls]"

run_case "" "$NEW" "" 0 0
[[ $rc == 0 && -z $calls ]] && pass "nginx not installed: nothing to do" || fail "not installed: rc=$rc calls=[$calls]"

run_case "$OLD" "$NEW" "" 0 0
if [[ $rc == 0 ]] && has "apt-get install .*--only-upgrade.* nginx NEEDRESTART_SUSPEND=1" && ! has "apt-get update" \
        && has "systemctl restart nginx" && [[ $(cat "$ST/installed") == "$NEW" ]]; then
    pass "outdated nginx, fixed build in the lists: upgraded (needrestart suspended) and restarted"
else fail "outdated + candidate: rc=$rc calls=[$calls] out=[$out]"; fi
has "systemctl reload" && fail "nginx was reloaded instead of restarted" || pass "no reload (a reload keeps the old binary)"

run_case "$OLD" "$OLD" "$NEW" 0 0
if [[ $rc == 0 ]] && has "apt-get update" && has "apt-get install .*nginx" && has "systemctl restart nginx"; then
    pass "fixed build only after apt-get update: lists refreshed, upgraded, restarted"
else fail "after update: rc=$rc calls=[$calls] out=[$out]"; fi

run_case "$OLD" "$OLD" "$OLD" 0 0
if [[ $rc == 0 ]] && has "apt-get update" && ! has "apt-get install" && ! has "systemctl restart" && grep -q 'WARN' <<<"$out"; then
    pass "no fixed build on the mirror: warns, installs nothing, does not fail the install"
else fail "no fixed build: rc=$rc calls=[$calls] out=[$out]"; fi

run_case "$OLD" "$NEW" "" 3 0
if [[ $rc == 0 ]] && has "apt-get install .*nginx" && ! has "systemctl restart"; then
    pass "nginx not running: upgraded, not started"
else fail "inactive: rc=$rc calls=[$calls] out=[$out]"; fi

run_case "$OLD" "$NEW" "" 0 1
if [[ $rc != 0 ]] && ! has "systemctl restart" && grep -q 'nginx -t' <<<"$out"; then
    pass "nginx -t fails after the upgrade: stops without restarting nginx"
else fail "nginx -t failure: rc=$rc calls=[$calls] out=[$out]"; fi

# --- install.sh wiring
grep -q '^ALL_PHASES=(preflight packages nginx-update fr-package ' "$ROOT/deploy/install.sh" \
    && pass "nginx-update runs right after packages" || fail "nginx-update not in ALL_PHASES after packages"
grep -q '^        nginx-update) phase_nginx_update ;;$' "$ROOT/deploy/install.sh" \
    && pass "install.sh dispatches nginx-update" || fail "install.sh does not dispatch nginx-update"

# --- update.sh: adds nginx-update when the installed nginx is older than the NEW release's floor
eval "$(awk '/^nginx_outdated\(\)/,/^}/' "$ROOT/deploy/update.sh")"
mkdir -p "$W/rel/deploy"; cp "$ROOT/deploy/lib.sh" "$W/rel/deploy/lib.sh"
printf '%s' "$OLD" > "$ST/installed"
nginx_outdated "$W/rel" && pass "update.sh: outdated nginx detected" || fail "update.sh: outdated nginx not detected"
printf '%s' "$NEW" > "$ST/installed"
nginx_outdated "$W/rel" && fail "update.sh: current nginx reported outdated" || pass "update.sh: current nginx left alone"
: > "$ST/installed"
nginx_outdated "$W/rel" && fail "update.sh: missing nginx reported outdated" || pass "update.sh: no nginx, no phase"
grep -q 'if nginx_outdated "$new"; then phases+=(nginx-update); fi' "$ROOT/deploy/update.sh" \
    && pass "update.sh adds the phase from its automatic choice" || fail "update.sh does not add nginx-update"

# --- preflight reports it (read-only: no apt-get / systemctl there)
grep -q 'nginx_installed_version' "$ROOT/deploy/preflight.sh" && grep -q 'nginx_version_ok' "$ROOT/deploy/preflight.sh" \
    && pass "preflight checks the nginx version" || fail "preflight does not check the nginx version"
grep -qE '^[^#"]*apt-get (install|update)' "$ROOT/deploy/preflight.sh" \
    && fail "preflight runs apt-get (it must stay read-only)" || pass "preflight stays read-only"

echo
if ((fails)); then echo "nginx security floor: $fails FAILED"; exit 1; fi
echo "nginx security floor: all checks passed"
