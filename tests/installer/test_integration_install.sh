#!/bin/bash
# deploy/integration-install.sh (SPEC section 29) in a throwaway directory: the copy is checked
# again, the provider's installer from the release runs, the state records the outcome.
# Root (the script chowns its log directory); sandbox only.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT=$ROOT/deploy/integration-install.sh
W=$(mktemp -d /tmp/ra-intinst.XXXXXX)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
export RA_HELPER_WORK=$W/helper RA_OPT=$W/opt RA_INTEGRATION_LOG_DIR=$W/logs
mkdir -p "$RA_HELPER_WORK" "$RA_OPT/integrations/duo"
FILE=duoauthproxy-6.7.0-src.tgz

prepare() { # prepare [SHA256] : the helper's checked copy and request.json
    local d=$RA_HELPER_WORK/integration/duo
    rm -rf "$d"; mkdir -p "$d"
    printf 'build bytes\n' > "$d/$FILE"
    local h=${1:-$(sha256sum "$d/$FILE" | cut -d' ' -f1)}
    printf '{"id": "duo", "version": "6.7.0", "file": "%s", "sha256": "%s", "size": %d, "verified": "catalog"}\n' \
        "$FILE" "$h" "$(stat -c %s "$d/$FILE")" > "$d/request.json"
}
st() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["duo"][sys.argv[2]])' "$RA_HELPER_WORK/integration-state.json" "$1"; }

# no installer in this release
prepare
bash "$SCRIPT" duo >/dev/null 2>&1
[[ $? -ne 0 && $(st state) == failed && $(st message) == *"no installer for duo"* ]] \
    && pass "a release without an installer for the provider fails cleanly" || fail "no installer: $(st message)"
[[ ! -d $RA_HELPER_WORK/integration/duo ]] && pass "the checked copy is removed afterwards" || fail "copy left behind"
ls "$RA_INTEGRATION_LOG_DIR"/integration-duo-*.log >/dev/null 2>&1 && [[ $(st log) == "$RA_INTEGRATION_LOG_DIR"/integration-duo-* ]] \
    && pass "the log is written and named in the state" || fail "log: $(st log)"

# the provider's installer gets request.json and the build
cat > "$RA_OPT/integrations/duo/install.sh" <<'EOF'
#!/bin/bash
echo "installer args: $1 $2"
[[ -f $1 && -f $2 ]] || exit 1
grep -q '"version": "6.7.0"' "$1"
EOF
chmod 0755 "$RA_OPT/integrations/duo/install.sh"
prepare
out=$(bash "$SCRIPT" duo 2>&1)
[[ $? -eq 0 && $(st state) == "done" && $(st message) == "installed 6.7.0" && $out == *"installer args: "*request.json* ]] \
    && pass "a checked build is installed by the provider's installer" || fail "install: $(st message) $out"

# the copy changed after the helper checked it
prepare "$(printf '0%.0s' {1..64})"
bash "$SCRIPT" duo >/dev/null 2>&1
[[ $? -ne 0 && $(st state) == failed && $(st message) == *"no longer matches"* ]] \
    && pass "a copy that changed after the check is refused" || fail "tampered copy: $(st message)"

# a failing installer
printf '#!/bin/bash\nexit 3\n' > "$RA_OPT/integrations/duo/install.sh"
prepare
bash "$SCRIPT" duo >/dev/null 2>&1
[[ $? -ne 0 && $(st state) == failed && $(st message) == *"installer for duo failed"* ]] \
    && pass "a failing installer is recorded as failed" || fail "failing installer: $(st message)"

# an installer others can change is not run
chmod 0777 "$RA_OPT/integrations/duo/install.sh"
prepare
bash "$SCRIPT" duo >/dev/null 2>&1
[[ $(st message) == *"writable only by root"* ]] && pass "a writable installer is not run" || fail "writable: $(st message)"
chmod 0755 "$RA_OPT/integrations/duo/install.sh"

# bad arguments
bash "$SCRIPT" '../x' >/dev/null 2>&1; [[ $? -eq 2 ]] && pass "an invalid id is refused" || fail "invalid id"

echo; (( fails == 0 )) && echo "all integration install checks passed" || echo "$fails check(s) FAILED"
exit $(( fails > 0 ))
