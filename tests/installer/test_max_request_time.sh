#!/bin/bash
# max_request_time in radiusd.conf (SPEC section 29): FreeRADIUS cuts every home server's
# response_window to it, and the second-factor providers wait up to 60 s, so install.sh's
# raise_max_request_time sets at least RA_FR_MAX_REQUEST_TIME (90) and keeps a higher live value.
# Fixtures only (temporary directory); needs no FreeRADIUS.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL=$ROOT/deploy/install.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

# shellcheck source=../../deploy/lib.sh
. "$ROOT/deploy/lib.sh"
die() { echo "die: $*"; return 1; }
eval "$(sed -n '/^raise_max_request_time() {/,/^}/p' "$INSTALL")"
declare -F raise_max_request_time >/dev/null || { echo "raise_max_request_time not found in $INSTALL"; exit 2; }

F=$W/radiusd.conf
conf() { # conf LINE... : a radiusd.conf like the stock one, with the given top-level lines
    { echo "prefix = /usr"; echo "#  max_request_time: The maximum time (in seconds) to handle a request."
      echo "#max_request_time = 10"; printf '%s\n' "$@"; echo "thread pool {"; echo "	max_request_time = 5"
      echo "}"; echo "\$INCLUDE sites-enabled/"; } > "$F"
    chmod 0640 "$F"
}
active() { sed -n 's/^max_request_time = //p' "$F" | tr '\n' ' '; }

# 1. stock value 30 -> 90
conf "max_request_time = 30" "cleanup_delay = 5"
out=$(raise_max_request_time "$F")
if [[ $(active) == "90 " && $out == *"30 -> 90"* ]]; then pass "stock 30 s raised to 90 s"; else fail "30: '$(active)' $out"; fi
# only the top-level line changed: the comment and the indented one stay
if grep -q '^#max_request_time = 10$' "$F" && grep -q '^	max_request_time = 5$' "$F" && grep -q '^cleanup_delay = 5$' "$F"; then
    pass "comments, indented lines and other settings untouched"
else fail "other lines changed:"; cat "$F"; fi
[[ $(stat -c %a "$F") == 640 ]] && pass "file mode kept" || fail "mode now $(stat -c %a "$F")"
# 2. idempotent
cp "$F" "$W/before"
out=$(raise_max_request_time "$F")
if cmp -s "$F" "$W/before" && [[ $out == *"kept"* ]]; then pass "second run changes nothing"; else fail "second run: $out"; fi
# 3. a higher live value is kept (rule 10)
conf "max_request_time = 120"
out=$(raise_max_request_time "$F")
if [[ $(active) == "120 " && $out == *"kept"* ]]; then pass "higher live value 120 kept"; else fail "120: '$(active)' $out"; fi
# 4. with a trailing comment
conf "max_request_time = 30   # stock"
raise_max_request_time "$F" >/dev/null
if grep -q '^max_request_time = 90' "$F"; then pass "value with a trailing comment raised"; else fail "comment case:"; grep -n max_request_time "$F"; fi
# 5. no top-level setting: appended at the end (top level)
conf
out=$(raise_max_request_time "$F")
if [[ $(active) == "90 " && $(tail -n1 "$F") == "max_request_time = 90" ]]; then pass "missing setting appended at top level"; else fail "missing: '$(active)' $out"; fi
# 6. preflight's reader
conf "max_request_time = 30"
[[ $(fr_max_request_time "$F") == 30 ]] && pass "fr_max_request_time reads 30" || fail "reader: '$(fr_max_request_time "$F")'"
[[ -z $(fr_max_request_time "$W/nonexistent") ]] && pass "fr_max_request_time: missing file -> empty" || fail "reader on missing file"
# 7. the shipped default is above every second-factor wait (60 s)
(( RA_FR_MAX_REQUEST_TIME > 60 )) && pass "RA_FR_MAX_REQUEST_TIME ($RA_FR_MAX_REQUEST_TIME) > 60" || fail "RA_FR_MAX_REQUEST_TIME=$RA_FR_MAX_REQUEST_TIME"

echo
if (( fails )); then echo "$fails test(s) FAILED"; exit 1; fi
echo "all max_request_time tests passed"
