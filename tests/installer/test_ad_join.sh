#!/bin/bash
# deploy/ad-join.sh without a domain: argument checks, FIPS refusal, the smb.conf it writes and
# when it may replace an existing one (--print-config / --dry-run change nothing). The join
# itself needs a real domain controller (RUNBOOK §6.9).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
J=$ROOT/deploy/ad-join.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
export RA_CONF=$W/no-config RA_SMB_CONF=$W/smb.conf RA_SMB_DEFAULT=$W/default.conf
run() { bash "$J" "$@" 2>&1; }

out=$(run --realm example.net --print-config)
if grep -qx $'\trealm = EXAMPLE.NET' <<<"$out" && grep -qx $'\tworkgroup = EXAMPLE' <<<"$out" \
    && grep -qx $'\tsecurity = ads' <<<"$out" && grep -qx $'\tntlm auth = mschapv2-and-ntlmv2-only' <<<"$out" \
    && ! grep -qE '^\[(homes|printers|print\$)\]' <<<"$out"; then
    pass "smb.conf: member of the realm, MSCHAPv2 allowed for ntlm_auth, no shares"
else fail "smb.conf: $out"; fi
grep -qx $'\tworkgroup = CORP' <<<"$(run --realm ad.example.net --workgroup corp --print-config)" \
    && pass "--workgroup sets the NetBIOS name" || fail "--workgroup"

for bad in "--realm example" "--realm exa_mple.net" "--realm x;reboot.example.net" \
           "--realm example.net --workgroup TOO-LONG-WORKGROUP" "--realm example.net --workgroup a.b" \
           "--realm example.net --admin a;b"; do
    # shellcheck disable=SC2086
    if run $bad --print-config >"$W/o"; then fail "accepted: $bad"; else pass "refused: $bad ($(tail -1 "$W/o" | cut -c8-70))"; fi
done

printf 'require_fips = true\n' > "$W/fips.conf"
RA_CONF=$W/fips.conf run --realm example.net --dry-run >"$W/o" && fail "FIPS mode accepted" \
    || { grep -q "FIPS mode" "$W/o" && pass "refused in FIPS mode" || fail "FIPS message: $(cat "$W/o")"; }

plan() { run --realm example.net --dry-run "$@" | grep -o 'smb.conf: .*'; }
rm -f "$RA_SMB_CONF"
[[ $(plan) == "smb.conf: write" ]] && pass "no smb.conf: written" || fail "no smb.conf: $(plan)"
printf '[global]\n\tworkgroup = WORKGROUP\n[printers]\n' > "$RA_SMB_DEFAULT"; cp "$RA_SMB_DEFAULT" "$RA_SMB_CONF"
[[ $(plan) == "smb.conf: replace-default" ]] && pass "package default smb.conf: replaced" || fail "default: $(plan)"
run --realm example.net --print-config > "$RA_SMB_CONF"
[[ $(plan) == "smb.conf: update" ]] && pass "own smb.conf: updated" || fail "own: $(plan)"
printf '[global]\n\tworkgroup = OTHER\n[data]\n\tpath = /srv/data\n' > "$RA_SMB_CONF"
run --realm example.net --dry-run >"$W/o" && fail "foreign smb.conf replaced without --replace-smb-conf" \
    || pass "foreign smb.conf: refused ($(tail -1 "$W/o" | cut -c8-70))"
[[ $(plan --replace-smb-conf) == "smb.conf: replace-backup" ]] && pass "foreign smb.conf with --replace-smb-conf: backup and replace" \
    || fail "replace: $(plan --replace-smb-conf)"
grep -q '\[data\]' "$RA_SMB_CONF" && pass "dry run changed nothing" || fail "dry run changed smb.conf"

echo
if (( fails )); then echo "$fails FAILED"; exit 1; fi
echo "ALL AD-JOIN TESTS PASSED"
