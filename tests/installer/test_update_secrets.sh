#!/bin/bash
# deploy/update.sh: RADIUS client shared secrets sealed at rest (SPEC section 3.2). Before a release
# that cannot read sealed secrets starts (--rollback, or a downgrade), the installed release writes
# them back in plain with `cli unseal-client-secrets`; nothing is installed when that fails.
# Fake releases and a stub interpreter; root (update.sh refuses otherwise); sandbox only.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
UPDATE=$ROOT/deploy/update.sh
[[ $EUID -eq 0 ]] || { echo "run as root (sandbox)"; exit 2; }
W=$(mktemp -d /tmp/ra-updsec.XXXXXX)
chmod 0755 "$W"
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
LOG=$W/calls.log
export RA_UPDATE_BASE=$W/src RA_OPT=$W/opt RA_ETC=$W/etc RA_APP_USER=root RA_PYTHON=$W/python

release() { # release VERSION [seals]: a release dir whose install.sh records its runs
    local d=$RA_UPDATE_BASE/releases/$1
    mkdir -p "$d/deploy" "$d/app/radius_admin"
    printf '#!/bin/bash\necho "install %s $*" >> %s\n' "$1" "$LOG" > "$d/deploy/install.sh"
    chmod 0755 "$d/deploy/install.sh"
    if [[ ${2:-} == seals ]]; then
        printf 'sub.add_parser("seal-client-secrets")\nsub.add_parser("unseal-client-secrets")\n' > "$d/app/radius_admin/cli.py"
    else
        printf 'sub.add_parser("render")\n' > "$d/app/radius_admin/cli.py"
    fi
}
installed() { # installed seals|old: what /opt/radius-admin/app holds
    mkdir -p "$RA_OPT/app/radius_admin"
    if [[ $1 == seals ]]; then cp "$RA_UPDATE_BASE/releases/0.3.1/app/radius_admin/cli.py" "$RA_OPT/app/radius_admin/"
    else printf 'sub.add_parser("render")\n' > "$RA_OPT/app/radius_admin/cli.py"; fi
}
stub() { # stub EXIT_CODE: the interpreter update.sh runs the CLI with
    printf '#!/bin/bash\necho "python $* PYTHONPATH=$PYTHONPATH" >> %s\necho "2 client shared secret(s) written back in plain"\nexit %s\n' \
        "$LOG" "$1" > "$RA_PYTHON"
    chmod 0755 "$RA_PYTHON"
}
reset() { rm -rf "$RA_UPDATE_BASE" "$RA_OPT"; : > "$LOG"; }

# rollback from a sealing release to one that cannot read sealed secrets
reset; release 0.3.0; release 0.3.1 seals; installed seals; stub 0
ln -sfn "$RA_UPDATE_BASE/releases/0.3.1" "$RA_UPDATE_BASE/current"
out=$("$UPDATE" --rollback --yes 2>&1); rc=$?
[[ $rc -eq 0 && $(sed -n 1p "$LOG") == "python -m radius_admin.cli unseal-client-secrets PYTHONPATH=$RA_OPT/app" \
   && $(sed -n 2p "$LOG") == "install 0.3.0 --phase app -y" ]] \
    && pass "a rollback writes the secrets back before the older release's app phase" || fail "rollback: rc=$rc $(cat "$LOG") $out"
[[ $out == *"written back in plain"* && $(readlink -f "$RA_UPDATE_BASE/current") == "$RA_UPDATE_BASE/releases/0.3.0" ]] \
    && pass "the rollback says so and switches the current release" || fail "rollback output: $out"

# the unseal step fails: nothing is installed, the current release stays
reset; release 0.3.0; release 0.3.1 seals; installed seals; stub 1
ln -sfn "$RA_UPDATE_BASE/releases/0.3.1" "$RA_UPDATE_BASE/current"
out=$("$UPDATE" --rollback --yes 2>&1); rc=$?
[[ $rc -ne 0 && $out == *"could not write the client shared secrets back"* ]] && ! grep -q '^install' "$LOG" \
   && [[ $(readlink -f "$RA_UPDATE_BASE/current") == "$RA_UPDATE_BASE/releases/0.3.1" ]] \
    && pass "a failed unseal installs nothing" || fail "failed unseal: rc=$rc $(cat "$LOG") $out"

# rolling back to a release that reads sealed secrets: nothing to write back
reset; release 0.3.1 seals; release 0.3.2 seals; installed seals; stub 0
ln -sfn "$RA_UPDATE_BASE/releases/0.3.2" "$RA_UPDATE_BASE/current"
"$UPDATE" --rollback --yes >/dev/null 2>&1
! grep -q '^python' "$LOG" && grep -q '^install 0.3.1' "$LOG" \
    && pass "a release that reads sealed secrets gets them sealed" || fail "sealing target: $(cat "$LOG")"

# the installed code never sealed anything (an upgrade from 0.3.0 that failed early): nothing to do
reset; release 0.2.9; release 0.3.0; installed old; stub 0
ln -sfn "$RA_UPDATE_BASE/releases/0.3.0" "$RA_UPDATE_BASE/current"
"$UPDATE" --rollback --yes >/dev/null 2>&1
! grep -q '^python' "$LOG" && grep -q '^install 0.2.9' "$LOG" \
    && pass "without sealing code installed nothing is written back" || fail "old install: $(cat "$LOG")"

echo; (( fails == 0 )) && echo "all update secret checks passed" || echo "$fails check(s) FAILED"
exit $(( fails > 0 ))
