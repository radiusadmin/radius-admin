#!/bin/bash
# radius-admin-update-install VERSION -- install a verified update (SPEC section 16).
#
# Started only by the root helper (systemctl start radius-admin-update-install@VERSION),
# after the helper verified the signed manifest and copied manifest and bundle into its
# own root-only directory. This script reads nothing else from outside root-owned paths.
#   1. checks the copy against the manifest again (SHA-384)
#   2. backs up the database (pg_dump) and notes the current release
#   3. runs the bundle's deploy/update.sh; when the release restarts FreeRADIUS, also its
#      freeradius phase with --restart-freeradius (that phase restores its own backup if
#      FreeRADIUS does not come back)
#   4. health checks: web portal answering, helper socket, nginx active and listening on
#      TCP 443 (when the portal's nginx site is enabled), FreeRADIUS active and listening,
#      the installed BUILD.json names VERSION
#   5. on failure: puts the previous release back (update.sh --rollback)
# Progress goes to the helper's update-state.json; the full log to /var/log/radius-admin.
set -Eeuo pipefail
umask 077
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

V=${1:-}
[[ $V =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(dev|rc)\.[0-9]{1,6})?$ ]] || { echo "invalid version '$V'" >&2; exit 2; }
HW=${RA_HELPER_WORK:-/var/lib/radius-admin-helper}
W=$HW/update/$V
STATE=$HW/update-state.json
BASE=/opt/radius-admin-src
OPT=/opt/radius-admin
BACKUPS=${RA_BACKUP_DIR:-/var/backups/radius-admin}
TS=$(date -u +%Y%m%dT%H%M%SZ)
install -d -o root -g adm -m 0750 /var/log/radius-admin
LOG=/var/log/radius-admin/update-$V-$TS.log
exec > >(tee -a "$LOG") 2>&1

state() { # state KEY=VALUE... : merge into update-state.json (atomic, root 0600)
    python3 -I - "$STATE" "$@" <<'PY'
import datetime, json, os, sys, tempfile
path = sys.argv[1]
try:
    with open(path) as fh:
        st = json.load(fh)
except (OSError, ValueError):
    st = {}
for kv in sys.argv[2:]:
    k, v = kv.split("=", 1)
    st[k] = v
now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
st["updated"] = now
if st.get("state") in ("done", "failed", "rolled_back"):
    st["finished"] = now
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".update-state.")
with os.fdopen(fd, "w") as fh:
    json.dump(st, fh, sort_keys=True)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
}
field() { # field FILE KEY[.KEY] : print a JSON value
    python3 -I -c 'import functools, json, sys
d = json.load(open(sys.argv[1]))
print(functools.reduce(lambda v, k: v.get(k, "") if isinstance(v, dict) else "", sys.argv[2].split("."), d))' "$1" "$2"
}
audit() { # audit RESULT MESSAGE : record the outcome in the portal's audit log
    runuser -u radius-admin -- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
        RADIUS_ADMIN_CONFIG=/etc/radius-admin/radius-admin.conf PYTHONPATH=$OPT/app PYTHONDONTWRITEBYTECODE=1 \
        python3 -m radius_admin.cli record-update --version "$V" --from "${FROM:-}" \
        --result "$1" --message "$2" --actor "${ACTOR:-}" || echo "warning: could not write the audit record"
}
finish() { # finish STATE MESSAGE
    state "state=$1" "message=$2"
    audit "$1" "$2"
    echo "== $1: $2"
    rm -rf "$W"
    if [[ $1 == "done" ]]; then exit 0; fi
    exit 1
}
trap 'finish failed "unexpected error (line $LINENO); see $LOG"' ERR

FROM=$(field "$STATE" from)
ACTOR=$(field "$STATE" actor)
state state=installing "message=checking the verified copy" "log=$LOG" "started=$TS"
echo "radius-admin update ${FROM:-?} -> $V ($(date -u))"
[[ -f $W/manifest.json && -f $W/bundle.tar.gz ]] || finish failed "the verified copy is missing"
[[ $(field "$W/manifest.json" version) == "$V" ]] || finish failed "the verified manifest is for another version"
[[ $(sha384sum "$W/bundle.tar.gz" | cut -d' ' -f1) == "$(field "$W/manifest.json" bundle.sha384)" ]] \
    || finish failed "the verified copy no longer matches its manifest"
restarts=$(field "$W/manifest.json" restarts_freeradius)

state "message=backing up the database"
install -d -o root -g root -m 0700 "$BACKUPS"
dump=$BACKUPS/radius-db-before-$V-$TS.dump
if ! runuser -u postgres -- pg_dump -Fc radius > "$dump"; then
    rm -f "$dump"; finish failed "database backup failed; nothing installed"
fi
chmod 0600 "$dump"
mapfile -t olddumps < <(ls -1t "$BACKUPS"/radius-db-before-*.dump 2>/dev/null | tail -n +6)
if (( ${#olddumps[@]} )); then rm -f "${olddumps[@]}"; fi
prev=$(readlink -f "$BASE/current" 2>/dev/null || true)

state "message=installing"
upd=$(mktemp)
tar -xzOf "$W/bundle.tar.gz" radius-admin/deploy/update.sh > "$upd"
args=(--package "$W/bundle.tar.gz" --sha256 "$(sha256sum "$W/bundle.tar.gz" | cut -d' ' -f1)" --yes --keep-upload)
if [[ $restarts == True ]]; then args+=(--with-freeradius -- --restart-freeradius); fi
trap - ERR
if ! bash "$upd" "${args[@]}"; then
    rm -f "$upd"
    # update.sh did not switch the current release; re-run its app phase so the portal
    # matches it again in case the new app phase stopped half-way
    if [[ -n $prev && -x $prev/deploy/install.sh ]]; then
        "$prev/deploy/install.sh" --phase app -y || true
    fi
    finish failed "the installer reported an error; the previous release stays current (log $LOG)"
fi
rm -f "$upd"

state "message=checking the new release"
NGINX_SITE=/etc/nginx/sites-enabled/radius-admin
portal_healthy() { # nginx serves the portal: active and listening on TCP 443 (if its site is enabled)
    [[ -e $NGINX_SITE || -L $NGINX_SITE ]] || return 0
    systemctl is-active --quiet nginx.service || { echo "health: nginx (the web portal) is not active"; return 1; }
    ss -H -ltn | awk '{print $4}' | grep -q ':443$' || { echo "health: nginx is not listening on TCP 443"; return 1; }
}
healthy() {
    systemctl is-active --quiet radius-admin.service || { echo "health: radius-admin.service is not active"; return 1; }
    systemctl is-active --quiet radius-admin-helper.socket || { echo "health: helper socket is not active"; return 1; }
    python3 -I - <<'PY' || { echo "health: the portal does not answer"; return 1; }
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect("/run/radius-admin/app.sock")
s.sendall(b"GET /login HTTP/1.0\r\nHost: localhost\r\n\r\n")
sys.exit(0 if s.recv(64).split(b" ")[1:2] in ([b"200"], [b"302"], [b"303"]) else 1)
PY
    portal_healthy || return 1
    if [[ $restarts == True ]]; then
        systemctl is-active --quiet freeradius.service || { echo "health: FreeRADIUS is not active"; return 1; }
        ss -H -lun | awk '{print $4}' | grep -q ':1812$' || { echo "health: FreeRADIUS is not listening on 1812"; return 1; }
    fi
    [[ $(field "$OPT/BUILD.json" version) == "$V" ]] || { echo "health: $OPT/BUILD.json does not name $V"; return 1; }
}
ok=0
for _ in $(seq 1 12); do
    if healthy; then ok=1; break; fi
    sleep 5
done
if (( ok )); then
    finish "done" "updated from ${FROM:-?} to $V"
fi
if [[ -n $prev ]] && [[ $(readlink -f "$BASE/current") != "$prev" ]]; then
    if "$BASE/current/deploy/update.sh" --rollback --yes; then
        finish rolled_back "the new release failed its health checks; rolled back to the previous release (log $LOG)"
    fi
fi
finish failed "the new release failed its health checks and could not be rolled back automatically (log $LOG)"
