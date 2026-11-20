#!/bin/bash
# radius-admin-integration-install ID -- install a checked second-factor provider build
# (SPEC section 29).
#
# Started only by the root helper (systemctl start radius-admin-integration-install@ID),
# after the helper copied the build into its own root-only directory and checked it against
# the signed catalog (or, in standard mode, against the SHA-256 the admin entered). This
# script reads nothing else from outside root-owned paths:
#   1. checks the copy against the helper's request.json again (SHA-256, size, provider)
#   2. runs the provider's installer from this release, <opt>/integrations/<ID>/install.sh
#      (root-owned), with request.json and the build
#   3. records the outcome in the helper's integration-state.json
# The full log goes to /var/log/radius-admin/integration-<ID>-<time>.log.
set -Eeuo pipefail
umask 077
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

ID=${1:-}
[[ $ID =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "invalid integration '$ID'" >&2; exit 2; }
HW=${RA_HELPER_WORK:-/var/lib/radius-admin-helper}
OPT=${RA_OPT:-/opt/radius-admin}
LOGDIR=${RA_INTEGRATION_LOG_DIR:-/var/log/radius-admin}
W=$HW/integration/$ID
STATE=$HW/integration-state.json
TS=$(date -u +%Y%m%dT%H%M%SZ)
install -d -o root -g adm -m 0750 "$LOGDIR"
LOG=$LOGDIR/integration-$ID-$TS.log
exec > >(tee -a "$LOG") 2>&1

state() { # state KEY=VALUE... : merge into integration-state.json[ID] (atomic, root 0600)
    python3 -I - "$STATE" "$ID" "$@" <<'PY'
import datetime, json, os, sys, tempfile
path, pid = sys.argv[1], sys.argv[2]
try:
    with open(path) as fh:
        st = json.load(fh)
except (OSError, ValueError):
    st = {}
if not isinstance(st, dict):
    st = {}
s = st.get(pid) if isinstance(st.get(pid), dict) else {}
for kv in sys.argv[3:]:
    k, v = kv.split("=", 1)
    s[k] = v
now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
s["updated"] = now
if s.get("state") in ("done", "failed"):
    s["finished"] = now
st[pid] = s
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".integration-state.")
with os.fdopen(fd, "w") as fh:
    json.dump(st, fh, sort_keys=True)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
}
field() { # field FILE KEY : print a JSON value
    python3 -I -c 'import json, sys
d = json.load(open(sys.argv[1]))
print(d.get(sys.argv[2], "") if isinstance(d, dict) else "")' "$1" "$2"
}
finish() { # finish STATE MESSAGE
    state "state=$1" "message=$2"
    echo "== $1: $2"
    rm -rf "$W"
    if [[ $1 == "done" ]]; then exit 0; fi
    exit 1
}
trap 'finish failed "unexpected error (line $LINENO); see $LOG"' ERR

state state=installing "message=checking the copy" "log=$LOG" "started=$TS"
echo "radius-admin integration install: $ID ($(date -u))"
REQ=$W/request.json
[[ -f $REQ && ! -L $REQ ]] || finish failed "the checked copy is missing"
[[ $(field "$REQ" id) == "$ID" ]] || finish failed "the checked copy is for another integration"
FILE=$(field "$REQ" file)
VERSION=$(field "$REQ" version)
[[ $FILE =~ ^[A-Za-z0-9._-]{1,100}$ && -f $W/$FILE && ! -L $W/$FILE ]] || finish failed "the checked build is missing"
[[ $(sha256sum "$W/$FILE" | cut -d' ' -f1) == "$(field "$REQ" sha256)" ]] \
    || finish failed "the copy no longer matches the SHA-256 the helper checked"
[[ $(stat -c %s "$W/$FILE") == "$(field "$REQ" size)" ]] || finish failed "the copy has another size than checked"
echo "build $FILE ($VERSION), $(field "$REQ" verified), SHA-256 $(field "$REQ" sha256)"

INSTALLER=$OPT/integrations/$ID/install.sh
if [[ ! -f $INSTALLER || -L $INSTALLER ]]; then
    finish failed "this release has no installer for $ID"
fi
[[ $(stat -c %u "$INSTALLER") == 0 && $(( 0$(stat -c %a "$INSTALLER") & 022 )) == 0 ]] \
    || finish failed "$INSTALLER must be owned by root and writable only by root"
state "message=installing $VERSION"
if bash "$INSTALLER" "$REQ" "$W/$FILE"; then
    finish "done" "installed $VERSION"
fi
finish failed "the installer for $ID failed; see $LOG"
