#!/bin/bash
# integrations/duo/install.sh REQUEST BUILD -- install the Duo Authentication Proxy from a
# checked source build (SPEC section 29.2).
#
# Run as root only by radius-admin-integration-install (deploy/integration-install.sh), which
# checked BUILD against REQUEST (the root helper's request.json) just before. Steps:
#   1. the distribution's build packages (apt, NEEDRESTART_SUSPEND=1)
#   2. extract (Python tarfile "data" filter: no absolute paths, no "..", no links leaving the
#      tree, no device files) and build as the unprivileged user radius-admin-build (plain make:
#      Duo's Makefile is not safe for parallel builds)
#   3. the build tree becomes root-owned and read-only before anything in it runs as root
#   4. Duo's own installer: /opt/duoauthproxy, service user duo_authproxy_svc, log group
#      duo_authproxy_grp, systemd unit (enabled, not started), no SELinux module
#   5. a systemd drop-in that hardens duoauthproxy.service
#   6. /opt/duoauthproxy/.radius-admin records version, SHA-256, check and FIPS mode
#   7. the service starts only once the portal has applied its configuration
set -Eeuo pipefail
umask 022
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

REQ=${1:?usage: install.sh REQUEST BUILD}
BUILD=${2:?usage: install.sh REQUEST BUILD}
DUO_DIR=${RA_DUO_DIR:-/opt/duoauthproxy}
BUILD_USER=${RA_DUO_BUILD_USER:-radius-admin-build}
SYSTEMCTL=${RA_SYSTEMCTL:-systemctl}
UNIT_DIR=${RA_SYSTEMD_DIR:-/etc/systemd/system}
SVC_USER=duo_authproxy_svc
LOG_GROUP=duo_authproxy_grp
PACKAGES=(build-essential libffi-dev zlib1g-dev perl)
die() { echo "duo install: $*" >&2; exit 1; }
field() { python3 -I -c 'import json, sys
d = json.load(open(sys.argv[1]))
v = d.get(sys.argv[2], "")
print(str(v).lower() if isinstance(v, bool) else v)' "$1" "$2"; }

VERSION=$(field "$REQ" version)
[[ $VERSION =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || die "invalid version '$VERSION'"
SRC_NAME=duoauthproxy-$VERSION-src
[[ $DUO_DIR == /* && $DUO_DIR != / ]] || die "invalid install directory $DUO_DIR"

echo "== build packages"
if [[ -z ${RA_DUO_SKIP_PACKAGES:-} ]]; then
    missing=()
    for p in "${PACKAGES[@]}"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p")
    done
    if (( ${#missing[@]} )); then
        echo "installing ${missing[*]}"
        NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${missing[@]}"
    else
        echo "all present"
    fi
fi

echo "== build as $BUILD_USER"
if ! getent passwd "$BUILD_USER" >/dev/null; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$BUILD_USER"
fi
B=$(mktemp -d /var/tmp/radius-admin-duo.XXXXXX)
trap 'rm -rf "$B"' EXIT
install -m 0644 "$BUILD" "$B/src.tgz"
install -d -o "$BUILD_USER" -m 0700 "$B/work"
chmod 0755 "$B"
runuser -u "$BUILD_USER" -- env -i PATH="$PATH" LC_ALL=C python3 -I - "$B/src.tgz" "$B/work" "$SRC_NAME" <<'PY'
import sys, tarfile
src, dst, top = sys.argv[1:]
with tarfile.open(src, "r:gz") as tf:
    names = tf.getnames()
    if not names or any(n != top and not n.startswith(top + "/") for n in names):
        sys.exit("the archive does not contain only %s/" % top)
    tf.extractall(dst, filter="data")
PY
S=$B/work/$SRC_NAME
[[ -f $S/Makefile ]] || die "no Makefile in $SRC_NAME"
runuser -u "$BUILD_USER" -- env -i PATH="$PATH" LC_ALL=C HOME="$B/work" \
    make -C "$S" >"$B/make.log" 2>&1 || { tail -n 40 "$B/make.log"; die "the build failed"; }
tail -n 5 "$B/make.log"
[[ -f $S/duoauthproxy-build/install ]] || die "the build produced no installer"
# from here on everything runs as root: nothing the build user can still change
chown -R root:root "$B/work"
chmod -R go-w "$B/work"

echo "== install into $DUO_DIR"
was_active=no
if "$SYSTEMCTL" is-active --quiet duoauthproxy.service 2>/dev/null; then
    was_active=yes
    "$SYSTEMCTL" stop duoauthproxy.service
fi
"$S/duoauthproxy-build/install" --install-dir "$DUO_DIR" --service-user "$SVC_USER" \
    --log-group "$LOG_GROUP" --create-init-script yes --enable-selinux no --silent

echo "== systemd drop-in"
install -d -m 0755 "$UNIT_DIR/duoauthproxy.service.d"
cat > "$UNIT_DIR/duoauthproxy.service.d/radius-admin.conf" <<EOF
# radius-admin (integrations/duo/install.sh): hardening for the Duo Authentication Proxy.
# It starts as root (twistd) and runs as $SVC_USER; it writes only its log and run directories.
[Service]
ProtectSystem=strict
ReadWritePaths=$DUO_DIR/log $DUO_DIR/run $DUO_DIR/conf -/etc/duoauthproxy
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
EOF
chmod 0644 "$UNIT_DIR/duoauthproxy.service.d/radius-admin.conf"
"$SYSTEMCTL" daemon-reload

echo "== record"
python3 -I - "$REQ" "$DUO_DIR/.radius-admin" <<'PY'
import datetime, json, os, sys
req = json.load(open(sys.argv[1]))
info = {k: req.get(k) for k in ("version", "sha256", "verified", "fips")}
info["installed"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
tmp = sys.argv[2] + ".tmp"
with open(tmp, "w") as fh:
    json.dump(info, fh, sort_keys=True)
os.chmod(tmp, 0o644)
os.replace(tmp, sys.argv[2])
PY

# The proxy starts with a configuration from the portal (first line "; radius-admin"),
# never with Duo's sample file.
if head -n 1 "$DUO_DIR/conf/authproxy.cfg" 2>/dev/null | grep -q '^; radius-admin'; then
    echo "== starting duoauthproxy with the applied configuration"
    "$SYSTEMCTL" restart duoauthproxy.service
else
    "$SYSTEMCTL" stop duoauthproxy.service 2>/dev/null || true
    echo "duoauthproxy is installed and enabled; it starts once its configuration is applied"
    [[ $was_active == yes ]] && echo "note: it was running before and is now stopped"
fi
echo "Duo Authentication Proxy $VERSION installed in $DUO_DIR"
