#!/bin/bash
# integrations/duo/remove.sh -- remove the Duo Authentication Proxy that radius-admin installed
# (SPEC section 29.2). Run as root only by radius-admin-integration-install --remove duo, which
# the root helper starts after checking that FreeRADIUS no longer uses the Duo provider.
set -Eeuo pipefail
umask 022
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
DUO_DIR=${RA_DUO_DIR:-/opt/duoauthproxy}
SYSTEMCTL=${RA_SYSTEMCTL:-systemctl}
UNIT_DIR=${RA_SYSTEMD_DIR:-/etc/systemd/system}
die() { echo "duo remove: $*" >&2; exit 1; }

[[ $DUO_DIR == /* && $DUO_DIR != / ]] || die "invalid install directory $DUO_DIR"
[[ -f $DUO_DIR/.radius-admin ]] || die "$DUO_DIR was not installed by radius-admin; nothing removed"
if [[ -f $DUO_DIR/conf/authproxy.cfg ]]; then
    bd=${RA_BACKUP_DIR:-/var/backups/radius-admin}
    b=$bd/duoauthproxy-authproxy.cfg-$(date -u +%Y%m%dT%H%M%SZ)
    install -d -m 0700 "$bd"
    install -m 0600 "$DUO_DIR/conf/authproxy.cfg" "$b"
    echo "configuration kept as $b"
fi
"$SYSTEMCTL" stop duoauthproxy.service 2>/dev/null || true
if [[ -x $DUO_DIR/uninstall ]]; then
    "$DUO_DIR/uninstall" --no-prompt
else
    "$SYSTEMCTL" disable duoauthproxy.service 2>/dev/null || true
    rm -f "$UNIT_DIR/duoauthproxy.service"
    rm -rf "$DUO_DIR"
fi
rm -rf "$UNIT_DIR/duoauthproxy.service.d"
"$SYSTEMCTL" daemon-reload
[[ ! -e $DUO_DIR ]] || rm -f "$DUO_DIR/.radius-admin"
echo "Duo Authentication Proxy removed"
