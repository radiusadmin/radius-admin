#!/bin/bash
# radius-admin rollback: return FreeRADIUS to its pre-install configuration.
#
#   sudo ./deploy/rollback.sh [--tarball /var/backups/radius-admin/freeradius-<ts>.tar.gz] [-y]
#
#  * restores /etc/freeradius from the tarball written by install.sh (freeradius phase).
#    That tarball contains the original mods-available/sql, so FreeRADIUS goes back to
#    the SQLite database /var/lib/freeradius/sqlite/freeradius.db (untouched by install).
#  * validates with radiusd -XC, restarts FreeRADIUS, checks UDP 1812.
#  * stops/disables radius-admin.service, the helper socket and the nginx site,
#    and removes the radius_admin nftables table.
#  * leaves the PostgreSQL database and /etc/radius-admin intact (data is kept).
# Default tarball: the OLDEST freeradius-*.tar.gz (= the state before the first install).
set -euo pipefail
umask 077
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

TARBALL=""
ASSUME_YES=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --tarball) TARBALL=$2; shift 2 ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done
require_root

if [[ -z $TARBALL ]]; then
    TARBALL=$(find "$RA_BACKUP_DIR" -maxdepth 1 -name 'freeradius-*.tar.gz' -printf '%f\n' 2>/dev/null | sort | head -n1)
    [[ -n $TARBALL ]] || die "no backup found in $RA_BACKUP_DIR; pass --tarball"
    TARBALL=$RA_BACKUP_DIR/$TARBALL
fi
[[ -f $TARBALL ]] || die "$TARBALL not found"
tar -tzf "$TARBALL" "${RA_RADDB#/}/radiusd.conf" >/dev/null 2>&1 || die "$TARBALL does not contain ${RA_RADDB#/}/radiusd.conf"

SVC=$(detect_fr_service) || die "FreeRADIUS unit not found"
RADIUSD=$(detect_radiusd "$SVC") || die "radiusd not found"
say "Rollback FreeRADIUS ($SVC, $RADIUSD) to $TARBALL"
say "radius-admin web UI will be stopped and disabled; PostgreSQL data is kept."
if (( ! ASSUME_YES )); then
    read -r -p "Proceed? [y/N] " a || true
    [[ $a == y || $a == Y || $a == yes ]] || die "aborted"
fi

TS=$(date -u +%Y%m%dT%H%M%SZ)
hdr "Stop the web UI"
systemctl disable --now radius-admin.service >/dev/null 2>&1 || true
systemctl disable --now radius-admin-helper.socket >/dev/null 2>&1 || true
ok "radius-admin.service and helper socket stopped/disabled"
if [[ -L /etc/nginx/sites-enabled/radius-admin ]]; then
    rm -f /etc/nginx/sites-enabled/radius-admin
    if nginx -t >/dev/null 2>&1; then systemctl reload nginx 2>/dev/null || true; fi
    ok "nginx site radius-admin disabled (config kept in sites-available)"
fi
systemctl disable --now radius-admin-firewall.service >/dev/null 2>&1 || true
nft delete table inet radius_admin 2>/dev/null || true
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'radius-admin UI'; then
    info "ufw rule 'radius-admin UI' left in place (harmless once nginx no longer listens); remove with: ufw status numbered"
fi

hdr "Restore $RA_RADDB"
SAVE=$RA_BACKUP_DIR/freeradius-before-rollback-$TS.tar.gz
tar -C / --numeric-owner -czpf "$SAVE" "${RA_RADDB#/}"
chmod 0600 "$SAVE"
info "current config saved to $SAVE"
OLD=$RA_RADDB.rolled-back-$TS
mv "$RA_RADDB" "$OLD"
chmod 0700 "$OLD"
tar -C / --numeric-owner -xzpf "$TARBALL"
ok "restored from $TARBALL (replaced tree kept at $OLD, mode 0700)"

if out=$(timeout 90 "$RADIUSD" -XC -d "$RA_RADDB" 2>&1) && grep -q 'appears to be OK' <<<"$out"; then
    ok "radiusd -XC OK"
else
    tail -n 30 <<<"$out" | sed 's/^/    | /'
    die "restored configuration does not validate. The pre-rollback state is in $SAVE / $OLD. Investigate before restarting."
fi

hdr "Restart FreeRADIUS"
systemctl restart "$SVC.service"
for _ in $(seq 1 15); do
    systemctl is-active --quiet "$SVC.service" && ss -H -lun | awk '{print $4}' | grep -q ':1812$' && break
    sleep 1
done
if systemctl is-active --quiet "$SVC.service" && ss -H -lun | awk '{print $4}' | grep -q ':1812$'; then
    ok "$SVC active, UDP 1812 listening"
else
    journalctl -u "$SVC.service" -n 30 --no-pager || true
    die "$SVC did not come up"
fi

hdr "Done"
cat <<EOF
  FreeRADIUS is back on its previous configuration (SQLite).
  Kept: PostgreSQL database 'radius', /etc/radius-admin, /opt/radius-admin, backups in $RA_BACKUP_DIR.
  Note: switch-admin passwords or MAB devices changed in the UI after migration exist only
  in PostgreSQL. Verify with radtest (docs/RUNBOOK.md, "Verify").
  To re-enable the UI later: sudo ./deploy/install.sh --from freeradius
EOF
