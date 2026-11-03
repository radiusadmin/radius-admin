#!/bin/bash
# Join this server to the Active Directory domain so that FreeRADIUS can check the PEAP-MSCHAPv2
# passwords of directory accounts with Samba's ntlm_auth (SPEC section 21). Run on the console
# as root. The domain administrator's password is asked for by `net ads join` on the terminal;
# this script never sees or stores it.
#
#   sudo ./deploy/ad-join.sh --realm EXAMPLE.NET [--workgroup EXAMPLE] [--admin Administrator]
#   sudo ./deploy/ad-join.sh --status                      join, trust and winbind state
#   ./deploy/ad-join.sh --realm EXAMPLE.NET --print-config  print the smb.conf it would write
#   sudo ./deploy/ad-join.sh --realm EXAMPLE.NET --dry-run  checks only, change nothing
#
# Options:
#   --realm REALM           the AD DNS domain (Kerberos realm), e.g. EXAMPLE.NET
#   --workgroup NAME        the NetBIOS domain name (default: the realm's first label)
#   --admin USER            an account allowed to join computers (default: Administrator)
#   --replace-smb-conf      replace an existing /etc/samba/smb.conf that this script did not
#                           write (a backup is kept); refused otherwise
#
# What it does: installs samba-common-bin and winbind (distribution packages), writes a
# member-only smb.conf (no shares, "ntlm auth = mschapv2-and-ntlmv2-only" so ntlm_auth accepts
# MSCHAPv2), joins with `net ads join`, starts winbind, adds freerad to winbindd_priv and checks
# the trust. Then restart FreeRADIUS and turn on "directory accounts over PEAP" in Settings.
# Refused in FIPS mode (require_fips): MSCHAPv2 uses MD4 and DES.
set -euo pipefail
umask 022
export LC_ALL=C
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

RA_CONF=${RA_CONF:-/etc/radius-admin/radius-admin.conf}
SMB_CONF=${RA_SMB_CONF:-/etc/samba/smb.conf}
SMB_DEFAULT=${RA_SMB_DEFAULT:-/usr/share/samba/smb.conf}   # the Debian package's own copy
MARK="# radius-admin (deploy/ad-join.sh)"
REALM="" WORKGROUP="" ADMIN=Administrator REPLACE=0 MODE=join

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do
    case $1 in
        --realm) REALM=${2:?}; shift 2 ;;
        --workgroup) WORKGROUP=${2:?}; shift 2 ;;
        --admin) ADMIN=${2:?}; shift 2 ;;
        --replace-smb-conf) REPLACE=1; shift ;;
        --print-config) MODE=print; shift ;;
        --dry-run) MODE=dry; shift ;;
        --status) MODE=status; shift ;;
        -h|--help) usage 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage 2 ;;
    esac
done

render_smb_conf() {
    cat <<EOF
$MARK
# Member of $REALM only so that FreeRADIUS can check PEAP-MSCHAPv2 passwords of directory
# accounts with ntlm_auth (winbind). No file or printer shares; smbd is not needed.
[global]
	workgroup = $WORKGROUP
	realm = $REALM
	security = ads
	server role = member server
	kerberos method = secrets and keytab
	ntlm auth = mschapv2-and-ntlmv2-only
	winbind use default domain = yes
	winbind enum users = no
	winbind enum groups = no
	idmap config * : backend = tdb
	idmap config * : range = 100000-199999
	load printers = no
	printcap name = /dev/null
	disable spoolss = yes
	log level = 1
EOF
}

status() {
    local rc=0
    if command -v net >/dev/null 2>&1 && net ads testjoin >/dev/null 2>&1; then ok "joined to the domain (net ads testjoin)"
    else bad "not joined to a domain (net ads testjoin failed or Samba not installed)"; rc=1; fi
    if systemctl is-active --quiet winbind 2>/dev/null; then ok "winbind running"; else bad "winbind not running"; rc=1; fi
    if command -v wbinfo >/dev/null 2>&1 && wbinfo -t >/dev/null 2>&1; then ok "trust with the domain controller works (wbinfo -t)"
    else bad "trust check failed (wbinfo -t)"; rc=1; fi
    if id -nG freerad 2>/dev/null | tr ' ' '\n' | grep -qx winbindd_priv; then ok "freerad is in winbindd_priv"
    else bad "freerad is not in group winbindd_priv (ntlm_auth cannot reach winbind)"; rc=1; fi
    [[ -x /usr/bin/ntlm_auth ]] && ok "/usr/bin/ntlm_auth present" || { bad "/usr/bin/ntlm_auth missing (apt install winbind)"; rc=1; }
    return $rc
}

if [[ $MODE == status ]]; then require_root; status; exit $?; fi

# ---------------------------------------------------------------- checks (all modes)
if [[ -r $RA_CONF ]] && grep -Eiq '^[[:space:]]*require_fips[[:space:]]*=[[:space:]]*(true|yes|1|on)[[:space:]]*$' "$RA_CONF"; then
    die "FIPS mode (require_fips in $RA_CONF): PEAP-MSCHAPv2 uses MD4 and DES and is not available. Use EAP-TTLS with directory accounts instead (RUNBOOK §6.9)."
fi
[[ $REALM =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] \
    || die "--realm must be the AD DNS domain, e.g. EXAMPLE.NET (got '${REALM}')"
REALM=${REALM^^}
[[ -n $WORKGROUP ]] || WORKGROUP=${REALM%%.*}
WORKGROUP=${WORKGROUP^^}
[[ $WORKGROUP =~ ^[A-Z0-9][A-Z0-9-]{0,14}$ ]] || die "--workgroup must be the NetBIOS domain name, 1-15 letters, digits or - (got '$WORKGROUP')"
[[ $ADMIN =~ ^[A-Za-z0-9._@\$-]{1,64}$ ]] || die "--admin must be an account name (letters, digits, . _ @ \$ -)"

if [[ $MODE == print ]]; then render_smb_conf; exit 0; fi

# smb.conf: write ours over nothing, the package default or our own earlier copy; anything
# else may be a configuration someone depends on
smb_action="write"
if [[ -e $SMB_CONF ]]; then
    if grep -qxF "$MARK" "$SMB_CONF"; then smb_action=update
    elif [[ -r $SMB_DEFAULT ]] && cmp -s "$SMB_CONF" "$SMB_DEFAULT"; then smb_action=replace-default
    elif (( REPLACE )); then smb_action=replace-backup
    else die "$SMB_CONF exists and was not written by this script (nor is it the package default). Check what uses it; rerun with --replace-smb-conf to replace it (a backup is kept)."
    fi
fi
say "Joining realm $REALM (workgroup $WORKGROUP) as $ADMIN; smb.conf: $smb_action"
if [[ $MODE == dry ]]; then say "dry run: nothing changed"; exit 0; fi

# ---------------------------------------------------------------- join
require_root
if ! command -v net >/dev/null 2>&1 || ! command -v wbinfo >/dev/null 2>&1 || [[ ! -x /usr/bin/ntlm_auth ]]; then
    info "installing samba-common-bin winbind"
    NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive apt-get install -y -q samba-common-bin winbind >/dev/null
fi
# the package may have just created its default smb.conf
if [[ $smb_action == write && -e $SMB_CONF ]] && [[ -r $SMB_DEFAULT ]] && cmp -s "$SMB_CONF" "$SMB_DEFAULT"; then
    smb_action=replace-default
fi
tmp=$(mktemp)
render_smb_conf > "$tmp"
if [[ $smb_action == replace-backup ]]; then
    cp --preserve=mode,timestamps "$SMB_CONF" "$SMB_CONF.radius-admin-$(date -u +%Y%m%dT%H%M%SZ)"
    info "kept a backup of the previous $SMB_CONF"
fi
install -D -o root -g root -m 0644 "$tmp" "$SMB_CONF"
rm -f "$tmp"
testparm -s "$SMB_CONF" >/dev/null 2>&1 || die "testparm rejects $SMB_CONF"
ok "wrote $SMB_CONF"

if net ads testjoin >/dev/null 2>&1; then
    ok "already joined to $REALM"
else
    say "net ads join asks for the password of $ADMIN (it is not stored):"
    net ads join -U "$ADMIN" || die "net ads join failed (DNS must find the domain controllers of $REALM; check the time too)"
    ok "joined $REALM"
fi
systemctl enable --quiet winbind
systemctl restart winbind
usermod -aG winbindd_priv freerad
ok "freerad added to winbindd_priv"
for _ in $(seq 1 20); do wbinfo -t >/dev/null 2>&1 && break; sleep 1; done
status || die "the join is not usable yet; see the checks above"
say ""
say "Next: restart FreeRADIUS (systemctl restart freeradius) so it gets the new group, check a"
say "login with: ntlm_auth --request-nt-key --username=<user>  (asks for the password), then turn"
say "on Settings -> 802.1X -> directory accounts over PEAP."
