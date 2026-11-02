#!/bin/bash
# The bundled radius-admin-freeradius package (tools/package/build-freeradius-deb.sh).
#   tests/package/test_freeradius_deb.sh [DEB] [--install]
# DEB defaults to the one in packages/ for this system. Without --install only the package
# file is inspected. --install also installs it through install.sh --phase fr-package,
# starts radiusd with throwaway certificates and purges it again: sandbox only, as root;
# refuses when FreeRADIUS or /etc/freeradius exists that this test did not create.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# shellcheck source=../../deploy/lib.sh
. "$ROOT/deploy/lib.sh"
# shellcheck source=../../tools/lib/fr-release.sh
. "$ROOT/tools/lib/fr-release.sh"
DEB="" INSTALL=0
for a in "$@"; do
    case $a in
        --install) INSTALL=1 ;;
        *) DEB=$a ;;
    esac
done
[[ -n $DEB ]] || DEB=$(detect_bundled_fr "$ROOT/packages" || true)
[[ -n $DEB && -f $DEB ]] || { echo "no package (build one with tools/package/build-freeradius-deb.sh)"; exit 2; }
DEB=$(realpath "$DEB")
P=/opt/radius-admin-freeradius
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
field() { dpkg-deb -f "$DEB" "$1"; }

# ------------------------------------------------------------------ the package file
(cd "$(dirname "$DEB")" && sha384sum --quiet --strict -c "$(basename "$DEB").sha384" 2>/dev/null) \
    && pass "SHA-384 file matches" || fail "SHA-384 file missing or wrong"
[[ $(field Package) == radius-admin-freeradius && $(field Version) == "$FR_VERSION"-* ]] \
    && pass "name and version ($(field Version))" || fail "control: $(field Package) $(field Version)"
grep -qw freeradius <<<"$(field Conflicts)" && pass "conflicts with the distribution freeradius" \
    || fail "no Conflicts: freeradius"
dep=$(field Depends)
missing=""
for d in libpq5 libssl3 libtalloc2 libldap; do grep -q "$d" <<<"$dep" || missing+=" $d"; done
[[ -z $missing ]] && pass "depends on the distribution libraries" || fail "Depends lacks$missing: $dep"
dpkg-deb -c "$DEB" | awk '{print $6}' > "$W/files"
grep -q '^\./etc/' "$W/files" && fail "package ships files in /etc: $(grep '^\./etc/' "$W/files" | head -3 | tr '\n' ' ')" \
    || pass "no files in /etc (the configuration is never package-owned)"
missing=""
for f in sbin/radiusd bin/radclient lib/rlm_sql_postgresql.so lib/rlm_ldap.so lib/rlm_eap_tls.so \
         share/freeradius/dictionary share/raddb-dist/radiusd.conf share/doc/radius-admin-freeradius/SOURCE; do
    grep -qx "\.$P/$f" "$W/files" || missing+=" $f"
done
grep -qx './usr/lib/systemd/system/freeradius.service' "$W/files" || missing+=" freeradius.service"
[[ -z $missing ]] && pass "radiusd, radclient, modules, dictionaries, unit and source note present" \
    || fail "missing:$missing"
grep -E 'raddb-dist/certs/[^/]+\.(key|pem|p12)$' "$W/files" >/dev/null \
    && fail "test certificates or keys in the package" || pass "no certificates or keys in the package"
dpkg-deb -x "$DEB" "$W/x"
dpkg-deb -e "$DEB" "$W/ctl"
grep -qE '^\s*user = freerad$' "$W/x$P/share/raddb-dist/radiusd.conf" \
    && grep -qE '^\s*group = freerad$' "$W/x$P/share/raddb-dist/radiusd.conf" \
    && pass "stock radiusd.conf drops to freerad" || fail "radiusd.conf user/group not freerad"
grep -qx "ExecStart=$P/sbin/radiusd -f \$FREERADIUS_OPTIONS" "$W/x/usr/lib/systemd/system/freeradius.service" \
    && ! grep -q '^User=' "$W/x/usr/lib/systemd/system/freeradius.service" \
    && pass "unit starts the packaged radiusd as root (it drops privileges itself)" || fail "unit ExecStart/User"
grep -q "$FR_KEY_FPR" "$W/x$P/share/doc/radius-admin-freeradius/SOURCE" 2>/dev/null \
    && pass "source note names the upstream signing key" || fail "SOURCE note"
ok_sh=1
for s in postinst prerm postrm; do sh -n "$W/ctl/$s" || ok_sh=0; done
(( ok_sh )) && pass "maintainer scripts parse" || fail "maintainer script syntax"
grep -v '^\s*#' "$W/ctl/postinst" | grep -qE 'systemctl +(re)?start|systemctl +enable' && fail "postinst starts or restarts radiusd" \
    || pass "postinst never starts radiusd"

if (( ! INSTALL )); then
    echo; (( fails == 0 )) && echo "all package checks passed" || echo "$fails check(s) FAILED"
    exit $(( fails > 0 ))
fi

# ------------------------------------------------------------------ install (sandbox)
[[ $EUID -eq 0 ]] || { echo "--install: run as root (sandbox)"; exit 2; }
pkg_installed() { dpkg-query -W -f '${Status}' radius-admin-freeradius 2>/dev/null | grep -q 'install ok installed'; }
if ! pkg_installed; then
    [[ -e /etc/freeradius ]] && { echo "/etc/freeradius exists: refusing (sandbox only)"; exit 2; }
    detect_fr_service >/dev/null && { echo "a FreeRADIUS service exists: refusing (sandbox only)"; exit 2; }
fi
DEBIAN_FRONTEND=noninteractive apt-get purge -y -q radius-admin-freeradius >/dev/null 2>&1
rm -rf /etc/freeradius
trap 'systemctl stop freeradius 2>/dev/null; DEBIAN_FRONTEND=noninteractive apt-get purge -y -q radius-admin-freeradius >/dev/null 2>&1; rm -rf /etc/freeradius "$W"' EXIT
INST() { "$ROOT/deploy/install.sh" --phase fr-package -y "$@"; }

out=$(INST --freeradius-deb "$DEB" 2>&1)
if [[ $? -eq 0 ]] && pkg_installed && [[ -f /etc/freeradius/radiusd.conf ]]; then
    pass "install.sh fr-package installs the package and the stock configuration"
else fail "fr-package install: $out"; fi
[[ $(stat -c '%U:%G %a' /etc/freeradius) == "root:freerad 750" && $(stat -c '%U:%G' /var/log/freeradius) == freerad:freerad ]] \
    && pass "/etc/freeradius root:freerad 0750, log directory owned by freerad" \
    || fail "ownership: $(stat -c '%U:%G %a' /etc/freeradius) $(stat -c '%U:%G' /var/log/freeradius)"
! systemctl is-active --quiet freeradius && ! systemctl is-enabled --quiet freeradius \
    && pass "radiusd neither started nor enabled by the package" || fail "service started/enabled on install"
svc=$(detect_fr_service || true); rd=$(detect_radiusd "$svc" || true); lib=$(detect_fr_libdir "$rd" || true)
[[ $svc == freeradius && $rd == $P/sbin/radiusd && -e $lib/rlm_sql_postgresql.so ]] \
    && pass "installer detection finds service, radiusd and modules" || fail "detection: $svc $rd $lib"
v=$("$P/sbin/radiusd" -v 2>/dev/null)
grep -q "^radiusd: FreeRADIUS Version $FR_VERSION," <<<"$v" \
    && pass "radiusd reports $FR_VERSION" || fail "radiusd -v"

out=$(INST --freeradius-deb "$DEB" 2>&1)
[[ $? -eq 0 ]] && grep -q 'radius-admin-freeradius .* is installed' <<<"$out" && ! grep -q 'Unpacking' <<<"$out" \
    && pass "second run is a no-op" || fail "second run: $out"

echo '# live setting kept by the package' >> /etc/freeradius/clients.conf
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --reinstall "$DEB" >/dev/null 2>&1
grep -q 'live setting kept by the package' /etc/freeradius/clients.conf \
    && pass "reinstall keeps an existing /etc/freeradius" || fail "reinstall changed /etc/freeradius"

cp "$DEB" "$W/"
echo "0000  $(basename "$DEB")" > "$W/$(basename "$DEB").sha384"
out=$(INST --freeradius-deb "$W/$(basename "$DEB")" 2>&1)
[[ $? -ne 0 ]] && grep -q 'does not match' <<<"$out" \
    && pass "a package that does not match its SHA-384 file is refused" || fail "bad checksum accepted: $out"
rm -f "$W/$(basename "$DEB").sha384"
out=$(INST --freeradius-deb "$W/$(basename "$DEB")" 2>&1)
[[ $? -ne 0 ]] && grep -q 'checksum file missing' <<<"$out" \
    && pass "a package without a SHA-384 file is refused" || fail "missing checksum accepted: $out"

# throwaway test CA from the stock bootstrap, then a real start
(cd /etc/freeradius/certs && ./bootstrap >/dev/null 2>&1)
chgrp -R freerad /etc/freeradius/certs; chmod -R g+r /etc/freeradius/certs
systemctl start freeradius
up=0
for _ in $(seq 1 15); do
    ss -H -lun | awk '{print $4}' | grep -q ':1812$' && { up=1; break; }
    sleep 1
done
(( up )) && [[ $(ps -o user= -C radiusd | head -n1) == freerad ]] \
    && pass "service starts, listens on UDP 1812 and runs as freerad" \
    || fail "service: $(systemctl is-active freeradius) $(journalctl -u freeradius -n 5 --no-pager 2>&1 | tail -3)"
r=$(echo 'User-Name = "nobody",User-Password = "x"' | "$P/bin/radclient" -r 1 -t 3 127.0.0.1 auth testing123 2>&1)
grep -q 'Received Access-Reject' <<<"$r" && pass "radclient gets an answer from the packaged radiusd" || fail "radclient: $r"

# a newer bundled package: upgraded, but the running radiusd is left alone
pid=$(pgrep -x radiusd | head -n1)
dpkg-deb -R "$DEB" "$W/up"
sed -i "s/^Version: .*/Version: $(field Version | sed 's/-\([0-9]*\)~/-\1+up1~/')/" "$W/up/DEBIAN/control"
UP=$W/$(basename "$DEB" .deb | sed 's/-\([0-9]*\)~/-\1+up1~/').deb
dpkg-deb --root-owner-group -Zxz --build "$W/up" "$UP" >/dev/null
(cd "$W" && sha384sum "$(basename "$UP")" > "$(basename "$UP").sha384")
out=$(INST --freeradius-deb "$UP" 2>&1)
[[ $? -eq 0 ]] && grep -q '(was ' <<<"$out" && grep -q 'FreeRADIUS still runs' <<<"$out" \
    && [[ $(pgrep -x radiusd | head -n1) == "$pid" ]] && grep -q 'live setting kept' /etc/freeradius/clients.conf \
    && pass "upgrade installs the newer package, keeps the configuration and does not restart radiusd" \
    || fail "upgrade: $out"

DEBIAN_FRONTEND=noninteractive apt-get purge -y -q radius-admin-freeradius >/dev/null 2>&1
! pgrep -x radiusd >/dev/null && [[ ! -e $P/sbin/radiusd && -f /etc/freeradius/radiusd.conf ]] \
    && pass "purge stops radiusd, removes the binaries and keeps /etc/freeradius" || fail "purge"

echo; (( fails == 0 )) && echo "all package checks passed" || echo "$fails check(s) FAILED"
exit $(( fails > 0 ))
