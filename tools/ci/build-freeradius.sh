#!/bin/bash
# Build FreeRADIUS 3.2.10 from the signed upstream release (--enable-fips-workaround) and
# eapol_test from Ubuntu's wpa 2.10 source, for the test bench. Run as root. rlm_ldap links the
# same private OpenSSL-based OpenLDAP build as the package (tools/lib/openldap-build.sh); a
# PREFIX built without it (no PREFIX/share/radius-admin-openldap) is rebuilt.
#   tools/ci/build-freeradius.sh [PREFIX] [SRCDIR]   (defaults /opt/fr-3.2.10 /opt/ci-src)
# Afterwards: PREFIX/sbin/radiusd, SRCDIR/eapol_test, SRCDIR/freeradius-server-3.2.10 (sources).
set -euo pipefail
TOOLS=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../lib/fr-release.sh
. "$TOOLS/lib/fr-release.sh"
# shellcheck source=../lib/openldap-build.sh
. "$TOOLS/lib/openldap-build.sh"
V=$FR_VERSION
PREFIX=${1:-/opt/fr-$V}
SRC=${2:-/opt/ci-src}
fr_fetch_verified "$SRC"
cd "$SRC"
T=$FR_TARBALL
MARK=$PREFIX/share/radius-admin-openldap

if [[ ! -x $PREFIX/sbin/radiusd || ! -f $MARK ]]; then
    # deb-src for apt-get source (openldap here, wpa below)
    if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]] && ! grep -q '^Types: deb deb-src$' /etc/apt/sources.list.d/ubuntu.sources; then
        sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
        apt-get update -q >/dev/null
    fi
    OLP=$SRC/openldap
    ol_build "$SRC" "$OLP"
    mapfile -t olargs < <(ol_fr_configure_args "$OLP")
    rm -rf "freeradius-server-$V"
    tar -xzf "$T"
    (cd "freeradius-server-$V" && ./configure --prefix="$PREFIX" --enable-fips-workaround "${olargs[@]}" \
        >../fr-configure.log 2>&1) || { tail -40 fr-configure.log >&2; exit 1; }
    ol_fr_fix_makefile "$SRC/freeradius-server-$V" "$OLP"
    (cd "freeradius-server-$V" && make -j"$(nproc)" >../fr-make.log 2>&1 && make install >../fr-install.log 2>&1) \
        || { tail -40 fr-make.log >&2; exit 1; }
    ol_check_elf "$PREFIX/lib/rlm_ldap.so"
    echo "openldap $OL_VERSION (static, OpenSSL)" > "$MARK"
fi
cat "$MARK"
"$PREFIX/sbin/radiusd" -v | head -1

if [[ ! -x $SRC/eapol_test ]]; then
    if ! grep -q '^Types: deb deb-src$' /etc/apt/sources.list.d/ubuntu.sources; then
        sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
        apt-get update -q >/dev/null
    fi
    rm -rf wpa-src && mkdir wpa-src
    (cd wpa-src && apt-get source -q wpa >../wpa-source.log 2>&1)
    cd wpa-src/wpa-*/wpa_supplicant
    cp defconfig .config
    sed -i 's/^#CONFIG_EAPOL_TEST=y/CONFIG_EAPOL_TEST=y/; s/^CONFIG_CTRL_IFACE_DBUS/#CONFIG_CTRL_IFACE_DBUS/' .config
    grep -q '^CONFIG_EAPOL_TEST=y' .config || echo 'CONFIG_EAPOL_TEST=y' >> .config
    sed -i 's/-Werror//g' Makefile ../src/build.rules 2>/dev/null || true
    make -j"$(nproc)" eapol_test > "$SRC/eapol-make.log" 2>&1 || { tail -40 "$SRC/eapol-make.log" >&2; exit 1; }
    cp eapol_test "$SRC/eapol_test"
fi
echo "eapol_test: $SRC/eapol_test"
