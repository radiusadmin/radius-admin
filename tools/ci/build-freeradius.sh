#!/bin/bash
# Build FreeRADIUS 3.2.10 from the signed upstream release (--enable-fips-workaround) and
# eapol_test from Ubuntu's wpa 2.10 source, for the test bench. Run as root.
#   tools/ci/build-freeradius.sh [PREFIX] [SRCDIR]   (defaults /opt/fr-3.2.10 /opt/ci-src)
# Afterwards: PREFIX/sbin/radiusd, SRCDIR/eapol_test, SRCDIR/freeradius-server-3.2.10 (sources).
set -euo pipefail
V=3.2.10
PREFIX=${1:-/opt/fr-$V}
SRC=${2:-/opt/ci-src}
# packages@freeradius.org release signing key
FPR=BF2384EC6938B9744B03E2A620E37C25995B4F85
mkdir -p "$SRC" && cd "$SRC"

T=freeradius-server-$V.tar.gz
U=https://github.com/FreeRADIUS/freeradius-server/releases/download/release_${V//./_}
[[ -f $T ]] || curl -fsSL -o "$T" "$U/$T"
[[ -f $T.sig ]] || curl -fsSL -o "$T.sig" "$U/$T.sig"
export GNUPGHOME=$SRC/gnupg
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
curl -fsSL https://freeradius.org/pgp/packages@freeradius.org | gpg -q --import 2>/dev/null
gpg --status-fd 1 --verify "$T.sig" "$T" 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG $FPR " \
    || { echo "FreeRADIUS $V: signature does not verify with key $FPR" >&2; exit 1; }
echo "FreeRADIUS $V: signature OK ($FPR)"

if [[ ! -x $PREFIX/sbin/radiusd ]]; then
    rm -rf "freeradius-server-$V"
    tar -xzf "$T"
    (cd "freeradius-server-$V" && ./configure --prefix="$PREFIX" --enable-fips-workaround >../fr-configure.log 2>&1 \
        && make -j"$(nproc)" >../fr-make.log 2>&1 && make install >../fr-install.log 2>&1) \
        || { tail -40 fr-make.log fr-configure.log >&2; exit 1; }
fi
"$PREFIX/sbin/radiusd" -v | head -1

if [[ ! -x $SRC/eapol_test ]]; then
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
    apt-get update -q >/dev/null
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
