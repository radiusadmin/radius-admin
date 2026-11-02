#!/bin/bash
# Build the radius-admin-freeradius package: FreeRADIUS 3.2.10 from the signed upstream
# release, --enable-fips-workaround (one build for standard and FIPS mode), installed under
# /opt/radius-admin-freeradius with its configuration in /etc/freeradius. Build on the
# distribution release you install on (Ubuntu 24.04, Debian 12); the package records it.
#   sudo tools/package/build-freeradius-deb.sh [OUTDIR] [WORKDIR]
#        (defaults: <repo>/packages, /var/tmp/radius-admin-frpkg)
# Writes OUTDIR/radius-admin-freeradius_<version>_<arch>.deb with a .sha384 next to it, and
# the upstream source with its signature in OUTDIR/source/ (GPLv2: ship the source with
# the binaries). FR_PKG_RELEASE=N sets the package revision (default 1).
set -euo pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/fr-release.sh
. "$REPO/tools/lib/fr-release.sh"

OUT=${1:-$REPO/packages}
WORK=${2:-/var/tmp/radius-admin-frpkg}
PREFIX=/opt/radius-admin-freeradius
PKG=radius-admin-freeradius
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (the package tree must be owned by root)"

BUILD_DEPS=(build-essential pkg-config dpkg-dev binutils libtalloc-dev libssl-dev libpq-dev
            libldap-dev curl gnupg ca-certificates file)
missing=()
for p in "${BUILD_DEPS[@]}"; do
    dpkg-query -W -f '${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p")
done
(( ${#missing[@]} == 0 )) || die "missing build packages: apt-get install ${missing[*]}"

# shellcheck source=/dev/null
. /etc/os-release
DIST=$ID$VERSION_ID
ARCH=$(dpkg --print-architecture)
PKGVER=$FR_VERSION-${FR_PKG_RELEASE:-1}~$DIST
DEB=$OUT/${PKG}_${PKGVER}_$ARCH.deb

fr_fetch_verified "$WORK"
rm -rf "$WORK/build" "$WORK/root"
mkdir -p "$WORK/build" "$WORK/root" "$OUT/source"
tar -C "$WORK/build" -xzf "$WORK/$FR_TARBALL"
SRCDIR=$WORK/build/freeradius-server-$FR_VERSION

# Modules that need libraries this product does not use are switched off, so the package
# and its dependencies do not change with whatever -dev packages the build host has.
without=(perl python python3 ruby rest json krb5 pam redis rediswho cache_redis cache_memcached
         kafka unbound couchbase eap_ikev2 eap_tnc sql_mysql sql_sqlite sql_iodbc sql_unixodbc
         sql_oracle sql_freetds sql_cassandra sql_mongo yubikey)
cfg=(--prefix="$PREFIX" --sysconfdir=/etc --localstatedir=/var
     --with-raddbdir=/etc/freeradius --with-logdir=/var/log/freeradius
     --enable-fips-workaround)
for m in "${without[@]}"; do cfg+=(--without-rlm_"$m"); done
echo "configure ${cfg[*]}"
(cd "$SRCDIR" && ./configure "${cfg[@]}") > "$WORK/configure.log" 2>&1 \
    || { tail -40 "$WORK/configure.log" >&2; die "configure failed (log: $WORK/configure.log)"; }
make -C "$SRCDIR" -j"$(nproc)" > "$WORK/make.log" 2>&1 \
    || { tail -40 "$WORK/make.log" >&2; die "make failed (log: $WORK/make.log)"; }
# PACKAGE=…: do not generate the test CA and server certificates into the package
make -C "$SRCDIR" install R="$WORK/root" PACKAGE="$PKG" > "$WORK/install.log" 2>&1 \
    || { tail -40 "$WORK/install.log" >&2; die "make install failed (log: $WORK/install.log)"; }

ROOT=$WORK/root
LIBDIR=$ROOT$PREFIX/lib
for m in rlm_sql_postgresql rlm_ldap rlm_eap rlm_eap_tls rlm_sql rlm_files rlm_pap; do
    [[ -e $LIBDIR/$m.so ]] || die "$m.so was not built (see $WORK/configure.log)"
done

# The stock configuration is shipped as a template; postinst copies it to /etc/freeradius
# only when that does not exist. The package never owns files in /etc.
mv "$ROOT/etc/freeradius" "$ROOT$PREFIX/share/raddb-dist"
sed -i -e 's/^#\(\s*\)user = radius$/\1user = freerad/' -e 's/^#\(\s*\)group = radius$/\1group = freerad/' \
    "$ROOT$PREFIX/share/raddb-dist/radiusd.conf"
grep -qE '^\s*user = freerad$' "$ROOT$PREFIX/share/raddb-dist/radiusd.conf" || die "could not set user = freerad"
rm -rf "${ROOT:?}/etc" "${ROOT:?}/var" "$ROOT$PREFIX/include"
find "$ROOT" \( -name '*.a' -o -name '*.la' \) -delete
while IFS= read -r -d '' f; do
    if file -b "$f" | grep -q '^ELF'; then strip --strip-unneeded "$f"; fi
done < <(find "$ROOT$PREFIX" -type f -print0)

install -D -m 0644 "$HERE/freeradius/freeradius.service" "$ROOT/usr/lib/systemd/system/freeradius.service"
DOC=$ROOT$PREFIX/share/doc/$PKG
install -d "$DOC"
cat "$SRCDIR/COPYRIGHT" "$SRCDIR/LICENSE" > "$DOC/copyright"
cat > "$DOC/SOURCE" <<EOF
FreeRADIUS $FR_VERSION, unmodified upstream release:
  $FR_URL/$FR_TARBALL
  sha256 $(sha256sum "$WORK/$FR_TARBALL" | cut -d' ' -f1)
  signature verified with $FR_KEY_FPR
configure ${cfg[*]}
EOF

# Runtime dependencies: the distribution packages that own the shared libraries the
# binaries link directly (NEEDED), at least the version on the build host.
declare -A deps=()
while IFS= read -r -d '' f; do
    file -b "$f" | grep -q '^ELF' || continue
    needed=$(objdump -p "$f" | awk '$1 == "NEEDED" {print $2}')
    while read -r so lib; do
        [[ $lib == "$ROOT"* ]] && continue
        grep -qxF "$so" <<<"$needed" || continue
        own=$(dpkg -S "$lib" 2>/dev/null || dpkg -S "/usr$lib" 2>/dev/null \
              || dpkg -S "$(realpath "$lib")" 2>/dev/null) || die "no package owns $lib (needed by ${f#"$ROOT"})"
        own=${own%%:*}; own=${own%%,*}
        deps[$own]=1
    done < <(LD_LIBRARY_PATH=$LIBDIR ldd "$f" 2>/dev/null | awk '$2 == "=>" && $3 ~ /^\// {print $1, $3}')
done < <(find "$ROOT$PREFIX" -type f -print0)
depends=""
for p in $(printf '%s\n' "${!deps[@]}" | sort); do
    depends+="${depends:+, }$p (>= $(dpkg-query -W -f '${Version}' "$p"))"
done
depends+=", passwd, systemd"

install -d -m 0755 "$ROOT/DEBIAN"
cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $PKGVER
Architecture: $ARCH
Maintainer: radius-admin <350100412+radiusadmin@users.noreply.github.com>
Section: net
Priority: optional
Depends: $depends
Conflicts: freeradius
Installed-Size: $(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)
Homepage: https://github.com/radiusadmin/radius-admin
Description: FreeRADIUS $FR_VERSION built for radius-admin
 FreeRADIUS $FR_VERSION from the signed upstream release, built with the FIPS
 workaround so one build serves standard and FIPS mode. Installed under
 $PREFIX; the configuration lives in /etc/freeradius, which the
 package creates from the stock configuration only when it does not exist and
 never changes afterwards.
EOF
for s in postinst prerm postrm; do install -m 0755 "$HERE/freeradius/$s" "$ROOT/DEBIAN/$s"; done

rm -f "$OUT/${PKG}"_*"_$ARCH.deb" "$OUT/${PKG}"_*"_$ARCH.deb.sha384"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$DEB" >/dev/null
(cd "$OUT" && sha384sum "$(basename "$DEB")" > "$(basename "$DEB").sha384")
cp "$WORK/$FR_TARBALL" "$WORK/$FR_TARBALL.sig" "$OUT/source/"
echo "built $DEB"
echo "  Depends: $depends"
