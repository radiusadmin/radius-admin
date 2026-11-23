#!/bin/bash
# Build the radius-admin-freeradius package: FreeRADIUS 3.2.10 from the signed upstream
# release, --enable-fips-workaround (one build for standard and FIPS mode), installed under
# /opt/radius-admin-freeradius with its configuration in /etc/freeradius. Build on the
# distribution release you install on (Ubuntu 24.04, Debian 12); the package records it.
# rlm_ldap and libexec/ra-ldapwhoami link a private static OpenLDAP client library built
# against the system OpenSSL from the distribution's openldap source package
# (tools/lib/openldap-build.sh; needs deb-src entries).
#   sudo tools/package/build-freeradius-deb.sh [OUTDIR] [WORKDIR]
#        (defaults: <repo>/packages, /var/tmp/radius-admin-frpkg)
# Writes OUTDIR/radius-admin-freeradius_<version>_<arch>.deb with a .sha384 next to it, and
# the upstream source with its signature in OUTDIR/source/ (GPLv2: ship the source with
# the binaries). FR_PKG_RELEASE=N sets the package revision (default 2: 1 used the
# distribution's GnuTLS libldap).
set -euo pipefail
export LC_ALL=C
# the package's file modes must not depend on the caller (CI runners use a permissive umask)
umask 022
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/fr-release.sh
. "$REPO/tools/lib/fr-release.sh"
# shellcheck source=../lib/openldap-build.sh
. "$REPO/tools/lib/openldap-build.sh"

OUT=${1:-$REPO/packages}
WORK=${2:-/var/tmp/radius-admin-frpkg}
PREFIX=/opt/radius-admin-freeradius
PKG=radius-admin-freeradius
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (the package tree must be owned by root)"

BUILD_DEPS=(build-essential pkg-config dpkg-dev binutils libtalloc-dev libssl-dev libpq-dev
            curl gnupg ca-certificates file python3-apt)
missing=()
for p in "${BUILD_DEPS[@]}"; do
    dpkg-query -W -f '${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p")
done
(( ${#missing[@]} == 0 )) || die "missing build packages: apt-get install ${missing[*]}"

# shellcheck source=/dev/null
. /etc/os-release
DIST=$ID$VERSION_ID
ARCH=$(dpkg --print-architecture)
PKGVER=$FR_VERSION-${FR_PKG_RELEASE:-2}~$DIST
DEB=$OUT/${PKG}_${PKGVER}_$ARCH.deb

fr_fetch_verified "$WORK"
rm -rf "$WORK/build" "$WORK/root"
OLP=$WORK/openldap
ol_build "$WORK" "$OLP"
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
mapfile -t olargs < <(ol_fr_configure_args "$OLP")
cfg+=("${olargs[@]}")
for m in "${without[@]}"; do cfg+=(--without-rlm_"$m"); done
echo "configure ${cfg[*]}"
(cd "$SRCDIR" && ./configure "${cfg[@]}") > "$WORK/configure.log" 2>&1 \
    || { tail -40 "$WORK/configure.log" >&2; die "configure failed (log: $WORK/configure.log)"; }
ol_fr_fix_makefile "$SRCDIR" "$OLP"
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
ol_check_elf "$LIBDIR/rlm_ldap.so"
# the installer's directory login test uses the same library as rlm_ldap (SPEC section 15)
install -D -m 0755 "$OLP/bin/ldapwhoami" "$ROOT$PREFIX/libexec/ra-ldapwhoami"

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
{
    cat "$SRCDIR/COPYRIGHT" "$SRCDIR/LICENSE"
    printf '\n\nOpenLDAP %s client libraries (liblber, libldap), statically linked into\nrlm_ldap.so and libexec/ra-ldapwhoami:\n\n' "$OL_VERSION"
    cat "$OL_SRCDIR/COPYRIGHT" "$OL_SRCDIR/LICENSE"
} > "$DOC/copyright"
cat > "$DOC/SOURCE" <<EOF
FreeRADIUS $FR_VERSION, unmodified upstream release:
  $FR_URL/$FR_TARBALL
  sha256 $(sha256sum "$WORK/$FR_TARBALL" | cut -d' ' -f1)
  signature verified with $FR_KEY_FPR
configure ${cfg[*]}

OpenLDAP client libraries $OL_VERSION (liblber, libldap; static, TLS by the system OpenSSL),
the distribution's source package (apt-get source openldap):
$(for f in "${OL_SRC_FILES[@]}"; do printf '  %s  sha256 %s\n' "${f##*/}" "$(sha256sum "$f" | cut -d' ' -f1)"; done)
configure ${OL_CONFIGURE[*]}
EOF

# Runtime dependencies. First a check that every shared library the binaries link directly
# (NEEDED) belongs to a distribution package; then dpkg-shlibdeps takes the minimum versions from
# those libraries' symbols/shlibs files. Never "at least the version on the build host": a build
# host with newer libraries (GitHub's runner has libpq5 18 from apt.postgresql.org) made a package
# that stock Ubuntu could not install.
declare -A deps=()
elfs=()
while IFS= read -r -d '' f; do
    file -b "$f" | grep -q '^ELF' || continue
    elfs+=("$f")
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
(( ${#deps[@]} > 0 )) || die "no shared library dependencies found"
shl=$WORK/shlibdeps
rm -rf "$shl"; mkdir -p "$shl/debian"
printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "$PKG" "$PKG" > "$shl/debian/control"
depends=$(cd "$shl" && LD_LIBRARY_PATH=$LIBDIR dpkg-shlibdeps -O --ignore-missing-info -l"$LIBDIR" "${elfs[@]}" 2>"$WORK/shlibdeps.log" \
          | sed -n 's/^shlibs:Depends=//p') || true
[[ -n $depends ]] || { cat "$WORK/shlibdeps.log" >&2; die "dpkg-shlibdeps found no dependencies"; }
for p in "${!deps[@]}"; do
    grep -qE "(^|, |\| )$p( |,|$)" <<<"$depends" || die "dpkg-shlibdeps left out $p: $depends"
done
# every versioned dependency must be installable from the distribution's own archive
"$HERE/check-depends.sh" "$depends" || die "Depends needs versions the distribution archive does not have: $depends"
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
 workaround so one build serves standard and FIPS mode. rlm_ldap uses OpenLDAP
 $OL_VERSION built against the system OpenSSL. Installed under
 $PREFIX; the configuration lives in /etc/freeradius, which the
 package creates from the stock configuration only when it does not exist and
 never changes afterwards.
EOF
for s in postinst prerm postrm; do install -m 0755 "$HERE/freeradius/$s" "$ROOT/DEBIAN/$s"; done

chmod -R go-w "$ROOT"
rm -f "$OUT/${PKG}"_*"_$ARCH.deb" "$OUT/${PKG}"_*"_$ARCH.deb.sha384"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$DEB" >/dev/null
(cd "$OUT" && sha384sum "$(basename "$DEB")" > "$(basename "$DEB").sha384")
cp "$WORK/$FR_TARBALL" "$WORK/$FR_TARBALL.sig" "$OUT/source/"
rm -f "$OUT/source/openldap_"*
cp "${OL_SRC_FILES[@]}" "$OUT/source/"
echo "built $DEB"
echo "  Depends: $depends"
