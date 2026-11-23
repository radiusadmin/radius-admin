# shellcheck shell=bash
# The OpenLDAP client library that rlm_ldap uses, built against the system OpenSSL (SPEC
# section 15). Ubuntu's and Debian's libldap use GnuTLS, outside the OpenSSL FIPS provider;
# this build makes rlm_ldap's LDAPS go through the system OpenSSL instead.
#
# Source: the distribution's own `openldap` source package (apt-get source, checked against the
# archive's signed Release file; the distribution's patches applied), so security fixes arrive
# as distribution updates. Static liblber/libldap with hidden symbols, linked into rlm_ldap.so:
# radiusd also loads the system libldap.so.2 through libpq, and a second shared libldap.so.2
# would clash with it by SONAME and symbol names. No Cyrus SASL (radius-admin binds simply).
# Source only. Used by tools/package/build-freeradius-deb.sh and tools/ci/build-freeradius.sh.

OL_CONFIGURE=(--disable-shared --enable-static --with-pic --with-tls=openssl --without-cyrus-sasl
              --disable-slapd --without-systemd --without-fetch --without-argon2)
# the static archives must not export their symbols from rlm_ldap.so
OL_FR_LDFLAGS="-Wl,--exclude-libs,libldap.a:liblber.a"

_ol_die() { printf 'ERROR: openldap: %s\n' "$*" >&2; exit 1; }

# ol_build WORK PREFIX : fetch the openldap source package into WORK/openldap-src and build the
# static client libraries, their headers and ldapwhoami into PREFIX (lib/, include/,
# bin/ldapwhoami). Sets OL_VERSION (source package version), OL_SRCDIR, OL_SRC_FILES (the .dsc
# and the tarballs it names, for shipping the source). Needs deb-src entries and dpkg-dev.
ol_build() {
    local prefix=$2 src=$1/openldap-src log=$1/openldap-build.log
    [[ -n $(apt-cache showsrc openldap 2>/dev/null) ]] \
        || _ol_die "no source package: enable deb-src for the distribution archive (Ubuntu: 'Types: deb deb-src' in /etc/apt/sources.list.d/ubuntu.sources; Debian: deb-src lines), then apt-get update"
    rm -rf "$src" "$prefix"
    mkdir -p "$src"
    (cd "$src" && apt-get source -q openldap) > "$log" 2>&1 \
        || { tail -20 "$log" >&2; _ol_die "apt-get source openldap failed (log: $log)"; }
    grep -qi 'unauthenticated\|not signed' "$log" && _ol_die "the openldap source was not authenticated by the archive (log: $log)"
    local dsc
    dsc=$(compgen -G "$src/openldap_*.dsc" | head -n1) || true
    [[ -n $dsc ]] || _ol_die "no .dsc after apt-get source"
    OL_VERSION=$(sed -n 's/^Version: //p' "$dsc")
    OL_SRCDIR=$(compgen -G "$src/openldap-*/" | head -n1) || true
    [[ -n $OL_VERSION && -d $OL_SRCDIR ]] || _ol_die "unexpected source layout in $src"
    OL_SRCDIR=${OL_SRCDIR%/}
    OL_SRC_FILES=("$dsc")
    local f
    while read -r f; do OL_SRC_FILES+=("$src/$f"); done \
        < <(awk '/^Files:/{on=1; next} /^[^ ]/{on=0} on && NF == 3 {print $3}' "$dsc")
    echo "openldap $OL_VERSION: source package from the distribution archive"
    (cd "$OL_SRCDIR" && ./configure --prefix="$prefix" "${OL_CONFIGURE[@]}" \
        && make depend && make -j"$(nproc)" -C libraries && make -C clients/tools ldapwhoami \
        && make -C libraries install && make -C include install) >> "$log" 2>&1 \
        || { tail -40 "$log" >&2; _ol_die "build failed (log: $log)"; }
    grep -qx '#define HAVE_OPENSSL 1' "$OL_SRCDIR/include/portable.h" \
        || _ol_die "configure did not select OpenSSL"
    grep -qE '^#define HAVE_(GNUTLS|CYRUS_SASL) 1' "$OL_SRCDIR/include/portable.h" \
        && _ol_die "configure selected GnuTLS or Cyrus SASL"
    install -D -m 0755 "$OL_SRCDIR/clients/tools/ldapwhoami" "$prefix/bin/ldapwhoami"
    [[ -f $prefix/lib/libldap.a && -f $prefix/lib/liblber.a && -f $prefix/include/ldap.h ]] \
        || _ol_die "libraries or headers missing in $prefix"
    # FreeRADIUS' configure links "-L<prefix>/lib -lldap" to find ldap_init; the static libldap.a
    # alone does not resolve (it needs liblber and OpenSSL), and without this the check fell back
    # to the system libldap or, with no libldap-dev, left rlm_ldap out. A linker script named
    # libldap.so pulls in the archives and OpenSSL.
    printf 'GROUP ( %s %s -lssl -lcrypto )\n' "$prefix/lib/libldap.a" "$prefix/lib/liblber.a" > "$prefix/lib/libldap.so"
    ol_check_elf "$prefix/bin/ldapwhoami"
}

# ol_fr_configure_args PREFIX : FreeRADIUS configure arguments for rlm_ldap with this build
ol_fr_configure_args() {
    printf '%s\n' "--with-rlm-ldap-lib-dir=$1/lib" "--with-rlm-ldap-include-dir=$1/include" \
        "LDFLAGS=$OL_FR_LDFLAGS"
}

# ol_fr_fix_makefile FRSRC PREFIX : after FreeRADIUS' configure. Its rlm_ldap makefile says only
# "-lldap" (no -L), which could link the system libldap.so; name the static archives instead.
ol_fr_fix_makefile() {
    local mk=$1/src/modules/rlm_ldap/all.mk prefix=$2
    [[ -f $mk ]] || _ol_die "$mk missing (rlm_ldap not configured?)"
    grep -q "^SRC_CFLAGS.*$prefix/include" "$mk" || _ol_die "rlm_ldap is not configured with $prefix/include"
    grep -q "^TGT_LDLIBS.*-L$prefix/lib" "$mk" \
        || _ol_die "rlm_ldap's configure did not link the private libldap in $prefix/lib ($(grep '^TGT_LDLIBS' "$mk"))"
    sed -i "s#^TGT_LDLIBS.*#TGT_LDLIBS := $prefix/lib/libldap.a $prefix/lib/liblber.a -lssl -lcrypto#" "$mk"
    grep -qx "TGT_LDLIBS := $prefix/lib/libldap.a $prefix/lib/liblber.a -lssl -lcrypto" "$mk" \
        || _ol_die "could not set the rlm_ldap libraries in $mk"
}

# ol_check_elf FILE : FILE (rlm_ldap.so or ldapwhoami) uses the system OpenSSL and no libldap,
# liblber or GnuTLS of its own, and calls no ldap_*/ber_* function from outside itself.
ol_check_elf() {
    local f=$1 needed
    needed=$(objdump -p "$f" | awk '$1 == "NEEDED" {print $2}')
    grep -qx 'libssl.so.3' <<<"$needed" || _ol_die "${f##*/} does not link libssl.so.3: $(tr '\n' ' ' <<<"$needed")"
    grep -qE '^lib(ldap|lber|gnutls)' <<<"$needed" && _ol_die "${f##*/} links $(grep -E '^lib(ldap|lber|gnutls)' <<<"$needed" | tr '\n' ' ')"
    nm -D --undefined-only "$f" | grep -qE ' (ldap|ber)_' \
        && _ol_die "${f##*/} takes ldap_*/ber_* functions from another library"
    # exported: only rlm_ldap's own tables, never the static library's functions
    nm -D --defined-only "$f" | awk '{print $NF}' | grep -E '^(ldap|ber)_' \
        | grep -qvxE 'ldap_scope|ldap_tls_require_cert' \
        && _ol_die "${f##*/} exports libldap/liblber symbols"
    return 0
}
