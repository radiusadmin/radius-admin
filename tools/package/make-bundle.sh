#!/bin/bash
# Make the release bundle: the committed tree (HEAD) plus the FreeRADIUS package and its
# source from packages/ (tools/package/build-freeradius-deb.sh), as one .tar.gz that
# deploy/update.sh and the Windows push script install.
#   tools/package/make-bundle.sh [OUTDIR]          (default <repo>/dist)
# Writes OUTDIR/radius-admin-<version>.tar.gz and a .sha256 next to it.
set -euo pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=${1:-$REPO/dist}
# shellcheck source=../lib/fr-release.sh
. "$REPO/tools/lib/fr-release.sh"
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

cd "$REPO"
[[ -z $(git status --porcelain --untracked-files=no) ]] \
    || die "uncommitted changes: the bundle is built from HEAD, commit first"
compgen -G "packages/radius-admin-freeradius_*.deb" >/dev/null \
    || die "no FreeRADIUS package in packages/ (run tools/package/build-freeradius-deb.sh first)"
for f in packages/radius-admin-freeradius_*.deb; do
    (cd packages && sha384sum --quiet --strict -c "$(basename "$f").sha384") || die "$f does not match its .sha384"
done
[[ -f packages/source/$FR_TARBALL && -f packages/source/$FR_TARBALL.sig ]] || die "packages/source/ has no FreeRADIUS source tarball"

ver=$(git describe --tags --always)
name=radius-admin-$ver.tar.gz
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git archive --format=tar --prefix=radius-admin/ HEAD | tar -C "$work" -x
mkdir -p "$work/radius-admin/packages"
cp -a packages/. "$work/radius-admin/packages/"
mkdir -p "$OUT"
tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner -czf "$OUT/$name" radius-admin
(cd "$OUT" && sha256sum "$name" > "$name.sha256")
echo "built $OUT/$name"
echo "  sha256 $(cut -d' ' -f1 "$OUT/$name.sha256")"
