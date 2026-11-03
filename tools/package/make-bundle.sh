#!/bin/bash
# Make the release bundle: the committed tree (HEAD) plus the FreeRADIUS package and its
# source from packages/ (tools/package/build-freeradius-deb.sh), as one .tar.gz that
# deploy/update.sh and the Windows push script install.
#   tools/package/make-bundle.sh [--channel main|testing|dev] [OUTDIR]   (default <repo>/dist)
# Writes OUTDIR/radius-admin-<version>.tar.gz and a .sha256 next to it. The bundle carries
# BUILD.json (version, channel, commit, built). With --channel the version comes from
# tools/release/build-version.sh; without it the build is "local" (version from VERSION).
set -euo pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
CHANNEL=""
if [[ ${1:-} == --channel ]]; then CHANNEL=${2:?--channel needs main, testing or dev}; shift 2; fi
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

if [[ -n $CHANNEL ]]; then
    ver=$("$REPO/tools/release/build-version.sh" "$CHANNEL" HEAD)
else
    ver=$(tr -d '[:space:]' < VERSION); CHANNEL=local
fi
name=radius-admin-$ver.tar.gz
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git archive --format=tar --prefix=radius-admin/ HEAD | tar -C "$work" -x
mkdir -p "$work/radius-admin/packages"
cp -a packages/. "$work/radius-admin/packages/"
printf '{"version": "%s", "channel": "%s", "commit": "%s", "built": "%s"}\n' \
    "$ver" "$CHANNEL" "$(git rev-parse HEAD)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$work/radius-admin/BUILD.json"
mkdir -p "$OUT"
tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner -czf "$OUT/$name" radius-admin
(cd "$OUT" && sha256sum "$name" > "$name.sha256")
echo "built $OUT/$name"
echo "  sha256 $(cut -d' ' -f1 "$OUT/$name.sha256")"
