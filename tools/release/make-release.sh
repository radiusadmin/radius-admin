#!/bin/bash
# Make a signed release from HEAD for an update channel (SPEC section 16). Run by
# .github/workflows/release.yml; works the same in a sandbox with a throwaway key.
#   UPDATE_SIGNING_KEY="$(cat key.pem)" tools/release/make-release.sh CHANNEL OUTDIR [PREV_TAG]
# CHANNEL is main, testing or dev; PREV_TAG the previous release on that channel (if any).
# Needs packages/ (tools/package/build-freeradius-deb.sh) and a clean tree at HEAD.
# Writes OUTDIR/radius-admin-<version>.tar.gz, manifest.json, manifest.json.sig and notes.md,
# and prints the version. The key must be ECDSA P-384 and match deploy/keys/update-signing.pem,
# the public key the servers pin, or nothing is written.
set -euo pipefail
export LC_ALL=C
umask 077
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
die() { printf 'make-release: %s\n' "$*" >&2; exit 1; }

CHANNEL=${1:?usage: make-release.sh CHANNEL OUTDIR [PREV_TAG]}
OUT=${2:?usage: make-release.sh CHANNEL OUTDIR [PREV_TAG]}
PREV=${3:-}
PINNED=$REPO/deploy/keys/update-signing.pem
[[ -n ${UPDATE_SIGNING_KEY:-} ]] || die "UPDATE_SIGNING_KEY is empty"
[[ -s $PINNED ]] || die "$PINNED is missing: commit the public key the servers pin first"
cd "$REPO"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '%s\n' "$UPDATE_SIGNING_KEY" > "$work/key.pem"
openssl pkey -in "$work/key.pem" -noout -text 2>/dev/null | grep -q 'ASN1 OID: secp384r1' \
    || die "the signing key is not an ECDSA P-384 private key"
openssl pkey -in "$work/key.pem" -pubout -out "$work/pub.pem" 2>/dev/null
[[ $(openssl pkey -pubin -in "$work/pub.pem" -outform DER | sha256sum) == \
   $(openssl pkey -pubin -in "$PINNED" -outform DER | sha256sum) ]] \
    || die "the signing key does not match $PINNED (servers could not verify this release)"

ver=$("$HERE/build-version.sh" "$CHANNEL" HEAD)
mkdir -p "$OUT"
"$REPO/tools/package/make-bundle.sh" --channel "$CHANNEL" "$OUT" >&2
bundle=radius-admin-$ver.tar.gz
rm -f "$OUT/$bundle.sha256"

# FreeRADIUS restarts when its configuration or package changed since the previous release
restarts=true
if [[ -n $PREV ]] && git rev-parse -q --verify "$PREV^{commit}" >/dev/null \
    && git diff --quiet "$PREV" HEAD -- freeradius tools/package tools/lib/fr-release.sh; then
    restarts=false
fi
if [[ -n $PREV ]] && git rev-parse -q --verify "$PREV^{commit}" >/dev/null; then
    git log --no-merges --format=%s "$PREV..HEAD" | head -n 100 > "$work/commits"
else
    git log --no-merges --format=%s -n 30 HEAD > "$work/commits"
fi
python3 -I "$HERE/release-notes.py" CHANGELOG.md "$ver" "$work/commits" > "$OUT/notes.md"

python3 -I - "$OUT" "$bundle" "$ver" "$CHANNEL" "$(git rev-parse HEAD)" "$restarts" <<'PY'
import datetime, hashlib, json, os, sys
out, bundle, ver, channel, commit, restarts = sys.argv[1:]
h = hashlib.sha384()
with open(os.path.join(out, bundle), "rb") as fh:
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
with open(os.path.join(out, "notes.md"), encoding="utf-8") as fh:
    notes = fh.read().strip()
manifest = {
    "format": 1, "product": "radius-admin", "version": ver, "channel": channel,
    "commit": commit,
    "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "restarts_freeradius": restarts == "true",
    "bundle": {"name": bundle, "size": os.path.getsize(os.path.join(out, bundle)),
               "sha384": h.hexdigest()},
    "notes": notes,
}
with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=1, sort_keys=True)
    fh.write("\n")
PY
openssl dgst -sha384 -sign "$work/key.pem" -out "$OUT/manifest.json.sig" "$OUT/manifest.json"
openssl dgst -sha384 -verify "$PINNED" -signature "$OUT/manifest.json.sig" "$OUT/manifest.json" >/dev/null \
    || die "the new signature does not verify with $PINNED"
chmod 0644 "$OUT"/*
echo "$ver"
