# shellcheck shell=bash
# The FreeRADIUS release this project builds, and how to fetch it with a signature check.
# Source only. Used by tools/ci/build-freeradius.sh (bench build) and
# tools/package/build-freeradius-deb.sh (the bundled radius-admin-freeradius package).

FR_VERSION=3.2.10
# packages@freeradius.org release signing key
FR_KEY_FPR=BF2384EC6938B9744B03E2A620E37C25995B4F85
FR_KEY_URL=https://freeradius.org/pgp/packages@freeradius.org
FR_TARBALL=freeradius-server-$FR_VERSION.tar.gz
FR_URL=https://github.com/FreeRADIUS/freeradius-server/releases/download/release_${FR_VERSION//./_}

# fr_fetch_verified DIR : download the release tarball and its signature into DIR (kept if
# already there) and verify the signature against FR_KEY_FPR. Exits on any mismatch.
fr_fetch_verified() {
    local dir=$1
    mkdir -p "$dir"
    [[ -f $dir/$FR_TARBALL ]] || curl -fsSL -o "$dir/$FR_TARBALL" "$FR_URL/$FR_TARBALL"
    [[ -f $dir/$FR_TARBALL.sig ]] || curl -fsSL -o "$dir/$FR_TARBALL.sig" "$FR_URL/$FR_TARBALL.sig"
    local gh=$dir/gnupg
    mkdir -p "$gh" && chmod 700 "$gh"
    curl -fsSL "$FR_KEY_URL" | GNUPGHOME=$gh gpg -q --import 2>/dev/null
    GNUPGHOME=$gh gpg --status-fd 1 --verify "$dir/$FR_TARBALL.sig" "$dir/$FR_TARBALL" 2>/dev/null \
        | grep -q "^\[GNUPG:\] VALIDSIG $FR_KEY_FPR " \
        || { echo "FreeRADIUS $FR_VERSION: signature does not verify with key $FR_KEY_FPR" >&2; exit 1; }
    echo "FreeRADIUS $FR_VERSION: signature OK ($FR_KEY_FPR)"
}
