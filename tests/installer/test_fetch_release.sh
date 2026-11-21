#!/bin/bash
# A full install from a git checkout downloads the signed release of the checkout's VERSION,
# verifies it and continues with that release's installer (install.sh, fetch_release in
# deploy/lib.sh). Uses a throwaway signing key, a fake release served from file:// and a stub
# installer inside the fake bundle: nothing is installed. Root only (install.sh requires it).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
[[ $EUID -eq 0 ]] || { echo "run as root (sandbox)"; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
V=9.8.7

# --- a checkout of version $V whose pinned update key is a throwaway P-384 key
CO=$W/checkout
mkdir -p "$CO"
cp -r "$ROOT/deploy" "$CO/deploy"
echo "$V" > "$CO/VERSION"
openssl ecparam -name secp384r1 -genkey -noout -out "$W/key.pem" 2>/dev/null
openssl ec -in "$W/key.pem" -pubout -out "$CO/deploy/keys/update-signing.pem" 2>/dev/null
openssl ecparam -name secp384r1 -genkey -noout -out "$W/other.pem" 2>/dev/null

# release REL_DIR [VERSION_IN_MANIFEST] [SIGNING_KEY] [EXTRA_PATH]: a fake release v$V
release() {
    local rel=$1 mver=${2:-$V} key=${3:-$W/key.pem} extra=${4:-} b=$W/build
    rm -rf "$b" "$rel"; mkdir -p "$b/radius-admin/deploy" "$rel/v$V"
    cat > "$b/radius-admin/deploy/install.sh" <<'EOF'
#!/bin/bash
# stub installer of the fake release: records how it was called
{ printf 'pwd=%s\n' "$PWD"; printf 'arg=%s\n' "$@"; } > "$STUB_LOG"
EOF
    chmod 0755 "$b/radius-admin/deploy/install.sh"
    echo "{\"version\": \"$V\", \"channel\": \"main\"}" > "$b/radius-admin/BUILD.json"
    if [[ -n $extra ]]; then
        tar -C "$b" -czf "$rel/v$V/radius-admin-$V.tar.gz" radius-admin "$extra" 2>/dev/null
    else
        tar -C "$b" -czf "$rel/v$V/radius-admin-$V.tar.gz" radius-admin
    fi
    python3 -I - "$rel/v$V" "$V" "$mver" <<'PY'
import hashlib, json, os, sys
d, v, mv = sys.argv[1:]
name = "radius-admin-%s.tar.gz" % v
h = hashlib.sha384(open(os.path.join(d, name), "rb").read()).hexdigest()
json.dump({"format": 1, "product": "radius-admin", "version": mv,
           "bundle": {"name": name, "size": 0, "sha384": h}}, open(os.path.join(d, "manifest.json"), "w"))
PY
    openssl dgst -sha384 -sign "$key" -out "$rel/v$V/manifest.json.sig" "$rel/v$V/manifest.json"
}

# run REL_DIR ARGS...: the checkout's install.sh against that release; output in $W/out
run() {
    local rel=$1; shift
    rm -f "$W/stub.log"; rm -rf "$W/src"
    (cd "$W" && STUB_LOG=$W/stub.log RA_RELEASE_URL=file://$rel RA_RELEASE_DIR=$W/src \
        "$CO/deploy/install.sh" "$@") >"$W/out" 2>&1
}

# --- a good release: verified, unpacked, its installer runs with the original arguments
release "$W/good"
echo 'server_name: radius.example.net' > "$W/site.yaml"
if run "$W/good" --answers site.yaml -y && [[ -s $W/src/radius-admin-$V/BUILD.json ]] \
    && grep -qx "pwd=$W" "$W/stub.log" \
    && [[ $(grep '^arg=' "$W/stub.log" | tr '\n' ' ') == 'arg=--answers arg=site.yaml arg=-y ' ]]; then
    pass "a checkout downloads the signed release and runs its installer with the same arguments"
else fail "good release: $(cat "$W/out" "$W/stub.log" 2>/dev/null)"; fi
compgen -G "$W/src/.radius-admin-*" >/dev/null && fail "staging directory left behind" \
    || pass "no staging directory left behind"
[[ -z $(find "$W/src/radius-admin-$V" -perm /022) ]] && pass "the unpacked release is not group/world-writable" \
    || fail "group/world-writable files in the unpacked release"

# a second run replaces the unpacked release instead of mixing old and new files
touch "$W/src/radius-admin-$V/stale-file"
rm -f "$W/stub.log"
if (cd "$W" && STUB_LOG=$W/stub.log RA_RELEASE_URL=file://$W/good RA_RELEASE_DIR=$W/src \
        "$CO/deploy/install.sh" -y) >"$W/out" 2>&1 \
    && [[ -s $W/src/radius-admin-$V/BUILD.json && ! -e $W/src/radius-admin-$V/stale-file ]]; then
    pass "a second run replaces the unpacked release"
else fail "second run: $(cat "$W/out")"; fi

# refuse REL_DIR LABEL PATTERN: the download is refused, nothing is unpacked or run
refuse() {
    if run "$1" -y; then fail "$2: accepted"
    elif [[ -e $W/stub.log || -e $W/src/radius-admin-$V ]]; then fail "$2: something was unpacked or run"
    elif grep -q -- "$3" "$W/out"; then pass "$2 is refused"
    else fail "$2: unexpected message: $(cat "$W/out")"; fi
}

release "$W/bad"; printf 'x' >> "$W/bad/v$V/radius-admin-$V.tar.gz"
refuse "$W/bad" "a bundle that does not match the manifest" "does not match its signed manifest"
release "$W/bad" "$V" "$W/other.pem"
refuse "$W/bad" "a manifest signed with another key" "is not signed by"
release "$W/bad" "9.8.6"
refuse "$W/bad" "a manifest for another version" "is not for radius-admin $V"
touch "$W/build-extra"
release "$W/bad" "$V" "$W/key.pem" "../build-extra"
refuse "$W/bad" "a bundle with files outside radius-admin/" "outside radius-admin/"
refuse "$W/none" "a missing release" "--from-checkout"

# --- no download: --from-checkout, --phase/--from, the print modes, and a release bundle
# (a missing answers file stops each run right after the place where it would download)
nodl() {
    local label=$1; shift
    run "$W/none" "$@" || true
    if grep -q 'downloading release' "$W/out" || [[ -e $W/src ]]; then fail "$label: downloaded"
    elif ! grep -q 'is not readable' "$W/out"; then fail "$label: did not reach the answers file: $(cat "$W/out")"
    else pass "$label: no download"; fi
}
nodl "--from-checkout" --from-checkout --answers "$W/no-such.yaml" -y
nodl "--phase" --phase preflight --answers "$W/no-such.yaml" -y
nodl "--from" --from users --answers "$W/no-such.yaml" -y
nodl "--print-answers" --answers "$W/no-such.yaml" --print-answers
nodl "--print-settings" --answers "$W/no-such.yaml" --print-settings
echo "{\"version\": \"$V\"}" > "$CO/BUILD.json"
nodl "a release bundle (BUILD.json)" --answers "$W/no-such.yaml" -y
rm -f "$CO/BUILD.json"

echo "fetch-release: $fails failure(s)"
[[ $fails -eq 0 ]]
