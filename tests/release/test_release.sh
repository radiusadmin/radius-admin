#!/bin/bash
# Release tooling (tools/release/): build versions, release notes, signed manifests.
# Works in throwaway git repositories with throwaway keys; needs git, openssl, python3.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
g() { git -c user.name=t -c user.email=t@example.net -c commit.gpgsign=false "$@"; }

# ------------------------------------------------------------------ build-version.sh
V=$ROOT/tools/release/build-version.sh
mkdir "$W/v" && cd "$W/v" && g init -q -b main || exit 2
echo 0.1.0 > VERSION; g add VERSION; g commit -qm v1
echo a > a; g add a; g commit -qm a
echo b > b; g add b; g commit -qm b
[[ $("$V" main) == 0.1.0 && $("$V" testing) == 0.1.0-rc.2 && $("$V" dev) == 0.1.0-dev.2 ]] \
    && pass "main / testing / dev versions from VERSION and the commit count" \
    || fail "versions: $("$V" main) $("$V" testing) $("$V" dev)"
[[ $("$V" dev HEAD~1) == 0.1.0-dev.1 ]] && pass "an older commit gets a lower build number" || fail "REV argument"
echo 0.2.0 > VERSION; g commit -qam v2
[[ $("$V" dev) == 0.2.0-dev.0 ]] && pass "bumping VERSION restarts the build number" || fail "after bump: $("$V" dev)"
"$V" feature/x >/dev/null 2>&1 && fail "a feature branch got a version" || pass "other branches have no release channel"
echo 1.2 > VERSION; g commit -qam bad
"$V" main >/dev/null 2>&1 && fail "accepted VERSION 1.2" || pass "VERSION must be X.Y.Z"
cd "$ROOT" || exit 2

# ------------------------------------------------------------------ release-notes.py
N=$ROOT/tools/release/release-notes.py
cat > "$W/CHANGELOG.md" <<'EOF'
# Changelog
## Unreleased
- next thing
## 0.2.0 — 2026-11-02
- second
## 0.1.0 — 2026-10-01
- first
EOF
printf 'Fix one\nAdd two\n' > "$W/commits"
out=$(python3 -I "$N" "$W/CHANGELOG.md" 0.2.0)
[[ $out == "- second" ]] && pass "a release gets its own changelog section" || fail "release notes: $out"
out=$(python3 -I "$N" "$W/CHANGELOG.md" 0.3.0-dev.4 "$W/commits")
grep -q -- '- next thing' <<<"$out" && grep -q -- '- Fix one' <<<"$out" && ! grep -q second <<<"$out" \
    && pass "a preview gets Unreleased plus its commits" || fail "preview notes: $out"

# ------------------------------------------------------------------ make-release.sh
R=$W/repo
mkdir "$R"
(cd "$ROOT" && git ls-files -z | xargs -0 -I{} cp --parents -a {} "$R/")
for f in tools/release/build-version.sh tools/release/make-release.sh tools/release/release-notes.py \
         VERSION CHANGELOG.md tools/package/make-bundle.sh tools/lib/fr-release.sh; do
    install -D -m "$(stat -c %a "$ROOT/$f")" "$ROOT/$f" "$R/$f"
done
cp "$ROOT/.gitignore" "$R/"
openssl ecparam -name secp384r1 -genkey -noout -out "$W/key.pem" 2>/dev/null
openssl ecparam -name secp384r1 -genkey -noout -out "$W/other.pem" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$W/p256.pem" 2>/dev/null
mkdir -p "$R/deploy/keys" "$R/packages/source"
openssl pkey -in "$W/key.pem" -pubout -out "$R/deploy/keys/update-signing.pem" 2>/dev/null
deb=radius-admin-freeradius_3.2.10-1~test_amd64.deb
echo fake > "$R/packages/$deb"; (cd "$R/packages" && sha384sum "$deb" > "$deb.sha384")
touch "$R/packages/source/freeradius-server-3.2.10.tar.gz" "$R/packages/source/freeradius-server-3.2.10.tar.gz.sig"
(cd "$R" && g init -q -b dev && g add -A && g commit -qm import)
MR=$R/tools/release/make-release.sh

ver=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/key.pem") "$MR" dev "$W/out1" 2>"$W/err1")
if [[ $? -eq 0 && $ver == 0.1.0-dev.0 && -f $W/out1/radius-admin-$ver.tar.gz ]]; then
    pass "makes a dev release ($ver)"
else fail "make-release dev: $ver $(tail -3 "$W/err1")"; fi
openssl dgst -sha384 -verify "$R/deploy/keys/update-signing.pem" -signature "$W/out1/manifest.json.sig" \
    "$W/out1/manifest.json" >/dev/null 2>&1 && pass "manifest signature verifies with the pinned key" \
    || fail "signature does not verify"
m() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {"d": d}))' "$@"; }
[[ $(m "$W/out1/manifest.json" 'd["bundle"]["sha384"]') == $(sha384sum "$W/out1/radius-admin-$ver.tar.gz" | cut -d' ' -f1) ]] \
    && [[ $(m "$W/out1/manifest.json" 'd["version"], d["channel"], d["restarts_freeradius"]') == "('0.1.0-dev.0', 'dev', True)" ]] \
    && pass "manifest records version, channel, bundle hash; first release restarts FreeRADIUS" \
    || fail "manifest: $(cat "$W/out1/manifest.json")"
b=$(tar -xzOf "$W/out1/radius-admin-$ver.tar.gz" radius-admin/BUILD.json 2>/dev/null)
[[ $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d["version"], d["channel"])' "$b") == "0.1.0-dev.0 dev" ]] \
    && grep -qx "radius-admin/packages/$deb" <<<"$(tar -tzf "$W/out1/radius-admin-$ver.tar.gz")" \
    && pass "bundle carries BUILD.json and the FreeRADIUS package" || fail "bundle contents: $b"

(cd "$R" && g tag "v$ver" && echo x >> README.md && g commit -qam "Docs only")
ver2=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/key.pem") "$MR" dev "$W/out2" "v$ver" 2>/dev/null)
[[ $ver2 == 0.1.0-dev.1 && $(m "$W/out2/manifest.json" 'd["restarts_freeradius"]') == False ]] \
    && grep -q -- '- Docs only' "$W/out2/notes.md" \
    && pass "a release without FreeRADIUS changes does not restart it; notes list its commits" \
    || fail "second release: $ver2 $(cat "$W/out2/manifest.json" 2>/dev/null | head -5)"
(cd "$R" && g tag "v$ver2" && echo '# x' >> freeradius/clients.conf && g commit -qam "FR change")
(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/key.pem") "$MR" dev "$W/out3" "v$ver2" >/dev/null 2>&1)
[[ $(m "$W/out3/manifest.json" 'd["restarts_freeradius"]') == True ]] \
    && pass "a FreeRADIUS configuration change marks the release as restarting it" || fail "restart flag"

out=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/other.pem") "$MR" dev "$W/out4" 2>&1)
[[ $? -ne 0 ]] && grep -q 'does not match' <<<"$out" && [[ ! -e $W/out4/manifest.json ]] \
    && pass "a key that is not the pinned one is refused before anything is written" || fail "wrong key: $out"
out=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/p256.pem") "$MR" dev "$W/out5" 2>&1)
[[ $? -ne 0 ]] && grep -q 'not an ECDSA P-384' <<<"$out" && pass "a P-256 key is refused" || fail "p256: $out"
out=$(cd "$R" && UPDATE_SIGNING_KEY="" "$MR" dev "$W/out6" 2>&1)
[[ $? -ne 0 ]] && grep -q 'empty' <<<"$out" && pass "no key, no release" || fail "empty key: $out"

echo; (( fails == 0 )) && echo "all release checks passed" || echo "$fails check(s) FAILED"
exit $(( fails > 0 ))
