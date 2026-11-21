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

# ------------------------------------------------------------------ prev-tag.sh
P=$ROOT/tools/release/prev-tag.sh
mkdir "$W/p" && cd "$W/p" && g init -q -b dev || exit 2
echo 0.3.0 > VERSION; g add VERSION; g commit -qm v1
for t in v0.1.0 v0.2.0 v0.2.0-rc.3 v0.2.0-rc.10 v0.3.0-dev.1 v0.3.0-dev.2 \
         'v9.9.9-dev.1;id' 'v9.9.9-rc.1$(id)' 'v9.9.9`id`' v9.9.9-dev.1x v09999.0.0; do
    g tag "$t" || fail "git refused test tag $t"
done
[[ $("$P" dev 0.3.0-dev.3) == v0.3.0-dev.2 && $("$P" dev 0.3.0-dev.2) == v0.3.0-dev.1 ]] \
    && pass "prev-tag: newest other dev tag; a crafted tag name that sorts higher is skipped" \
    || fail "prev-tag dev: $("$P" dev 0.3.0-dev.3)"
[[ $("$P" testing 0.2.0-rc.11) == v0.2.0-rc.10 && $("$P" main 0.3.0) == v0.2.0 ]] \
    && pass "prev-tag: testing sorts by version, main ignores previews and crafted tags" \
    || fail "prev-tag testing/main: $("$P" testing 0.2.0-rc.11) $("$P" main 0.3.0)"
(cd "$W/p" && g tag -d v0.3.0-dev.1 v0.3.0-dev.2 >/dev/null)
out=$("$P" dev 0.3.0-dev.3) && [[ -z $out ]] \
    && pass "prev-tag: only crafted dev tags left means no previous tag" || fail "prev-tag empty: $out"
bad=0
for v in '0.3.0-dev.3;id' $'0.3.0-dev.3\nx' $'0.3.0\n' '0.3.0-rc.1' ' 0.3.0'; do
    "$P" main "$v" >/dev/null 2>&1 && { bad=1; echo "accepted: ${v@Q}"; }
done
"$P" feature/x 0.3.0 >/dev/null 2>&1 && bad=1
"$P" dev '0.3.0-dev.3$(id)' >/dev/null 2>&1 && bad=1
(( bad == 0 )) && pass "prev-tag: refuses invalid versions (shell characters, newlines) and channels" \
    || fail "prev-tag accepted an invalid version or channel"
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
         VERSION CHANGELOG.md tools/package/make-bundle.sh tools/lib/fr-release.sh \
         integrations/catalog.json tools/integrations/catalog.py; do
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
BASE=$(tr -d '[:space:]' < "$R/VERSION")   # the repository's VERSION, copied above

ver=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/key.pem") "$MR" dev "$W/out1" 2>"$W/err1")
if [[ $? -eq 0 && $ver == "$BASE-dev.0" && -f $W/out1/radius-admin-$ver.tar.gz ]]; then
    pass "makes a dev release ($ver)"
else fail "make-release dev: $ver $(tail -3 "$W/err1")"; fi
openssl dgst -sha384 -verify "$R/deploy/keys/update-signing.pem" -signature "$W/out1/manifest.json.sig" \
    "$W/out1/manifest.json" >/dev/null 2>&1 && pass "manifest signature verifies with the pinned key" \
    || fail "signature does not verify"
m() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {"d": d}))' "$@"; }
[[ $(m "$W/out1/manifest.json" 'd["bundle"]["sha384"]') == $(sha384sum "$W/out1/radius-admin-$ver.tar.gz" | cut -d' ' -f1) ]] \
    && [[ $(m "$W/out1/manifest.json" 'd["version"], d["channel"], d["restarts_freeradius"]') == "('$BASE-dev.0', 'dev', True)" ]] \
    && pass "manifest records version, channel, bundle hash; first release restarts FreeRADIUS" \
    || fail "manifest: $(cat "$W/out1/manifest.json")"
b=$(tar -xzOf "$W/out1/radius-admin-$ver.tar.gz" radius-admin/BUILD.json 2>/dev/null)
[[ $(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d["version"], d["channel"])' "$b") == "$BASE-dev.0 dev" ]] \
    && grep -qx "radius-admin/packages/$deb" <<<"$(tar -tzf "$W/out1/radius-admin-$ver.tar.gz")" \
    && pass "bundle carries BUILD.json and the FreeRADIUS package" || fail "bundle contents: $b"
mkdir -p "$W/cat1"
tar -xzf "$W/out1/radius-admin-$ver.tar.gz" -C "$W/cat1" radius-admin/integrations/catalog.json \
    radius-admin/integrations/catalog.json.sig 2>/dev/null
openssl dgst -sha384 -verify "$R/deploy/keys/update-signing.pem" -signature "$W/cat1/radius-admin/integrations/catalog.json.sig" \
    "$W/cat1/radius-admin/integrations/catalog.json" >/dev/null 2>&1 \
    && pass "bundle carries the integrations catalog, signed with the pinned key" || fail "catalog signature in the bundle"

(cd "$R" && g tag "v$ver" && echo x >> README.md && g commit -qam "Docs only")
ver2=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/key.pem") "$MR" dev "$W/out2" "v$ver" 2>/dev/null)
[[ $ver2 == "$BASE-dev.1" && $(m "$W/out2/manifest.json" 'd["restarts_freeradius"]') == False ]] \
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
(cd "$R" && echo '{"format": 1, "serial": 0, "entries": []}' > integrations/catalog.json && g commit -qam "bad catalog")
out=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/key.pem") "$MR" dev "$W/out7" 2>&1)
[[ $? -ne 0 ]] && grep -q 'catalog' <<<"$out" && [[ ! -e $W/out7/manifest.json ]] \
    && pass "an invalid integrations catalog stops the release" || fail "bad catalog: $out"
out=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/key.pem") "$MR" dev "$W/out8" 'v0.0.1;touch x' 2>&1)
[[ $? -ne 0 ]] && grep -q 'not a release tag' <<<"$out" && [[ ! -e $W/out8/manifest.json && ! -e $R/x ]] \
    && pass "a PREV_TAG that is not an exact release tag is refused" || fail "crafted PREV_TAG: $out"
out=$(cd "$R" && UPDATE_SIGNING_KEY=$(cat "$W/key.pem") "$MR" dev "$W/out9" $'v0.0.1\n' 2>&1)
[[ $? -ne 0 ]] && grep -q 'not a release tag' <<<"$out" && pass "a PREV_TAG with a trailing newline is refused" \
    || fail "PREV_TAG newline: $out"
out=$(cd "$R" && UPDATE_SIGNING_KEY="" "$MR" dev "$W/out6" 2>&1)
[[ $? -ne 0 ]] && grep -q 'empty' <<<"$out" && pass "no key, no release" || fail "empty key: $out"

# ------------------------------------------------------------------ tools/integrations/catalog.py
C=$ROOT/tools/integrations/catalog.py
printf '{"format": 1, "serial": 1, "entries": []}\n' > "$W/cat.json"
mkdir -p "$W/dl"; printf 'duo build\n' > "$W/dl/duoauthproxy-6.7.0-src.tgz"
h=$(sha256sum "$W/dl/duoauthproxy-6.7.0-src.tgz" | cut -d' ' -f1)
out=$(python3 -I "$C" --catalog "$W/cat.json" add duo 6.7.0 "$W/dl/duoauthproxy-6.7.0-src.tgz" --vendor-sha256 "$(printf '0%.0s' {1..64})" 2>&1)
[[ $? -ne 0 && $out == *"does not match the vendor"* ]] && pass "catalog add refuses a file whose SHA-256 differs from the vendor's" \
    || fail "catalog add mismatch: $out"
cp "$W/dl/duoauthproxy-6.7.0-src.tgz" "$W/dl/renamed.tgz"
python3 -I "$C" --catalog "$W/cat.json" add duo 6.7.0 "$W/dl/renamed.tgz" --vendor-sha256 "$h" >/dev/null 2>&1 \
    && fail "catalog add accepted a renamed file" || pass "catalog add wants the vendor's file name"
python3 -I "$C" --catalog "$W/cat.json" add duo 6.7.0 "$W/dl/duoauthproxy-6.7.0-src.tgz" --vendor-sha256 "$h" >/dev/null \
    && python3 -I "$C" --catalog "$W/cat.json" fips duo 6.7.0 ubuntu-24.04-pro-fips >/dev/null \
    && python3 -I "$C" --catalog "$W/cat.json" withdraw duo 6.7.0 >/dev/null
[[ $(m "$W/cat.json" 'd["serial"], d["entries"][0]["fips"], d["entries"][0]["withdrawn"], d["entries"][0]["sha256"] == "'"$h"'"') == "(4, True, True, True)" ]] \
    && pass "catalog add, fips and withdraw each bump the serial" || fail "catalog edits: $(cat "$W/cat.json")"
python3 -I "$C" --catalog "$W/cat.json" sign "$W/key.pem" >/dev/null \
    && python3 -I "$C" --catalog "$W/cat.json" verify "$R/deploy/keys/update-signing.pem" >/dev/null \
    && ! python3 -I "$C" --catalog "$W/cat.json" verify <(openssl pkey -in "$W/other.pem" -pubout 2>/dev/null) >/dev/null 2>&1 \
    && pass "catalog sign and verify (another key does not verify)" || fail "catalog sign/verify"

echo; (( fails == 0 )) && echo "all release checks passed" || echo "$fails check(s) FAILED"
exit $(( fails > 0 ))
