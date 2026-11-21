#!/bin/bash
# integrations/duo/install.sh and remove.sh (SPEC section 29.2) with a FAKE Duo source tarball:
# the same layout and installer options as the real one, no Duo code. Root (creates the build
# user radius-admin-build); sandbox or CI runner only.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL=$ROOT/integrations/duo/install.sh
REMOVE=$ROOT/integrations/duo/remove.sh
W=$(mktemp -d /tmp/ra-duoinst.XXXXXX)
chmod 0755 "$W"
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
export RA_DUO_DIR=$W/opt/duoauthproxy RA_SYSTEMD_DIR=$W/systemd RA_DUO_SKIP_PACKAGES=1 \
       RA_SYSTEMCTL=$W/systemctl RA_BACKUP_DIR=$W/backups
mkdir -p "$RA_SYSTEMD_DIR" "$W/opt"
cat > "$W/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> "$W/systemctl.log"
case "\$1" in is-active) exit 1;; esac
exit 0
EOF
chmod 0755 "$W/systemctl"

# make_src VERSION [makefile-body] [extra tar member]
make_src() {
    local v=$1 body=${2:-} d=$W/src/duoauthproxy-$1-src
    rm -rf "$W/src"; mkdir -p "$d"
    if [[ -z $body ]]; then
        body=$(cat <<'MK'
all:
	mkdir -p duoauthproxy-build
	id -un > duoauthproxy-build/built-by
	cp fake-install duoauthproxy-build/install
	chmod 0755 duoauthproxy-build/install
MK
)
    fi
    printf '%s\n' "$body" > "$d/Makefile"
    cat > "$d/fake-install" <<'SH'
#!/bin/bash
# stands in for duoauthproxy-build/install: records how it was called, lays out an install
dir=""
while [ $# -gt 0 ]; do case "$1" in --install-dir) dir=$2; shift;; esac; shift; done
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dir/conf" "$dir/log" "$dir/run"
cp "$here/built-by" "$dir/built-by"
[ "$(stat -c %U "$here/install")" = root ] && [ "$(stat -c %U "$here")" = root ] && echo "owner root" > "$dir/owner-check"
[ -f "$dir/conf/authproxy.cfg" ] || printf '; Duo sample\n' > "$dir/conf/authproxy.cfg"
printf '#!/bin/sh\nrm -rf "%s"\n' "$dir" > "$dir/uninstall"; chmod 0755 "$dir/uninstall"
SH
    (cd "$W/src" && tar -czf "$W/build.tgz" "duoauthproxy-$v-src")
}
request() { # request VERSION
    printf '{"id": "duo", "version": "%s", "file": "duoauthproxy-%s-src.tgz", "sha256": "%s", "size": 1, "verified": "catalog", "fips": false}\n' \
        "$1" "$1" "$(sha256sum "$W/build.tgz" | cut -d' ' -f1)" > "$W/request.json"
}

make_src 9.9.9; request 9.9.9
out=$(bash "$INSTALL" "$W/request.json" "$W/build.tgz" 2>&1); rc=$?
[[ $rc -eq 0 && -f $RA_DUO_DIR/conf/authproxy.cfg ]] && pass "a source build is built and installed" || fail "install: $out"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["version"]=="9.9.9" and d["verified"]=="catalog" and d["fips"] is False and d["installed"]' \
    "$RA_DUO_DIR/.radius-admin" 2>/dev/null && pass "the install is recorded in .radius-admin" || fail "marker"
[[ $(stat -c '%U %a' "$RA_DUO_DIR/.radius-admin") == "root 644" ]] && pass "the record is root-owned" || fail "marker owner"
grep -q '^ProtectSystem=strict' "$RA_SYSTEMD_DIR/duoauthproxy.service.d/radius-admin.conf" 2>/dev/null \
    && grep -q "^ReadWritePaths=$RA_DUO_DIR/log $RA_DUO_DIR/run" "$RA_SYSTEMD_DIR/duoauthproxy.service.d/radius-admin.conf" \
    && pass "the hardening drop-in is written" || fail "drop-in"
grep -q '^daemon-reload' "$W/systemctl.log" && grep -q '^stop duoauthproxy.service' "$W/systemctl.log" \
    && ! grep -q '^restart' "$W/systemctl.log" && pass "the service is not started with Duo's sample configuration" \
    || fail "systemctl: $(cat "$W/systemctl.log")"
[[ $out == *"it starts once its configuration is applied"* ]] && pass "the log says what happens next" || fail "message"
[[ -z $(ls /var/tmp/radius-admin-duo.* 2>/dev/null) ]] && pass "the build directory is removed" || fail "build dir left"

[[ $(cat "$RA_DUO_DIR/built-by" 2>/dev/null) == radius-admin-build ]] && pass "the build runs as radius-admin-build" \
    || fail "built by: $(cat "$RA_DUO_DIR/built-by" 2>/dev/null)"
[[ $(cat "$RA_DUO_DIR/owner-check" 2>/dev/null) == "owner root" ]] \
    && pass "the build tree is root-owned before Duo's installer runs as root" || fail "build tree owner"
out=$(bash "$INSTALL" "$W/request.json" "$W/build.tgz" 2>&1)
[[ $out == *"installed in"* ]] && pass "an upgrade over an existing install runs" || fail "upgrade: $out"

# an applied radius-admin configuration: the service is (re)started
printf '; radius-admin: test\n' > "$RA_DUO_DIR/conf/authproxy.cfg"
: > "$W/systemctl.log"
bash "$INSTALL" "$W/request.json" "$W/build.tgz" >/dev/null 2>&1
grep -q '^restart duoauthproxy.service' "$W/systemctl.log" && pass "with an applied configuration the service restarts" \
    || fail "restart: $(cat "$W/systemctl.log")"

# unsafe archives and failing builds install nothing
mkdir -p "$W/evil/duoauthproxy-9.9.9-src"; echo x > "$W/evil/duoauthproxy-9.9.9-src/Makefile"; echo x > "$W/evil/other"
(cd "$W/evil" && tar -czf "$W/build.tgz" duoauthproxy-9.9.9-src other)
request 9.9.9
out=$(bash "$INSTALL" "$W/request.json" "$W/build.tgz" 2>&1)
[[ $? -ne 0 && $out == *"does not contain only"* ]] && pass "an archive with other top-level entries is refused" || fail "extra member: $out"
python3 - "$W/build.tgz" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as tf:
    for name, data in (("duoauthproxy-9.9.9-src/Makefile", b"all:\n\ttrue\n"), ("duoauthproxy-9.9.9-src/../../escape", b"x")):
        ti = tarfile.TarInfo(name); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
PY
request 9.9.9
out=$(bash "$INSTALL" "$W/request.json" "$W/build.tgz" 2>&1)
[[ $? -ne 0 && ! -e $W/escape ]] && pass "an archive member leaving the tree is refused" || fail "traversal: $out"
make_src 9.9.9 "$(printf 'all:\n\tfalse\n')"; request 9.9.9
out=$(bash "$INSTALL" "$W/request.json" "$W/build.tgz" 2>&1)
[[ $? -ne 0 && $out == *"the build failed"* ]] && pass "a failing build is reported" || fail "failing build: $out"
make_src 9.9.9; request 1.2
out=$(bash "$INSTALL" "$W/request.json" "$W/build.tgz" 2>&1)
[[ $? -ne 0 && $out == *"invalid version"* ]] && pass "an invalid version is refused" || fail "version: $out"

# remove: keeps a copy of the configuration, runs Duo's uninstaller, drops the drop-in
out=$(bash "$REMOVE" 2>&1)
[[ $? -eq 0 && ! -e $RA_DUO_DIR && ! -e $RA_SYSTEMD_DIR/duoauthproxy.service.d ]] && pass "remove runs the uninstaller and drops the drop-in" \
    || fail "remove: $out"
ls "$RA_BACKUP_DIR"/duoauthproxy-authproxy.cfg-* >/dev/null 2>&1 && pass "remove keeps a copy of the configuration" || fail "config copy"
mkdir -p "$RA_DUO_DIR"
out=$(bash "$REMOVE" 2>&1)
[[ $? -ne 0 && $out == *"not installed by radius-admin"* && -d $RA_DUO_DIR ]] && pass "a Duo install radius-admin did not make is left alone" \
    || fail "foreign remove: $out"

echo; (( fails == 0 )) && echo "all Duo install checks passed" || echo "$fails check(s) FAILED"
exit $(( fails > 0 ))
