#!/usr/bin/env bash
# radius-admin updater: install a new radius-admin package on this server.
#
# Normally started by the Windows push script (tools/windows/push-radius-admin.ps1), which
# copies the package here over SSH and runs:
#   sudo bash update.sh --package ~/radius-admin-<hash>.tar.gz --sha256 <hash>
#
# It can also be run by hand on the server:
#   sudo ./deploy/update.sh --package /path/radius-admin.tar.gz [--sha256 HASH]
#   sudo ./deploy/update.sh --rollback          re-install the release before the current one (app phase)
#   sudo ./deploy/update.sh --list              show installed releases
#
# What it does
#   1. Checks the package SHA-256 (when given) and that every file is inside radius-admin/
#      with no "..", then unpacks it as root into /opt/radius-admin-src/releases/<time>-<hash>.
#   2. Compares the new release with the current one and picks the install.sh phases:
#        packages  if the package list in install.sh changed
#        postgres  if sql/ or deploy/postgres/ changed (all SQL files are idempotent)
#        app       always (installs only what changed; restarts the web UI and the poller)
#        nginx     if deploy/nginx/ changed
#        firewall  if deploy/firewall/ changed
#      FreeRADIUS files (freeradius/) are never installed automatically: when they change
#      you are told, and --with-freeradius adds the freeradius phase (it still does not
#      restart FreeRADIUS; that happens from Review and apply or with --restart-freeradius).
#   3. Shows the plan, asks for confirmation (unless --yes), runs install.sh, and on
#      success points /opt/radius-admin-src/current at the new release and keeps the last
#      5 releases. On failure the new release is discarded, the "current" link is left
#      unchanged and the uploaded package is kept. Phases that already ran before the
#      failure are not undone (they are idempotent; fix the cause and push again).
#
# Options
#   --package FILE        package to install (.tar.gz)
#   --sha256 HASH         expected SHA-256 of FILE (the push script always passes it)
#   --phases a,b          use exactly these install.sh phases instead of the automatic choice
#   --with-freeradius     also run the freeradius phase
#   --force               reinstall even if this package is already the current release
#   --keep-upload         do not delete FILE after a successful install
#   -y, --yes             do not ask for confirmation
#   --rollback            re-run the app phase from the previous release and make it current
#   --list                list releases
#   -- ARGS               pass ARGS to install.sh (e.g. -- --listen-ip 192.0.2.5)
set -Eeuo pipefail
umask 022

BASE=/opt/radius-admin-src
REL=$BASE/releases
KEEP=5

say()  { printf '%s\n' "$*"; }
info() { printf '  - %s\n' "$*"; }
die()  { printf 'update: error: %s\n' "$*" >&2; exit 1; }

PKG="" SHA="" PHASES_OVERRIDE="" WITH_FR=0 FORCE=0 KEEP_UPLOAD=0 YES=0 MODE=install
PASS=()
while (($#)); do
    case $1 in
        --package) PKG=${2:?}; shift 2 ;;
        --sha256) SHA=${2:?}; shift 2 ;;
        --phases) PHASES_OVERRIDE=${2:?}; shift 2 ;;
        --with-freeradius) WITH_FR=1; shift ;;
        --force) FORCE=1; shift ;;
        --keep-upload) KEEP_UPLOAD=1; shift ;;
        -y|--yes) YES=1; shift ;;
        --rollback) MODE=rollback; shift ;;
        --list) MODE=list; shift ;;
        --) shift; PASS=("$@"); break ;;
        -h|--help) sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done
[[ $EUID -eq 0 ]] || die "run as root (sudo)"
install -d -o root -g root -m 0755 "$BASE" "$REL"

confirm() {
    ((YES)) && return 0
    local a; read -r -p "$1 [y/N] " a || true
    [[ $a == y || $a == Y || $a == yes ]]
}
releases() { find "$REL" -mindepth 1 -maxdepth 1 -type d ! -name '.*' | sort; }  # oldest first
current() { readlink -f "$BASE/current" 2>/dev/null || true; }
rel_info() { if [[ -f $1/.release ]]; then sed -n 's/^sha256=//p' "$1/.release"; fi; }

list_releases() {
    local cur; cur=$(current)
    say "Releases in $REL (newest first, * = current):"
    local d
    for d in $(releases | sort -r); do
        printf '  %s %s  %s\n' "$([[ $d == "$cur" ]] && echo '*' || echo ' ')" "$(basename "$d")" \
            "$(sed -n 's/^installed=//p' "$d/.release" 2>/dev/null) by $(sed -n 's/^by=//p' "$d/.release" 2>/dev/null)"
    done
}

run_install() { # run_install RELEASE_DIR PHASE...
    local dir=$1; shift
    local args=() p
    for p in "$@"; do args+=(--phase "$p"); done
    say ""
    say "Running: $dir/deploy/install.sh ${args[*]} -y ${PASS[*]}"
    "$dir/deploy/install.sh" "${args[@]}" -y "${PASS[@]}"
}

if [[ $MODE == list ]]; then list_releases; exit 0; fi

if [[ $MODE == rollback ]]; then
    cur=$(current)
    [[ -n $cur ]] || die "no current release recorded"
    prev=""
    for d in $(releases); do
        if [[ $(basename "$d") < $(basename "$cur") ]]; then prev=$d; fi
    done
    [[ -n $prev ]] || die "no previous release to roll back to"
    say "Roll back the web UI from $(basename "${cur:-none}") to $(basename "$prev")."
    say "Database changes are additive and stay in place; FreeRADIUS is not touched."
    confirm "Continue?" || die "cancelled"
    run_install "$prev" app
    ln -sfn "$prev" "$BASE/current"
    say ""; say "Rolled back to $(basename "$prev")."
    exit 0
fi

# ------------------------------------------------------------------ install a package
[[ -n $PKG ]] || die "--package is required (see --help)"
[[ -f $PKG ]] || die "package not found: $PKG"
actual=$(sha256sum "$PKG" | awk '{print $1}')
if [[ -n $SHA ]]; then
    [[ ${SHA,,} == "$actual" ]] || die "SHA-256 mismatch: expected $SHA, got $actual (upload damaged or wrong file)"
    info "package SHA-256 verified: $actual"
else
    info "package SHA-256: $actual (not verified: no --sha256 given)"
fi

listing=$(tar -tzf "$PKG") || die "not a readable .tar.gz: $PKG"
if grep -qvE '^radius-admin(/|$)' <<<"$listing"; then die "package contains files outside radius-admin/"; fi
if grep -qE '(^|/)\.\.(/|$)' <<<"$listing"; then die "package contains '..' paths"; fi
grep -qx 'radius-admin/deploy/install.sh' <<<"$listing" || die "package has no deploy/install.sh"

cur=$(current)
if [[ -n $cur && $(rel_info "$cur") == "$actual" && $FORCE -eq 0 ]]; then
    say "This package is already the current release ($(basename "$cur")). Use --force to reinstall."
    exit 0
fi

new=$REL/$(date -u +%Y%m%dT%H%M%SZ)-${actual:0:8}
stage=$(mktemp -d "$REL/.incoming.XXXXXX")
trap 'rm -rf "$stage"' EXIT
tar -C "$stage" --no-same-owner -xzf "$PKG"
mv "$stage/radius-admin" "$new"
rm -rf "$stage"; trap - EXIT
chown -R root:root "$new"
chmod -R go-w "$new"
cat > "$new/.release" <<EOF
sha256=$actual
installed=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
by=${SUDO_USER:-root}
EOF

# ------------------------------------------------------------------ choose phases
changed() { # changed PATH... -> true if any differs between current and new release
    [[ -z $cur || ! -d $cur ]] && return 0
    local p
    for p in "$@"; do
        diff -rq "$cur/$p" "$new/$p" >/dev/null 2>&1 || return 0
    done
    return 1
}
pkg_list() { # the package list in install.sh, to detect when the packages phase is needed
    if [[ -f $1/deploy/install.sh ]]; then
        awk '/^phase_packages\(\)/,/^}/' "$1/deploy/install.sh" | grep -A2 'pkgs=' || true
    fi
}

phases=()
fr_changed=0
if [[ -n $PHASES_OVERRIDE ]]; then
    IFS=, read -r -a phases <<<"$PHASES_OVERRIDE"
else
    if [[ -z $cur ]] || [[ "$(pkg_list "$cur")" != "$(pkg_list "$new")" ]]; then phases+=(packages); fi
    if changed sql deploy/postgres; then phases+=(postgres); fi
    if changed freeradius; then fr_changed=1; fi
    if ((WITH_FR)); then phases+=(freeradius); fi
    phases+=(app)
    if changed deploy/nginx; then phases+=(nginx); fi
    if changed deploy/firewall; then phases+=(firewall); fi
fi

say ""
say "radius-admin update"
say "  from: ${cur:+$(basename "$cur")}${cur:-"(no release installed by this updater yet)"}"
say "  to:   $(basename "$new")"
if [[ -n $cur ]]; then
    n=$(diff -rq "$cur" "$new" -x .release 2>/dev/null | wc -l || true)
    say "  files changed: $n"
fi
say "  install.sh phases: ${phases[*]}"
if ((fr_changed && !WITH_FR)) && [[ -z $PHASES_OVERRIDE ]]; then
    say ""
    say "  NOTE: FreeRADIUS files changed in this release but are not installed automatically."
    say "        Re-run with --with-freeradius (push script: -WithFreeradius) when ready."
fi
say ""
if ! confirm "Install?"; then
    rm -rf "$new"
    die "cancelled (nothing changed)"
fi

if ! run_install "$new" "${phases[@]}"; then
    rm -rf "$new"   # never offer a failed release to --rollback; the uploaded package is kept
    say ""
    say "update: install.sh FAILED. The 'current' release link was not changed and the"
    say "        uploaded package was kept ($PKG)."
    say "        Fix the reported problem and push again, or roll back the web UI with:"
    say "          sudo $BASE/current/deploy/update.sh --rollback"
    exit 1
fi

ln -sfn "$new" "$BASE/current"
# prune: keep the newest $KEEP releases (never the current one)
mapfile -t olds < <(releases | sort -r | tail -n +$((KEEP + 1)))
for d in "${olds[@]}"; do if [[ $d != "$new" ]]; then rm -rf "$d"; fi; done
if ((!KEEP_UPLOAD)); then rm -f "$PKG"; fi

say ""
say "Update complete: $(basename "$new") is now current."
say "Roll back the web UI if needed: sudo $BASE/current/deploy/update.sh --rollback"
