#!/bin/bash
# The version of a build, from VERSION and the branch it was built from (SPEC section 16):
#   main      0.2.0           stable release (published only when VERSION changes)
#   testing   0.2.0-rc.N      release candidate
#   dev       0.2.0-dev.N     development build
# N counts the commits since VERSION last changed, so it only grows along a branch.
#   tools/release/build-version.sh BRANCH [REV]      (REV default HEAD)
set -euo pipefail
branch=${1:?usage: build-version.sh BRANCH [REV]}
rev=${2:-HEAD}
base=$(git show "$rev:VERSION" | tr -d '[:space:]')
[[ $base =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || { echo "VERSION is not X.Y.Z: $base" >&2; exit 1; }
bump=$(git log -1 --format=%H "$rev" -- VERSION)
[[ -n $bump ]] || { echo "VERSION has no history at $rev" >&2; exit 1; }
n=$(git rev-list --count "$bump..$rev")
case $branch in
    main) echo "$base" ;;
    testing) echo "$base-rc.$n" ;;
    dev) echo "$base-dev.$n" ;;
    *) echo "no release channel for branch $branch" >&2; exit 1 ;;
esac
