#!/bin/bash
# The previous release tag on an update channel (SPEC section 16), for make-release.sh.
#   tools/release/prev-tag.sh CHANNEL VERSION        (prints nothing when there is none)
# Tag names come from the repository and anyone who can push a tag chooses them, so only
# tags that are exactly v<version> for the channel are considered (a tag such as
# "v9.9.9-dev.1;id" is skipped, never printed). VERSION and CHANNEL are checked the same way.
set -euo pipefail
export LC_ALL=C
channel=${1:?usage: prev-tag.sh CHANNEL VERSION}
ver=${2:?usage: prev-tag.sh CHANNEL VERSION}
xyz='[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}'
case $channel in
    main) re="v$xyz" ;;
    testing) re="v$xyz-rc\.[0-9]{1,6}" ;;
    dev) re="v$xyz-dev\.[0-9]{1,6}" ;;
    *) echo "prev-tag: no release channel $channel" >&2; exit 1 ;;
esac
# bash [[ =~ ]] anchors ^...$ at the ends of the whole string (a newline is not a line end)
[[ v$ver =~ ^$re$ ]] || { echo "prev-tag: version is not valid for $channel" >&2; exit 1; }
git tag -l 'v*' --sort=-v:refname | grep -Ex -- "$re" | grep -vxF -- "v$ver" | head -n1 || true
