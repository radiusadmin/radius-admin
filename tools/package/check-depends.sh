#!/bin/bash
# check-depends.sh "DEPENDS" : every versioned dependency in a Debian Depends field can be met by
# a version from the distribution's own archive (*.ubuntu.com, *.debian.org), not only by a
# third-party repository such as apt.postgresql.org. Used by build-freeradius-deb.sh and the
# package test. Needs current apt lists (apt-get update). Prints the offending terms; exit 1 if any.
set -uo pipefail
export LC_ALL=C
dep=${1:?usage: check-depends.sh "DEPENDS"}
bad=0
IFS=',' read -r -a terms <<<"$dep"
for term in "${terms[@]}"; do
    ok=0
    IFS='|' read -r -a alts <<<"$term"
    for alt in "${alts[@]}"; do
        alt=$(sed 's/^ *//; s/ *$//' <<<"$alt")
        if [[ $alt =~ ^([a-z0-9][a-z0-9+.-]*)(:[a-z0-9]+)?\ *\(\>=\ *([^\)]+)\)$ ]]; then
            pkg=${BASH_REMATCH[1]} want=${BASH_REMATCH[3]}
            while read -r v; do
                [[ -n $v ]] && dpkg --compare-versions "$v" ge "$want" && { ok=1; break; }
            done < <(apt-cache madison "$pkg" 2>/dev/null \
                     | awk -F'|' '$3 ~ /(ubuntu\.com|debian\.org)/ {gsub(/ /, "", $2); print $2}')
        elif [[ $alt =~ ^([a-z0-9][a-z0-9+.-]*)(:[a-z0-9]+)?$ ]]; then
            # no version: the archive only has to have the package
            apt-cache madison "${BASH_REMATCH[1]}" 2>/dev/null | awk -F'|' '$3 ~ /(ubuntu\.com|debian\.org)/' | grep -q . && ok=1
        elif [[ -n $alt ]]; then
            echo "check-depends: cannot read '$alt'" >&2
        fi
        (( ok )) && break
    done
    if (( ! ok )); then
        echo "check-depends: not satisfiable from the distribution archive: $(sed 's/^ *//' <<<"$term")" >&2
        bad=1
    fi
done
exit "$bad"
