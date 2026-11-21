#!/bin/bash
# check-depends.sh "DEPENDS" : every dependency in a Debian Depends field can be met by a version
# whose archive Origin is the distribution (Ubuntu, Debian), not only by a third-party repository
# such as apt.postgresql.org. Used by build-freeradius-deb.sh and the package test. Reads apt's
# package lists through python3-apt (the archive's Origin field: source URLs say nothing on hosts
# that fetch through a mirror list, such as GitHub's runners). Needs current lists (apt-get update).
# Prints the dependencies that cannot be met; exit 1 if there are any.
set -uo pipefail
dep=${1:?usage: check-depends.sh "DEPENDS"}
exec python3 -I - "$dep" <<'PY'
import sys
import apt_pkg

DISTRO = {"Ubuntu", "Debian"}
apt_pkg.init()
cache = apt_pkg.Cache(None)


def from_distro(ver):
    return any(f.origin in DISTRO for f, _ in ver.file_list)


bad = []
for group in apt_pkg.parse_depends(sys.argv[1], False):
    ok = False
    for name, want, op in group:
        try:
            pkg = cache[name]
        except KeyError:
            continue
        for ver in pkg.version_list:
            if from_distro(ver) and (not want or apt_pkg.check_dep(ver.ver_str, op, want)):
                ok = True
                break
        if ok:
            break
    if not ok:
        bad.append(" | ".join("%s (%s %s)" % (n, o, w) if w else n for n, w, o in group))
for b in bad:
    print("check-depends: not satisfiable from the distribution archive: %s" % b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
