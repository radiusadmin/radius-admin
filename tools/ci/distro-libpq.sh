#!/bin/bash
# distro-libpq.sh : make libpq5/libpq-dev the distribution's own build, before building the
# radius-admin-freeradius package. GitHub's runner image carries apt.postgresql.org, whose newer
# libpq would otherwise be what the package is built and tested against (a package built that way
# required "libpq5 (>= 18.7-1.pgdg…)" and did not install on stock Ubuntu). CI only, as root.
set -euo pipefail
cat > /etc/apt/preferences.d/radius-admin-distro-libpq <<'EOF'
# radius-admin CI: libpq from the distribution archive, also as a downgrade
Package: libpq5 libpq-dev
Pin: release o=Ubuntu
Pin-Priority: 1001
EOF
apt-get update -q
apt-get install -y -q --allow-downgrades --no-install-recommends libpq5 libpq-dev
v=$(dpkg-query -W -f '${Version}' libpq5)
case $v in
    *pgdg*) echo "libpq5 is still $v (not the distribution's)" >&2; exit 1 ;;
esac
echo "libpq5 $v from the distribution archive"
