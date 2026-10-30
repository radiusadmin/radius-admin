#!/bin/bash
# Start a throwaway slapd emulating AD on ldaps://dc01.example.net:636 (127.0.0.1).
# Usage: start-slapd.sh <benchdir> <bindpw>
set -euo pipefail
B=${1:?benchdir}; PW=${2:?bindpw}
HERE=$(cd "$(dirname "$0")" && pwd)
D=$B/slapd; rm -rf "$D"; mkdir -p "$D/db"
cp "$B/pki/dc.pem" "$B/pki/dc.key" "$B/pki/ca.pem" "$D/"
cat > "$D/slapd.conf" <<CONF
modulepath /usr/lib/ldap
moduleload nestgroup
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include $HERE/ad-emul.schema
pidfile $D/slapd.pid
modulepath /usr/lib/ldap
moduleload back_mdb
TLSCertificateFile $D/dc.pem
TLSCertificateKeyFile $D/dc.key
TLSCACertificateFile $D/ca.pem
TLSProtocolMin 3.3
sizelimit unlimited
database mdb
suffix "dc=example,dc=net"
rootdn "cn=admin,dc=example,dc=net"
rootpw "$PW"
directory $D/db
# Nested groups: a (member=<dn>) filter also matches groups that contain <dn>
# indirectly. Emulates AD's LDAP_MATCHING_RULE_IN_CHAIN, which OpenLDAP lacks.
overlay nestgroup
nestgroup-member member
nestgroup-memberof memberOf
nestgroup-base "OU=Groups,DC=example,DC=net"
nestgroup-flags member-filter
access to attrs=userPassword by anonymous auth by * none
access to * by dn.exact="CN=RADIUS LDAP Bind,OU=Service Accounts,DC=example,DC=net" read by * none
CONF
python3 - "$HERE/ad-emul.ldif.in" "$D/data.ldif" "$PW" <<'PY'
import sys
src, dst, pw = sys.argv[1:4]
s = open(src).read().replace("@BINDPW@", pw)
names = ["Many Group %03d" % i for i in range(1, 300)] + ["Zz Many 300"]
dn = lambda n: "CN=%s,OU=Groups,DC=example,DC=net" % n
s = s.replace("@PC8_MEMBEROF@\n", "".join("memberOf: %s\n" % dn(n) for n in names))
s = s.replace("@PC8_GROUPS@\n", "".join(
    "dn: %s\nobjectClass: group\ncn: %s\nmember: CN=PC8,OU=Computers,DC=example,DC=net\n\n" % (dn(n), n)
    for n in names))
open(dst, "w").write(s)
PY
slapadd -q -f "$D/slapd.conf" -l "$D/data.ldif"
slapd -f "$D/slapd.conf" -h "ldaps://127.0.0.1:636/" -d 0 > "$D/slapd.log" 2>&1 &
for _ in $(seq 1 50); do [ -s "$D/slapd.pid" ] && break; sleep 0.1; done
echo "slapd pid $(cat "$D/slapd.pid")"
