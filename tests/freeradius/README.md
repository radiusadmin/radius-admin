# FreeRADIUS test bench (sandbox only)

Functional tests for the `freeradius/` deliverables and the policy rendered by
`app/radius_admin/unlang.py`, against a real FreeRADIUS 3.2.10 built with
`--enable-fips-workaround`. **Never run this on the production server.** It adds
`/etc/hosts` entries, starts slapd and an OCSP responder, and writes to the `radius`
PostgreSQL database (test users `t-*`, MACs `AA-BB-CC-00-00-*`; it empties
`radpostauth`, **replaces `ui.access_rule`** with the seed rules, resets
`admin_subnet`/`admin_priv15`, and stops and starts the `16/main` cluster for the
database-down test).

## Prerequisites (Ubuntu 24.04, as root)

```
apt install build-essential libtalloc-dev libssl-dev libpq-dev libldap-dev \
            slapd ldap-utils postgresql-16 python3-psycopg2 sqlite3 \
            libnl-3-dev libnl-genl-3-dev libnl-route-3-dev
# FreeRADIUS 3.2.10 (latest stable release; the same build serves standard and FIPS mode)
# from the signed release tarball, verified with the packages@freeradius.org key
# (fingerprint BF23 84EC 6938 B974 4B03  E2A6 20E3 7C25 995B 4F85):
U=https://github.com/FreeRADIUS/freeradius-server/releases/download/release_3_2_10
curl -fLO $U/freeradius-server-3.2.10.tar.gz -fLO $U/freeradius-server-3.2.10.tar.gz.sig
curl -fsSL https://freeradius.org/pgp/packages@freeradius.org | gpg --import
gpg --verify freeradius-server-3.2.10.tar.gz.sig freeradius-server-3.2.10.tar.gz
# into a private prefix
./configure --prefix=$PREFIX --enable-fips-workaround && make && make install
# eapol_test (wpa 2.10 source, `apt-get source wpa`): in wpa_supplicant/
#   cp defconfig .config; enable CONFIG_EAPOL_TEST=y; comment out CONFIG_CTRL_IFACE_DBUS*
#   (no D-Bus headers needed); remove -Werror (gcc 13); make eapol_test
```

Sandbox setup the scripts expect:

* PostgreSQL loaded from `sql/00..40`, plus pg_hba/pg_ident as in SPEC section 3
  (`radiusmap freerad radius_fr`), and an OS user `freerad` (radiusd drops to it).
* `/etc/hosts`: `127.0.0.1 dc01.example.net pki.example.net`
  so the unchanged production LDAP server and OCSP URL resolve to the emulators.
* Loopback aliases used as RADIUS client source addresses:
  `ip addr add 192.0.2.10/32 dev lo; ip addr add 198.51.100.10/32 dev lo;
  ip addr add 203.0.113.201/32 dev lo`.

## Run

```
python3 run-tests.py --prefix $PREFIX --bench $WORKDIR --eapol-test /path/to/eapol_test
```

| File | Purpose |
|---|---|
| `run-tests.py` | orchestrates everything, prints PASS/FAIL per case, exit 0 iff all pass |
| `build-raddb.sh` | stock 3.2.10 raddb + deliverables + production module/site set + rendered policy and clients |
| `render.py` | renders policy and clients with `unlang.py` (`render_policy(custom)`); `SEED_RULES` (SPEC section 8) is loaded into `ui.access_rule` |
| `make-test-pki.sh` | throwaway RSA-3072/SHA-256 PKI: Root, Issuing, server, DC, OCSP signer, pc1..pc5 (pc5 revoked), no-SAN and rogue-CA client certs; `ca.pem` = Issuing + Root as in production |
| `start-slapd.sh`, `ad-emul.schema`, `ad-emul.ldif.in` | OpenLDAP over LDAPS emulating the AD bits used: `computer` objects with `dNSHostName` and `memberOf`, `group` objects with `member`,, the bind account DN, nested groups (pc6 is in `R&D Lab (Bldg-2)`, which is a member of Wired-Utility) and a group named `Guests,Wired-Support`. **OpenLDAP has no AD in-chain matching rule (1.2.840.113556.1.4.1941)**: a filter using it returns nothing. So `build-raddb.sh` swaps the bench copy's `membership_filter` for `(member=...)`, and `slapo-nestgroup` (`nestgroup-flags member-filter`) makes that filter match transitively, as AD's in-chain rule does. |
| `pbkdf2_hash.py` | makes the `{X-PBKDF2}HMACSHA2+256:...` value (600000 iterations) |

Test-only substitutions made by `build-raddb.sh`, all in the bench copy only:
`/etc/freeradius/certs/site/` is replaced by the bench path, the LDAP bind password
`REDACTED` by the test password, the in-chain `membership_filter` by `(member=...)`
(see above), `user/group = freerad` is set, and the two IPv6 listeners are commented
out when the kernel has no IPv6.

## What is covered

* `radiusd -XC` with the generated policy.
* PAP switch admin: PBKDF2 Accept (with and without priv15 Cisco-AVPair), wrong
  password, user not in `net-admins`, a switch outside 192.0.2.0/24, legacy `$6$`
  Crypt-Password Accept, unknown user, and CHAP rejected.
* MAB: 5 user-name formats Accept with VLAN; no Calling-Station-Id Accept; unknown,
  disabled, Calling-Station-Id mismatch, non-MAC Calling-Station-Id, no
  NAS-Port-Type=Ethernet and 13 hex digits are all Reject.
* EAP-TLS with `eapol_test`: wired VLANs 500/510/520 including group priority; no group;
  each SSID mapping; SSID without membership; unknown SSID; a suffix trick; the
  admin-branch shape; no DNS SAN; an unknown CA; a revoked cert (OCSP). Every case
  must show a successful OCSP check. PEAP, TTLS and MD5 are rejected.
* Nested AD group membership gives the right VLAN. A group name containing a comma
  cannot impersonate another group.
* SQL injection: FreeRADIUS 3.2 un-escapes `\047`, `\\` and similar sequences in `%{sql:...}`
  arguments *after* SQL escaping, so request and directory data are sent only hex-encoded.
  The bench sends payloads in Called-Station-Id (`\047`, `\x27`, `\\`, `'`, `%{exec:}`,
  `\n`, `\000`), in User-Name (PAP and MAB), as an unknown NAS-Port-Type, and as AD group
  cns containing `\047` and `'`. Every one must be rejected or matched literally, with
  tables intact and no delay.
* Audit of the whole debug log: every `radius_admin_*_hex()` call carries hex-only
  arguments, and the text functions are never called.
* A machine in 300 groups (the only matching group is last) gets the right VLAN.
* Group names with spaces, `&`, `()`, a comma and a quote round-trip literally.
* LIVE (radiusd keeps running, same PID): change a VLAN, disable a rule, add a rule,
  add an SSID with space, dot and dash, change `admin_subnet` (including /32), and
  toggle priv15. Each change shows on the next authentication.
* DB down: EAP-TLS, PAP admin and MAB are all rejected (fail closed). After the DB is
  back, auth recovers after the sql pool `retry_delay` (30 s) with no restart.
* `radpostauth`: authmethod, vlan, certsan and nasipaddress are correct, the REJECT
  path is logged, and no password text appears anywhere.

Not covered: real AD (the in-chain rule itself, only its effect emulated),
real Catalyst 1300 / AP attribute formats, the production OCSP responder, and IPv6.
