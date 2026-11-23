# radius-admin — Runbook

Target: `radius01` / `radius.example.net`, Ubuntu 24.04.5 + Ubuntu Pro FIPS,
FreeRADIUS 3.2.10 (custom build, `--enable-fips-workaround`), single RADIUS server.
All commands run as root (`sudo -i`) from the repository checkout, e.g.
`/root/radius-admin`, unless stated otherwise.

Contents: 1 Prerequisites · 2 Plan the maintenance window · 3 Install step by step ·
4 Verify · 5 Catalyst 1300 notes · 6 Day-to-day: apply / rollback from the UI ·
7 Backup and restore · 8 Logs · 9 Upgrading · 10 Rollback of the whole change ·
11 Troubleshooting · 12 Clean-up and secure disposal

---

## 1. Prerequisites

| Item | How to check |
|---|---|
| Kernel FIPS on (FIPS mode only) | `cat /proc/sys/crypto/fips_enabled` → `1` |
| Ubuntu Pro FIPS stream (FIPS mode only) | `pro status` (see SECURITY.md §1 about `fips-updates` vs `fips`) |
| Internal apt mirror reachable | `apt-get update` |
| Packages available | `apt-cache policy postgresql nginx python3-flask python3-psycopg2 gunicorn python3-cryptography python3-qrcode nftables` |
| FreeRADIUS unit + binary | new server: nothing to do, the release bundle carries `packages/radius-admin-freeradius_*.deb` (§1.2). Existing server: `systemctl list-unit-files 'freeradius*' 'radiusd*'`; `command -v radiusd freeradius` |
| **`rlm_sql_postgresql.so` in the custom build** | existing builds only, see below |
| management address on this host | `ip -4 addr` (an address in 192.0.2.0/24) |
| DNS for `pki.example.net` | `getent hosts pki.example.net` (nginx refuses to start otherwise) |
| UI certificate | issued by pki.example.net from the CSR made by `deploy/make-csr.sh` |
| DNS record `radius.example.net` → management address | `getent hosts radius.example.net` from an admin PC |
| Backup of the VM | hypervisor snapshot taken right before the window |

`deploy/preflight.sh` checks all of this read-only and exits non-zero on blocking
problems. Run it a few days before the window:

```bash
sudo ./deploy/preflight.sh | tee /root/preflight-$(date +%F).txt
```

### 1.1 The PostgreSQL driver of the custom FreeRADIUS build

FreeRADIUS only builds `rlm_sql_postgresql` when `libpq-dev` was installed at
`./configure` time. Preflight locates the module directory (RUNPATH of `radiusd`, or
`<prefix>/lib`) and reports `rlm_sql_postgresql.so present` or **MISSING**. To check
by hand:

```bash
R=$(command -v radiusd || command -v freeradius); echo $R
readelf -d "$R" | grep -i path        # module dir, e.g. /usr/local/lib
ls -l /usr/local/lib/rlm_sql_postgresql.so /usr/lib/freeradius/rlm_sql_postgresql.so 2>/dev/null
```

If it is missing, rebuild **in the original source tree** with the original flags:

```bash
apt-get install libpq-dev
cd /usr/local/src/freeradius-server-3.2.10      # wherever the original build lives
head -n 10 config.log                            # shows the exact original ./configure line
./configure <SAME FLAGS AS BEFORE, including --enable-fips-workaround>
grep -A1 'rlm_sql_postgresql' config.log | head  #   or watch for "rlm_sql_postgresql ... OK"
make -j"$(nproc)"
make install                                     # in the maintenance window; then
systemctl restart freeradius && systemctl status freeradius
```

Do this rebuild *before* the main window (it does not change behaviour; it only adds a
module). `make install` does not overwrite existing files under `/etc/freeradius`
(FreeRADIUS installs raddb files only when missing), but take the tarball backup first:
`tar -czpf /root/freeradius-etc-prebuild.tgz /etc/freeradius`.
Production builds should not use `--enable-developer` (preflight warns if radiusd was
built with `WITH_VERIFY_PTR`).

### 1.2 The bundled FreeRADIUS package

A release bundle contains `packages/radius-admin-freeradius_3.2.10-<n>~<distro>_amd64.deb`: the
signed upstream 3.2.10 release built with `--enable-fips-workaround` (one build for both modes),
installed under `/opt/radius-admin-freeradius`, with the unit `freeradius.service`. The installer's
`fr-package` phase installs it on a server that has no FreeRADIUS:

```bash
sudo ./deploy/install.sh --phase fr-package       # also part of a full install
```

- The package is refused unless it matches its `.sha384` file.
- It never owns or changes `/etc/freeradius`. On first install it creates that directory from
  the stock configuration only if it does not exist; upgrades, reinstalls and even
  `apt-get purge` leave it alone.
- It never starts or restarts radiusd. The `freeradius` phase enables the unit once
  `radiusd -XC` passes and restarts it with `--restart-freeradius`.
- A FreeRADIUS installed another way (the distribution's `freeradius` package or a source build)
  is kept; the phase warns and does nothing. Moving such a server onto the package is a
  separate, planned step.
- Upgrades: a release with a newer package upgrades it in the `fr-package` phase (also from
  `update.sh`). The running daemon keeps the old binaries until you restart it in a window
  (`systemctl restart freeradius`, or `--restart-freeradius`).

Building the package (on the distribution release it is for, as root, network access to GitHub
and freeradius.org):

```bash
sudo tools/package/build-freeradius-deb.sh            # -> packages/*.deb, *.sha384, packages/source/
sudo bash tests/package/test_freeradius_deb.sh         # inspect the package
tools/package/make-bundle.sh                            # -> dist/radius-admin-<version>.tar.gz
```

The upstream source tarball and its signature are kept in `packages/source/` and ship in the
bundle (FreeRADIUS is GPLv2). `/opt/radius-admin-freeradius/share/doc/radius-admin-freeradius/SOURCE`
records the URL, SHA-256, signing key and configure line.

---

## 2. Plan the maintenance window

Expected RADIUS impact: one FreeRADIUS restart (a few seconds) and, if a rollback is
needed, a second one. Allow 2 hours including verification.

* Have console access to at least one Catalyst 1300 via a **local** account (in case PAP
  admin logins break) and to the server (hypervisor console).
* Have one Windows machine with a valid machine certificate on a wired 802.1X port,
  one on each SSID, and one MAB device (printer etc.).
* Announce: switch admin passwords are reset to new PBKDF2 hashes during/after the
  migration (see §12).

---

## 3. Install step by step

Every phase is idempotent and can be re-run. `install.sh --help` lists options.

**Getting the release.** Clone the repository and run the installer from the clone:

```bash
git clone --depth 1 https://github.com/radiusadmin/radius-admin.git
sudo radius-admin/deploy/install.sh
```

A clone has no FreeRADIUS package, no signed integrations catalog and no `BUILD.json`, so a full
install from it downloads the release of the clone's `VERSION` from GitHub, checks the manifest
signature against the clone's `deploy/keys/update-signing.pem` and the bundle's SHA-384, unpacks it
to `/usr/local/src/radius-admin-<version>` and continues with that bundle's installer, with the
same options. A release bundle copied to the server (`tar -xzf radius-admin-<version>.tar.gz`)
installs as it is and needs no download, as do `--phase`/`--from` runs. `--from-checkout` installs
a checkout without downloading anything (development; the result is a `local` build).

**Crypto mode (choose before the first install).** Standard mode is the default. FIPS mode is an
explicit choice: answers key `fips: on`, the last interactive question, or `install.sh --fips`
(`--standard-mode` or `fips: off` choose standard mode explicitly). FIPS mode is refused unless
the host's kernel already runs in FIPS mode (`/proc/sys/crypto/fips_enabled` = 1: Ubuntu Pro,
`pro enable fips-updates`, reboot). The first install writes the choice as `require_fips` in
`/etc/radius-admin/radius-admin.conf`; later runs and updates never change it (an option or answer
that differs is ignored with a warning), and `install.sh --print-settings` shows the mode in use.
Preflight treats its FIPS checks as blocking only in FIPS mode (`preflight.sh --fips-mode on|off`,
default: the installed `require_fips`, else standard mode).

### 3.0 Before the window

```bash
sudo ./deploy/preflight.sh                # FIPS mode: sudo ./deploy/preflight.sh --fips-mode on
sudo ./deploy/make-csr.sh                 # ECDSA P-384; add --ip <management-IP> if wanted; --rsa for RSA-3072
cat /etc/radius-admin/tls/server.csr      # submit to pki.example.net (TLS Web Server template)
# when issued (leaf first, then Example-IssuingCA):
sudo install -o root -g root -m 0644 radius.example.net-chain.pem /etc/radius-admin/tls/server.crt
sudo ./deploy/install.sh --phase packages,nginx-update,users -y     # no service impact
```

`nginx-update` upgrades nginx when it is older than the oldest build with the security fixes
the portal needs (`RA_NGINX_MIN_VERSION` in `deploy/lib.sh`, currently `1.24.0-2ubuntu7.20`;
see SECURITY.md 2.v). Preflight warns about an old nginx; the phase refreshes the package lists
if needed, upgrades it when the mirror has a fixed build and restarts it if it was running. If
the mirror has none (no `noble-security`), it warns and the install continues. Check with
`dpkg-query -W nginx`.

Verify: `id radius-admin`, `ls -l /etc/radius-admin/keys/data.key` →
`-r-------- radius-admin radius-admin 32`. **Back up `data.key` offline** (encrypted
media / password vault): without it, all TOTP enrolments must be redone.

### 3.1 PostgreSQL (no RADIUS impact)

```bash
sudo ./deploy/install.sh --phase postgres
```

Inserts the managed block from `deploy/postgres/pg_hba.conf.snippet` *before* the first
rule of `pg_hba.conf`, appends the map to `pg_ident.conf` (originals saved as
`*.pre-radius-admin`), sets `listen_addresses = ''` via
`/etc/postgresql/16/main/conf.d/radius-admin.conf`, restarts PostgreSQL once, and loads
`sql/00…30-*.sql` as `postgres`. It then proves that `freerad` → `radius_fr` and
`radius-admin` → `radius_admin` work and that `nobody` cannot use those roles.

Verify:

```bash
sudo -u postgres psql -Atc 'SHOW listen_addresses'                 # (empty)
ss -ltnp | grep 5432                                               # nothing
sudo -u freerad psql "dbname=radius host=/var/run/postgresql user=radius_fr" -Atc 'select current_user'
```

### 3.2 Window starts — migrate the data

```bash
sudo ./deploy/install.sh --phase migrate --confirm-migrate
```

Takes a consistent `sqlite3 .backup` snapshot to
`/var/backups/radius-admin/freeradius-sqlite-<ts>.db` (0600; **contains cleartext
passwords**, see §12), then runs `deploy/migrate_sqlite_to_pg.py` on that snapshot —
first with `--dry-run` (rolls back), then for real. The script reads its inputs as root,
drops to the `postgres` user and writes everything in one transaction; it refuses to
run if the target tables already contain rows (`--force` replaces them — run it by hand
if you really need that). The migration imports radcheck/radusergroup/… unchanged, radpostauth and
radacct history **without** the `pass` column, the RADIUS clients from `clients.conf` +
`switches.conf` into `ui.radius_client`, and the seed access rules/settings
(`admin_priv15 = false` = current behaviour).

Verify:

```bash
sudo -u postgres psql -d radius -c 'select count(*) from ui.radius_client' \
     -c 'select priority,connection,ssid,ad_group,vlan from ui.access_rule order by id' \
     -c 'select username,attribute from radcheck'
```

Expect 26 clients, all enabled (25 switches + wifi-aps; `localhost`/`localhost_ipv6` are
skipped and stay in `clients.conf`), 6 rules, 3 `Crypt-Password` rows. The script needs
the PostgreSQL unix socket, and aborts with **nothing written** if any client secret
contains a quote, backslash or whitespace — fix that secret on the switch and in
`switches.conf`/`clients.conf` first.

### 3.3 FreeRADIUS configuration

```bash
sudo ./deploy/install.sh --phase freeradius            # validates, does NOT restart
sudo ./deploy/install.sh --phase freeradius --restart-freeradius   # or restart here
```

What it does, in order:

1. `tar` of `/etc/freeradius` → `/var/backups/radius-admin/freeradius-<ts>.tar.gz` (0600).
   **This tarball is the rollback** (`rollback.sh --tarball …`).
2. Copies the files from `freeradius/` (sql → postgresql, eap TLS-only, ldap
   hardening, default site, clients.conf with `$INCLUDE radius-admin-clients.conf`,
   users file without bob/doug, queries.conf without password logging). The new
   `clients.conf` keeps only `client localhost`; the `wifi-aps` block and
   `$INCLUDE switches.conf` are replaced by `$INCLUDE radius-admin-clients.conf` (those
   clients now come from the database). Secrets that are `REDACTED` placeholders in the
   repo (LDAP bind password, `localhost` client secret) are carried over from the live
   files; if the live `client localhost` secret or LDAP password cannot be found the
   phase **stops before changing anything**. On an upgrade the live LDAP connection
   settings and, in `mods-available/eap`, the EAP certificate, CA, CRL and OCSP settings
   (`ocsp { url }` among them) are kept too (SPEC §4 item 5); the phase prints which keys it
   kept. After the phase, `diff` the new `mods-available/eap` against the backup tarball if
   EAP-TLS logins fail.
3. Renders the initial `policy.d/radius-admin` and `radius-admin-clients.conf` from the
   database with `python3 -m radius_admin.cli render` (as `radius-admin`) and installs
   them root:freerad 0640; also leaves them in the app's staging dir.
4. Removes the symlinks listed in `freeradius/modules-to-disable.txt` (including
   `exec`: nothing in the new configuration runs external programs) and
   `sites-enabled/inner-tunnel`. Raises `max_request_time` in `radiusd.conf` to 90 s when it is
   lower (stock: 30 s; a higher value is kept): FreeRADIUS cuts every home server's wait to it,
   and second-factor providers wait up to 60 s for the person (§6.9b).
5. `radiusd -XC` (run as root, like the service — radiusd drops to `freerad` itself). On failure the tarball is restored at once
   (the running daemon was never touched).
6. With `--restart-freeradius`: restart, wait ≤ 15 s for active + UDP 1812, otherwise
   restore + restart.

Watch the live log while you test (§4): `journalctl -fu freeradius` (or
`tail -f /var/log/freeradius/radius.log`). For deep debugging stop the service and run
`radiusd -X` in a terminal (`systemctl stop freeradius; radiusd -X | tee /root/radiusd-X.log`).

### 3.4 Web UI, nginx and firewall

```bash
sudo ./deploy/install.sh --phase app,nginx,firewall
```

* **app**: code to `/opt/radius-admin/app`, `/etc/radius-admin/radius-admin.conf`
  (root:radius-admin 0640), helper to `/usr/local/libexec/radius-admin/`,
  `/etc/radius-admin/helper.conf` (root:root 0644, with the **detected** FreeRADIUS
  unit and radiusd path — check them), systemd units, rsyslog/logrotate snippets;
  enables `radius-admin-helper.socket` and `radius-admin.service`, checks the app
  answers on its socket and the helper answers `status`.
* **nginx**: renders `deploy/nginx/radius-admin.conf` with the management address
  (auto-detected, or `--listen-ip`), DNS resolvers for OCSP (from `resolvectl dns`,
  falling back to `/etc/resolv.conf`; override with `--resolver "10.x.x.x 10.y.y.y"`),
  copies `/etc/freeradius/certs/site/ca.pem` → `/etc/radius-admin/tls/client-ca.pem`,
  checks key/cert match and SAN, `nginx -t`, reload. The Debian default site (port
  80) is disabled; nothing listens on port 80. Also installs the drop-in
  `/etc/systemd/system/nginx.service.d/radius-admin.conf`: nginx resolves the OCSP
  responder when it starts and refuses to start if that lookup fails, so the drop-in
  starts it after `network-online.target` and restarts it every 30 seconds after a failure
  (no start limit). A short DNS outage at boot or while `unattended-upgrades` restarts
  nginx then no longer leaves the portal down. Check with `systemctl cat nginx`.
* **firewall**: detects ufw / nftables / iptables. Always loads the self-contained
  nftables table `inet radius_admin` (TCP 443 to the management address accepted only from
  192.0.2.0/24, everything else to 443 dropped; RADIUS, SSH and all other ports are
  untouched) via `radius-admin-firewall.service`. If ufw is active it additionally adds
  `ufw allow proto tcp from 192.0.2.0/24 to <ip> port 443`. If a site
  `/etc/nftables.conf` has an input chain with `policy drop`, the installer prints the
  accept rule you must add there.

### 3.5 First administrator

```bash
sudo -u radius-admin env RADIUS_ADMIN_CONFIG=/etc/radius-admin/radius-admin.conf \
     PYTHONPATH=/opt/radius-admin/app python3 -m radius_admin.cli create-admin --username jdoe --role admin
```

The temporary password is printed once. From an admin PC in 192.0.2.0/24 open
`https://radius.example.net/`, acknowledge the banner, sign in, set a new password
(≥ 15 characters) and enrol TOTP (or register your site client certificate). Create the
other admins in the UI (Admins page) — each gets their own account; do not share.

---

## 4. Verify

### 4.1 Platform

```bash
systemctl status freeradius radius-admin radius-admin-helper.socket nginx postgresql@16-main radius-admin-firewall
ss -lunp | grep -E ':1812|:1813'                  # radiusd
ss -ltnp | grep -E ':443|:80 |:5432'              # only nginx on <management-IP>:443
sudo -u radius-admin env RADIUS_ADMIN_CONFIG=/etc/radius-admin/radius-admin.conf PYTHONPATH=/opt/radius-admin/app python3 -m radius_admin.cli check-fips   # FIPS mode
nft list table inet radius_admin
curl -sI https://radius.example.net/login | head -n 5     # from an admin PC: 200 + HSTS
curl -m 5 https://radius.example.net/                      # from a NON-admin subnet: must time out
openssl s_client -connect radius.example.net:443 -tls1_1 </dev/null   # must fail
```

### 4.2 RADIUS functional tests

`radtest` ships with FreeRADIUS. Tests from the server itself use the `localhost` client
(secret in `/etc/freeradius/clients.conf`). Because the admin-login policy also checks
the **source address** (192.0.2.0/24), a PAP admin test from 127.0.0.1 is expected to
be *rejected* — test admin logins from a switch, or with `-x` from a host on the management subnet
that is configured as a client.

**Switch admin (PAP), real switch — the definitive test.** On a Catalyst 1300 that
uses RADIUS for management login, log in via SSH with a `net-admins` account. Expect
access at privilege 15 (see §5 regarding `priv-lvl`). In the UI → Auth log, the entry
shows method `pap-admin`, reply `Access-Accept`.

**Switch admin from the server (negative test, proves the source check):**

```bash
radtest -t pap jdoe 'the-password' 127.0.0.1 0 '<localhost secret>'   # → Access-Reject (source not in 192.0.2.0/24)
```

**MAB device** (register the MAC in the UI first, e.g. `00-11-22-33-44-55` → VLAN 40):

```bash
cat <<'EOF' | radclient -x 127.0.0.1 auth '<localhost secret>'
User-Name = "001122334455"
User-Password = "001122334455"
NAS-Port-Type = Ethernet
Calling-Station-Id = "00-11-22-33-44-55"
Service-Type = Call-Check
EOF
# expect Access-Accept with Tunnel-Type = VLAN, Tunnel-Medium-Type = IEEE-802, Tunnel-Private-Group-Id = "40"
# an unregistered MAC, or a Calling-Station-Id different from User-Name → Access-Reject
```

**EAP-TLS (real machine).** `radtest` cannot do EAP-TLS. Use a domain-joined Windows
PC with its machine certificate:

1. Wired: plug into an 802.1X port; `netsh lan show interfaces` → "Authentication
   succeeded"; on the switch `show dot1x interface gi1/0/x` / check VLAN assignment.
2. Wireless: connect to `Example_Main` and `Example_Admin`; check the client IP is in the
   expected VLAN.
3. In the UI → Auth log: method `eap-tls`, VLAN column = expected VLAN, cert SAN = the
   machine's DNS name.

Optional lab test with `eapol_test` (wpa_supplicant source, not in Ubuntu main) using a
test machine cert issued by the site PKI:
`eapol_test -c tls.conf -a <server IP> -s <client secret>` with
`eap=TLS identity="host/pc01.example.net" client_cert=… private_key=… ca_cert=…`.

**Negative EAP tests:** a revoked certificate (OCSP) is rejected; a machine not in any
AD group of the rules is rejected; an unknown SSID is rejected.

**Trust anchors changed:** `ca_path = ${cadir}` was removed from `mods-available/eap`
and `reject_unknown_intermediate_ca = yes` is set. Supplicant certificates must now
chain to **Example-IssuingCA → Example-RootCA** (the two certificates in
`/etc/freeradius/certs/site/ca.pem`); the FreeRADIUS bootstrap test CA in
`/etc/freeradius/certs/` is no longer trusted. A certificate from any other issuer,
including a test cert from that CA, must be rejected — include one such negative test.

**Admin-subnet check:** the generated policy checks
`&Packet-Src-IP-Address <= 192.0.2.0/24` (unlang "contained in network"); changing
the `admin_subnet` setting in the UI changes this line on the next Apply.

### 4.3 UI apply cycle

In the UI change a client description → Apply page shows the diff → Validate (shows
`radiusd -XC` output) → Apply → success with backup id. `journalctl -t radius-admin-helper`
shows the action. Then roll back to that backup id from the Apply history.

### 4.4 Test harnesses (sandbox only — never on production)

`tests/freeradius/` (see its README) and `tests/migration/test_migrate.sh` reproduce
the FreeRADIUS behaviour and the migration against a lab build. They add `/etc/hosts`
entries, start slapd/OCSP emulators, insert test users/MACs and **truncate
`radpostauth`** in the database they point at. Run them only on a lab VM, never on
`radius01`. `tests/helper/` is safe anywhere (temp dirs, fake binaries) but
needs root.

---

## 5. Cisco Catalyst 1300 notes

* **MAB must use RADIUS PAP, not EAP-MD5.** EAP-MD5 is removed from the server (not
  FIPS-acceptable, and `eap md5` is gone from `mods-available/eap`). On the C1300 web
  UI: *Security → 802.1X/MAC/Web Authentication → Port Authentication*, MAC
  authentication method = **RADIUS (PAP)**. (CLI: `dot1x mac-auth mac-only` and
  `dot1x mac-authentication-method radius` — exact keyword varies by firmware; check
  `show dot1x` after the change.)
* **Verify the attributes the C1300 actually sends** (look at a request with
  `radiusd -X` in the maintenance window, or in the Auth log): the policy tells request
  types apart by attributes, so this must hold on the real switch —
  * admin logins (SSH / console / web via RADIUS) must **not** carry
    `NAS-Port-Type = Ethernet` (and no `Called-Station-Id`), otherwise they are treated
    as 802.1X/MAB and rejected;
  * MAB requests must carry `NAS-Port-Type = Ethernet` and `User-Name` = the MAC (any
    format), without EAP-Message.
* **MAC format: any.** The policy accepts `aabbccddeeff`, `AA-BB-CC-DD-EE-FF`,
  `aa:bb:…`, `aabb.ccdd.eeff`, any case; it normalises to `AA-BB-CC-DD-EE-FF` and
  rejects if `Calling-Station-Id` is a different MAC.
* **Privilege level 15 for admins.** Today all switch admins land at priv 15 without
  a reply attribute (the switch default for RADIUS users). The UI setting
  `admin_priv15` adds `Cisco-AVPair = "shell:priv-lvl=15"`; it is **off** after
  migration. The setting is global (single RADIUS server), so test it with **one**
  switch watched closely: keep an SSH session open on that switch (and a local
  fallback account), turn the setting on, Apply, open a *new* SSH login, run
  `show privilege` (expect 15) and a config command. If login fails or lands at a
  lower level, turn it off and Apply again at once. Then spot-check a few more switches
  before leaving it on.
* **Message-Authenticator (BlastRADIUS, CVE-2024-3596).** Clients are migrated with
  `require_message_authenticator = auto` (switches) / `yes` (wifi-aps). With `auto`,
  FreeRADIUS logs whether a client sends Message-Authenticator. For each switch:
  watch `journalctl -u freeradius | grep -i message-authenticator` (or radius.log) for a
  few days; when a switch is seen sending it on every request, set that client to
  **yes** in the UI and Apply. Update firmware on switches that never send it. Also set
  `limit_proxy_state = yes` where offered.
* **RadSec (RADIUS over TLS)** is not assumed to be supported by the C1300; RADIUS stays
  on UDP 1812/1813 inside the management VLAN.
* **Shared secrets**: use the UI's *Generate* (32 random alphanumerics) when rotating;
  update the switch (`radius-server host <ip> key <secret>`) right after Apply. Rotate
  one switch at a time.

---

## 6. Day-to-day: apply and rollback from the UI

* Changes to **clients, access rules, custom policy, settings** are *pending* until
  applied. The dashboard shows a banner. Apply page → review the diff of both generated
  files → **Validate** (no change) → **Apply** (step-up re-authentication required).
* Apply = helper validates a private raddb copy as `freerad` → backs up the two live
  files to `/var/lib/radius-admin-helper/backups/<UTC ts>/` → installs them atomically →
  `systemctl restart freeradius` → waits ≤ 15 s for *active* and UDP 1812 → on failure
  restores the backup and restarts again (`rolled_back: true` in the result).
* **Switch admins and MAB devices are live immediately** (SQL) — no apply needed.
* **Rollback** (admin role): Apply page → history → pick a backup id → Rollback. The
  helper keeps the newest 50 backups.
* Only one apply/rollback runs at a time (lock). An apply takes typically 5–20 s; the
  UI waits up to 120 s.

---

### 6.1 Account recovery from the console (locked out of the UI)

If another admin can sign in, use **UI admins** instead (unlock / reset password /
reset two-factor). If nobody can, recover from the server console. These commands
must run as the `radius-admin` user (database access is by OS user), are recorded in
the audit log and syslog with your sudo user, and need no web access:

```bash
RA="sudo -u radius-admin env RADIUS_ADMIN_CONFIG=/etc/radius-admin/radius-admin.conf PYTHONPATH=/opt/radius-admin/app python3 -m radius_admin.cli"

$RA unlock --username jdoe                      # too many failed sign-ins (also expires by itself after 15 min)
$RA reset-password --username jdoe              # forgot password: prints a one-time temporary password,
                                                #   unlocks, re-enables, ends all sessions
$RA reset-password --username jdoe --reset-mfa  # lost phone/certificate too: also removes two-factor
$RA reset-mfa --username jdoe                   # two-factor only
```

After `reset-password` sign in with the temporary password; you must set a new one
(at least 15 characters, not one of your last 5) and, if two-factor was reset, enrol
it again before anything else. `create-admin` (section 3.5) still works for adding a
new account.

### 6.2 Importing RADIUS clients from CSV

UI → RADIUS clients → **Import CSV** (operator or admin). Columns:
`ip,secret,hostname,secret_type,key_scope,dot1x_ports`. A header row is recommended;
without one the columns are read in that order and `key_scope` / `dot1x_ports` may be
left off. `secret_type` is `plaintext`, `encrypted` or `none`; `key_scope` is `server`
(per-server key), `global` (the switch uses its global `radius-server key`) or `none`
(empty = none); `dot1x_ports` is free text kept for reference, e.g.
`gi1/0/1-20,gi1/0/23` (quoted or not: when it is the last column, unquoted commas are
kept as part of the list). The client list shows the first two port groups and a
"+N more" pop-up with the full list and port counts. A template is on the import page.

* The whole file is checked first; one bad row means nothing is imported. A preview
  shows each row as new / update / unchanged / skip before you confirm (password + 2FA).
* Existing clients are matched by IP, then by hostname, so an import can rename a client
  or change its IP. Choose "update existing" or "skip existing" per import.
* **Encrypted or missing keys:** FreeRADIUS needs the plaintext shared secret. Encrypted
  values are never stored. New clients with `encrypted`/`none` are created **disabled**
  with a notice and cannot be enabled until you enter or generate a plaintext key on the
  client page (then configure that key on the switch). Existing clients keep their
  current key.
* Imported clients are pending changes: Validate → Apply to load them into FreeRADIUS.

Upgrade to this release: `sudo ./deploy/install.sh --phase postgres` (adds the
key_status / key_scope / dot1x_ports columns) then `--phase app`. No FreeRADIUS restart.

### 6.3 Switch monitoring (read-only SNMPv3)

UI → **Switch monitoring** (admin). The `radius-admin-snmp` service polls only the RADIUS
clients **marked as switches** (and that are a single address) and shows reachability, model, the ports with 802.1X
port-control **auto**, and the switch's RADIUS counters (requests, rejects, timeouts,
bad authenticators — a rising bad-authenticator count usually means a shared-secret
mismatch). It never changes anything on a switch.

On every switch, create one SNMPv3 user, security level **authPriv**, authentication
**SHA-256**, privacy **AES-128**, in a group with a **read-only** view limited to:

| OID | Contents |
|---|---|
| `1.3.6.1.2.1.1` | system (name, model, uptime) |
| `1.3.6.1.2.1.31.1.1.1.1` | interface names |
| `1.0.8802.1.1.1` | IEEE 802.1X port settings |
| `1.3.6.1.2.1.67.1.2` | RADIUS client counters |
| `1.3.6.1.2.1.2.2.1.8` | interface link state (ifOperStatus) — per-port view |
| `1.3.6.1.2.1.17.1.4.1.2` | bridge port to interface map — per-port view |
| `1.3.6.1.2.1.17.7.1.4.5.1.1` | native port VLAN (dot1qPvid) — per-port view; the VLAN in use comes from RADIUS accounting |

(`1.0.8802.1.1.1` already covers the per-port 802.1X state and session user. Without the
three per-port rows the port table still shows the 802.1X state but no link or VLAN.)

Restrict SNMP access on the switch to this server's address, and allow UDP 161 from
this server to the switches in any firewall between them.

**Switch networks.** systemd lets `radius-admin-snmp` reach only the networks in
`switch_nets` (installer answers; default: the management subnet). A switch outside them
fails at once with "not sent: … outside the switch networks": the packet never leaves this
server, so a firewall on the way logs nothing (Net-SNMP itself would say "Unknown engine ID
(Operation not permitted)", radclient "sendto failed: Operation not permitted"). Check and
change the list:

```
systemctl show radius-admin-snmp -p IPAddressAllow
sudoedit /etc/radius-admin/site.yaml        # switch_nets: "192.0.2.0/24 198.51.100.0/24"
sudo ./deploy/install.sh --answers /etc/radius-admin/site.yaml --phase app
```

(Without an answers file: `sudo ./deploy/install.sh --switch-nets "192.0.2.0/24 198.51.100.0/24"
--phase app`.) Updates and `--phase app` runs without answers keep the networks of the
installed unit. Releases before this one replaced them with `192.0.2.0/24` on every
`--phase app` run without `--admin-net`; if the command above shows that example network,
set `switch_nets` once. (The Catalyst 1300 web UI has
this under SNMP → Views / Groups / Users; check the CLI syntax for your firmware.)

Then in the UI: enter the username and both passphrases, tick **Enable switch
monitoring**, Save (a first poll starts at once), and use **Test one switch**. With
**Keep each client's 802.1X ports in sync** off, differences between the recorded port
list (CSV) and the switch are only flagged ("Differs from switch"); with it on, the list
is replaced by what the switch reports and each change is audited.

Which clients are polled: tick **This is a switch** on a client's edit page, use the
**Monitored devices** list on the Switch monitoring page to mark several at once, or set
it during CSV import (the **Mark new clients as switches** option, or an optional
`is_switch` column with yes/no; an empty cell keeps the current value). Access points,
firewalls and other RADIUS clients that are left unticked never receive SNMP requests.
Unmarking a client removes its stored status. Clients that existed before this release
start unmarked, so mark your switches once after upgrading.

Notes: standalone Catalyst 1300s name ports `gi4` over SNMP; they are shown as
`gi1/0/4` to match the CLI and the CSV. Network entries (CIDR) are not polled. Keys and
`key_scope` cannot be read over SNMP and still come from the CSV import.

Upgrade to this release: `sudo ./deploy/install.sh --phase packages` (adds `snmp`),
`--phase postgres` (adds the monitoring tables), then `--phase app` (installs and starts
`radius-admin-snmp.service`). If you already have the monitoring release, `--phase
postgres` then `--phase app` adds the switch flag. No FreeRADIUS restart. Logs: `journalctl -u radius-admin-snmp`.

### 6.4 Live sessions and session actions (disconnect / re-authenticate)

UI → **Sessions** lists who is connected now: user or MAC (with vendor), switch and port,
VLAN, start time and duration, and the port's live 802.1X state from switch monitoring.
“Last 30 days” shows ended sessions with the reason they ended. The data is RADIUS
accounting, so each switch must send it. On every Catalyst 1300 (config mode):

```
aaa accounting dot1x start-stop group radius
```

Sessions → the summary line names any switch that sent no accounting in 30 days. If
the server runs a host firewall (ufw), UDP 1813 from the switches must be allowed (it
already is when the firewall only restricts the UI port, as installed).

**Actions** (operator or admin), from the *Actions* menu of a session that is still up, in
either view (“Last 30 days” offers them for the sessions that have not ended). To act on
several sessions at once, tick them (the box in the table header ticks the whole page) and
use the buttons in the bar above the table; one request is sent per session, at most one page
(50) at a time.

| Action | What the switch does |
|---|---|
| Re-authenticate | re-runs 802.1X/MAB for the session; link stays up (picks up a changed VLAN or MAB entry) |
| Bounce port | shuts the port briefly and re-enables it; the device reconnects |
| Disconnect | ends the session; the device must authenticate again |

The page does not change while a request is sent: the session's row shows *Sending…* and
then **Done** or **Failed**, which links to the details (the switch's answer and what to check
when it failed). A result stays in the row for 15 minutes. **Session actions** in the menu
lists every request of the last 90 days, with filters for user, MAC, port, requester, switch,
action and result. When a switch does not answer, the remaining requests queued for it in
the same pass are marked “Not sent” at once instead of each waiting for a timeout; send them
again once the switch answers.

Going back to a list (*Back to sessions*, *Back to log*, *Cancel* on a form, or after a row
action) returns to the filters and page you had; the menu links open the plain list.

These are RADIUS Change-of-Authorization messages (RFC 5176) sent by the monitoring
service with `radclient` from your FreeRADIUS build, to the client's **session-action port**
(Clients → edit; empty = its device profile's: UDP **1700** for the Catalyst 1200/1300
profile, **3799** for the Generic profile). Only the actions the device profile has are
offered: the Generic profile has Disconnect only. Requirements on each Catalyst 1300
(firmware **4.1.3.36 or later**):

```
aaa server radius dynamic-author
 client <this RADIUS server's IP> server-key <the switch's shared secret in this console>
 exit
```

Cisco documents ISE as the tested CoA client for the 1300 series. The requests name the
session by the device's MAC (Calling-Station-Id) and port (NAS-Port-Id), with the switch's
NAS-IP-Address, Event-Timestamp, Message-Authenticator and the Cisco AV-pairs
`subscriber:command=reauthenticate` / `bounce-host-port`. Acct-Session-Id is sent only for a
session without a MAC: a Catalyst 1300 answers a request that names one with
`CoA-NAK: Session-Context-Not-Found`, and one without NAS-IP-Address with `Missing-Attribute`. **Test once on one switch**
before relying on it; the Failed or Done label in its row links to the details, which show the switch's ACK or NAK (with Error-Cause),
and every request and result is in the audit log. `install.sh --phase app` reports
whether it found radclient; if it lives somewhere unusual set
`radclient = /path/to/radclient` in `/etc/radius-admin/radius-admin.conf`.

**Sessions that never ended.** A switch that reboots, loses an Accounting-Stop or starts a new
accounting session when it re-authenticates a port leaves the old record open. Every 5 minutes
the monitoring service closes an open record once the same device (MAC) has started a newer
session on the same switch, and one whose switch sent interim updates but none for 24 hours;
the 30-day view shows them as "Closed: newer session from this device" / "Closed: no
accounting update for a day". A session action the switch refuses with
`Session-Context-Not-Found` closes its record too ("Closed: the switch no longer has it").
Records from a switch that sends no interim updates are only closed by those two events, so
turn on periodic interim accounting updates on the switches where the firmware offers it.

### 6.5 Alerts

UI → **Alerts**. The monitoring service checks every minute and raises:

* **Reject spike**: N or more rejects within M minutes (default 25 in 5); clears below N/2.
* **Switch not responding**: a switch marked for monitoring failed N SNMP polls in a row
  (default 2). Needs switch monitoring enabled.
* **FreeRADIUS down**: the service is stopped or not listening on its RADIUS port in two
  checks in a row (so the brief restart of Review and apply never alerts).
* **Portal down**: nginx is stopped or not listening on TCP 443 in two checks in a row
  (only on servers where the portal's nginx site is enabled). While nginx is down the
  Alerts page cannot be reached, so this one is useful only with syslog forwarding or
  email (the Alerts pages warn while email is off); afterwards it stays in the alert history. nginx restarts itself every 30 seconds after a failure (nginx phase drop-in), so
  an alert means it has stayed down; check `systemctl status nginx` and `nginx -t`.
* **Second-factor provider down**: the Duo provider is on, a configuration with Duo has been
  applied, and `duoauthproxy.service` is not active or not listening on 127.0.0.1:18120 in two
  checks in a row. Device admin logins that need a second factor are rejected meanwhile; exempt
  break-glass accounts still log in (§6.9b).
* **Second factor not answering**: N or more device admin logins rejected with "the
  second-factor provider did not answer" within M minutes (default 3 in 15; its own switch);
  clears below N/2. A few are normal (an ignored push); many mean the provider or its link to
  the vendor's cloud is down.
* **Unverified second-factor build**: the Duo provider is on and its build was installed with
  an admin-entered SHA-256 that the signed catalog still does not list. Sent again once a day
  while open; clears by itself once a release's catalog lists the build.
* **Withdrawn second-factor build**: the installed Duo build was withdrawn from the signed
  catalog (by SHA-256 or version). Sent again once a day until a current build is installed.

  The three provider alerts share one switch in Alert settings. The monitor asks the helper
  (`integration_status`, the catalog once an hour); an older helper without those actions
  raises nothing.

Each alert is sent once when it opens and once when it clears, and recorded in the audit
log. The dashboard and the side menu show open alerts; the dashboard and Alerts page also
warn if the monitoring service itself stops reporting.

**Syslog** (on): lines tagged `radius-admin`, facility authpriv, e.g.
`ALERT OPEN switch_down [12]: SW-ACCESS-11 (192.0.2.11) does not answer SNMP …`
(priority warning; critical for FreeRADIUS down; notice when resolved). To forward to a
SIEM, add an rsyslog rule, e.g. `/etc/rsyslog.d/40-forward-radius-admin.conf`:
`if $programname == 'radius-admin' and $msg contains 'ALERT' then @@siem.example.net:514`.

**Email** (off; Alert settings, admin + step-up): relay, port, STARTTLS/TLS (certificate
checked against the server's trust store — add the internal CA with
`update-ca-certificates`), optional login (stored encrypted), From and To. The monitoring
service may only reach the switch networks (§6.3); for a relay outside them add one exception:

```
sudo systemctl edit radius-admin-snmp
#   [Service]
#   IPAddressAllow=<relay IP>
sudo systemctl restart radius-admin-snmp
```

Use **Send test alert** to check delivery.

### 6.6 MAB: expiry, vendor names and unknown devices

* **Expiry**: optional “Expires after” date on a MAB device (access ends at the end of
  that day, UTC). Expired devices are rejected but stay listed (filter *Expired*) so they
  can be renewed. CSV import accepts an optional fourth column `expires` (YYYY-MM-DD).
* **Vendor names** come from the IEEE registry in the `ieee-data` package (offline).
  Addresses with the locally-administered bit (phones' private Wi-Fi addresses, VMs) show
  as “Private (randomized or locally assigned)”.
* **Unknown devices** (MAB devices → Unknown devices): every MAC that tries MAB without
  being registered is listed with the switch, port, attempts and first/last seen. Set a
  default VLAN once; **Approve** registers the MAC with that VLAN (changeable per row) and
  an optional expiry. The switch admits it at its next MAB attempt (Catalyst 1300 quiet
  period, about a minute) — or use Sessions → Re-authenticate. *Hide* keeps rejecting a
  device without listing it; *Remove* drops it until it tries again. The queue keeps at
  most 2000 MACs; entries not seen for 30 days are removed. A MAC that has authenticated
  with a certificate (EAP-TLS accept) is never listed, even if the switch tried MAB first
  or falls back to it later; such MAB attempts are rejected with the reason *MAB not used:
  this device authenticates with a certificate*. Register the MAC under MAB devices if it
  really needs MAB.

### 6.7 Why was it rejected?

Auth log → select a time. The record shows the reject reason in plain words with a hint,
the switch and port, the station's vendor, the client certificate (DNS name, CN, subject,
issuer, serial, expiry), the computer's AD groups as FreeRADIUS saw them and the access
rule that assigned the VLAN, plus other attempts from the same device. Records from
before this release have no reason or certificate details.

### 6.8 Audit reports

UI → **Reports**: configuration changes (audit log, sign-ins optional), authentication
summary, privileged access (admins only), network sessions, RADIUS clients, MAB devices,
access rules, alerts and session actions. *View / print* opens a print layout — use the
browser's Print → Save as PDF; *CSV* downloads a spreadsheet (cells that a spreadsheet
would evaluate as a formula are prefixed with `'`). Shared secrets never appear. Every
report viewed or downloaded is recorded in the audit log.

### 6.9 802.1X with a username and password (EAP-TTLS)

For people and devices without a machine certificate. Certificates (EAP-TLS) stay the
stronger choice and keep working alongside.

1. **Turn it on.** UI → **Settings** → *802.1X with a username and password* (admin). It
   takes effect at the next connection; no Apply.
2. **Add users.** UI → **802.1X users** → *Add 802.1X user* (operator): username, password,
   groups (comma-separated), optional description and expiry. The groups are matched against
   the access rules' group names, the same way a computer's directory groups are: a user in
   `Wired-Office` gets the VLAN of the first enabled rule for `Wired-Office` on that kind of
   connection (wired, or that SSID). A group without a rule is flagged on the list; a user with
   no matching rule is rejected. Disable, set an expiry, set a new password or delete there;
   changes apply to the next connection.
3. **Set up the devices.** The device must use **EAP-TTLS** with **PAP** as the inner method, and
   it **must** trust the CA that issued the RADIUS server certificate (`certs/site/ca.pem`) and
   check the server name (the name in that certificate, for example `radius.example.net`).
   Without that check a fake access point can collect passwords. An outer (anonymous) identity
   such as `anonymous` is fine: the log shows the name typed inside the tunnel.
   * Windows 10/11: no built-in prompt for TTLS; push a wired or Wi-Fi profile (Group Policy or
     Intune) with EAP-TTLS, inner method *Unencrypted password (PAP)*, the CA as trusted root and
     the server name.
   * macOS / iOS: a configuration profile (Apple Configurator, MDM) with TTLS, inner PAP, the CA
     certificate and the server name as *trusted server certificate name*.
   * Android: *EAP method* TTLS, *Phase 2* PAP, *CA certificate* the installed CA, *Domain* the
     server name.
   * Linux (NetworkManager): *Tunneled TLS*, inner *PAP*, the CA certificate.
4. **Directory accounts (optional).** Settings → *Also accept directory accounts*. People who are
   not local 802.1X users then sign in with their directory user name (`jroe`) or user@domain
   (`jroe@example.net`) and directory password; FreeRADIUS checks it with an LDAP bind as that
   person, using the same domain controllers, bind account and CA as for computers
   (`mods-available/ldap`). Their directory groups, nested groups included, select the VLAN
   through the access rules, exactly as for a computer. A local 802.1X user of the same name
   always wins. Disabled, locked or expired directory accounts are refused by the directory.
5. **PEAP (optional, standard mode).** Settings → *Also allow PEAP with MSCHAPv2*, then tick
   **Allow PEAP** on the users who need it, when you set their password (the NT hash MSCHAPv2
   needs can only be made from the password; existing users need a new password). PEAP is what
   many devices offer without a profile (Windows: *Microsoft: Protected EAP (PEAP)* with *Secured
   password (EAP-MSCHAP v2)*), but it is weaker: prefer EAP-TTLS or certificates, and still check
   the server certificate and name on the devices. Windows 11 with Credential Guard does not
   offer saved credentials for MSCHAPv2.

   **Directory accounts over PEAP** need this server joined to the domain, because MSCHAPv2
   cannot be checked with an LDAP login. On the console:
   ```
   sudo ./deploy/ad-join.sh --realm EXAMPLE.NET --dry-run        # checks, changes nothing
   sudo ./deploy/ad-join.sh --realm EXAMPLE.NET --admin Administrator
   sudo systemctl restart freeradius
   ntlm_auth --request-nt-key --username=jroe                       # asks for the password: NT_KEY = works
   sudo ./deploy/ad-join.sh --status
   ```
   It installs Samba's winbind, writes a member-only `/etc/samba/smb.conf` (it refuses to replace
   one it did not write unless you add `--replace-smb-conf`), asks `net ads join` to prompt for
   the administrator's password, and lets FreeRADIUS use `ntlm_auth`. DNS must find the domain
   controllers and the clock must be right. The domain controllers must allow NTLM for this
   computer account (Group Policy *Network security: Restrict NTLM*). Then tick *Also accept
   directory accounts over PEAP* in Settings. Users type their user name or `DOMAIN\user`; their
   directory groups select the VLAN, a local 802.1X user of the same name wins.
6. **Check.** UI → **Auth log**, method `ttls-pap` / `peap` (local) or `ttls-ldap` / `peap-ldap`
   (directory). Rejects give
   the reason in plain words: turned off, no such user, disabled, expired, wrong password (or, for
   the directory, a refused account), not PAP inside the tunnel, or no access rule for the user's
   groups (§6.7). A directory record lists the groups the rule matcher saw.

Switch admins and 802.1X users are separate: a switch admin's password never opens a network
port, and an 802.1X user cannot sign in to a switch. A MAC that has connected with a password is
never offered for MAB approval, as for certificates.

Upgrade to this release: `sudo ./deploy/install.sh --phase postgres` (table and functions),
`--phase app`, then `--phase freeradius --restart-freeradius` in a maintenance window (enables
EAP-TTLS and PEAP with their inner servers `radius-admin-inner` and `radius-admin-peap`, the
`mschap` module and the `ldap_user` section of `mods-available/ldap`; your directory settings
are kept as before). Both methods stay off until you turn them on in Settings. EAP-TLS, MAB and switch logins behave as before.

### 6.9a Device admins with directory accounts

**Device admins** (formerly *switch admins*) are the logins to the management of switches, access
points, firewalls and other RADIUS clients. Besides the local accounts on the Device admins page,
members of chosen directory groups can log in with their directory account and password:

1. **Prerequisite.** The directory connection works (the same one EAP-TLS and EAP-TTLS directory
   accounts use; RUNBOOK §6.9 step 4). Nothing else to install.
2. UI → **Settings → Device admin logins**: tick *Also accept directory accounts* and list the
   directory groups allowed to log in, one per line (for example `Network-Admins`). Nested groups
   count. Save (step-up). Takes effect at the next login; no Apply, no restart.
3. On the device, keep RADIUS login as today (PAP from the management subnet). Users type their
   user name or `user@domain` and their directory password. *Grant full admin rights* applies to
   directory accounts as well.
4. **Check.** Auth log, method `admin-ldap`: the record lists the user's directory groups and marks
   the allowed ones. Rejects say why: outside the management subnet, not found in the directory,
   the directory refused the password (wrong, disabled, locked or expired), not in a device admin
   group, or the directory could not be searched.

A local device admin of the same name always wins (its own password and disabled state), so keep
one or two local accounts as a break-glass path for when the directory is unreachable. Repeated
wrong passwords count against the directory account's lockout policy, as for any LDAP bind; logins
from outside the management subnet never reach the directory.

Upgrade to this release: `sudo ./deploy/install.sh --phase postgres`, `--phase app`, then
`--phase freeradius --restart-freeradius` in a maintenance window. The old address
`/switch-admins/` redirects to `/device-admins/`.

### 6.9b A second factor for device admin logins (Integrations)

A device admin login can be made to need a second factor (SPEC section 29): FreeRADIUS checks the
management subnet, then sends the login to a multi-factor provider, which asks the person to
approve it. 802.1X network access never uses a second factor.

**Remote RADIUS MFA server** (directory accounts). Any RADIUS server that checks the password and
asks for the second factor itself: a Network Policy Server with the Microsoft Entra multifactor
extension, privacyIDEA, an Okta RADIUS agent on another host. FreeRADIUS looks the person up in the
directory first (unknown names never leave the server) and, after the remote server's accept, still
requires one of the device admin groups (§6.9a). Not offered in FIPS mode.

1. On the remote server, add this RADIUS server as a client with a new shared secret (16–128
   characters) and make sure it answers with Message-Authenticator (or untick that option below).
2. UI → **Integrations → Add remote MFA server**: id, address, port, shared secret, how long to wait
   for the person (5–60 s). Save (step-up), then **Apply changes**.
3. UI → **Integrations → Change the rules**: *Directory accounts* → require a second factor with that
   server, on all clients or on selected ones. Saved rules apply at the next login, no Apply.
4. On each device, raise the RADIUS timeout so that it waits for the answer (for example about 60 s,
   or the server's wait time plus a margin), with one retry. A device that gives up early shows a
   failed login although the person approved.

**Duo Authentication Proxy** (local and directory accounts). FreeRADIUS sends the login to the Duo
proxy on this server (127.0.0.1:18120); Duo sends the password check back to the virtual server
`radius-admin-mfa-primary` (127.0.0.1:18121), which checks it exactly like a normal device admin
login, and only then asks for the push, phone call or passcode. Installing and configuring Duo from
the portal is described below.

**Rules and break-glass.** Rules exist per account kind (local, directory) and can be limited to
selected clients. Exempt local accounts (at most 10) never need a second factor: keep at least one,
because a login that needs a second factor is rejected when the provider does not answer, is turned
off, or was added but not applied yet.

**Check.** Auth log: methods `pap-admin+mfa` and `admin-ldap+mfa`. Reject reasons: refused in the
second-factor chain (Duo: wrong password, not a device admin, or denied), the second-factor server
refused the login, the provider did not answer, the provider is turned off, the login did not reach
its provider (apply the configuration), a remote server for a local account.

Upgrade to this release: `sudo ./deploy/install.sh --phase postgres`, `--phase app`, then
`--phase freeradius --restart-freeradius` in a maintenance window. Nothing changes until a provider
and a rule are configured.

**Provider builds and the catalog.** Builds of a provider installed on this server (Duo) are
checked against `/opt/radius-admin/integrations/catalog.json`, which every release signs with the
update key (`catalog.json.sig` next to it). The helper keeps the newest catalog it has seen
(`/var/lib/radius-admin-helper/integrations-catalog.json`), so a downgrade does not bring back a
withdrawn build. Downloads land in `/var/lib/radius-admin/integrations/` (status in
`fetch-<provider>.json`, unit `radius-admin-integration-fetch@<provider>-<version>`), installs run
as `radius-admin-integration-install@<provider>` with the log in
`/var/log/radius-admin/integration-<provider>-<time>.log`. A checkout (not a release bundle) has no
signed catalog: builds then need the SHA-256 entered, and nothing installs in FIPS mode.

**Setting up Duo** (Integrations → Duo Authentication Proxy):

1. In the Duo Admin Panel, protect an application of type *RADIUS*; note its integration key,
   secret key and API hostname. Allow outbound HTTPS from this server to that hostname.
2. *Check this server*, then *Download* a build the catalog lists (or *Upload* Duo's unmodified
   source file). A build that is not in the catalog can be installed outside FIPS mode after you
   enter its SHA-256 from Duo's checksum page; it shows as *Unverified*.
3. *Install* (a few minutes; the Details drop-down shows the log).
4. *Connect to Duo*: keys, API hostname, fail mode, factors; tick *On*, save, then **Apply
   changes** (this starts the Duo proxy and restarts FreeRADIUS).
5. *Run the check*, then choose Duo in **Change the rules** for local and/or directory accounts,
   keep a break-glass account exempt, and raise the devices' RADIUS timeout to about 60 s.

**Duo on this server** (SPEC section 29.2). The install builds Duo's source as the unprivileged
user `radius-admin-build` (about two minutes; build packages are added when missing), runs Duo's
installer into `/opt/duoauthproxy` (service user `duo_authproxy_svc`, unit `duoauthproxy.service`,
hardened by a radius-admin drop-in) and leaves the proxy stopped until its configuration is
applied. Applying changes writes `/opt/duoauthproxy/conf/authproxy.cfg` (never edit it by hand: the
next apply replaces it) and restarts the proxy before FreeRADIUS; if the proxy does not come up its
previous configuration returns and FreeRADIUS is not touched. Duo's own log is
`/opt/duoauthproxy/log/authproxy.log`. Removing Duo is refused while FreeRADIUS still sends logins
to it: turn the Duo provider off and apply first; the removal keeps a copy of the configuration in
`/var/backups/radius-admin/`. Outbound HTTPS from the proxy to `api-*.duosecurity.com:443` must be
allowed.

**Elsewhere in the portal.** The Integrations page lists, per device profile of the clients the
rules cover, how to raise the device's RADIUS timeout (Catalyst 1200/1300: `radius-server timeout
30` and `radius-server retransmit 2`, about 90 s with the retries; other devices: at least 60 s in
total); custom profiles have a field for it. The auth log detail of a `+mfa` login names the
provider the rule named at that time (rebuilt from the audit log of rule changes). The
privileged-access report shows per account whether a second factor is needed, by which provider
and on which clients, the exemptions, and warns when no local account is exempt. The setup
checklist has an optional step "Second factor for device admins". Alerts: §6.5.

**How long FreeRADIUS waits.** The Duo provider waits 60 s for the person, a remote server as
long as its setting (5–60 s). FreeRADIUS cuts any such wait to `max_request_time` in
`radiusd.conf` (stock 30 s; radiusd then logs `Ignoring "response_window = 60.000000", forcing to
"response_window = 30.000000"` at start), so the freeradius phase raises it to 90 s and preflight
warns when it is lower. Run `--phase freeradius --restart-freeradius` after upgrading to this
release.

**Applying with Duo takes longer.** An apply that changes Duo's configuration restarts the Duo
proxy and then FreeRADIUS; in the worst case (both fail and are restored) the helper needs about
180 s. The portal then waits up to `helper_duo_timeout` (210 s, `[app]` in radius-admin.conf),
nginx and gunicorn up to 240 s; the Apply button says it can take a few minutes. A changed
`restart_timeout`/`restart_wait` in helper.conf must keep `lock + validate + 4 × (restart + wait)`
below `helper_duo_timeout`.

**FIPS mode.** Only builds the signed catalog marks FIPS-capable can be installed, turned on and
applied; the build must have been installed in FIPS mode, and Duo then runs with `fips_mode=true`
and fail mode secure. A Duo installed before FIPS mode was turned on is refused at apply (validate
says so) and the Unverified alert names the reason; install a FIPS-capable build or turn Duo off
and apply. FIPS-capable builds: Duo 6.8.1 (checked on Ubuntu 24.04 Pro `fips-updates`, amd64).
Remote MFA servers are not offered in FIPS mode.

Duo in FIPS mode keeps RADIUS's MD5 on its two loopback hops, like FreeRADIUS itself (SECURITY.md
§1.1 exceptions 1, 2 and 9); its TLS to Duo runs on Duo's bundled OpenSSL FIPS Provider 3.1.2
(CMVP #4985). Before turning it on, put the controls of SECURITY.md §1.3 in place: isolated
management network for RADIUS (IPsec between sites, RadSec where devices support it), unique
secrets and Message-Authenticator per device, host firewall (outbound only to
`api-*.duosecurity.com:443`), Duo factors push or passcode with lockout on, a break-glass account,
alerts to the SIEM. After installing or updating Duo, keep the evidence for the assessor:

```bash
sudo python3 tools/integrations/duo-fips-check.py host
sudo python3 tools/integrations/duo-fips-check.py installed --running --json duo-fips.json
```

(from the release bundle; R1–R6 must pass). Record exception 9 in the SSP.

Maintainers add a build with `tools/integrations/catalog.py add duo X.Y.Z <downloaded file>
--vendor-sha256 <value from the vendor's checksum page>` (refused unless both agree), mark it
FIPS-capable only after the FIPS VM check (`catalog.py fips duo X.Y.Z <platform>`), and withdraw a
bad one with `catalog.py withdraw duo X.Y.Z`; the next release signs the catalog.

**FIPS check of a Duo build (maintainers only; lab VM, never a production server).** A build gets
`fips: true` only after this check passes for it. What is known so far (Duo 6.8.1, read and run in
a standard-mode sandbox): Duo ships a prebuilt OpenSSL FIPS provider per architecture
(`pkgs/fips_modules/<amd64|aarch64>/fips.so`, "OpenSSL FIPS Provider 3.1.2", module MAC intact)
with its `openssl.cnf`, installed as `/opt/duoauthproxy/usr/local/openssl/`; `fips_mode = true`
in `[main]` makes Duo's `cryptography` 43.0.1 (a manylinux wheel that links its own OpenSSL 3.3.2)
use only that provider: SHA-256 works, MD5 is refused. Duo logs "FIPS mode is not enabled" at a
start without it.

1. Lab VM: Ubuntu 24.04 LTS, `sudo pro attach <token>`, `sudo pro enable fips-updates`, reboot;
   `cat /proc/sys/crypto/fips_enabled` must print 1. Install radius-admin from the release
   candidate's bundle (`require_fips` on).
2. Static check of Duo's file (nothing in it runs):
   `python3 tools/integrations/duo-fips-check.py source duoauthproxy-X.Y.Z-src.tgz`
   (R3: the provider for this architecture is intact; prints its version).
3. Lab catalog: the helper installs in FIPS mode only builds the signed catalog marks
   FIPS-capable, so sign a lab catalog with a throwaway key on the VM:
   `openssl ecparam -name secp384r1 -genkey -noout -out lab.pem`,
   `openssl pkey -in lab.pem -pubout -out lab-pub.pem`, `cp integrations/catalog.json lab.json`,
   `tools/integrations/catalog.py --catalog lab.json add duo X.Y.Z <file> --vendor-sha256 <Duo's value>`,
   `catalog.py --catalog lab.json fips duo X.Y.Z lab`, `catalog.py --catalog lab.json sign lab.pem`;
   install `lab.json` and its `.sig` as `catalog.json` / `catalog.json.sig` (root, 0644) in
   `/opt/radius-admin/integrations/`, and point `update_pubkey` in `/etc/radius-admin/helper.conf`
   at `lab-pub.pem`. Never on a real server and never committed.
4. Portal: Integrations → Duo: upload the build, install (FIPS mode), connect with the keys of a
   Duo trial account's RADIUS application (or dummy keys: the proxy starts, logins fail), tick
   On, Apply. A test login with a push is worth doing with a trial account.
5. Full check: `sudo python3 tools/integrations/duo-fips-check.py all duoauthproxy-X.Y.Z-src.tgz
   --running --json duo-X.Y.Z-fips.json`. Required: R1 kernel FIPS, R2 system OpenSSL FIPS
   provider active, R3/R3i provider intact and the installed copy is the source's, R4 Duo's
   provider loads and passes its self-tests, R5 MD5 refused / SHA-256 works in Duo's Python, R6
   applied `fips_mode=true` + `failmode=secure`, proxy listening, log says FIPS mode is enabled.
   Your decision: M1, the provider version is on an active CMVP certificate for OpenSSL's FIPS
   provider (csrc.nist.gov, Cryptographic Module Validation Program; check the certificate's
   status and its operational environment notes); M2, a prebuilt provider binary from Duo and a
   `cryptography` wheel with its own OpenSSL are acceptable under rule 6 and the maintainer's
   FIPS decision for providers.
6. Only if all of that holds: in the repository, `tools/integrations/catalog.py fips duo X.Y.Z
   ubuntu-24.04-pro-fips-updates-<arch>` (one name per architecture actually checked), with the
   JSON report's summary in the pull request; the next release signs it. Otherwise leave
   `fips: false` and note why in the release notes. Record of decisions: Duo 6.8.1, 2026-11-20,
   amd64: R1–R6 passed; M1 accepted (OpenSSL FIPS Provider 3.1.2 = CMVP #4985, FIPS 140-3, active
   to 2030-03-10; Ubuntu 24.04 not a tested environment); M2 accepted (Duo's prebuilt provider and
   `cryptography` wheel); its RADIUS MD5 on loopback is SECURITY.md exception 9.
7. Throw the VM away (or `sudo /opt/duoauthproxy/uninstall --no-prompt` and restore
   `update_pubkey`).

### 6.10 Device profiles (switches from other vendors)

A **device profile** says which attributes this server sends to a RADIUS client (VLAN
assignment, full admin rights on a management login), which session actions it offers and
how its SNMP port names map to the names it sends in RADIUS. Built-in profiles:

| Profile | Use for |
|---|---|
| Cisco Catalyst 1200/1300 (default) | Catalyst 1200/1300 |
| Generic (RFC standard attributes) | Devices without a profile of their own: VLAN by the RFC 3580 tunnel attributes, an access rule's role as `Filter-Id`, admin rights by `Service-Type = Administrative-User`, MAB from wired ports and access points, Disconnect only, on UDP 3799 |

A built-in profile that does not work with a device: Device profiles → **Report a problem**
opens an issue form on GitHub with the profile id and version filled in (nothing else from
this server). Add the device model and firmware and what went wrong, without secrets, host
names or addresses.

* **Custom profiles:** Network access → **Device profiles** (admins). *Copy* a built-in profile
  (or *New profile*), adjust the attributes, the MAB port types, the session actions and the
  port-name rules, and save; each line of an attribute box is `Attribute := value`. Attribute
  names must exist in the FreeRADIUS dictionary (vendor dictionaries included, for example
  `Aruba-User-Role`). Try a custom profile on one device first. *Export JSON* downloads any
  profile; *Import JSON* on another server adds it (tick *Replace* to update an existing custom
  profile). A profile in use or chosen as the default cannot be deleted. After changing a
  profile that clients use, **Apply** for the reply attributes; session actions and port names
  use it at once.
* **Per client:** Clients → edit → *Device profile* (leave on *Default* to follow the
  installation default) and *Session-action port* (leave empty for the profile's port).
* **Default:** Settings → Devices → *Default device profile*, used by every client that does
  not name one.
* **CSV import:** an optional `vendor_profile` column (`default`, `cisco-c1300`, `cisco-iosxe`, `generic-rfc`).
* **Roles:** Access rules → edit → *Role* (optional). Devices whose profile uses roles get it
  with the VLAN (the Generic profile sends it as `Filter-Id`: the device must know a filter or
  role of that name, or it may refuse the session); others get the VLAN only. Takes effect at
  the next authentication, like any rule change.
* **MAB from access points:** registered MAC addresses are accepted from access points and
  controllers whose profile allows it (Generic). Choose on the device which SSIDs use MAC
  authentication; the MAB device's VLAN applies on every one of them.

Both changes reach FreeRADIUS at the next **Apply** (the clients file names the client's
profile and the policy picks the attributes from it). Test a management login and an 802.1X
or MAB login from the device afterwards. Upgrades keep every client on the profile it used:
existing clients follow the default, which stays Catalyst 1200/1300, and a session-action port
changed under the old single setting is copied to each client.

## 7. Backup and restore

What to back up:

| What | How |
|---|---|
| PostgreSQL database `radius` | `pg_dump` (below) — daily |
| `/etc/radius-admin/` (config, **keys/data.key**, tls/) | file backup, encrypted — on change |
| `/etc/freeradius/` | file backup / the installer tarballs in `/var/backups/radius-admin/` |
| `/var/lib/radius-admin-helper/backups/` | optional (last 50 applied file sets) |

Daily dump (e.g. `/etc/cron.d/radius-admin-pgdump`):

```cron
15 2 * * * postgres pg_dump -Fc -d radius -f /var/backups/radius-admin/radius-$(date +\%a).dump
```

`/var/backups/radius-admin` is root 0700; give postgres a subdirectory
(`install -d -o postgres -m 0700 /var/backups/radius-admin/pg`) and point the job there.
The dump contains RADIUS shared secrets and encrypted TOTP secrets — store copies
encrypted and treat as sensitive.

Restore (stop writers first):

```bash
systemctl stop radius-admin freeradius
sudo -u postgres dropdb radius
sudo -u postgres psql -f sql/00-roles.sql          # recreates roles + empty db (owner radius_owner)
sudo -u postgres pg_restore -d radius --no-owner --role=radius_owner /path/radius-Mon.dump
sudo -u postgres psql -d radius -f sql/30-grants.sql
systemctl start freeradius radius-admin
```

After a restore, Apply once from the UI so the generated files match the database.

---

## 8. Logs

| Source | Where |
|---|---|
| UI audit (every mutation + auth event) | DB `ui.audit_log` (hash chain; UI → Audit log → Verify; CLI `verify-audit`) and syslog ident `radius-admin`, facility authpriv |
| Root helper | syslog ident `radius-admin-helper`, facility authpriv; `journalctl -t radius-admin-helper` |
| Both, consolidated | `/var/log/radius-admin/audit.log` (rsyslog snippet, rotated weekly, 104 weeks) and `/var/log/auth.log` |
| gunicorn | `journalctl -u radius-admin` |
| nginx | `/var/log/nginx/radius-admin.access.log`, `…error.log` |
| FreeRADIUS | `journalctl -u freeradius`, `/var/log/freeradius/radius.log`; auth results in `radpostauth` (UI → Auth log) |
| PostgreSQL | `/var/log/postgresql/postgresql-16-main.log` (connections logged) |
| Firewall drops | `nft list table inet radius_admin` (counters) |

Forward `radius-admin`/`radius-admin-helper` to the SIEM: uncomment the `omfwd` block in
`/etc/rsyslog.d/30-radius-admin.conf`.

**Time zone.** The database stores every time in UTC. The console shows times (authentication
and audit logs, sessions, every other page) in the zone chosen under Settings → Time zone
(default UTC), labelled with the zone's abbreviation, e.g. `14:00:00 CEST`; the auth log's
From/To dates are whole days in that zone. Reports, report CSVs, alert messages, syslog and the
audit hash chain stay in UTC.

---

## 9. Upgrading radius-admin

```bash
# unpack the new release over your existing copy (e.g. ~/radius-admin), then:
sudo ./deploy/preflight.sh
sudo ./deploy/install.sh --phase postgres,app    # schema files are idempotent; code + units
```

`--phase app` replaces `/opt/radius-admin/app` atomically and restarts the app; it never
overwrites an existing `/etc/radius-admin/*.conf` (diff against
`deploy/etc/*.example` by hand). Re-run `--phase nginx` only if the nginx template
changed. Do **not** re-run `--phase freeradius` for app upgrades (it would re-install
the base FreeRADIUS files; the UI-generated files are re-rendered from the DB, so it is
safe but restarts are then up to you).

FreeRADIUS upgrades: rebuild with the same flags (§1.1); then `radiusd -XC` and
UI → Validate.

### 9.0 Pushing updates from a Windows PC

`tools/windows/push-radius-admin.cmd` copies a package to the server over SSH and installs
it with `deploy/update.sh`, so no manual upload, unpack or `install.sh` command is needed.
It uses the OpenSSH client built into Windows 10/11 (`ssh -V` in a terminal to check).

One-time setup on the PC:

1. Unpack only the tools folder from a package, for example in PowerShell:
   `tar -xzf $HOME\Downloads\radius-admin.tar.gz radius-admin/tools/windows` and keep
   `radius-admin\tools\windows` somewhere permanent (e.g. Documents).
2. Optional but recommended: an SSH key, so you type only your sudo password. FIPS-mode
   OpenSSH on the server does not accept Ed25519 keys; use ECDSA P-384:
   ```powershell
   ssh-keygen -t ecdsa -b 384
   type $env:USERPROFILE\.ssh\id_ecdsa.pub | ssh you@radius.example.net "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
   ```
   Without a key you are asked for your SSH password twice (copy, then install).

Each update: download the new `radius-admin.tar.gz` to Downloads and double-click
`push-radius-admin.cmd` (or run it from a terminal). The first run asks for the server
name and your Linux user name and remembers them in
`%APPDATA%\radius-admin-push\settings.json`. The script shows the package SHA-256, copies
the package to your home directory on the server, checks the SHA-256 there and runs
`update.sh` with sudo. `update.sh` shows the plan and asks before installing.

| Command | Does |
|---|---|
| `push-radius-admin.cmd` | install the newest `radius-admin*.tar.gz` from Downloads |
| `push-radius-admin.cmd -Package C:\path\file.tar.gz` | install a specific package |
| `push-radius-admin.cmd -WithFreeradius` | also install changed FreeRADIUS files (no restart) |
| `push-radius-admin.cmd -List` | list releases on the server (`*` = current) |
| `push-radius-admin.cmd -Rollback` | re-install the release before the current one (web UI only) |
| `-Server`, `-User`, `-Port`, `-IdentityFile` | override (and remember) connection settings |

How `update.sh` chooses what to run: it unpacks the release to
`/opt/radius-admin-src/releases/<UTC time>-<hash>` (root-owned), compares it with
`/opt/radius-admin-src/current`, and runs `install.sh` with `packages` only if the package
list changed, `nginx-update` if the installed nginx is older than the new release's security
floor (it upgrades nginx from the mirror and restarts it), `postgres` if `sql/` or `deploy/postgres/` changed, always `app`, and `nginx`
or `firewall` if their templates changed (the plan then shows the portal settings they keep from
this server, see section 13.1; extra `install.sh` options go after `--`). FreeRADIUS files are only installed with
`-WithFreeradius`; FreeRADIUS is never restarted by an update. The first push (no previous
release recorded) runs all of these phases once; they are idempotent. On success the
uploaded file is deleted and the last 5 releases are kept; on failure the new release is
discarded, `current` is unchanged and the uploaded file is kept for a retry.

On the server the same tool can be used directly:
`sudo /opt/radius-admin-src/current/deploy/update.sh --list | --rollback | --package FILE`.

If Windows refuses to run the script, your organization may enforce a PowerShell policy
(the `.cmd` already bypasses the default per-user policy); ask IT to allow it, or run the
commands in this section's manual form (above) instead.

### 9.2 Upgrading to the sessions / alerts / reports release (2026-10-29)

This release changes the database (sql/70), the FreeRADIUS logging query
(`mods-config/sql/main/postgresql/queries.conf`) and the generated policy file, and adds
the `ieee-data` package. From the Windows push script:

```
push-radius-admin.cmd -WithFreeradius
```

(by hand: `sudo ./deploy/install.sh --phase packages,postgres,freeradius,app`). Then in the
UI: **Review and apply** once (the Apply page says “Policy format updated; apply once”;
FreeRADIUS restarts for a moment). Until that Apply, FreeRADIUS keeps working with the old
policy; the new logging query only fills the extra columns.

Order matters and the tools keep it: database first (the new columns and functions must
exist before FreeRADIUS uses them), then FreeRADIUS files, then the app. After the Apply:

1. Auth log → open a recent reject: a reason should be shown.
2. On the switches: `aaa accounting dot1x start-stop group radius` (sessions) and, if you
   want session actions, `aaa server radius dynamic-author` (§6.4). Test one switch.
3. Switch monitoring → the per-port table appears on each switch's page after the next
   poll; add the three per-port OIDs to the switches' SNMP view (§6.3).
4. Alerts → Send test alert, and check syslog.

### 9.1 Upgrading an existing install to live rules

Releases from 2026-10-23 evaluate **access rules and settings live** (SPEC §10).
FreeRADIUS asks PostgreSQL on every request through `radius_admin_vlan_hex()`,
`radius_admin_admin_source_ok_hex()` and `radius_admin_priv15()` (`sql/40-live-policy.sql`).
Request and directory values (Called-Station-Id, AD group names, source address) are
passed to SQL **only hex-encoded**. FreeRADIUS un-escapes backslash sequences in
`%{sql:...}` arguments after SQL escaping, so passing raw strings would allow SQL
injection even with `auto_escape = yes`.
`/etc/freeradius/policy.d/radius-admin` **no longer contains any rules, VLANs, the admin
subnet or the priv15 setting**. It holds the MAB logic, the calls to those functions and
your custom policy. RADIUS clients and the custom policy still need Validate → Apply
(a restart). The upgrade needs **one** FreeRADIUS restart. Do it in a quiet period.

```bash
# unpack the new release over your existing copy (e.g. ~/radius-admin), then:
sudo ./deploy/preflight.sh

# 1. Database: load sql/40-live-policy.sql (idempotent; no RADIUS impact yet)
sudo ./deploy/install.sh --phase postgres
sudo -u postgres psql -d radius -c '\df public.radius_admin_*'      # 7 functions

# 2. FreeRADIUS: new ldap (group cacheable_name = yes), sql (auto_escape = yes) and
#    the re-rendered policy.d/radius-admin. This is the last restart that rules and
#    settings will ever need.
sudo ./deploy/install.sh --phase freeradius --restart-freeradius
sudo grep -c 'radius_admin_vlan_hex' /etc/freeradius/policy.d/radius-admin    # >= 1
sudo grep -c 'LDAP-Group ==' /etc/freeradius/policy.d/radius-admin        # 0

# 3. Web app (rules + settings pages become "live immediately")
sudo ./deploy/install.sh --phase app
```

4. **Test every rule group straight away** with real clients, the same way as §4.2:
   - one machine per wired group (Wired-Support → 510, Wired-Office → 500, Wired-Utility → 520);
   - one machine per SSID (Example_Main_Test, Example_Admin, Example_Main → expected VLAN);
   - a machine in no matching group (must be rejected);
   - a switch-admin login from 192.0.2.0/24 (accepted; priv-lvl 15 only if enabled);
   - a registered MAB device.

   Check each one in UI → Auth log (authmethod and VLAN columns). The UI's rule
   tester ("test a match") calls `radius_admin_vlan()`. That function and FreeRADIUS's
   `radius_admin_vlan_hex()` both use the same matcher, `radius_admin_vlan_core()`.
   Also check one machine whose AD group is **nested** inside a rule's group. Nested
   membership now comes from the `group.membership_filter` search (the AD in-chain
   rule) and is cached per request.
5. If something is wrong, go back to the previous release's FreeRADIUS configuration with
   `sudo ./deploy/rollback.sh --tarball /var/backups/radius-admin/freeradius-<ts>.tar.gz`.
   Pass the tarball that step 2 just created, **not** the oldest one: the oldest is the
   pre-radius-admin SQLite state (§10). The functions from step 1 can stay; nothing
   uses them after a rollback.

What changes for operators:
- Edits to access rules (VLAN, enable/disable, add, delete, priority) and to the settings
  `admin_subnet` / `admin_priv15` apply to the **next authentication**, with no Apply
  and no restart. Every edit is still audited.
- **Fail-closed:** if PostgreSQL is unreachable, every EAP-TLS, switch-admin and MAB
  request is rejected (it was already partly DB-dependent before: admin logins and MAB).
  After PostgreSQL comes back, FreeRADIUS reconnects by itself within the sql pool's
  `retry_delay` (30 s). No restart is needed.
- **Group matching is case-insensitive** (`Wired-Support` = `wired-support`). This is a behaviour
  change: the original hand-written policy used `LDAP-Group == "..."`, which compares
  case-sensitively against the cached names. In AD two groups cannot differ only by
  case, so this matches AD semantics. Check that no rule relies on case to *not* match.
- **No limit on the number of groups.** A computer's full group list (including nested
  groups) is sent to PostgreSQL hex-encoded. Tested with a machine in 300 groups whose
  only matching group was the last one (about 10 KB of hex). Remaining limits:
  - **Group name length:** a group name longer than about 1,000 bytes cannot be
    hex-encoded by FreeRADIUS, so the request is rejected. AD's `cn` limit is
    64 characters.
  - **Membership count:** no FreeRADIUS cap applies with `cacheable_name = yes`; on the
    test bench all 300 groups were cached from both `memberOf` and the
    `membership_filter` search. The 64-entry cap in rlm_ldap only applies to
    `cacheable_dn`, which is off. The DC's own MaxPageSize (AD default 1000) bounds a
    single search; a computer in more groups than that would lose the excess
    (nested) ones, so those groups must not be relied on.
- An AD group whose name contains a comma, a quote or backslash sequences such as
  `\047` is matched literally, byte for byte. Rule group names cannot contain commas
  or quotes (UI validation).

OS/Ubuntu Pro updates: normal `apt upgrade`; afterwards `check-fips` and the dashboard's
FIPS indicator.

---

### 9.3 Updates from the portal (signed builds)

Every push to `main` or `testing` that passes CI becomes a signed build on GitHub (a release
`v<version>`); `dev` builds are published only on request (below), so the release list stays
short. A server follows one of those branches, its **channel**, and
installs only builds whose signature verifies with the public key it was installed with.

**One-time setup for the repository (maintainer).** On a trusted machine, not a server:

```bash
openssl ecparam -name secp384r1 -genkey -noout -out update-signing.key
openssl pkey -in update-signing.key -pubout -out deploy/keys/update-signing.pem
```

Commit `deploy/keys/update-signing.pem` (the public key), add the private key as the
repository secret `UPDATE_SIGNING_KEY` (Settings → Secrets and variables → Actions), and keep
an offline copy of `update-signing.key` somewhere safe, then delete it from the machine. Until
both exist, CI publishes no builds and the Updates page says updates are not set up.
Optionally require a reviewer for the `release` environment (Settings → Environments), so a
person approves every published build. Only the build job uses that environment, and it runs
only for a new version, so a merge that publishes nothing never waits for a reviewer.

**Releasing.** Bump `VERSION` on `dev` right after a release (for example `0.2.0`), describe
changes under `## Unreleased` in `CHANGELOG.md`, and when releasing rename that section to
`## 0.2.0 — <date>`. `dev` builds are `0.2.0-dev.N`, `testing` builds `0.2.0-rc.N`, and the
merge to `main` publishes `0.2.0`. To publish a `dev` build (for a test server on the dev
channel), open Actions → **Release** → **Run workflow**, choose the branch `dev` and run it; it
builds the newest commit on `dev` once CI has passed for it. testing and dev keep their
newest 3 builds. A push to `main` without a `VERSION` change publishes
nothing: the Release run's version check shows the warning "No release published" and the
signed build job is skipped, so there is nothing to approve. Rename
`## Unreleased` before the merge to `main`, or the run warns "Empty release notes" and the
release is published without notes.

**CI on promotions.** The package and bench jobs (most of a CI run) record the tree they
passed on. A run of the same tree within 7 days skips them and links the run that passed, so
a squash merge into `dev` and the `dev` → `testing` promotion do not repeat what the pull request
already ran (`tools/ci/tested-tree.py`). Pushes to `main` and runs started by hand
(Actions → CI → Run workflow) always run every job; use one to force a full run elsewhere.

**On a server.** Settings → **Updates** shows the installed and the latest build on the
channel, what changed in between, and whether the update restarts FreeRADIUS.
- **Channel:** main (stable releases) for production; testing and dev for test servers.
  Switching to a channel whose newest build is older offers it as a downgrade, which needs an
  extra confirmation (the database stays as it is; migrations only add).
- **Mode:** Off never contacts GitHub. Notify (default) checks once a day. Automatic checks every
  hour and installs builds that only change the console at once; builds that restart
  FreeRADIUS wait for the maintenance window (day and hour, server time). A build that failed
  to install is never retried automatically.
- **Install** asks for step-up. The helper verifies the signature and the bundle's SHA-384, then
  `radius-admin-update-install@<version>` backs up the database, installs, checks the portal
  (the app, and nginx active and listening on 443) and FreeRADIUS, and rolls back if they do
  not come up. While it runs the page shows the current step with a spinner; **Details** opens
  the install log as it is written (the same file as below). The console restarts once during
  the install, so the page may say it lost contact for a few seconds.

Outbound access: the check service needs HTTPS to `api.github.com`, `github.com` and
`objects.githubusercontent.com`. Behind a proxy, put `HTTPS_PROXY=http://proxy.example.net:3128`
in `/etc/radius-admin/update.env`.

**If an update fails.** The page shows the result; details are in
`/var/log/radius-admin/update-<version>-<time>.log` and `journalctl -u
'radius-admin-update-install@*'`. The database backup taken before the install is
`/var/backups/radius-admin/radius-db-before-<version>-<time>.dump`
(`pg_restore -d radius --clean` as postgres, only if a migration went wrong). By hand:
`sudo /opt/radius-admin-src/current/deploy/update.sh --rollback`. A server installed from a
checkout has no previous release to roll back to until its first update.

**Client shared secrets and rollback.** From 0.3.1 the RADIUS client shared secrets are stored
encrypted with the data key; the installer encrypts existing ones in its app phase. A rollback or
downgrade with `update.sh` to a release that cannot read them first writes them back in plain
(`unseal-client-secrets`) and stops, installing nothing, if that fails. Installing an older
release by other means (its `install.sh` directly) skips that step: run
`sudo -u radius-admin env RADIUS_ADMIN_CONFIG=/etc/radius-admin/radius-admin.conf
PYTHONPATH=/opt/radius-admin/app python3 -m radius_admin.cli unseal-client-secrets` first.

**Check a build by hand** (for example before uploading it to an offline server):

```bash
openssl dgst -sha384 -verify /usr/local/share/radius-admin/update-signing.pem \
    -signature manifest.json.sig manifest.json
```
```bash
sha384sum radius-admin-<version>.tar.gz     # compare with bundle.sha384 in manifest.json
```

## 10. Rollback of the whole change

```bash
sudo ./deploy/rollback.sh                       # uses the OLDEST installer tarball = pre-install state
sudo ./deploy/rollback.sh --tarball /var/backups/radius-admin/freeradius-<ts>.tar.gz
```

Stops and disables the UI, helper socket, nginx site and firewall table; saves the
current `/etc/freeradius` as `freeradius-before-rollback-<ts>.tar.gz`; restores the
tarball (original `mods-available/sql` → SQLite), runs `radiusd -XC`, restarts
FreeRADIUS and checks UDP 1812. PostgreSQL data stays. Anything changed in the UI after
migration (new switch-admin passwords, MAB devices) exists only in PostgreSQL.

---

## 11. Troubleshooting

* **FreeRADIUS will not start; `radius.log` shows `rlm_ldap … Bind credentials incorrect`
  (`data 52e`) and `Instantiation failed for module "ldap"`.** AD refuses the LDAP service
  account in `mods-available/ldap` (`identity` / `password`), and FreeRADIUS does not start
  without LDAP. `radiusd -XC` does not catch this (it never contacts AD). First stop the
  restart loop so the account is not locked out: `sudo systemctl stop freeradius`. Fix the
  `identity` / `password` line (test with
  `ldapwhoami -x -H ldaps://dc01.example.net -D '<identity>' -W`), then
  `sudo systemctl start freeradius`. The installer keeps the live `identity`, `password`,
  `base_dn`, `server` and `port` lines and the TLS settings (`ca_file`, `ca_path`, client
  certificate, `start_tls`, `require_cert`, `check_crl`) when it installs FreeRADIUS files,
  and tests the AD login before installing anything (it refuses on “Invalid credentials”).
* **Update fails in the freeradius phase with `Unable to check file '…/ca.pem'` and
  `Invalid configuration for module "ldap"`.** The LDAP CA file named in the new
  `mods-available/ldap` does not exist. Since 0.2.1 the installer takes `ca_file` and the other
  TLS settings from the live file; on 0.2.0 and earlier, the update restores the previous
  configuration (nothing changes) and you can update again once 0.2.1 is out.

| Symptom | Check / fix |
|---|---|
| Browser: connection times out | source not in 192.0.2.0/24 (by design); `nft list table inet radius_admin`; ufw rules; nginx bound to the right IP (`ss -ltnp`) |
| `403 Forbidden` from nginx | `allow/deny` in the site — client not in admin subnet (NAT?) |
| `400 The SSL certificate error` | the browser presented a client certificate that is revoked, expired, or **OCSP could not be checked** (responder `pki.example.net:8080` unreachable or DNS failing). nginx fails closed. Check `/var/log/nginx/radius-admin.error.log`. Workaround: use a browser profile without the certificate and sign in with TOTP. |
| nginx won't start: `host not found in OCSP responder` | `pki.example.net` must resolve at nginx start; fix DNS / `--resolver` |
| `502 Bad Gateway` | `systemctl status radius-admin`; `journalctl -u radius-admin`; socket perms `ls -l /run/radius-admin/` (srwxrwx--- radius-admin:radius-admin-web); `id www-data` must list radius-admin-web (restart nginx after adding) |
| App refuses to start: FIPS | FIPS mode only: `check-fips`; `/proc/sys/crypto/fips_enabled`; do not set `require_fips = false` on a server installed in FIPS mode |
| "helper unavailable" | `systemctl status radius-admin-helper.socket`; `ls -l /run/radius-admin-helper.sock` (root:radius-admin 0660) |
| "helper misconfigured" | `journalctl -t radius-admin-helper`; `/etc/radius-admin/helper.conf` must be root-owned, not group/world-writable, keys valid |
| Validate fails | output shows the radiusd error and line; most often custom policy syntax; fix and re-validate. "forbidden construct" = the policy uses `$INCLUDE`, `$ENV`, `$TEMPLATE`, `%{exec:}`, `Exec-Program`, backticks, an interpreter xlat or a numeric attribute alias (`Attr-<n>`); use attribute names instead |
| Apply → rolled back | FreeRADIUS did not become active/listening in 15 s; `journalctl -u freeradius`; run `radiusd -XC` |
| Apply fails "another apply … in progress" | wait; lock is released when the other request finishes |
| Device admin rejected | Auth log reason; source IP not in admin subnet; user not in `net-admins`; directory account not in an allowed group (§6.9a); legacy hash → reset password in UI; account disabled (`Auth-Type := Reject`) |
| MAB rejected | MAC registered + enabled? switch sends PAP (not EAP-MD5)? Calling-Station-Id matches User-Name? |
| EAP-TLS rejected | cert SAN DNS present? chains to Example-IssuingCA/Example-RootCA (`reject_unknown_intermediate_ca`)? OCSP reachable from FreeRADIUS? AD computer object in a rule group? `radiusd -X` |
| LDAP bind/TLS errors | libldap uses GnuTLS (preflight shows it); `cipher_list` is unset on purpose; check the DC's Schannel policy allows TLS 1.2 ECDHE-AES-GCM; `ldapsearch -H ldaps://dc01.example.net -x -D '<bind DN>' -W -b '' -s base` |
| `rlm_sql_postgresql` load error | §1.1; `ldd <libdir>/rlm_sql_postgresql.so` (needs libpq5) |
| DB permission denied | grants (`sql/30-grants.sql`), pg_hba order (`radius-admin` block must precede generic `local` lines) |

---

## 12. Clean-up and secure disposal (after verification)

Do this once the new setup has run correctly for an agreed period (e.g. 1 week) and
the rollback option is no longer needed.

1. **Old SQLite database — contains switch-admin passwords in CLEARTEXT**
   (`radpostauth.pass`, logged by the stock post-auth query). Not migrated.
   ```bash
   systemctl stop freeradius   # not needed: no longer used, but be sure nothing opens it
   shred -u -z -n 3 /var/lib/freeradius/sqlite/freeradius.db
   shred -u -z -n 3 /var/backups/radius-admin/freeradius-sqlite-*.db
   ```
   Note: `shred` is not reliable on journaling/CoW/thin-provisioned storage or SSDs.
   Also delete VM snapshots and backups that contain the file, per the media
   sanitization procedure (NIST SP 800-88).
2. **Rotate all switch-admin passwords** — they were exposed in cleartext. Reset each
   in the UI (stored as PBKDF2-HMAC-SHA256, 600 000 iterations; the legacy
   `Crypt-Password` row is removed). Tell the admins.
3. **Remove the FreeRADIUS bootstrap test CA** in `/etc/freeradius/certs/`
   (ca.key, ca.pem, server.*, client.*, user@example.org.*, 01.pem, 02.pem, index*,
   serial*, passwords.mk, *.cnf, Makefile, bootstrap). Production uses only
   `certs/site/`. First confirm nothing references them:
   `grep -rn 'certs/\(ca\|server\|client\)' /etc/freeradius --include=* | grep -v '^#'`,
   then move them to an encrypted archive or shred, and run `radiusd -XC`.
4. The installer tarballs in `/var/backups/radius-admin/` contain the old config
   (LDAP bind password, shared secrets). Keep the oldest until the rollback period ends,
   then shred.
5. Rotate the LDAP bind password and RADIUS shared secrets on the normal schedule (see
   SECURITY.md findings).

---

## 13. Universal edition features

### 13.1 Interactive install and answers file

`sudo ./deploy/install.sh` with no options asks for the server name, management subnet,
portal address, switch networks (where the monitor may send SNMP and CoA, §6.3), DNS resolvers, portal certificate, first administrator, crypto mode (standard by default, FIPS mode on request: §3), the 802.1X (EAP) certificate of a new server and an OCSP responder (§13.4), shows a summary and
asks for confirmation. Unattended: `--answers FILE` (format in `deploy/answers.sh`);
`--print-answers` only checks and prints. The answers are kept in `/etc/radius-admin/site.yaml`
(root 0640); re-run later with `--answers /etc/radius-admin/site.yaml`. If a first install stops
before it saved them (before the `site` phase), a re-run on a terminal asks the questions again,
even with options such as `--skip-preflight`. On such a half-installed new server, preflight
reports the package's stock FreeRADIUS configuration failing `radiusd -XC` as information: the
`freeradius` phase replaces it. The PostgreSQL cluster must be on port 5432 (radius-admin uses
its Unix socket only); if 5432 was taken when the cluster was created, the `postgres` phase stops
and prints the `pg_conftool … set port 5432` command that fixes it.

Runs without answers (updates, or `--phase nginx` by hand) keep the portal settings this server
already uses: server name, management subnet, portal address and resolvers come from `site.yaml`,
else from the installed nginx site, else from the firewall table, and the OCSP responder from the
nginx site. To see what a run would use: `sudo ./deploy/install.sh --print-settings`. To change
one, give the option (`--admin-net`, `--listen-ip`, `--server-name`, `--resolver`); it wins over
`site.yaml` and answers files, and the `nginx`/`firewall` phases record the new value in
`site.yaml` so later updates keep it. With nothing installed and no option or answers, these two
phases stop rather than open the portal to the 192.0.2.0/24 example subnet.

Portal certificate choices:
- `self-signed`: ECDSA P-384 for the server name (browsers warn; replace it later by installing
  your CA's certificate as `/etc/radius-admin/tls/server.crt` and running `--phase nginx`).
- `csr`: the run stops after `deploy/make-csr.sh`; install the issued certificate, then
  `sudo ./deploy/install.sh --answers /etc/radius-admin/site.yaml --from nginx`.
- `existing`: give `tls_cert` and `tls_key`.

The bootstrap phase creates the first administrator and prints a one-time password. After
signing in, the dashboard shows the **setup checklist** until it is finished.

### 13.2 RadSec

1. RADIUS clients → **RadSec listener**: turn it on (default TCP 2083 on all addresses), optionally
   enable OCSP (responder from the certificate, or a fixed URL).
2. Edit the access point → Transport **RadSec**; optionally enter the name its certificate carries
   (CN or DNS name). The device needs a certificate from the site CA (the 802.1X CA) and must trust
   this server's RADIUS certificate.
3. **Apply changes**. Allow TCP 2083 from the access points in any firewall in front of the server.
4. Check: Auth log entries from the device; a rejected one with "RadSec certificate does not match"
   means the certificate name differs from the client's setting. In `radiusd -X` style logs,
   "Ignoring request … from unknown client" means the device's address is not a RadSec client.

CoA to RadSec clients still goes over UDP to the client's CoA port.

### 13.3 Single sign-on with Microsoft Entra ID

1. Console → **Single sign-on**: note the Identifier (Entity ID) and Reply URL.
2. Entra admin center → Enterprise applications → New application → Create your own → SAML.
   Enter the Identifier and Reply URL. Signing: SHA-256. Attributes & Claims → Add a group claim →
   "Groups assigned to the application" (avoids the 150-group overage). Assign the groups that
   should have access. Download **Federation Metadata XML**.
3. Console: paste the metadata, map each group's **Object ID** to viewer / operator / admin, choose
   whether local passwords stay for every account or administrators only, turn SSO on.
4. Test in a private window with an account in a mapped group. Refusals are in the Audit log
   (`auth.login`, `method: saml`, with the reason).
5. Keep at least one local administrator with MFA as break-glass access.

### 13.4 A new server: directory, EAP certificates and OCSP

On a new server (FreeRADIUS never set up by radius-admin and no SQLite database to migrate) the
`freeradius` phase installs a working configuration that rejects every 802.1X user until you
configure it. It needs nothing from the stock FreeRADIUS files:

- **Access rules** may be empty: a warning says that every 802.1X user is rejected until you add
  rules in the portal. (With a SQLite database present the phase still refuses and asks for the
  `migrate` phase first.)
- **Directory: not configured.** `mods-available/ldap` gets the line
  `#  radius-admin: directory not configured`, an empty password, the server
  `ldaps://directory.invalid` and a connection pool that does not connect at start. FreeRADIUS
  starts. Directory lookups fail, so EAP-TLS and directory accounts are rejected, while local
  accounts, PEAP/TTLS with local users and MAB work. Updates keep this state while the marker line
  is there.
- **EAP certificates** in `/etc/freeradius/certs/site/` (`radius.pem`, `radius.key`, `ca.pem`):
  the installer asks whether you have them (answers `eap_tls: existing` with `eap_cert`, `eap_key`
  and `eap_ca`, the CA that issues client certificates). If you don't, it makes **self-signed**
  ones: a throwaway ECDSA P-384 CA signs the server certificate for the server name, then its key
  is destroyed. Replace them: no client certificate can chain to that CA. Files already in
  `certs/site/` are kept.
- **localhost client secret**: a random one replaces the stock `testing123`.
- **OCSP** for EAP-TLS and portal client certificates: only with a responder (answers `ocsp_url`,
  or `RA_OCSP_URL` in the environment). Without one, EAP OCSP is off and the nginx site has no
  `ssl_ocsp` lines. Preflight checks the responder's name only when one is set.

**Set up the directory later** (by hand until the portal's Setup step exists):

1. In `/etc/freeradius/mods-available/ldap` set `server`, `port`, `identity`, `password`,
   `base_dn` and, in `tls { }`, `ca_file` (the CA of your domain controllers). Test the login with
   the same values first:
   `LDAPTLS_CACERT=<ca_file> ldapwhoami -x -H ldaps://dc01.example.net -D '<identity>' -W`.
2. Delete the line `#  radius-admin: directory not configured`.
3. `sudo ./deploy/install.sh --phase freeradius --restart-freeradius`. The phase now carries your
   settings over, tests the bind and starts the connection pool as shipped. Updates keep them.

**Replace the EAP certificates** in the console: **Certificates** (§13.5), then Apply changes.

### 13.5 Certificates in the console

**Network access → Certificates** shows the installed certificates (subject, issuer, expiry, key
type, fingerprint) and lets an administrator (with step-up) change them. Nothing is installed until
**Apply changes**; the Apply page lists what changes, with private keys only as fingerprints.

- **802.1X server certificate** (FreeRADIUS, also RadSec) and **portal HTTPS certificate**:
  - *Upload a certificate and key*: PEM certificate (server certificate first, then the
    intermediate CAs, or the intermediates as a second file) and PEM key, with its password if it
    has one; or one PKCS#12 file (.p12/.pfx) with its password.
  - *Make a key and certificate request here*: give the DNS name(s) and key type (ECDSA P-384 by
    default), download the `.csr`, have your CA issue the certificate (TLS Web Server template),
    then upload the issued certificate (and the intermediates). The key never leaves the server.
  - The portal certificate must name the portal (its `server_name`); the 802.1X certificate needs
    the name your supplicants are configured to expect.
- **Client certificate CA**: the issuing and root CA certificates of your client certificates.
  FreeRADIUS trusts them for EAP-TLS and the portal for client-certificate sign-in.
- **OCSP for EAP-TLS**: leave as installed, off, or on with the responder URL.

Allowed keys: RSA 3072 bits or more, ECDSA P-256 or P-384. Expired certificates, CA certificates as
server certificates, and certificates for client authentication only are refused.

On Apply the helper checks everything again, validates FreeRADIUS with the new files, restarts it,
then (portal certificate or client CA) tests and reloads nginx and checks that the portal serves
the new certificate. If any step fails, every file of that apply is put back. A rollback on the
Apply page also restores the certificate files of that backup.

**Stop managing it here** leaves the installed certificate as it is and stops the console from
changing it. Note: re-running the installer with `tls: existing` in the answers installs the
portal certificate files those answers name; remove `tls_cert`/`tls_key` (or use `tls: self-signed`,
which keeps an existing certificate) once the console manages the portal certificate.

Troubleshooting: "the private key does not belong to the certificate" (wrong key file, or for an
issued certificate: the CA signed another request); "does not name …" (add the name as a DNS
subject alternative name); "key type … is not allowed" (re-issue with RSA 3072+ or ECDSA).

### 13.6 Licence

radius-admin is source available under the Business Source License 1.1; see LICENSING.md. Nothing
is locked whatever you record.

1. Settings → **Licence**: choose free use (personal, or fewer than 50 people) or commercial. For
   commercial, install the licence file, or, without one yet, press "Start the 60-day trial". This
   is the first setup step: an admin is taken to this
   page at sign-in until it is answered (operators, viewers and RADIUS are never affected). The
   60-day trial starts the first time you choose it and does not restart. Changing the answer later
   asks you to confirm the licence definitions; earlier answers are listed on the page.
2. A commercial licence or written exception is a `.json` licence file (upload or paste). It is checked on the server against the project's public key. A renewed
   licence is installed the same way.
3. Admins see one line on the dashboard when something needs attention (a trial ending, a licence
   expiring); "Hide for 30 days" hides that line. After a trial ends, a banner on every admin page
   says so until a licence is installed or the answer changes. Changes are in the Audit log
   (`licence.*`).

**Issuing licences (maintainer).** On the machine that holds the signing key, as root:

    tools/licence/licence-tool.py serve          # prints http://localhost:8766/?token=…
    tools/licence/licence-tool.py issue --licensee "Example Corp" --tier 50-249
    tools/licence/licence-tool.py list

Files: `/root/.config/radius-admin/licence-signing/` (`signing-key.pem` 0600, `public.pem`,
`register.json`, `issued/`). Back up the whole directory offline after issuing. Revoking only marks
the register: a server keeps a revoked file valid until it expires, so issue revocable deals with
short terms. To rotate the key: move the old directory aside, `keygen`, copy `public.pem` to
`app/radius_admin/licence_keys/<key id>.pem` in the next release, keep the old public key there
until the licences it signed have expired (remove it at once if it was exposed).
