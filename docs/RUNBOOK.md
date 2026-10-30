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
| Kernel FIPS on | `cat /proc/sys/crypto/fips_enabled` → `1` |
| Ubuntu Pro FIPS stream | `pro status` (see SECURITY.md §1 about `fips-updates` vs `fips`) |
| Internal apt mirror reachable | `apt-get update` |
| Packages available | `apt-cache policy postgresql nginx python3-flask python3-psycopg2 gunicorn python3-cryptography python3-qrcode nftables` |
| FreeRADIUS unit + binary | `systemctl list-unit-files 'freeradius*' 'radiusd*'`; `command -v radiusd freeradius` |
| **`rlm_sql_postgresql.so` in the custom build** | see below |
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

### 3.0 Before the window

```bash
sudo ./deploy/preflight.sh
sudo ./deploy/make-csr.sh                 # ECDSA P-384; add --ip <management-IP> if wanted; --rsa for RSA-3072
cat /etc/radius-admin/tls/server.csr      # submit to pki.example.net (TLS Web Server template)
# when issued (leaf first, then Example-IssuingCA):
sudo install -o root -g root -m 0644 radius.example.net-chain.pem /etc/radius-admin/tls/server.crt
sudo ./deploy/install.sh --phase packages,users -y     # no service impact
```

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
   phase **stops before changing anything**.
3. Renders the initial `policy.d/radius-admin` and `radius-admin-clients.conf` from the
   database with `python3 -m radius_admin.cli render` (as `radius-admin`) and installs
   them root:freerad 0640; also leaves them in the app's staging dir.
4. Removes the symlinks listed in `freeradius/modules-to-disable.txt` (including
   `exec`: nothing in the new configuration runs external programs) and
   `sites-enabled/inner-tunnel`.
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
  80) is disabled; nothing listens on port 80.
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
sudo -u radius-admin env RADIUS_ADMIN_CONFIG=/etc/radius-admin/radius-admin.conf PYTHONPATH=/opt/radius-admin/app python3 -m radius_admin.cli check-fips
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
| `1.3.6.1.2.1.17.7.1.4.5.1.1` | port VLAN (dot1qPvid) — per-port view |

(`1.0.8802.1.1.1` already covers the per-port 802.1X state and session user. Without the
three per-port rows the port table still shows the 802.1X state but no link or VLAN.)

Restrict SNMP access on the switch to this server's address, and allow UDP 161 from
this server to the switches in any firewall between them. (The Catalyst 1300 web UI has
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

**Actions** (operator or admin), from the *Actions* menu of an open session:

| Action | What the switch does |
|---|---|
| Re-authenticate | re-runs 802.1X/MAB for the session; link stays up (picks up a changed VLAN or MAB entry) |
| Bounce port | shuts the port briefly and re-enables it; the device reconnects |
| Disconnect | ends the session; the device must authenticate again |

These are RADIUS Change-of-Authorization messages (RFC 5176) sent by the monitoring
service with `radclient` from your FreeRADIUS build, to UDP **1700** on the switch
(Catalyst 1300; changeable under Switch monitoring → Session actions). Requirements on
each switch (firmware **4.1.3.36 or later**):

```
aaa server radius dynamic-author
 client <this RADIUS server's IP> server-key <the switch's shared secret in this console>
 exit
```

Cisco documents ISE as the tested CoA client for the 1300 series; the requests use the
same attributes ISE sends for these actions (Acct-Session-Id, Calling-Station-Id,
NAS-Port-Id, Event-Timestamp, Message-Authenticator and the Cisco AV-pairs
`subscriber:command=reauthenticate` / `bounce-host-port`). **Test once on one switch**
before relying on it; the result page shows the switch's ACK or NAK (with Error-Cause),
and every request and result is in the audit log. `install.sh --phase app` reports
whether it found radclient; if it lives somewhere unusual set
`radclient = /path/to/radclient` in `/etc/radius-admin/radius-admin.conf`.

### 6.5 Alerts

UI → **Alerts**. The monitoring service checks every minute and raises:

* **Reject spike**: N or more rejects within M minutes (default 25 in 5); clears below N/2.
* **Switch not responding**: a switch marked for monitoring failed N SNMP polls in a row
  (default 2). Needs switch monitoring enabled.
* **FreeRADIUS down**: the service is stopped or not listening on its RADIUS port in two
  checks in a row (so the brief restart of Review and apply never alerts).

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
service may only reach the management subnet; for a relay outside it add one exception:

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
  most 2000 MACs; entries not seen for 30 days are removed.

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
list changed, `postgres` if `sql/` or `deploy/postgres/` changed, always `app`, and `nginx`
or `firewall` if their templates changed. FreeRADIUS files are only installed with
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
  `base_dn` and `server` lines when it installs FreeRADIUS files, and tests the AD login
  before installing anything (it refuses on “Invalid credentials”).

| Symptom | Check / fix |
|---|---|
| Browser: connection times out | source not in 192.0.2.0/24 (by design); `nft list table inet radius_admin`; ufw rules; nginx bound to the right IP (`ss -ltnp`) |
| `403 Forbidden` from nginx | `allow/deny` in the site — client not in admin subnet (NAT?) |
| `400 The SSL certificate error` | the browser presented a client certificate that is revoked, expired, or **OCSP could not be checked** (responder `pki.example.net:8080` unreachable or DNS failing). nginx fails closed. Check `/var/log/nginx/radius-admin.error.log`. Workaround: use a browser profile without the certificate and sign in with TOTP. |
| nginx won't start: `host not found in OCSP responder` | `pki.example.net` must resolve at nginx start; fix DNS / `--resolver` |
| `502 Bad Gateway` | `systemctl status radius-admin`; `journalctl -u radius-admin`; socket perms `ls -l /run/radius-admin/` (srwxrwx--- radius-admin:radius-admin-web); `id www-data` must list radius-admin-web (restart nginx after adding) |
| App refuses to start: FIPS | `check-fips`; `/proc/sys/crypto/fips_enabled`; never set `require_fips = false` in production |
| "helper unavailable" | `systemctl status radius-admin-helper.socket`; `ls -l /run/radius-admin-helper.sock` (root:radius-admin 0660) |
| "helper misconfigured" | `journalctl -t radius-admin-helper`; `/etc/radius-admin/helper.conf` must be root-owned, not group/world-writable, keys valid |
| Validate fails | output shows the radiusd error and line; most often custom policy syntax; fix and re-validate. "forbidden construct" = the policy uses `$INCLUDE`, `$ENV`, `$TEMPLATE`, `%{exec:}`, `Exec-Program`, backticks, an interpreter xlat or a numeric attribute alias (`Attr-<n>`); use attribute names instead |
| Apply → rolled back | FreeRADIUS did not become active/listening in 15 s; `journalctl -u freeradius`; run `radiusd -XC` |
| Apply fails "another apply … in progress" | wait; lock is released when the other request finishes |
| Switch admin rejected | Auth log reason; source IP not in admin subnet; user not in `net-admins`; legacy hash → reset password in UI; account disabled (`Auth-Type := Reject`) |
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
portal address, DNS resolvers, portal certificate and first administrator, shows a summary and
asks for confirmation. Unattended: `--answers FILE` (format in `deploy/answers.sh`);
`--print-answers` only checks and prints. The answers are kept in `/etc/radius-admin/site.yaml`
(root 0640); re-run later with `--answers /etc/radius-admin/site.yaml`.

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
