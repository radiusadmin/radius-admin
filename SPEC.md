# radius-admin — Design Specification (authoritative contract)

All components MUST follow this document. If something here is wrong or impossible,
stop and report it rather than silently diverging. Paths, names, table/column names,
the helper protocol and the policy template are contracts between components.

## 0. Reference environment

The reference build targets (example names; every site sets its own):
- Server `radius01` / `radius.example.net`: Ubuntu 24.04 LTS, Python 3.12, OpenSSL 3.0,
  PostgreSQL 16. Optionally kernel FIPS mode (`/proc/sys/crypto/fips_enabled = 1`, Ubuntu
  Pro FIPS stream). Only apt packages from Ubuntu main/universe are used (no pip; the
  server may have no internet access, only an apt mirror).
- FreeRADIUS 3.2.x. On a FIPS host it is a custom build with `--enable-fips-workaround`
  (FreeRADIUS uses its own internal MD4/MD5 so RADIUS works on FIPS OpenSSL). raddb =
  `/etc/freeradius` (`confdir = ${raddbdir}`, `certdir = cadir = ${confdir}/certs`). Runs
  as user/group `freerad`; the systemd unit name is auto-detected / configurable.
- An existing SQLite FreeRADIUS database may be migrated to PostgreSQL
  (`deploy/migrate_sqlite_to_pg.py`).
- Clients: `clients.conf` keeps `client localhost`; switches and access points are managed
  in the UI and rendered to a clients file.
- 802.1X: EAP-TLS only (machine certificates from an internal PKI, e.g. `pki.example.net`,
  with OCSP). LDAPS to Active Directory (e.g. `dc01.example.net`); the user filter matches
  the computer object by `dNSHostName = TLS-Client-Cert-Subject-Alt-Name-Dns`;
  `LDAP-Group` checks select the VLAN.
- Switch admin logins: PAP from the management subnet (example 192.0.2.0/24); the user
  must be in SQL group `net-admins`. The UI is reachable only from the admin network.

Verified in FreeRADIUS 3.2.10 source:
- Postgres `nas` table has NO require_message_authenticator column and rlm_sql
  `read_clients` gives SQL clients the GLOBAL `security { require_message_authenticator }`.
  => DECISION: clients are NOT read from SQL. The UI renders a clients file
  (`/etc/freeradius/radius-admin-clients.conf`) so per-client
  `require_message_authenticator` / `limit_proxy_state` work.
- rlm_pap verifies PBKDF2 via OpenSSL `PKCS5_PBKDF2_HMAC` (validated module path).
  Format we use, stored in radcheck as
  `Password-With-Header := "{X-PBKDF2}HMACSHA2+256:<b64(4-byte big-endian iterations)>:<b64 salt>:<b64 hash>"`
  (standard base64 with padding). Iterations 600000, salt 16 bytes, hash 32 bytes.
- Default postgres `post-auth` query logs `User-Password` into `radpostauth.pass`.
  The current SQLite DB therefore contains switch-admin CLEARTEXT passwords.
  => DECISION: replace the post-auth query; never store passwords; do not migrate `pass`.

## 1. Repository layout

```
radius-admin/
  SPEC.md                      this file
  README.md                    overview / quick start            (DEPLOY agent)
  docs/RUNBOOK.md              install, migrate, verify, rollback (DEPLOY agent)
  docs/SECURITY.md             FIPS boundary, exceptions, 800-171 mapping, findings (DEPLOY agent)
  app/                         Python application                 (APP agent, except unlang.py)
    radius_admin/
      __init__.py              create_app()
      unlang.py                policy + clients file rendering & validators (FR agent owns)
      ...
    tests/
  helper/radius-admin-helper   root helper, python3 stdlib only   (DEPLOY agent)
  sql/                         Postgres DDL                       (FR agent)
    00-roles.sql 10-freeradius-schema.sql 20-radius-admin-schema.sql 30-grants.sql
  freeradius/                  FreeRADIUS config deliverables     (FR agent)
    mods-available/sql
    mods-available/eap
    mods-available/ldap
    mods-config/sql/main/postgresql/queries.conf
    sites-available/default
    clients.conf
    mods-config/files/authorize
    modules-to-disable.txt
    diffs/*.diff               unified diffs vs stock FreeRADIUS 3.2.10 raddb
  deploy/                      (DEPLOY agent unless stated)
    install.sh                 idempotent installer
    preflight.sh               read-only checks before anything changes
    migrate_sqlite_to_pg.py    (FR agent)
    rollback.sh
    make-csr.sh
    nginx/radius-admin.conf
    systemd/radius-admin.service
    systemd/radius-admin-helper.socket
    systemd/radius-admin-helper@.service
    postgres/pg_hba.conf.snippet  postgres/pg_ident.conf.snippet
    etc/radius-admin.conf.example
```

## 2. OS accounts, paths, permissions

| Item | Value |
|---|---|
| App OS user/group | `radius-admin` (system, no login shell, home `/var/lib/radius-admin`) |
| Web socket group | `radius-admin-web`; `www-data` is a member |
| App code | `/opt/radius-admin/` (root:root 0755) |
| App config | `/etc/radius-admin/radius-admin.conf` (root:radius-admin 0640), INI format |
| Key file | `/etc/radius-admin/keys/data.key` 32 random bytes (radius-admin:radius-admin 0400) — AES-256-GCM key for TOTP secrets |
| Gunicorn socket | `/run/radius-admin/app.sock` (dir radius-admin:radius-admin-web 0750) |
| Staging dir | `/var/lib/radius-admin/staging/` (radius-admin:radius-admin 0700) files `policy`, `clients` |
| Helper | `/usr/local/libexec/radius-admin/radius-admin-helper` (root 0755) |
| Helper socket | `/run/radius-admin-helper.sock` root:radius-admin 0660, systemd socket activated, Accept=yes |
| Helper work | `/var/lib/radius-admin-helper/` (root 0700): `backups/<UTC ts>/`, `validate/`, `state.json`, lock file |
| Generated policy | `/etc/freeradius/policy.d/radius-admin` (root:freerad 0640) |
| Generated clients | `/etc/freeradius/radius-admin-clients.conf` (root:freerad 0640) |

Config file `/etc/radius-admin/radius-admin.conf` (INI):
```
[app]
require_fips = true
db_dsn = dbname=radius host=/var/run/postgresql user=radius_admin
key_file = /etc/radius-admin/keys/data.key
helper_socket = /run/radius-admin-helper.sock
staging_dir = /var/lib/radius-admin/staging
session_idle_minutes = 15
session_absolute_hours = 8
stepup_minutes = 5
lockout_threshold = 5
lockout_minutes = 15
password_min_length = 15
password_history = 5
pbkdf2_iterations = 600000
log_syslog = true
[helper]          # read by helper only (helper also reads /etc/radius-admin/helper.conf if present, root-owned, preferred)
service = freeradius
radiusd = /usr/sbin/radiusd
raddb = /etc/freeradius
freerad_user = freerad
```
The helper MUST read its settings from root-owned `/etc/radius-admin/helper.conf`
(root:root 0644, same `[helper]` keys) — never from anything the app can write.

## 3. PostgreSQL

Database `radius`, owner role `radius_owner` (NOLOGIN). Local only:
`listen_addresses = ''` is NOT required, but pg_hba must only allow `local` peer auth
for these roles. No passwords anywhere.

Roles (LOGIN, peer-mapped via pg_ident map `radiusmap`):
- `radius_fr`   ← OS user `freerad`        (FreeRADIUS)
- `radius_admin` ← OS user `radius-admin`  (web app + its CLI)
pg_hba lines (before any generic local line):
```
local  radius  radius_fr     peer map=radiusmap
local  radius  radius_admin  peer map=radiusmap
```
pg_ident:
```
radiusmap  freerad        radius_fr
radiusmap  radius-admin   radius_admin
```
Migration/DDL runs as `postgres` superuser; objects owned by `radius_owner`.
`password_encryption = scram-sha-256` (default) — no role has a password anyway.

### 3.1 FreeRADIUS tables (schema `public`) — from 3.2.10 postgresql schema.sql
radacct, radcheck, radgroupcheck, radgroupreply, radreply, radusergroup, nas, nasreload
unchanged, PLUS modified `radpostauth`:
```
CREATE TABLE radpostauth (
  id bigserial PRIMARY KEY,
  username text NOT NULL,
  reply text,                         -- Access-Accept / Access-Reject
  authmethod text,                    -- 'eap-tls' | 'pap-admin' | 'mab' | 'other'
  nasipaddress inet,
  calledstationid text,
  callingstationid text,
  nasporttype text,
  vlan text,                          -- reply:Tunnel-Private-Group-Id
  certsan text,                       -- TLS-Client-Cert-Subject-Alt-Name-Dns
  authdate timestamptz NOT NULL DEFAULT now(),
  class text
);  -- NO password column. Index on authdate, username.
```
New table (FreeRADIUS reads it, app writes it):
```
CREATE TABLE mab_device (
  id serial PRIMARY KEY,
  mac text NOT NULL UNIQUE CHECK (mac ~ '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$'),
  vlan integer NOT NULL CHECK (vlan BETWEEN 1 AND 4094),
  description text NOT NULL DEFAULT '',
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
```
Grants:
- radius_fr: SELECT on radcheck, radreply, radgroupcheck, radgroupreply, radusergroup,
  nas, mab_device; INSERT on radpostauth; SELECT/INSERT/UPDATE on radacct; USAGE on
  their sequences. Nothing on schema `ui`.
- radius_admin: SELECT/INSERT/UPDATE/DELETE on radcheck, radreply, radusergroup,
  radgroupcheck, radgroupreply, mab_device; SELECT on radpostauth, radacct, nas;
  sequence usage; plus schema `ui` grants below.

### 3.2 App schema `ui` (owner radius_owner)
```
ui.admin_user(
  id serial PK, username text UNIQUE NOT NULL CHECK (username ~ '^[a-z0-9._-]{2,64}$'),
  display_name text NOT NULL DEFAULT '', role text NOT NULL CHECK (role IN ('viewer','operator','admin')),
  password_hash text NOT NULL,            -- 'pbkdf2-sha256$<iter>$<b64salt>$<b64hash>'
  password_changed_at timestamptz NOT NULL DEFAULT now(),
  must_change_password boolean NOT NULL DEFAULT true,
  failed_count integer NOT NULL DEFAULT 0, locked_until timestamptz,
  mfa_method text CHECK (mfa_method IN ('totp','cert')),
  totp_secret_enc bytea, totp_last_step bigint,
  cert_sha256 text, cert_subject text,
  enabled boolean NOT NULL DEFAULT true,
  last_login_at timestamptz, last_login_ip inet,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())
ui.password_history(id serial PK, user_id int REFERENCES ui.admin_user ON DELETE CASCADE, password_hash text, created_at timestamptz default now())
ui.session(id serial PK, token_sha256 text UNIQUE NOT NULL, user_id int REFERENCES ui.admin_user ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(),
  mfa_ok boolean NOT NULL DEFAULT false, stepup_at timestamptz, csrf_token text NOT NULL,
  ip inet, user_agent text)
ui.login_attempt(id bigserial PK, ip inet, username text, success boolean, at timestamptz default now())
ui.radius_client(
  id serial PK, name text UNIQUE NOT NULL CHECK (name ~ '^[A-Za-z0-9._-]{1,63}$'),
  ipaddr text NOT NULL,                   -- IPv4/IPv6 address or CIDR, validated in app
  secret text NOT NULL,                   -- RADIUS shared secret (must be cleartext for RADIUS)
  require_ma text NOT NULL DEFAULT 'auto' CHECK (require_ma IN ('yes','no','auto')),
  limit_proxy_state text NOT NULL DEFAULT 'auto' CHECK (limit_proxy_state IN ('yes','no','auto')),
  nas_type text NOT NULL DEFAULT 'other', description text NOT NULL DEFAULT '',
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())
ui.access_rule(
  id serial PK, priority integer NOT NULL,
  connection text NOT NULL CHECK (connection IN ('wired','wireless')),
  ssid text,                              -- required iff wireless
  ad_group text NOT NULL, vlan integer NOT NULL CHECK (vlan BETWEEN 1 AND 4094),
  description text NOT NULL DEFAULT '', enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())
ui.setting(key text PK, value text NOT NULL, updated_at timestamptz default now())
   -- keys: admin_subnet (default '192.0.2.0/24'), admin_priv15 ('true'),
   --       custom_policy (default ''), banner_text
ui.apply_log(id serial PK, at timestamptz default now(), actor text, action text,
  policy_sha256 text, clients_sha256 text, success boolean, message text, backup_id text)
ui.audit_log(id bigserial PK, at timestamptz NOT NULL DEFAULT now(), actor text, actor_ip inet,
  action text NOT NULL, object_type text, object_id text, detail jsonb, success boolean NOT NULL,
  prev_hash text NOT NULL, hash text NOT NULL)
```
radius_admin: full DML on ui.* EXCEPT ui.audit_log where it has only SELECT, INSERT
(+ sequence usage). A trigger on ui.audit_log raises on UPDATE/DELETE/TRUNCATE.
Audit hash: `hash = sha256_hex(prev_hash + canonical_json(row fields except id/hash))`,
genesis prev_hash = 64 zeros. Insert must be serialized with
`SELECT pg_advisory_xact_lock(7212001)` inside the transaction (LOCK TABLE is not
possible: radius_admin has no UPDATE/DELETE on that table).

The SQL files in `sql/` are ALREADY WRITTEN and validated (by the lead). Agents must not
change them without reporting why. A sandbox PostgreSQL 16 cluster is running
(`pg_ctlcluster 16 main`, socket /var/run/postgresql) with roles and database `radius`
loaded from these files.

## 4. FreeRADIUS changes (FR agent)

1. `mods-available/sql`: dialect postgresql, driver rlm_sql_postgresql,
   `radius_db = "dbname=radius host=/var/run/postgresql user=radius_fr"`, `read_clients`
   stays commented/no. Keep pool settings. Requires `rlm_sql_postgresql.so` in the
   custom build (preflight checks; RUNBOOK documents rebuilding with libpq-dev).
2. `queries.conf` (postgresql) post-auth query → insert into the new radpostauth columns,
   never User-Password. authmethod derived: `&control:Tmp-String-1` set by policy
   (see §5) else 'other'.
3. `sites-available/default`:
   - authorize: remove `chap`, `mschap`, `digest`; after `preprocess` insert
     `radius_admin_mab` then `if (&control:Auth-Type == Accept) { return }`... (exact
     form is FR agent's choice but MAB must not hit LDAP/PAP).
   - authenticate: remove CHAP, MS-CHAP, `mschap`, `digest`.
   - post-auth: replace the hand-written "Site policy" block (orig lines 847–934) with
     the single line `radius_admin_postauth`. Everything else unchanged.
4. `inner-tunnel` removed from sites-enabled (no PEAP/TTLS).
5. `mods-available/eap`: keep only `tls-config tls-common` + `tls`. Remove md5, psk,
   gtc, ttls, peap, mschapv2. Remove `ca_path = ${cadir}` (test CA lives there). Set
   `reject_unknown_intermediate_ca = yes` (certs/site/ca.pem = Example-IssuingCA + Example-RootCA,
   sizes match). cipher_list = FIPS list (§7). Keep OCSP as is.
6. `mods-available/ldap`: `ldap_debug = 0x0000`, `tls_min_version = "1.2"`,
   `cipher_list` = FIPS list. Nothing else.
7. Modules to remove from mods-enabled: chap, digest, dpsk, dynamic_clients, echo,
   mschap, ntlm_auth, passwd, unix, totp, replicate, radutmp, sradutmp,
   proxy_rate_limit. (Validate with `radiusd -XC`; keep anything still referenced.)
8. `mods-config/files/authorize`: remove `bob` and `doug`.
9. `clients.conf`: keep `client localhost`; replace `wifi-aps` block and
   `$INCLUDE switches.conf` with `$INCLUDE radius-admin-clients.conf` (those clients are
   imported into ui.radius_client by the migration).
10. Must be validated against a real FreeRADIUS 3.2.10 built from source with
   `--enable-fips-workaround` (sandbox), including functional radtest checks.

## 5. Generated unlang (FR agent implements in `app/radius_admin/unlang.py`)

`render_policy(settings: dict, rules: list[dict], custom: str) -> str` produces the full
content of `/etc/freeradius/policy.d/radius-admin`. It defines exactly these policies:

- `radius_admin_mab` (authorize): if no EAP-Message AND NAS-Port-Type == Ethernet AND
  User-Name is a MAC (12 hex digits, separators `-`, `:`, `.` optional, any case):
  normalize to `AA-BB-CC-DD-EE-FF`; if Calling-Station-Id present and its normalized
  value differs → reject; look up `SELECT vlan FROM mab_device WHERE mac='<norm>' AND
  enabled LIMIT 1` via `%{sql:...}`; found → `control:Auth-Type := Accept`,
  `control:Tmp-String-0 := <vlan>`, `control:Tmp-String-1 := "mab"`; not found → reject.
  Non-MAB requests: noop.
- `radius_admin_postauth` (post-auth):
  1. MAB (`control:Tmp-String-1 == "mab"`): reply Tunnel-Type := VLAN,
     Tunnel-Medium-Type := IEEE-802, Tunnel-Private-Group-Id := control:Tmp-String-0.
  2. Admin login (same condition as original: no EAP-Message, NAS-Port-Type absent or
     != Ethernet, no Called-Station-Id): accept only if `Packet-Src-IP-Address` is in
     `settings.admin_subnet` AND `SQL-Group == "net-admins"`; set
     `control:Tmp-String-1 := "pap-admin"`; if `settings.admin_priv15` is true add
     `reply:Cisco-AVPair += "shell:priv-lvl=15"`; else reject.
  3. EAP: reject if no `TLS-Client-Cert-Subject-Alt-Name-Dns`; set Tmp-String-1
     "eap-tls"; then rules: wired rules (connection=wired, NAS-Port-Type == Ethernet)
     and per-SSID wireless rules (`Called-Station-Id =~ /:<escaped ssid>$/`), each
     group an if/elsif chain ordered by priority, first matching `LDAP-Group == "<g>"`
     sets the 3 VLAN reply attrs; no match → reject; unknown SSID → reject. Disabled
     rules omitted. Must reproduce the original behaviour exactly when fed the
     original rules (seed data in §8).
  4. `radius_admin_custom` is called last; its body is `settings.custom_policy` verbatim
     (empty → `noop`).
- Header comment: generated by radius-admin, timestamp NOT included (output must be
  deterministic for hashing), "do not edit".
Validators (raise ValueError with a human message):
`validate_ssid` `^[A-Za-z0-9 _.\-]{1,32}$`; `validate_ad_group` `^[A-Za-z0-9 _.()&\-]{1,64}$`;
`validate_vlan` 1–4094; `validate_mac` → normalized; `validate_client_name`;
`validate_ipaddr` (ipaddress module: address or network); `validate_secret`
(16–128 printable ASCII, no `"` `\` or whitespace); `validate_custom_policy`
(≤ 64 KiB; reject `$INCLUDE`, `$-INCLUDE`, `$ENV`, `$TEMPLATE`, `exec` xlat, `Exec-Program`,
backticks, `perl`, `python`; must have balanced braces).
`render_clients(clients: list[dict]) -> str`: one `client <name> { ipaddr|ipv6addr = ..;
secret = "<secret>"; shortname = <name>; nas_type = ..; require_message_authenticator = ..;
limit_proxy_state = .. }` per enabled client, sorted by name, deterministic. Use
`ipv4addr`/`ipv6addr` per family; CIDR allowed.
The helper performs its own independent safety checks (§6).

## 6. Root helper protocol (DEPLOY agent implements; APP agent's client)

Socket `/run/radius-admin-helper.sock`, one JSON object per line (UTF-8, ≤ 64 KiB) in,
one JSON line out, then the connection closes. Request: `{"action": <str>, ...}`.
Response always: `{"ok": bool, "action": str, "message": str, ...}`.
Actions:
- `status` → `{"ok":true, "service_active": bool, "fips_enabled": bool,
  "radiusd_version": str, "last_apply": {...}|null, "backups": [ids newest first, max 20]}`
- `validate` → reads `<staging>/policy` and `<staging>/clients`, runs safety checks,
  builds a temp copy of raddb with those files in place, runs
  `runuser -u freerad -- <radiusd> -XC -d <tmpraddb>`; returns `{"ok", "output": last 200 lines}`.
- `apply` → lock; validate; backup current two target files to `backups/<ts>/`; install
  staged files atomically (root:freerad 0640); `systemctl restart <service>`; wait ≤ 15 s
  for active and UDP 1812 listening; on failure restore backup + restart and return
  `{"ok":false, "rolled_back":true, ...}`; success → `{"ok":true, "backup_id":..,
  "policy_sha256":.., "clients_sha256":..}`.
- `rollback` `{"backup_id": "<ts>"}` (format `^\d{8}T\d{6}Z$`) → restore that backup,
  validate, restart, same failure handling.
Staging path is fixed in helper.conf, never taken from the request. Helper safety
checks: files ≤ 1 MiB, UTF-8, no NUL; clients file must consist only of `client <name> {`
blocks containing whitelisted keys (ipaddr, ipv4addr, ipv6addr, secret, shortname,
nas_type, require_message_authenticator, limit_proxy_state) and comments; policy file
must not contain `$INCLUDE`, `$-INCLUDE`, `$ENV`, `$TEMPLATE`, `%{exec:`, `Exec-Program`,
backticks. Helper logs every action to syslog (ident `radius-admin-helper`).

## 7. Crypto / FIPS rules (ALL agents)

- All crypto through system OpenSSL 3 (FIPS provider). Python: `hashlib`, `hmac`
  (OpenSSL-backed), `ssl.RAND_bytes` for ALL randomness (tokens, salts, secrets, TOTP
  keys). Do NOT use `random`, `secrets`, `os.urandom`, `uuid4` for security values.
- Password hashing: PBKDF2-HMAC-SHA256 via `hashlib.pbkdf2_hmac`, 600000 iterations,
  16-byte salt. Constant-time compare `hmac.compare_digest`.
- Symmetric encryption at rest: AES-256-GCM via apt `python3-cryptography`
  (links system libssl). 12-byte nonce from RAND_bytes.
- TOTP: RFC 6238, HMAC-SHA1 (approved for HMAC), 6 digits, 30 s, ±1 step, replay
  protection via totp_last_step. 20-byte secret.
- Forbidden: md5, sha1 (except inside HMAC for TOTP), bcrypt, scrypt, argon2, DES/3DES,
  RC4, non-OpenSSL crypto libs, pip wheels.
- App refuses to start when `require_fips = true` unless
  `/proc/sys/crypto/fips_enabled == 1` AND `_hashlib.get_fips_mode() == 1`.
- TLS (nginx, eap, ldap) cipher list for TLS 1.2:
  `ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256`
  TLS 1.3 (nginx only): TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256. Curves
  `secp384r1:prime256v1`. EAP stays TLS 1.2 max (unchanged).

## 8. Seed data (migration inserts; reproduces current behaviour)

ui.access_rule (priority, connection, ssid, ad_group, vlan):
10 wired - Wired-Support 510 · 20 wired - Wired-Office 500 · 30 wired - Wired-Utility 520 ·
10 wireless Example_Main_Test Wireless-Office-Test 530 · 10 wireless Example_Admin WIRELESS-SUPPORT 510 ·
10 wireless Example_Main WIRELESS-OFFICE 530.
SSID group order in output: order of the lowest rule id per SSID (Example_Main_Test,
Example_Admin, Example_Main) — matches original.
ui.setting: admin_subnet=192.0.2.0/24, admin_priv15=false at migration (preserve
current behaviour; admin turns it on deliberately), custom_policy='', banner_text = default.
ui.radius_client: parsed from clients.conf `wifi-aps` + switches.conf (secrets copied,
require_ma: wifi-aps 'yes', switches 'auto').
radcheck: existing `Crypt-Password` rows migrated unchanged (flagged legacy in UI);
radpostauth/radacct history migrated WITHOUT `pass`.

## 9. Web app requirements (APP agent)

Flask (apt python3-flask 3.0.x), Jinja2 autoescape, psycopg2 (apt), gunicorn (apt),
python3-cryptography, optional python3-qrcode (SVG; fall back to showing the secret).
No Flask sessions/itsdangerous; own server-side sessions (§3.2).
- Login: consent banner acknowledge → username/password → MFA (TOTP code, or verified
  client cert whose SHA-256 matches `cert_sha256`) → forced enrollment if no MFA →
  forced password change if `must_change_password`. Generic errors; dummy PBKDF2 on
  unknown user. Lockout after `lockout_threshold` failures for `lockout_minutes`
  (password and MFA failures both count). Per-IP: >20 failures/15 min → reject.
- Cookie `__Host-radius_admin`, Secure, HttpOnly, SameSite=Strict, Path=/, 32-byte
  random token; DB stores sha256(token). Rotate on login and on MFA success.
  Idle 15 min, absolute 8 h.
- CSRF token per session on every POST (hidden field) + Origin/Referer same-host check.
- Step-up re-auth (password + MFA) within `stepup_minutes` for: apply, rollback,
  custom policy edit, settings, UI admin management, revealing a secret, MFA reset.
- RBAC: viewer = read-only (secrets masked); operator = edit clients, switch admins,
  MAB, access rules, and apply; admin = everything incl. custom policy, settings,
  UI admins, rollback, secret reveal.
- Client cert: trust ONLY headers `X-Client-Verify` (must be `SUCCESS`) and
  `X-Client-Cert` (URL-escaped PEM) set by nginx; compute SHA-256 of DER.
- Pages: dashboard (helper status, FIPS, pending-changes banner, recent rejects),
  RADIUS clients CRUD (generate secret = 32 chars [A-Za-z0-9] from RAND_bytes,
  masked, reveal admin+step-up), switch admins (radcheck + radusergroup net-admins;
  set/reset password → Password-With-Header {X-PBKDF2} format §0, delete legacy
  Crypt-Password row on reset; disable = radcheck `Auth-Type := Reject`; show
  "legacy hash – reset required" badge), access rules CRUD + reorder + generated
  policy preview, MAB devices CRUD + CSV import (mac,vlan,description) — live
  immediately, no apply, auth log (radpostauth search/paginate), audit log
  (+ chain verify), apply page (diff current-vs-staged for both files, validate,
  apply, history, rollback), custom policy editor (admin), settings (admin), UI admin
  users (admin: create w/ temp password, role, enable/disable, unlock, reset MFA),
  account (change password, MFA, list/revoke own sessions).
- Pending changes = render(current DB) differs from last successful apply hashes.
- Every mutation and every auth event → ui.audit_log + syslog (ident `radius-admin`).
  Never log secrets/passwords/TOTP codes.
- Security headers (also set by nginx): CSP `default-src 'self'; script-src 'self';
  style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none';
  form-action 'self'; frame-ancestors 'none'`, X-Content-Type-Options nosniff,
  Referrer-Policy same-origin (no-referrer makes browsers send `Origin: null` on POST), Cache-Control no-store on authenticated pages.
  No inline scripts/styles.
- CLI `python3 -m radius_admin.cli` subcommands: `create-admin --username --role`
  (prints one-time temp password), `render --out-dir` (writes policy+clients),
  `verify-audit`, `check-fips`.
- Tests: pytest against a real local PostgreSQL (sandbox), covering auth, lockout,
  CSRF, RBAC, step-up, TOTP, PBKDF2 format compatibility with FreeRADIUS, audit chain.

## 10. Change (2026-10-23): access rules and settings are LIVE

User decision: access rules and settings take effect immediately (no restart); RADIUS
clients and custom policy keep the validate → apply → restart flow.

- `sql/40-live-policy.sql` (written + validated by the lead, loaded in sandbox DBs
  `radius` and `radius_apptest`) adds SECURITY DEFINER functions, EXECUTE granted to
  radius_fr and radius_admin (radius_fr still has NO rights on schema ui):
  - `radius_admin_vlan(port_type text, called_station_id text, groups text) -> text|NULL`
    groups = comma-separated AD group names; wired iff port_type = 'Ethernet'; wireless
    SSID = ':'-anchored suffix of Called-Station-Id; case-insensitive group match;
    first by (priority, id); NULL = reject.
  - `radius_admin_admin_source_ok(src text) -> boolean` (setting admin_subnet)
  - `radius_admin_priv15() -> boolean` (setting admin_priv15)
- FreeRADIUS: ldap `group { cacheable_name = 'yes' }` so the computer's groups (incl.
  nested via membership_filter) are in `&control:LDAP-Group[*]`; sql `auto_escape = yes`
  (PQescapeStringConn instead of mime-encoding, so group names with spaces/&/() survive);
  the generated policy calls the functions via `%{sql:SELECT ...}`; empty/NULL → reject
  (fail closed if the DB is down).
- `unlang.render_policy(custom: str) -> str` (NEW SIGNATURE): output no longer depends on
  rules or settings; only the custom policy body. `render_clients` unchanged.
- UI: Access rules + Settings move to "Live immediately"; pending-changes = clients +
  custom policy only; rules page gets a "test a match" tool that calls
  `radius_admin_vlan()` (single source of truth with FreeRADIUS).
- Upgrade on the server: `install.sh --phase postgres` (loads 40), then
  `--phase freeradius --restart-freeradius` (one last restart), then `--phase app`.

## 11. Change (2026-10-28): RADIUS client CSV import

CSV columns (header row required, exact names, any order tolerated by name):
`ip,secret,hostname,secret_type,key_scope,dot1x_ports`
- `ip`: IPv4/IPv6 address or CIDR (validate_ipaddr). `hostname`: client name
  (validate_client_name; leading/trailing space trimmed). `secret_type`: `plaintext` |
  `encrypted` | `none` (case-insensitive). `key_scope`: `server` | `global` | `none` (or empty; `host` accepted as alias of server)
  (`global` = the switch has no per-server key and uses its global `radius-server key`).
  `dot1x_ports`: free text (e.g. `gi1/0/1-24`), informational, ≤ 1000 chars, stored as is.
- `sql/50-client-import.sql` (written + validated by the lead, loaded in sandbox DBs) adds
  to ui.radius_client: `key_status` ('ok'|'encrypted'|'missing', default 'ok'),
  `key_scope` (NULL = none|'server'|'global'), `dot1x_ports` (text, default ''), and CHECK
  `key_status = 'ok' OR NOT enabled` — a client without a usable plaintext key can never
  be enabled, so it never reaches radius-admin-clients.conf.
- Row semantics:
  - plaintext: secret must pass validate_secret → key_status 'ok'.
  - encrypted: the value is NOT stored anywhere (it is unusable by FreeRADIUS); new
    client → created disabled, key_status 'encrypted', secret ''; existing client →
    its current secret/enabled state is kept, other fields updated, and a warning shown.
  - none: new client → disabled, key_status 'missing', secret ''; existing → secret kept.
- Matching existing clients: by IP, else by hostname. IP matches client A and hostname
  matches a different client B → that row is an error. Duplicate IPs or hostnames
  within the file → error. Options: "update existing" (hostname, ip, secret when
  plaintext, key_scope, dot1x_ports) or "skip existing"; default Message-Authenticator
  (require_ma) for NEW clients (auto/yes/no).
- Flow: upload (≤ 1 MiB, ≤ 5000 rows) → validate the whole file (any error → nothing
  imported, errors listed by line) → preview table (new / update / unchanged / skip,
  per-row warnings for encrypted/none/global) → confirm (step-up required, operator+)
  → single transaction → audit (counts + names, never secrets) → pending changes
  (clients need Apply).
- Notices: client list shows a badge "Encrypted key – not usable" / "No key" with a
  tooltip/inline text explaining FreeRADIUS needs the plaintext shared secret; such
  clients are disabled and cannot be enabled until a plaintext key is entered or
  generated (which sets key_status 'ok'). `global` scope badge explains that rotating
  that key on the switch changes its global radius-server key (all servers on it).
- Header detection (2026-10-28): the first non-empty row is a header if every non-empty
  cell is a known column name (any case/order); it is DATA if any cell is an IP
  address/network or it has fewer than two column-name cells; otherwise it is reported
  as a bad header. Headerless files use the standard order and may omit key_scope and
  dot1x_ports (4–6 fields). The preview states which mode was used.

- Revision (2026-10-28, user): `key_scope` values are `server` | `global` | `none`
  (empty = none; stored NULL; legacy `host` accepted as `server`). `dot1x_ports` is
  REMOVED: no DB column (sql/50 drops it), not in the UI, not in the template; CSV
  layout is `ip,secret,hostname,secret_type,key_scope`. A `dot1x_ports` header column
  or a 6th headerless field from older exports is accepted and ignored.
- Revision 2 (2026-10-28, user): `dot1x_ports` is KEPT after all (column, UI, template,
  CSV 6th column as originally specified). The key_scope change above stands.

## 12. Change (2026-10-28): read-only SNMPv3 switch monitoring

- `sql/60-snmp.sql`: `ui.snmp_profile` (singleton; username, auth SHA-256/384/512, priv AES-128,
  passphrases AES-256-GCM encrypted with the app data key, AAD `radius-admin/snmp_profile/<auth|priv>`,
  poll interval 5–1440 min, `auto_update_ports`), `ui.switch_status` (latest poll per client),
  `ui.snmp_test` (UI-queued single-switch tests, pruned after 7 days).
- `radius_admin/snmp.py`: Net-SNMP `snmpget`/`snmpbulkwalk` (system OpenSSL), credentials in a
  private 0600 snmp.conf (SNMPCONFPATH), literal IP targets only. Standard MIBs: system,
  IEEE8021-PAE-MIB port control (2 = auto → 802.1X port), IF-MIB ifName (standalone C1300 `gi4`
  → `gi1/0/4`), RADIUS-AUTH-CLIENT-MIB ext table (RFC 4668) or old table.
- `radius_admin/snmp_poller.py` + `deploy/systemd/radius-admin-snmp.service`: OS user
  radius-admin, the only component with network access (IPAddressAllow = admin subnet).
  Polls only clients with `ui.radius_client.is_switch` (default false) that are a single address; optional auto-sync of `dot1x_ports` (audited,
  actor `system:snmp-poller`), compared as port sets.
- UI: Switch monitoring page (admin + step-up; passphrases write-only), Refresh now and Test
  (operator+), client list Switch column + "Differs from switch" badge, client edit status panel
  with RADIUS counters. No config fetching (would need SNMP write access).
- Switch flag: `is_switch` set from the client form, the bulk "Monitored devices" selector
  (`POST /switch-monitoring/devices`, admin + step-up, audited `snmp.devices`; unmarking deletes
  the client's `switch_status` row), or CSV import (upload option for new clients, optional
  `is_switch` column yes/no/true/false/1/0/switch, empty = unchanged).
- Layout: client list fits without horizontal scrolling down to 1024 px (RADIUS options column
  hidden below 1480 px; Edit/Disable/Delete move into a "⋯" row menu below 1240 px); all controls
  share one height (2.5 rem, small 2 rem) and table cells align on the text baseline.

## 13. Change (2026-10-29): sessions, authentication detail, per-port state, alerts, CoA, MAB queue, reports

- `sql/70-operations.sql` (idempotent):
  - `radpostauth` gains `reason` (Module-Failure-Message), `nasportid`, `cert_cn`, `cert_subject`,
    `cert_issuer`, `cert_serial`, `cert_expiry`, `ad_groups_hex` (the hex list passed to the rule matcher)
    and `rule_id`; indexes for station and reject queries; `radacct` indexes for open sessions.
  - `mab_device.expires_at`; `mab_pending` (unknown MACs: first/last seen, attempts, NAS, port, ignored),
    written only by `radius_admin_mab_hex(mac, nas_hex, port_hex)` (SECURITY DEFINER, VOLATILE, granted to
    radius_fr only). It returns `<vlan>` / `disabled` / `expired` / `unknown` / NULL and queues unknown MACs
    (best effort, at most 2000 rows; never blocks the reply).
  - `radius_admin_vlan_rule_hex()` = `radius_admin_vlan_hex()` returning `<vlan>:<rule id>`
    (`radius_admin_vlan_rule_core()` mirrors `radius_admin_vlan_core()`).
  - `ui.switch_status` gains `fail_count`, `last_ok_at`, `ports` (jsonb per-port state).
  - `ui.alert_settings` (singleton), `ui.alert` (one open row per kind+subject), `ui.monitor_state`
    (heartbeat, last FreeRADIUS check, radclient), `ui.coa_request`; `ui.snmp_profile.coa_port` (1700).
- Policy (`unlang.py`): every reject sets `Module-Failure-Message` (`radius-admin: …`); MAB calls
  `radius_admin_mab_hex` with the regex-built MAC and hex NAS address / port (port hex re-validated);
  EAP-TLS calls `radius_admin_vlan_rule_hex` and splits `vlan:rule` by regex into Tmp-String-0/-6;
  admin branch evaluates the source check once into Tmp-String-8 (default "f", fail closed).
  `services.policy_format_upgrade` flags a running policy without `radius_admin_mab_hex(` (one Apply).
- `queries.conf` post-auth query writes the new columns; `rule_id` via
  `substring(x from '^[0-9]{1,9}$')::integer` (a CASE with `''::integer` fails at plan time and a failed
  post-auth insert turns an Accept into a Reject).
- Monitor service (`snmp_poller.py`, unit `radius-admin-snmp`): heartbeat every 5 s; CoA queue every
  tick (`coa.py`: radclient from the FreeRADIUS build, `-S` secret file, validated attributes, Cisco
  AV-pairs reauthenticate / bounce-host-port, Disconnect-Request); alerts every 60 s (`alerts.py`:
  reject spike with hysteresis, switch_down after N failed polls, radius_down after 2 failed helper
  `status` checks — the helper now reports `listening`); per-port SNMP (`snmp.build_ports`:
  dot1xAuthPaeState, dot1xAuthAuthControlledPortStatus, dot1xAuthSessionUserName, ifOperStatus,
  dot1qPvid via dot1dBasePortIfIndex) for port-control-auto ports; hourly housekeeping (mab_pending
  30 d, coa_request 90 d, snmp_test 7 d, resolved alerts 400 d).
- UI: Sessions (`views/sessions.py`; accounting coverage per switch; CoA queue + result page),
  auth-log detail (`/auth-log/<id>`, `insight.py` reason hints, cert expiry, group decode, NAS→client),
  Alerts (+ settings, admin + step-up; SMTP password AES-256-GCM, AAD `radius-admin/alert_settings/smtp`),
  MAB expiry / vendor (`oui.py`, package `ieee-data`) / unknown-device queue with one-click approve and
  a `mab_default_vlan` setting, Reports (`views/reports.py`: CSV with formula neutralisation + print
  layout; every view/export audited `report.view` / `report.export`; privileged report admin-only),
  dashboard alerts / heartbeat / sessions, nav badges (savepoint-protected query).
- Wording: second factor “client certificate” (no smart cards in this environment).

## 14. Change (2026-10-29): universal edition first release

- **FreeRADIUS 3.2.10** (latest signed release, `--enable-fips-workaround`, one build for standard
  and FIPS mode). The single-site build ran an unreleased v3.2.x snapshot reporting "3.2.11";
  `freeradius/diffs/` are now against stock 3.2.10. Schemas are identical between the two.
- **Schema** `sql/80-universal.sql` (additive only): `ui.admin_user.theme`, `.auth_source`
  ('local'|'saml'), `.saml_name_id` (unique); `ui.radius_client.transport` ('udp'|'radsec'),
  `.radsec_peer_name`; tables `ui.sso_group_role`, `ui.saml_request`, `ui.saml_replay`;
  settings `radsec_*`, `saml_*`, `setup_skipped`, `setup_finished`.
- **Database sessions are UTC.** `db.utc_dsn()` adds `-c timezone=UTC` to every app and monitor
  connection, so timestamps labelled UTC are UTC on any host (fixes off-by-hours alert text and
  a date test that failed outside UTC).
- **Session row lock.** `load_session` commits its `last_seen_at` update at once. Before, two admins
  disabling each other deadlocked (each held its own session row and waited for the other's via
  the admin-change advisory lock).
- **Colour theme.** Per user ('system'|'light'|'dark'), rendered server-side as `html[data-theme]`
  (no inline script); a `__Host-radius_admin_theme` cookie styles the sign-in page. Each dark CSS
  rule exists under `prefers-color-scheme` (unless "light") and for `[data-theme="dark"]`.
  Audited `account.theme`.
- **RadSec (RFC 6614), per client.** A client's transport is UDP (shared secret) or RadSec (TLS,
  certificate from the site CA, fixed secret "radsec"). `render_clients(clients, radsec)` renders
  RadSec clients into `clients radius_admin_radsec { … }` plus one top-level `listen { proto = tcp …
  tls { … } }` into the existing clients file (valid at the top level of radiusd.conf), only while
  the listener is on and an enabled RadSec client exists. TLS 1.2–1.3, FIPS cipher list, server
  certificate/key and CA = `certs/site/radius.{pem,key}` and `ca.pem` (the EAP-TLS files; the app
  never handles a private key), optional OCSP (`softfail = no`). The policy `radius_admin_radsec`
  (called first in authorize and preacct) rejects a RadSec client whose connection certificate's
  CN / first DNS SAN (`%{listen:TLS-Client-Cert-…}`) differs from `%{client:radsec_peer_name}`.
  FreeRADIUS exposes the connection certificate only through `%{listen:…}`, never as request
  attributes, so it cannot be confused with an EAP-TLS client certificate inside the connection.
  **Helper:** the clients-file grammar (`check_clients`) now parses sections into a tree and
  allows, besides `client` blocks, at most one RadSec `listen` and one `clients radius_admin_radsec`
  section (both or neither) with every key and value pinned, certificate paths limited to
  `<raddb>/certs/site/{radius.key,radius.pem,ca.pem}`. The helper protocol is unchanged.
  TLS listeners need radiusd's thread pool (`-X` implies single-threaded and refuses them).
  UI: transport choice on the client form; `/clients/radsec` (admin) for the listener; refused to
  turn off while enabled RadSec clients exist. Audited `radsec.settings`; client events carry
  `transport`. CSV import stays UDP-only.
- **Portal SAML SSO** (`sso.py`, `views/sso.py`, pysaml2 + xmlsec1 distribution packages). SP only,
  no SAML private key: unsigned AuthnRequest (HTTP-Redirect, `ForceAuthn` for step-up), response by
  HTTP-POST to `/saml/acs` (the only CSRF-exempt endpoint) with a signed assertion or response;
  SHA-1 refused before parsing; audience, destination, time window (±120 s) and InResponseTo
  checked by pysaml2; the request id is stored in `ui.saml_request` with the SHA-256 of a nonce held
  in a `SameSite=None` cookie (binds the answer to the browser; the session cookie is Strict and is
  not sent on the IdP's cross-site POST); assertion ids recorded in `ui.saml_replay`. After success
  the ACS answers with a meta-refresh page so the new Strict session cookie is sent on the next,
  same-site navigation. Roles: group claim values (Entra object IDs) → `ui.sso_group_role`,
  highest role wins, none → refused; the Entra overage claim is refused (no Graph calls). Users are
  created on first sign-in (`auth_source='saml'`, password marker `!saml` that never verifies,
  MFA by the IdP), role updated at every sign-in. Step-up for SSO users = IdP re-authentication.
  `saml_local_login='admins'` keeps local passwords for administrators only (break glass).
  Audited: `auth.login` / `auth.stepup` with `method: saml`, `ui_admin.create`, `ui_admin.role`,
  `sso.settings`, `sso.group_add`, `sso.group_delete`.
- **Setup checklist** (`views/setup.py`, admin): required steps (FreeRADIUS running via helper
  `status`, ≥1 enabled client, ≥1 enabled rule, admin subnet not the 192.0.2.0/24 example, applied
  and not pending) and optional ones (second admin, switch admins, SSO, RadSec, monitoring, alert
  e-mail; skippable). Dashboard strip until finished. Audited `setup.skip|restore|finish|reopen`.
- **Installer answers** (`deploy/answers.sh`): `install.sh` with no options on a terminal, or
  `--interactive`, asks server name, management subnet, listen address, resolvers, portal
  certificate (self-signed ECDSA P-384 / CSR / existing) and the first admin; `--answers FILE`
  takes the same unattended; `--print-answers` validates and prints only. New phase `site` writes
  `/etc/radius-admin/site.yaml` (root 0640) and the certificate; `bootstrap` creates the first
  admin. With a CSR the run stops until the issued certificate is installed.
- **Navigation and wording.** Side navigation grouped by topic: Network access (RADIUS clients,
  access rules, MAB devices, switch admins, custom policy, Apply changes), Monitoring, Records,
  Administration (settings, single sign-on, UI admins, setup checklist; admins only). The
  "Live now" / "Needs Apply" badges are gone: pages whose changes need Apply (clients, client
  import, RadSec listener, custom policy) show one note under the title (`m.apply_note()`).
- **Console session limits in Settings** (admin + step-up): step-up window 1–60 min, idle timeout
  5–480 min, session length 1–24 h, stored in `ui.setting` (`stepup_minutes`,
  `session_idle_minutes`, `session_absolute_hours`); the config file values are the defaults.
  `load_session` reads them in its query and clamps them to the same bounds. Audited in
  `settings.update`.
- **FIPS wording** appears only when FIPS mode is on (`require_fips`); a test renders every page in
  standard mode and fails on "FIPS". Row and account drop-down menus are positioned against the
  window (`app.js`), so a scrolling table cannot clip them.

