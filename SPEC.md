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
- 802.1X: EAP-TLS (machine certificates from an internal PKI, e.g. `pki.example.net`,
  with OCSP); optionally EAP-TTLS/PAP for local 802.1X users (section 18) and directory
  accounts (section 19), and PEAP-MSCHAPv2 in standard mode for local users (section 20) and
  directory accounts on a domain-joined server (section 21). LDAPS to Active Directory (e.g. `dc01.example.net`); the user filter matches
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
  README.md                    overview / quick start
  docs/RUNBOOK.md              install, migrate, verify, rollback
  docs/SECURITY.md             FIPS boundary, exceptions, 800-171 mapping, findings
  app/                         Python application
    radius_admin/
      __init__.py              create_app()
      unlang.py                policy + clients file rendering & validators
      ...
    tests/
  helper/radius-admin-helper   root helper, python3 stdlib only
  sql/                         Postgres DDL
    00-roles.sql 10-freeradius-schema.sql 20-radius-admin-schema.sql 30-grants.sql
  freeradius/                  FreeRADIUS config deliverables
    mods-available/sql
    mods-available/eap
    mods-available/ldap
    mods-config/sql/main/postgresql/queries.conf
    sites-available/default
    clients.conf
    mods-config/files/authorize
    modules-to-disable.txt
    diffs/*.diff               unified diffs vs stock FreeRADIUS 3.2.10 raddb
  deploy/
    install.sh                 idempotent installer
    preflight.sh               read-only checks before anything changes
    migrate_sqlite_to_pg.py
    rollback.sh
    make-csr.sh
    nginx/radius-admin.conf
    systemd/radius-admin.service
    systemd/radius-admin-helper.socket
    systemd/radius-admin-helper@.service
    systemd/nginx.service.d/radius-admin.conf  drop-in for nginx.service (start after network, retry)
    postgres/pg_hba.conf.snippet  postgres/pg_ident.conf.snippet
    etc/radius-admin.conf.example
  tools/lib/fr-release.sh      FreeRADIUS release, signing key, verified download
  tools/package/               build-freeradius-deb.sh (radius-admin-freeradius .deb),
                               make-bundle.sh (release .tar.gz), freeradius/ (unit, maintainer scripts)
  packages/                    built packages (not in git; part of the release bundle)
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
| FreeRADIUS (bundled package) | `/opt/radius-admin-freeradius/` (`sbin/radiusd`, `bin/radclient`, `lib/rlm_*.so`, `share/freeradius` dictionaries), unit `freeradius.service`, logs `/var/log/freeradius/` (freerad 0750), raddb `/etc/freeradius` (root:freerad 0750) |

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
  authmethod text,                    -- 'eap-tls' | 'ttls-pap' | 'ttls-ldap' | 'peap' | 'peap-ldap' | 'pap-admin' | 'mab' | 'other'
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

The SQL files in `sql/` are applied in numeric order. Change them only with a reason
recorded in the commit; a migration only adds objects, and old ones go at least one
release later, so a rollback never needs a database restore. A sandbox
PostgreSQL 16 cluster (`pg_ctlcluster 16 main`, socket /var/run/postgresql) has the
roles and database `radius` loaded from these files.

## 4. FreeRADIUS changes

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
     form is free but MAB must not hit LDAP/PAP).
   - authenticate: remove CHAP, MS-CHAP, `mschap`, `digest`.
   - post-auth: replace the hand-written "Site policy" block (orig lines 847–934) with
     the single line `radius_admin_postauth`. Everything else unchanged.
4. `inner-tunnel` removed from sites-enabled. EAP-TTLS and PEAP use the project's own
   `sites-available/radius-admin-inner` and `radius-admin-peap` instead (sections 18, 20).
5. `mods-available/eap`: keep only `tls-config tls-common`, `tls`, a `ttls` block pointing at
   `radius-admin-inner` (section 18) and a `peap` block pointing at `radius-admin-peap`, plus the
   inner instance `eap radius_admin_inner_eap` (mschapv2 only; section 20). Remove md5, psk, gtc. Remove `ca_path = ${cadir}` (test CA lives there). Set
   `reject_unknown_intermediate_ca = yes` (certs/site/ca.pem = Example-IssuingCA + Example-RootCA,
   sizes match). cipher_list = FIPS list (§7). Keep OCSP as is.
   Upgrades keep the site's values (`install.sh` `carry_over_secrets`, when the live file was
   installed by radius-admin, i.e. has a `radius-admin:` comment; a stock eap is not merged): in
   `tls-config tls-common` outside its sub-sections `private_key_password`, `private_key_file`,
   `certificate_file`, `ca_file`, `ca_path`, `check_crl`, `check_all_crl`, `check_cert_issuer`,
   `check_cert_cn`, and in its `ocsp { }` `enable`, `override_cert_url`, `url`, `use_nonce`,
   `timeout`, `softfail` (set, added or commented out to match the live file; a live file
   without `ocsp { }` keeps OCSP off). Ciphers, TLS versions and the method blocks come from the
   release. The installer prints the names of the kept keys, never their values.
6. `mods-available/ldap`: `ldap_debug = 0x0000`, `tls_min_version = "1.2"`,
   `cipher_list` = FIPS list. Nothing else.
7. Modules to remove from mods-enabled: chap, digest, dpsk, dynamic_clients, echo,
   ntlm_auth, passwd, unix, totp, replicate, radutmp, sradutmp (mschap stays for PEAP, section 20),
   proxy_rate_limit. (Validate with `radiusd -XC`; keep anything still referenced.)
8. `mods-config/files/authorize`: remove `bob` and `doug`.
9. `clients.conf`: keep `client localhost`; replace `wifi-aps` block and
   `$INCLUDE switches.conf` with `$INCLUDE radius-admin-clients.conf` (those clients are
   imported into ui.radius_client by the migration).
10. Must be validated against a real FreeRADIUS 3.2.10 built from source with
   `--enable-fips-workaround` (sandbox), including functional radtest checks.

## 5. Generated unlang

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
  1. MAB (`control:Tmp-String-1 == "mab"`): the vendor profile's VLAN reply attributes
     (§26; Catalyst 1300: Tunnel-Type := VLAN, Tunnel-Medium-Type := IEEE-802,
     Tunnel-Private-Group-Id := control:Tmp-String-0).
  2. Admin login (same condition as original: no EAP-Message, NAS-Port-Type absent or
     != Ethernet, no Called-Station-Id): accept only if `Packet-Src-IP-Address` is in
     `settings.admin_subnet` AND `SQL-Group == "net-admins"`; set
     `control:Tmp-String-1 := "pap-admin"`; if `settings.admin_priv15` is true add the
     vendor profile's full-admin reply attributes (§26; Catalyst 1300:
     `reply:Cisco-AVPair += "shell:priv-lvl=15"`); else reject.
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
secret = "<secret>"; shortname = <name>; nas_type = ..; [radius_admin_profile = <id>;]
require_message_authenticator = ..; limit_proxy_state = .. }` per enabled client, sorted by
name, deterministic (`radius_admin_profile`: §26). Use
`ipv4addr`/`ipv6addr` per family; CIDR allowed.
The helper performs its own independent safety checks (§6).

## 6. Root helper protocol

Socket `/run/radius-admin-helper.sock`, one JSON object per line (UTF-8, ≤ 64 KiB) in,
one JSON line out, then the connection closes. Request: `{"action": <str>, ...}`.
Response always: `{"ok": bool, "action": str, "message": str, ...}`.
Actions:
- `status` → `{"ok":true, "service_active": bool, "fips_enabled": bool,
  "radiusd_version": str, "last_apply": {...}|null, "backups": [ids newest first, max 20],
  "portal_configured": bool, "portal_active": bool, "portal_listening": bool}`.
  The `portal_*` fields describe the web portal: `portal_configured` when `portal_site`
  (default `/etc/nginx/sites-enabled/radius-admin`) exists, then `portal_service` (default
  `nginx.service`) is-active and something named nginx listens on TCP `portal_port` (443).
  Without the site both are false and nginx is not queried. Older helpers omit the fields;
  clients treat a missing `portal_configured` as "not known".
- `validate` → reads `<staging>/policy` and `<staging>/clients`, runs safety checks,
  builds a temp copy of raddb with those files in place, runs
  `runuser -u freerad -- <radiusd> -XC -d <tmpraddb>`; returns `{"ok", "output": last 200 lines}`.
- `apply` → lock; validate; backup current two target files to `backups/<ts>/`; install
  staged files atomically (root:freerad 0640); `systemctl restart <service>`; wait ≤ 15 s
  for active and UDP 1812 listening; on failure restore backup + restart and return
  `{"ok":false, "rolled_back":true, ...}`; success → `{"ok":true, "backup_id":..,
  "policy_sha256":.., "clients_sha256":..}`.
- `rollback` `{"backup_id": "<ts>"}` (format `^\d{8}T\d{6}Z\Z`) → restore that backup,
  validate, restart, same failure handling.
- `update_status` → `{"ok":true, "installed": {version, channel, commit, built} from
  `build_file`, "key_present": bool, "key_fingerprint": sha256 of the pinned key's DER,
  "state": {state: queued|installing|done|failed|rolled_back, version, from, channel,
  restarts_freeradius, actor, requested, finished, message, log}}`. A queued/installing
  state whose install unit is no longer running is marked failed (section 16).
- `update_check` → `systemctl start --no-block <update_check_unit>`.
- `update_install` `{"version": "X.Y.Z[-rc.N|-dev.N]", "allow_downgrade": true|absent,
  "actor": "<username>"|"auto"}` → copies `<update_dir>/<version>/{manifest.json,
  manifest.json.sig, radius-admin-<version>.tar.gz}` (regular, single-linked, owned by
  `update_owner`, opened O_NOFOLLOW) into `<work_dir>/update/<version>/`, verifies the
  manifest with `openssl dgst -sha384 -verify <update_pubkey>`, checks the manifest
  (format 1, product, version, channel, bundle name/size ≤ update_max_mib) and the bundle's
  SHA-384, refuses a version not newer than the installed one unless `allow_downgrade` is
  JSON `true`, refuses while another install runs, writes the state and starts
  `<update_install_unit>@<version>.service`. Only `allow_downgrade: true` (the boolean) counts.
- `update_log` `{"offset": <int ≥ 0>|absent}` → `{"ok":true, "state": {as update_status},
  "log": "<file name>"|"", "offset": int, "size": int, "skipped": int, "text": str}`: the
  install log named by the state's `log`, from byte `offset`. Read-only. The name must be
  `update-<version>-<YYYYmmddTHHMMSSZ>.log` directly in `update_log_dir` (helper.conf,
  default `/var/log/radius-admin`), opened O_NOFOLLOW, a regular file owned by root. At most
  64 KiB per answer, cut after the last newline when there is one; when the caller is
  further behind, only the newest 64 KiB (`skipped` = bytes left out). An `offset` past the
  end starts again at 0. Invalid UTF-8 is replaced. No log yet, or the file gone: ok with
  empty `text` and a message (section 23).
- `integration_status`, `integration_catalog`, `integration_preflight`, `integration_fetch`,
  `integration_install`, `integration_log`: second-factor provider installs, section 29.1.
Staging path is fixed in helper.conf, never taken from the request. Helper safety
checks: files ≤ 1 MiB, UTF-8, no NUL; clients file must consist only of `client <name> {`
blocks containing whitelisted keys (ipaddr, ipv4addr, ipv6addr, secret, shortname,
nas_type, require_message_authenticator, limit_proxy_state, radius_admin_profile (§26)) and
comments, plus the RadSec (§14) and second-factor (§29) sections; policy file
must not contain `$INCLUDE`, `$-INCLUDE`, `$ENV`, `$TEMPLATE`, `%{exec:`, `Exec-Program`,
backticks. Helper logs every action to syslog (ident `radius-admin-helper`).

## 7. Crypto / FIPS rules (all components)

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

## 9. Web app requirements

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

- `sql/40-live-policy.sql` (loaded in sandbox DBs
  `radius` and `radius_apptest`) adds SECURITY DEFINER functions, EXECUTE granted to
  radius_fr and radius_admin (radius_fr still has NO rights on schema ui):
  - `radius_admin_vlan(port_type text, called_station_id text, groups text) -> text|NULL`
    groups = comma-separated AD group names; wired iff port_type = 'Ethernet'; wireless
    SSID = ':'-anchored suffix of Called-Station-Id; case-insensitive group match;
    first by (priority, id); NULL = reject.
  - `radius_admin_admin_source_ok(src text) -> boolean` (setting admin_subnet)
  - `radius_admin_priv15() -> boolean` (setting admin_priv15)
- FreeRADIUS: ldap `group { cacheable_name = 'yes' }` so the computer's groups (incl.
  nested via membership_filter) are in `&control:LDAP-Group[*]`. rlm_ldap adds the names from
  both lookups (`memberOf` and the membership_filter search) without merging them, so each
  direct group arrives twice; the policy hex-encodes each name and appends it to the list only
  if it is not there yet (byte-for-byte), for computers and directory users alike, so the list
  passed to the matcher and logged in `radpostauth.ad_groups_hex` holds each name once. The
  authentication detail page also shows each name once for rows logged before this; sql `auto_escape = yes`
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
- `sql/50-client-import.sql` (loaded in sandbox DBs) adds
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
  IEEE8021-PAE-MIB port control (2 = auto → 802.1X port), IF-MIB ifName, renamed by the vendor
  profile's port-name rules (§26; standalone C1300 `gi4` → `gi1/0/4`), RADIUS-AUTH-CLIENT-MIB ext table (RFC 4668) or old table.
- `radius_admin/snmp_poller.py` + `deploy/systemd/radius-admin-snmp.service`: OS user
  radius-admin, the only component with network access (IPAddressAllow = the switch networks:
  answers key `switch_nets` / `install.sh --switch-nets`, default the admin subnet; runs without
  answers keep the installed unit's list). A send that systemd drops (EPERM) is reported as
  "not sent: <address> is outside the switch networks…" (`snmp.blocked_message`), for SNMP and CoA.
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
    radius_fr only). It returns `<vlan>` / `disabled` / `expired` / `certificate` / `unknown` / NULL and queues
    unknown MACs (best effort, at most 2000 rows; never blocks the reply). *(2026-11-02)* `certificate`: the
    MAC is not registered but has an EAP-TLS Access-Accept in `radpostauth` (Calling-Station-Id compared by
    its hex digits; partial expression index `radpostauth_cert_mac_idx`). Such a MAC is never queued, an
    earlier queue row is deleted, and the policy rejects with "MAB not used: this device authenticates
    with a certificate". A registered MAC keeps its VLAN. The console reads the queue (list, counts, nav
    badge, auth detail) through the view `mab_pending_open`, which leaves out those MACs, so a device
    queued before its first certificate login disappears at once.
  - `radius_admin_vlan_rule_hex()` = `radius_admin_vlan_hex()` returning `<vlan>:<rule id>`
    (`radius_admin_vlan_rule_core()` mirrors `radius_admin_vlan_core()`).
  - `ui.switch_status` gains `fail_count`, `last_ok_at`, `ports` (jsonb per-port state).
  - `ui.alert_settings` (singleton), `ui.alert` (one open row per kind+subject), `ui.monitor_state`
    (heartbeat, last FreeRADIUS check, radclient), `ui.coa_request`; `ui.snmp_profile.coa_port` (1700;
    replaced by a port per client in §26).
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
  AV-pairs reauthenticate / bounce-host-port, Disconnect-Request; the session is named by
  Calling-Station-Id + NAS-Port-Id with NAS-IP-Address and Event-Timestamp, Acct-Session-Id only
  when the record has no MAC, since a Catalyst 1300 then finds no session); alerts every 60 s (`alerts.py`:
  reject spike with hysteresis, switch_down after N failed polls, radius_down after 2 failed helper
  `status` checks — the helper now reports `listening`; portal_down after 2 checks in which the
  helper reports the nginx site enabled but nginx not active or not on TCP 443, switch
  `ui.alert_settings.portal_enabled`, no "last check" kept since the portal can only show it
  while nginx is up; the Alerts pages warn when it is on and email is off, `sql/96-portal-alert.sql`); per-port SNMP (`snmp.build_ports`:
  dot1xAuthPaeState, dot1xAuthAuthControlledPortStatus, dot1xAuthSessionUserName, ifOperStatus,
  dot1qPvid via dot1dBasePortIfIndex) for port-control-auto ports. dot1qPvid is the port's native
  VLAN; the client page shows the VLAN in use from the open session's Access-Accept on that port
  (`clients._port_rows`), the native VLAN only as a labelled fallback, and "—" without a device.
  Quoted SNMP values spanning lines (-Ox wraps hex at 16 bytes) are joined; hourly housekeeping (mab_pending
  30 d, coa_request 90 d, snmp_test 7 d, resolved alerts 400 d).
- UI: Sessions (`views/sessions.py`; accounting coverage per switch; CoA queue + result page; reworked in section 24),
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
  and not pending) and optional ones (second admin, switch admins, second factor for device admins
  (section 29.4), SSO, RadSec, monitoring, alert e-mail; skippable). Dashboard strip until finished. Audited `setup.skip|restore|finish|reopen`.
- **Installer answers** (`deploy/answers.sh`): `install.sh` with no options on a terminal, or
  `--interactive`, asks server name, management subnet, listen address, switch networks, resolvers, portal
  certificate (self-signed ECDSA P-384 / CSR / existing) and the first admin; `--answers FILE`
  takes the same unattended; `--print-answers` validates and prints only. New phase `site` writes
  `/etc/radius-admin/site.yaml` (root 0640) and the certificate; `bootstrap` creates the first
  admin. With a CSR the run stops until the issued certificate is installed.
- **Portal settings without answers** (`update.sh`, which runs `install.sh --phase … -y`, or a
  phase run by hand): `server_name`, `admin_net`, `listen_ip` and `resolver` come from
  `/etc/radius-admin/site.yaml` (read with `ans_load`), else from the installed nginx site
  (`server_name`, `allow`, `listen …:443`, `resolver`), else from `/etc/radius-admin/firewall.nft`
  (`ip saddr`/`ip daddr`); `ocsp_url` from the nginx site (`ssl_ocsp_responder`) unless
  `RA_OCSP_URL` is set. Values found this way are validated like answers and a bad one stops the
  run. `--admin-net`, `--listen-ip`, `--server-name` and `--resolver` win over all of these and
  over an answers file. The `nginx` and `firewall` phases stop when no management subnet is
  known instead of using the 192.0.2.0/24 example, and after they install write the values in use
  back into an existing `site.yaml` (other keys kept), so a later update does not revert an
  option. `install.sh --print-settings` prints each value and its source; `update.sh` shows it in
  the plan when it runs `nginx` or `firewall`, and stops (release discarded) if it fails.
- **Navigation and wording.** Side navigation grouped by topic: Network access (RADIUS clients,
  access rules, MAB devices, switch admins, custom policy, Apply changes), Monitoring, Records.
  Admins also get one **Settings** button pinned to the bottom of the side panel (it carries the
  update badge); it opens `/settings/overview`, which lists the settings pages by category:
  RADIUS and switches (general settings), Console access (UI admins, single sign-on, sign-in
  notice, sessions and time zone), Notifications (alert settings), Maintenance (updates, setup
  checklist). Those pages highlight the button and show an "All settings" link back. The
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

## 15. Change (2026-10-31): bundled FreeRADIUS package

- **`radius-admin-freeradius`** (`tools/package/build-freeradius-deb.sh`): FreeRADIUS 3.2.10 from the
  signed upstream release (key `FR_KEY_FPR` in `tools/lib/fr-release.sh`, shared with the bench
  build), `--enable-fips-workaround`, prefix `/opt/radius-admin-freeradius`, raddb `/etc/freeradius`,
  logs `/var/log/freeradius`. Modules needing libraries the product does not use (perl, python,
  mysql, sqlite, redis, rest, …) are configured out, so the package does not depend on the build
  host; the build fails unless `rlm_sql_postgresql`, `rlm_ldap`, `rlm_eap_tls`, `rlm_sql`, `rlm_files`
  and `rlm_pap` were built. Depends are the distribution packages owning the directly linked
  libraries (≥ the build host's version); the package is built per distribution release and its
  version says which (`3.2.10-1~ubuntu24.04`). `Conflicts: freeradius`.
- **The package owns no file in `/etc`.** The stock raddb ships as
  `/opt/radius-admin-freeradius/share/raddb-dist` (no test certificates: built with `PACKAGE=…`;
  `user = freerad`, `group = freerad`). `postinst` creates the `freerad` user/group and
  `/var/log/freeradius`, and copies raddb-dist to `/etc/freeradius` **only when that does not
  exist** (root:freerad, no group write, no world access; modes only, no ACLs, so a default ACL on
  `/opt` cannot make later files world-writable, which radiusd refuses). Upgrades, reinstalls and purge never
  change or delete `/etc/freeradius`. `postinst` never starts, restarts or enables radiusd; `prerm`
  stops and disables it on removal only.
- **Unit `freeradius.service`**: radiusd starts as root and drops to `freerad` itself (no `User=`),
  `ExecStartPre … -Cx`, `ProtectSystem=full`, `NoNewPrivileges`, writable `/var/log/freeradius` only.
  The existing detection (`detect_fr_service`, `detect_radiusd` from `ExecStart`, `detect_fr_libdir`
  from the RUNPATH) finds it unchanged; `helper.conf` gets `radiusd = /opt/radius-admin-freeradius/sbin/radiusd`.
- **Release layout.** The packages go in `packages/` of the release tree with a `.sha384` each,
  plus `packages/source/` (upstream tarball and signature, for the GPLv2). `tools/package/make-bundle.sh`
  makes `radius-admin-<git describe>.tar.gz` from HEAD plus `packages/` with a `.sha256`.
- **Installer phase `fr-package`** (after `packages`, before `users`): picks
  `packages/radius-admin-freeradius_*~<ID><VERSION_ID>_<arch>.deb` (or `--freeradius-deb FILE`),
  refuses it without a matching `.sha384`, and installs it with `apt-get` when no FreeRADIUS is
  installed, or upgrades it when the bundled version is newer. A FreeRADIUS installed any other
  way (the distribution's `freeradius`, or a source build with its own unit) is kept with a
  warning. On upgrade the running radiusd is restarted only with `--restart-freeradius`; the
  installer's `apt-get` calls set `NEEDRESTART_SUSPEND=1` so Ubuntu's needrestart cannot restart
  it behind the installer's back. Without a
  bundled package and without FreeRADIUS the phase stops. The `freeradius` phase now enables the
  unit after `radiusd -XC` passes. Preflight reports a host without FreeRADIUS as ready when a
  bundled package is present. `update.sh` adds `fr-package` when `packages/` changed.
- **radclient**: `/opt/radius-admin-freeradius/bin` is searched first (app `coa.SEARCH_DIRS`,
  dictionaries `DICT_DIRS`, installer).
- Tests: `tests/package/test_freeradius_deb.sh` (package contents; with `--install`, the installer
  phase, idempotency, kept configuration, checksum refusal, start and answer, upgrade without
  restart, purge).

## 16. Change (2026-11-02): updates from signed GitHub builds

- **Versions.** `VERSION` holds X.Y.Z. `tools/release/build-version.sh BRANCH` gives the build
  version: `main` X.Y.Z, `testing` X.Y.Z-rc.N, `dev` X.Y.Z-dev.N, with N = commits since
  `VERSION` last changed. Ordering (same X.Y.Z): dev < rc < release (`radius_admin.versions`,
  and a copy in the helper). Bump `VERSION` on `dev` right after a release. `CHANGELOG.md`
  has an `## Unreleased` section and one `## X.Y.Z — date` section per release. On main the
  release job warns when `vX.Y.Z` already exists (nothing is published) and when
  `CHANGELOG.md` has no `## X.Y.Z` section (the release would have no notes).
- **Releases** (`.github/workflows/release.yml`; a version check job, then the build job in the
  `release` environment, which runs only when the check finds a version not yet tagged): main and
  testing after CI passes on a push; dev only when started by hand (`workflow_dispatch` on
  `dev`; the job refuses a commit without a successful CI push run): builds the FreeRADIUS package and the bundle
  (`make-bundle.sh --channel`, which writes `BUILD.json`), then `tools/release/make-release.sh`
  writes `manifest.json` `{format: 1, product, version, channel, commit, created,
  restarts_freeradius, bundle: {name, size, sha384}, notes}` and `manifest.json.sig`
  (ECDSA P-384 over SHA-384, `openssl dgst -sha384 -sign`), and publishes release
  `v<version>` (testing/dev as prereleases) with the bundle, manifest and signature as
  assets. The key is the `UPDATE_SIGNING_KEY` secret; the script refuses a key that is not
  P-384 or does not match `deploy/keys/update-signing.pem`, the public key servers pin.
  Without the secret or the pinned key the job warns and publishes nothing. main publishes
  only when `VERSION` changes (otherwise the build job is skipped and no reviewer is asked);
  testing and dev keep their newest 3 releases.
  `restarts_freeradius` is true when `freeradius/`, `tools/package/` or
  `tools/lib/fr-release.sh` changed since the previous release on the channel (or there is
  none). Notes: the release's CHANGELOG section; previews get `Unreleased` plus the
  commit subjects since the previous preview.
- **Settings** (`sql/90-updates.sql`, ui.setting): `update_channel` main|testing|dev
  (default main), `update_mode` off|notify|auto (default notify), `update_window_day`
  mon…sun|daily (default sun), `update_window_hour` 0–23 (default 3, server local time),
  `update_check_requested` (ISO time of the last "Check now"). Table `ui.update_check`
  (one row): checked_at, ok, error, channel, installed_version, latest_version, downgrade,
  restarts_freeradius, downloaded, releases (jsonb: version, published, notes,
  restarts_freeradius; newest first, at most 20).
- **Update check** (`radius_admin.updater`, `radius-admin-update-check.service` run hourly by
  its timer as radius-admin; the only component with outbound HTTPS, honours `HTTPS_PROXY`
  from `/etc/radius-admin/update.env`): off → returns without network. notify → runs when the
  last check is ≥ 23 h old, the channel changed, or `update_check_requested` is newer; auto →
  every run. Lists `GET <update_api>/repos/<update_repo>/releases`, keeps non-draft
  releases whose tag is `v<version>` and that carry all three assets, picks the newest on the
  channel; if none is newer but the installed build is from another channel, offers the
  channel's newest as a downgrade. Downloads it to `<update_dir>/<version>/` (https only;
  sizes capped; discarded unless the bundle matches the manifest's SHA-384; other versions
  removed) and records the row. auto: installs (helper `update_install`, actor `auto`) when
  the listed builds do not restart FreeRADIUS, otherwise only within the window hour; never
  when the helper's state shows this version failed, rolled back or still running; audited
  `update.auto_install`.
- **Install** (`deploy/update-install.sh` as `/usr/local/libexec/radius-admin/
  radius-admin-update-install`, unit `radius-admin-update-install@<version>.service`, root):
  re-checks the verified copy against the manifest, `pg_dump -Fc radius` to
  `/var/backups/radius-admin/radius-db-before-<version>-<ts>.dump` (newest 5 kept), runs the
  bundle's `deploy/update.sh --package … --yes --keep-upload` (plus `--with-freeradius --
  --restart-freeradius` when the release restarts FreeRADIUS), then health checks (portal
  answers on its socket, helper socket active, `nginx.service` active and TCP 443 listening when
  `/etc/nginx/sites-enabled/radius-admin` exists, FreeRADIUS active and on UDP 1812 when
  restarted, `/opt/radius-admin/BUILD.json` names the version) for up to a minute. On an
  installer error it re-runs the previous release's app phase; on failed health checks
  `update.sh --rollback`. Progress in the helper's `update-state.json`, log in
  `/var/log/radius-admin/update-<version>-<ts>.log`, outcome audited `update.install`
  (`radius_admin.cli record-update`).
- **Installer**: `/var/lib/radius-admin/updates` (radius-admin 0750); app phase installs the
  install script, the three units (timer enabled), `deploy/keys/update-signing.pem` as
  `/usr/local/share/radius-admin/update-signing.pem` (root 0644; warns when the release has
  none) and `BUILD.json` as `/opt/radius-admin/BUILD.json` (from a checkout: version from
  `VERSION`, channel `local`). The helper unit may read `/var/lib/radius-admin/updates`.
- **Updates page** (`/updates`, admin; settings and install need step-up): installed →
  latest version, the notes of every newer build (a safe Markdown subset), "restarts
  FreeRADIUS" marks, install (only the build the last check downloaded; a downgrade needs an
  explicit confirmation), install progress (section 23) and the last result,
  "Check now" (not in off mode), and the settings. A nav badge shows an available update
  while the check's `installed_version` is the installed build (it goes once that build is
  installed, without waiting for the next check).
  Audited `update.settings`, `update.check`, `update.install_requested`.

## 17. Change (2026-11-02): display time zone

- **Setting** `display_timezone` in `ui.setting` (absent = `UTC`; no migration): an IANA zone name
  from the system zone list (`services.timezones()`, tzdata; installer package `tzdata`). Settings page (admin +
  step-up), "Time zone" select; other names are refused. Audited in `settings.update`
  (`display_timezone: {from, to}`).
- **Display only.** Database sessions stay UTC (section 14) and storage is unchanged. The `dt`/`dtc`
  filters convert to the zone (read once per request, `services.display_zone()`; a stored name
  that is not a known zone falls back to UTC) and label times with its abbreviation (`%Z`). The
  auth log's From/To filters are whole days in the zone. Reports and their CSVs (whole UTC days),
  alert messages, syslog and the audit hash stay in UTC.

## 18. Change (2026-11-03): 802.1X with a username and password (EAP-TTLS/PAP, local users)

Step 1 of username/password 802.1X: EAP-TTLS with PAP inside the tunnel, checked against
local accounts. Directory passwords and PEAP-MSCHAPv2 follow in later steps.

- **Setting** `dot1x_ttls` in `ui.setting` (`'false'` by default): Settings page (admin +
  step-up), audited in `settings.update`. Read live by the SQL functions; no Apply, no restart.
- **Table** `ui.dot1x_user` (`sql/95-dot1x-passwords.sql`): `username` (`[A-Za-z0-9._@-]{1,64}`,
  unique case-insensitively), `password_hash` (rlm_pap `{X-PBKDF2}HMACSHA2+256:…`, PBKDF2-HMAC-SHA256,
  `pbkdf2_iterations`), `groups text[]` (≤ 50, each a valid access-rule group name), `description`,
  `enabled`, `expires_at`, `created_at/by`, `updated_at`. Separate from switch admins: the inner
  tunnel never reads `radcheck`, so a switch admin's password never opens a port and an 802.1X user
  never reaches switch management. `radius_admin` has full access; `radius_fr` none.
- **SQL functions** (SECURITY DEFINER, EXECUTE for `radius_fr` only, hex arguments only):
  `radius_admin_dot1x_user_hex(user_hex)` → the stored hash, or `off` / `unknown` / `disabled` /
  `expired`, NULL for malformed input (more than 64 bytes, not hex);
  `radius_admin_dot1x_vlan_rule_hex(user_hex, wired, csi_hex)` → `'<vlan>:<rule id>'` from
  `radius_admin_vlan_rule_core` with the user's groups (account re-checked), or NULL.
- **FreeRADIUS.** `mods-available/eap` gains `ttls { tls = tls-common; virtual_server =
  "radius-admin-inner"; copy_request_to_tunnel = no; use_tunneled_reply = no }`.
  `sites-available/radius-admin-inner` (enabled by the installer's freeradius phase) runs
  `filter_username`, `radius_admin_inner_authorize`, `pap`; authenticate PAP only; post-auth
  `radius_admin_inner_postauth`, Post-Auth-Type REJECT `radius_admin_inner_reject`.
- **Policy** (`unlang.render_policy`):
  - `radius_admin_inner_authorize`: sets `outer.control:Tmp-String-1 = "ttls-pap"` and
    `outer.control:Stripped-User-Name` = the inner User-Name (for the log, also on reject);
    rejects anything but PAP (EAP or MS-CHAP inside); looks the user up and copies a hash that
    matches the PBKDF2 pattern into `control:Password-With-Header`; otherwise rejects with a
    reason on `outer.request:Module-Failure-Message`.
  - `radius_admin_inner_postauth`: `outer.session-state:Tmp-String-1 = "ttls-pap"` and
    `Stripped-User-Name`, only after the password was accepted.
  - `radius_admin_inner_reject`: reason "wrong password" when none was set.
  - `radius_admin_postauth`, new branch after the admin branch and before EAP-TLS: EAP-Message
    present and the session marker set → removes the marker from session-state, sets
    `control:Tmp-String-1` / `Stripped-User-Name`, wired or SSID exactly like EAP-TLS, VLAN and
    rule id from `radius_admin_dot1x_vlan_rule_hex`; no match → reject.
- **Log.** The post-auth query writes `username = %{%{control:Stripped-User-Name}:-%{User-Name}}`
  (only the policy sets `control:Stripped-User-Name`), so EAP-TTLS rows show the inner name,
  never the outer anonymous identity; `authmethod = 'ttls-pap'`; `rule_id` and the reasons
  `turned off`, `no such 802.1X user`, `802.1X user is disabled` / `has expired`, `wrong password
  for 802.1X user`, `only PAP is accepted inside EAP-TTLS`, `no enabled access rule matches the
  user's groups for this connection`.
- **MAB.** A MAC with an EAP-TLS or EAP-TTLS Access-Accept is never queued (`radius_admin_mab_hex`,
  `mab_pending_open`; index `radpostauth_dot1x_mac_idx`, replacing `radpostauth_cert_mac_idx` one
  release later). The reason reads "MAB not used: this device authenticates with 802.1X".
- **UI.** `/dot1x-users/` (all roles view; operator+ create, edit groups/description/expiry/
  enabled, set password, delete). Groups without an enabled rule are flagged. Audited
  `dot1x_user.create|update|credential_reset|delete` (object_id = username; never the password or
  its hash). Auth log method filter and labels for `ttls-pap`; reason hints for each reason.
- **Upgrade.** `--phase postgres` (table, functions), `--phase app`, then `--phase freeradius`
  (eap, the inner site and its symlink, re-rendered policy) and a FreeRADIUS restart. Without the
  freeradius phase nothing changes for clients: the new policies are defined but unused.

## 19. Change (2026-11-03): EAP-TTLS with directory passwords

Step 2 of username/password 802.1X: a name that is not a local 802.1X user can sign in with its
directory account; the password is checked with an LDAP bind as that person.

- **Setting** `dot1x_ttls_directory` (`'false'` by default; Settings, admin + step-up, audited).
  Only effective while `dot1x_ttls` is on. A local 802.1X user of the same name always wins
  (its own password, groups, disabled/expired state).
- **SQL.** `radius_admin_dot1x_user_hex` returns `'directory'` instead of `'unknown'` when the
  name is not a local user and the setting is on.
- **FreeRADIUS.** `mods-available/ldap` gains a second section, `ldap ldap_user`, after the main
  one. It takes `server`, `port`, `identity`, `password`, `base_dn`, the group lookup and the TLS
  settings from the main section by reference (`${modules.ldap.…}`; FreeRADIUS resolves references
  while reading and reads `mods-enabled/` in no fixed order, hence the same file). Upgrades
  (`install.sh` `carry_over_secrets`) keep the live `password`, `identity`, `base_dn`, `server`,
  `port` and, in the main section's `tls { }`, `start_tls`, `ca_file`, `ca_path`,
  `certificate_file`, `private_key_file`, `require_cert`, `check_crl` (set, added or commented out
  to match the live file; `ldap_user`'s references follow). `tls_min_version` stays as shipped.
  User filter:
  `(&(objectClass=user)(!(objectClass=computer))(|(sAMAccountName=%{User-Name})(userPrincipalName=%{User-Name})))`,
  values escaped by rlm_ldap. No `update` section (nothing is read from the entry besides groups);
  pool `start = 0`. The installer's live-setting carry-over (first match for identity, base DN,
  password; bind test) is unaffected; its server-line handling ignores reference lines.
- **Inner site.** When the policy left `control:Tmp-String-0 = "directory"`: `ldap_user`
  (authorize: user DN, group names cached in `control:ldap_user-LDAP-Group`); `notfound` → reject
  "no such 802.1X user (not a local user, not found in the directory)"; any other failure → reject
  "the directory could not be searched for this user"; else `Auth-Type := ldap_user` (authenticate:
  LDAP bind as the user) and the group names are copied to `control:Tmp-String-9`. Otherwise `pap`.
- **Policy.** `radius_admin_inner_authorize` marks `outer.control:Tmp-String-1 = "ttls-ldap"` for
  directory names. `radius_admin_inner_postauth` hex-encodes the groups (same pattern as EAP-TLS:
  attribute copy, `%{hex:…}` per item) into `outer.session-state:Tmp-String-3` with the marker
  `ttls-ldap`. `radius_admin_inner_reject` gives "the directory refused the password (wrong password,
  or a disabled, locked or expired account)". The outer branch accepts either marker; for
  `ttls-ldap` it validates the group list (`^(,[0-9a-f]+)*$`) and calls `radius_admin_vlan_rule_hex`
  (the EAP-TLS matcher), and the groups are logged in `radpostauth.ad_groups_hex`.
- **Log/UI.** `authmethod = 'ttls-ldap'`; filter and labels; the auth log record shows the
  directory groups seen and the matching rule; hints for the three directory reasons; the 802.1X
  users page says when directory accounts are accepted. MAB treats `ttls-ldap` like the other
  802.1X methods.
- **Upgrade.** As section 18 (`--phase postgres`, `app`, `freeradius` and a restart).

## 20. Change (2026-11-03): PEAP-MSCHAPv2 for local 802.1X users (standard mode only)

Step 3 of username/password 802.1X. MSCHAPv2 uses MD4, DES and SHA-1: a documented exception
(SECURITY §1.1 exception 8), never available with `require_fips`.

- **Setting** `dot1x_peap` (`'false'`; Settings, admin + step-up, audited). With `require_fips`
  the checkbox is not shown, a posted value is ignored, `create_app` switches an earlier `'true'`
  off (`services.fips_peap_off`, audited as `system:fips`).
- **Column** `ui.dot1x_user.nt_hash` (32 lower-case hex digits or NULL): MD4 of the UTF-16LE
  password (`crypto.nt_hash`, RFC 1320 in Python). Set only when a password is entered with
  "Allow PEAP" ticked (create, set password); unticking on edit sets it to NULL; ticking on edit
  without a password is refused. Never shown or audited (audit detail `peap: bool`). Ignored and
  cleared on save in FIPS mode.
- **SQL** `radius_admin_dot1x_nt_hex(user_hex)` → `'0x' || nt_hash`, or `off` / `unknown` /
  `disabled` / `expired` / `nopeap`, NULL for malformed input; EXECUTE for `radius_fr` only.
  `radius_admin_dot1x_vlan_rule_hex` answers while `dot1x_ttls` or `dot1x_peap` is on.
- **FreeRADIUS.** `mods-available/eap`: `peap { tls = tls-common; default_eap_type = mschapv2;
  virtual_server = "radius-admin-peap"; copy_request_to_tunnel = no; use_tunneled_reply = no }`
  and, after the main section, `eap radius_admin_inner_eap { default_eap_type = mschapv2;
  mschapv2 { send_error = no } }`. `sites-available/radius-admin-peap`: authorize
  `filter_username`, `radius_admin_peap_authorize`, `radius_admin_inner_eap { ok = return }`;
  authenticate `Auth-Type MS-CHAP { mschap }`, `radius_admin_inner_eap`; post-auth
  `radius_admin_peap_postauth`, REJECT `radius_admin_inner_reject`. The installer enables the
  site and re-enables `mods-enabled/mschap` (no longer in `modules-to-disable.txt`).
  `sites-available/default`, Post-Auth-Type REJECT: `radius_admin_reject` before `-sql`.
- **Policy.** `radius_admin_peap_authorize` (every inner round): method `peap` and the inner
  User-Name on `outer.control`; no EAP-Message → reject; `NT-Password` from the function when it
  matches `^0x[0-9a-f]{32}$`, otherwise reject with the reason. `radius_admin_peap_postauth`:
  `outer.session-state` marker `peap`. `radius_admin_inner_reject` also stores method, user and
  reason in `outer.session-state` (`Tmp-String-4`, `Tmp-String-5`, `Module-Failure-Message`);
  `radius_admin_reject` restores them for the outer reject one round later (PEAP sends its
  failure inside the tunnel), only when `control:Tmp-String-1` is unset and the stored method is
  one of `ttls-pap|ttls-ldap|peap`. The outer post-auth branch accepts `peap` like `ttls-pap`.
- **Log/UI.** `authmethod = 'peap'`; filter, labels, hints (turned off, not allowed for this user,
  only EAP-MSCHAPv2 inside); PEAP tag on the 802.1X users list. MAB treats `peap` like the other
  802.1X methods.
- **Upgrade.** As section 18; the freeradius phase also installs the PEAP site, re-enables mschap
  and the new default-site line. The policy and that line are installed together; after an app
  downgrade an Apply is refused by `radiusd -XC` (the policy lacks `radius_admin_reject`) rather
  than breaking FreeRADIUS.

## 21. Change (2026-11-03): PEAP-MSCHAPv2 with directory accounts (domain join, ntlm_auth)

Step 4 of username/password 802.1X. Same exception and FIPS rule as section 20.

- **Join.** `deploy/ad-join.sh --realm REALM [--workgroup NAME] [--admin USER]` (console, root):
  refuses with `require_fips`; installs `samba-common-bin winbind`; writes `/etc/samba/smb.conf`
  (member only: `security = ads`, `ntlm auth = mschapv2-and-ntlmv2-only`, no shares; first line
  `# radius-admin (deploy/ad-join.sh)`), replacing only nothing, the package default
  (`/usr/share/samba/smb.conf`) or its own earlier file unless `--replace-smb-conf` (backup kept);
  `net ads join -U USER` (prompts; the password never passes through the script); enables winbind;
  `usermod -aG winbindd_priv freerad`; checks `net ads testjoin`, `wbinfo -t`. `--status`,
  `--dry-run`, `--print-config`. Not run by the installer or the updater.
- **Setting** `dot1x_peap_directory` (`'false'`; hidden and refused with `require_fips`, switched
  off by `fips_peap_off` with `dot1x_peap`). `radius_admin_dot1x_nt_hex` returns `'directory'` for
  a name that is not local while it is on.
- **FreeRADIUS.** `mods-available/mschap` is shipped (stock 3.2.10 plus `ntlm_auth =
  "/usr/bin/ntlm_auth --request-nt-key --allow-mschapv2 --username=%{%{mschap:User-Name}:-None}
  --challenge=… --nt-response=…"`, `ntlm_auth_timeout = 5`). Local users get
  `MS-CHAP-Use-NTLM-Auth := No` with their `NT-Password`, so ntlm_auth runs only for directory
  names. The `ldap_user` filter uses `%{%{Stripped-User-Name}:-%{User-Name}}`.
  `radius-admin-peap` authorize, for `"directory"`: `Stripped-User-Name := %{mschap:User-Name}`
  (no `DOMAIN\` prefix), `ldap_user` (notfound → "not found in the directory"; other failure →
  "could not be searched"), groups to `control:Tmp-String-9`; then the inner EAP.
- **Policy.** `radius_admin_peap_authorize`: `outer.control:Tmp-String-1 = "peap-ldap"` for
  directory names, no reject. `radius_admin_peap_postauth`: hex-encoded groups (shared
  `_DIRECTORY_GROUPS_HEX`) into `outer.session-state` with marker `peap-ldap`. Outer branch and
  `radius_admin_reject` accept `peap-ldap` like `ttls-ldap`; the directory reject reason covers it.
- **Log/UI.** `authmethod = 'peap-ldap'`; Settings checkbox with the `ad-join.sh` hint; labels,
  filter, directory groups on the record. MAB treats it like the other 802.1X methods.
- **Bench.** `tests/freeradius/fake-ntlm-auth.py` stands in for ntlm_auth (checks the MSCHAPv2
  NT-Response with DES and the NT hash, RFC 2759; logs every call). `tests/installer/test_ad_join.sh`
  covers the script without a domain.

## 22. Change (2026-11-04): numbered pages

- **Lists.** The authentication log, the audit log and the sessions page show 50 rows per page
  with numbered page links (`paging.Pager`, macro `pager` in `_macros.html`): "51–100 of 1,234"
  and Previous · 1 … 4 5 [6] 7 8 … 25 · Next (first and last page, two each side of the current
  one). The sessions page previously showed 100 per page with Newer/Older only.
- **Counting.** Each view counts the matching rows with the same `FROM … WHERE` as the page query,
  capped at `MAX_PAGE` (10,000) pages (`count(*)` over a `LIMIT` subquery); a capped count shows
  as "500,000+". A page number past the end shows the last page; anything unparsable is page 1.
- **Links** keep the active filters and leave out empty ones.

## 23. Change (2026-11-04): progress indicators instead of page refreshes

Pages that wait for work done elsewhere (the monitor service, the update check, the install
unit) show a spinner and ask a JSON status URL; they reload once, when the work is done. The
meta refresh stays only inside `<noscript>`, so every page still works without JavaScript.

- **Contract.** `GET <status URL>` → `{"done": bool, "message": str?}` (`application/json`).
  `_macros.html`: `live_status(url, message, interval, limit, timeout)` renders the spinner
  and `data-live`; `noscript_refresh(s)` the fallback; `busy_button(label)` a disabled button
  with a spinner for work already running. `app.js` polls every `interval` seconds, shows
  "Lost contact with the console; retrying…" after two failed requests (the console restarts
  during an install), reloads when `done`, reloads at once when the answer is not JSON (signed
  out), and stops after `limit` seconds with the `timeout` text.
- **Busy buttons.** A form with `data-busy="<label>"` shows a spinner on the button that
  submitted it (and the label, if not empty) until the next page; a cancelled `data-confirm`
  leaves it alone. Used by Check now, Install, Validate, Apply, Roll back, SNMP Refresh now and
  Test, and Send test alert.
- **Status URLs.**

  | Page | URL (role) | Done when |
  | --- | --- | --- |
  | Updates, Check now | `/updates/status?wait=check` (admin; no helper call) | `ui.update_check.checked_at` ≥ `update_check_requested`, or 5 min passed (the page then says the check did not finish; forgotten after 1 h) |
  | Updates, install | `/updates/status?wait=install` (admin) | the helper's state is not queued/installing; a helper that does not answer is "not done" |
  | SNMP test | `/switch-monitoring/test/<id>/status` (signed in) | `ui.snmp_test.done_at` set |
  | Session action (CoA), its own page | `/sessions/coa/<id>/status` (signed in) | `ui.coa_request.done_at` set (rows of the sessions page: section 24) |
  | Switch monitoring, Refresh now | `/switch-monitoring/refresh/status` (operator) | every switch has `ui.switch_status.polled_at` ≥ `refresh_requested_at`, or 3 min passed |
  | Alerts, Send test alert | `/alerts/test/status` (admin) | a `test` alert opened at or after `test_requested_at`, or 2 min passed |

  "Results appear within a minute" and "This page refreshes by itself" are gone from these
  pages (Refresh now from the clients page keeps its message).
- **Install log.** During an install, and after it for the last one, the Updates page has a
  Details drop-down with the install log in a terminal-style box. It asks `GET /updates/log?
  offset=N` (admin) every 2 s while open and the install runs (helper `update_log`, section
  6), appends the text, keeps the view at the bottom unless the reader scrolled up, and keeps
  at most 400,000 characters. The app removes terminal escape sequences and control
  characters other than tab and newline; a lone carriage return becomes a newline. A helper
  from an older release answers "unknown action": the box then says the log arrives with the
  update, and the step messages above still show the progress. The drop-down stays open
  across the reload that shows the result (sessionStorage, per tab).
- **Confirmations.** `data-confirm` forms and the role select ask in a modal `<dialog>` built by
  `app.js` (no `window.confirm`, except in browsers without `<dialog>`): the text up to the first
  "?" is the title, the rest the explanation; the action button is named after the pressed
  button ("Confirm" when that is longer than 32 characters) and is red for buttons with a
  `danger` class or messages starting Delete/Remove/Disable, which open with Cancel focused.
  Escape, Cancel and the backdrop cancel. On OK the form is submitted again with the same
  button (`requestSubmit`), so validation and the busy spinner still apply.
- Polling counts as activity for the idle session timeout while it runs (bounded by `limit`:
  30 min for an install, at most 5 min elsewhere).

## 24. Change (2026-11-10): session actions in place, several at once; lists keep their filters

- **One POST for one or many.** `POST /sessions/coa` (operator; replaces `/sessions/<id>/coa`)
  takes `action` (`reauth`/`bounce`/`disconnect`) and `sid` once per session (`radacct.radacctid`,
  digits only, at most 50 = one page; anything else is 400). Each session that is still open, on
  an enabled RADIUS client and without a request already waiting gets its own `ui.coa_request`
  row and its own `coa.request` audit event (detail gains `selected`, the number of sessions
  named in the POST). The others are skipped with a reason (ended, switch unknown or disabled,
  request waiting, record gone). Nothing selected is not an error status: the answer says so.
  - Browser form: redirect to the sessions list as it was last shown, with the summary as a
    flash message.
  - `Accept: application/json` (the page script): `{"action", "label", "message", "queued":
    [{"sid", "id", "url"}], "skipped": [{"sid", "name", "reason"}]}`.
- **Open sessions in the 30-day view.** Tick boxes and the Actions menu appear for every row
  with no stop time and a known switch, in both views; ended rows have neither. The server
  decides again on every request.
- **State in the row.** `ui.coa_request.radacct_id` (`sql/97-session-actions.sql`: nullable
  bigint, partial index, additive; no foreign key because accounting rows are owned by
  FreeRADIUS and pruned separately) names the session. The sessions page joins the latest
  request per session and shows it in the row while it waits and for 15 minutes after it was
  requested: spinner and "Sending…", then Done or Failed, always a link to the request's page.
  `GET /sessions/coa/status?id=1&id=2…` (signed in, at most 200 ids, unknown ids left out) →
  `{"requests": [{"id", "state": "waiting"|"ok"|"failed", "message"}]}`; `app.js` asks every
  2 s for all waiting rows of the page at once and stops after 5 minutes ("No answer yet").
  With JavaScript the POST is sent with `fetch` and nothing reloads; without it the page comes
  back with the same row states and a `<noscript>` refresh every 5 s while a request waits.
  The confirmation dialog takes its question from the pressed button when that has
  `data-confirm` (the bulk buttons: "<Action> N sessions?").
- **Session actions page.** `GET /sessions/actions` (signed in; menu item under Monitoring):
  every request, newest first, 50 per page, filters `q` (user, MAC, port, requester),
  `switch`, `action`, `result` (`ok`/`failed`/`waiting`). Each row links to
  `/sessions/coa/<id>`, which shows the result, the advice for a failure and the request's
  details (who, when, switch, port, user, station and vendor, accounting session id and
  whether that session is still open). The "recent requests" table on the sessions page is gone.
- **Monitor.** In one pass over the queue (10 requests), after a switch gave no reply the other
  requests for that switch are answered "Not sent: <switch> did not answer the request before
  this one" without waiting for each to time out; the next pass tries the switch again.
- **Lists keep their filters** (`listnav.py`). The sessions list, session actions, the
  authentication log, RADIUS clients, MAB devices, unknown devices and alerts remember the
  query arguments they were last shown with (the names in `listnav.LISTS`, values cut to 100
  characters). `list_url(endpoint)` (Python and templates) builds the list's URL with them; it
  is used by "Back to …" and Cancel links and by the redirects after editing, deleting or
  acting on a row. Adding or importing entries still opens the plain list, where the new entry
  is. Opening a list without arguments (the menu) forgets its filters. The state is a session
  cookie `__Host-radius_admin_lists` (Secure, HttpOnly, SameSite=Strict; base64 JSON, at most
  3000 characters, deleted at sign-out), per browser rather than per tab. It is display state
  and is not trusted: only the listed argument names are read, as text, and only to build the
  URL of the same list, whose view validates them like any query string.

## 25. Change (2026-11-19): accounting records without an Accounting-Stop are closed

- **Why.** A switch that reboots without Accounting-On, loses a Stop packet, or starts a new
  accounting session each time it re-authenticates a port (802.1X ↔ MAB) leaves the old
  `radacct` row open. The sessions page listed every such row as up, each with the port's live
  state ("Authorized" came from the device's current session), and session actions on them
  failed with `Session-Context-Not-Found`.
- **`sql/98-stale-sessions.sql`** (idempotent, additive): partial index
  `radacct_open_csi_idx (callingstationid, nasipaddress) WHERE acctstoptime IS NULL` and two
  `SECURITY DEFINER` functions owned by `radius_owner`, `search_path` pinned, executable only by
  `radius_admin` (the web app's role still has `SELECT` only on `radacct`):
  - `radius_admin_close_stale_sessions(p_stale_hours integer DEFAULT 24, OUT superseded,
    OUT stale)`: closes an open record when a later accounting session started for the same
    Calling-Station-Id on the same NAS address (stop = the later start, cause `Superseded`),
    then open records that had interim updates and none for `p_stale_hours` (at least 24;
    stop = last update, session time kept from it, cause `Stale-Session`). Records that never
    had an interim update are left open. Takes no request data.
  - `radius_admin_close_after_coa(p_request_id bigint) → boolean`: closes the record named by
    `ui.coa_request.radacct_id` only when that request is finished, not ok and its message
    contains `Session-Context-Not-Found`, and only if the record is still open (stop = last
    update, else now; cause `Session-Not-Found`).
  A real Accounting-Stop that arrives later still overwrites the row (the stock stop query's
  last fallback has no `AcctStopTime IS NULL`); an Interim-Update for a closed row is ignored.
- **Monitor.** `close_stale_sessions()` runs every 5 minutes (`CLOSE_SESSIONS_EVERY`) and
  writes a syslog line when it closed anything. After a CoA/Disconnect request is refused with
  `Session-Context-Not-Found` for a request that names a session, `run_coa` calls
  `radius_admin_close_after_coa` and appends "The switch no longer has this session; its
  accounting record was marked as ended." to the request's message.
- **UI.** The 30-day view and the request page show the three causes as "Closed: newer
  session from this device", "Closed: no accounting update for a day" and "Closed: the switch
  no longer has it". The request page explains `Session-Context-Not-Found` instead of the
  dynamic-authorization checklist.

## 26. Change (2026-11-19): vendor profiles

- **Why.** The reply attributes for a VLAN and for full admin rights, the CoA attributes and
  the SNMP port-name rule were written into the code for the Catalyst 1300. They now come from a
  vendor profile so that other switches, access points and firewalls can be supported by adding
  a profile, without code changes. This step moves the existing behaviour into the built-in
  profile `cisco-c1300`, which every client uses; the generated policy, the clients file and
  every CoA request are byte-for-byte what they were before.
- **Format 1** (JSON, `app/radius_admin/vendor_profiles/<id>.json`; the same form is the
  export/import format). Every field is required except `description`; unknown fields are
  refused.

  | Field | Contents |
  |---|---|
  | `format` | `1` |
  | `id` | `[a-z0-9][a-z0-9-]{0,31}`; a built-in profile's file name |
  | `label`, `description` | Display text, 1-64 / up to 300 printable characters |
  | `status` | `supported` (passed the bench and real hardware) or `unverified` |
  | `reply.vlan` | Attributes sent with an accepted MAB / 802.1X request. One value must be `{vlan}` |
  | `reply.admin_full` | Attributes added to a device admin login (local or directory account) when `admin_priv15` is on |
  | `reply.role` | Optional (absent = empty). Attributes added to an 802.1X accept when the matched access rule has a role; one value must be `{role}` |
  | `mab.port_types` | Optional (absent = `["Ethernet"]`). NAS-Port-Type values that start MAB: `Ethernet`, `Wireless-802.11` (access points and controllers) |
  | `coa.port` | UDP port of the device's dynamic-authorization server, used when the client sets none |
  | `coa.identify` | How the session is named: `mac-then-session` (Calling-Station-Id, else Acct-Session-Id) or `session-and-mac` (Acct-Session-Id and Calling-Station-Id, each when known; RFC 5176 §3.3) |
  | `coa.send_nas_port_id` | Add NAS-Port-Id from the accounting record |
  | `coa.reauth`, `coa.bounce`, `coa.disconnect` | `null` (the device cannot) or `{"packet": "coa"\|"disconnect", "attrs": [...]}` |
  | `setup.accounting`, `setup.coa` | Optional. Device commands the portal shows (as escaped text, never configuration) for turning on accounting / dynamic authorization; `null` or absent: a generic sentence instead |
  | `setup.mfa_timeout` | Optional (section 29.4). Device commands for a RADIUS timeout long enough for a second factor; `null` or absent: `vendors.GENERIC_MFA_TIMEOUT` |
  | `snmp.port_names` | Up to 8 rules `{"match": <regex, full match>, "ignore_case": bool, "format": ...}`; the first match renames an ifName; `format` is `[A-Za-z0-9/._:-]` plus `{n}`, `{n:lower}`, `{n:upper}` |

  Reply entries are `{"attr", "op": ":=" | "+=", "value"}`, CoA entries `{"attr", "value"}`, at
  most 8 per list. Each reply list needs at least one entry (FreeRADIUS refuses an empty
  `update` section).
- **Validation** (`vendors.validate`, applied to built-in files too, and again by
  `render_policy` to any profile passed in). Attribute names are `[A-Za-z][A-Za-z0-9-]{0,63}`
  and may not be server-internal or secret: `Auth-Type`, `Exec-Program*`, `Tmp-*`, `Module-*`,
  `*-Password`, raw `Attr-N` / `Vendor-*` forms, packet framing (`Message-Authenticator`,
  `State`, `EAP-*`), or the attributes the CoA sender fills in itself. Values are 1-247
  printable ASCII characters without `"` `\` `%` `$` `` ` `` `{` `}`, so they cannot leave
  their string, expand an xlat or reference configuration; a placeholder is a whole value and
  `{vlan}` only in `reply.vlan`, `{role}` only in `reply.role`. Rendering: a placeholder becomes
  its attribute reference (`{vlan}` → `&control:Tmp-String-0`, `{role}` → `&control:Tmp-String-4`),
  a value of letters, digits and `-` is written bare
  (enumeration names such as `VLAN`), anything else double-quoted.
- **Code.** `vendors.py` (`validate`, `builtin`, `default`, `export_json`, `import_json`,
  `port_name`, `format_value`); `unlang.render_policy(custom, profile=None)`;
  `coa.build_request(..., profile=None)` and `coa.send(..., profile=None)` (an action the
  profile sets to `null` is refused); `snmp.cli_port_name(name, profile=None)`, passed through
  `build_status`, `build_ports` and `poll_switch`. `coa.ACTIONS` is now the tuple of action
  names.
- **Built-in profiles.**

  | id | Status | VLAN | Full admin | CoA |
  |---|---|---|---|---|
  | id | MAB from | Role |
  |---|---|---|
  | `cisco-c1300` | Ethernet | none |
  | `generic-rfc` | Ethernet, Wireless-802.11 | `Filter-Id := {role}` (RFC 2865) |

  | id | Status | VLAN | Full admin | CoA |
  |---|---|---|---|---|
  | `cisco-c1300` (default) | supported | RFC 3580 tunnel attributes | `Cisco-AVPair += "shell:priv-lvl=15"` | UDP 1700, `mac-then-session`; reauth and bounce by `Cisco-AVPair` subscriber commands; Disconnect |
  | `generic-rfc` | unverified | RFC 3580 tunnel attributes | `Service-Type := Administrative-User` (RFC 2865) | UDP 3799, `session-and-mac`; Disconnect only (re-authenticate and bounce have no standard form) |

  `generic-rfc` keeps SNMP port names as reported. Both render a policy that passes
  `radiusd -XC`; `generic-rfc` stays "unverified" until it has run against real hardware.
- **A profile per client.**
  - **Database** (`sql/99-vendor-profiles.sql`, additive, idempotent): `ui.radius_client.vendor_profile`
    (`NULL` = the default; CHECK `^[a-z0-9][a-z0-9-]{0,31}$`) and `ui.radius_client.coa_port`
    (`NULL` = the profile's port; 1-65535). When the column is added and
    `ui.snmp_profile.coa_port` is not 1700, that value is copied to every existing client once,
    so CoA keeps reaching the port it used before. `ui.snmp_profile.coa_port` is no longer read
    or shown and is dropped in a later release. Setting `ui.setting.default_vendor_profile`
    (absent or unknown: `cisco-c1300`), changed under Settings → Devices.
  - **Clients file.** A client whose profile is set and differs from the default carries
    `radius_admin_profile = <id>` (UDP and RadSec clients). FreeRADIUS 3.2 keeps unknown pairs of
    a client section, and `%{client:radius_admin_profile}` reads it. The root helper accepts the
    key in both client grammars, unquoted, matching `[a-z0-9][a-z0-9-]{0,31}`.
  - **Policy.** `render_policy(custom, profile, others)`: `profile` is the default, `others` the
    profiles enabled clients name. Each `update reply` with profile attributes becomes, when some
    of `others` have a different attribute list for it, `if ("%{client:radius_admin_profile}" ==
    "<id>" || …) { update reply {…} } … else { update reply {<default's>} }`, one branch per
    distinct list, ids sorted. With no other profiles, or only ones with the same lists, the
    output is what it was before. `services.render_all` refuses (PolicyInputError) a client
    that names a profile this server does not have. A default-profile change, like a client's
    profile change, takes effect at the next Apply.
  - **CoA.** `run_coa` builds and sends each request with the client's profile, to
    `coalesce(client.coa_port, profile.coa.port)`. The sessions page offers only the actions the
    session's switch can take; a request for one it cannot is not queued ("<switch> (<profile>)
    cannot bounce a port"). The request page names the profile and shows its `setup.coa`.
  - **SNMP.** The poller (`run_cycle`, `run_tests`) passes each switch's profile to `poll_switch`;
    the sessions page and the client's port table match NAS-Port-Id with it.
  - **UI.** Client form: *Device profile* (Default: <label>, a built-in profile, or a custom one
    marked "(custom)") and *Session-action port (UDP)* (empty = the profile's).
    Client list: the profile's label in the options column. Settings → Devices: default profile.
    Switch monitoring → Session actions: the port field is gone (text points to the client).
    Sessions: the accounting setup text comes from the profiles of the switches concerned.
  - **CSV import.** Optional header column `vendor_profile`: empty = not given (existing clients
    keep theirs, new ones use the default), `default` = back to the default, else a built-in id;
    anything else is an error for that line.
  - **Audit.** `client.create` / `client.update` include `vendor_profile` and `coa_port`;
    `settings.update` includes `default_vendor_profile`.
- **MAB from access points.** The MAB condition (authorize `radius_admin_mab` and the post-auth
  re-check) becomes, when a profile in use accepts more than Ethernet,
  `&NAS-Port-Type && ((&NAS-Port-Type == Ethernet[ && <profiles>]) || (&NAS-Port-Type ==
  Wireless-802.11 && <profiles>))`, where `<profiles>` names the clients' profiles that accept
  that port type (`"%{client:radius_admin_profile}" == "<id>" || …`), or, when the default does,
  `!(<the profiles that do not>)`. Every profile in use Ethernet-only: unchanged. The registered
  MAC, its VLAN, the approval queue and the Calling-Station-Id check are the same for both; the
  device decides which SSIDs use MAC authentication.
- **A role per access rule.** `ui.access_rule.role` (`sql/99-vendor-profiles.sql`; NULL or
  `^[A-Za-z0-9._-]{1,64}$`, CHECK), set on the rule form (optional) and audited with the rule.
  When some profile in use has `reply.role` attributes, both 802.1X branches (password and
  EAP-TLS) add after the VLAN: if `&control:Tmp-String-6` (the matched rule id) is 1-10 digits,
  `&control:Tmp-String-4 := "%{sql:SELECT radius_admin_rule_role(<id>)}"`, and if that matches
  `^[A-Za-z0-9._-]{1,64}$`, an `update reply` with the profile's role attributes (branched per
  profile; a profile without any gets `noop`). `radius_admin_rule_role(bigint) → text`:
  SECURITY DEFINER, owner `radius_owner`, `search_path` pinned, executable only by `radius_fr`;
  the role of the enabled rule with that id, else `''`. It takes no request data (the id was
  produced by `radius_admin_vlan_rule_hex` / `radius_admin_dot1x_vlan_rule_hex` and is checked
  to be digits). The role reaches the reply only as an attribute reference, never re-parsed;
  `Tmp-String-4` is otherwise used only by the switch-admin branch, and the post-auth insert
  does not read it. A failed lookup sends the VLAN without the role. MAB devices get no role.
- **SNMP without IEEE8021-PAE-MIB.** Such devices are still polled (system, uptime, RADIUS
  servers); the client page says the 802.1X state is not offered over SNMP instead of implying
  a fault.
- **Custom profiles (portal).**
  - **Storage.** `ui.vendor_profile (id PK, doc jsonb, created_at, updated_at, updated_by)`
    (`sql/99-vendor-profiles.sql`; CHECK: id pattern, `doc` an object whose `id` equals the row's;
    the app role has SELECT/INSERT/UPDATE/DELETE). `doc` is the profile as `validate()` returned
    it. `vendors.catalog(conn)` = built-in profiles plus every stored profile that still
    validates, has the row's id and no built-in id (others are left out). Every lookup goes
    through the catalog: rendering for Apply, the default-profile setting, the client form and
    list, CSV import, the sessions page, CoA and SNMP in the monitor.
  - **Pages** (`views/profiles.py`, nav *Network access → Device profiles*). `/profiles/` (all
    roles): every profile with type ("Built-in" or "Custom"; `status` is not shown), the number of
    clients using it (a client that names no profile counts for the default) and the default
    marker; Export JSON for each; for admins Copy, New, Import,
    and Delete for custom ones; for built-in profiles **Report a problem**: a link to
    `https://github.com/<update_repo>/issues/new?template=device-profile.yml&title=…&profile=<id>&version=<installed version>`
    (`vendors.report_url`; `update_repo` must be `owner/name`, else no link), the issue form
    `.github/ISSUE_TEMPLATE/device-profile.yml` (profile, version, device and firmware, what
    does not work, a privacy confirmation). Nothing else about the site goes into the link. `/profiles/<id>` shows the profile in a form,
    read-only for built-in profiles and for non-admins. `/profiles/new?from=<id>` (admin)
    starts from a copy. Saving, importing and deleting are admin-only and need a current
    step-up (inline step-up fields keep the entries when it has lapsed). The id cannot be
    changed after creation. Custom profiles are always saved as `unverified`.
  - **Form.** One attribute per line, `Attribute := value` / `Attribute += value` (reply lists)
    or `Attribute = value` (CoA extras); a packet type per CoA action ("Not supported" = `null`);
    one port-name rule per line, `regex => format`, optional `(ignore case)`; checkboxes for the
    MAB port types. `vendors.form_to_profile` builds the document and runs `validate()`; an error
    is shown at the field its path names. When the FreeRADIUS dictionary directory is found (as
    for CoA), every attribute name must be defined in its `dictionary*` files; otherwise the
    check is left to `radiusd -XC` at Apply.
  - **Export / import.** `/profiles/<id>/export` downloads `export_json(profile)` as
    `<id>.radius-admin-profile.json` (audited `profile.export`). `/profiles/import` takes a file
    or pasted JSON (≤ 64 KiB, UTF-8): status forced to `unverified`, `validate()`, the built-in id
    and dictionary checks; an existing custom id needs "Replace". Audit: `profile.create`,
    `profile.update` (with the before/after SHA-256 of the exported JSON, clients using it,
    default), `profile.delete`, `profile.import` (`replaced`), failures included.
  - **Delete** is refused while a client names the profile or it is the default.
  - **Effect.** Reply attributes and MAB port types reach FreeRADIUS at the next Apply (the apply
    page shows the pending change for a profile in use); CoA attributes, the CoA port and
    port-name rules apply from the monitor's next pass and the next page load.

## 27. Change (2026-11-19): nginx security floor

- **Why.** The nginx security release of 2026-11-18 (1.30.7 / 1.31.9) fixes two HTTP/2 bugs
  (CVE-2026-123007, CVE-2026-123633) and a TLS 1.3 denial of service (CVE-2026-118899) that
  the portal's site is exposed to (`listen … ssl http2`, TLS 1.3, `proxy_pass` to gunicorn).
  Ubuntu 24.04 fixed them in nginx `1.24.0-2ubuntu7.20` (USN-9159-1). The other CVEs of that
  release need HTTP/3, the mail proxy, stream modules, a `proxy_pass` built from request data
  with `resolver`, or `try_files` with `alias` and `map` captures; the site uses none of them.
- **`RA_NGINX_MIN_VERSION`** (`deploy/lib.sh`, overridable from the environment): the oldest
  nginx package with the fixes the site needs, compared with `dpkg --compare-versions`. Raise it
  when a later nginx advisory affects the site template. Helpers `nginx_installed_version`,
  `nginx_candidate_version`, `nginx_version_ok` (read-only).
- **Preflight** reports the installed nginx (OK, or WARN when older, saying whether the package
  lists already offer a fixed build), or, before nginx is installed, warns when the candidate
  is older. Warnings only: preflight stays read-only and never blocks on this.
- **Installer phase `nginx-update`** (after `packages`, before `fr-package`): nothing when nginx
  is not installed or already at the floor (no apt call). Otherwise, when the cached candidate
  is too old it runs `apt-get update` once; when the candidate then meets the floor it runs
  `apt-get install --only-upgrade nginx` (`NEEDRESTART_SUSPEND=1`), checks the installed
  version, and restarts a running nginx after `nginx -t` (a restart, not a reload: a reload keeps
  the old binary). No fixed build on the mirror: a warning, the install continues. `nginx -t`
  failing after the upgrade stops the installer without restarting nginx.
- **`update.sh`** adds `nginx-update` to its automatic choice when the installed nginx is older
  than the *new* release's `RA_NGINX_MIN_VERSION` (it sources the new `deploy/lib.sh`), so a
  release that raises the floor upgrades nginx on servers that update; the plan shows the phase
  before the confirmation. The portal's signed updates run the same `update.sh`, and their
  health check (nginx active and listening on 443) covers the restart.
- Tests: `tests/installer/test_nginx_update.sh` (version comparison, every branch of the phase
  with stubbed apt/dpkg/systemctl/nginx, the update.sh choice, preflight wiring).

## 28. Change (2026-11-19): device admins; directory accounts for device admin logins

- **Name.** "Switch admins" are shown as **device admins** (switches, access points, firewalls and
  other RADIUS clients' management logins): navigation, page titles, settings, logs, reports, the
  setup checklist and the reject reasons FreeRADIUS writes. Internal names are unchanged so audit
  history and upgrades stay consistent: the group `net-admins`, the blueprint `switch_admins`, the
  audit actions `switch_admin.*`, the setting keys `admin_subnet`/`admin_priv15`, the authmethod
  `pap-admin`. The page moves to `/device-admins/`; `/switch-admins/…` answers 308 to the same path
  there (query string kept). The log hints match the old and the new reason texts.
- **Settings** (`sql/100-device-admins.sql`, ui.setting; Settings → Device admin logins, admin +
  step-up, audited as `settings.update`): `admin_directory` (`'false'` by default) and
  `admin_directory_groups` (directory group names, one per line; the console trims them, drops blank
  lines and duplicates in any case, checks each with `validate_ad_group`, allows at most 50, and
  refuses to turn directory accounts on with no group). Live: read by FreeRADIUS on every login.
- **SQL** (SECURITY DEFINER, execute for `radius_fr` only):
  `radius_admin_admin_directory_hex(user_hex)` → `'local'` when the name has any `radcheck` or
  `radusergroup` row (case-insensitive: a local account always wins), `'off'` when the setting is
  off or no group is configured, else `'directory'`; NULL for malformed hex (1–253 bytes).
  `radius_admin_admin_group_hex(groups_hex)` → true when the setting is on and one of the
  `,<hex>` group names equals a configured group (case-insensitive); false otherwise and on
  malformed input. `radius_admin_admin_directory_groups()` (internal) parses the setting.
- **SQL file order.** The two-digit names were used up: `install.sh` and `tools/ci/setup.sh` load
  `sql/[0-9]*-*.sql` in version order (`sort -V`: `00-`, …, `99-`, `100-`). Every file stays
  idempotent and is re-applied on each `postgres` phase.
- **Policy** `radius_admin_admin_authorize`, called in the default server's authorize after
  `-ldap`, before `expiration`/`pap`. For a device admin login (no EAP-Message, no NAS-Port-Type
  Ethernet, no Called-Station-Id) with User-Password and no Auth-Type yet, it asks
  `radius_admin_admin_directory_hex('%{hex:User-Name}')`. On `'directory'`: marker
  `control:Tmp-String-1 = "admin-ldap"`; the management-subnet check (as in post-auth) runs first,
  so a device outside it never makes the server bind (reject "device admin login from an address
  outside the management subnet"); then `ldap_user` (the section of SPEC 19: user filter, group
  cache in `control:ldap_user-LDAP-Group`, nested groups): `notfound` → reject "no such device admin
  (not a local account, not found in the directory)", other failures → reject "the directory could
  not be searched for this user"; else `Auth-Type := ldap_user` and the groups go to
  `control:Tmp-String-9`. Default server: new `Auth-Type ldap_user { ldap_user }` (LDAP bind as the
  user). A refused bind reaches `radius_admin_reject`, which replaces rlm_ldap's own reason (none, or
  "… Bind credentials incorrect / Invalid credentials") with "the directory refused the password
  (wrong password, or a disabled, locked or expired account)"; other LDAP failures keep their text.
- **Post-auth** (device admin branch): the marker `pap-admin` is set unless it is already
  `admin-ldap`; the subnet check is unchanged; for `admin-ldap` the groups are hex-encoded into
  `control:Tmp-String-3` (as for EAP-TTLS, each name once, `"x"` when one is too long), checked
  against `^(,[0-9a-f]+)*$` and passed to `radius_admin_admin_group_hex`; true → accept, with
  the profile's `admin_full` attributes when `admin_priv15` is on (same setting as local admins);
  false → reject "the directory account is not in a device admin group". Local accounts still
  need `SQL-Group == "net-admins"`.
- **Log/UI.** `authmethod = 'admin-ldap'` with the groups in `ad_groups_hex`; the auth log record
  shows the groups seen and marks the ones allowed now; hints for the new reasons. The Device admins
  page shows whether directory accounts are accepted and for which groups; the privileged-access
  report lists the groups; the setup step "device admins" also counts as done with directory
  groups. Sessions label `admin (directory)`.
- **Upgrade.** `--phase postgres` (settings, functions), `app`, and `freeradius` with a restart
  (default server: the new policy call and `Auth-Type ldap_user`). Directory accounts stay off
  until turned on; local device admins behave as before.

## 29. Change (2026-11-20): second-factor providers for device admin logins

First step of the MFA integrations: the FreeRADIUS chain, a remote RADIUS MFA server configured in
the portal, and the live rules. Installing the Duo Authentication Proxy from the portal, its
configuration file and the signed integrations catalog follow in later steps; the Duo chain is
complete on the FreeRADIUS side and bench-tested with a stand-in.

- **Scope.** Device admin logins (section 28: PAP, no EAP-Message, no NAS-Port-Type Ethernet, no
  Called-Station-Id) only; never 802.1X. Provider types: `duo` (the Duo Authentication Proxy on this
  server, 127.0.0.1) and `radius-mfa` (a remote RADIUS server that checks the password and the second
  factor itself; directory accounts only).
- **SQL** (`sql/101-mfa.sql`, additive): `ui.mfa_provider` (id `^[a-z][a-z0-9-]{0,31}$`, type, label,
  enabled, `settings` jsonb with the non-secret values, `secrets_enc` = AES-256-GCM of a JSON object
  with the shared secrets, additional data `radius-admin:mfa_provider:<id>`, plus install columns for
  later steps); `ui.mfa_policy` (one row per account kind `local` / `directory`: enabled,
  provider_id, client_scope `all`/`selected`; enabled needs a provider); `ui.mfa_policy_client`
  (selected clients, cascades with the client); `ui.mfa_exempt` (local break-glass accounts,
  case-insensitively unique). `radius_admin_mfa_hex(user_hex, client_hex, kind)` (SECURITY DEFINER,
  execute for `radius_fr` only) → `'off'`, `'exempt'` (local accounts on the list), `'unavailable'`
  (the rule's provider is off), `'<type>:<id>'`, or NULL for malformed input or an error. Live: read
  on every login.
- **Policy** (`radius_admin_admin_authorize`). After `radius_admin_admin_directory_hex`, the client
  shortname goes to `&control:Tmp-String-5` and `radius_admin_mfa_hex('%{hex:User-Name}',
  '%{hex:control:Tmp-String-5}', 'local'|'directory')` to `&control:Tmp-String-7` (kind `directory`
  when the directory function said so). A provider →
  `&control:Proxy-To-Realm := "radius_admin_mfa_<id>"`, `&control:Tmp-Integer-0` = 1 (duo) or 2
  (remote), method `pap-admin+mfa` / `admin-ldap+mfa`, the management-subnet check (reject before
  anything is proxied); for a remote server a directory account is looked up with `ldap_user`
  (groups to `&control:Tmp-String-9`, no bind) and a local account is rejected; then `return`, so no
  later module sets an Auth-Type. `'unavailable'` → reject "a second factor is required for this
  login, but its provider is turned off"; anything other than `'off'`/`'exempt'` → reject "could not
  determine whether this login needs a second factor". FreeRADIUS proxies only if the realm exists;
  a realm that was never applied leaves the request unproxied and without an Auth-Type, so it is
  rejected.
- **Post-auth** (device admin branch). With `&control:Tmp-Integer-0`: reject unless
  `&proxy-reply:Packet-Type == Access-Accept` ("… did not reach its provider (… not applied)"); for
  Duo the proxy reply's Class must be `radius-admin:pap-admin` / `radius-admin:admin-ldap` matching
  the method ("… did not carry the password check of radius-admin-mfa-primary"); a remote marker
  with a local method is rejected. Then `update { &reply: !* ANY }` (the provider's own attributes
  never reach the device) and: Duo → the profile's `admin_full` attributes when `admin_priv15` is on;
  remote → the directory group check of section 28 on the groups looked up before proxying, then the
  same attributes. Local logins without a second factor are unchanged.
- **Reject reasons** (`radius_admin_reject`, only when no reason is set yet): a proxied login that the
  provider refused → "refused in the second-factor chain (wrong password, not a device admin, or the
  second factor was denied)" (Duo) or "the second-factor server refused the login (wrong password or
  second factor denied)" (remote); no answer → "the second-factor provider did not answer".
- **Password check for Duo** (`freeradius/sites-available/radius-admin-mfa-primary`, enabled by the
  freeradius phase). Virtual server; the Duo proxy sends the login back here before the second
  factor. authorize: `filter_username`, `radius_admin_mfa_primary_authorize` (reject without
  User-Password or with EAP; directory accounts: `ldap_user` and `Auth-Type ldap_user`), `sql`,
  `pap`; post-auth `radius_admin_mfa_primary_postauth`: directory group check or
  `SQL-Group == "net-admins"`, then `reply:Class := "radius-admin:<method>"`, else reject. It writes
  no authentication log (the default server does).
- **Clients file** (`render_clients(..., mfa)` → `render_mfa(providers)`, deterministic, sorted by
  id, enabled providers only): per provider `home_server` / `home_server_pool` (fail-over) / `realm`
  named `radius_admin_mfa_<id>` (type auth, udp, `ipv4addr`/`ipv6addr` literal, port, secret,
  `require_message_authenticator` yes (duo) or the setting (remote), `response_window` = timeout
  (duo 60; remote 5–60), `zombie_period` = 2 × timeout, `revive_interval = 60`,
  `status_check = none`); with an enabled Duo provider (at most one) also `listen { type = auth;
  ipv4addr = 127.0.0.1; port = 18121; proto = udp; virtual_server = radius-admin-mfa-primary;
  clients = radius_admin_mfa }` and `clients radius_admin_mfa` with one client
  `radius-admin-duo-proxy` (127.0.0.1, the password-check secret, `require_message_authenticator =
  yes`). The Duo proxy listens on 127.0.0.1:18120. Provider changes need Apply; `render_all` decrypts
  the secrets with the data key (the app's, or `cli render` loads it from `key_file`).
- **Helper** (section 6 clients grammar). Also accepted, with every key and value pinned: one MFA
  `listen` (virtual_server `radius-admin-mfa-primary`, 127.0.0.1, port 1024–65535) with exactly one
  `clients radius_admin_mfa` section holding one client (127.0.0.1, quoted secret,
  `require_message_authenticator = yes`); up to 8 `home_server radius_admin_mfa_<id>` (keys above;
  address literal, not a network; `response_window` 1–60, `zombie_period` 1–120,
  `revive_interval` 10–3600), each with `home_server_pool` (type fail-over, its own home_server) and
  `realm` (its own auth_pool) of the same name. The returned client count leaves out the Duo proxy.
- **Portal.** Integrations page (`/integrations/`, navigation under Device admins; viewers see it):
  rules, providers, available integrations. Admin + step-up: add/edit/remove a remote MFA server
  (id, description, address, port, shared secret write-only, timeout 5–60, require
  Message-Authenticator, on/off; a provider used by an enabled rule cannot be turned off, and one named
  by any rule cannot be removed); Second-factor rules (`/integrations/policy`): per account kind on/off,
  provider (must be on; a remote server only for directory accounts), all or selected clients
  (at least one), exempt local device admins (at most 10, must be local device admins). Audit:
  `integration.provider_create` / `_update` / `_delete` (detail without secrets: `shared_key_set`,
  `shared_key_updated`), `integration.policy`. FIPS mode: remote servers are not offered and the rules
  refuse them (the password would leave the server protected only by RADIUS's MD5-based hiding); in
  standard mode no page mentions FIPS.
- **Bench.** `tests/freeradius/fake-mfa-proxy.py` stands in for the Duo proxy (password check through
  radius-admin-mfa-primary, then a scripted second factor) and for a remote server (own password,
  extra reply attributes and a forged Class). Cases: rules off/on per kind, exemptions, selected
  clients, Duo accept/deny/no Class/retransmit with one prompt, wrong password and non-admin without a
  prompt, management subnet before proxying, provider off, provider not applied, remote server for a
  local account, remote accept with group check, reply attributes dropped, remote no answer,
  injection through the user name; the SQL audit checks the new hex-only call.
- **Upgrade.** `--phase postgres` (tables, function), `app`, and `freeradius` with a restart (new
  virtual server, new policy branches). Nothing changes until a provider and a rule are configured.

### 29.1 Provider installs: signed catalog and helper actions

The plumbing for installing a provider on this server (the portal's install pages and the Duo
installer itself follow in the next step).

- **Catalog.** `integrations/catalog.json`: `{"format": 1, "serial": N, "entries": [...]}`; each
  entry `provider` (known to the helper: `duo`), `version` (X.Y.Z), `file`
  (`duoauthproxy-<version>-src.tgz`), `url` (exactly `https://dl.duosecurity.com/` + file),
  `size`, `sha256`, `fips` (bool; `true` only with `fips_tested`, the platforms checked),
  `withdrawn` (bool), optional `min_radius_admin`. Edited only with `tools/integrations/catalog.py`
  (`add` needs the vendor's published SHA-256 and the vendor's file name and refuses when they
  differ; `fips`, `withdraw`; each change bumps `serial`). `tools/release/make-release.sh` signs it
  with the update key (ECDSA P-384, SHA-384; checked against the pinned public key) and
  `make-bundle.sh --catalog-sig` puts `integrations/catalog.json.sig` into the bundle; an invalid
  catalog stops the release. The `app` phase installs `integrations/` as
  `/opt/radius-admin/integrations/` (root, 0644; `*.sh` 0755) and removes a stale signature when
  installing from a checkout (no signature: no catalog).
- **Helper.conf** (defaults): `integration_dir = /var/lib/radius-admin/integrations` (owned by
  `integration_owner = radius-admin`, created by the installer, 0750), `integration_catalog =
  /opt/radius-admin/integrations/catalog.json`, `integration_fetch_unit`,
  `integration_install_unit`, `integration_max_mib = 128`, `integration_log_dir =
  /var/log/radius-admin`, `duo_dir = /opt/duoauthproxy`. The helper knows per provider the file
  pattern, the download prefix, its service (`duoauthproxy.service`), its address (127.0.0.1:18120),
  its API host pattern (`api-*.duosecurity.com`) and its build packages; the request only names the id.
- **Catalog checks** (every action that uses it). The shipped catalog and `.sig` must be
  root-owned, writable only by root, ≤ 256 KiB, and verify with `update_pubkey`
  (`openssl dgst -sha384 -verify` on a private copy); every entry must match the provider's rules or
  the catalog is refused. The helper keeps the newest verified catalog in its work dir
  (`integrations-catalog.json` + `.sig`): a shipped catalog replaces it only with a higher serial; a
  lower serial, or the same serial with other content, is ignored with a message (a downgrade cannot
  bring back a withdrawn build). Without a verified catalog: serial 0, no entries.
- **Actions** (section 6 additions):
  - `integration_status` → `{"fips_enabled", "integrations": {id: {label, installed (from
    <duo_dir>/.radius-admin, root-owned: version, sha256, verified, installed, fips), service_active,
    listening, state}}}`; an install whose unit no longer runs is marked failed.
  - `integration_catalog` → `{serial, source: release|kept|none, fips_enabled, entries, message}`.
  - `integration_preflight {"id", "api_host"?}` → `{ready, checks: [{check, ok, detail}]}`: free
    space (≥ 1 GiB) for `duo_dir`'s parent and the work dir, OS (Ubuntu/Debian from
    `/etc/os-release`, read not sourced), missing build packages (`dpkg-query`), and with a valid
    `api_host` a TCP connection to port 443. Read-only.
  - `integration_fetch {"id", "version"}` → starts `<integration_fetch_unit>@<id>-<version>.service`.
    Refused for a withdrawn build, and in FIPS mode for any build the catalog does not list as FIPS.
  - `integration_install {"id", "file", "sha256"?, "actor"?}`: `file` must match the provider's
    pattern; it is opened in `integration_dir` (which must belong to `integration_owner` and not be
    world-writable) with O_NOFOLLOW, must be a regular single-linked file of that user ≤
    `integration_max_mib`, and is copied into `<work_dir>/integration/<id>/` (root 0700) while
    hashing (SHA-256). A catalog entry with that hash → `verified: catalog` (size and version must
    match; withdrawn, a non-FIPS entry in FIPS mode, or `min_radius_admin` above the installed build
    → refused). Not in the catalog: refused in FIPS mode; otherwise refused with the file's SHA-256
    in the message unless `sha256` equals it → `verified: pasted-hash`. Writes `request.json` (id,
    version, file, sha256, size, verified, fips, catalog_serial), the state (`queued`, actor) and
    starts `<integration_install_unit>@<id>.service`; refused while that unit runs.
  - `integration_log {"id", "offset"?}`: as `update_log`, for the log the state names
    (`integration-<id>-<YYYYmmddTHHMMSSZ>.log` in `integration_log_dir`).
- **Download** (`radius_admin.integration_fetch`, unit `radius-admin-integration-fetch@.service`:
  radius-admin, the update check's sandbox, writes only `integration_dir`, `HTTPS_PROXY` from
  `update.env`). Instance `<provider>-<X.Y.Z>`; downloads `https://dl.duosecurity.com/duoauthproxy-
  <version>-src.tgz` only (a redirect off that host is refused) into `integration_dir`, checks size
  and SHA-256 when the shipped catalog lists the build, keeps one build per provider, and reports in
  `integration_dir/fetch-<provider>.json` (state downloading|done|failed, version, file, size,
  sha256, listed, message). App config: `integration_dir`, `integration_catalog`.
- **Install** (`deploy/integration-install.sh` → `/usr/local/libexec/radius-admin/radius-admin-
  integration-install`, unit `radius-admin-integration-install@.service`, root, 1 h timeout): checks
  the copy against `request.json` again (SHA-256, size, id), runs the release's root-owned
  `/opt/radius-admin/integrations/<id>/install.sh REQUEST BUILD` (refused when missing, a symlink or
  writable by others), records `installing` / `done` / `failed` with the log path in
  `integration-state.json`, and removes the copy.
- **Units.** The helper unit may read `/var/lib/radius-admin/integrations`.

### 29.2 Duo Authentication Proxy: installer, configuration, removal

Checked against Duo Authentication Proxy 6.8.1 (source read, built and run in the lab: the
FreeRADIUS → Duo → radius-admin-mfa-primary round trip with Class and Message-Authenticator works;
the second factor itself needs a Duo account and was replaced by `failmode=safe` with the Duo API
unreachable). The portal pages that drive this follow.

- **Installer** (`integrations/duo/install.sh REQUEST BUILD`, run by the install dispatcher):
  build packages `build-essential libffi-dev zlib1g-dev perl` (missing ones only, apt,
  `NEEDRESTART_SUSPEND=1`); extraction as the system user `radius-admin-build` (created when
  missing) with Python's tarfile `data` filter, and only when every member is under
  `duoauthproxy-<version>-src/`; plain `make` (Duo's Makefile is not safe for `-j`) as that user;
  then the tree becomes `root:root`, `go-w`, before Duo's installer runs as root:
  `duoauthproxy-build/install --install-dir /opt/duoauthproxy --service-user duo_authproxy_svc
  --log-group duo_authproxy_grp --create-init-script yes --enable-selinux no --silent` (it creates
  the user and group, writes and enables `/etc/systemd/system/duoauthproxy.service`, Type=forking,
  twistd started as root dropping to the service user; `conf/authproxy.cfg` owned by the service
  user, 0640). A running proxy is stopped first. Drop-in
  `duoauthproxy.service.d/radius-admin.conf`: `ProtectSystem=strict` with write access to
  `log`, `run`, `conf` and `-/etc/duoauthproxy` (Duo's secret storage), private /tmp and devices,
  protected kernel and cgroups, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`,
  no namespaces, no SUID/SGID, locked personality. `/opt/duoauthproxy/.radius-admin` (root 0644):
  version, sha256, verified, fips, installed. The proxy is (re)started only when `authproxy.cfg`
  starts with `; radius-admin` (an applied configuration), otherwise left stopped.
- **Removal** (`integrations/duo/remove.sh`, `radius-admin-integration-install --remove duo`,
  unit `radius-admin-integration-remove@.service`): only an install with `.radius-admin`; the
  configuration is copied to `/var/backups/radius-admin/duoauthproxy-authproxy.cfg-<time>` (0600),
  the service stopped, Duo's `uninstall --no-prompt` run, the drop-in removed.
- **Outcome audit.** The dispatcher records `integration.install` / `integration.remove` (result
  done, removed or failed; version; message; the actor from the state) with
  `python3 -m radius_admin.cli record-integration`.
- **Configuration** (`unlang.render_duo_config(settings, fips)`, deterministic):
  `[main] log_auth_events=true` (+ `fips_mode=true` in FIPS mode); `[radius_client] host=127.0.0.1,
  port=18121, secret=<password-check secret>, pass_through_attr_names=Class`; `[radius_server_auto]
  ikey, skey, api_host, radius_ip_1=127.0.0.1, radius_secret_1=<proxy secret>, interface=127.0.0.1,
  port=18120, client=radius_client, failmode (secure|safe; FIPS: secure), factors (auto, push, phone,
  passcode), pass_through_attr_names=Message-Authenticator, force_message_authenticator=true`.
  Duo's RADIUS client adds Message-Authenticator to its request only when the incoming request's is
  passed through, and its server adds one to replies only when forced: both are needed because the
  loopback client and the home server require it. Settings: ikey `DI` + 18 upper-case letters or
  digits, skey 40 letters or digits, `api-<1-16>.duosecurity.com`, secrets 16–128 letters or
  digits (the INI format has comment characters).
- **Helper.** Staged file `provider-duo` (optional; same rules as the other staged files).
  Grammar (`check_duo_config`): first line `; radius-admin`; sections `main`, `radius_client`,
  `radius_server_auto` once each; only the keys above, values as above (hosts and interface
  127.0.0.1, ports 1024–65535, `client=radius_client`); in FIPS mode `fips_mode=true` and
  `failmode=secure` are required. `validate` checks it (and that Duo is installed). `apply` with a
  staged Duo file backs up the live `authproxy.cfg` too (`duo_managed` in the backup), installs it
  keeping its owner, group and mode, restarts `duoauthproxy.service` and waits for 127.0.0.1:18120
  (`restart_wait`) before touching FreeRADIUS; a proxy that does not come up gets its previous file
  back and FreeRADIUS is left unchanged; a FreeRADIUS failure restores both. An unchanged Duo file
  does not restart the proxy. Responses and the state carry `duo_sha256`. `rollback` restores a
  backed-up Duo file that radius-admin wrote; Duo's own sample is not restored (the restored
  FreeRADIUS files do not use Duo). With a changed Duo file the worst case of apply is about 180 s;
  the portal waits longer for it (section 29.4).
- **Actions.** `integration_remove {"id", "actor"?}`: refused unless radius-admin installed it, while
  the live clients file still has the `radius-admin-mfa-primary` listener ("turn the provider off
  and apply first") or an install/removal runs; state `queued` with `action: remove`; starts
  `<integration_remove_unit>@<id>.service`. `integration_test {"id"}`: runs Duo's
  `usr/local/bin/authproxy_connectivity_tool` (root-owned, writable only by root) for at most
  120 s; `{passed, output}` with lines naming skey, secret or password redacted.

### 29.3 Duo in the portal

- **Provider row.** `ui.mfa_provider` id `duo`, type `duo`, created on the first save of the Duo
  settings (off) with two random 32-character secrets (`secret`: default server → Duo proxy;
  `primary_secret`: Duo proxy → radius-admin-mfa-primary). Settings: ikey, api_host, failmode,
  factors; secrets (encrypted): skey and the two shared secrets. It can be turned on only while the
  helper reports Duo installed, and turned off only when no enabled rule names it. It is not removed
  through the providers table.
- **Staging.** `services.render_provider_files()` → `{"provider-duo": render_duo_config(...)}`
  while the Duo provider is on (FIPS mode from `require_fips`). The apply page stages it next to
  policy and clients (`write_staging(..., providers=)` writes it, or removes it when Duo is off),
  shows its diff with `skey`, `secret` and `radius_secret_N` masked, includes
  `providers_sha256` (one SHA-256 over the provider files, '' without any) in the "expected" token
  and in `ui.apply_log.providers_sha256` (new column, sql/101-mfa.sql); `pending_state` compares it
  with the last apply (NULL counts as ''). The applied copy and its history keep the provider files;
  a rollback to a set without a Duo file leaves the applied Duo copy, like the helper.
- **Page** `/integrations/duo` (viewers: state; operators: test; admin + step-up: everything else):
  state (installed version, catalog-checked or Unverified, service running and listening, provider
  on/off, last install or removal), live progress and the install log (`/integrations/duo/status`,
  `/integrations/duo/log`, the updates page's indicators); 1. Check this server
  (`integration_preflight`, with the API hostname when set); 2. Get and install: the catalog's builds
  (FIPS mode: FIPS-capable only; withdrawn hidden) with Download (`integration_fetch`), without
  catalog entries a version field (standard mode only), the download's state from
  `fetch-duo.json`, Upload, and Install for each build in `integration_dir` (with, in standard mode
  only, a SHA-256 field and a required confirmation that it was compared with Duo's published value);
  3. Connect to Duo (ikey, skey write-only, API hostname, fail mode (standard mode only), factors,
  on/off); 4. Test (`integration_test`); Remove (refused while the provider is on).
- **Upload** `POST /integrations/duo/upload`: multipart field `build`; the file name (directory part
  dropped) must be `duoauthproxy-X.Y.Z-src.tgz`; at most 128 MiB, written to a temporary file in
  `integration_dir` and renamed (0640). The request size limit is 2 MiB everywhere else; this path
  allows 129 MiB (`app.request_class`), and nginx `client_max_body_size 130m` for exactly this
  location. The portal service may write `/var/lib/radius-admin/integrations`.
- **Audit:** `integration.fetch`, `integration.upload` (file, size, SHA-256),
  `integration.install_requested` (file, verified, SHA-256), `integration.configure` (changes;
  `duo_skey_updated`, never the key), `integration.test`, `integration.remove_requested`; the outcome
  of an install or removal is `integration.install` / `integration.remove` (section 29.2).

### 29.4 Second factor: alerts, reports, apply time, FIPS

- **Alerts** (`alerts.py`, monitor every 60 s; `sql/101-mfa.sql` adds the kinds to
  `alert_kind_check`, `ui.alert_settings.mfa_enabled`, `mfa_timeout_enabled`,
  `mfa_timeout_threshold` (1–100000, default 3), `mfa_timeout_window_minutes` (1–1440, default 15)
  and `ui.alert.reminded_at`):
  - `mfa_provider_down` (subject `duo`): the Duo provider is on, the last successful apply/rollback
    has a non-empty `providers_sha256`, and the helper's `integration_status` reports Duo not
    installed, not active or not listening on 127.0.0.1:18120, in two checks in a row. A helper
    error (or a helper without the action) neither opens nor resolves.
  - `mfa_timeouts`: rejects with reason exactly `radius-admin: the second-factor provider did not
    answer` (= `unlang._MFA_NO_ANSWER`) in the window ≥ threshold; resolves below threshold/2; its own
    switch.
  - `mfa_unverified` (subject `duo`): the provider is on and its build was installed with
    `verified = pasted-hash` while no catalog entry with that SHA-256 (not withdrawn) exists; in FIPS
    mode also when the build is not FIPS-capable (below), with a message starting "FIPS mode:".
  - `mfa_withdrawn` (subject `duo`): an installed build (on or off) matches a withdrawn catalog entry
    by SHA-256 or version.
  - The last two are sent again (`alerts.remind_alert`, prefix "Still open: ") 24 h after they were
    last sent, while open. `mfa_enabled` switches the three provider alerts. The monitor calls
    `integration_status` every round and `integration_catalog` at most once an hour, only while
    Duo is installed. `integrations.build_check(installed, entries)` → `verified`, `listed`,
    `withdrawn`, `fips_capable` is shared with the Duo page, which now shows a build the catalog
    lists later as checked and a withdrawn build in red.
- **Reports and logs.** Privileged-access report: the "Two-factor" column of device admin rows is
  "exempt (break-glass)", "not required", "<provider>, on all clients|selected clients: …" or
  "required …, but <provider> is off: these logins are rejected" (`integrations.coverage`,
  `coverage_text`), plus a section "Second factor for device admin logins" (accounts, required,
  provider, provider state, clients, exempt) and notes (no exempt local account; reject when the
  provider is off or silent). Auth log detail of `pap-admin+mfa` / `admin-ldap+mfa`: "Second factor"
  with the provider the rule for that account kind named at the login's time
  (`integrations.provider_at`: the current rule with every later successful `integration.policy`
  change of `provider_id` undone; "Provider not known" when it named none). radpostauth gets no
  provider column (rule 3). Setup checklist: optional step `mfa` "Second factor for device admins",
  done when a rule is on and its provider is on, linking to the Integrations page.
- **Device timeout.** Vendor profiles gain `setup.mfa_timeout` (section 26; Catalyst 1200/1300:
  `radius-server timeout 30` + `radius-server retransmit 2`; generic-rfc `null` → the generic text;
  custom profiles: form field `setup_mfa_timeout`). The Integrations page lists, per profile of the
  enabled clients the enabled rules cover (all enabled clients when a rule covers all, or no rule
  is on), the profile's commands or the generic text and the client count.
- **Apply time.** Worst case of apply/rollback with a changed Duo file: lock 10 + validate 30 + 4 ×
  (restart 20 + wait 15) = 180 s. The app waits `helper_duo_timeout` (default 210 s; never less than
  `helper_timeout`) for `apply` when the staged `provider-duo` differs from the applied copy, and for
  `rollback` when a Duo configuration was applied or a Duo provider exists; otherwise
  `helper_timeout` (120 s). gunicorn `--timeout 240`, nginx `proxy_read_timeout 240s`. The Apply
  button's busy text says it can take a few minutes when providers are pending. No helper protocol
  change.
- **FIPS.** In FIPS mode the helper's `validate`/`apply`/`rollback` with a staged Duo file also
  require (`check_duo_fips`) that `<duo_dir>/.radius-admin` says `fips: true` (installed in FIPS
  mode) and that the verified catalog has an entry with that SHA-256, `fips: true`, not withdrawn;
  otherwise "FIPS mode: the installed Duo Authentication Proxy X is not a FIPS-capable build …" or
  "… was installed before FIPS mode was turned on …", and nothing changes. The Duo page refuses
  "On" for such a build in FIPS mode and says why (standard mode: no wording). No catalog entry is
  FIPS-capable yet. `tools/integrations/duo-fips-check.py` (`source`, `host`, `installed`, `all`;
  `--running`, `--json`) is the maintainers' lab check before `catalog.py fips` (RUNBOOK §6.9b):
  R1 kernel FIPS, R2 system OpenSSL FIPS provider active, R3 Duo's `pkgs/fips_modules/<arch>/fips.so`
  HMAC-SHA256 (OpenSSL's public fipsinstall key) equals its `module-mac`, in the source and the
  installed tree, same file, R4 the installed provider loads with Duo's `openssl.cnf` (self-tests),
  R5 Duo's Python with FIPS enabled refuses MD5 and computes SHA-256, R6 applied `fips_mode=true`,
  `failmode=secure`, listening, log "FIPS mode is enabled"; M1 (CMVP certificate of the provider
  version) and M2 (prebuilt provider, `cryptography` wheel with its own OpenSSL) are decided by the
  maintainer. Exit 0 only when every required check that ran passed.
