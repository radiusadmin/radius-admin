# radius-admin — Security notes

Scope: the radius-admin web UI, its root helper, the local PostgreSQL database and
the FreeRADIUS configuration changes delivered with it, on `radius01`. This
document describes what the system does; it is input to the SSP, not a substitute for
it. Statements of the form "supports control X" mean the feature *contributes* to the
control — organisational procedures are still required.

## 1. FIPS 140 cryptographic boundary

The host runs Ubuntu 24.04 with kernel FIPS mode on and the Ubuntu Pro FIPS packages.
The cryptographic modules in play are the **Ubuntu 24.04 OpenSSL 3 FIPS provider**
(libssl / libcrypto, "OpenSSL 3.0.13" line) and the **Ubuntu 24.04 kernel crypto API**.
They count as *FIPS 140-validated* only when the exact certified package versions of the
`fips` stream are installed; on `fips-updates` they are the same FIPS provider code with
later security fixes, not the certified binaries (F-1). Throughout this document, "OpenSSL
FIPS provider" means: approved algorithms enforced by the FIPS provider; validated only
when running the `fips` stream's certified packages — see F-1. Check the CMVP certificate
numbers that match your installed package versions in the Ubuntu FIPS documentation and
record them in the SSP.

> **Finding F-1: `fips-updates` vs `fips`.** If the server is on the `fips-updates`
> stream: those packages contain security fixes applied *after* the CMVP validation,
> so the installed module versions are not the exact validated binaries. Many
> organisations accept this (security fixes over certificate equality) but it must be
> a documented decision. For strict "FIPS 140-validated" claims (e.g. DFARS/CMMC
> assessors who check versions), switch to the `fips` stream
> (`pro disable fips-updates && pro enable fips` — needs a reboot) and accept slower
> security fixes. preflight.sh reports the stream.

| Function | Component | Implementation | Module |
|---|---|---|---|
| HTTPS to admins (TLS 1.2/1.3, ECDHE + AES-GCM, P-384/P-256) | nginx | libssl | OpenSSL FIPS provider |
| Client-certificate verification + OCSP | nginx | libssl | OpenSSL FIPS provider |
| UI password hashing (PBKDF2-HMAC-SHA256, 600 000 it., 16-byte salt) | app | `hashlib.pbkdf2_hmac` → libcrypto | OpenSSL FIPS provider |
| Switch-admin password hashes (`{X-PBKDF2}HMACSHA2+256`) — created | app | `hashlib.pbkdf2_hmac` | OpenSSL FIPS provider |
| — verified | FreeRADIUS rlm_pap | `PKCS5_PBKDF2_HMAC` | OpenSSL FIPS provider |
| Session tokens, CSRF tokens, salts, TOTP secrets, generated RADIUS secrets | app | `ssl.RAND_bytes` (DRBG) | OpenSSL FIPS provider |
| Data key (`data.key`, 256-bit) | install.sh | `openssl rand 32` | OpenSSL FIPS provider |
| TOTP secret encryption at rest (AES-256-GCM, 96-bit nonce) | app | `python3-cryptography` (apt, links system libcrypto) | OpenSSL FIPS provider |
| TOTP (RFC 6238, HMAC-SHA1) | app | `hmac` → libcrypto | OpenSSL FIPS provider (HMAC-SHA1 is approved) |
| Session token storage (SHA-256), audit hash chain (SHA-256) | app | `hashlib` | OpenSSL FIPS provider |
| EAP-TLS (TLS 1.2, FIPS cipher list) | FreeRADIUS rlm_eap_tls | libssl | OpenSSL FIPS provider |
| LDAPS to AD | FreeRADIUS rlm_ldap → libldap | **GnuTLS** — Ubuntu's libldap is built against GnuTLS, so this connection does **not** use the OpenSSL FIPS provider | **Outside the OpenSSL boundary — see exception 5.** Verify whether the GnuTLS in use is a FIPS-validated module in your Ubuntu Pro FIPS stream |
| Package signatures | apt | gpgv | not a FIPS function (integrity of software supply, outside the boundary) |

The app refuses to start (and the CLI refuses to run) when `require_fips = true` unless
`/proc/sys/crypto/fips_enabled == 1` and `_hashlib.get_fips_mode() == 1`. The dashboard
and the helper's `status` show FIPS state. No pip packages and no non-OpenSSL crypto
libraries are used (`random`, `secrets`, `os.urandom`, `uuid4` are not used for
security values). The root helper does no cryptography except SHA-256 file
fingerprints (`hashlib`).

### 1.1 Documented exceptions (for the SSP)

1. **RADIUS protocol (RFC 2865) uses MD5** for the Response Authenticator, User-Password
   hiding and (HMAC-MD5) Message-Authenticator. MD5 is not FIPS-approved. The custom
   build's `--enable-fips-workaround` makes FreeRADIUS use its *internal* MD5/MD4
   implementation instead of OpenSSL so it runs on a FIPS kernel/OpenSSL. This is **not
   FIPS-validated cryptography** and must not be relied on for confidentiality. The
   compensating controls are: RADIUS traffic is confined to the management VLAN
   (192.0.2.0/24) and the AP subnet; per-client unique 32-character random shared
   secrets; Message-Authenticator enforced per client as soon as each switch supports
   it (§4, F-9). RADIUS/TLS (RadSec) would remove the exception but is not assumed to
   be supported by the Catalyst 1300.
2. **Switch-admin logins use PAP inside RADIUS**: the password crosses the network
   protected only by the MD5-based User-Password hiding (exception 1). Stored hashes are
   PBKDF2 (approved). Compensating: management VLAN only, source-address check in the
   policy (`Packet-Src-IP-Address` in the admin subnet), SSH (FIPS) from admin to switch.
3. **MAB is identification, not authentication.** A MAC address is trivially spoofed.
   MAB devices are restricted to a pre-registered list, the `Calling-Station-Id` must
   match, and each device is placed in a dedicated VLAN; they should get only the access
   they need (printers/IoT VLAN with ACLs). The User-Password in MAB requests is the MAC
   and is not a secret.
4. **TOTP uses HMAC-SHA1** — HMAC-SHA1 remains approved (SP 800-131A Rev. 2) and is
   computed by the FIPS provider; SHA-1 is not used for anything else.
5. **LDAPS to Active Directory does not go through the OpenSSL FIPS provider.** Ubuntu's
   `libldap` links GnuTLS, so rlm_ldap's TLS session to `dc01` uses GnuTLS.
   Consequences found in testing (sandbox, FreeRADIUS 3.2):
   * `cipher_list` is therefore **left unset** in `mods-available/ldap` (commented out):
     an OpenSSL-syntax list is not meaningful to GnuTLS (in testing rlm_ldap still
     connected with garbage values and to a server offering only AES128-SHA with RSA key
     exchange; stand-alone `ldapsearch` rejects it with `TLS: could not set cipher list`).
     The LDAPS cipher suites are therefore GnuTLS defaults, negotiated with whatever the
     DC offers — see mitigations (a) and (b).
   * `tls_min_version = "1.2"` is set; its enforcement through GnuTLS was **not verified**.
   * radiusd warns that mixing GnuTLS (libldap) and OpenSSL in one process may cause
     crashes.
   Mitigations (recommended a + b):
   (a) restrict the domain controller(s) to TLS 1.2+ with ECDHE + AES-GCM suites only
   (Schannel protocol/cipher-suite policy via GPO) — this constrains the session
   regardless of the client library;
   (b) verify whether the GnuTLS in use is a FIPS-validated module in your Ubuntu Pro
   FIPS stream, and record the result in the SSP (do not assume it);
   (c) optional, test first in a lab: set a GnuTLS priority string as `cipher_list`,
   e.g. `NONE:+VERS-TLS1.3:+VERS-TLS1.2:+AES-256-GCM:+AES-128-GCM:+ECDHE-ECDSA:+ECDHE-RSA:+AEAD:+SIGN-ALL:-SIGN-RSA-SHA1:-SIGN-ECDSA-SHA1:+GROUP-SECP384R1:+GROUP-SECP256R1:+COMP-NULL`,
   and confirm with a packet capture that the DC session uses it;
   (d) for a clean OpenSSL boundary, rebuild OpenLDAP's libldap against OpenSSL
   (`--with-tls=openssl`) and link FreeRADIUS against it (custom package — maintenance
   cost). `preflight.sh` reports which TLS library rlm_ldap/libldap link.
6. **EAP-TLS stays TLS 1.2 max** (unchanged from current production; TLS 1.3 for EAP
   has known supplicant interop issues). Cipher list restricted to the FIPS list below.
7. **CoA / Disconnect requests (RFC 5176) use the same RADIUS MD5** as exception 1. They are
   built and signed by `radclient` from the same `--enable-fips-workaround` FreeRADIUS build
   (no new MD5 implementation in radius-admin), carry Message-Authenticator and
   Event-Timestamp, and go only to switches in the management subnet. The shared secret is
   passed in a private 0600 file, never on a command line.

### 1.2 TLS parameters

TLS 1.2 ciphers (nginx, EAP; not LDAP — see exception 5):
`ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256`;
TLS 1.3 (nginx): `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`; groups
`secp384r1:prime256v1`; session tickets off; HSTS. UI server key: ECDSA P-384 (or
RSA-3072) generated on the host by `make-csr.sh`, 0600, never exported.
Verified in the sandbox: TLS 1.1 refused; ChaCha20 refused; negotiated
`ECDHE-ECDSA-AES256-GCM-SHA384` over secp384r1 on TLS 1.2, `TLS_AES_256_GCM_SHA384` on 1.3.

## 2. Security architecture (summary)

* **Network**: nginx binds only to the management address on 443 (no port 80); `allow
  192.0.2.0/24; deny all;` in nginx *and* an nftables table that drops 443 from
  anywhere else (independent of ufw). PostgreSQL has no TCP listener. gunicorn listens
  on a unix socket only reachable by group `radius-admin-web` (www-data).
* **Privilege separation**: app (`radius-admin`, no capabilities, `ProtectSystem=strict`,
  `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, `MemoryDenyWriteExecute`,
  seccomp `@system-service`, cannot read `/etc/freeradius` or the helper's work dir)
  ↔ root helper (socket-activated per request; accepts only `status|validate|apply|rollback`
  and a regex-checked backup id; settings only from root-owned `helper.conf`; peer UID
  checked with SO_PEERCRED; staged files opened with `O_NOFOLLOW`, must be regular,
  single-link, owned by `radius-admin`, ≤ 1 MiB UTF-8; clients file must match a strict
  whitelist grammar; policy file must not contain `$INCLUDE`, `$ENV`, `$TEMPLATE`,
  `%{exec:`, `Exec-Program`, backticks, interpreter xlats or numeric attribute aliases
  (`Attr-<n>`, `Vendor-*-Attr-<n>`) — a blocklist, i.e. defence in depth, not a sandbox
  for admin-authored unlang (see below); validation with
  `radiusd -XC` as `freerad` on a private copy; atomic install; automatic rollback).
  The helper never executes anything derived from request or file content; all program
  paths come from `helper.conf`, subprocesses get a fixed environment and timeouts.
* **Database**: peer authentication only, per-component roles with least privilege
  (FreeRADIUS cannot read `ui.*`; the app cannot UPDATE/DELETE the audit log; a trigger
  blocks UPDATE/DELETE/TRUNCATE on `ui.audit_log`).
* **The UI `admin` role is effectively `freerad`-equivalent.** An admin can author the
  custom unlang policy, which runs inside FreeRADIUS on every request. The forbidden-token
  checks (app and helper) block file inclusion, environment expansion, program execution
  (`%{exec:}`, `Exec-Program`, backticks, interpreter xlats) and numeric attribute aliases
  (`Attr-<n>`, `Vendor-*-Attr-<n>`, which could otherwise name Exec-Program as `Attr-502`).
  Even so, custom unlang can still run `%{sql:…}` with the `radius_fr` role's rights,
  query LDAP, and **change any authentication or authorization decision** (accept,
  reject, VLAN). That is why custom policy is admin-only, requires step-up
  re-authentication, is shown as a diff, validated, applied with a backup and fully
  audited. Keep the number of admin accounts minimal and review custom-policy changes.
* **`exec` module removed.** `rlm_exec` is disabled (in `modules-to-disable.txt`) and no
  longer called from post-auth or accounting, so `Exec-Program` / `Exec-Program-Wait`
  attributes have no effect even if they appear in a reply.
* **Apply history and audit chain.** `ui.apply_log` is append-only for the app role
  (SELECT, INSERT only), so the apply history and the "pending changes" state cannot be
  rewritten by the application. `ui.audit_log` is append-only (grants + trigger) and
  hash-chained, but the chain is **unkeyed**: it detects modification or deletion of
  existing rows, not wholesale forgery — a DB superuser (or a compromised app appending
  well-formed rows) can produce a consistent chain. Ship the `radius-admin` and
  `radius-admin-helper` syslog streams to the SIEM as the independent record (§5).
* **Residual risk — helper as root**: the helper runs as root with a reduced
  capability bounding set and `ProtectSystem=strict` (writable: `/etc/freeradius`,
  its work dir). It cannot drop to an unprivileged user entirely because it must
  restart FreeRADIUS and install files owned by root.

### 2.x Live access rules and settings (database on the authentication path)

Access rules and the switch-admin settings are evaluated by PostgreSQL on every
request (`sql/40-live-policy.sql`), so UI edits apply to the next authentication
without a FreeRADIUS restart. Security properties:

* **Injection-proof argument passing.** FreeRADIUS 3.2 un-escapes backslash sequences in
  the assembled argument of `%{sql:...}` *after* rlm_sql has escaped the values, so
  `auto_escape` alone does not make string interpolation safe. Every request- or
  directory-derived value (Called-Station-Id, the computer's AD group names, the packet
  source address) is therefore passed **only as hex** (`[0-9a-f]`) and decoded inside
  PostgreSQL; malformed input yields NULL/false = reject. Covered by bench tests with
  `\047`, `\x27`, `\\`, quotes, newlines, NUL and xlat payloads in request attributes
  and in AD group names.
* **Least privilege.** The functions are `SECURITY DEFINER` with a pinned `search_path`
  and no dynamic SQL. `radius_fr` can execute only `radius_admin_vlan_hex`,
  `radius_admin_admin_source_ok_hex` and `radius_admin_priv15`, and still has no
  rights on schema `ui`. The web app gets the text-argument matcher for its
  parameterized "Test a match" tool; both use the same core matcher.
* **Fail closed.** If PostgreSQL is unavailable, EAP-TLS, switch-admin and MAB requests
  are rejected; service recovers by itself once the database returns (sql pool
  `retry_delay`, 30 s). PostgreSQL is now a hard dependency of every 802.1X login.
* **Behaviour change.** AD group names now match case-insensitively (the original
  `LDAP-Group ==` compare was case-sensitive). Group membership is read once per login
  (`cacheable_name = yes`, nested groups via the AD in-chain filter — verify against the
  real domain once, RUNBOOK §9.1).

### 2.y Read-only SNMPv3 switch monitoring

* **Separate, network-restricted service.** Only `radius-admin-snmp.service` may send
  network traffic, and systemd limits it to the management subnet (`IPAddressAllow`);
  the web app and the root helper still have no network access.
* **Read-only by design.** The switch-side user should have a read-only view limited to
  the four subtrees in RUNBOOK §6.3. Nothing is ever written to a switch; no running
  configuration is fetched.
* **Crypto.** SNMPv3 authPriv with HMAC-SHA-256 (or SHA-384/512) and AES-128 through
  Net-SNMP, which uses the system OpenSSL (FIPS provider). **SSP note:** SNMPv3's
  password-to-key localisation (RFC 3414/7860) is its own SHA-based scheme, not a NIST
  approved KDF — record it as an exception next to the RADIUS MD5 one, as with other
  FIPS-mode SNMP implementations.
* **Credentials.** Passphrases are write-only in the UI (admin + step-up), stored
  AES-256-GCM encrypted with the app data key, never logged or audited in clear, and
  handed to Net-SNMP in a private 0600 file that is wiped after each run (never on a
  command line or in the environment). Compromise of the server exposes read-only SNMP
  access to the switches, not management access.

### 2.z Monitoring, session actions, MAB queue and reports (2026-10-29)

* **Network.** CoA to switches (UDP 1700) and SNMP are sent only by `radius-admin-snmp`,
  still limited by `IPAddressAllow` to the management subnet. Email alerts to a relay outside
  it need an explicit drop-in (RUNBOOK §6.5). The web app gained no network access.
* **Session actions** are operator/admin only, queued in the database, executed by the
  monitor, and audited twice (request with the user who asked, result with the switch's
  answer). Attribute values come from accounting records and are checked against strict
  patterns (session id, MAC, port) before use; a request for an ended session is refused.
* **Unknown-device queue.** FreeRADIUS writes it only through `radius_admin_mab_hex()`
  (SECURITY DEFINER; radius_fr has no table rights), arguments hex-encoded or regex-built,
  bounded to 2000 rows so random-MAC floods cannot exhaust the database. Approval is an
  operator action and is audited with the attempt count, switch and port. MAB remains
  identification, not authentication (exception 3): approve only devices you can account
  for, prefer an expiry for temporary devices.
* **Authentication detail** stores certificate subject/issuer/serial/expiry, the reject
  reason and the AD group names seen. No passwords or keys are stored; the AD group names
  are directory data visible to viewers (as the auth log already was).
* **Alerts.** Syslog lines carry no secrets. The SMTP password is write-only in the UI,
  AES-256-GCM encrypted at rest, sent only over STARTTLS/TLS (TLS 1.2+, certificate
  verified); a login over plain SMTP is refused.
* **Reports** never include shared secrets or password hashes; CSV cells that a spreadsheet
  would evaluate are prefixed with `'` (formula injection); each view or download is in the
  audit log; the privileged-access report is admin-only.

## 3. NIST SP 800-171 Rev. 2 — how the UI supports the requirements

"Supports" = technical mechanism provided; the organisation still owns policy,
procedures, reviews, and evidence. Requirements not listed are out of scope for this
component or fully organisational.

| Req. | Requirement (short) | How radius-admin supports it | Not covered / org. responsibility |
|---|---|---|---|
| 3.1.1 | Limit system access to authorized users | Individual named accounts only, created by an admin; disable/enable; no self-registration; DB roles via peer auth only; RADIUS clients explicitly listed | Account approval process, periodic account review |
| 3.1.2 | Limit to permitted transactions/functions | RBAC viewer/operator/admin enforced server-side on every route; operators cannot change custom policy, settings, UI admins or reveal secrets | Role assignment policy |
| 3.1.5 | Least privilege | Three roles; app runs unprivileged, root work isolated in a 4-action helper; DB roles least-privilege; FreeRADIUS role cannot read UI tables | Keeping admin count minimal |
| 3.1.7 | Prevent non-privileged users from executing privileged functions; audit them | Privileged functions require admin role + step-up re-auth; all of them audited (actor, IP, object, result) | — |
| 3.1.8 | Limit unsuccessful logon attempts | Lockout after 5 failures (password or MFA) for 15 min; per-IP limit (20/15 min); nginx rate-limits `/login` | Thresholds per org policy |
| 3.1.9 | Privacy and security notices | Configurable consent banner, must be acknowledged before login (`banner_text`) | Banner wording approved by legal/security |
| 3.1.10 | Session lock after inactivity | Server-side idle timeout 15 min (session invalid, re-login required) | Workstation screen lock (endpoint control) |
| 3.1.11 | Terminate session after defined condition | Absolute session lifetime 8 h; logout; admins can revoke own sessions; sessions invalidated on password change/disable | — |
| 3.1.12 | Monitor and control remote access | UI reachable only from management VLAN; all access logged (nginx + audit log) | VPN/jump-host policy for remote admins |
| 3.1.13 | Cryptographic protection of remote access sessions | TLS 1.2/1.3 with FIPS-approved suites via the OpenSSL FIPS provider (validated only on the `fips` stream's certified packages — see F-1) | — |
| 3.3.1 | Create and retain audit logs | Hash-chained `ui.audit_log` in PostgreSQL; syslog (authpriv) for app and helper; helper/state log; nginx logs; `radpostauth` for RADIUS auths; `radacct` sessions; exportable audit reports (CSV / PDF), each export itself audited | Retention period, central log server (rsyslog forwarding snippet provided, disabled by default) |
| 3.3.2 | Actions traceable to individual users | Every audit record has the named actor, source IP, action, object and result; helper logs peer and action | — |
| 3.3.8 | Protect audit information | Audit table and `ui.apply_log` append-only for the app role (no UPDATE/DELETE grants; trigger on audit_log); SHA-256 hash chain verifiable in UI/CLI (detects edits/deletions of existing rows); log files root:adm 0640 | Chain is unkeyed: a DB superuser can rewrite it consistently — forward syslog to the SIEM as the independent record |
| 3.4.2 / 3.4.6 | Security configuration / least functionality | Unused EAP methods and FreeRADIUS modules removed, inner-tunnel removed, PostgreSQL local only, nginx port 80 disabled, systemd sandboxing | Baseline documentation (CM plan) |
| 3.4.3 | Track, review, approve, log changes | Pending-change diff, validate, apply with backup id and hashes in `ui.apply_log` + audit log; rollback | Change approval (CAB) is organisational; the UI does not enforce two-person approval |
| 3.5.1 / 3.5.2 | Identify and authenticate users | Unique usernames; password + MFA for every login | — |
| 3.5.3 | MFA for privileged and network access | All UI accounts require a second factor (TOTP or site client certificate checked against OCSP); enrolment forced at first login | Switch-admin logins to the network devices are **password-only** via RADIUS (see §1.1 exc. 2) — 3.5.3 for device administration must be covered otherwise (e.g. jump host with MFA) |
| 3.5.4 | Replay-resistant authentication | TLS for the UI; TOTP step replay protection (`totp_last_step`); EAP-TLS for 802.1X | RADIUS PAP admin logins are not replay-resistant beyond the RADIUS authenticator |
| 3.5.7 | Password complexity / change of characters | Minimum length 15 (configurable, cannot go below 15); length-based policy per SP 800-63B | Org policy may require more; no composition rules by design |
| 3.5.8 | Prohibit password reuse | Last 5 passwords (PBKDF2 hashes) rejected | Generations number per policy |
| 3.5.9 | Temporary passwords with immediate change | Admin-created and reset passwords are random one-time temporary passwords; change forced at next login | — |
| 3.5.10 | Store and transmit only cryptographically protected passwords | UI and switch-admin passwords stored as PBKDF2-HMAC-SHA256 (600 000 it.); never logged; `radpostauth` no longer has a password column; transmitted only over TLS (UI) | Legacy `Crypt-Password` rows remain until reset (flagged in UI); RADIUS PAP transmission is exception 2 |
| 3.5.11 | Obscure feedback of authentication information | Password fields masked; generic login errors; secrets masked unless revealed by admin with step-up (audited) | — |
| 3.13.1 | Monitor/control communications at boundaries | nginx ACL + host firewall restrict the UI to the management network | Network firewalls/VLAN ACLs |
| 3.13.8 | Cryptographic protection of CUI in transit | TLS (UI), LDAPS (AD), EAP-TLS | RADIUS/UDP itself (exception 1); LDAPS cipher policy not enforced client-side (exception 5) |
| 3.13.10 | Establish and manage cryptographic keys | UI TLS key generated on host (make-csr.sh), cert from internal PKI; data key 0400 radius-admin; RADIUS secrets generated from DRBG | Key/cert lifecycle, backup of data.key, secret rotation schedule |
| 3.13.11 | FIPS-validated cryptography for CUI | All app/nginx/EAP crypto via the OpenSSL FIPS provider (validated only on the `fips` stream's certified packages — see F-1); app refuses non-FIPS start | Exceptions §1.1 (RADIUS MD5; LDAPS via GnuTLS); F-1 stream choice |
| 3.13.15 | Protect authenticity of communications sessions | TLS; server-side sessions with 256-bit random tokens, rotated at login and MFA, `__Host-` Secure HttpOnly SameSite=Strict cookie; CSRF token + Origin/Referer checks; HSTS, CSP, frame-ancestors none | — |
| 3.14.6 / 3.14.7 | Monitor systems / identify unauthorized use | Auth log (radpostauth) with reject reasons and per-record detail, live sessions (accounting), unknown-device queue, alerts (reject spikes, unresponsive switches, FreeRADIUS down) to syslog/email, audit log, failed-login records | Forward alerts to the SIEM and define response procedures |

## 4. Hardening checklist when taking over an existing FreeRADIUS server

Generic issues commonly found on hand-maintained FreeRADIUS servers, and what this
package does about each. Check every one on the server you migrate.

| # | Issue | Severity | Action |
|---|---|---|---|
| F-1 | Ubuntu Pro **`fips-updates`** stream instead of `fips` (see §1) | Medium (compliance) | Decide and document; switch to `fips` if validated-version equality is required |
| F-2 | Ordinary endpoints placed on the management VLAN by an access rule | High | Keep the management VLAN for infrastructure only; tighten `admin_subnet` / the nginx ACL to admin hosts |
| F-3 | Test accounts with `Cleartext-Password` in `mods-config/files/authorize` | High | Removed by the new `authorize` file |
| F-4 | FreeRADIUS bootstrap test CA and test certificates with private keys left in `certs/`; `ca_path = ${cadir}` makes EAP trust that test CA | High | `ca_path` removed and `reject_unknown_intermediate_ca = yes`; delete/shred the test material after cut-over (RUNBOOK §12) |
| F-5 | `radpostauth.pass` contains switch-admin passwords in cleartext (the stock post-auth query logs User-Password) | High | Not migrated; the new query never stores passwords; shred the old database; rotate every switch-admin password |
| F-6 | Unused EAP methods and modules enabled; inner-tunnel enabled | Medium | Removed (EAP-TLS only); less attack surface and fewer non-FIPS code paths (MD4/DES in MS-CHAP) |
| F-7 | TLS cipher lists `DEFAULT` for LDAP/EAP | Medium | EAP: FIPS list (OpenSSL). LDAP: `tls_min_version = 1.2`; `cipher_list` left unset because libldap uses GnuTLS (§1.1 exception 5) |
| F-8 | Verbose `ldap_debug` | Low | Set to `0x0000` |
| F-9 | **Message-Authenticator** not required for switches (BlastRADIUS, CVE-2024-3596) | High | Migrated as `auto`; per switch, after confirming it sends Message-Authenticator, set `yes` in the UI (RUNBOOK §5); set `limit_proxy_state = yes` |
| F-10 | Shared secrets generated by a script, stored in cleartext files, unknown age | Medium | Rotate to UI-generated 32-character random secrets, one switch at a time; protect database backups |
| F-11 | RadSec would remove the MD5 exception, but switch support is not assumed | Info | Re-evaluate per vendor; until then keep RADIUS on management networks |
| F-12 | Switch-admin logins are single-factor PAP | Medium | Consider an MFA-protected jump host for device administration (800-171 3.5.3); keep the source-subnet restriction |
| F-13 | Single RADIUS server, no redundancy | Medium (availability) | Keep local emergency accounts on switches; consider a second server |
| F-14 | All switch admins get priv 15 | Info | Consider read-only roles (priv-lvl per group) |
| F-15 | `data.key` loss makes all TOTP enrolments unusable; compromise exposes TOTP secrets | Medium | Back it up encrypted offline; restrict root access |

## 5. Logging

Syslog identifiers: `radius-admin` (web app and CLI) and `radius-admin-helper`
(root helper), both facility **authpriv**. rsyslog snippet
(`/etc/rsyslog.d/30-radius-admin.conf`) writes them to `/var/log/radius-admin/audit.log`
and contains a disabled forwarding block for the SIEM. Passwords, TOTP codes, session
tokens and RADIUS secrets are never logged; the helper redacts `secret = …` and
`password = …` lines from radiusd output it returns.

## Universal edition additions (SPEC section 14)

**Portal single sign-on (SAML).**
- Service provider only: the portal holds no SAML private key. It accepts only responses with a
  signed assertion or signed response (RSA/ECDSA with SHA-2; any SHA-1 signature or digest is
  refused before parsing), checks audience, destination, validity window (±2 min) and
  InResponseTo (pysaml2 with `xmlsec1`), and refuses DOCTYPE/entity declarations.
- Login CSRF and replay: every AuthnRequest id is stored with the SHA-256 of a one-time nonce
  kept in a `SameSite=None` cookie; the response must come back in the same browser within
  10 minutes, once. Assertion ids are kept in `ui.saml_replay` until they expire.
- `/saml/acs` is the only POST endpoint without the CSRF token check (the IdP's POST is
  cross-site by design); the checks above replace it.
- Authorization comes from group claims mapped in the portal; no mapping, a disabled account or an
  Entra group-overage claim means no access. Roles are recomputed at every sign-in; removing a
  group takes effect at the next sign-in (sessions stay capped by the idle and absolute limits).
  The portal never calls Microsoft Graph (no outbound traffic besides updates).
- SSO accounts have no usable password. MFA is the identity provider's (Conditional Access);
  step-up re-authenticates at the IdP with `ForceAuthn`. With "local passwords for administrators
  only", local non-admin accounts cannot sign in while SSO is on (break-glass admins stay).
- Logout ends the portal session only (no single logout to the IdP).

**RadSec.** TLS 1.2/1.3 with the FIPS cipher list; client certificates must chain to the site CA
(the 802.1X CA) and pass OCSP when enabled (`softfail = no`); a per-client expected certificate
name narrows that further. Connections from addresses that are not RadSec clients are dropped by
FreeRADIUS before any request is read. The connection certificate is only visible through
`%{listen:…}`, so it cannot be mistaken for the EAP-TLS certificate of a device behind an access
point. The RadSec listener reuses the EAP-TLS server certificate and key: the web app never
handles a private key.

**Root helper grammar.** The clients file may now contain one RadSec `listen` section and one
`clients radius_admin_radsec` section; every key and value is pinned (type, protocol, virtual
server, TLS versions, certificate paths limited to `<raddb>/certs/site/{radius.key,radius.pem,ca.pem}`,
secret exactly "radsec"). Anything else is refused before `radiusd -XC`.

**Other fixes.** Database sessions run in UTC (timestamps labelled UTC were in the host's zone);
a request no longer holds a lock on its own session row (removed a deadlock between two admins
changing each other's accounts). The colour-theme cookie is a display hint only.
