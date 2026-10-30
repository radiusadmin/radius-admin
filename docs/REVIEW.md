# Independent security review: radius-admin

Reviewer: an independent agent that did not write this code. Date: 2026-10-23.

**Scope:** app/, helper/, deploy/, sql/, freeradius/ and docs/, checked against SPEC.md and the original FreeRADIUS configuration.

**How it was checked:**
- Read all of the code.
- Ran the app tests: 170 passed, 1 failed (environment issue, see I-5).
- Ran the helper tests: 64 passed, 1 skipped.
- Read the existing FreeRADIUS bench log: 61/61 PASS.
- Ran `radiusd -XC` (sandbox 3.2.11 build) on a copy of the bench raddb with a crafted custom policy.
- Inspected the sandbox PostgreSQL grants.
- Checked the shell behaviour of install.sh.

## High

### H-1 The custom-policy blocklist can be bypassed with a numeric attribute alias
**Where:** `app/radius_admin/unlang.py:205-216` (`_CUSTOM_FORBIDDEN`) and `helper/radius-admin-helper:209-218` (`POLICY_FORBIDDEN`).

**Problem:** Both checks match the attribute *name* `Exec-Program`. FreeRADIUS also accepts the numeric form `Attr-502`, and `Attr-503` for Exec-Program-Wait. The parser maps these to the same dictionary attribute (`src/main/tmpl.c:652-664`).

**Verified:** A custom policy containing `update reply { &Attr-502 := "..." }` gets through all three checks:
- `validate_custom_policy` accepts it.
- The helper regex accepts it.
- `radiusd -XC` reports "Configuration appears to be OK".

**Impact:** `exec` is still listed in `post-auth` (`freeradius/sites-available/default:979`) and in `accounting` (`:828`). Once applied, rlm_exec runs the program named in reply:Exec-Program as `freerad`. That account can read the EAP private key, every RADIUS shared secret and the LDAP bind password.

This needs an admin account plus step-up, but it defeats a control that SPEC §5/§6 requires. It also contradicts SECURITY.md §2, which presents the forbidden list as a real boundary.

**Fix:**
1. In both checkers, reject `Attr-\d`, `Vendor-\d+-Attr-` and `-Attr-\d` forms. Better: reject any attribute reference not in a small allow-list.
2. Remove `exec` from `post-auth` and `accounting`, and add `exec` to `modules-to-disable.txt`. Nothing in the policy needs it.
3. Add regression tests for `Attr-502` and `Attr-503`.
4. In SECURITY.md, state plainly that an admin with custom-policy access has `freerad`-equivalent power.

## Medium
None found.

## Low

### L-1 The installer exits with code 1 on hosts running ufw
**Where:** `deploy/install.sh:633`.

**Problem:** The last command of the `ufw)` branch is `ufw status | grep ... && warn ...`. When port 80 is not allowed (the normal case), that command returns 1. The function therefore returns 1, and `set -e` stops the script. I reproduced this pattern in bash.

**Effect:** The firewall rules are already loaded, but the `bootstrap` phase never runs and the operator sees a failure.

**Fix:** Write it as `if ufw status | grep -qE ...; then warn ...; fi`, or add `return 0`.

### L-2 EAP does not pin the elliptic curves
**Where:** `freeradius/mods-available/eap` sets `ecdh_curve = ""`, unchanged from the original.

**Problem:** SPEC §7 requires the curves `secp384r1:prime256v1`. The empty value leaves the choice to OpenSSL defaults. The FIPS provider limits this in practice, but it is not explicit.

**Fix:** Set `ecdh_curve = "secp384r1:prime256v1"`.

### L-3 The last-admin check can race
**Where:** `views/admins.py:160-165`.

**Problem:** `enabled_admin_count()` is read without a lock. Two admins demoting or disabling each other at the same moment can leave no enabled admin.

**Fix:** Run `SELECT ... FOR UPDATE` on the admin rows, or take an advisory lock, before the check.

### L-4 The app role can change apply history
**Where:** `sql/30-grants.sql:45-48`.

**Problem:** `radius_admin` has UPDATE/DELETE on `ui.apply_log`, so apply history (and with it the "pending" state) can be rewritten. The audit log is append-only, but its hash chain carries no key. A compromised app can therefore still append well-formed forged entries.

**Fix:**
- Limit `ui.apply_log` to SELECT and INSERT.
- Document that the audit chain detects edits and deletions, not forged appends.
- Optionally, forward syslog to a remote collector.

### L-5 A large CSV field causes a 500 error
**Where:** `views/mab.py:111-140`.

**Problem:** A single field over 128 KiB raises `_csv.Error`, which is not caught.

**Fix:** Catch `csv.Error` and report it as a form error.

### L-6 Operators can learn any client's secret
**Where:** `views/clients.py:66-74, 134-136`.

**Problem:** An operator can rotate a client's secret to a value they choose, or a generated one they are then shown, and then apply it. That is effectively access to the secret, even though revealing a secret requires admin plus step-up. It is consistent with SPEC's operator role, but it should be a documented decision.

**Fix:** Either require step-up for secret changes, or record this in SECURITY.md.

## Info

- **I-1:** `safe_next` allows `/%2f/evil.com`. Browsers do not decode `%2f` in a Location path, so this is not exploitable. Rejecting `%2f` and `%5c` would be stricter.
- **I-2:** The app trusts `X-Real-IP` and `X-Client-*` headers. This is safe only because the gunicorn socket is `0770 radius-admin:radius-admin-web`, nginx overwrites those headers, and `Host` is pinned (return 421 otherwise). Keep it that way. Any other proxy path would allow forged client certificates and IP addresses.
- **I-3:** With `ssl_ocsp leaf`, an unreachable OCSP responder makes nginx return 400 to every browser that presents a certificate. This is fail-closed and documented, so TOTP is the fallback.
- **I-4:** Using `%{sql:...}` in the custom policy gives `radius_fr` rights: write access to radpostauth and radacct only. This is already listed as a residual risk.
- **I-5:** `test_seed_reproduces_original_eap_logic` fails with a PermissionError because the `postgres` user could not read the original configuration files. The test environment needed fixing, not the code (the test has since been removed with those files).
- **I-6:** SECURITY.md §3 (3.1.13 / 3.13.11) says "validated OpenSSL", while F-1 admits that fips-updates packages are not the validated binaries. Align the wording.

## Verified OK (coverage)

- **FIPS:**
  - All randomness comes from `ssl.RAND_bytes`. No `random`, `secrets`, `urandom` or `uuid`.
  - PBKDF2-SHA256 at 600k iterations with a 16-byte salt. The `{X-PBKDF2}HMACSHA2+256` format matches rlm_pap, and the bench gets Accept.
  - AES-GCM uses a fresh 12-byte nonce and AAD bound to the user or session.
  - TOTP uses ±1 step, replay protection through a conditional UPDATE, and a 20-byte seed.
  - The FIPS gate fails closed in both the app and the CLI.
  - The nginx TLS versions, ciphers and curves match SPEC.
- **Login and sessions:**
  - The flow runs banner, then password, then MFA or enrollment, then forced password change. `login_required` blocks every data route until MFA is done and the password changed.
  - The token is rotated at login and at MFA. The cookie uses `__Host-`, Secure, HttpOnly and SameSite=Strict. Idle and absolute timeouts are enforced in SQL.
  - Lockout counts password, MFA and step-up failures. Usernames are lowercased, unknown users get dummy PBKDF2 work, and the per-IP throttle is in place.
- **CSRF:** Every POST is checked in `before_request` (token plus Origin/Referer).
- **RBAC:** All routes were enumerated (viewer: read; operator: CRUD, apply, validate; admin: settings, custom policy, UI admins, rollback, reveal). Step-up is on every route SPEC lists.
- **XSS and SQL injection:**
  - Autoescape is on, with no `|safe`, Markup or inline script.
  - All SQL is parameterized. The only string-built WHERE clauses use fixed fragments.
- **Unlang and config injection:**
  - Inputs are whitelisted: SSID, AD group, VLAN, MAC, client name, IP address and secret (no `"`, `\`, whitespace or `${`). The admin subnet goes through `ipaddress`.
  - The MAB `%{sql:}` lookup only receives hex captures.
  - The helper independently applies the clients-file grammar.
  - Brace balancing prevents escaping `radius_admin_custom`.
- **Root helper:**
  - SO_PEERCRED check, socket mode 0660 `root:radius-admin`.
  - Staged files are opened with O_NOFOLLOW relative to a directory fd, with uid, nlink and size checks, so no symlink, hardlink or TOCTOU trick works.
  - Subprocesses get a fixed argv and environment and have timeouts. Backups are root 0700/0600.
  - Install is atomic with automatic rollback. The systemd hardening of both units is reasonable, and there is no sudo.
- **Database:**
  - pg_hba/pg_ident: peer authentication, other roles rejected for database `radius`, no TCP access.
  - The grants match SPEC. No CREATE on public, and `radius_fr` cannot reach `ui`.
  - The audit trigger blocks UPDATE, DELETE and TRUNCATE.
- **FreeRADIUS changes:**
  - The post-auth query stores no password and has a correct `%l.%M` timestamp.
  - The MAB checks Calling-Station-Id consistency and re-checks its own branch in post-auth.
  - The admin-login condition is identical to the original. The seed policy reproduces the original EAP chain (bench passes).
  - EAP is TLS-only, without `ca_path`, with `reject_unknown_intermediate_ca` and OCSP kept.
  - The LDAP GnuTLS exception is honestly documented.
- **Deployment:**
  - Scripts use `set -euo pipefail`, quoted variables, and a tarball backup before any change.
  - The localhost and LDAP secrets are carried over, and the install aborts if any `REDACTED` remains.
  - The firewall touches only TCP 443 (policy accept), so SSH and UDP 1812/1813 are unaffected.
  - Rollback restores the tarball, validates it and restarts FreeRADIUS.

---

## Resolution status (lead, 2026-10-23)

| ID | Status | Fix |
|---|---|---|
| H-1 | Fixed | `rlm_exec` disabled and removed from accounting/post-auth (Exec-Program attributes now inert; exploit re-tested on bench: no command ran). `Attr-\d` / `Vendor-…-Attr-\d` blocked in both `unlang.validate_custom_policy` and the root helper; regression tests added. SECURITY.md documents the admin role as freerad-equivalent. |
| L-1 | Fixed | `cmd && action` patterns under `set -e` converted in install.sh (15) and preflight.sh (7). |
| L-2 | Fixed | `ecdh_curve = "secp384r1:prime256v1"`; EAP-TLS bench re-run passes. |
| L-3 | Fixed | Admin demote/disable/delete serialized with `pg_advisory_xact_lock(7212002)`; concurrency tests added. |
| L-4 | Fixed | `radius_admin` has only SELECT, INSERT on `ui.apply_log` (and `ui.audit_log`). Audit chain documented as unkeyed; SIEM forwarding recommended. |
| L-5 | Fixed | CSV errors → form error; 1 MiB / 10,000-line caps. |
| L-6 | Fixed | Any client secret change (set or generate, any role) requires step-up. |
| I-1 | Fixed | `safe_next` is an allow-list with repeated percent-decoding. |
| I-5 | Fixed | Test now runs (reference files made readable; skip guard kept). |
| I-6 | Fixed | SECURITY.md wording: validated only on the `fips` stream's certified packages. |
| I-2, I-3, I-4 | Accepted / documented | Rely on nginx header overwrite + socket perms; OCSP fail-closed with TOTP fallback; `%{sql:}` in custom policy is admin-only residual risk. |

Final verification: app 211 passed; helper 71 passed / 1 skipped (real-radiusd test, env-gated);
unlang 108 passed (included in app run); FreeRADIUS 3.2.11 bench 61/61; shellcheck clean.
