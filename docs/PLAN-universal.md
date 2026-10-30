# RADIUS Admin Universal Edition — Implementation Plan

Plan date: 2026-10-29. This is the working plan for the repository; update it as decisions are made.

## Summary

The universal edition turns radius-admin from a portal fitted to one existing server into a product: a fresh Linux server plus one installer command gives a working FreeRADIUS server with the web portal, ready for switches and access points. The work is about 15–20 weeks of focused effort in seven phases. It lives in its own GitHub repository, started from a cleaned copy of the original single-site build with every site-specific detail removed. The original production server stays on its own build and can move onto version 1.0 later, by choice.

**Goals for version 1**

- One-command install on a fresh server, with a first-run setup that needs no hand-editing of FreeRADIUS files.
- Everything the current portal does: clients, access rules, MAB with the approval queue, switch admins, sessions, per-port status, alerts, CoA, reports, audit log, MFA.
- Directory choices beyond Active Directory, and switch vendors beyond the Catalyst 1300.
- FIPS mode as an optional install flag, invisible when off.
- Signed updates from GitHub, checked and installed from the portal, with automatic rollback.

**Not in version 1**

Guest captive portals, device posture checks, BYOD onboarding, outbound RadSec proxying (federation), and multi-server high availability. Each is a large product on its own; they stay on a later list.

**Added to version 1 (decided 2026-10-29), built with the first commit**

| Feature | Notes |
| --- | --- |
| RadSec, inbound, chosen per client | Native FreeRADIUS TLS listener rendered into the clients file; per-client expected certificate name; OCSP; bench-tested with radsecproxy (SPEC section 14) |
| Portal SAML single sign-on | Entra ID first; group object IDs map to the global roles viewer/operator/admin; local break-glass admins; answers open question 7 |
| Light/dark/system theme | Per user, server-rendered, no inline script |
| Setup checklist and interactive installer | First slice of phase 3, over what the portal manages today; extended when phase 2 generates the FreeRADIUS configuration |
| FreeRADIUS 3.2.10 | Latest signed release for both modes (the single-site build ran an unreleased 3.2.x snapshot); answers the version part of open question 5 |

Not yet in this slice: RadSec client CSV import, per-client CA choice for RadSec (needs a helper file type), and a portal Setup step for the directory and certificates (needs phase 2).

## Key decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Delivery | Installer package only; no Docker image | RADIUS identifies switches by source IP, which container networking rewrites unless run with host networking. Apply/restart relies on systemd and a root helper; in a container that needs the Docker socket (root on the host). FIPS needs the host's kernel and a validated OpenSSL, which most container images lack. One delivery method also means one update mechanism and half the test matrix. |
| FIPS | Optional `--fips` install flag, off by default | Most users never need it. Off, the portal never mentions FIPS. On, it enforces approved algorithms and shows compliance status. |
| FreeRADIUS | One build of upstream FreeRADIUS 3.2 for both modes, packaged and signed by the project | Every installation runs the version the test bench passed, with current BlastRADIUS fixes. The FIPS workaround is compiled in and harmless when FIPS is off. Trade-off: the project ships FreeRADIUS security fixes itself (open question 5). |
| Configuration | The portal generates the whole FreeRADIUS configuration from templates and a site file | No more patching an existing `/etc/freeradius`; upgrades can never overwrite a live setting (an earlier upgrade overwrote a live LDAP bind identity and FreeRADIUS would not start). |
| Updates | Signed GitHub Releases; checked by the server, installed by the root helper after signature verification | Never `git pull`. A signature check means even a compromised repository cannot push code to servers. |
| Python and database | Distribution packages only (Flask, psycopg2, cryptography, PostgreSQL) | No pip at install time, so no extra supply chain, and the OS vendor ships security updates. |
| Repository | A separate repository; its first commit is a cleaned copy of the current build | No site hostnames, addresses, accounts, switch data or organization context ever enter its history. Universal work never touches the original production server. |

## Platforms and scope

Version 1 supports Ubuntu 24.04 LTS and Debian 12 on x86-64; the RHEL family (RHEL, Rocky, AlmaLinux 9) follows in phase 7. A server needs 2 vCPU, 4 GB RAM and 20 GB disk for a few hundred switches.

| Platform | Standard mode | FIPS mode | Phase |
| --- | --- | --- | --- |
| Ubuntu 24.04 LTS | Yes | Yes, with Ubuntu Pro `fips-updates` | 3 |
| Debian 12 | Yes | No (no validated FIPS stack) | 3 |
| RHEL / Rocky / AlmaLinux 9 | Yes | Yes, with `fips-mode-setup --enable` | 7 |
| Ubuntu 22.04 LTS | Only if asked (open question 3) | — | — |

**Features in version 1**

| Area | Included |
| --- | --- |
| Authentication | EAP-TLS (default); PEAP-MSCHAPv2 as an option in standard mode only; MAB; switch-admin logins (PAP) |
| Identity sources | Active Directory groups (nested), generic LDAP groups, certificate attributes only (no directory) |
| Access rules | Match on group, certificate attribute, connection type, SSID and switch group; result VLAN plus optional extra attributes |
| Network devices | Clients with CSV import, vendor profiles, SNMPv3 monitoring with per-port 802.1X state, sessions, CoA |
| Operations | Alerts (syslog, email), audit log, reports, signed updates, backup and restore |
| Portal security | Local admin accounts with MFA (TOTP or client certificate), roles, step-up, admin-subnet restriction |

## Architecture

**Only the root helper changes FreeRADIUS; the web portal runs unprivileged.**

```
 Admin browser ──HTTPS──> nginx (443, TLS, admin subnet only) ──> Web portal (Flask, unprivileged)
 (management subnet)                                                  │            │
                                                          unix socket ▼            ▼
                                       Root helper (validate, apply, update)   PostgreSQL (rules, MAB, logs, audit)
                                                          │ install, restart       ▲
                                                          ▼                        │ SQL
                                                   FreeRADIUS 3.2 (generated config) ──LDAPS──> Directory (AD or LDAP)
                                                          ▲ RADIUS 1812/1813
 GitHub Releases ──signed bundles──> Update check   Switches and APs <──SNMPv3, CoA 1700── Monitor service ──> Alerts out
 (HTTPS out, daily timer)            (hands to helper)                                       (SNMP, alerts, CoA)   (syslog, SIEM, email)
```

The web portal never touches FreeRADIUS files or services: it asks the root helper over a local socket, and the helper validates, installs, restarts and rolls back. The same helper installs verified updates. Only two services talk to the network beyond RADIUS: the monitor (switches only) and the update check (GitHub only, while it runs).

| Package | Contains |
| --- | --- |
| `radius-admin` | Portal, root helper, monitor, update check, templates, vendor profiles, systemd units, nginx site, `radius-admin-ctl` |
| `radius-admin-freeradius` | FreeRADIUS 3.2 built by the project (FIPS workaround compiled in) |
| From the distribution | PostgreSQL, nginx, Python libraries, Net-SNMP, ieee-data, ldap-utils |

On disk: `/opt/radius-admin` (code), `/etc/radius-admin` (site file, keys), `/etc/freeradius` (generated, owned by the portal), `/var/lib/radius-admin` (staging, releases, backups).

## Site configuration and first-run setup

Every value that was hard-coded for the original site moves into one file, `/etc/radius-admin/site.yaml`, plus the database. The installer asks only what it needs to bring the portal up; everything else is set up in the portal, where each step can be tested.

**What the installer asks** (or reads from an answers file for unattended installs: `install.sh --answers site.yaml`)

1. Server name and the address to listen on.
2. Management subnet allowed to reach the portal.
3. Portal certificate: self-signed to start, a CSR for your own CA, or an existing certificate and key.
4. FIPS mode (only when `--fips` is given).
5. First administrator. A one-time password is printed; MFA enrolment is forced at first sign-in, as today.

**What the portal's Setup checklist covers** (shown until complete, each with a test button)

1. Directory: AD, LDAP or none. Server, bind account, CA certificate; **Test login** runs the bind before saving.
2. Certificates for 802.1X: upload the CA that issues client certificates, set up revocation checks (OCSP or CRL), and choose the RADIUS server certificate (generated CSR or upload).
3. Authentication methods: EAP-TLS, PEAP (standard mode only), MAB, switch-admin logins.
4. Default vendor profile for new clients.
5. First RADIUS client and first access rule.
6. Alerts and update settings.

**Where each value lives**

| Setting | Stored in | Changed by |
| --- | --- | --- |
| Server name, listen address, FIPS flag | `site.yaml` | Installer (`radius-admin-ctl` for later changes) |
| Directory, certificates, methods, vendor defaults | Database (secrets encrypted with the data key) | Portal, Needs Apply |
| Rules, MAB, switch admins, alerts | Database | Portal, live |
| Directory bind password | Database (encrypted); written only into the generated FreeRADIUS file (root:freerad, 0640) | Portal (write-only field) |

## FreeRADIUS configuration

The portal owns the whole FreeRADIUS configuration: it renders every file from templates, and the root helper validates and installs the complete set, never individual patches. Today the package edits an existing `/etc/freeradius` and carries secrets across; that disappears.

**How a change reaches FreeRADIUS** (extends today's validate, apply and rollback)

1. The portal renders the full configuration tree from templates, `site.yaml` and the database into a staging directory.
2. The root helper checks the file list against an allow-list, runs `radiusd -XC` on a copy, and runs a real directory login with the bind account (the check that would have caught the bind-identity overwrite).
3. It backs up the live tree, installs the new one, restarts FreeRADIUS and waits for it to listen.
4. If FreeRADIUS does not come up, it restores the backup and restarts again. The portal shows FreeRADIUS's own error from `radius.log`, not only "service not active".

**Feature modules** (each one switches template blocks on or off)

| Module | Options | Notes |
| --- | --- | --- |
| Identity source | Active Directory, generic LDAP, none | AD uses the nested-group lookup; LDAP takes group attribute and filter; none means certificate attributes only |
| EAP methods | EAP-TLS; PEAP-MSCHAPv2 | PEAP needs a password source (AD via ntlm\_auth, or local users with NT hashes) and is hidden and blocked in FIPS mode |
| Access rules | Match on group, certificate field (CN, SAN, OU, issuer), connection type, SSID, switch group | First match wins, as today; still evaluated live in the database |
| MAB | On or off; queue, expiry, default VLAN | As built today |
| Switch-admin logins | Local accounts or a directory group; privilege attribute from the vendor profile | Source-subnet check stays |
| Accounting and CoA | On by default | CoA attributes come from the client's vendor profile |
| Revocation | OCSP, CRL, or both | CRL files refreshed by the monitor service |

The hex-only rule for request data passed to SQL, and the test bench cases that prove it, carry over unchanged to every template.

## FIPS mode (optional)

FIPS mode is chosen at install time with `install.sh --fips` and stored as `fips: true` in `site.yaml`. When it is off, nothing in the portal, its reports or its documentation pages mentions FIPS; when it is on, the portal enforces approved algorithms and shows whether the server is compliant.

**What the flag changes**

| Area | Standard mode | FIPS mode |
| --- | --- | --- |
| Preflight | Basic checks | Stops unless the kernel's `fips_enabled` is 1 and OpenSSL's FIPS provider is active, with the exact steps to enable them |
| EAP methods | EAP-TLS default, PEAP optional | EAP-TLS only; PEAP hidden and refused if set through the API |
| TLS | Modern defaults (TLS 1.2+) | FIPS cipher lists for the portal, EAP and LDAPS |
| SNMPv3 | SHA-1 and above allowed, AES | SHA-2 and AES only, as today |
| SSH guidance | Not shown | Setup checklist shows the FIPS `sshd` algorithm snippet (Windows OpenSSH defaults are refused by a FIPS sshd) |
| Portal start-up | Normal | Refuses to start if FIPS is off at the OS level (`require_fips`) |
| Update signatures | ECDSA P-384, verified by OpenSSL | Same; chosen so it works in both modes |

**What the portal shows**

- Standard mode: no FIPS badge, no FIPS row on the dashboard, no FIPS text in reports or settings. An automated test renders every page in standard mode and fails if the word "FIPS" appears.
- FIPS mode: a status line on the dashboard (compliant, or what is wrong) and an Exceptions page listing the documented exceptions (RADIUS MD5, SNMP key localisation, LDAP over GnuTLS) for an auditor.

**Switching modes later**

`radius-admin-ctl fips enable` checks the OS, switches the setting, regenerates the configuration and asks for one Apply. Turning FIPS on in the OS (Ubuntu Pro or `fips-mode-setup`, then a reboot) stays the administrator's step. `fips disable` reverses it.

## Vendor profiles

Everything that differs between switch makers moves into small profile files, one per vendor family, chosen per RADIUS client (with a default). A profile ships only after it has passed the bench with that vendor's packets and been tried on real hardware.

**What a profile defines**

- **VLAN assignment:** the reply attributes (the standard Tunnel-Type, Tunnel-Medium-Type and Tunnel-Private-Group-Id cover most vendors).
- **Admin logins:** how privilege is granted (for example Cisco `shell:priv-lvl=15`), and how to tell an admin login from 802.1X or MAB by its attributes.
- **MAB:** the MAC formats and attributes the vendor sends.
- **CoA:** UDP port, and the attributes for re-authenticate, bounce port and disconnect.
- **SNMP:** port-name rules (like Catalyst 1300 `gi4` to `gi1/0/4`) and any vendor tables beyond the standard MIBs.
- **Setup snippet:** the switch commands the portal shows for this vendor (RADIUS server, accounting, dynamic authorization, SNMPv3 user).

| Profile | Release | Status |
| --- | --- | --- |
| Cisco Catalyst 1200/1300 | v1 | Built and tested in production |
| Cisco IOS / IOS-XE (Catalyst 9000, 2960) | v1 | Same attributes as ISE; needs a lab switch |
| Generic RFC (VLAN attributes, RFC 5176 disconnect only) | v1 | Fallback for anything else |
| Aruba / HPE (AOS-CX, ProCurve) | v1.1 | Attribute names to confirm in the lab |
| Juniper EX | v1.1 | Attribute names to confirm in the lab |
| Wireless controllers (Aruba, Meraki, Ubiquiti) | Later | SSID matching works today; CoA per vendor |

New vendors are added by writing a profile file plus bench cases; no portal code changes.

## Updates from GitHub

Servers install only signed GitHub Releases. Each server checks for them daily, and the default is to notify and let an administrator click Install. The root helper verifies the signature and runs the install with backups, health checks and automatic rollback; the web portal only asks for it.

**Release pipeline (GitHub Actions)**

1. A version tag starts the pipeline: unit tests, the FreeRADIUS bench, and installer and upgrade tests on clean VMs.
2. It builds the release bundle: portal package, FreeRADIUS package, installer, a manifest with SHA-384 hashes, release notes, and a list of all components and versions (SBOM).
3. A protected release job signs the manifest with an ECDSA P-384 key. The key is never stored in the repository; publishing needs a second person's approval (or yours, if you are the only maintainer).
4. The release is published with a flag saying whether it restarts FreeRADIUS.

**On the server**

1. **Check.** A small timer service asks the GitHub API for the newest release on the chosen channel (stable, or beta). It is the only part allowed outbound HTTPS, and only while it runs; an HTTPS proxy setting is supported.
2. **Notify.** The Updates page shows the current and available versions, release notes, and whether FreeRADIUS will restart. Alerts and the dashboard mention it.
3. **Install** (admin with step-up, or automatically if the site chose it):
   1. The helper downloads the bundle and verifies the manifest's signature with the public key built into the installed version, then every file's hash. Any mismatch stops here.
   2. It refuses an older version unless an administrator chose a rollback.
   3. It backs up the database (`pg_dump`), the FreeRADIUS configuration and the current release.
   4. It installs: database migrations, packages, portal, configuration.
   5. Health checks: FreeRADIUS active and listening, a test authentication against localhost, a directory login, the portal answering, migrations recorded.
   6. If any check fails, it restores the previous release and configuration and alerts.
4. **Record.** Every step goes to the audit log and syslog.

**Update modes** (per server, set in the portal)

| Mode | Behaviour |
| --- | --- |
| Off | Never contacts GitHub; upload only |
| Notify (default) | Check daily; install on click |
| Maintenance window | Install automatically in a chosen weekly window |
| Automatic | Install portal-only updates at once; anything that restarts FreeRADIUS waits for the window |

**Offline and air-gapped servers** upload the downloaded bundle and its signature in the portal or with the push script; verification is identical.

**Rules that keep rollback safe:** database migrations only add (new columns, tables, functions) in the release that introduces them, and remove old ones at least one release later. A rollback therefore never needs a database restore, except in an emergency.

**Key rotation:** a release can carry the next public key, signed by the current one. Servers accept a new key only that way.

## Migration

**The original production server** stays on its current build while the universal edition is developed in the separate repository. Moving it onto version 1.0 is optional and comes after release: `radius-admin-ctl adopt` reads its `/etc/freeradius` and database and writes `site.yaml`, `adopt --compare` shows every difference between the generated and the running configuration, and the switch happens in a maintenance window with automatic rollback. The database keeps its data; migrations continue from `70-operations.sql`.

**Importing other existing servers** (Setup checklist, Import step; each import shows a preview before anything is saved)

| Source | Imports |
| --- | --- |
| FreeRADIUS `clients.conf` | Clients and secrets, NAS type to vendor profile where recognisable |
| FreeRADIUS `users` file | MAC entries as MAB devices with VLAN; other entries listed for manual review |
| FreeRADIUS SQL (`radcheck`, `radreply`, `radusergroup`) | Switch admins, MAB devices, group VLANs as access rules |
| SQLite FreeRADIUS databases | As above, through the existing SQLite migration |
| CSV | Clients and MAB devices, as today |

Policy written by hand in `sites-available` cannot be converted automatically; the importer lists it so it can be recreated as access rules or kept as custom policy.

## Testing and CI

No release ships unless the full test matrix passes on clean machines; the FreeRADIUS bench built during this project is the core of it.

| Layer | What runs | Where |
| --- | --- | --- |
| Unit and portal tests | The current \~310 app tests and 71 helper tests, plus a run of every page in standard mode asserting no FIPS wording | Every push |
| FreeRADIUS bench | Real radiusd, eapol\_test, OCSP responder and an LDAP stand-in for AD: EAP-TLS, PEAP, MAB, admin logins, injection cases, live rule changes, database-down behaviour (114 checks today) | Every push, for each identity source and vendor profile |
| Installer | `install.sh --answers` on fresh Ubuntu 24.04 and Debian 12 VMs, then the bench against the installed server | Every release candidate |
| Upgrade and rollback | Install release N−1, upgrade to N through the updater, force a failed health check, confirm rollback | Every release candidate |
| FIPS | Same installer and bench on an Ubuntu Pro FIPS VM | Self-hosted runner (GitHub's runners cannot boot a FIPS kernel) |
| CoA and SNMP | Simulated switch (the RFC 5176 responder used today) and an SNMP agent | Every push |
| Hardware | One switch per vendor profile | Before a profile is marked supported |

A release needs: every row green, a signed bundle, release notes, and migration notes for anything that changes the database.

## Security

The current security design carries over unchanged: separate root helper, sandboxed services, MFA, hash-chained audit log, hex-only SQL arguments. These points are new for a product other people install.

- **Secure defaults:** EAP-TLS only; the portal reachable only from the management subnet; MFA required; new clients require Message-Authenticator; no default passwords (first admin gets a one-time password). A self-signed portal certificate shows a warning until replaced.
- **Updates are a code-execution path:** signature verified by the root helper with a pinned key; no downgrades without an explicit rollback; the update check is a separate service whose network access exists only while it runs; every step audited; can be switched off entirely.
- **Supply chain:** distribution packages for Python and PostgreSQL; FreeRADIUS built in CI from upstream release tarballs with signature checks; SBOM per release; dependency and CVE alerts on the repository.
- **Repository and signing:** two-factor sign-in for maintainers, protected branches, release job in a protected environment, signing key held outside the repository (GitHub encrypted secret to start; hardware key later).
- **Vulnerability handling:** a `SECURITY.md` with a private reporting address, fixes released as signed updates, and an advisory for each fix.
- **No telemetry:** servers contact only GitHub, only for updates, only if enabled.

## Roadmap

**Version 1.0 in about 16 weeks, starting from a clean import.** Phases run in order; each ends at a gate that must pass. Weeks are rough, focused effort.

| Phase | Weeks | Work | Gate |
| --- | --- | --- | --- |
| 1. Clean import and site configuration | 2 | Cleaned build becomes the first commit; hard-coded values move to `site.yaml` | The site-data scan finds nothing; all tests and the bench pass |
| 2. Generated FreeRADIUS configuration | 3 | Templates for the whole tree; helper installs the full set; directory login test before install | The FreeRADIUS bench passes on the generated configuration |
| 3. Installer and setup | 3 | `install.sh` for Ubuntu 24.04 and Debian 12, answers file, Setup checklist, the `--fips` flag | A fresh-VM install passes the bench in standard and FIPS mode |
| 4. Feature modules and vendor profiles | 4 | LDAP and certificate-only identity, PEAP option, new rule matches, Cisco IOS and Generic profiles | Every profile passes the bench; a Cisco IOS lab switch works |
| 5. Signed updates | 2 | Release pipeline, ECDSA signing, update check, Updates page, health checks, rollback | Upgrade from the previous release and a forced rollback both pass |
| 6. Import, documentation, beta | 2 | Importers, `adopt` and `adopt --compare`, documentation, public beta | **Version 1.0 released** |
| 7. RHEL family and more vendors | 3 | RHEL, Rocky and AlmaLinux 9 with SELinux; Aruba/HPE and Juniper profiles | **Version 1.1 released** |

Version 1.0 is about 16 weeks of focused work (phases 1–6), and version 1.1 about 3 more. Phase 1 starts from the cleaned package delivered with this plan. Phase 2 starts once open questions 1–5 are answered.

## Risks

| Risk | Effect | Mitigation |
| --- | --- | --- |
| A bad update reaches many servers | Authentication outages at several sites | Notify-only default, health checks, automatic rollback, staged channels (beta before stable) |
| Signing key or repository compromised | Malicious code installed as root | Key outside the repository, protected release job, second-person approval, key rotation by signed release |
| FreeRADIUS security fix lags upstream | Exposure window on every server | CI watches upstream releases; rebuild and ship within days; option to fall back to distribution packages (open question 5) |
| Vendor profile wrong for real hardware | Wrong VLAN, failed CoA or admin login | Profiles marked supported only after a hardware test; Generic RFC fallback |
| Scope grows toward a full NAC product | Release slips, maintenance load grows | Non-goals written down; later features need their own plan |
| Moving the original production server onto 1.0 behaves differently | Production outage | Optional and after 1.0; adopt --compare shows every difference from the running files before a windowed apply |
| Support load from other people's networks | Time taken from other work | Clear supported-platform list, troubleshooting pages, issue templates asking for the bench-style diagnostics |
| Employer IP or publication rules | Cannot publish | Clear ownership before the repository is made public (open question 1) |

## Open questions

Recommendations are in brackets; questions 1–5 need an answer before phase 2 starts.

1. **Ownership and licence.** Does the code owner allow publishing this? Public or private repository? \[Apache-2.0 for the portal; FreeRADIUS stays GPLv2 as its own package.\]
2. **Name and release control.** Product name, GitHub organisation, and who approves and signs releases. \[A dedicated organisation; you as approver to start.\]
3. **Platforms.** Are Ubuntu 24.04 and Debian 12 enough for version 1, or is Ubuntu 22.04 or RHEL needed earlier? \[24.04 and Debian 12 first.\]
4. **Authentication scope.** Should PEAP-MSCHAPv2 be in version 1? Many small sites expect it, but with AD it needs the server joined to the domain (Samba `ntlm_auth`). \[Yes, standard mode only, clearly marked as weaker than EAP-TLS.\]
5. **FreeRADIUS packaging.** Project-built FreeRADIUS for both modes, or the distribution's package in standard mode? \[Project-built: one tested version everywhere.\]
6. **Vendors.** Which makes besides the Catalyst 1300 matter to you, and what hardware is available for lab tests?
7. **Portal sign-in.** Decided: local accounts plus SAML single sign-on (Entra ID first) in version 1, roles from group claims. Directory (LDAP) sign-in to the portal stays for v1.1.
8. **Update defaults.** Is notify-only the right default, and should fully automatic installs be offered at all? \[Notify by default; automatic only for portal-only updates.\]
9. **Original production server.** Decided: a separate repository; that server stays on its own build. Still open: move it onto 1.0 after release, and when? \[After 1.0 has run elsewhere for a few weeks, in a maintenance window.\]
10. **Second server.** Is a standby RADIUS server likely within a year? If so, the version 1 database design should allow two servers to sync later.
11. **Installer style.** Interactive questions, an answers file, or both? \[Both.\]
