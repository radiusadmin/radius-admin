# radius-admin

![status](https://img.shields.io/badge/status-early%20development-orange)
![tests](https://img.shields.io/badge/tests-620%20passing-brightgreen)
![FreeRADIUS bench](https://img.shields.io/badge/FreeRADIUS%20bench-124%2F124-brightgreen)
![FreeRADIUS](https://img.shields.io/badge/FreeRADIUS-3.2.10-blue)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![FIPS mode](https://img.shields.io/badge/FIPS%20mode-optional-informational)
![licence](https://img.shields.io/badge/licence-to%20be%20decided-lightgrey)
![made with love](https://img.shields.io/badge/made%20with-%E2%9D%A4%EF%B8%8F-red)

**A secure web console for FreeRADIUS: 802.1X, MAB, RadSec and switch logins, managed in one place.**

radius-admin turns a FreeRADIUS 3.2 server into a network access control service you run
from the browser. Instead of hand-editing configuration files and SQL tables, you manage RADIUS
clients, access rules, MAC authentication and switch administrators in an audited, role-based,
MFA-protected portal. Every change is validated before FreeRADIUS sees it, and rolled back
automatically if FreeRADIUS does not come back up.

> **A young project.** radius-admin is new and under active development. It grew out of a
> console that has run a production network, and is now being turned into a product anyone can
> install. Expect rough edges and frequent improvements. See the [roadmap](docs/PLAN-universal.md)
> for what is coming next, and please report what you find.
>
> Made with ❤️ for the people who keep networks running.

## Use cases

- **Wired and wireless 802.1X with EAP-TLS.** Computers authenticate with certificates; their
  Active Directory group decides the VLAN (per wired port or per SSID). Nested groups work.
- **Devices without 802.1X** (printers, cameras, IoT). MAC Authentication Bypass with a VLAN per
  device, optional expiry, vendor names, and an approval queue: unknown devices that try to
  connect show up for one-click approval.
- **Switch and device administrator logins** over RADIUS (PAP), limited to the management
  subnet, with optional privilege level 15.
- **Access points and controllers over untrusted networks.** RadSec (RADIUS over TLS) per
  client: switch an AP to RadSec while your switches stay on plain RADIUS.
- **Security-conscious and regulated environments.** Optional FIPS mode, a hash-chained audit
  log of every administrative action, and printable audit reports.
- **Teams with a central identity provider.** Admins sign in to the console with SAML single sign-on
  (Microsoft Entra ID tested); their role comes from group membership.

## Features

**Network access**
- RADIUS clients (switches, APs, controllers) with per-client Message-Authenticator and
  Proxy-State settings (BlastRADIUS mitigations), generated shared secrets and CSV import.
- RadSec per client: TLS 1.2/1.3, certificates from your CA, an optional expected certificate
  name per client, and OCSP revocation checks.
- Access rules: directory group → VLAN for wired or per-SSID connections. Changes take effect on the
  next authentication, with no restart, and a rule tester shows which rule would match.
- MAB devices and the unknown-device approval queue.
- Switch administrator accounts (PBKDF2-hashed).
- Custom unlang policy for administrators, checked before it is installed.

**Operations**
- Dashboard, live sessions, and change of authorization (disconnect, re-authenticate, bounce port).
- Authentication log with the reason for every reject, the certificate, groups and matched rule.
- SNMPv3 switch monitoring with per-port 802.1X state.
- Alerts by syslog and e-mail (reject spikes, switches down, RADIUS down).
- Audit reports as CSV or for print/PDF.
- Safe apply: the root helper validates the full configuration with `radiusd -XC`, installs it,
  restarts FreeRADIUS, checks that it listens, and rolls back by itself if it does not.

**Console security**
- Local accounts with mandatory MFA (TOTP or client certificate), roles (viewer, operator,
  admin), step-up re-authentication for sensitive actions, account lockout.
- SAML single sign-on with group-to-role mapping; local break-glass administrators.
- Hash-chained, append-only audit log; strict Content Security Policy; light, dark or
  system colour theme.
- The web application never runs as root and never writes FreeRADIUS files itself.

**Getting started**
- Interactive installer (or an answers file for unattended installs).
- A setup checklist in the console that tracks what is left to configure.

## How it works

```
 admin browser (management subnet)            identity provider (optional SSO)
        │  HTTPS 443, TLS 1.2/1.3                    ▲ SAML (redirect / POST)
        ▼                                            │
 ┌───────────────────────────────────────────────────┴──────────────────────┐
 │ nftables: 443 only from the management subnet · nginx (TLS, client certs) │
 └───────────────┬──────────────────────────────────────────────────────────┘
                 │ unix socket
                 ▼
 ┌───────────────────────────────┐   peer auth (no passwords)  ┌───────────────────────┐
 │ web portal (Flask + gunicorn) │ ─────────────────────────▶  │ PostgreSQL 16         │
 │ unprivileged, sandboxed       │                             │ rules, MAB, users,    │
 │ stages generated files        │                             │ logs, audit log       │
 └──────────────┬────────────────┘                             └──────────▲────────────┘
                │ JSON over a local socket                                │ SQL (hex-encoded
                ▼                                                         │  request data only)
 ┌───────────────────────────────┐  validate, install, restart ┌─────────┴─────────────┐
 │ root helper                   │ ──────────────────────────▶ │ FreeRADIUS 3.2.10     │
 │ allow-list, radiusd -XC,      │  automatic rollback         │ EAP-TLS, MAB, PAP     │
 │ backups                       │                             │ → LDAPS directory     │
 └───────────────────────────────┘                             └───────────────────────┘
                                                      ▲ RADIUS UDP 1812/1813   ▲ RadSec TCP 2083
                                                      │ switches               │ access points
```

Access rules and MAB decisions are read live from PostgreSQL by FreeRADIUS, so most changes
apply immediately. Changes to RADIUS clients, RadSec and the custom policy are staged and reach
FreeRADIUS when you click **Apply**. More detail: [SPEC.md](SPEC.md) and
[docs/SECURITY.md](docs/SECURITY.md).

## Requirements

- Ubuntu 24.04 LTS (Debian 12 is planned) with 2 vCPU, 4 GB RAM and 20 GB disk for a few
  hundred switches.
- FreeRADIUS **3.2.10**, built from the signed upstream release with `--enable-fips-workaround`
  (one build works in standard and FIPS mode). See [tests/freeradius/README.md](tests/freeradius/README.md)
  for the build steps.
- Distribution packages only, with no pip or npm: PostgreSQL 16, nginx, Python 3.12 with
  `python3-flask`, `python3-psycopg2`, `python3-cryptography`, `python3-pysaml2` and friends
  ([app/requirements-apt.txt](app/requirements-apt.txt)).
- For EAP-TLS: a CA that issues client certificates, and a RADIUS server certificate.
- Optional: Ubuntu Pro FIPS for FIPS mode.

## Getting started

1. **Check the server** (read-only):
   ```bash
   sudo ./deploy/preflight.sh
   ```
2. **Install.** Run the installer with no options and answer the questions: server name,
   management subnet, portal address, DNS resolvers, portal certificate (self-signed to start,
   a CSR for your CA, or existing files) and the first administrator:
   ```bash
   sudo ./deploy/install.sh
   ```
   For unattended installs, put the same answers in a file
   (the format is described in [deploy/answers.sh](deploy/answers.sh)):
   ```yaml
   server_name: radius.example.net
   admin_net: 192.0.2.0/24
   listen_ip: 192.0.2.10
   resolver: "192.0.2.53"
   tls: self-signed
   admin_username: netadmin
   ```
   ```bash
   sudo ./deploy/install.sh --answers site.yaml --print-answers   # check only
   sudo ./deploy/install.sh --answers site.yaml
   ```
   The installer keeps your answers in `/etc/radius-admin/site.yaml` for later runs.
3. **Sign in.** Browse from the management subnet to `https://<server name>/`, sign in with the
   one-time password the installer printed, choose your own password and set up two-factor
   authentication.
4. **Follow the setup checklist** on the dashboard: add RADIUS clients, create access rules, set
   the switch-admin subnet and apply. Optional steps include single sign-on, RadSec, switch
   monitoring and alert e-mail.

The full procedure, including migration from an existing FreeRADIUS server, is in
[docs/RUNBOOK.md](docs/RUNBOOK.md).

### Single sign-on with Microsoft Entra ID

In the console open **Single sign-on**. It shows the Entity ID and reply URL to enter in a new
Entra enterprise application (SAML). Paste the application's federation metadata XML, add a
group claim ("Groups assigned to the application"), map group object IDs to roles, and turn it on.
You can keep local passwords for administrators only, as break-glass accounts.

### RadSec

Open **RADIUS clients → RadSec listener**, turn the listener on (TCP 2083), then edit a client
and choose **RadSec** as its transport. You can also enter the name its certificate must carry.
Clients present a certificate from the same CA as your 802.1X clients. Apply the change and
allow TCP 2083 from those clients.

## Current limitations

Being a young project, some parts are still on the [roadmap](docs/PLAN-universal.md):

- The installer expects FreeRADIUS 3.2.10 to be installed already, with its certificates under
  `/etc/freeradius/certs/site/`. Packaging FreeRADIUS and generating its whole configuration
  are the next phases.
- The nginx phase expects the site CA bundle and an OCSP responder for client-certificate MFA.
- Vendor profiles: Cisco Catalyst 1200/1300 is the tested switch family today.
- Signed updates from GitHub Releases are planned. Today, updates use `deploy/update.sh` or the
  Windows push script.

## Development and tests

The test suites run in a sandbox (an Ubuntu 24.04 VM or WSL) and never on a production server:
some of them stop PostgreSQL, truncate tables and add `/etc/hosts` entries.

### Test status

Last full run: 2026-10-29, Ubuntu 24.04, FreeRADIUS 3.2.10. **620 checks passing.**

| Suite | Result | Command (as root) |
|---|---|---|
| Web app | 375 passed | `cd app && runuser -u postgres -- python3 -m pytest -q -p no:cacheprovider` |
| Root helper | 89 passed, 1 skipped (needs a live raddb) | `python3 -m pytest -q -p no:cacheprovider tests/helper` |
| FreeRADIUS bench: real radiusd, eapol_test, radsecproxy, LDAP, OCSP | 124 / 124 | `python3 tests/freeradius/run-tests.py --prefix … --bench … --eapol-test …` |
| Migration from SQLite | 12 / 12 | `bash tests/migration/test_migrate.sh …` |
| Installer answers | 20 / 20 | `bash tests/installer/test_answers.sh` |
| Shell scripts | clean | `shellcheck -S warning deploy/*.sh tests/*/*.sh` |
| Site-data scan | clean | `tools/site-scan.sh` |

The design contract between the components is [SPEC.md](SPEC.md); security design and
findings are in [docs/SECURITY.md](docs/SECURITY.md). Before every commit, `tools/site-scan.sh`
must report clean: no real host names, addresses, accounts or secrets ever enter the repository.

## Licence

Not decided yet (see the open questions in the [plan](docs/PLAN-universal.md)).

---

radius-admin is made with ❤️ and a lot of `radiusd -X`.
