# radius-admin

[![CI](https://github.com/radiusadmin/radius-admin/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/radiusadmin/radius-admin/actions/workflows/ci.yml)
![status](https://img.shields.io/badge/status-early%20development-orange)
[![tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fradiusadmin%2Fradius-admin%2Fbadges%2Ftests.json&label=tests)](https://github.com/radiusadmin/radius-admin/actions/workflows/ci.yml?query=branch%3Amain)
[![FreeRADIUS bench](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fradiusadmin%2Fradius-admin%2Fbadges%2Fbench.json&label=FreeRADIUS%20bench)](https://github.com/radiusadmin/radius-admin/actions/workflows/ci.yml?query=branch%3Amain)
![FreeRADIUS](https://img.shields.io/badge/FreeRADIUS-3.2.10-blue)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![FIPS mode](https://img.shields.io/badge/FIPS%20mode-optional-informational)
[![licence](https://img.shields.io/badge/licence-BSL%201.1%20(source%20available)-blue)](LICENSING.md)
![made with love](https://img.shields.io/badge/made%20with-%E2%9D%A4%EF%B8%8F-red)

**A secure web console for FreeRADIUS: 802.1X, MAB, RadSec and switch logins, managed in one place.**

radius-admin turns a FreeRADIUS 3.2 server into a network access control service you run
from the browser. Instead of hand-editing configuration files and SQL tables, you manage RADIUS
clients, access rules, MAC authentication and device administrators in an audited, role-based,
MFA-protected portal. Every change is validated before FreeRADIUS sees it, and rolled back
automatically if FreeRADIUS does not come back up.

> **A young project.** radius-admin is new and under active development. It grew out of a
> console that has run a production network, and is now being turned into a product anyone can
> install. Expect rough edges and frequent improvements, and please report what you find.
>
> Made with ❤️ for the people who keep networks running.

## Use cases

- **Wired and wireless 802.1X with EAP-TLS.** Computers authenticate with certificates; their
  Active Directory group decides the VLAN (per wired port or per SSID). Nested groups work.
- **802.1X with a username and password** (EAP-TTLS with PAP inside) for people and devices
  without a certificate: local accounts with groups and expiry, or Active Directory accounts
  and their groups, with the same access rules. PEAP-MSCHAPv2 where devices need it, for
  local users or, with the server joined to the domain, directory accounts.
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
- Device administrator logins for switches, access points and firewalls: local accounts
  (PBKDF2-hashed) or members of chosen directory groups with their directory password (LDAPS).
- Custom unlang policy for administrators, checked before it is installed.
- Certificates in the console: the 802.1X server certificate, the CA for client certificates, OCSP
  for EAP-TLS and the portal's HTTPS certificate. Upload them, or make the key and request on the
  server; they are installed with Apply and rolled back if FreeRADIUS or the portal does not take them.

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

**Updates**
- An Updates page that shows the installed and the latest version, the changelog in between,
  and installs with a click: database backup first, health checks after, automatic rollback.
- Choose the channel to follow (`main` for stable releases, `testing`, `dev`), notify-only or
  automatic updates, and a maintenance window for updates that restart FreeRADIUS.
- Builds are signed in CI (ECDSA P-384); the server verifies the signature before installing.

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
- FreeRADIUS **3.2.10** comes with radius-admin: the release bundle carries the
  `radius-admin-freeradius` package, built from the signed upstream release with
  `--enable-fips-workaround` (one build works in standard and FIPS mode), and the installer
  installs it on a server without FreeRADIUS. It never overwrites an existing FreeRADIUS or
  `/etc/freeradius`. To build the package yourself: `sudo tools/package/build-freeradius-deb.sh`
  ([RUNBOOK §1.2](docs/RUNBOOK.md#12-the-bundled-freeradius-package)).
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
   a CSR for your CA, or existing files), the first administrator, the crypto mode (standard by
   default; FIPS mode on a FIPS host), the 802.1X (EAP) server certificate (your files, or
   self-signed to replace later) and an optional OCSP responder:
   ```bash
   sudo ./deploy/install.sh
   ```
   For unattended installs, put the same answers in a file
   (the format is described in [deploy/answers.sh](deploy/answers.sh)):
   ```yaml
   server_name: radius.example.net
   admin_net: 192.0.2.0/24
   switch_nets: "192.0.2.0/24 198.51.100.0/24"
   listen_ip: 192.0.2.10
   resolver: "192.0.2.53"
   tls: self-signed
   admin_username: netadmin
   eap_tls: self-signed
   ```
   ```bash
   sudo ./deploy/install.sh --answers site.yaml --print-answers   # check only
   sudo ./deploy/install.sh --answers site.yaml
   ```
   The installer keeps your answers in `/etc/radius-admin/site.yaml` for later runs. On a new
   server, FreeRADIUS starts without a directory and rejects every 802.1X user until you add
   access rules and set up the directory
   ([RUNBOOK §13.4](docs/RUNBOOK.md#134-a-new-server-directory-eap-certificates-and-ocsp)).
3. **Sign in.** Browse from the management subnet to `https://<server name>/`, sign in with the
   one-time password the installer printed, choose your own password and set up two-factor
   authentication.
4. **Follow the setup checklist** on the dashboard: add RADIUS clients, create access rules, set
   the device admin subnet and apply. Optional steps include single sign-on, RadSec, switch
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

Being a young project, some parts are still to come:

- The directory (LDAP/AD) of a new server is set up by hand in `mods-available/ldap`; a portal
  Setup step for the directory comes with the generated FreeRADIUS configuration, the next phase.
- The bundled FreeRADIUS package is built for Ubuntu 24.04 (amd64); Debian 12 follows.
- Vendor profiles: Cisco Catalyst 1200/1300 is the tested switch family today.

## Licence

Copyright © 2026 Collin Linde.

radius-admin is **source available** under the [Business Source License 1.1](LICENSE). Every
feature is in the same public code, with nothing locked behind a licence key.

- **Free** for personal use (home networks and labs), for organizations with **fewer than 50**
  people (employees and contractors, affiliates included), and for any organization during its
  first 60 days of production use. Testing, development and evaluation are always free.
- **Organizations with 50 or more people need a commercial licence** for production use after
  the 60-day trial. So does running radius-admin for a customer that has 50 or more people.
- Each version becomes available under the GNU Affero General Public License, version 3 or
  later, four years after it is published. Versions up to and including 0.2.5 are under the
  GNU AGPL already.

Commercial licences are annual, per organization, by headcount: USD 1,000 (50–249 people),
USD 4,000 (250–999), USD 10,000 (1,000–4,999), on request from 5,000. Every tier includes every
feature and unlimited servers. These are list prices; deployments with special requirements are
quoted individually. [LICENSING.md](LICENSING.md) explains how to count the
headcount, the rules for service providers and how to get a licence. Questions, or a price that
does not fit? E-mail licensing@radiusadmin.net; prices are open to discussion.
radius-admin is provided WITHOUT ANY WARRANTY; see the licence for details.

The release bundle also contains the `radius-admin-freeradius` package: FreeRADIUS, a separate
program under its own licence (GNU GPL version 2 or later; parts under the LGPL). Its upstream
source tarball and signature ship in the bundle's `packages/source/`, and its licence and
copyright notices are installed with it under
`/opt/radius-admin-freeradius/share/doc/radius-admin-freeradius/`. radius-admin runs and
configures FreeRADIUS; it does not link to it.

## Contributing

Contributions are welcome; please read [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests can
be merged once their author has accepted the [Contributor License Agreement](CLA.md).

---

radius-admin is made with ❤️ and a lot of `radiusd -X`.
