# Changelog

Each release has a section here. `main` builds are the stable releases (`0.2.0`);
`testing` and `dev` builds are previews of the next one (`0.2.0-rc.3`, `0.2.0-dev.14`) and
show the "Unreleased" section plus their commits. Bump `VERSION` on `dev` right after a
release, so previews sort after it.

## 0.2.0 — 2026-11-04

### Added
- 802.1X with a username and password: EAP-TTLS with PAP inside, for local 802.1X users
  (new 802.1X users page) and, optionally, directory accounts checked with an LDAP bind as
  the user. Both are off by default in Settings. The access rules assign the VLAN by the
  user's groups (local, or directory groups including nested ones); the auth log shows the
  name typed inside the tunnel. PEAP-MSCHAPv2 is available too, for local users who allow
  it (it needs an NT hash of their password, so it is weaker; never with FIPS mode) and for
  directory accounts once the server has joined the domain (`deploy/ad-join.sh`). Needs
  the freeradius install phase and a FreeRADIUS restart.
- Licence: GNU AGPL version 3 or later (copyright Collin Linde), with a Contributor License
  Agreement for outside contributions (`CLA.md`, `CONTRIBUTING.md`, pull request template).
- "Portal down" alert: the monitor alerts (syslog, email) when nginx is not active or not
  listening on port 443 for two checks in a row, on servers where the portal's nginx site is
  enabled. On by default; switch it off in Alert settings. Updates also check that nginx
  serves the portal and roll back if it does not.
- Auth log, audit log and sessions: numbered pages ("51–100 of 1,234", Previous 1 … 4 5 6 …
  Next) instead of Newer/Older; sessions show 50 per page.

### Fixed
- The portal no longer stays down when nginx fails to start because DNS was briefly
  unavailable (nginx looks up the OCSP responder when it starts, for example when
  unattended-upgrades restarts it). nginx now starts after the network is up and retries
  every 30 seconds; the drop-in is installed by the nginx phase.
- A MAC that connected with 802.1X is reported as such when the switch tries MAB ("authenticates
  with 802.1X"), for passwords as for certificates.
- Switch page, 802.1X ports: the VLAN column shows the VLAN RADIUS assigned to the connected
  device (it showed the port's native VLAN, usually 1); "native" marks the fallback and "—" a
  port without a device. 802.1X user names longer than 16 characters are shown in full
  instead of as raw hexadecimal.

## 0.1.1 — 2026-11-03

### Added
- Updates page: current and latest version, changelog, update channel (main, testing,
  dev) and automatic updates. Builds are signed in CI and verified by the root helper
  before anything is installed.
- Switch networks (`switch_nets` in the installer answers, `--switch-nets`): the monitor may
  reach switches in several networks for SNMP and CoA, not only the management subnet.

### Fixed
- `install.sh --phase app` without answers (and updates) no longer resets the monitor's
  allowed network to the `192.0.2.0/24` example; it keeps the installed list.
- A switch outside the allowed networks is reported as such, instead of Net-SNMP's
  "Unknown engine ID (Operation not permitted)" with advice about the switch.
- Updates that change the nginx site or firewall template keep the server's management
  subnet, portal address, server name, resolvers and OCSP responder (from `site.yaml`, else
  the installed nginx site or firewall table) instead of the example defaults, which could
  stop the update or restrict the portal to the example subnet. Command-line options win over
  answers files; `install.sh --print-settings` shows what a run would use.

## 0.1.0 — 2026-11-02

First release of the universal edition.

### Added
- RADIUS clients with CSV import, access rules (directory group → VLAN), MAB with an
  approval queue, switch-admin logins, custom policy with validate, apply and rollback.
- Sessions and change of authorization, SNMPv3 switch monitoring, alerts, reports and a
  hash-chained audit log.
- Console accounts with mandatory MFA, roles and step-up; SAML single sign-on.
- RadSec (RADIUS over TLS) per client.
- Interactive installer and answers file, setup checklist, light and dark theme.
- The `radius-admin-freeradius` package: FreeRADIUS 3.2.10 from the signed upstream
  release, installed by the installer on a server without FreeRADIUS.
