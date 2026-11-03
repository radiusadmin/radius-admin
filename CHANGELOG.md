# Changelog

Each release has a section here. `main` builds are the stable releases (`0.2.0`);
`testing` and `dev` builds are previews of the next one (`0.2.0-rc.3`, `0.2.0-dev.14`) and
show the "Unreleased" section plus their commits. Bump `VERSION` on `dev` right after a
release, so previews sort after it.

## Unreleased

### Added
- Licence: GNU AGPL version 3 or later (copyright Collin Linde), with a Contributor License
  Agreement for outside contributions (`CLA.md`, `CONTRIBUTING.md`, pull request template).
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

### Fixed
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
