# Changelog

Each release has a section here. `main` builds are the stable releases (`0.2.0`);
`testing` and `dev` builds are previews of the next one (`0.2.0-rc.3`, `0.2.0-dev.14`) and
show the "Unreleased" section plus their commits. Bump `VERSION` on `dev` right after a
release, so previews sort after it.

## Unreleased

### Added
- **Duo: send a test push.** Once Duo's settings are applied, an admin can send a Duo Push to a
  user from the Duo page and see whether it was approved, denied, not answered or the user is not
  enrolled. The server signs the request to Duo with SHA-512; at most one push per user every 30
  seconds and ten an hour.
- **Device profile for Cisco Catalyst 9000 switches (IOS-XE).** Built-in profile
  `cisco-iosxe`: VLAN by the standard tunnel attributes, full admin rights by
  `shell:priv-lvl=15`, session actions on UDP 1700 (re-authenticate, bounce port, disconnect)
  naming the session by accounting session id and MAC, and SNMP port names expanded to the
  names the switch sends in RADIUS (`Gi1/0/5` → `GigabitEthernet1/0/5`). Choose it per client
  or as the default.

### Changed
- **FIPS mode: FreeRADIUS uses the OpenSSL FIPS provider.** Upstream FreeRADIUS 3.2.10 loads
  OpenSSL's default provider even on a FIPS kernel, so EAP, password hashing and LDAPS in radiusd
  were not using the validated module. The bundled `radius-admin-freeradius` package (3.2.10-3)
  carries a patch that, in FIPS mode only, loads just the FIPS provider and refuses to start
  without it. Standard mode is unchanged. A password-protected EAP private key encrypted with
  parameters the FIPS provider rejects can no longer be read in FIPS mode; radius-admin's own keys
  are unencrypted and not affected.
- **LDAPS through OpenSSL with the bundled FreeRADIUS.** The `radius-admin-freeradius` package
  (3.2.10-2) links rlm_ldap against OpenLDAP built from the distribution's own source package
  with OpenSSL, instead of the distribution's GnuTLS libldap, so in FIPS mode the connection to
  the directory uses the OpenSSL FIPS provider. The package also carries `ra-ldapwhoami`, built
  the same way, for testing the directory login. OpenSSL is stricter than GnuTLS: domain
  controllers with SHA-1-signed or small-key certificates, or without TLS 1.2, are refused.
  Before installing or upgrading the package, the installer logs in to the directory with the
  new package's library; when only the new library fails, it stops, changes nothing and says
  why (for example "EE certificate key too weak"). `--skip-ldap-check` installs anyway.
  Servers on the distribution's FreeRADIUS are unchanged.
- **Auth log names MAB devices.** A MAB login from a registered device shows the device's
  description, with the MAC under it, in the list and on the record. The "User / device" filter
  also searches MAB descriptions.
- **Option to allow only catalog-checked Duo builds.** `integration_allow_unlisted = false` in
  `helper.conf` makes the helper refuse a Duo build that the signed catalog does not list, even
  with its SHA-256 entered. The default (`true`) keeps today's behaviour; FIPS mode refuses such
  builds either way.
- **Duo page: one button uploads a build.** "Upload a build…" picks Duo's source build and
  uploads it in one step (it goes to Ready to install; installing stays a separate step). Without
  JavaScript the page keeps the file field and the Upload button.
- **Duo: one button disables and removes it.** "Disable and remove Duo" turns the provider off,
  applies that and removes the proxy, after one confirmation. When a second-factor rule uses Duo,
  the page names it and the rule is turned off in the same action once you tick it. If something
  fails, the page shows the actual reason.
- **Duo: Save applies.** Saving the Duo settings shows what changes (Duo's configuration with
  secrets hidden, and which services restart), then saves and applies it and runs the connectivity
  check, all on the Duo page. When other changes are pending too, the dialog lists them and offers
  to apply everything from there (after a tick) or to save Duo only; it never applies part of
  them. A failed apply shows the reason. Test asks you to apply your Duo settings first instead
  of checking Duo's sample configuration.
- **Duo page: an Enabled / Disabled switch and hidden stored secrets.** The Duo provider is turned
  on and off with a switch that shows its state; when it cannot be changed (Duo not installed, or a
  second-factor rule uses it) the switch is greyed out with the reason next to it, instead of an
  error after Save. Once a secret key is stored the page shows "Secret key: set" with a "Change
  secret key" link to enter a new one; saving without it keeps the stored key. The edit form of a
  remote MFA server shows its shared secret the same way.

### Fixed
- **Re-authentication from a result page.** After the Duo check (or another result shown in
  place), an action that asked you to confirm your identity first ended in "Method Not Allowed"
  again. You now come back to the Duo page, or to the dashboard when there is no page to return to.
- **Duo test push: a refusal before any push no longer blocks a retry.** When Duo refuses a user
  before sending anything (for example no access to the application), the page now says "Refused
  by Duo before any push" instead of "Denied", and you can try again at once; the 30-second wait
  only follows a push that was sent.
- **Licence tool: issuing from the web page works.** `licence-tool.py serve` refused every form
  as a "cross-site request": its no-referrer policy made browsers send `Origin: null`.
- **Re-authentication no longer ends in "Method Not Allowed".** When an action such as Remove
  Duo asked you to confirm your identity first, the portal then sent you to the action's own
  address, which only accepts form posts. It now returns you to the page you were on.
- **Second factor: no silent device lockout.** Requiring a second factor for local device admins
  now needs an exempt break-glass account, or an explicit confirmation that there is none: while the
  provider is unreachable FreeRADIUS rejects these logins, so devices do not fall back to their own
  accounts.
- **Duo: the connection test and applying its configuration work on a real server.** The root
  helper's sandbox kept `/opt/duoauthproxy` read-only, so the Test button failed with "Read-only
  file system: 'log/connectivity_tool.log'" and applying a Duo configuration could not write
  `authproxy.cfg`; with that fixed, the test reported the running proxy's own port as "in use by
  an Unknown Process". The helper may now write Duo's `conf/` (nothing else of Duo), and
  runs Duo's connectivity tool in a sandbox of its own that can recognise the running proxy.
- **Duo: a failed install no longer leaves the proxy stopped.** The installer starts the proxy it
  stopped again when Duo's installer fails.
- **Provider secrets no longer pile up in clear.** The portal's history of applied files (which
  includes Duo's configuration with its secret key) now keeps the same 50 sets as the helper's
  backups instead of growing without limit, and seals every file it keeps with the data key: the
  policy, the clients file with the RADIUS shared secrets, Duo's configuration and the private keys of
  managed certificates. Copies from earlier versions are sealed by the next apply. Removing Duo
  keeps its configuration with the secrets replaced by `REDACTED`.
- **RADIUS client shared secrets are encrypted in the database.** They are stored with the data
  key (AES-256-GCM) instead of in clear; the update encrypts the existing ones, nothing has to be
  entered again, and the clients file FreeRADIUS reads is unchanged. Rolling back with
  `update.sh --rollback` (or downgrading) writes them back in clear first, so the older release
  keeps working.
- **No secrets left in the staging directory.** The files staged for the helper (clients file,
  Duo's configuration, certificate private keys) are removed as soon as the helper has read them,
  and the update removes the ones an older release left and encrypts its copies of applied files
  right away, not at the next apply.

## 0.3.0 - 2026-11-20

### Added
- **Install from a git clone.** `git clone` and `sudo radius-admin/deploy/install.sh` is the whole
  install: from a checkout, the installer downloads the release of the same version from GitHub,
  verifies its signed manifest (ECDSA P-384) and SHA-384, and continues with that release, which
  carries the FreeRADIUS package. `--from-checkout` installs a checkout as it is. The website's
  install steps show the two cases (new server, existing FreeRADIUS server).
- **A second factor for device admin logins (Integrations).** A new Integrations page sets which
  device admin logins must be approved with a second factor: local or directory accounts, on all
  clients or selected ones, with exempt break-glass accounts. First provider: a remote RADIUS MFA
  server (for example a Network Policy Server with the Entra multifactor extension, privacyIDEA or
  an Okta RADIUS agent) for directory accounts; FreeRADIUS still checks the management subnet first
  and the device admin group after the server's accept. Second provider: the Duo
  Authentication Proxy on this server (password checked here before the push; see below).
  Logins that need a second factor fail closed. Auth log methods `pap-admin+mfa` and `admin-ldap+mfa`.
- **Duo set up from the portal.** Integrations → Duo Authentication Proxy: check the server,
  download or upload Duo, install it with a live log, enter its keys, test the connection, remove
  it. Duo then serves local and directory device admin accounts; its configuration is applied, shown
  as a diff and rolled back together with FreeRADIUS's files.
- **Duo Authentication Proxy installer.** Builds Duo's source as an unprivileged user, installs it
  with a hardened systemd unit and configures it from the portal: applying changes writes Duo's
  configuration and restarts it before FreeRADIUS, restoring both if either fails. Removal and
  Duo's connectivity check through the root helper. Checked with Duo 6.8.1.
- **Signed integrations catalog.** Releases carry a catalog of provider builds this project has
  checked, signed with the update key. The root helper can download a provider build, check it
  against the catalog (or, outside FIPS mode, a SHA-256 the admin enters) and hand it to an install
  unit; FIPS mode accepts only builds the catalog lists as FIPS-capable.
- **Second-factor alerts.** Alerts when the Duo proxy stops or stops listening, when device admin
  logins get no answer from the second-factor provider (threshold and window in Alert settings),
  and once a day while the Duo build in use is unverified or was withdrawn from the signed catalog.
- **Second factor in reports and logs.** The privileged-access report shows per account whether a
  second factor is needed, by which provider and on which clients, and the break-glass exemptions;
  the auth log detail of a `+mfa` login names its provider; the setup checklist has an optional
  "Second factor for device admins" step; the Integrations page shows each device profile's RADIUS
  timeout commands (Catalyst 1200/1300: `radius-server timeout 30`, `retransmit 2`), and custom
  profiles have a field for them.
- **Certificates in the console.** A new Certificates page manages the 802.1X server certificate,
  the CA for client certificates, OCSP for EAP-TLS and the portal's HTTPS certificate. Upload a
  certificate and key (PEM or PKCS#12), or make the key and request on the server and upload what
  your CA issues. Keys are stored encrypted. Changes are installed with Apply: the helper checks
  them again, restarts FreeRADIUS, tests and reloads the portal, and puts everything back if either
  does not come up with them. RUNBOOK §13.5.
- **A new server installs from the release bundle.** On a server where FreeRADIUS was never set
  up by radius-admin and there is nothing to migrate, the installer now brings up a working,
  default-deny FreeRADIUS and the portal: no access rules needed yet, no directory yet (EAP-TLS and
  directory accounts are rejected until it is configured), the EAP certificates you give it
  (answers `eap_tls: existing`) or self-signed ones to replace, a new localhost secret instead of
  the stock one, and OCSP only when you name a responder (answers `ocsp_url`). The portal no
  longer needs an OCSP responder either. Fixes the stock `testing123` localhost secret being kept
  on such a server. RUNBOOK §13.4.
- **Licence page.** Settings → Licence records how a server is licensed under the Business Source
  License 1.1 (free use for individuals and organizations with fewer than 50 people, or
  commercial: a signed licence file, ECDSA P-384, checked offline, or a 60-day trial until it
  arrives). Answering is the first setup step; admins are taken to it at sign-in
  until it is answered, changes ask for confirmation and are listed on the page. Admins get one
  dashboard line when something needs attention; after a trial ends, a banner on every admin page. Nothing is ever locked or limited and the server never contacts anyone. Every
  page has a licence footer; the installer prints the notice and installs LICENSE and LICENSING.md.

### Changed
- **Licence: from the GNU AGPL to the Business Source License 1.1 (source available).**
  Free for personal use, for organizations with fewer than 50 people and for a 60-day trial;
  organizations with 50 or more people need a commercial licence for production use. Every
  feature stays in the same public code. Each version becomes GNU AGPL (version 3 or later)
  four years after it is published; 0.2.5 and earlier stay under the GNU AGPL. See
  `LICENSING.md`, which also lists the commercial licence prices. Contributor License
  Agreement version 1.1 (section 4).
- **Standard mode is the installer's default; FIPS mode is an explicit choice.** A fresh install
  on a host without FIPS no longer stops in preflight. Choose FIPS mode with the answers key
  `fips: on`, the new interactive question or `install.sh --fips` (`--standard-mode` / `fips: off`
  for standard mode); it is refused unless the host's kernel runs in FIPS mode. The choice is
  written as `require_fips` on the first install and never changed by later runs or updates.
  Preflight's FIPS checks block only in FIPS mode (`preflight.sh --fips-mode on|off`).
- An apply that also restarts the Duo proxy may take up to about three minutes; the portal, nginx
  and gunicorn now wait long enough for it (`helper_duo_timeout`, 210 s; 240 s in front).
- A Duo build the signed catalog marks FIPS-capable is now required in FIPS mode for turning Duo on
  and for every apply with Duo, not only for installing.
- **Duo in FIPS mode.** The signed catalog lists Duo Authentication Proxy 6.8.1 and marks it
  FIPS-capable, checked on Ubuntu 24.04 Pro `fips-updates` (amd64): Duo runs with its FIPS mode on
  its bundled OpenSSL FIPS Provider 3.1.2 (CMVP certificate #4985) for TLS to Duo. Its RADIUS hops
  on this server's loopback still use RADIUS's MD5, as FreeRADIUS does; SECURITY.md records this as
  a documented exception and lists the controls to put in place (§1.3).
- The Duo page shows a build as checked once a later catalog lists it, and flags a withdrawn build.
- The release workflow no longer puts tag-derived values into its scripts: the version and the
  previous release tag reach the signing job only as environment variables, are checked against
  exact patterns in both jobs, and a tag whose name is not an exact release tag is ignored
  (`tools/release/prev-tag.sh`). `make-release.sh` refuses such a previous tag too.

### Fixed
- **The bundled FreeRADIUS package did not install on a stock Ubuntu 24.04 server** (0.2.4 and
  0.2.5 too): built on a CI runner that carries apt.postgresql.org, it required
  `libpq5 (>= 18.7-1.pgdg24.04+2)`, and every other library at the runner's exact version. The
  package now takes minimum versions from `dpkg-shlibdeps`, the build refuses a dependency the
  distribution archive cannot meet, and CI builds against the distribution's libpq.
- **An interactive install stopped at "Install with these settings?"** with
  `confirm: command not found` and "aborted": every `install.sh` run without `-y` or an answers
  file failed there (since the first release). It now asks and goes ahead on `y`.
- **The suggested management subnet could be a /32 on the loopback interface** (on WSL, its DNS
  stub address), and the portal address with it. The installer now suggests the address of the
  interface that carries the default route, and never one on `lo`.
- `install.sh --interactive --print-answers > site.yaml` wrote the questions' help lines and
  warnings into the file, which `--answers` then refused ("expected 'key: value'"). They now go to
  stderr; the output is the answers only.
- Re-running the installer after a first install stopped part way: the set-up questions are asked
  again on a terminal when no answers were saved yet, whatever other options are given (before,
  any option such as `--skip-preflight` skipped them and the nginx phase stopped with
  "management subnet unknown"); preflight no longer blocks on the package's stock FreeRADIUS
  configuration of a new server; a PostgreSQL cluster created on another port than 5432 is
  named with the command that fixes it, and "PostgreSQL not ready" shows the end of its log.
- README: how to download the release bundle and check its signature and checksum before
  installing.
- **A second factor approved after 30 seconds was rejected.** FreeRADIUS's stock
  `max_request_time` (30 s) cut the Duo proxy's and remote MFA servers' wait of up to 60 s, so a
  person who approved later got "the second-factor provider did not answer". The freeradius phase
  now raises `max_request_time` in `radiusd.conf` to 90 s (a higher value is kept) and preflight
  warns when it is lower.

## 0.2.5 - 2026-11-20

### Added
- **Directory accounts for device admin logins.** Members of chosen directory groups can log in
  to switches, access points and firewalls with their directory password (LDAP bind over the
  existing LDAPS connection, nested groups included). Settings → Device admin logins turns it on
  and lists the groups; a local account of the same name always wins, and logins from outside
  the management subnet never reach the directory. Auth log method `admin-ldap` with the groups
  seen.

### Changed
- "Switch admins" are now **device admins** everywhere in the console. The page moved to
  `/device-admins/`; the old address redirects.
- The installer loads the SQL files in numeric order, so files numbered from 100 load last.

### Fixed
- **Upgrades no longer reset the EAP-TLS certificates and OCSP responder.** The freeradius
  phase installed the shipped `mods-available/eap` (`certs/site/…`, OCSP responder
  `pki.example.net`), so after an upgrade with `--with-freeradius` every EAP-TLS login was
  rejected with "Couldn't connect to OCSP responder". It now keeps the live certificate, CA,
  CRL and OCSP settings, as it does for LDAP. Affects 0.2.0 to 0.2.4: after such an upgrade,
  check `ocsp { url }` and the certificate paths in `mods-available/eap` against the backup
  the phase made (`/var/backups/radius-admin/freeradius-*.tar.gz`).
- Device profiles: "Used by" now counts the clients left on *Default*, under the default
  profile. They were counted only when a client named the profile itself.

## 0.2.4 - 2026-11-19

### Added
- **Vendor profiles.** Each RADIUS client has a device profile that decides the reply
  attributes for the VLAN, full admin rights and an optional role, the MAB port types, the CoA
  port, attributes and session naming, and the SNMP port-name rules. Built-in profiles:
  `cisco-c1300` (the default; output unchanged from 0.2.3) and `generic-rfc` (RFC 3580 VLAN,
  Filter-Id role, Service-Type admin rights, MAB from wired ports and access points, Disconnect
  on UDP 3799).
- **Device profiles** pages (admins, with step-up): list, view, create by copying, edit, delete
  (refused while in use), JSON export and import, and a dictionary check of attribute names.
  Settings has a default device profile; the RADIUS client CSV import takes an optional
  `vendor_profile` column.
- A role per access rule, sent with the role attributes of the client's profile, and MAB from
  wireless access points for profiles that allow it.
- A CoA port per RADIUS client. A CoA port changed under the old single setting is copied to
  the existing clients once.

### Changed
- The Administration group in the side panel is replaced by a single **Settings** button at the
  bottom of the panel (admins only; it carries the update badge). It opens an overview of the
  settings pages by category: RADIUS and switches, Console access, Notifications (alert
  settings, previously reachable only from the Alerts page) and Maintenance.
- The Sessions page offers only the actions the session's device supports.

### Fixed
- Form fields carried `aria-describedby` twice, so screen readers lost the error message of an
  invalid field.

### Security
- nginx security floor: preflight warns when nginx is older than `1.24.0-2ubuntu7.20` (Ubuntu's
  fix for the HTTP/2 and TLS 1.3 vulnerabilities of 2026-11-18, CVE-2026-123007,
  CVE-2026-123633, CVE-2026-118899), and the new installer phase `nginx-update`, which updates
  also run when needed, upgrades nginx from the package mirror and restarts it.

## 0.2.3 - 2026-11-19

### Added
- Session actions for several sessions at once: tick the sessions (or the whole page) and choose
  Re-authenticate, Bounce port or Disconnect in the bar above the table.
- **Session actions** in the menu: every request of the last 90 days with its result, filters,
  and a page per request with the switch's answer and the request's details.

### Changed
- dev builds are no longer published on every push: start one from Actions → Release → Run
  workflow on `dev`. testing and dev keep their newest 3 builds instead of 10.
- A session action no longer opens a page of its own. The session's row shows "Sending…" and
  then Done or Failed, linked to the details.
- "Last 30 days, including ended" offers the actions for sessions that are still up.
- Going back to a list keeps its filters and page: Back and Cancel links and the return after a
  row action, on Sessions, Session actions, the authentication log, RADIUS clients, MAB devices,
  unknown devices and alerts. The menu links still open the plain list.
- When a switch does not answer a session action, the other requests waiting for that switch are
  marked "Not sent" right away instead of each waiting for its own timeout.

### Fixed
- Session actions (Re-authenticate, Bounce port, Disconnect) work on Catalyst 1300 switches. The
  switch refused them with "CoA-NAK: Session-Context-Not-Found" because the request also named
  the accounting session id; it now names the session by the device's MAC and port (the
  session id only when there is no MAC).

## 0.2.2 — 2026-11-04

### Changed
- Pages that wait for something no longer reload every few seconds: Check now and Install on
  the Updates page, SNMP tests, session actions (CoA), Refresh now on the switch monitoring
  page and the test alert show a spinner and update once, when the result is there. Buttons
  for slow actions (Validate, Apply, Roll back) show a spinner while the server works.
- Confirmations (delete, apply, roll back, role changes, …) open in the console's own dialog
  instead of the browser's pop-up box, with the action named on the button.
- The Updates page has a **Details** drop-down with the install log, live while an update runs.
  During the update to 0.2.2 itself the page shows the steps only (the log needs the new root
  helper); it works from the next update on.

### Fixed
- The "1" next to Updates in the menu goes away as soon as the update is installed; it used to
  stay until the next update check.

## 0.2.1 — 2026-11-04

### Fixed
- Updates keep how the server trusts the directory: the TLS settings of the LDAP module
  (`ca_file`, `ca_path`, client certificate, `start_tls`, `require_cert`, `check_crl`) and
  its `port` come from the installed `mods-available/ldap`, like the bind account, search
  base and server already did. An update to 0.2.0 failed on servers whose directory CA is not
  at the package's `certs/site/ca.pem` ("Unable to check file … ca_file"; the previous
  configuration was restored). The AD login test before installing now names a missing CA
  file instead of reporting "Can't contact LDAP server".

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
