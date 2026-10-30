push-radius-admin: install a new radius-admin package on the RADIUS server from this PC.

  1. Download the new radius-admin.tar.gz to your Downloads folder.
  2. Double-click push-radius-admin.cmd (keep the .cmd and .ps1 in the same folder).
  3. Enter your SSH password (unless you use a key) and your sudo password when asked,
     check the plan the server prints, and answer y.

Other uses (from a terminal in this folder):
  push-radius-admin.cmd -List            releases on the server
  push-radius-admin.cmd -Rollback        go back to the previous release (web UI only)
  push-radius-admin.cmd -WithFreeradius  also install changed FreeRADIUS files
  push-radius-admin.cmd -Package C:\path\radius-admin.tar.gz

Full details, SSH key setup (ECDSA P-384; FIPS sshd rejects Ed25519): docs/RUNBOOK.md 9.0.
