# Contributing to radius-admin

Thank you for helping. Bug reports, fixes, vendor profiles and documentation are all welcome.

## Licence and the CLA

radius-admin is licensed under the GNU Affero General Public License, version 3 or later
([LICENSE](LICENSE)). Copyright is held by Collin Linde.

Before a contribution can be merged, its author must accept the
[Contributor License Agreement](CLA.md). You keep the copyright in your work; the CLA lets the
project offer its code under other terms as well (for example a commercial licence), while
everything that is merged also stays available under the open-source licence. To accept it,
tick the box in the pull request template and include this sentence in the pull request:

> I have read CLA.md (version 1.0) and I agree to it for my contributions to radius-admin.

If you contribute as part of your job, make sure your employer agrees (CLA section 5), and
name the organization in the pull request.

## Working on the code

- Branch from `dev` and open the pull request against `dev`; `main` holds released versions.
- Keep changes small and focused, with tests that fail without the change.
- Run the checks described in the README and in `tests/freeradius/README.md` in a sandbox or
  lab VM, never on a production server: the bench and some tests stop PostgreSQL and change
  `/etc/hosts`.
- `tools/site-scan.sh` must report "clean": no real host names, addresses, account names,
  secrets or device output. Use `example.net`/`example.com` and the documentation address
  ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
- `SPEC.md` is the contract between components; update it, and `docs/RUNBOOK.md` or
  `docs/SECURITY.md` where relevant, in the same pull request as the code.
- Only distribution packages at install and run time (no pip or npm), and FIPS-approved
  cryptography for anything new (see `docs/SECURITY.md`).

## Reporting security problems

Please do not open a public issue for a vulnerability. Contact the maintainer through the
repository's private security advisory ("Report a vulnerability") instead.
