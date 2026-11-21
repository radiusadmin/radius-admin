# Second-factor provider integrations

Installed with radius-admin into `/opt/radius-admin/integrations/` (SPEC section 29).

- `catalog.json`: the provider builds this project has checked. Each release signs it with the
  update signing key (`catalog.json.sig`, made by `tools/release/make-release.sh`); the root
  helper accepts a build only when it matches a signed entry, or, in standard mode only, a
  SHA-256 the admin enters. In FIPS mode only entries with `"fips": true` count. The `serial`
  only grows: the helper keeps the newest catalog it has seen, so an older release cannot bring
  back a withdrawn build.
- `<provider>/install.sh`: the installer the root helper's install unit runs for a checked build.

Edit the catalog only with `tools/integrations/catalog.py` (it bumps the serial):

    tools/integrations/catalog.py add duo 6.7.0 path/to/duoauthproxy-6.7.0-src.tgz
    tools/integrations/catalog.py fips duo 6.7.0 ubuntu-24.04-pro-fips   # after the FIPS VM check
    tools/integrations/catalog.py withdraw duo 6.6.0
    tools/integrations/catalog.py check
