-- radius-admin: RADIUS client shared secrets sealed at rest (SPEC section 3.2).
-- secret_enc: AES-256-GCM (data key) of the shared secret; `secret` is '' once sealed. The app
-- seals plain secrets in its install/update step (python3 -m radius_admin.cli seal-client-secrets)
-- and update.sh writes them back in plain (unseal-client-secrets) before it starts a release that
-- does not read secret_enc. FreeRADIUS never reads this table (it reads the rendered clients file).
-- Idempotent, additive only: an older release ignores the column.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 103-client-secrets.sql
SET ROLE radius_owner;

ALTER TABLE ui.radius_client ADD COLUMN IF NOT EXISTS secret_enc bytea;

RESET ROLE;
