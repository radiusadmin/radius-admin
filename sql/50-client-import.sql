-- radius-admin: RADIUS client CSV import support (idempotent).
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 50-client-import.sql
-- Adds per-client key status so clients imported without a usable plaintext key
-- (secret_type 'encrypted' or 'none') can be recorded but never rendered/enabled
-- until an operator sets a plaintext key.
SET ROLE radius_owner;

ALTER TABLE ui.radius_client ADD COLUMN IF NOT EXISTS key_status text NOT NULL DEFAULT 'ok';
ALTER TABLE ui.radius_client ADD COLUMN IF NOT EXISTS key_scope text;
ALTER TABLE ui.radius_client ADD COLUMN IF NOT EXISTS dot1x_ports text NOT NULL DEFAULT '';

DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'radius_client_key_status_chk') THEN
		ALTER TABLE ui.radius_client ADD CONSTRAINT radius_client_key_status_chk
			CHECK (key_status IN ('ok', 'encrypted', 'missing'));
	END IF;
	-- key_scope: 'server' (per-server key on the switch), 'global' (the switch's global
	-- radius-server key) or NULL (none). Earlier builds used 'host' for 'server'.
	ALTER TABLE ui.radius_client DROP CONSTRAINT IF EXISTS radius_client_key_scope_chk;
	UPDATE ui.radius_client SET key_scope = 'server' WHERE key_scope = 'host';
	ALTER TABLE ui.radius_client ADD CONSTRAINT radius_client_key_scope_chk
		CHECK (key_scope IS NULL OR key_scope IN ('server', 'global'));
	-- A client whose key is not a usable plaintext key can never be enabled
	-- (so it can never reach radius-admin-clients.conf).
	IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'radius_client_enabled_needs_key_chk') THEN
		ALTER TABLE ui.radius_client ADD CONSTRAINT radius_client_enabled_needs_key_chk
			CHECK (key_status = 'ok' OR NOT enabled);
	END IF;
END
$$;
RESET ROLE;
