-- radius-admin: "Portal down" alert (nginx not active or not listening on TCP 443), raised by
-- the monitor from the root helper's status (SPEC section 13). Idempotent, additive only:
-- the alert kind list only grows, so an older release still accepts every row.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 96-portal-alert.sql
SET ROLE radius_owner;

ALTER TABLE ui.alert_settings ADD COLUMN IF NOT EXISTS portal_enabled boolean NOT NULL DEFAULT true;

ALTER TABLE ui.alert DROP CONSTRAINT IF EXISTS alert_kind_check;
ALTER TABLE ui.alert ADD CONSTRAINT alert_kind_check
	CHECK (kind IN ('reject_spike', 'switch_down', 'radius_down', 'portal_down', 'monitor_down', 'test'));

RESET ROLE;
