-- radius-admin: session actions name their accounting record (SPEC section 24), so the
-- sessions page can show the latest request in the session's row. Idempotent, additive
-- only: an older release ignores the column, and old rows keep NULL.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 97-session-actions.sql
SET ROLE radius_owner;

ALTER TABLE ui.coa_request ADD COLUMN IF NOT EXISTS radacct_id bigint;
CREATE INDEX IF NOT EXISTS coa_request_radacct_idx ON ui.coa_request (radacct_id, id DESC)
	WHERE radacct_id IS NOT NULL;

RESET ROLE;
