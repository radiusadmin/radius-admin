-- radius-admin: updates from signed GitHub builds (SPEC section 16). Idempotent, additive only.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 90-updates.sql
SET ROLE radius_owner;

-- update_channel: main (stable releases) | testing | dev
-- update_mode:    off (never contacts GitHub) | notify (check daily) | auto (install by itself;
--                 updates that restart FreeRADIUS wait for the weekly window)
-- update_window_day / _hour: the window for those, in the server's local time
INSERT INTO ui.setting (key, value) VALUES
	('update_channel', 'main'),
	('update_mode', 'notify'),
	('update_window_day', 'sun'),
	('update_window_hour', '3')
ON CONFLICT (key) DO NOTHING;

-- The last check, written by the update check service (radius_admin.updater).
-- releases: builds on the channel newer than the installed one, newest first:
--   [{"version", "published", "notes", "restarts_freeradius"}]
CREATE TABLE IF NOT EXISTS ui.update_check (
	id			integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	checked_at		timestamptz NOT NULL DEFAULT now(),
	ok			boolean NOT NULL,
	error			text NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
	channel			text NOT NULL DEFAULT '' CHECK (channel IN ('', 'main', 'testing', 'dev')),
	installed_version	text NOT NULL DEFAULT '' CHECK (length(installed_version) <= 40),
	latest_version		text NOT NULL DEFAULT '' CHECK (length(latest_version) <= 40),
	downgrade		boolean NOT NULL DEFAULT false,
	restarts_freeradius	boolean NOT NULL DEFAULT false,
	downloaded		boolean NOT NULL DEFAULT false,
	releases		jsonb NOT NULL DEFAULT '[]'::jsonb
);

GRANT SELECT, INSERT, UPDATE ON ui.update_check TO radius_admin;
