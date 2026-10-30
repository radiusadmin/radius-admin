-- radius-admin: read-only SNMPv3 switch monitoring (idempotent).
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 60-snmp.sql
-- The poller (radius-admin-snmp.service, OS user radius-admin) polls every RADIUS
-- client over SNMPv3 authPriv and stores what it sees; the web app shows it.
-- Credentials are AES-256-GCM encrypted with the app data key (never stored in clear).
SET ROLE radius_owner;

CREATE TABLE IF NOT EXISTS ui.snmp_profile (
	id			integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	enabled			boolean NOT NULL DEFAULT false,
	username		text NOT NULL DEFAULT '' CHECK (username ~ '^[A-Za-z0-9._@-]{0,32}$'),
	auth_protocol		text NOT NULL DEFAULT 'SHA-256' CHECK (auth_protocol IN ('SHA-256', 'SHA-384', 'SHA-512')),
	auth_pass_enc		bytea,
	priv_protocol		text NOT NULL DEFAULT 'AES' CHECK (priv_protocol IN ('AES')),
	priv_pass_enc		bytea,
	poll_minutes		integer NOT NULL DEFAULT 15 CHECK (poll_minutes BETWEEN 5 AND 1440),
	auto_update_ports	boolean NOT NULL DEFAULT false,
	refresh_requested_at	timestamptz,
	updated_at		timestamptz NOT NULL DEFAULT now(),
	updated_by		text
);
INSERT INTO ui.snmp_profile (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Latest poll result per RADIUS client.
CREATE TABLE IF NOT EXISTS ui.switch_status (
	client_id		integer PRIMARY KEY REFERENCES ui.radius_client(id) ON DELETE CASCADE,
	polled_at		timestamptz NOT NULL DEFAULT now(),
	reachable		boolean NOT NULL,
	error			text NOT NULL DEFAULT '',
	sys_name		text NOT NULL DEFAULT '',
	sys_descr		text NOT NULL DEFAULT '',
	uptime_seconds		bigint,
	dot1x_supported		boolean NOT NULL DEFAULT false,
	dot1x_ports		text NOT NULL DEFAULT '',	-- ports with port-control auto, compressed (te1/0/1-20,te1/0/23)
	dot1x_port_count	integer NOT NULL DEFAULT 0,
	radius_servers		jsonb NOT NULL DEFAULT '[]'::jsonb
);

-- "Test this switch" requests from the UI, executed by the poller.
CREATE TABLE IF NOT EXISTS ui.snmp_test (
	id			serial PRIMARY KEY,
	client_id		integer NOT NULL REFERENCES ui.radius_client(id) ON DELETE CASCADE,
	requested_by		text,
	requested_at		timestamptz NOT NULL DEFAULT now(),
	done_at			timestamptz,
	ok			boolean,
	message			text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS snmp_test_pending_idx ON ui.snmp_test (requested_at) WHERE done_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON ui.snmp_profile TO radius_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ui.switch_status, ui.snmp_test TO radius_admin;
GRANT USAGE ON SEQUENCE ui.snmp_test_id_seq TO radius_admin;
RESET ROLE;

-- Which RADIUS clients are switches to poll (APs and other NAS devices are not polled).
SET ROLE radius_owner;
ALTER TABLE ui.radius_client ADD COLUMN IF NOT EXISTS is_switch boolean NOT NULL DEFAULT false;
RESET ROLE;
