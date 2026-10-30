-- radius-admin: operations features (idempotent).
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 70-operations.sql
--   * authentication detail columns in radpostauth (reason, client certificate,
--     NAS port, AD groups, matched access rule)
--   * MAB: expiry dates and the unknown-device queue (radius_admin_mab_hex)
--   * per-port 802.1X status, alerts, monitor heartbeat
--   * CoA / Disconnect requests queued by the UI and sent by the monitor service
SET ROLE radius_owner;

-- ---------------------------------------------------------------- authentication detail
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS reason text;
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS nasportid text;
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS cert_cn text;
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS cert_subject text;
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS cert_issuer text;
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS cert_serial text;
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS cert_expiry text;      -- as sent by FreeRADIUS (YYMMDDhhmmssZ)
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS ad_groups_hex text;    -- ",<hex(cn)>,..." exactly as passed to the rule matcher
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS rule_id integer;       -- ui.access_rule.id that assigned the VLAN
CREATE INDEX IF NOT EXISTS radpostauth_csi_idx ON radpostauth (callingstationid);
CREATE INDEX IF NOT EXISTS radpostauth_reject_idx ON radpostauth (authdate) WHERE reply = 'Access-Reject';

-- ---------------------------------------------------------------- live sessions
CREATE INDEX IF NOT EXISTS radacct_open_nas_idx ON radacct (nasipaddress) WHERE acctstoptime IS NULL;
CREATE INDEX IF NOT EXISTS radacct_csi_idx ON radacct (callingstationid);
CREATE INDEX IF NOT EXISTS radacct_start_idx ON radacct (acctstarttime);

-- ---------------------------------------------------------------- MAB
ALTER TABLE mab_device ADD COLUMN IF NOT EXISTS expires_at timestamptz;

-- MACs that tried MAB and are not registered. Written only by radius_admin_mab_hex()
-- (SECURITY DEFINER), bounded to 2000 rows so a flood of random MACs cannot grow it.
CREATE TABLE IF NOT EXISTS mab_pending (
	mac		text PRIMARY KEY CHECK (mac ~ '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$'),
	first_seen	timestamptz NOT NULL DEFAULT now(),
	last_seen	timestamptz NOT NULL DEFAULT now(),
	attempts	integer NOT NULL DEFAULT 1,
	nas_ip		inet,
	nas_port_id	text,
	ignored		boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS mab_pending_seen_idx ON mab_pending (last_seen);

-- MAB decision for FreeRADIUS. p_mac is the normalized AA-BB-CC-DD-EE-FF built by the
-- policy from regex captures (hex digits and dashes only); NAS address and port are
-- passed hex-encoded (see 40-live-policy.sql for why). Returns:
--   '<vlan>'    registered, enabled, not expired -> accept into that VLAN
--   'disabled'  registered but disabled          -> reject
--   'expired'   registration expired              -> reject
--   'unknown'   not registered (recorded in mab_pending) -> reject
--   NULL        malformed input                   -> reject
CREATE OR REPLACE FUNCTION public.radius_admin_mab_hex(p_mac text, p_nas_hex text, p_port_hex text)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	d record;
	v_nas inet;
	v_port text;
	v_bytes bytea;
BEGIN
	IF p_mac IS NULL OR p_mac !~ '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$' THEN
		RETURN NULL;
	END IF;
	SELECT vlan, enabled, expires_at INTO d FROM mab_device WHERE mac = p_mac;
	IF FOUND THEN
		IF NOT d.enabled THEN
			RETURN 'disabled';
		END IF;
		IF d.expires_at IS NOT NULL AND d.expires_at <= now() THEN
			RETURN 'expired';
		END IF;
		RETURN d.vlan::text;
	END IF;
	-- Unknown: remember it for the approval queue (best effort; never blocks the reply).
	BEGIN
		IF p_nas_hex ~ '^[0-9a-fA-F]{8}$' THEN
			v_bytes := decode(p_nas_hex, 'hex');
			v_nas := (get_byte(v_bytes, 0) || '.' || get_byte(v_bytes, 1) || '.' ||
				  get_byte(v_bytes, 2) || '.' || get_byte(v_bytes, 3))::inet;
		END IF;
		v_port := left(radius_admin_unhex(coalesce(p_port_hex, '')), 64);
		IF EXISTS (SELECT 1 FROM mab_pending WHERE mac = p_mac) THEN
			UPDATE mab_pending SET last_seen = now(), attempts = least(attempts + 1, 1000000000),
				nas_ip = coalesce(v_nas, nas_ip), nas_port_id = coalesce(nullif(v_port, ''), nas_port_id)
			WHERE mac = p_mac;
		ELSIF (SELECT count(*) FROM mab_pending) < 2000 THEN
			INSERT INTO mab_pending (mac, nas_ip, nas_port_id) VALUES (p_mac, v_nas, nullif(v_port, ''))
			ON CONFLICT (mac) DO NOTHING;
		END IF;
	EXCEPTION WHEN others THEN
		NULL;
	END;
	RETURN 'unknown';
EXCEPTION WHEN others THEN
	RETURN NULL;
END
$$;

-- Same matcher as radius_admin_vlan_hex() but returns '<vlan>:<rule id>' so the
-- authentication log can record which rule assigned the VLAN.
CREATE OR REPLACE FUNCTION public.radius_admin_vlan_rule_core(p_wired boolean, p_called_station_id text, p_groups text[])
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
	SELECT r.vlan::text || ':' || r.id::text
	FROM ui.access_rule r
	WHERE r.enabled
	  AND p_wired IS NOT NULL
	  AND lower(r.ad_group) = ANY (SELECT lower(g) FROM unnest(coalesce(p_groups, ARRAY[]::text[])) AS g)
	  AND CASE
		WHEN p_wired THEN r.connection = 'wired'
		ELSE r.connection = 'wireless'
		     AND r.ssid IS NOT NULL
		     AND coalesce(p_called_station_id, '') <> ''
		     AND right(p_called_station_id, length(r.ssid) + 1) = ':' || r.ssid
	      END
	ORDER BY r.priority, r.id
	LIMIT 1
$$;

CREATE OR REPLACE FUNCTION public.radius_admin_vlan_rule_hex(p_wired boolean, p_csi_hex text, p_groups_hex text)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_csi text;
	v_groups text[];
	v_item text;
	v_name text;
BEGIN
	IF p_wired IS NULL OR p_groups_hex IS NULL OR p_groups_hex !~ '^(,[0-9a-fA-F]*)*$' THEN
		RETURN NULL;
	END IF;
	v_csi := radius_admin_unhex(coalesce(p_csi_hex, ''));
	IF v_csi IS NULL THEN
		RETURN NULL;
	END IF;
	v_groups := ARRAY[]::text[];
	FOREACH v_item IN ARRAY string_to_array(substr(p_groups_hex, 2), ',') LOOP
		v_name := radius_admin_unhex(v_item);
		IF v_name IS NULL THEN
			RETURN NULL;
		END IF;
		IF v_name <> '' THEN
			v_groups := v_groups || v_name;
		END IF;
	END LOOP;
	RETURN radius_admin_vlan_rule_core(p_wired, v_csi, v_groups);
EXCEPTION WHEN others THEN
	RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION public.radius_admin_mab_hex(text, text, text) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_vlan_rule_core(boolean, text, text[]) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_vlan_rule_hex(boolean, text, text) FROM PUBLIC, radius_fr, radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_mab_hex(text, text, text) TO radius_fr;
GRANT EXECUTE ON FUNCTION public.radius_admin_vlan_rule_hex(boolean, text, text) TO radius_fr;

GRANT SELECT, UPDATE, DELETE ON mab_pending TO radius_admin;

-- ---------------------------------------------------------------- per-port 802.1X status
ALTER TABLE ui.switch_status ADD COLUMN IF NOT EXISTS fail_count integer NOT NULL DEFAULT 0;
ALTER TABLE ui.switch_status ADD COLUMN IF NOT EXISTS ports jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE ui.switch_status ADD COLUMN IF NOT EXISTS last_ok_at timestamptz;

-- ---------------------------------------------------------------- alerts
CREATE TABLE IF NOT EXISTS ui.alert_settings (
	id			integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	syslog_enabled		boolean NOT NULL DEFAULT true,
	email_enabled		boolean NOT NULL DEFAULT false,
	smtp_host		text NOT NULL DEFAULT '' CHECK (smtp_host ~ '^[A-Za-z0-9.:\-]{0,253}$'),
	smtp_port		integer NOT NULL DEFAULT 25 CHECK (smtp_port BETWEEN 1 AND 65535),
	smtp_security		text NOT NULL DEFAULT 'starttls' CHECK (smtp_security IN ('starttls', 'tls', 'none')),
	smtp_user		text NOT NULL DEFAULT '',
	smtp_pass_enc		bytea,
	mail_from		text NOT NULL DEFAULT '',
	mail_to			text NOT NULL DEFAULT '',
	reject_enabled		boolean NOT NULL DEFAULT true,
	reject_threshold	integer NOT NULL DEFAULT 25 CHECK (reject_threshold BETWEEN 1 AND 100000),
	reject_window_minutes	integer NOT NULL DEFAULT 5 CHECK (reject_window_minutes BETWEEN 1 AND 1440),
	switch_enabled		boolean NOT NULL DEFAULT true,
	switch_failed_polls	integer NOT NULL DEFAULT 2 CHECK (switch_failed_polls BETWEEN 1 AND 20),
	radius_enabled		boolean NOT NULL DEFAULT true,
	test_requested_at	timestamptz,
	test_requested_by	text,
	updated_at		timestamptz NOT NULL DEFAULT now(),
	updated_by		text
);
INSERT INTO ui.alert_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
ALTER TABLE ui.alert_settings ADD COLUMN IF NOT EXISTS test_requested_by text;

CREATE TABLE IF NOT EXISTS ui.alert (
	id		serial PRIMARY KEY,
	kind		text NOT NULL CHECK (kind IN ('reject_spike', 'switch_down', 'radius_down', 'monitor_down', 'test')),
	subject		text NOT NULL DEFAULT '',		-- e.g. the switch's client id
	state		text NOT NULL CHECK (state IN ('open', 'resolved')),
	opened_at	timestamptz NOT NULL DEFAULT now(),
	resolved_at	timestamptz,
	message		text NOT NULL,
	detail		jsonb NOT NULL DEFAULT '{}'::jsonb,
	notified	text NOT NULL DEFAULT ''		-- channels that accepted the notification / errors
);
CREATE UNIQUE INDEX IF NOT EXISTS alert_one_open_idx ON ui.alert (kind, subject) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS alert_opened_idx ON ui.alert (opened_at);

-- One row: the monitor service's heartbeat and its last FreeRADIUS check.
CREATE TABLE IF NOT EXISTS ui.monitor_state (
	id			integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	heartbeat_at		timestamptz,
	radius_checked_at	timestamptz,
	radius_ok		boolean,
	radius_message		text NOT NULL DEFAULT '',
	radclient		text NOT NULL DEFAULT ''	-- path found, or why CoA is unavailable
);
INSERT INTO ui.monitor_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------- CoA / Disconnect
CREATE TABLE IF NOT EXISTS ui.coa_request (
	id			serial PRIMARY KEY,
	client_id		integer NOT NULL REFERENCES ui.radius_client(id) ON DELETE CASCADE,
	action			text NOT NULL CHECK (action IN ('reauth', 'disconnect', 'bounce')),
	acct_session_id		text NOT NULL DEFAULT '',
	calling_station_id	text NOT NULL DEFAULT '',
	nas_ip			inet NOT NULL,
	nas_port_id		text NOT NULL DEFAULT '',
	username		text NOT NULL DEFAULT '',
	requested_by		text,
	requested_at		timestamptz NOT NULL DEFAULT now(),
	done_at			timestamptz,
	ok			boolean,
	message			text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS coa_request_pending_idx ON ui.coa_request (requested_at) WHERE done_at IS NULL;

ALTER TABLE ui.snmp_profile ADD COLUMN IF NOT EXISTS coa_port integer NOT NULL DEFAULT 1700 CHECK (coa_port BETWEEN 1 AND 65535);

GRANT SELECT, UPDATE ON ui.alert_settings, ui.monitor_state TO radius_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ui.alert, ui.coa_request TO radius_admin;
GRANT USAGE ON SEQUENCE ui.alert_id_seq, ui.coa_request_id_seq TO radius_admin;
RESET ROLE;
