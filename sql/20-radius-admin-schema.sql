-- radius-admin application schema. Run as postgres, connected to database radius:
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 20-radius-admin-schema.sql
SET ROLE radius_owner;
CREATE SCHEMA IF NOT EXISTS ui AUTHORIZATION radius_owner;
REVOKE ALL ON SCHEMA ui FROM PUBLIC;

CREATE TABLE IF NOT EXISTS ui.admin_user (
	id			serial PRIMARY KEY,
	username		text UNIQUE NOT NULL CHECK (username ~ '^[a-z0-9._-]{2,64}$'),
	display_name		text NOT NULL DEFAULT '',
	role			text NOT NULL CHECK (role IN ('viewer','operator','admin')),
	password_hash		text NOT NULL,
	password_changed_at	timestamptz NOT NULL DEFAULT now(),
	must_change_password	boolean NOT NULL DEFAULT true,
	failed_count		integer NOT NULL DEFAULT 0,
	locked_until		timestamptz,
	mfa_method		text CHECK (mfa_method IN ('totp','cert')),
	totp_secret_enc		bytea,
	totp_last_step		bigint,
	cert_sha256		text,
	cert_subject		text,
	enabled			boolean NOT NULL DEFAULT true,
	last_login_at		timestamptz,
	last_login_ip		inet,
	created_at		timestamptz NOT NULL DEFAULT now(),
	updated_at		timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS admin_user_cert_sha256_uq ON ui.admin_user (cert_sha256) WHERE cert_sha256 IS NOT NULL;

CREATE TABLE IF NOT EXISTS ui.password_history (
	id			serial PRIMARY KEY,
	user_id			integer NOT NULL REFERENCES ui.admin_user(id) ON DELETE CASCADE,
	password_hash		text NOT NULL,
	created_at		timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ui.session (
	id			serial PRIMARY KEY,
	token_sha256		text UNIQUE NOT NULL,
	user_id			integer NOT NULL REFERENCES ui.admin_user(id) ON DELETE CASCADE,
	created_at		timestamptz NOT NULL DEFAULT now(),
	last_seen_at		timestamptz NOT NULL DEFAULT now(),
	mfa_ok			boolean NOT NULL DEFAULT false,
	stepup_at		timestamptz,
	csrf_token		text NOT NULL,
	ip			inet,
	user_agent		text
);
CREATE INDEX IF NOT EXISTS session_user_idx ON ui.session (user_id);

CREATE TABLE IF NOT EXISTS ui.login_attempt (
	id			bigserial PRIMARY KEY,
	ip			inet,
	username		text,
	success			boolean NOT NULL,
	at			timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS login_attempt_ip_at_idx ON ui.login_attempt (ip, at);

CREATE TABLE IF NOT EXISTS ui.radius_client (
	id			serial PRIMARY KEY,
	name			text UNIQUE NOT NULL CHECK (name ~ '^[A-Za-z0-9._-]{1,63}$'),
	ipaddr			text NOT NULL,
	secret			text NOT NULL,
	require_ma		text NOT NULL DEFAULT 'auto' CHECK (require_ma IN ('yes','no','auto')),
	limit_proxy_state	text NOT NULL DEFAULT 'auto' CHECK (limit_proxy_state IN ('yes','no','auto')),
	nas_type		text NOT NULL DEFAULT 'other',
	description		text NOT NULL DEFAULT '',
	enabled			boolean NOT NULL DEFAULT true,
	created_at		timestamptz NOT NULL DEFAULT now(),
	updated_at		timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ui.access_rule (
	id			serial PRIMARY KEY,
	priority		integer NOT NULL,
	connection		text NOT NULL CHECK (connection IN ('wired','wireless')),
	ssid			text,
	ad_group		text NOT NULL,
	vlan			integer NOT NULL CHECK (vlan BETWEEN 1 AND 4094),
	description		text NOT NULL DEFAULT '',
	enabled			boolean NOT NULL DEFAULT true,
	created_at		timestamptz NOT NULL DEFAULT now(),
	updated_at		timestamptz NOT NULL DEFAULT now(),
	CHECK ((connection = 'wireless') = (ssid IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS ui.setting (
	key			text PRIMARY KEY,
	value			text NOT NULL,
	updated_at		timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ui.apply_log (
	id			serial PRIMARY KEY,
	at			timestamptz NOT NULL DEFAULT now(),
	actor			text,
	action			text NOT NULL,
	policy_sha256		text,
	clients_sha256		text,
	success			boolean NOT NULL,
	message			text,
	backup_id		text
);

CREATE TABLE IF NOT EXISTS ui.audit_log (
	id			bigserial PRIMARY KEY,
	at			timestamptz NOT NULL DEFAULT now(),
	actor			text,
	actor_ip		inet,
	action			text NOT NULL,
	object_type		text,
	object_id		text,
	detail			jsonb,
	success			boolean NOT NULL,
	prev_hash		text NOT NULL,
	hash			text NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_at_idx ON ui.audit_log (at);

-- Append-only audit log: refuse UPDATE / DELETE / TRUNCATE for everyone except the owner
-- performing explicit maintenance with the trigger disabled.
CREATE OR REPLACE FUNCTION ui.audit_log_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
	RAISE EXCEPTION 'ui.audit_log is append-only';
END
$$;
DROP TRIGGER IF EXISTS audit_log_no_update ON ui.audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON ui.audit_log
	FOR EACH ROW EXECUTE FUNCTION ui.audit_log_immutable();
DROP TRIGGER IF EXISTS audit_log_no_truncate ON ui.audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON ui.audit_log
	FOR EACH STATEMENT EXECUTE FUNCTION ui.audit_log_immutable();

INSERT INTO ui.setting (key, value) VALUES
	('admin_subnet', '192.0.2.0/24'),
	('admin_priv15', 'false'),
	('custom_policy', ''),
	('banner_text', 'This system is for authorized use only. Activity on this system is monitored and recorded. By continuing, you consent to this monitoring and acknowledge that unauthorized use may result in disciplinary action and/or civil and criminal penalties.')
ON CONFLICT (key) DO NOTHING;
RESET ROLE;
