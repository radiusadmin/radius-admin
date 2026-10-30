-- radius-admin universal edition: schema additions (idempotent, additive only).
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 80-universal.sql
--   * per-user colour theme
--   * RadSec (RADIUS over TLS) per client, plus the server-wide listener settings
SET ROLE radius_owner;

-- ---------------------------------------------------------------- colour theme
-- 'system' follows the browser's prefers-color-scheme; 'light'/'dark' override it.
ALTER TABLE ui.admin_user ADD COLUMN IF NOT EXISTS theme text NOT NULL DEFAULT 'system'
	CHECK (theme IN ('system','light','dark'));

-- ---------------------------------------------------------------- RadSec
-- transport 'radsec': the client connects over TLS (TCP 2083) with a certificate from
-- the site CA; its shared secret is the fixed RFC 6614 value, so `secret` is unused.
-- radsec_peer_name: expected certificate CN or DNS name ('' = any certificate of the CA).
ALTER TABLE ui.radius_client ADD COLUMN IF NOT EXISTS transport text NOT NULL DEFAULT 'udp'
	CHECK (transport IN ('udp','radsec'));
ALTER TABLE ui.radius_client ADD COLUMN IF NOT EXISTS radsec_peer_name text NOT NULL DEFAULT ''
	CHECK (length(radsec_peer_name) <= 253);
INSERT INTO ui.setting (key, value) VALUES
	('radsec_enabled', 'false'),
	('radsec_listen', '*'),
	('radsec_port', '2083'),
	('radsec_max_connections', '16'),
	('radsec_idle_timeout', '30'),
	('radsec_ocsp', 'false'),
	('radsec_ocsp_url', '')
ON CONFLICT (key) DO NOTHING;

-- ---------------------------------------------------------------- SAML single sign-on
-- auth_source 'saml': created at first SSO sign-in; password_hash holds a marker that never
-- verifies, the role is recomputed from the group claims at every sign-in.
ALTER TABLE ui.admin_user ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'
	CHECK (auth_source IN ('local','saml'));
ALTER TABLE ui.admin_user ADD COLUMN IF NOT EXISTS saml_name_id text;
CREATE UNIQUE INDEX IF NOT EXISTS admin_user_saml_name_id_uq ON ui.admin_user (saml_name_id)
	WHERE saml_name_id IS NOT NULL;

-- Group claim value (Entra: group object ID) -> portal role. Highest matching role wins.
CREATE TABLE IF NOT EXISTS ui.sso_group_role (
	id		serial PRIMARY KEY,
	group_id	text NOT NULL CHECK (length(group_id) BETWEEN 1 AND 256),
	label		text NOT NULL DEFAULT '' CHECK (length(label) <= 200),
	role		text NOT NULL CHECK (role IN ('viewer','operator','admin')),
	created_at	timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS sso_group_role_group_uq ON ui.sso_group_role (lower(group_id));

-- Outstanding AuthnRequests (InResponseTo). nonce_sha256 binds the response to the browser
-- that started the sign-in (cookie); session_id is set for step-up re-authentication.
CREATE TABLE IF NOT EXISTS ui.saml_request (
	id		text PRIMARY KEY CHECK (length(id) <= 100),
	nonce_sha256	text NOT NULL,
	session_id	integer REFERENCES ui.session(id) ON DELETE CASCADE,
	next_path	text NOT NULL DEFAULT '/',
	created_at	timestamptz NOT NULL DEFAULT now()
);
-- Assertion IDs already used (replay protection), kept until the assertion expires.
CREATE TABLE IF NOT EXISTS ui.saml_replay (
	assertion_id	text PRIMARY KEY CHECK (length(assertion_id) <= 200),
	expires_at	timestamptz NOT NULL
);

INSERT INTO ui.setting (key, value) VALUES
	('saml_enabled', 'false'),
	('saml_idp_metadata', ''),
	('saml_entity_id', ''),
	('saml_group_attribute', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'),
	('saml_name_attribute', 'http://schemas.microsoft.com/identity/claims/displayname'),
	('saml_local_login', 'all')
ON CONFLICT (key) DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON ui.sso_group_role, ui.saml_request, ui.saml_replay TO radius_admin;
GRANT USAGE ON SEQUENCE ui.sso_group_role_id_seq TO radius_admin;

RESET ROLE;
