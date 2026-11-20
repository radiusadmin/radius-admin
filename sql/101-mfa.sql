-- radius-admin: second-factor providers for device admin logins (SPEC section 29).
-- A device admin login that needs a second factor is proxied by FreeRADIUS to a provider:
-- the Duo Authentication Proxy on this server ('duo'), or a remote RADIUS server that checks
-- the password and the second factor itself ('radius-mfa'). Which logins need one is decided
-- live, per login, by radius_admin_mfa_hex(); the providers' addresses and shared secrets
-- are rendered into the clients file and need Apply.
-- Idempotent, additive only: an older release ignores the new tables and function.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 101-mfa.sql
SET ROLE radius_owner;

-- One row per configured provider. settings: the non-secret values (address, port, timeout);
-- secrets_enc: AES-256-GCM (data key) of a JSON object with the shared secrets. The install
-- columns are filled by the portal for providers it installs on this server.
CREATE TABLE IF NOT EXISTS ui.mfa_provider (
	id			text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9-]{0,31}$'),
	type			text NOT NULL CHECK (type IN ('duo', 'radius-mfa')),
	label			text NOT NULL DEFAULT '' CHECK (length(label) <= 100),
	enabled			boolean NOT NULL DEFAULT false,
	settings		jsonb NOT NULL DEFAULT '{}'::jsonb,
	secrets_enc		bytea,
	install_state		text NOT NULL DEFAULT 'none'
				CHECK (install_state IN ('none', 'installing', 'installed', 'failed')),
	installed_version	text,
	verified		text CHECK (verified IN ('catalog', 'pasted-hash')),
	sha256			text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
	created_at		timestamptz NOT NULL DEFAULT now(),
	updated_at		timestamptz NOT NULL DEFAULT now()
);

-- Which device admin logins need a second factor: one row per account kind (local accounts,
-- directory accounts). client_scope 'selected' limits it to the clients in ui.mfa_policy_client.
CREATE TABLE IF NOT EXISTS ui.mfa_policy (
	account_kind		text PRIMARY KEY CHECK (account_kind IN ('local', 'directory')),
	enabled			boolean NOT NULL DEFAULT false,
	provider_id		text REFERENCES ui.mfa_provider (id) ON DELETE RESTRICT,
	client_scope		text NOT NULL DEFAULT 'all' CHECK (client_scope IN ('all', 'selected')),
	updated_at		timestamptz NOT NULL DEFAULT now(),
	CHECK (NOT enabled OR provider_id IS NOT NULL)
);
INSERT INTO ui.mfa_policy (account_kind) VALUES ('local'), ('directory') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS ui.mfa_policy_client (
	account_kind		text NOT NULL REFERENCES ui.mfa_policy (account_kind) ON DELETE CASCADE,
	client_id		integer NOT NULL REFERENCES ui.radius_client (id) ON DELETE CASCADE,
	PRIMARY KEY (account_kind, client_id)
);

-- Local device admins that never need a second factor (break-glass accounts).
CREATE TABLE IF NOT EXISTS ui.mfa_exempt (
	username		text PRIMARY KEY CHECK (username ~ '^[A-Za-z0-9._@-]{1,64}$'),
	created_at		timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS mfa_exempt_lower ON ui.mfa_exempt (lower(username));

GRANT SELECT, INSERT, UPDATE, DELETE ON ui.mfa_provider, ui.mfa_policy, ui.mfa_policy_client, ui.mfa_exempt
	TO radius_admin;

-- What an apply also installed besides policy and clients: SHA-256 over the provider files
-- (the Duo Authentication Proxy's configuration, SPEC section 29.2); NULL/'' = none.
ALTER TABLE ui.apply_log ADD COLUMN IF NOT EXISTS providers_sha256 text;

-- Device admin login, authorize: does it need a second factor, and from which provider?
-- p_user_hex = hex(User-Name), p_client_hex = hex(client shortname), p_kind = 'local' or
-- 'directory' (literal from the policy, as decided by radius_admin_admin_directory_hex).
-- Returns
--   'off'            no second factor for this login
--   'exempt'         a local account on the exemption list
--   'unavailable'    a second factor is required but the provider is turned off
--   '<type>:<id>'    proxy to provider <id> of type duo or radius-mfa
--   NULL             malformed input or an error (the policy rejects the login)
CREATE OR REPLACE FUNCTION public.radius_admin_mfa_hex(p_user_hex text, p_client_hex text, p_kind text)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_name text;
	v_client text;
	v_policy ui.mfa_policy%ROWTYPE;
	v_provider ui.mfa_provider%ROWTYPE;
BEGIN
	IF p_user_hex IS NULL OR p_user_hex !~ '^([0-9a-fA-F]{2}){1,253}$'
	   OR p_client_hex IS NULL OR p_client_hex !~ '^([0-9a-fA-F]{2}){0,63}$'
	   OR p_kind IS NULL OR p_kind NOT IN ('local', 'directory') THEN
		RETURN NULL;
	END IF;
	v_name := radius_admin_unhex(p_user_hex);
	v_client := radius_admin_unhex(p_client_hex);
	IF v_name IS NULL OR v_name = '' OR v_client IS NULL THEN
		RETURN NULL;
	END IF;
	SELECT * INTO v_policy FROM ui.mfa_policy WHERE account_kind = p_kind;
	IF NOT FOUND OR NOT v_policy.enabled THEN
		RETURN 'off';
	END IF;
	IF v_policy.client_scope = 'selected' AND NOT EXISTS (
		SELECT 1 FROM ui.mfa_policy_client pc JOIN ui.radius_client c ON c.id = pc.client_id
		WHERE pc.account_kind = p_kind AND c.name = v_client) THEN
		RETURN 'off';
	END IF;
	IF p_kind = 'local' AND EXISTS (SELECT 1 FROM ui.mfa_exempt WHERE lower(username) = lower(v_name)) THEN
		RETURN 'exempt';
	END IF;
	SELECT * INTO v_provider FROM ui.mfa_provider WHERE id = v_policy.provider_id;
	IF NOT FOUND OR NOT v_provider.enabled THEN
		RETURN 'unavailable';
	END IF;
	RETURN v_provider.type || ':' || v_provider.id;
EXCEPTION WHEN others THEN
	RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION public.radius_admin_mfa_hex(text, text, text) FROM PUBLIC, radius_fr, radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_mfa_hex(text, text, text) TO radius_fr;
RESET ROLE;
