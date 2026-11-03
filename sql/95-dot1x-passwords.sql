-- radius-admin: 802.1X with a username and password (EAP-TTLS with PAP inside), local
-- accounts (SPEC section 18). Idempotent, additive only.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 95-dot1x-passwords.sql
SET ROLE radius_owner;

-- dot1x_ttls: 'true' lets local 802.1X users sign in with EAP-TTLS/PAP (off by default)
-- dot1x_ttls_directory: 'true' also accepts directory accounts (LDAP bind as the user;
--   SPEC section 19). A local user of the same name always wins.
INSERT INTO ui.setting (key, value) VALUES ('dot1x_ttls', 'false'), ('dot1x_ttls_directory', 'false')
ON CONFLICT (key) DO NOTHING;

-- Local 802.1X accounts. Separate from switch admins (radcheck/net-admins): a switch
-- admin's password never opens a network port, and an 802.1X user never reaches switch
-- management. groups are matched against the access rules' group names, the same way a
-- computer's directory groups are.
--   password_hash  rlm_pap Password-With-Header value: {X-PBKDF2}HMACSHA2+256:...
CREATE TABLE IF NOT EXISTS ui.dot1x_user (
	id			serial PRIMARY KEY,
	username		text NOT NULL CHECK (username ~ '^[A-Za-z0-9._@-]{1,64}$'),
	password_hash		text NOT NULL CHECK (password_hash ~ '^\{X-PBKDF2\}HMACSHA2\+256:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'),
	groups			text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(groups) <= 50),
	description		text NOT NULL DEFAULT '' CHECK (length(description) <= 200),
	enabled			boolean NOT NULL DEFAULT true,
	expires_at		timestamptz,
	created_at		timestamptz NOT NULL DEFAULT now(),
	created_by		text,
	updated_at		timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS dot1x_user_username_idx ON ui.dot1x_user (lower(username));
GRANT SELECT, INSERT, UPDATE, DELETE ON ui.dot1x_user TO radius_admin;
GRANT USAGE ON SEQUENCE ui.dot1x_user_id_seq TO radius_admin;

-- Password check for the inner tunnel. p_user_hex = hex(User-Name inside the tunnel).
-- Returns the stored hash for rlm_pap, or why there is none:
--   'off'       username/password 802.1X is turned off (setting dot1x_ttls)
--   'directory' no such local user, and directory accounts are accepted: the inner
--               tunnel asks the directory (ldap_user) instead
--   'unknown'   no such local user (directory accounts not accepted)
--   'disabled'  the account is disabled
--   'expired'   the account has expired
--   NULL        malformed input
CREATE OR REPLACE FUNCTION public.radius_admin_dot1x_user_hex(p_user_hex text)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_name text;
	u record;
BEGIN
	IF coalesce((SELECT value FROM ui.setting WHERE key = 'dot1x_ttls'), 'false') <> 'true' THEN
		RETURN 'off';
	END IF;
	IF p_user_hex IS NULL OR p_user_hex !~ '^([0-9a-fA-F]{2}){1,64}$' THEN
		RETURN NULL;
	END IF;
	v_name := radius_admin_unhex(p_user_hex);
	IF v_name IS NULL THEN
		RETURN NULL;
	END IF;
	SELECT password_hash, enabled, expires_at INTO u FROM ui.dot1x_user WHERE lower(username) = lower(v_name);
	IF NOT FOUND THEN
		IF coalesce((SELECT value FROM ui.setting WHERE key = 'dot1x_ttls_directory'), 'false') = 'true' THEN
			RETURN 'directory';
		END IF;
		RETURN 'unknown';
	END IF;
	IF NOT u.enabled THEN
		RETURN 'disabled';
	END IF;
	IF u.expires_at IS NOT NULL AND u.expires_at <= now() THEN
		RETURN 'expired';
	END IF;
	RETURN u.password_hash;
EXCEPTION WHEN others THEN
	RETURN NULL;
END
$$;

-- VLAN for an authenticated local 802.1X user: '<vlan>:<rule id>' from the access rules
-- (same matcher as EAP-TLS, the user's groups in place of directory groups), or NULL.
-- The account is checked again so that disabling it between the password check and
-- post-auth still rejects.
CREATE OR REPLACE FUNCTION public.radius_admin_dot1x_vlan_rule_hex(p_user_hex text, p_wired boolean, p_csi_hex text)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_name text;
	v_csi text;
	v_groups text[];
BEGIN
	IF p_wired IS NULL OR p_user_hex IS NULL OR p_user_hex !~ '^([0-9a-fA-F]{2}){1,64}$' THEN
		RETURN NULL;
	END IF;
	IF coalesce((SELECT value FROM ui.setting WHERE key = 'dot1x_ttls'), 'false') <> 'true' THEN
		RETURN NULL;
	END IF;
	v_name := radius_admin_unhex(p_user_hex);
	v_csi := radius_admin_unhex(coalesce(p_csi_hex, ''));
	IF v_name IS NULL OR v_csi IS NULL THEN
		RETURN NULL;
	END IF;
	SELECT groups INTO v_groups FROM ui.dot1x_user
	WHERE lower(username) = lower(v_name) AND enabled AND (expires_at IS NULL OR expires_at > now());
	IF NOT FOUND THEN
		RETURN NULL;
	END IF;
	RETURN radius_admin_vlan_rule_core(p_wired, v_csi, v_groups);
EXCEPTION WHEN others THEN
	RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION public.radius_admin_dot1x_user_hex(text) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_dot1x_vlan_rule_hex(text, boolean, text) FROM PUBLIC, radius_fr, radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_dot1x_user_hex(text) TO radius_fr;
GRANT EXECUTE ON FUNCTION public.radius_admin_dot1x_vlan_rule_hex(text, boolean, text) TO radius_fr;

-- MACs that authenticated with 802.1X (certificate or password) are never MAB candidates
-- (radius_admin_mab_hex, mab_pending_open in 70-operations.sql). radpostauth_cert_mac_idx
-- covers EAP-TLS only; it is dropped one release after this one.
CREATE INDEX IF NOT EXISTS radpostauth_dot1x_mac_idx
	ON radpostauth ((upper(regexp_replace(callingstationid, '[^0-9A-Fa-f]', '', 'g'))))
	WHERE reply = 'Access-Accept' AND authmethod IN ('eap-tls', 'ttls-pap', 'ttls-ldap');
RESET ROLE;
