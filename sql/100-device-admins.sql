-- radius-admin: device admin logins with directory accounts (SPEC section 28).
-- A name that is not a local device admin can log in to a switch, access point or firewall
-- with its directory password (LDAP bind as the user, over the directory connection
-- FreeRADIUS already has), when the account is in one of the configured directory groups.
-- Idempotent, additive only: an older release ignores the new settings and functions.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 100-device-admins.sql
SET ROLE radius_owner;

-- admin_directory: 'true' accepts directory accounts for device admin logins (off by default)
-- admin_directory_groups: the directory group names (cn) whose members may log in, one per
--   line, compared case-insensitively. Directory logins stay off while the list is empty.
INSERT INTO ui.setting (key, value) VALUES ('admin_directory', 'false'), ('admin_directory_groups', '')
ON CONFLICT (key) DO NOTHING;

-- The configured group names, lower case, without blanks; empty array when there are none.
CREATE OR REPLACE FUNCTION public.radius_admin_admin_directory_groups()
RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
	SELECT coalesce(array_agg(DISTINCT lower(btrim(g))) FILTER (WHERE btrim(g) <> ''), ARRAY[]::text[])
	FROM ui.setting s, regexp_split_to_table(s.value, E'\n') AS g
	WHERE s.key = 'admin_directory_groups'
$$;

-- Device admin login, authorize: may this name be checked against the directory?
-- p_user_hex = hex(User-Name). Returns
--   'directory'  directory accounts are on, at least one group is configured, and the name
--                is not a local account (radcheck/radusergroup, compared case-insensitively:
--                a local account of the same name always wins)
--   'local'      the name is a local account (FreeRADIUS checks its stored password)
--   'off'        directory accounts are off, or no group is configured
--   NULL         malformed input
CREATE OR REPLACE FUNCTION public.radius_admin_admin_directory_hex(p_user_hex text)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_name text;
BEGIN
	IF p_user_hex IS NULL OR p_user_hex !~ '^([0-9a-fA-F]{2}){1,253}$' THEN
		RETURN NULL;
	END IF;
	v_name := radius_admin_unhex(p_user_hex);
	IF v_name IS NULL OR v_name = '' THEN
		RETURN NULL;
	END IF;
	IF EXISTS (SELECT 1 FROM radcheck WHERE lower(username) = lower(v_name))
	   OR EXISTS (SELECT 1 FROM radusergroup WHERE lower(username) = lower(v_name)) THEN
		RETURN 'local';
	END IF;
	IF coalesce((SELECT value FROM ui.setting WHERE key = 'admin_directory'), 'false') <> 'true'
	   OR cardinality(radius_admin_admin_directory_groups()) = 0 THEN
		RETURN 'off';
	END IF;
	RETURN 'directory';
EXCEPTION WHEN others THEN
	RETURN NULL;
END
$$;

-- Device admin login, post-auth: is the directory account in a configured group?
-- p_groups_hex = ',<hex>,<hex>...' (the directory group names, as for the access rules).
-- false when directory accounts are off, on malformed input and when no group matches.
CREATE OR REPLACE FUNCTION public.radius_admin_admin_group_hex(p_groups_hex text)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_allowed text[];
	v_item text;
	v_name text;
BEGIN
	IF p_groups_hex IS NULL OR p_groups_hex !~ '^(,[0-9a-fA-F]*)*$' THEN
		RETURN false;
	END IF;
	IF coalesce((SELECT value FROM ui.setting WHERE key = 'admin_directory'), 'false') <> 'true' THEN
		RETURN false;
	END IF;
	v_allowed := radius_admin_admin_directory_groups();
	IF cardinality(v_allowed) = 0 OR p_groups_hex = '' THEN
		RETURN false;
	END IF;
	FOREACH v_item IN ARRAY string_to_array(substr(p_groups_hex, 2), ',') LOOP
		v_name := radius_admin_unhex(v_item);
		IF v_name IS NULL THEN
			RETURN false;
		END IF;
		IF v_name <> '' AND lower(v_name) = ANY (v_allowed) THEN
			RETURN true;
		END IF;
	END LOOP;
	RETURN false;
EXCEPTION WHEN others THEN
	RETURN false;
END
$$;

REVOKE ALL ON FUNCTION public.radius_admin_admin_directory_groups() FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_admin_directory_hex(text) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_admin_group_hex(text) FROM PUBLIC, radius_fr, radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_admin_directory_hex(text) TO radius_fr;
GRANT EXECUTE ON FUNCTION public.radius_admin_admin_group_hex(text) TO radius_fr;
RESET ROLE;
