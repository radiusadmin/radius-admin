-- radius-admin: a vendor profile and a CoA port per RADIUS client, a role per access rule
-- (SPEC section 26).
-- vendor_profile NULL means "the default profile" (ui.setting default_vendor_profile, else
-- cisco-c1300); coa_port NULL means "the port the client's profile names". Before this
-- change one CoA port (ui.snmp_profile.coa_port) applied to every client: when an
-- installation had changed it from 1700, the value is copied to each existing client once,
-- when the column is added, so CoA keeps reaching the same port. ui.snmp_profile.coa_port
-- stays (a rollback reads it) and is removed in a later release.
-- Idempotent, additive only: an older release ignores the new columns.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 99-vendor-profiles.sql
SET ROLE radius_owner;

ALTER TABLE ui.radius_client ADD COLUMN IF NOT EXISTS vendor_profile text
	CHECK (vendor_profile ~ '^[a-z0-9][a-z0-9-]{0,31}$');

DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM information_schema.columns
	               WHERE table_schema = 'ui' AND table_name = 'radius_client' AND column_name = 'coa_port') THEN
		ALTER TABLE ui.radius_client ADD COLUMN coa_port integer CHECK (coa_port BETWEEN 1 AND 65535);
		UPDATE ui.radius_client c SET coa_port = p.coa_port
			FROM ui.snmp_profile p WHERE p.id = 1 AND p.coa_port <> 1700;
	END IF;
END
$$;

-- Custom vendor profiles, created in the portal or imported (SPEC section 26). The document is
-- the profile as vendors.validate() returned it; the app validates it again on every read.
CREATE TABLE IF NOT EXISTS ui.vendor_profile (
	id		text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
	doc		jsonb NOT NULL CHECK (jsonb_typeof(doc) = 'object' AND doc->>'id' = id),
	created_at	timestamptz NOT NULL DEFAULT now(),
	updated_at	timestamptz NOT NULL DEFAULT now(),
	updated_by	text NOT NULL DEFAULT ''
);
GRANT SELECT, INSERT, UPDATE, DELETE ON ui.vendor_profile TO radius_admin;

-- A role per access rule: sent with the attributes of the client's vendor profile that use
-- {role} (an Aruba user role, a firewall group, Filter-Id ...). Letters, digits and . _ - only,
-- so the value can stand in a reply attribute without quoting concerns.
ALTER TABLE ui.access_rule ADD COLUMN IF NOT EXISTS role text
	CHECK (role ~ '^[A-Za-z0-9._-]{1,64}$');

-- The role of the access rule FreeRADIUS just matched (the rule id comes from
-- radius_admin_vlan_rule_hex / radius_admin_dot1x_vlan_rule_hex and is checked to be digits
-- by the policy; no request data). '' when the rule has none, is disabled or does not exist.
CREATE OR REPLACE FUNCTION public.radius_admin_rule_role(p_rule_id bigint)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
	SELECT coalesce((SELECT role FROM ui.access_rule WHERE id = p_rule_id AND enabled), '')
$$;
REVOKE ALL ON FUNCTION public.radius_admin_rule_role(bigint) FROM PUBLIC, radius_fr, radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_rule_role(bigint) TO radius_fr;

RESET ROLE;
