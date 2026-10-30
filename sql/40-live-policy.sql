-- radius-admin: live access rules and settings.
-- FreeRADIUS evaluates the VLAN rules and the switch-admin settings through these
-- functions on every request, so edits in the UI take effect immediately (no restart).
-- They are SECURITY DEFINER so radius_fr never needs any right on schema ui; each one
-- returns only the single decision it computes. Fail-closed: any bad input -> NULL/false.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 40-live-policy.sql
SET ROLE radius_owner;

-- Core matcher shared by radius_admin_vlan() (web UI rule tester) and
-- radius_admin_vlan_hex() (FreeRADIUS), so both always agree.
--   p_wired   true = wired rules only; false = wireless rules whose SSID is the
--             ':'-anchored suffix of p_called_station_id
--   p_groups  the computer's AD group names (any case)
CREATE OR REPLACE FUNCTION public.radius_admin_vlan_core(p_wired boolean, p_called_station_id text, p_groups text[])
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
	SELECT r.vlan::text
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

-- VLAN for an 802.1X (EAP-TLS) authentication, or NULL (= reject). Text arguments,
-- for the web UI's rule tester (parameterized query). FreeRADIUS does NOT call this
-- one (it uses radius_admin_vlan_hex below).
--   p_port_type          NAS-Port-Type as text ('Ethernet' for wired)
--   p_called_station_id  Called-Station-Id ('<AP MAC>:<SSID>' for wireless)
--   p_groups             comma-separated AD group names (cn) of the computer
-- Wired requests match only wired rules; anything else matches only wireless rules
-- whose SSID is the ':'-anchored suffix of Called-Station-Id (same as the original
-- `=~ /:SSID$/`). Group names compare case-insensitively. First rule by
-- (priority, id) wins.
CREATE OR REPLACE FUNCTION public.radius_admin_vlan(p_port_type text, p_called_station_id text, p_groups text)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
	SELECT radius_admin_vlan_core(coalesce(p_port_type, '') = 'Ethernet', p_called_station_id,
	                              string_to_array(coalesce(p_groups, ''), ','))
$$;

-- true when p_src (the RADIUS packet source address) is inside setting admin_subnet.
CREATE OR REPLACE FUNCTION public.radius_admin_admin_source_ok(p_src text)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_subnet text;
BEGIN
	SELECT value INTO v_subnet FROM ui.setting WHERE key = 'admin_subnet';
	IF v_subnet IS NULL OR p_src IS NULL OR p_src = '' THEN
		RETURN false;
	END IF;
	RETURN p_src::inet <<= v_subnet::cidr;
EXCEPTION WHEN others THEN
	RETURN false;
END
$$;

-- true when switch-admin logins should receive Cisco-AVPair shell:priv-lvl=15.
CREATE OR REPLACE FUNCTION public.radius_admin_priv15()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
	SELECT coalesce((SELECT value = 'true' FROM ui.setting WHERE key = 'admin_priv15'), false)
$$;

-- =====================================================================================
-- Hex-argument wrappers: the ONLY functions FreeRADIUS calls (from policy.d/radius-admin).
--
-- Why: FreeRADIUS 3.2 un-escapes backslash sequences (\047, \\, ...) in the assembled
-- argument of %{sql:...} AFTER rlm_sql has escaped the values, so a request- or
-- directory-derived string inside a %{sql:...} literal can inject SQL even with
-- auto_escape = yes. The generated policy therefore passes such values only as
-- lowercase hex (%{hex:...}), alphabet [0-9a-f], which survives any (un)escaping.
-- These wrappers validate and decode the hex; any malformed input -> NULL/false
-- (= reject). The text-argument functions above stay for the web app's rule tester.
-- =====================================================================================

-- Decode lowercase/uppercase hex to UTF-8 text; NULL on anything malformed.
CREATE OR REPLACE FUNCTION public.radius_admin_unhex(p_hex text)
RETURNS text
LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, public
AS $$
BEGIN
	IF p_hex IS NULL THEN
		RETURN NULL;
	END IF;
	IF p_hex !~ '^([0-9a-fA-F]{2})*$' THEN
		RETURN NULL;
	END IF;
	RETURN convert_from(decode(p_hex, 'hex'), 'UTF8');
EXCEPTION WHEN others THEN
	RETURN NULL;
END
$$;

-- p_wired:   true for wired (NAS-Port-Type == Ethernet, decided in unlang), else wireless
-- p_csi_hex: hex(Called-Station-Id) or ''
-- p_groups_hex: concatenation of ",<hex(group cn)>" items (leading comma each, any
--               case; compared case-insensitively). No length limit.
CREATE OR REPLACE FUNCTION public.radius_admin_vlan_hex(p_wired boolean, p_csi_hex text, p_groups_hex text)
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
	RETURN radius_admin_vlan_core(p_wired, v_csi, v_groups);
EXCEPTION WHEN others THEN
	RETURN NULL;
END
$$;

-- p_src_hex: the packet source address, hex-encoded by the policy:
--   IPv4: the 4 raw octets (exactly 8 hex digits, %{hex:<ipaddr attribute>})
--   IPv6: hex of its printed text form (e.g. hex('fd00::1'))
CREATE OR REPLACE FUNCTION public.radius_admin_admin_source_ok_hex(p_src_hex text)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_bytes bytea;
	v_src text;
BEGIN
	IF p_src_hex IS NULL OR p_src_hex !~ '^([0-9a-fA-F]{2}){4,64}$' THEN
		RETURN false;
	END IF;
	IF length(p_src_hex) = 8 THEN
		v_bytes := decode(p_src_hex, 'hex');
		v_src := get_byte(v_bytes, 0) || '.' || get_byte(v_bytes, 1) || '.' ||
			 get_byte(v_bytes, 2) || '.' || get_byte(v_bytes, 3);
	ELSE
		v_src := radius_admin_unhex(p_src_hex);
		IF v_src IS NULL OR position(':' IN v_src) = 0 THEN
			RETURN false;
		END IF;
	END IF;
	RETURN coalesce(radius_admin_admin_source_ok(v_src), false);
EXCEPTION WHEN others THEN
	RETURN false;
END
$$;

-- Least privilege: FreeRADIUS (radius_fr) may call ONLY the hex-argument entry points it
-- uses plus priv15; the text-argument functions and the helpers are reached only from
-- inside these SECURITY DEFINER functions (which run as radius_owner). The web app
-- (radius_admin) gets the text-argument matcher for its parameterized rule tester.
-- Explicit REVOKEs make re-running this file on an older install remove earlier grants.
REVOKE ALL ON FUNCTION public.radius_admin_vlan_core(boolean, text, text[]) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_unhex(text) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_vlan(text, text, text) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_admin_source_ok(text) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_vlan_hex(boolean, text, text) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_admin_source_ok_hex(text) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_priv15() FROM PUBLIC, radius_fr, radius_admin;

GRANT EXECUTE ON FUNCTION public.radius_admin_vlan_hex(boolean, text, text) TO radius_fr;
GRANT EXECUTE ON FUNCTION public.radius_admin_admin_source_ok_hex(text) TO radius_fr;
GRANT EXECUTE ON FUNCTION public.radius_admin_priv15() TO radius_fr, radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_vlan(text, text, text) TO radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_admin_source_ok(text) TO radius_admin;
RESET ROLE;
