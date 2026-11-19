-- radius-admin: close accounting records that never got an Accounting-Stop (SPEC section 25).
-- A switch that reboots, loses a Stop packet or starts a new accounting session when it
-- re-authenticates a port leaves the old radacct row open for ever, and the sessions page
-- listed it as up. The monitor service calls these functions; the web app's role still has
-- no write access to radacct. Idempotent, additive only: an older release ignores them.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 98-stale-sessions.sql
SET ROLE radius_owner;

-- Partial index for the "newer session of the same device on the same switch" lookup.
CREATE INDEX IF NOT EXISTS radacct_open_csi_idx ON radacct (callingstationid, nasipaddress)
	WHERE acctstoptime IS NULL;

-- Closes, and returns how many:
--   superseded  an open record when a later accounting session started for the same station
--               (Calling-Station-Id) on the same NAS: a device has one session per switch.
--               Ends at the later session's start; cause "Superseded".
--   stale       an open record whose switch sent interim updates and has sent none for
--               p_stale_hours (at least 24). Ends at its last update; cause "Stale-Session".
--               Records without any interim update are left alone: nothing says they ended.
-- A real Accounting-Stop that arrives later still updates the row (the stock stop query's
-- last fallback has no "AcctStopTime IS NULL"). Takes no request data.
CREATE OR REPLACE FUNCTION public.radius_admin_close_stale_sessions(p_stale_hours integer DEFAULT 24,
	OUT superseded integer, OUT stale integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_hours integer := greatest(coalesce(p_stale_hours, 24), 24);
BEGIN
	WITH nxt AS (
		SELECT a.radacctid, (SELECT min(b.acctstarttime) FROM radacct b
				     WHERE b.callingstationid = a.callingstationid
				       AND b.nasipaddress = a.nasipaddress
				       AND b.radacctid <> a.radacctid
				       AND b.acctstarttime IS NOT NULL
				       AND (b.acctstarttime > a.acctstarttime
					    OR (b.acctstarttime = a.acctstarttime AND b.radacctid > a.radacctid))) AS next_start
		FROM radacct a
		WHERE a.acctstoptime IS NULL AND a.acctstarttime IS NOT NULL
		  AND coalesce(a.callingstationid, '') <> '')
	UPDATE radacct a
	SET acctstoptime = nxt.next_start,
	    acctsessiontime = greatest(0, floor(extract(epoch FROM nxt.next_start - a.acctstarttime)))::bigint,
	    acctterminatecause = 'Superseded'
	FROM nxt
	WHERE a.radacctid = nxt.radacctid AND nxt.next_start IS NOT NULL AND a.acctstoptime IS NULL;
	GET DIAGNOSTICS superseded = ROW_COUNT;

	UPDATE radacct
	SET acctstoptime = greatest(acctupdatetime, acctstarttime),
	    acctsessiontime = coalesce(acctsessiontime,
		greatest(0, floor(extract(epoch FROM acctupdatetime - acctstarttime)))::bigint),
	    acctterminatecause = 'Stale-Session'
	WHERE acctstoptime IS NULL AND acctupdatetime IS NOT NULL AND acctstarttime IS NOT NULL
	  AND acctupdatetime < now() - make_interval(hours => v_hours);
	GET DIAGNOSTICS stale = ROW_COUNT;
END
$$;

-- Closes the session named by a CoA / Disconnect request when the switch refused it with
-- Session-Context-Not-Found (the request names the session by MAC, port and NAS address, so
-- the switch has no such session any more). Only for a finished, refused request with that
-- answer, and only if the record is still open; ends at its last interim update (else now),
-- cause "Session-Not-Found".
-- Returns true when it closed the record.
CREATE OR REPLACE FUNCTION public.radius_admin_close_after_coa(p_request_id bigint)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
	v_sid bigint;
BEGIN
	SELECT r.radacct_id INTO v_sid FROM ui.coa_request r
	WHERE r.id = p_request_id AND r.done_at IS NOT NULL AND r.ok IS FALSE
	  AND r.message LIKE '%Session-Context-Not-Found%' AND r.radacct_id IS NOT NULL;
	IF v_sid IS NULL THEN
		RETURN false;
	END IF;
	UPDATE radacct
	SET acctstoptime = greatest(coalesce(acctupdatetime, now()), acctstarttime),
	    acctsessiontime = coalesce(greatest(0, floor(extract(epoch FROM
				coalesce(acctupdatetime, now()) - acctstarttime)))::bigint, acctsessiontime),
	    acctterminatecause = 'Session-Not-Found'
	WHERE radacctid = v_sid AND acctstoptime IS NULL;
	RETURN FOUND;
END
$$;

REVOKE ALL ON FUNCTION public.radius_admin_close_stale_sessions(integer) FROM PUBLIC, radius_fr, radius_admin;
REVOKE ALL ON FUNCTION public.radius_admin_close_after_coa(bigint) FROM PUBLIC, radius_fr, radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_close_stale_sessions(integer) TO radius_admin;
GRANT EXECUTE ON FUNCTION public.radius_admin_close_after_coa(bigint) TO radius_admin;
RESET ROLE;
