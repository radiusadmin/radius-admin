-- radius-admin: least-privilege grants. Run as postgres, connected to database radius:
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 30-grants.sql
SET ROLE radius_owner;

-- FreeRADIUS (radius_fr): read policy data, write logs/accounting. Nothing in schema ui.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM radius_fr;
GRANT SELECT ON radcheck, radreply, radgroupcheck, radgroupreply, radusergroup, nas, mab_device TO radius_fr;
GRANT INSERT ON radpostauth TO radius_fr;
GRANT SELECT, INSERT, UPDATE ON radacct TO radius_fr;
GRANT USAGE ON SEQUENCE radpostauth_id_seq, radacct_radacctid_seq TO radius_fr;

-- Web app (radius_admin)
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM radius_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON radcheck, radreply, radusergroup, radgroupcheck, radgroupreply, mab_device TO radius_admin;
GRANT SELECT ON radpostauth, radacct, nas TO radius_admin;
GRANT USAGE ON SEQUENCE radcheck_id_seq, radreply_id_seq, radusergroup_id_seq,
	radgroupcheck_id_seq, radgroupreply_id_seq, mab_device_id_seq TO radius_admin;

GRANT USAGE ON SCHEMA ui TO radius_admin;
REVOKE ALL ON ALL TABLES IN SCHEMA ui FROM radius_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON
	ui.admin_user, ui.password_history, ui.session, ui.login_attempt,
	ui.radius_client, ui.access_rule, ui.setting
	TO radius_admin;
-- History tables are append-only for the app.
REVOKE ALL ON ui.apply_log, ui.audit_log FROM radius_admin;
GRANT SELECT, INSERT ON ui.apply_log, ui.audit_log TO radius_admin;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA ui TO radius_admin;
RESET ROLE;
