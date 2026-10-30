-- FreeRADIUS 3.2.10 PostgreSQL schema (from raddb/mods-config/sql/main/postgresql/schema.sql)
-- with these radius-admin changes:
--   * radpostauth has NO password column and records auth method, NAS, VLAN, cert SAN
--   * new table mab_device (MAC Authentication Bypass registry)
-- Run as postgres, connected to database radius:
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 10-freeradius-schema.sql
SET ROLE radius_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO radius_fr, radius_admin;

CREATE TABLE IF NOT EXISTS radacct (
	RadAcctId		bigserial PRIMARY KEY,
	AcctSessionId		text NOT NULL,
	AcctUniqueId		text NOT NULL UNIQUE,
	UserName		text,
	Realm			text,
	NASIPAddress		inet NOT NULL,
	NASPortId		text,
	NASPortType		text,
	AcctStartTime		timestamp with time zone,
	AcctUpdateTime		timestamp with time zone,
	AcctStopTime		timestamp with time zone,
	AcctInterval		bigint,
	AcctSessionTime		bigint,
	AcctAuthentic		text,
	ConnectInfo_start	text,
	ConnectInfo_stop	text,
	AcctInputOctets		bigint,
	AcctOutputOctets	bigint,
	CalledStationId		text,
	CallingStationId	text,
	AcctTerminateCause	text,
	ServiceType		text,
	FramedProtocol		text,
	FramedIPAddress		inet,
	FramedIPv6Address	inet,
	FramedIPv6Prefix	inet,
	FramedInterfaceId	text,
	DelegatedIPv6Prefix	inet,
	Class			text
);
CREATE INDEX IF NOT EXISTS radacct_active_session_idx ON radacct (AcctUniqueId) WHERE AcctStopTime IS NULL;
CREATE INDEX IF NOT EXISTS radacct_bulk_close ON radacct (NASIPAddress, AcctStartTime) WHERE AcctStopTime IS NULL;
CREATE INDEX IF NOT EXISTS radacct_start_user_idx ON radacct (AcctStartTime, UserName);
CREATE INDEX IF NOT EXISTS radacct_calss_idx ON radacct (Class);

CREATE TABLE IF NOT EXISTS radcheck (
	id			serial PRIMARY KEY,
	UserName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '==',
	Value			text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radcheck_UserName ON radcheck (UserName, Attribute);

CREATE TABLE IF NOT EXISTS radgroupcheck (
	id			serial PRIMARY KEY,
	GroupName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '==',
	Value			text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radgroupcheck_GroupName ON radgroupcheck (GroupName, Attribute);

CREATE TABLE IF NOT EXISTS radgroupreply (
	id			serial PRIMARY KEY,
	GroupName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '=',
	Value			text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radgroupreply_GroupName ON radgroupreply (GroupName, Attribute);

CREATE TABLE IF NOT EXISTS radreply (
	id			serial PRIMARY KEY,
	UserName		text NOT NULL DEFAULT '',
	Attribute		text NOT NULL DEFAULT '',
	op			VARCHAR(2) NOT NULL DEFAULT '=',
	Value			text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radreply_UserName ON radreply (UserName, Attribute);

CREATE TABLE IF NOT EXISTS radusergroup (
	id			serial PRIMARY KEY,
	UserName		text NOT NULL DEFAULT '',
	GroupName		text NOT NULL DEFAULT '',
	priority		integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS radusergroup_UserName ON radusergroup (UserName);

-- radius-admin: no password column, ever.
CREATE TABLE IF NOT EXISTS radpostauth (
	id			bigserial PRIMARY KEY,
	username		text NOT NULL,
	reply			text,
	authmethod		text,
	nasipaddress		inet,
	calledstationid		text,
	callingstationid	text,
	nasporttype		text,
	vlan			text,
	certsan			text,
	authdate		timestamp with time zone NOT NULL DEFAULT now(),
	class			text
);
CREATE INDEX IF NOT EXISTS radpostauth_username_idx ON radpostauth (username);
CREATE INDEX IF NOT EXISTS radpostauth_authdate_idx ON radpostauth (authdate);
CREATE INDEX IF NOT EXISTS radpostauth_class_idx ON radpostauth (class);

CREATE TABLE IF NOT EXISTS nas (
	id			serial PRIMARY KEY,
	nasname			text NOT NULL,
	shortname		text NOT NULL,
	type			text NOT NULL DEFAULT 'other',
	ports			integer,
	secret			text NOT NULL,
	server			text,
	community		text,
	description		text
);
CREATE INDEX IF NOT EXISTS nas_nasname ON nas (nasname);

CREATE TABLE IF NOT EXISTS nasreload (
	NASIPAddress		inet PRIMARY KEY,
	ReloadTime		timestamp with time zone NOT NULL
);

-- radius-admin: MAC Authentication Bypass registry (read live by FreeRADIUS)
CREATE TABLE IF NOT EXISTS mab_device (
	id			serial PRIMARY KEY,
	mac			text NOT NULL UNIQUE CHECK (mac ~ '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$'),
	vlan			integer NOT NULL CHECK (vlan BETWEEN 1 AND 4094),
	description		text NOT NULL DEFAULT '',
	enabled			boolean NOT NULL DEFAULT true,
	created_at		timestamp with time zone NOT NULL DEFAULT now(),
	updated_at		timestamp with time zone NOT NULL DEFAULT now()
);
RESET ROLE;
