-- radius-admin: roles and database. Run as the postgres superuser:
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -f 00-roles.sql
-- No role has a password: access is local peer auth only (see pg_hba/pg_ident snippets).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius_owner') THEN
    CREATE ROLE radius_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius_fr') THEN
    CREATE ROLE radius_fr LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius_admin') THEN
    CREATE ROLE radius_admin LOGIN;
  END IF;
END
$$;
ALTER ROLE radius_fr    PASSWORD NULL NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 64;
ALTER ROLE radius_admin PASSWORD NULL NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 32;

SELECT 'CREATE DATABASE radius OWNER radius_owner ENCODING ''UTF8'' TEMPLATE template0'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'radius')\gexec

REVOKE ALL ON DATABASE radius FROM PUBLIC;
GRANT CONNECT ON DATABASE radius TO radius_fr, radius_admin;
