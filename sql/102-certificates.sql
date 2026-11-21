-- radius-admin: certificates managed in the portal (SPEC section 30).
-- One row per certificate the portal manages: the 802.1X (EAP) server certificate, the CA bundle
-- for client certificates, the portal's HTTPS certificate. No row: whatever is installed stays.
-- key_enc / csr_key_enc: AES-256-GCM (data key) of the PEM private key. csr_*: a key and request
-- made on this server, waiting for the issued certificate. Changes need Review and apply.
-- Idempotent, additive only: an older release ignores the table.
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d radius -f 102-certificates.sql
SET ROLE radius_owner;

CREATE TABLE IF NOT EXISTS ui.tls_cert (
	kind			text PRIMARY KEY CHECK (kind IN ('eap_server', 'client_ca', 'portal_server')),
	cert_pem		text CHECK (cert_pem IS NULL OR length(cert_pem) <= 65536),
	key_enc			bytea,
	csr_pem			text CHECK (csr_pem IS NULL OR length(csr_pem) <= 16384),
	csr_key_enc		bytea,
	source			text CHECK (source IN ('upload', 'csr')),
	updated_at		timestamptz NOT NULL DEFAULT now(),
	updated_by		text,
	CHECK (kind = 'client_ca' OR (cert_pem IS NULL) = (key_enc IS NULL)),
	CHECK (kind <> 'client_ca' OR (key_enc IS NULL AND csr_pem IS NULL)),
	CHECK ((csr_pem IS NULL) = (csr_key_enc IS NULL))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ui.tls_cert TO radius_admin;
