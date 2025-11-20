-- Below script required to upgrade from 1.3.0-B4 to 1.3.0
\c mosip_keymgr

COMMENT ON COLUMN keymgr.ca_cert_store.ca_cert_type
    IS NULL;

-- Drop the ca_cert_type column (if it exists)
ALTER TABLE IF EXISTS keymgr.ca_cert_store
    DROP COLUMN IF EXISTS ca_cert_type;

-- Below script is required to rollback from 1.3.0-B2 to 1.3.0-B1 --
-- ca_cert_type column is removed/deleted from ca_cert_store table --
\c mosip_keymgr

COMMENT ON COLUMN keymgr.ca_cert_store.ca_cert_type
    IS NULL;

ALTER TABLE IF EXISTS keymgr.ca_cert_store
    DROP COLUMN IF EXISTS ca_cert_type;