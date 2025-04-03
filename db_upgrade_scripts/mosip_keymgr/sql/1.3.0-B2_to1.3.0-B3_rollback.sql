-- ca_cert_type column is removed/deleted from ca_cert_store table --
\c mosip_keymgr

COMMENT ON COLUMN keymgr.ca_cert_store.ca_cert_type
    IS NULL;

ALTER TABLE IF EXISTS keymgr.ca_cert_store
    DROP COLUMN IF EXISTS ca_cert_type;