-- Below script required to rollback from 1.3.0 to 1.3.0-B4
\c mosip_keymgr

COMMENT ON COLUMN keymgr.ca_cert_store.ca_cert_type
    IS NULL;

-- Drop the ca_cert_type column (if it exists)
ALTER TABLE IF EXISTS keymgr.ca_cert_store
    DROP COLUMN IF EXISTS ca_cert_type;

-- ROLLBACK FOR PERFORMANCE OPTIMIZATION INDEXES
DROP INDEX IF EXISTS keymgr.idx_ca_cert_store_cr_dtimes;
DROP INDEX IF EXISTS keymgr.idx_ca_cert_store_del_dtimes;
DROP INDEX IF EXISTS keymgr.idx_ca_cert_store_upd_dtimes;
DROP INDEX IF EXISTS keymgr.idx_ca_cert_times;