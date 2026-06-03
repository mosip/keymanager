-- Below script required to upgrade from 1.3.0-B4 to 1.3.0
\c mosip_keymgr

ALTER TABLE IF EXISTS keymgr.ca_cert_store
    ADD COLUMN ca_cert_type character varying(25);

COMMENT ON COLUMN keymgr.ca_cert_store.ca_cert_type
    IS 'CA_Certificate Type: Specifies the type of CA_Certificate e.g., Root, Intermediate';


--PERFORMANCE INDEXES--
CREATE INDEX IF NOT EXISTS idx_ca_cert_store_cr_dtimes ON keymgr.ca_cert_store USING btree (cr_dtimes);
CREATE INDEX IF NOT EXISTS idx_ca_cert_store_del_dtimes ON keymgr.ca_cert_store USING btree (del_dtimes);
CREATE INDEX IF NOT EXISTS idx_ca_cert_store_upd_dtimes ON keymgr.ca_cert_store USING btree (upd_dtimes);
CREATE INDEX IF NOT EXISTS idx_ca_cert_times ON keymgr.ca_cert_store USING btree (cr_dtimes, upd_dtimes, del_dtimes);
--END PERFORMANCE INDEXES--