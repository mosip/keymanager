-- Below script required to upgrade from 1.3.0-B4 to 1.3.0
\c mosip_keymgr

ALTER TABLE IF EXISTS keymgr.ca_cert_store
    ADD COLUMN ca_cert_type character varying(25);

COMMENT ON COLUMN keymgr.ca_cert_store.ca_cert_type
    IS 'CA_Certificate Type: Specifies the type of CA_Certificate e.g., Root, Intermediate';
