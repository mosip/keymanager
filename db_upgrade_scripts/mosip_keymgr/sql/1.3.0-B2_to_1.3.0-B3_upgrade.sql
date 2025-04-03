-- ca_cert_type column is added to the ca_cert_store table --
\c mosip_keymgr

ALTER TABLE IF EXISTS keymgr.ca_cert_store
    ADD COLUMN ca_cert_type character varying(25);

COMMENT ON COLUMN keymgr.ca_cert_store.ca_cert_type
    IS 'CA_Certificate Type: Specifies the type of CA_Certificate e.g., Root, Intermediate';
