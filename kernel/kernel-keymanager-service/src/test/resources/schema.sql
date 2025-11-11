CREATE SCHEMA IF NOT EXISTS keymgr;

CREATE TABLE IF NOT EXISTS keymgr.key_policy_def (
                                       app_id VARCHAR(36) NOT NULL,
                                       key_validity_duration SMALLINT,
                                       is_active BOOLEAN NOT NULL,
                                       pre_expire_days SMALLINT,
                                       access_allowed VARCHAR(1024),
                                       cr_by VARCHAR(256) NOT NULL,
                                       cr_dtimes TIMESTAMP NOT NULL,
                                       upd_by VARCHAR(256),
                                       upd_dtimes TIMESTAMP,
                                       is_deleted BOOLEAN DEFAULT FALSE,
                                       del_dtimes TIMESTAMP,
                                       CONSTRAINT pk_keypdef_id PRIMARY KEY (app_id)
);

CREATE TABLE IF NOT EXISTS keymgr.key_alias (
                                  id VARCHAR(36) NOT NULL,
                                  app_id VARCHAR(36) NOT NULL,
                                  ref_id VARCHAR(128),
                                  key_gen_dtimes TIMESTAMP,
                                  key_expire_dtimes TIMESTAMP,
                                  status_code VARCHAR(36),
                                  lang_code VARCHAR(3),
                                  cr_by VARCHAR(256) NOT NULL,
                                  cr_dtimes TIMESTAMP NOT NULL,
                                  upd_by VARCHAR(256),
                                  upd_dtimes TIMESTAMP,
                                  is_deleted BOOLEAN DEFAULT FALSE,
                                  del_dtimes TIMESTAMP,
                                  cert_thumbprint VARCHAR(100),
                                  uni_ident VARCHAR(50),
                                  CONSTRAINT pk_keymals_id PRIMARY KEY (id),
                                  CONSTRAINT uni_ident_const UNIQUE (uni_ident)
);

CREATE TABLE IF NOT EXISTS keymgr.key_store (
                                  id VARCHAR(36) NOT NULL,
                                  master_key VARCHAR(36) NOT NULL,
                                  private_key VARCHAR(2500) NOT NULL,
                                  certificate_data VARCHAR(5000) NOT NULL,
                                  cr_by VARCHAR(256) NOT NULL,
                                  cr_dtimes TIMESTAMP NOT NULL,
                                  upd_by VARCHAR(256),
                                  upd_dtimes TIMESTAMP,
                                  is_deleted BOOLEAN DEFAULT FALSE,
                                  del_dtimes TIMESTAMP,
                                  CONSTRAINT pk_keystr_id PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS keymgr.ca_cert_store (
                                      cert_id VARCHAR(36) NOT NULL,
                                      cert_subject VARCHAR(500) NOT NULL,
                                      cert_issuer VARCHAR(500) NOT NULL,
                                      issuer_id VARCHAR(36) NOT NULL,
                                      cert_not_before TIMESTAMP,
                                      cert_not_after TIMESTAMP,
                                      crl_uri VARCHAR(120),
                                      cert_data VARCHAR(5000),
                                      cert_thumbprint VARCHAR(100),
                                      cert_serial_no VARCHAR(50),
                                      partner_domain VARCHAR(36),
                                      cr_by VARCHAR(256),
                                      cr_dtimes TIMESTAMP,
                                      upd_by VARCHAR(256),
                                      upd_dtimes TIMESTAMP,
                                      is_deleted BOOLEAN DEFAULT FALSE,
                                      del_dtimes TIMESTAMP,
                                      ca_cert_type VARCHAR(25),
                                      CONSTRAINT pk_cacs_id PRIMARY KEY (cert_id),
                                      CONSTRAINT cert_thumbprint_unique UNIQUE (cert_thumbprint, partner_domain)
);

CREATE TABLE IF NOT EXISTS keymgr.partner_cert_store (
                                           cert_id VARCHAR(36) NOT NULL,
                                           cert_subject VARCHAR(500) NOT NULL,
                                           cert_issuer VARCHAR(500) NOT NULL,
                                           issuer_id VARCHAR(36) NOT NULL,
                                           cert_not_before TIMESTAMP,
                                           cert_not_after TIMESTAMP,
                                           partner_domain VARCHAR(36),
                                           cert_data VARCHAR(5000),
                                           signed_cert_data VARCHAR(50000),
                                           key_usage VARCHAR(150),
                                           organization_name VARCHAR(120),
                                           cert_thumbprint VARCHAR(100),
                                           cert_serial_no VARCHAR(50),
                                           cr_by VARCHAR(256),
                                           cr_dtimes TIMESTAMP,
                                           upd_by VARCHAR(256),
                                           upd_dtimes TIMESTAMP,
                                           is_deleted BOOLEAN DEFAULT FALSE,
                                           del_dtimes TIMESTAMP,
                                           CONSTRAINT pk_parcs_id PRIMARY KEY (cert_id)
);

CREATE TABLE IF NOT EXISTS keymgr.data_encrypt_keystore (
                                              id BIGINT NOT NULL,
                                              "key" VARCHAR(64) NOT NULL,
                                              key_status VARCHAR(16),
                                              cr_by VARCHAR(256) NOT NULL,
                                              cr_dtimes TIMESTAMP NOT NULL,
                                              upd_by VARCHAR(256),
                                              upd_dtimes TIMESTAMP,
                                              CONSTRAINT pk_dekstr_id PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS keymgr.licensekey_list (
                                        license_key VARCHAR(255) NOT NULL,
                                        created_dtime TIMESTAMP,
                                        expiry_dtime TIMESTAMP,
                                        is_active BOOLEAN NOT NULL,
                                        cr_by VARCHAR(256) NOT NULL,
                                        cr_dtimes TIMESTAMP NOT NULL,
                                        upd_by VARCHAR(256),
                                        upd_dtimes TIMESTAMP,
                                        is_deleted BOOLEAN DEFAULT FALSE,
                                        del_dtimes TIMESTAMP,
                                        CONSTRAINT pk_lkeylst PRIMARY KEY (license_key)
);

CREATE TABLE IF NOT EXISTS keymgr.licensekey_permission (
                                              license_key VARCHAR(255) NOT NULL,
                                              permission VARCHAR(512),
                                              is_active BOOLEAN NOT NULL,
                                              cr_by VARCHAR(256) NOT NULL,
                                              cr_dtimes TIMESTAMP NOT NULL,
                                              upd_by VARCHAR(256),
                                              upd_dtimes TIMESTAMP,
                                              is_deleted BOOLEAN DEFAULT FALSE,
                                              del_dtimes TIMESTAMP,
                                              CONSTRAINT pk_lkeyper PRIMARY KEY (license_key)
);

CREATE TABLE IF NOT EXISTS keymgr.tsp_licensekey_map (
                                           tsp_id VARCHAR(36) NOT NULL,
                                           license_key VARCHAR(255) NOT NULL,
                                           is_active BOOLEAN NOT NULL,
                                           cr_by VARCHAR(256) NOT NULL,
                                           cr_dtimes TIMESTAMP NOT NULL,
                                           upd_by VARCHAR(256),
                                           upd_dtimes TIMESTAMP,
                                           is_deleted BOOLEAN DEFAULT FALSE,
                                           del_dtimes TIMESTAMP,
                                           CONSTRAINT pk_tsplkeym PRIMARY KEY (tsp_id, license_key)
);

-- ALTER TABLE keymgr.tsp_licensekey_map ADD CONSTRAINT fk_tsplkeym FOREIGN KEY (license_key)
--     REFERENCES keymgr.licensekey_list (license_key) ON DELETE NO ACTION ON UPDATE NO ACTION;
--
-- ALTER TABLE keymgr.licensekey_permission ADD CONSTRAINT fk_lkeyper FOREIGN KEY (license_key)
--     REFERENCES keymgr.licensekey_list (license_key) ON DELETE NO ACTION ON UPDATE NO ACTION;

-- ALTER TABLE keymgr.key_store ALTER COLUMN certificate_data VARCHAR(5000);
-- ALTER TABLE keymgr.key_store ALTER COLUMN private_key VARCHAR(2500);
-- ALTER TABLE keymgr.ca_cert_store ALTER COLUMN cert_data VARCHAR(5000);
-- ALTER TABLE keymgr.partner_cert_store ALTER COLUMN signed_cert_data VARCHAR(50000);