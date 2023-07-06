\c mosip_keymgr

REASSIGN OWNED BY sysadmin TO postgres;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA keymgr FROM keymgruser;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA keymgr FROM sysadmin;

GRANT SELECT, INSERT, TRUNCATE, REFERENCES, UPDATE, DELETE ON ALL TABLES IN SCHEMA keymgr TO keymgruser;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA keymgr TO postgres;

ALTER TABLE keymgr.ca_cert_store ADD CONSTRAINT cert_thumbprint_unique UNIQUE (cert_thumbprint,partner_domain);

ALTER TABLE keymgr.key_alias ADD COLUMN uni_ident character varying(50);
ALTER TABLE keymgr.key_alias ADD CONSTRAINT uni_ident_const UNIQUE (uni_ident);

ALTER TABLE keymgr.key_policy_def ADD COLUMN pre_expire_days smallint;
ALTER TABLE keymgr.key_policy_def ADD COLUMN access_allowed character varying(1024);

insert into keymgr.key_policy_def(app_id, key_validity_duration, is_active, cr_by, cr_dtimes, pre_expire_days, access_allowed) 
	SELECT 'ADMIN_SERVICES',1095,TRUE,'mosipadmin',now(),60,'NA' WHERE NOT EXISTS (SELECT app_id FROM keymgr.key_policy_def WHERE app_id='ADMIN_SERVICES');
insert into keymgr.key_policy_def(app_id, key_validity_duration, is_active, cr_by, cr_dtimes, pre_expire_days, access_allowed) 
	SELECT 'RESIDENT',1095,TRUE,'mosipadmin',now(),60,'NA' WHERE NOT EXISTS (SELECT app_id FROM keymgr.key_policy_def WHERE app_id='RESIDENT');
insert into keymgr.key_policy_def(app_id, key_validity_duration, is_active, cr_by, cr_dtimes, pre_expire_days, access_allowed) 
	SELECT 'COMPLIANCE_TOOLKIT',1095,TRUE,'mosipadmin',now(),60,'NA' WHERE NOT EXISTS (SELECT app_id FROM keymgr.key_policy_def WHERE app_id='COMPLIANCE_TOOLKIT');


-- updating default values for pre_expire_days & access_allowed columns
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='PRE_REGISTRATION';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='REGISTRATION';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='REGISTRATION_PROCESSOR';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='ID_REPO';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='KERNEL';
update keymgr.key_policy_def set pre_expire_days=1125, access_allowed='NA' where app_id='ROOT';
update keymgr.key_policy_def set pre_expire_days=30, access_allowed='NA' where app_id='BASE';
update keymgr.key_policy_def set pre_expire_days=395, access_allowed='NA' where app_id='PMS';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='ADMIN_SERVICES';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='RESIDENT';
update keymgr.key_policy_def set pre_expire_days=60, access_allowed='NA' where app_id='COMPLIANCE_TOOLKIT';

delete from keymgr.key_policy_def where app_id='IDA';
delete from keymgr.key_policy_def where app_id='DATASHARE';