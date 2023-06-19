\c mosip_keymgr 

TRUNCATE TABLE keymgr.key_policy_def cascade ;

\COPY keymgr.key_policy_def (app_id,key_validity_duration,is_active,cr_by,cr_dtimes,pre_expire_days,access_allowed) FROM './dml/keymgr-key_policy_def.csv' delimiter ',' HEADER  csv;