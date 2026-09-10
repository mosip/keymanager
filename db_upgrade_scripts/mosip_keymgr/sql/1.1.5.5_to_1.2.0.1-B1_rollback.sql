\c :mosipdbname

REASSIGN OWNED BY postgres TO sysadmin;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA keymgr TO sysadmin;

delete from keymgr.key_policy_def where app_id in ('ADMIN_SERVICES','RESIDENT','COMPLIANCE_TOOLKIT'); 


ALTER TABLE keymgr.key_alias DROP COLUMN IF EXISTS uni_ident;

ALTER TABLE keymgr.key_policy_def DROP COLUMN IF EXISTS pre_expire_days;
ALTER TABLE keymgr.key_policy_def DROP COLUMN IF EXISTS access_allowed;
