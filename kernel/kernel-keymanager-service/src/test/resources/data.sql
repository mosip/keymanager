INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'PRE_REGISTRATION', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'PRE_REGISTRATION');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'REGISTRATION', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'REGISTRATION');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'REGISTRATION_PROCESSOR', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'REGISTRATION_PROCESSOR');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'ID_REPO', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'ID_REPO');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'KERNEL', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'KERNEL');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'ROOT', 2920, TRUE, 1125, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'ROOT');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'BASE', 730, TRUE, 30, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'BASE');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'PMS', 1460, TRUE, 395, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'PMS');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'RESIDENT', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'RESIDENT');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'ADMIN_SERVICES', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'ADMIN_SERVICES');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'DIGITAL_CARD', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'DIGITAL_CARD');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'COMPLIANCE_TOOLKIT', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'COMPLIANCE_TOOLKIT');

INSERT INTO keymgr.key_policy_def
(app_id, key_validity_duration, is_active, pre_expire_days, access_allowed, cr_by, cr_dtimes, upd_by, upd_dtimes, is_deleted, del_dtimes)
SELECT 'TEST', 1095, TRUE, 60, 'NA', 'mosipadmin', '2024-07-15 19:25:11.482', NULL, NULL, FALSE, NULL
    WHERE NOT EXISTS (SELECT 1 FROM keymgr.key_policy_def WHERE app_id = 'TEST');
