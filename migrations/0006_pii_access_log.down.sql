-- 0006_pii_access_log.down.sql — backward-compatible rollback of 0006.
-- Drops the LGPD/art.13 PII read-access register. The forensic mutation trail
-- (audit_log) and the mandate/charge records (pix_rec/pix_cobr) are unaffected —
-- they live in their own tables. Reversible by re-applying 0006.up.
DROP TABLE IF EXISTS pii_access_log;
