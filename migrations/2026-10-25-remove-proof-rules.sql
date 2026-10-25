-- Migration: remove proof-rule/death-certificate requirements
-- Date: 2026-10-25
-- 
-- Product decision: simplify to interview-only release verification.
-- No database migration is run (to preserve existing data), but new saves
-- always set proof_required='none', and all reads/enforcement treat stored
-- values as if they were 'none'.

-- Existing rows keep their stored proof_required values (none/nominee_confirm/death_certificate)
-- but the application always uses 'none' regardless of what's stored.
-- Future schema change could: UPDATE users SET proof_required='none' WHERE proof_required!='none';
-- but leaving stored values unchanged is safer during alpha.

-- No ALTER TABLE needed; the default remains for reference only.
