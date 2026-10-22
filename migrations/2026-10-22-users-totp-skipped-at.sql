-- Optional 2FA: records when an owner chose "Skip for now" at signup (NULL = never skipped).
-- Additive and safe to run once on production D1 (savemysecrets-signups) before deploying the code that uses it.
ALTER TABLE users ADD COLUMN totp_skipped_at INTEGER;
