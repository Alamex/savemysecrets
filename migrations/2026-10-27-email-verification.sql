-- Email verification for open signup (2026-10-27)
-- Users must verify their email before they can use the vault

ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN email_verify_token TEXT;
ALTER TABLE users ADD COLUMN email_verify_token_expires INTEGER;

-- Existing users are already verified (they came through invite-only)
UPDATE users SET email_verified = 1 WHERE email_verified = 0;
