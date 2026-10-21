-- PR #11 (head 6667c45): the only schema change vs main is a new nullable column on invites.
-- Additive and safe on existing rows (NULL = legacy/manual code, not tied to an email).
ALTER TABLE invites ADD COLUMN approved_email TEXT;
