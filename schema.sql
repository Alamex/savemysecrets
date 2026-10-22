-- Save My Secrets alpha schema (Cloudflare D1)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  phone TEXT,
  auth_salt TEXT NOT NULL,          -- server-side salt for the auth hash
  auth_hash TEXT NOT NULL,          -- PBKDF2 of the client auth key (server never sees the password)
  kdf_salt TEXT NOT NULL,           -- client KDF salt (public)
  totp_secret TEXT,                 -- base32, null until 2FA enrolled
  totp_enabled INTEGER DEFAULT 0,
  totp_skipped_at INTEGER,         -- set when the owner chose "Skip for now" at signup; cleared when 2FA is turned on
  invite_code TEXT,
  recovery_hashes TEXT,             -- SHA-256 of one-off recovery codes
  link_used_issue INTEGER DEFAULT 0, -- check-in links issued at or before this are spent
  prev_state TEXT, prev_next_checkin INTEGER, forced_overdue INTEGER DEFAULT 0,
  -- vault (all ciphertext; server cannot read)
  vault_ct TEXT,                    -- AES-GCM(K_vault, vault JSON)
  wrapped_owner TEXT,               -- AES-GCM(K_owner(password), K_vault)
  wrapped_release TEXT,             -- AES-GCM(HKDF(S || L), K_vault)
  server_share TEXT,                -- S, released only after verification
  release_mode TEXT DEFAULT 'sovereign', -- sovereign = needs printed legacy code; standard = server can release alone
  -- policy
  checkin_days INTEGER DEFAULT 90,
  grace_weeks INTEGER DEFAULT 6,
  proof_required TEXT DEFAULT 'death_certificate', -- none | nominee_confirm | death_certificate
  veto_days INTEGER DEFAULT 7,
  -- state machine
  state TEXT DEFAULT 'active',      -- active | overdue | nominees_contacted | veto_window | released
  next_checkin_at INTEGER,
  overdue_since INTEGER,
  last_reminder_at INTEGER,
  reminders_sent INTEGER DEFAULT 0,
  veto_ends_at INTEGER,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id TEXT NOT NULL, stage TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nominees (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
  name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT, address TEXT, relationship TEXT,
  notify_early INTEGER DEFAULT 0,   -- 0 = they only hear from us at trigger time
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS claims (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, nominee_id TEXT, claimant_id TEXT,
  claimant_email TEXT NOT NULL, claimant_name TEXT,
  status TEXT DEFAULT 'otp',        -- otp | interview | awaiting_document | review | approved | rejected | vetoed | released
  otp_hash TEXT, otp_expires INTEGER,
  token TEXT,                       -- claimant session token
  transcript TEXT DEFAULT '[]',
  ai_assessment TEXT,
  doc_key TEXT, doc_analysis TEXT,
  admin_note TEXT, unlock_fails INTEGER DEFAULT 0, unlock_after INTEGER,
  created_at INTEGER, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, kind TEXT, detail TEXT, at INTEGER
);
-- signups already exists in production (holding page); created here for local dev only
CREATE TABLE IF NOT EXISTS signups (
  id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, source TEXT, ip TEXT, ua TEXT,
  created_at TEXT DEFAULT (datetime('now')), invited_at INTEGER, invite_code TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_signups_email ON signups(email);
-- added Oct 2026: ALTER TABLE signups ADD COLUMN invited_at INTEGER; ALTER TABLE signups ADD COLUMN invite_code TEXT;
CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY, label TEXT, max_uses INTEGER DEFAULT 100, uses INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1, approved_email TEXT, expires_at INTEGER, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS claimants (
  id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT, otp_hash TEXT, otp_expires INTEGER,
  otp_attempts INTEGER DEFAULT 0, verified INTEGER DEFAULT 0, token TEXT, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS ratelimit ( key TEXT PRIMARY KEY, count INTEGER, reset_at INTEGER );
CREATE TABLE IF NOT EXISTS docs ( key TEXT PRIMARY KEY, mime TEXT, data TEXT, created_at INTEGER );
CREATE INDEX IF NOT EXISTS idx_users_state ON users(state, next_checkin_at);
CREATE INDEX IF NOT EXISTS idx_claims_user ON claims(user_id);
CREATE INDEX IF NOT EXISTS idx_claimants_token ON claimants(token);
CREATE INDEX IF NOT EXISTS idx_claims_token ON claims(token);
CREATE TABLE IF NOT EXISTS feedback ( id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, email TEXT, page TEXT, text TEXT NOT NULL, created_at INTEGER );
CREATE TABLE IF NOT EXISTS nominee_keys ( nominee_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, questions TEXT NOT NULL, salts TEXT NOT NULL, wraps TEXT NOT NULL, verifiers TEXT NOT NULL, created_at INTEGER );
