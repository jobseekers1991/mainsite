CREATE TABLE IF NOT EXISTS accounts (
  id              TEXT PRIMARY KEY,
  role            TEXT NOT NULL CHECK (role IN ('client', 'va')),
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  password_salt   TEXT NOT NULL,
  first_name      TEXT NOT NULL,
  last_name       TEXT NOT NULL,
  verified        BOOLEAN NOT NULL DEFAULT FALSE,
  verify_token_hash TEXT,
  verify_expires  BIGINT,
  company_name    TEXT,
  company_size    TEXT,
  source          TEXT,
  mobile          TEXT,
  city            TEXT,
  skill           TEXT,
  years           TEXT,
  created_at      BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_verify_token_hash ON accounts (verify_token_hash) WHERE verify_token_hash IS NOT NULL;

-- Profile fields added after the initial schema. Idempotent so we can re-run on boot.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS title        TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS tagline      TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS profile_data JSONB;

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires     BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_account_id ON sessions (account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires);

CREATE TABLE IF NOT EXISTS password_resets (
  token_hash  TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires     BIGINT NOT NULL,
  used        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_password_resets_account_id ON password_resets (account_id);

CREATE TABLE IF NOT EXISTS va_certificates (
  id              TEXT PRIMARY KEY,
  account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  source          TEXT NOT NULL CHECK (source IN ('academy', 'external')),
  title           TEXT NOT NULL,
  issuer          TEXT,
  issue_date      TEXT,
  credential_url  TEXT,
  academy_course  TEXT,
  academy_score   TEXT,
  image_data      BYTEA,
  image_mime      TEXT,
  created_at      BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_va_certificates_account_id ON va_certificates (account_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_va_certificates_one_academy_per_course
  ON va_certificates (account_id, academy_course)
  WHERE source = 'academy';

CREATE TABLE IF NOT EXISTS va_portfolio (
  id            TEXT PRIMARY KEY,
  account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  title         TEXT NOT NULL,
  category      TEXT,
  description   TEXT,
  link_url      TEXT,
  file_data     BYTEA,
  file_mime     TEXT,
  created_at    BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_va_portfolio_account_id ON va_portfolio (account_id);

-- Upwork-style portfolio fields added after the initial va_portfolio schema.
ALTER TABLE va_portfolio ADD COLUMN IF NOT EXISTS role         TEXT;
ALTER TABLE va_portfolio ADD COLUMN IF NOT EXISTS completed_on TEXT;
ALTER TABLE va_portfolio ADD COLUMN IF NOT EXISTS skills_used  JSONB;
