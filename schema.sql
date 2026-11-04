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
