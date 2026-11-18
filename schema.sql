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
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS avatar_data  BYTEA;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS avatar_mime  TEXT;

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

-- ============================================================
-- Marketplace core: jobs, applications, threads, messages
-- ============================================================

CREATE TABLE IF NOT EXISTS jobs (
  id                   TEXT PRIMARY KEY,
  client_id            TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  title                TEXT NOT NULL,
  category             TEXT,
  job_type             TEXT NOT NULL CHECK (job_type IN ('fulltime','parttime','project','contract')),
  shift                TEXT NOT NULL CHECK (shift IN ('us-east','us-west','uk','au','ph','flex')),
  description          TEXT NOT NULL,
  pay_min              NUMERIC(10,2),
  pay_max              NUMERIC(10,2),
  experience_level     TEXT,
  english_level        TEXT,
  skills               JSONB NOT NULL DEFAULT '[]'::jsonb,
  screening_questions  JSONB NOT NULL DEFAULT '[]'::jsonb,
  application_deadline TEXT,
  start_mode           TEXT CHECK (start_mode IN ('trial','direct')),
  trial_days           INTEGER,
  trial_hours          INTEGER,
  trial_scope          TEXT,
  company_name         TEXT,
  status               TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','flagged','removed')),
  created_at           BIGINT NOT NULL,
  updated_at           BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_client_id   ON jobs (client_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status      ON jobs (status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at  ON jobs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_shift       ON jobs (shift);

CREATE TABLE IF NOT EXISTS applications (
  id              TEXT PRIMARY KEY,
  job_id          TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  va_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  cover           TEXT NOT NULL,
  rate            NUMERIC(10,2) NOT NULL,
  can_start       TEXT,
  answers         JSONB NOT NULL DEFAULT '[]'::jsonb,
  shift_ok        BOOLEAN NOT NULL DEFAULT FALSE,
  open_to_trial   BOOLEAN NOT NULL DEFAULT FALSE,
  attach_profile  BOOLEAN NOT NULL DEFAULT TRUE,
  status          TEXT NOT NULL DEFAULT 'submitted'
                    CHECK (status IN ('submitted','viewed','interview','trial','trialing','hired','rejected','withdrawn')),
  created_at      BIGINT NOT NULL,
  updated_at      BIGINT NOT NULL
);

-- One live application per VA per job. Withdrawn applications don't block re-applying.
CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_unique_active
  ON applications (job_id, va_id) WHERE status <> 'withdrawn';
CREATE INDEX IF NOT EXISTS idx_applications_va_id   ON applications (va_id);
CREATE INDEX IF NOT EXISTS idx_applications_job_id  ON applications (job_id);
CREATE INDEX IF NOT EXISTS idx_applications_status  ON applications (status);

CREATE TABLE IF NOT EXISTS threads (
  id               TEXT PRIMARY KEY,
  client_id        TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  va_id            TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  job_id           TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  last_message_at  BIGINT NOT NULL,
  created_at       BIGINT NOT NULL
);

-- One thread per (client, va, job) combo. job_id NULL means a general thread
-- not tied to a specific job — those still dedupe per (client, va).
CREATE UNIQUE INDEX IF NOT EXISTS idx_threads_unique_with_job
  ON threads (client_id, va_id, job_id) WHERE job_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_threads_unique_no_job
  ON threads (client_id, va_id) WHERE job_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_threads_client_id ON threads (client_id, last_message_at DESC);
CREATE INDEX IF NOT EXISTS idx_threads_va_id     ON threads (va_id, last_message_at DESC);

CREATE TABLE IF NOT EXISTS messages (
  id                 TEXT PRIMARY KEY,
  thread_id          TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
  sender_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  body               TEXT NOT NULL,
  off_platform_flag  BOOLEAN NOT NULL DEFAULT FALSE,
  read_at            BIGINT,
  created_at         BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_thread_created ON messages (thread_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender_id      ON messages (sender_id);
