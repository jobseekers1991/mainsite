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

-- ============================================================
-- Admin role: allow a third role so admin.html and /api/admin/* can gate on it.
-- The CHECK constraint on accounts.role is replaced to accept 'admin' too.
-- ============================================================

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_role_check') THEN
    ALTER TABLE accounts DROP CONSTRAINT accounts_role_check;
  END IF;
EXCEPTION WHEN undefined_table THEN NULL;
END$$;

ALTER TABLE accounts ADD CONSTRAINT accounts_role_check
  CHECK (role IN ('client', 'va', 'admin'));

-- ============================================================
-- Per-user key/value settings. Used by settings.html (notifications toggles,
-- language, timezone, etc.). Shape is intentionally open — one JSONB column so
-- we can add new preference keys without migrations.
-- ============================================================

CREATE TABLE IF NOT EXISTS user_settings (
  account_id   TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  data         JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at   BIGINT NOT NULL
);

-- ============================================================
-- Notifications. One row per delivered in-app notification. The frontend
-- polls /api/notifications; read_at is nulled until the user opens the page.
-- ============================================================

CREATE TABLE IF NOT EXISTS notifications (
  id           TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind         TEXT NOT NULL,        -- application, message, interview, timesheet, invoice, system
  title        TEXT NOT NULL,
  body         TEXT,
  link         TEXT,                 -- optional deep-link path
  read_at      BIGINT,
  created_at   BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_account_created
  ON notifications (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_unread
  ON notifications (account_id) WHERE read_at IS NULL;

-- ============================================================
-- Talent-pool favorites. One row per (client, saved_va). Deduped.
-- saved_va_id is nullable so clients can save directory profiles too;
-- for those we store the slug in saved_va_slug and leave the id NULL.
-- ============================================================

CREATE TABLE IF NOT EXISTS favorites (
  id             TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  saved_va_id    TEXT REFERENCES accounts(id) ON DELETE CASCADE,
  saved_va_slug  TEXT,
  note           TEXT,
  created_at     BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_favorites_client_vaid
  ON favorites (client_id, saved_va_id) WHERE saved_va_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_favorites_client_slug
  ON favorites (client_id, saved_va_slug) WHERE saved_va_slug IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_favorites_client ON favorites (client_id, created_at DESC);

-- ============================================================
-- Job templates. Pre-saved job post drafts a client can reuse.
-- ============================================================

CREATE TABLE IF NOT EXISTS job_templates (
  id             TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name           TEXT NOT NULL,
  data           JSONB NOT NULL DEFAULT '{}'::jsonb,   -- mirrors the job post form shape
  created_at     BIGINT NOT NULL,
  updated_at     BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_job_templates_client ON job_templates (client_id, created_at DESC);

-- ============================================================
-- Interviews. Scheduled video/phone/in-platform interviews between client+VA.
-- ============================================================

CREATE TABLE IF NOT EXISTS interviews (
  id             TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  va_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  job_id         TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  application_id TEXT REFERENCES applications(id) ON DELETE SET NULL,
  scheduled_for  BIGINT NOT NULL,
  duration_min   INTEGER NOT NULL DEFAULT 30,
  platform       TEXT NOT NULL DEFAULT 'zoom',   -- zoom, meet, phone, inplatform
  meeting_url    TEXT,
  notes          TEXT,
  status         TEXT NOT NULL DEFAULT 'upcoming'
                   CHECK (status IN ('upcoming', 'completed', 'cancelled', 'no-show')),
  created_at     BIGINT NOT NULL,
  updated_at     BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_interviews_client ON interviews (client_id, scheduled_for DESC);
CREATE INDEX IF NOT EXISTS idx_interviews_va     ON interviews (va_id, scheduled_for DESC);
CREATE INDEX IF NOT EXISTS idx_interviews_job    ON interviews (job_id);

-- ============================================================
-- Timesheets. VA submits weekly hours; client approves. Hours stored in
-- whole minutes to avoid float.
-- ============================================================

CREATE TABLE IF NOT EXISTS timesheets (
  id            TEXT PRIMARY KEY,
  client_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  va_id         TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  job_id        TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  week_start    TEXT NOT NULL,        -- YYYY-MM-DD, Monday of the week
  minutes       INTEGER NOT NULL,
  rate          NUMERIC(10,2) NOT NULL,
  summary       TEXT,
  status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'approved', 'rejected')),
  decided_at    BIGINT,
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timesheets_client  ON timesheets (client_id, week_start DESC);
CREATE INDEX IF NOT EXISTS idx_timesheets_va      ON timesheets (va_id, week_start DESC);
CREATE INDEX IF NOT EXISTS idx_timesheets_pending ON timesheets (client_id) WHERE status = 'pending';

-- ============================================================
-- Invoices. VA bills a client. Status: draft / sent / paid / void.
-- ============================================================

CREATE TABLE IF NOT EXISTS invoices (
  id            TEXT PRIMARY KEY,
  client_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  va_id         TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  job_id        TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  invoice_no    TEXT NOT NULL,
  issued_on     TEXT NOT NULL,        -- YYYY-MM-DD
  due_on        TEXT,                 -- YYYY-MM-DD
  currency      TEXT NOT NULL DEFAULT 'USD',
  subtotal      NUMERIC(12,2) NOT NULL,
  total         NUMERIC(12,2) NOT NULL,
  items         JSONB NOT NULL DEFAULT '[]'::jsonb,
  notes         TEXT,
  status        TEXT NOT NULL DEFAULT 'sent'
                  CHECK (status IN ('draft', 'sent', 'paid', 'void')),
  paid_at       BIGINT,
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invoices_client ON invoices (client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invoices_va     ON invoices (va_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices (status);

-- ============================================================
-- Reviews. Mutual ratings between client and VA after a hire. One review per
-- (reviewer, hire) pair.
-- ============================================================

CREATE TABLE IF NOT EXISTS reviews (
  id            TEXT PRIMARY KEY,
  reviewer_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  subject_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  job_id        TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  rating        INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  body          TEXT,
  created_at    BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_reviewer_subject_job
  ON reviews (reviewer_id, subject_id, COALESCE(job_id, ''));
CREATE INDEX IF NOT EXISTS idx_reviews_subject ON reviews (subject_id, created_at DESC);

-- ============================================================
-- Teams (client-side workspaces). A client account owns a team and can
-- invite other clients as members.
-- ============================================================

CREATE TABLE IF NOT EXISTS teams (
  id            TEXT PRIMARY KEY,
  owner_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  created_at    BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_teams_owner ON teams (owner_id);

CREATE TABLE IF NOT EXISTS team_members (
  id            TEXT PRIMARY KEY,
  team_id       TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  account_id    TEXT REFERENCES accounts(id) ON DELETE CASCADE,
  invite_email  TEXT,
  role          TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'invited', 'removed')),
  created_at    BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_team_members_unique
  ON team_members (team_id, COALESCE(account_id, invite_email, ''));
CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members (team_id);

-- ============================================================
-- Trials. Separate table for active trial periods — ties to an application
-- and records hours/days committed. When the trial ends, the client either
-- hires (updates application to 'hired') or passes.
-- ============================================================

CREATE TABLE IF NOT EXISTS trials (
  id              TEXT PRIMARY KEY,
  application_id  TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  job_id          TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  client_id       TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  va_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  started_at      BIGINT NOT NULL,
  ends_at         BIGINT NOT NULL,
  scope           TEXT,
  outcome         TEXT CHECK (outcome IN ('hired', 'passed', 'cancelled')),
  decided_at      BIGINT,
  created_at      BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_trials_application ON trials (application_id);
CREATE INDEX IF NOT EXISTS idx_trials_client ON trials (client_id, ends_at DESC);
CREATE INDEX IF NOT EXISTS idx_trials_va     ON trials (va_id, ends_at DESC);

-- ============================================================
-- Academy course progress. One row per (va, course) with the furthest step
-- reached and last activity. Certificates (existing va_certificates) are the
-- completion artifact.
-- ============================================================

CREATE TABLE IF NOT EXISTS academy_progress (
  account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  course        TEXT NOT NULL,
  step          INTEGER NOT NULL DEFAULT 0,
  score         INTEGER,
  updated_at    BIGINT NOT NULL,
  PRIMARY KEY (account_id, course)
);

-- ============================================================
-- Contact-form submissions. Written when a visitor submits contact.html.
-- No email yet — Trust & Safety can scan these via /api/admin/contact.
-- ============================================================

CREATE TABLE IF NOT EXISTS contact_messages (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  email      TEXT NOT NULL,
  subject    TEXT,
  body       TEXT NOT NULL,
  ip         TEXT,
  created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_contact_messages_created ON contact_messages (created_at DESC);

-- ============================================================
-- Community forum. Threads + nested replies. Soft-moderated —
-- status flips to 'flagged' when the scam/off-platform rules trip.
-- ============================================================

CREATE TABLE IF NOT EXISTS forum_threads (
  id            TEXT PRIMARY KEY,
  author_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  category      TEXT NOT NULL,
  title         TEXT NOT NULL,
  body          TEXT,
  views         INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open', 'closed', 'flagged', 'removed')),
  last_reply_at BIGINT NOT NULL,
  created_at    BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_forum_threads_cat_time
  ON forum_threads (category, last_reply_at DESC);
CREATE INDEX IF NOT EXISTS idx_forum_threads_time
  ON forum_threads (last_reply_at DESC);
CREATE INDEX IF NOT EXISTS idx_forum_threads_author
  ON forum_threads (author_id);

CREATE TABLE IF NOT EXISTS forum_replies (
  id            TEXT PRIMARY KEY,
  thread_id     TEXT NOT NULL REFERENCES forum_threads(id) ON DELETE CASCADE,
  author_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  body          TEXT NOT NULL,
  flagged       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_forum_replies_thread
  ON forum_replies (thread_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_forum_replies_author
  ON forum_replies (author_id);
