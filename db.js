// ================================
// Postgres pool + schema init
// ================================
// Reads DATABASE_URL from env. On Railway it's injected automatically when the
// Postgres service is linked. Locally, paste the public connection string from
// Railway (Settings → Public Networking) into .env.
//
// Schema is applied idempotently on boot — the file is small and lives in
// schema.sql at the repo root. No migration framework yet; keep it simple.

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('[db] DATABASE_URL is not set. Add it to .env for local dev or link Postgres on Railway.');
  process.exit(1);
}

// Railway Postgres public URL uses TLS. The private URL inside Railway's network
// does not, but node-postgres handles both transparently when ssl is enabled.
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
});

pool.on('error', err => console.error('[db] pool error:', err));

async function initSchema() {
  const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(sql);
  console.log('  Postgres schema ready');
}

function query(text, params) {
  return pool.query(text, params);
}

module.exports = { pool, query, initSchema };
