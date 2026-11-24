#!/usr/bin/env node
/*
  Create (or reset) an admin account directly.

  Usage:
    node scripts/create-admin.js <email> <password>
*/
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

(function loadEnv() {
  const envPath = path.resolve(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i);
    if (!m) continue;
    const [, k, v] = m;
    if (!process.env[k]) process.env[k] = v.replace(/^["']|["']$/g, '');
  }
})();

const { Pool } = require('pg');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

async function main() {
  const email = (process.argv[2] || '').trim().toLowerCase();
  const password = process.argv[3] || '';
  if (!email || !password) {
    console.error('Usage: node scripts/create-admin.js <email> <password>');
    process.exit(2);
  }
  if (password.length < 8) {
    console.error('Password must be at least 8 characters.');
    process.exit(2);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
  });

  const { salt, hash } = hashPassword(password);
  const existing = await pool.query('SELECT id, role FROM accounts WHERE email = $1', [email]);
  if (existing.rows[0]) {
    await pool.query(
      `UPDATE accounts SET role = 'admin', verified = TRUE,
              password_hash = $1, password_salt = $2,
              suspended = FALSE, suspend_reason = NULL
        WHERE id = $3`,
      [hash, salt, existing.rows[0].id]
    );
    console.log(`Updated existing account ${email} (was ${existing.rows[0].role}) -> admin, password reset.`);
  } else {
    const id = 'u_' + crypto.randomBytes(8).toString('hex');
    await pool.query(
      `INSERT INTO accounts (id, role, email, password_hash, password_salt, first_name, last_name,
         verified, created_at)
       VALUES ($1, 'admin', $2, $3, $4, 'Admin', 'Jobseekers.ph', TRUE, $5)`,
      [id, email, hash, salt, Date.now()]
    );
    console.log(`Created new admin account ${email} (id: ${id})`);
  }
  console.log(`Sign in at /auth with:`);
  console.log(`  email:    ${email}`);
  console.log(`  password: ${password}`);
  await pool.end();
}

main().catch(err => { console.error(err); process.exit(1); });
