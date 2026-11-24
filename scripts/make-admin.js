#!/usr/bin/env node
/*
  Promote an existing account to role='admin' by email.

  Usage:
    node scripts/make-admin.js seo@airvidachambers.com
    node scripts/make-admin.js seo@airvidachambers.com --demote

  Reads DATABASE_URL from .env (same file server.js uses). The account must
  already exist — sign up normally first at /auth, then run this.
*/

const path = require('path');
const fs = require('fs');

// Load .env the same way the server does (simple KEY=VALUE parser so we
// don't need a dotenv dependency).
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

async function main() {
  const email = (process.argv[2] || '').trim().toLowerCase();
  const demote = process.argv.includes('--demote');
  if (!email) {
    console.error('Usage: node scripts/make-admin.js <email> [--demote]');
    process.exit(2);
  }
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is not set. Add it to .env.');
    process.exit(2);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
  });

  const existing = await pool.query(
    'SELECT id, role, email, first_name, last_name FROM accounts WHERE email = $1',
    [email]
  );
  const acc = existing.rows[0];
  if (!acc) {
    console.error(`No account found with email: ${email}`);
    console.error('Sign up first at /auth, then rerun this script.');
    await pool.end();
    process.exit(1);
  }

  const newRole = demote ? (acc.role === 'admin' ? 'client' : acc.role) : 'admin';
  if (acc.role === newRole) {
    console.log(`${email} is already role='${acc.role}'. Nothing to do.`);
    await pool.end();
    return;
  }

  await pool.query(
    'UPDATE accounts SET role = $1, verified = TRUE WHERE id = $2',
    [newRole, acc.id]
  );
  console.log(`${email}: ${acc.role} -> ${newRole} (verified)`);
  await pool.end();
}

main().catch(err => { console.error(err); process.exit(1); });
