#!/usr/bin/env node
/*
  Create (or promote) an admin account by email.

  Usage:
    node scripts/seed-admin.js admin@jobseekers.ph
    node scripts/seed-admin.js admin@jobseekers.ph MyPassword123

  If the account already exists, only role/verified are updated and the existing
  password is preserved. If it doesn't exist, a new admin is created with the
  given password (or a strong random one printed to stdout).

  Mirrors server.js hashPassword: scrypt(pw, saltHex, 64) -> hex.
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

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function strongPassword() {
  // 18 chars, URL-safe-ish, from crypto.randomBytes
  return crypto.randomBytes(14).toString('base64')
    .replace(/\+/g, 'A').replace(/\//g, 'z').replace(/=/g, '');
}

async function main() {
  const args = process.argv.slice(2);
  const resetFlag = args.includes('--reset-password');
  const positional = args.filter(a => !a.startsWith('--'));
  const email = (positional[0] || '').trim().toLowerCase();
  let password = (positional[1] || '').trim();
  if (!email) {
    console.error('Usage: node scripts/seed-admin.js <email> [password] [--reset-password]');
    process.exit(2);
  }
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is not set. Add it to .env.');
    process.exit(2);
  }

  const generated = !password;
  if (generated) password = strongPassword();

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
  });

  const existing = await pool.query(
    'SELECT id, role, verified FROM accounts WHERE email = $1',
    [email]
  );

  if (existing.rows.length) {
    const acc = existing.rows[0];
    if (resetFlag) {
      const { salt, hash } = hashPassword(password);
      await pool.query(
        `UPDATE accounts SET role = 'admin', verified = TRUE,
                              password_hash = $1, password_salt = $2
           WHERE id = $3`,
        [hash, salt, acc.id]
      );
      console.log('Reset password for existing admin.');
      console.log('  email:    ' + email);
      console.log('  password: ' + password + (generated ? '   (generated — change after login)' : ''));
    } else {
      await pool.query(
        `UPDATE accounts SET role = 'admin', verified = TRUE WHERE id = $1`,
        [acc.id]
      );
      console.log(`Promoted existing account: ${email} (${acc.role} -> admin, verified)`);
      console.log('Password was NOT changed. Use the existing password to sign in.');
    }
  } else {
    const { salt, hash } = hashPassword(password);
    const id = 'u_' + crypto.randomBytes(8).toString('hex');
    await pool.query(
      `INSERT INTO accounts (id, role, email, password_hash, password_salt,
         first_name, last_name, verified, created_at)
       VALUES ($1,'admin',$2,$3,$4,'Admin','User',TRUE,$5)`,
      [id, email, hash, salt, Date.now()]
    );
    console.log('Created admin account.');
    console.log('  email:    ' + email);
    console.log('  password: ' + password + (generated ? '   (generated — change after login)' : ''));
    console.log('  id:       ' + id);
  }

  await pool.end();
}

main().catch(err => { console.error(err); process.exit(1); });
