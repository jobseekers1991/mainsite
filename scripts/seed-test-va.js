#!/usr/bin/env node
// Seed a verified test VA account for demo logins.
//   Local:   DATABASE_URL=... node scripts/seed-test-va.js
//   Railway: railway run node scripts/seed-test-va.js
//
// Overridable via env: TEST_EMAIL, TEST_PASSWORD, TEST_FIRST, TEST_LAST.

const crypto = require('crypto');
const db = require('../db');

const EMAIL    = (process.env.TEST_EMAIL    || 'va-demo@jobseekers.ph').toLowerCase();
const PASSWORD =  process.env.TEST_PASSWORD || 'TestVA2026!';
const FIRST    =  process.env.TEST_FIRST    || 'Demo';
const LAST     =  process.env.TEST_LAST     || 'VA';

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

(async () => {
  const existing = await db.query('SELECT id FROM accounts WHERE email = $1', [EMAIL]);
  if (existing.rows[0]) {
    const { salt, hash } = hashPassword(PASSWORD);
    await db.query(
      `UPDATE accounts SET password_hash = $1, password_salt = $2, verified = TRUE,
         verify_token_hash = NULL, verify_expires = NULL WHERE email = $3`,
      [hash, salt, EMAIL]
    );
    console.log(`Updated existing VA account: ${EMAIL} (password reset, verified)`);
  } else {
    const { salt, hash } = hashPassword(PASSWORD);
    const id = 'u_' + crypto.randomBytes(8).toString('hex');
    await db.query(
      `INSERT INTO accounts (id, role, email, password_hash, password_salt, first_name, last_name,
         verified, mobile, city, skill, years, created_at)
       VALUES ($1, 'va', $2, $3, $4, $5, $6, TRUE, $7, $8, $9, $10, $11)`,
      [id, EMAIL, hash, salt, FIRST, LAST, '+63 917 000 0000', 'Manila', 'Admin Support', '3', Date.now()]
    );
    console.log(`Created VA account: ${EMAIL} (id ${id})`);
  }
  console.log(`  Email:    ${EMAIL}`);
  console.log(`  Password: ${PASSWORD}`);
  await db.pool.end();
})().catch(err => {
  console.error('seed failed:', err);
  process.exit(1);
});
