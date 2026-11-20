const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { sendVerificationEmail, sendPasswordResetEmail, sendNotificationEmail } = require('./mail');
const db = require('./db');

const PORT = process.env.PORT || 3004;
const ROOT = __dirname;
// Set NOINDEX=1 while the site is on a staging/preview domain. Sends
// X-Robots-Tag on every response and serves a disallow-all robots.txt.
// Remove the env var (or set to 0) once we're on the production domain.
const NOINDEX = process.env.NOINDEX === '1' || process.env.NOINDEX === 'true';
const DATA_DIR = path.join(ROOT, 'data');
const VAS_FILE      = path.join(DATA_DIR, 'vas.json');
const VAS_FULL_FILE = path.join(DATA_DIR, 'vas-full.json');
const SESSION_DAYS = 30;
const VERIFY_TTL_HOURS = 48;
const RESET_TTL_HOURS = 2;

fs.mkdirSync(DATA_DIR, { recursive: true });

// Load the training-center VA directory once at boot. Imported from the SQL
// dump via scripts/import-sql.js — see data/vas.json. ~15 MB / 31k rows, fine
// to keep in memory. If the file is missing we just serve an empty list.
let VAS = [];
try {
  VAS = JSON.parse(fs.readFileSync(VAS_FILE, 'utf8'));
  console.log(`  VA directory: ${VAS.length.toLocaleString()} profiles loaded from data/vas.json`);
} catch (e) {
  console.warn('  VA directory: data/vas.json missing — run `node scripts/import-sql.js`');
}
const VAS_BY_SLUG = new Map(VAS.map(v => [v.slug, v]));

// Deep profiles (work history / education / portfolio / testimonials / socials)
// are kept in a separate file to keep the list endpoint light. Loaded lazily
// the first time /api/vas/:slug is hit so startup stays fast when a dev isn't
// browsing profiles.
let VAS_FULL = null;
function loadFullProfiles() {
  if (VAS_FULL) return VAS_FULL;
  try {
    VAS_FULL = JSON.parse(fs.readFileSync(VAS_FULL_FILE, 'utf8'));
    console.log(`  VA deep profiles: ${Object.keys(VAS_FULL).length.toLocaleString()} loaded from data/vas-full.json`);
  } catch (e) {
    VAS_FULL = {};
    console.warn('  VA deep profiles: data/vas-full.json missing — run `node scripts/import-sql.js`');
  }
  return VAS_FULL;
}

const MIME = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.json': 'application/json',
  '.woff2':'font/woff2',
};

function notFound(res) {
  fs.readFile(path.join(ROOT, '404.html'), (err, data) => {
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end(err ? '<h2>404 — Not Found</h2>' : data);
  });
}

function tryServe(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      notFound(res);
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    // Keep HTML/JS/CSS fresh so edits show up without a hard refresh.
    // Fonts/images can still be cached normally.
    const dynamic = ext === '.html' || ext === '.js' || ext === '.css';
    const headers = { 'Content-Type': mime };
    if (dynamic) headers['Cache-Control'] = 'no-store, must-revalidate';
    res.writeHead(200, headers);
    res.end(data);
  });
}

// ============================================================
// Auth: register / login / verify-email / forgot/reset-password / me / logout
// Backed by Postgres (see db.js + schema.sql). Passwords are scrypt(pw,salt,64).
// Verify and reset tokens are stored as sha256 hashes — the raw token lives
// only inside the email we send out.
// ============================================================

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, expected) {
  const { hash } = hashPassword(password, salt);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function hashToken(raw) {
  return crypto.createHash('sha256').update(String(raw)).digest('hex');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i < 0) return;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', chunk => {
      total += chunk.length;
      if (total > (limit || 32 * 1024)) { req.destroy(); reject(new Error('payload too large')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, body, extraHeaders) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(extraHeaders || {}) });
  res.end(JSON.stringify(body));
  return true;
}

// Trust x-forwarded-proto on Railway so Secure cookies kick in behind the proxy.
function isHttps(req) {
  const xf = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  return xf === 'https' || req.socket.encrypted === true;
}

function sessionCookie(id, req, maxAgeSeconds) {
  const value = id === '' ? '' : encodeURIComponent(id);
  const maxAge = id === '' ? 0 : (maxAgeSeconds || SESSION_DAYS * 86400);
  const secure = isHttps(req) ? '; Secure' : '';
  return `jsph_session=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

// Rough client identifier for rate-limit buckets. Prefers the forwarded IP
// so we don't key everything to Railway's load balancer address.
function clientKey(req) {
  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.socket.remoteAddress || 'unknown';
}

// In-memory sliding window: Map<bucket, number[] of timestamps>. Fine for a
// single-process Node server; swap for Redis if we ever scale horizontally.
const rateBuckets = new Map();
function rateLimit(bucket, max, windowMs) {
  const now = Date.now();
  const arr = rateBuckets.get(bucket) || [];
  const fresh = arr.filter(t => now - t < windowMs);
  if (fresh.length >= max) {
    rateBuckets.set(bucket, fresh);
    return false;
  }
  fresh.push(now);
  rateBuckets.set(bucket, fresh);
  return true;
}

// Occasional cleanup so the map doesn't grow forever on a busy server.
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of rateBuckets) {
    const fresh = arr.filter(t => now - t < 60 * 60 * 1000);
    if (fresh.length === 0) rateBuckets.delete(k);
    else rateBuckets.set(k, fresh);
  }
}, 10 * 60 * 1000).unref();

const ACCOUNT_COLUMNS = `id, role, email, password_hash AS "passwordHash", password_salt AS "passwordSalt",
  first_name AS "firstName", last_name AS "lastName", verified,
  verify_token_hash AS "verifyTokenHash", verify_expires AS "verifyExpires",
  company_name AS "companyName", company_size AS "companySize", source,
  mobile, city, skill, years, title, tagline, profile_data AS "profileData",
  (avatar_data IS NOT NULL) AS "hasAvatar", created_at AS "createdAt"`;

// Same column list, but qualified with the accounts alias — needed whenever
// we JOIN another table that also has an `id` column (e.g. sessions).
const ACCOUNT_COLUMNS_A = `a.id, a.role, a.email, a.password_hash AS "passwordHash", a.password_salt AS "passwordSalt",
  a.first_name AS "firstName", a.last_name AS "lastName", a.verified,
  a.verify_token_hash AS "verifyTokenHash", a.verify_expires AS "verifyExpires",
  a.company_name AS "companyName", a.company_size AS "companySize", a.source,
  a.mobile, a.city, a.skill, a.years, a.title, a.tagline, a.profile_data AS "profileData",
  (a.avatar_data IS NOT NULL) AS "hasAvatar", a.created_at AS "createdAt"`;

async function findAccountByEmail(email) {
  const r = await db.query(`SELECT ${ACCOUNT_COLUMNS} FROM accounts WHERE email = $1`, [email]);
  return r.rows[0] || null;
}
async function findAccountById(id) {
  const r = await db.query(`SELECT ${ACCOUNT_COLUMNS} FROM accounts WHERE id = $1`, [id]);
  return r.rows[0] || null;
}

async function currentUser(req) {
  const sid = parseCookies(req).jsph_session;
  if (!sid) return null;
  const r = await db.query(
    `SELECT ${ACCOUNT_COLUMNS_A}, s.expires AS session_expires
     FROM sessions s JOIN accounts a ON a.id = s.account_id
     WHERE s.id = $1`,
    [sid]
  );
  const row = r.rows[0];
  if (!row || Number(row.session_expires) < Date.now()) return null;
  const { session_expires, ...acc } = row;
  return { ...acc, sessionId: sid };
}

async function issueSession(accountId) {
  // Opportunistically purge expired sessions while we're here.
  await db.query('DELETE FROM sessions WHERE expires < $1', [Date.now()]);
  const sid = 'sess_' + crypto.randomBytes(24).toString('hex');
  await db.query(
    'INSERT INTO sessions (id, account_id, expires) VALUES ($1, $2, $3)',
    [sid, accountId, Date.now() + SESSION_DAYS * 86400 * 1000]
  );
  return sid;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRegister(body) {
  const errors = {};
  const role = body.role === 'client' || body.role === 'va' ? body.role : null;
  if (!role) errors.role = 'Choose whether you want to hire a VA or work as a VA.';
  const firstName = String(body.firstName || '').trim();
  const lastName  = String(body.lastName  || '').trim();
  const email     = String(body.email     || '').trim().toLowerCase();
  const password  = String(body.password  || '');
  if (!firstName) errors.firstName = 'First name is required.';
  if (!lastName)  errors.lastName  = 'Last name is required.';
  if (!EMAIL_RE.test(email)) errors.email = 'Enter a valid email address.';
  if (password.length < 8)   errors.password = 'Use at least 8 characters.';
  if (role === 'client') {
    if (!String(body.companyName || '').trim()) errors.companyName = 'Company name is required.';
    if (!String(body.companySize || '').trim()) errors.companySize = 'Pick a company size.';
  } else if (role === 'va') {
    if (!String(body.mobile || '').trim()) errors.mobile = 'Mobile number is required for GCash payouts.';
    if (!String(body.city   || '').trim()) errors.city   = 'City or province is required.';
    if (!String(body.skill  || '').trim()) errors.skill  = 'Pick your primary skill.';
  }
  return {
    errors, role, firstName, lastName, email, password,
    companyName: String(body.companyName || '').trim(),
    companySize: String(body.companySize || '').trim(),
    source:      String(body.source || '').trim(),
    mobile:      String(body.mobile || '').trim(),
    city:        String(body.city || '').trim(),
    skill:       String(body.skill || '').trim(),
    years:       String(body.years || '').trim(),
  };
}

async function handleAuth(req, res, urlPath) {
  if (urlPath === '/api/register' && req.method === 'POST') {
    if (!rateLimit('register:' + clientKey(req), 5, 60 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many signup attempts. Try again in an hour.' });
    }
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const v = validateRegister(body);
    if (Object.keys(v.errors).length) return sendJson(res, 400, { ok: false, errors: v.errors });

    const existing = await findAccountByEmail(v.email);
    if (existing) return sendJson(res, 409, { ok: false, errors: { email: 'An account with this email already exists.' } });

    const { salt, hash } = hashPassword(v.password);
    const verifyToken = crypto.randomBytes(24).toString('hex');
    const accountId = 'u_' + crypto.randomBytes(8).toString('hex');
    await db.query(
      `INSERT INTO accounts (id, role, email, password_hash, password_salt, first_name, last_name,
         verified, verify_token_hash, verify_expires,
         company_name, company_size, source, mobile, city, skill, years, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [
        accountId, v.role, v.email, hash, salt, v.firstName, v.lastName,
        hashToken(verifyToken), Date.now() + VERIFY_TTL_HOURS * 3600 * 1000,
        v.role === 'client' ? v.companyName : null,
        v.role === 'client' ? v.companySize : null,
        v.role === 'client' ? v.source : null,
        v.role === 'va' ? v.mobile : null,
        v.role === 'va' ? v.city : null,
        v.role === 'va' ? v.skill : null,
        v.role === 'va' ? v.years : null,
        Date.now(),
      ]
    );

    const link = `/verify-email?token=${verifyToken}`;
    sendVerificationEmail({ to: v.email, firstName: v.firstName, role: v.role, verifyPath: link })
      .catch(err => console.error('[register] mail error:', err));

    const sid = await issueSession(accountId);
    sendJson(res, 200, { ok: true, role: v.role, email: v.email, verifyLink: link }, { 'Set-Cookie': sessionCookie(sid, req) });
    return true;
  }

  if (urlPath === '/api/login' && req.method === 'POST') {
    if (!rateLimit('login:' + clientKey(req), 10, 15 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many login attempts. Try again in 15 minutes.' });
    }
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!email || !password) return sendJson(res, 400, { ok: false, error: 'Email and password are required.' });
    const account = await findAccountByEmail(email);
    if (!account || !verifyPassword(password, account.passwordSalt, account.passwordHash)) {
      return sendJson(res, 401, { ok: false, error: 'Email or password is incorrect.' });
    }
    const sid = await issueSession(account.id);
    sendJson(res, 200, { ok: true, role: account.role, verified: !!account.verified }, { 'Set-Cookie': sessionCookie(sid, req) });
    return true;
  }

  if (urlPath === '/api/verify-email' && req.method === 'POST') {
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const token = String(body.token || '').trim();
    if (!token) return sendJson(res, 400, { ok: false, error: 'Missing token.' });
    const tokenHash = hashToken(token);
    const r = await db.query(
      `SELECT ${ACCOUNT_COLUMNS} FROM accounts WHERE verify_token_hash = $1`,
      [tokenHash]
    );
    const account = r.rows[0];
    if (!account) {
      // Fall back: maybe already verified. We can't look it up without the raw
      // token though, so just return the standard invalid message.
      return sendJson(res, 404, { ok: false, error: 'This verification link is invalid or already used.' });
    }
    if (account.verified) return sendJson(res, 200, { ok: true, role: account.role, alreadyVerified: true });
    if (account.verifyExpires && Number(account.verifyExpires) < Date.now()) {
      return sendJson(res, 410, { ok: false, error: 'This verification link has expired. Request a new one.' });
    }
    await db.query(
      'UPDATE accounts SET verified = TRUE, verify_token_hash = NULL, verify_expires = NULL WHERE id = $1',
      [account.id]
    );
    const sid = await issueSession(account.id);
    sendJson(res, 200, { ok: true, role: account.role }, { 'Set-Cookie': sessionCookie(sid, req) });
    return true;
  }

  if (urlPath === '/api/resend-verification' && req.method === 'POST') {
    if (!rateLimit('resend:' + clientKey(req), 5, 60 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many resends. Try again in an hour.' });
    }
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.verified) return sendJson(res, 200, { ok: true, alreadyVerified: true });
    const verifyToken = crypto.randomBytes(24).toString('hex');
    await db.query(
      'UPDATE accounts SET verify_token_hash = $1, verify_expires = $2 WHERE id = $3',
      [hashToken(verifyToken), Date.now() + VERIFY_TTL_HOURS * 3600 * 1000, user.id]
    );
    const link = `/verify-email?token=${verifyToken}`;
    sendVerificationEmail({ to: user.email, firstName: user.firstName, role: user.role, verifyPath: link })
      .catch(err => console.error('[resend] mail error:', err));
    sendJson(res, 200, { ok: true, verifyLink: link });
    return true;
  }

  if (urlPath === '/api/forgot-password' && req.method === 'POST') {
    if (!rateLimit('forgot:' + clientKey(req), 5, 60 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many reset attempts. Try again in an hour.' });
    }
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const email = String(body.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return sendJson(res, 400, { ok: false, error: 'Enter a valid email address.' });

    const account = await findAccountByEmail(email);
    // Always return 200 to avoid leaking which emails are registered.
    if (account) {
      const resetToken = crypto.randomBytes(24).toString('hex');
      await db.query(
        'INSERT INTO password_resets (token_hash, account_id, expires, used) VALUES ($1, $2, $3, FALSE)',
        [hashToken(resetToken), account.id, Date.now() + RESET_TTL_HOURS * 3600 * 1000]
      );
      const link = `/forgot-password?token=${resetToken}`;
      sendPasswordResetEmail({ to: account.email, firstName: account.firstName, resetPath: link })
        .catch(err => console.error('[forgot] mail error:', err));
    }
    sendJson(res, 200, { ok: true });
    return true;
  }

  if (urlPath === '/api/reset-password' && req.method === 'POST') {
    if (!rateLimit('reset:' + clientKey(req), 10, 60 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many reset attempts. Try again in an hour.' });
    }
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const token = String(body.token || '').trim();
    const password = String(body.password || '');
    if (!token) return sendJson(res, 400, { ok: false, error: 'Missing token.' });
    if (password.length < 8) return sendJson(res, 400, { ok: false, errors: { password: 'Use at least 8 characters.' } });

    const r = await db.query(
      'SELECT account_id, expires, used FROM password_resets WHERE token_hash = $1',
      [hashToken(token)]
    );
    const row = r.rows[0];
    if (!row || row.used) return sendJson(res, 404, { ok: false, error: 'This reset link is invalid or already used.' });
    if (Number(row.expires) < Date.now()) return sendJson(res, 410, { ok: false, error: 'This reset link has expired. Request a new one.' });

    const { salt, hash } = hashPassword(password);
    await db.query('UPDATE accounts SET password_hash = $1, password_salt = $2 WHERE id = $3', [hash, salt, row.account_id]);
    await db.query('UPDATE password_resets SET used = TRUE WHERE token_hash = $1', [hashToken(token)]);
    // Invalidate every other session for this account — a password change should
    // log out anyone who might have a stolen cookie.
    await db.query('DELETE FROM sessions WHERE account_id = $1', [row.account_id]);
    const sid = await issueSession(row.account_id);
    const account = await findAccountById(row.account_id);
    sendJson(res, 200, { ok: true, role: account.role }, { 'Set-Cookie': sessionCookie(sid, req) });
    return true;
  }

  if (urlPath === '/api/me' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false });
    const { passwordHash, passwordSalt, verifyTokenHash, verifyExpires, ...safe } = user;
    sendJson(res, 200, { ok: true, user: safe });
    return true;
  }

  if (urlPath === '/api/me' && req.method === 'PATCH') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });

    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }

    // Only these fields are editable from the profile form. Trim and cap each.
    const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
    const fields = {
      first_name:   str(body.firstName, 80),
      last_name:    str(body.lastName, 80),
      title:        str(body.title, 150) || null,
      tagline:      str(body.tagline, 160) || null,
      city:         str(body.city, 80) || null,
      mobile:       str(body.mobile, 40) || null,
      skill:        str(body.skill, 80) || null,
      years:        str(body.years, 10) || null,
    };
    if (!fields.first_name) return sendJson(res, 400, { ok: false, errors: { firstName: 'First name is required.' } });
    if (!fields.last_name)  return sendJson(res, 400, { ok: false, errors: { lastName:  'Last name is required.' } });

    // Extended profile data — stored as a single JSONB blob so we don't need
    // a new table per section. Shape-check and trim each top-level field.
    if (body.profileData !== undefined) {
      const pd = body.profileData || {};
      const bio = str(pd.bio, 4000) || null;
      const skills = Array.isArray(pd.skills)
        ? pd.skills.map(s => String(s || '').trim()).filter(Boolean).slice(0, 20).map(s => s.slice(0, 60))
        : [];
      const socials = pd.socials && typeof pd.socials === 'object'
        ? Object.fromEntries(
            Object.entries(pd.socials)
              .filter(([k, v]) => /^[a-z0-9_]{1,24}$/i.test(k))
              .map(([k, v]) => [k, str(v, 500)])
              .filter(([, v]) => v)
          )
        : {};

      const experience = Array.isArray(pd.experience)
        ? pd.experience.slice(0, 15).map(e => ({
            title:       str(e && e.title, 120),
            company:     str(e && e.company, 120),
            type:        str(e && e.type, 40),
            location:    str(e && e.location, 120),
            startDate:   str(e && e.startDate, 20),
            endDate:     str(e && e.endDate, 20),
            current:     !!(e && e.current),
            description: str(e && e.description, 2000),
          })).filter(e => e.title || e.company)
        : [];

      const education = Array.isArray(pd.education)
        ? pd.education.slice(0, 10).map(e => ({
            school: str(e && e.school, 150),
            degree: str(e && e.degree, 120),
            field:  str(e && e.field, 120),
            year:   str(e && e.year, 10),
          })).filter(e => e.school || e.degree)
        : [];

      const languages = Array.isArray(pd.languages)
        ? pd.languages.slice(0, 15).map(l => ({
            name:  str(l && l.name, 60),
            level: str(l && l.level, 30),
          })).filter(l => l.name)
        : [];

      const tools = Array.isArray(pd.tools)
        ? pd.tools.map(t => String(t || '').trim()).filter(Boolean).slice(0, 60).map(t => t.slice(0, 60))
        : [];

      const prefs = pd.preferences && typeof pd.preferences === 'object' ? pd.preferences : {};
      const preferences = {
        hourlyRate:     str(prefs.hourlyRate, 10),
        hoursPerWeek:   str(prefs.hoursPerWeek, 40),
        availability:   str(prefs.availability, 30),
        workSchedule:   str(prefs.workSchedule, 60),
        timezone:       str(prefs.timezone, 60),
        responseTime:   str(prefs.responseTime, 60),
      };

      fields.profile_data = JSON.stringify({
        bio, skills, socials, experience, education, languages, tools, preferences,
      });
    }

    const sets = Object.keys(fields).map((k, i) => `${k} = $${i + 1}`).join(', ');
    const values = Object.values(fields);
    values.push(user.id);
    await db.query(`UPDATE accounts SET ${sets} WHERE id = $${values.length}`, values);

    const updated = await findAccountById(user.id);
    const { passwordHash, passwordSalt, verifyTokenHash, verifyExpires, ...safe } = updated;
    sendJson(res, 200, { ok: true, user: safe });
    return true;
  }

  if (urlPath === '/api/logout' && req.method === 'POST') {
    const sid = parseCookies(req).jsph_session;
    if (sid) await db.query('DELETE FROM sessions WHERE id = $1', [sid]);
    sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', req, 0) });
    return true;
  }

  return false;
}

// ============================================================
// VA directory: /api/vas (list + filter + paginate), /api/vas/:slug
// Reads from the in-memory VAS array loaded above.
// ============================================================

// Reverse-lookup of a vanity slug (firstnamelastname, lowercased, non-alphanum
// stripped) to a real VA account. Mirrors the client-side slug derivation in
// dashboard-va.html so /<slug> and /api/vas/<slug> resolve the same signed-up
// user. Returns the account row or null.
async function findVaAccountBySlug(slug) {
  const r = await db.query(
    `SELECT id, first_name AS "firstName", last_name AS "lastName", email,
            title, tagline, city, skill, years, verified,
            profile_data AS "profileData",
            (avatar_data IS NOT NULL) AS "hasAvatar",
            created_at AS "createdAt"
       FROM accounts
      WHERE role = 'va'
        AND LOWER(REGEXP_REPLACE(first_name || last_name, '[^a-zA-Z0-9]', '', 'g')) = $1
      LIMIT 1`,
    [String(slug || '').toLowerCase()]
  );
  return r.rows[0] || null;
}

// Build a VA-shaped object (matching the shape loadFullProfiles/VAS returns)
// from a signed-in account, so the /<slug> page renders the same way for both
// demo and real users. Mirrors the client-side loadFromAccount() in va-profile.
async function accountToVaShape(acc) {
  const pd = acc.profileData || {};
  const slug = (acc.firstName + acc.lastName).toLowerCase().replace(/[^a-z0-9]/g, '');
  const name = `${acc.firstName || ''} ${acc.lastName || ''}`.trim();
  const pdSkills = Array.isArray(pd.skills) ? pd.skills : [];

  // Hydrate portfolio + certs + reviews + trust signals so the public profile
  // shows real uploads and real ratings, not placeholders.
  const [portR, certR, reviewR, hireR, settingsR] = await Promise.all([
    db.query(
      `SELECT id, title, category, description, link_url, role, completed_on, skills_used, file_mime,
              (file_data IS NOT NULL) AS has_file, created_at
         FROM va_portfolio WHERE account_id = $1 ORDER BY created_at DESC`,
      [acc.id]
    ),
    db.query(
      `SELECT title FROM va_certificates WHERE account_id = $1 ORDER BY created_at DESC`,
      [acc.id]
    ),
    db.query(
      `SELECT COUNT(*)::int AS n, COALESCE(AVG(rating), 0) AS avg
         FROM reviews WHERE subject_id = $1`,
      [acc.id]
    ),
    db.query(
      `SELECT COUNT(*)::int AS n FROM applications
        WHERE va_id = $1 AND status = 'hired'`,
      [acc.id]
    ),
    db.query('SELECT data FROM user_settings WHERE account_id = $1', [acc.id]),
  ]);
  const reviewCount = reviewR.rows[0].n;
  const reviewAvg = reviewCount ? Math.round(Number(reviewR.rows[0].avg) * 10) / 10 : null;
  const hireCount = hireR.rows[0].n;
  const settings = (settingsR.rows[0] && settingsR.rows[0].data) || {};
  const brownoutStatus = settings.brownout_status || null;
  const brownoutVerified = settings.brownout_verified === true || settings.brownout_verified === 'true';

  return {
    slug,
    name,
    firstName: acc.firstName || '',
    title: acc.title || acc.skill || 'Virtual Assistant',
    tagline: pd.bio || acc.tagline || '',
    city: acc.city || '',
    state: '',
    createdAt: Number(acc.createdAt) || Date.now(),
    skills: pdSkills.length ? pdSkills : (acc.skill ? [acc.skill] : []),
    certs: certR.rows.map(r => r.title),
    portfolio: portR.rows.map(r => ({
      id: r.id,
      title: r.title,
      category: r.category,
      description: r.description,
      linkUrl: r.link_url,
      role: r.role || null,
      completedOn: r.completed_on || null,
      skillsUsed: Array.isArray(r.skills_used) ? r.skills_used : [],
      fileUrl: r.has_file ? `/api/portfolio/${r.id}/file` : null,
      fileMime: r.file_mime || null,
    })),
    services: [],
    experience: Array.isArray(pd.experience) ? pd.experience.map(e => ({
      role: e.title, company: e.company,
      startDate: e.startDate, endDate: e.current ? 'Present' : e.endDate,
      content: e.description,
    })) : [],
    testimonials: [],
    education: Array.isArray(pd.education) ? pd.education.map(e => ({
      degree: [e.degree, e.field].filter(Boolean).join(' · ') || e.degree || '',
      school: e.school, year: e.year,
    })) : [],
    socials: [],
    languages: Array.isArray(pd.languages) ? pd.languages : [],
    tools: Array.isArray(pd.tools) ? pd.tools : [],
    preferences: pd.preferences || {},
    hasAvatar: !!acc.hasAvatar,
    accountId: acc.id,
    // Trust signals used by va-profile.html to render Upwork-style badges.
    verified: !!acc.verified,
    hireCount,
    reviewCount,
    reviewAverage: reviewAvg,
    brownoutStatus,         // 'pending' | 'verified' | null
    brownoutVerified,       // true once Trust & Safety approves the claim
    academyCertified: certR.rows.some(r => (r.title || '').includes('Academy')) || certR.rows.length > 0,
  };
}

async function handleVaDirectory(req, res, urlPath) {
  if (urlPath === '/api/vas' && req.method === 'GET') {
    const url = new URL(req.url, 'http://localhost');
    const q      = (url.searchParams.get('q')     || '').trim().toLowerCase();
    const skill  = (url.searchParams.get('skill') || '').trim().toLowerCase();
    const city   = (url.searchParams.get('city')  || '').trim().toLowerCase();
    const page   = Math.max(1, parseInt(url.searchParams.get('page')  || '1', 10) || 1);
    const limit  = Math.min(60, Math.max(1, parseInt(url.searchParams.get('limit') || '20', 10) || 20));

    let filtered = VAS;
    if (q || skill || city) {
      filtered = VAS.filter(v => {
        if (q) {
          const hay = (v.name + ' ' + v.title + ' ' + (v.skills || []).join(' ')).toLowerCase();
          if (!hay.includes(q)) return false;
        }
        if (skill) {
          if (!(v.skills || []).some(s => s.toLowerCase().includes(skill))) return false;
        }
        if (city) {
          if (!(v.city || '').toLowerCase().includes(city)) return false;
        }
        return true;
      });
    }

    const total = filtered.length;
    const start = (page - 1) * limit;
    const slice = filtered.slice(start, start + limit);
    return sendJson(res, 200, { ok: true, total, page, limit, pages: Math.ceil(total / limit), vas: slice });
  }

  const match = urlPath.match(/^\/api\/vas\/([a-z0-9-]+)$/);
  if (match && req.method === 'GET') {
    const slug = match[1];
    const full = loadFullProfiles()[slug];
    if (full) return sendJson(res, 200, { ok: true, va: full });
    const lean = VAS_BY_SLUG.get(slug);
    if (lean) return sendJson(res, 200, { ok: true, va: lean });
    // Fall back to signed-up VA accounts whose derived slug matches.
    const acc = await findVaAccountBySlug(slug);
    if (acc) return sendJson(res, 200, { ok: true, va: await accountToVaShape(acc) });
    return sendJson(res, 404, { ok: false, error: 'Not found' });
  }

  return false;
}

// ============================================================
// AI Match: POST /api/match { keywords: [], text: '' } → top 5 VAs with reasons.
// Client extracts keywords from the role description using SKILL_SYNONYMS
// (shared vocabulary in js/va-data.js) and sends them here. We score every
// VA against name + title + skills + services and return the top 5.
// ============================================================

function scoreVa(v, keywords, textLower) {
  const hay = (
    (v.title    || '') + ' ' +
    (v.skills   || []).join(' ') + ' ' +
    (v.services || []).join(' ')
  ).toLowerCase();

  const matched = [];
  for (const kw of keywords) {
    if (hay.includes(kw)) matched.push(kw);
  }
  const skillFit    = keywords.length ? matched.length / keywords.length : 0;
  const titleHit    = keywords.some(kw => (v.title || '').toLowerCase().includes(kw)) ? 1 : 0;
  const serviceDepth= Math.min((v.services || []).length, 4) / 4;
  const certBonus   = (v.certs || []).length ? 1 : 0;
  const featured    = v.featured ? 1 : 0;
  const cityHit     = textLower && v.city && textLower.includes(v.city.toLowerCase()) ? 1 : 0;

  const score = Math.round(
    55 * skillFit +
    15 * titleHit +
    10 * serviceDepth +
     8 * certBonus +
     7 * featured +
     5 * cityHit
  );
  return { score, matched };
}

function handleAiMatch(req, res, urlPath) {
  if (urlPath !== '/api/match' || req.method !== 'POST') return false;
  readBody(req, 8 * 1024).then(raw => {
    let body;
    try { body = JSON.parse(raw); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const keywords = (Array.isArray(body.keywords) ? body.keywords : [])
      .map(k => String(k || '').trim().toLowerCase())
      .filter(Boolean)
      .slice(0, 15);
    const textLower = String(body.text || '').toLowerCase().slice(0, 2000);
    if (!keywords.length) return sendJson(res, 400, { ok: false, error: 'No skill keywords detected. Mention tasks or tools in your description.' });

    const scored = [];
    for (const v of VAS) {
      const s = scoreVa(v, keywords, textLower);
      if (s.score >= 25) scored.push({ v, score: s.score, matched: s.matched });
    }
    scored.sort((a, b) => b.score - a.score || (b.v.featured - a.v.featured));
    const top = scored.slice(0, 5).map(m => ({
      va: m.v,
      score: m.score,
      matched: m.matched,
      missing: keywords.filter(k => !m.matched.includes(k)),
    }));
    sendJson(res, 200, { ok: true, matches: top, totalCandidates: scored.length, keywords });
  }).catch(err => {
    console.error('[match]', err);
    sendJson(res, 500, { ok: false, error: 'Server error' });
  });
  return true;
}

// ============================================================
// VA Certificates: /api/certificates (list/create), /:id/image (view),
// /:id (delete), /api/academy/complete (auto-issue from VA Academy quiz)
//
// Images are kept in the DB as BYTEA so they survive redeploys on Railway
// (no persistent filesystem). Uploads come in as base64 JSON — avoids pulling
// in a multipart parser for the hand-rolled http server. 2 MB cap.
// ============================================================

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
const UPLOAD_JSON_LIMIT = Math.round(MAX_UPLOAD_BYTES * 1.5) + 8 * 1024;

// Deliberately narrow: only JPG and PDF. PNG/WEBP/GIF/SVG are rejected, and
// anything HTML-like (<!doctype, <html, <script, <svg) will fail the magic-byte
// check below even if the attacker claims application/pdf.
const ALLOWED_UPLOAD_MIME = new Set(['image/jpeg', 'application/pdf']);

// Keep legacy name alive for the cert handler further down.
const MAX_CERT_IMAGE_BYTES = MAX_UPLOAD_BYTES;
const CERT_UPLOAD_JSON_LIMIT = UPLOAD_JSON_LIMIT;
const ALLOWED_CERT_MIME = ALLOWED_UPLOAD_MIME;

// Sniff the actual file type from its first bytes. Returns the canonical MIME
// we trust, or null if the signature doesn't match something we allow.
// Client-sent Content-Type is spoofable — this is the real gate.
function sniffUploadMime(buf) {
  if (!buf || buf.length < 4) return null;
  // JPEG: FF D8 FF
  if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'image/jpeg';
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47
      && buf[4] === 0x0D && buf[5] === 0x0A && buf[6] === 0x1A && buf[7] === 0x0A) return 'image/png';
  // PDF: "%PDF-"
  if (buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46 && buf[4] === 0x2D) return 'application/pdf';
  return null;
}

// Defence in depth: even once the magic bytes say PDF, scan the first ~2 KB
// for anything that looks like embedded HTML/JS so we don't ship a hybrid
// polyglot file (a valid PDF header followed by <script>). Browsers won't
// render a .pdf as HTML with nosniff, but this keeps the file itself clean
// before it ever reaches storage.
function containsHtmlInjection(buf) {
  const head = buf.slice(0, Math.min(buf.length, 2048)).toString('latin1').toLowerCase();
  return /<\s*(script|iframe|html|!doctype\s+html|svg|object|embed|meta\s+http-equiv)/.test(head);
}

// Serve a stored upload with the strictest headers we can: exact MIME,
// nosniff so the browser can't reinterpret it, and attachment Content-
// Disposition so it downloads rather than executes inline. Also blocks any
// embedding and Flash-era policy escapes.
function writeSecureFileHeaders(res, mime, length, downloadName) {
  const safeName = String(downloadName || 'file').replace(/[^\w.\- ]+/g, '_').slice(0, 80);
  res.writeHead(200, {
    'Content-Type': mime,
    'Content-Length': length,
    'Content-Disposition': `attachment; filename="${safeName}"`,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; sandbox",
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'private, max-age=86400',
  });
}

// Known academy courses and their canonical titles. Keeps the auto-issue
// endpoint from accepting arbitrary course keys and lets us render a nice
// badge label even if the client sends just the key.
const ACADEMY_COURSES = {
  foundations: { title: 'VA Foundations',           issuer: 'Jobseekers.ph Academy' },
  exec:        { title: 'Executive Assistant Pro',  issuer: 'Jobseekers.ph Academy' },
  shopify:     { title: 'Shopify Store Ops',        issuer: 'Jobseekers.ph Academy' },
  qbo:         { title: 'QuickBooks Bookkeeping',   issuer: 'Jobseekers.ph Academy' },
  smm:         { title: 'Social Media Manager',     issuer: 'Jobseekers.ph Academy' },
  support:     { title: 'Customer Support Excellence', issuer: 'Jobseekers.ph Academy' },
};

function certRowToJson(row) {
  return {
    id: row.id,
    source: row.source,
    title: row.title,
    issuer: row.issuer,
    issueDate: row.issue_date,
    credentialUrl: row.credential_url,
    academyCourse: row.academy_course,
    academyScore: row.academy_score,
    hasImage: !!row.has_image,
    imageUrl: row.has_image ? `/api/certificates/${row.id}/image` : null,
    createdAt: Number(row.created_at),
  };
}

async function handleCertificates(req, res, urlPath) {
  // GET /api/certificates — list current user's certificates
  if (urlPath === '/api/certificates' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'Only VA accounts have certificates.' });
    const r = await db.query(
      `SELECT id, source, title, issuer, issue_date, credential_url, academy_course, academy_score,
              (image_data IS NOT NULL) AS has_image, created_at
         FROM va_certificates WHERE account_id = $1 ORDER BY created_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, { ok: true, certificates: r.rows.map(certRowToJson) });
  }

  // POST /api/certificates — upload an external certificate
  if (urlPath === '/api/certificates' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'Only VA accounts can add certificates.' });

    let body;
    try { body = JSON.parse(await readBody(req, CERT_UPLOAD_JSON_LIMIT)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON or file too large (2 MB max).' }); }

    const title = String(body.title || '').trim().slice(0, 150);
    const issuer = String(body.issuer || '').trim().slice(0, 150) || null;
    const issueDate = String(body.issueDate || '').trim().slice(0, 20) || null;
    const credentialUrl = String(body.credentialUrl || '').trim().slice(0, 500) || null;
    if (!title) return sendJson(res, 400, { ok: false, errors: { title: 'Certification name is required.' } });
    if (credentialUrl && !/^https?:\/\//i.test(credentialUrl)) {
      return sendJson(res, 400, { ok: false, errors: { credentialUrl: 'Must be a full https:// URL.' } });
    }

    let imageBuf = null;
    let imageMime = null;
    if (body.imageBase64) {
      const declared = String(body.imageMime || '').toLowerCase();
      if (!ALLOWED_UPLOAD_MIME.has(declared)) {
        return sendJson(res, 400, { ok: false, errors: { image: 'Only JPG or PDF files are allowed.' } });
      }
      try { imageBuf = Buffer.from(String(body.imageBase64), 'base64'); }
      catch (e) { return sendJson(res, 400, { ok: false, errors: { image: 'Could not decode uploaded file.' } }); }
      if (imageBuf.length === 0) {
        return sendJson(res, 400, { ok: false, errors: { image: 'Uploaded file is empty.' } });
      }
      if (imageBuf.length > MAX_UPLOAD_BYTES) {
        return sendJson(res, 400, { ok: false, errors: { image: 'File is larger than 2 MB.' } });
      }
      // Magic-byte sniff — the declared MIME is not trusted on its own. Prevents
      // an attacker from uploading an HTML or script file disguised as a PDF.
      const sniffed = sniffUploadMime(imageBuf);
      if (!sniffed || sniffed !== declared) {
        return sendJson(res, 400, { ok: false, errors: { image: 'File contents are not a valid JPG or PDF.' } });
      }
      if (containsHtmlInjection(imageBuf)) {
        return sendJson(res, 400, { ok: false, errors: { image: 'File rejected: contains disallowed markup.' } });
      }
      imageMime = sniffed;
    }

    const id = 'cert_' + crypto.randomBytes(8).toString('hex');
    await db.query(
      `INSERT INTO va_certificates
         (id, account_id, source, title, issuer, issue_date, credential_url, image_data, image_mime, created_at)
       VALUES ($1,$2,'external',$3,$4,$5,$6,$7,$8,$9)`,
      [id, user.id, title, issuer, issueDate, credentialUrl, imageBuf, imageMime, Date.now()]
    );
    return sendJson(res, 200, {
      ok: true,
      certificate: {
        id, source: 'external', title, issuer, issueDate, credentialUrl,
        academyCourse: null, academyScore: null,
        hasImage: !!imageBuf,
        imageUrl: imageBuf ? `/api/certificates/${id}/image` : null,
        createdAt: Date.now(),
      },
    });
  }

  // GET /api/certificates/:id/image — stream the stored image bytes
  const imgMatch = urlPath.match(/^\/api\/certificates\/([a-z0-9_]+)\/image$/);
  if (imgMatch && req.method === 'GET') {
    const id = imgMatch[1];
    const r = await db.query(
      'SELECT account_id, image_data, image_mime, title FROM va_certificates WHERE id = $1',
      [id]
    );
    const row = r.rows[0];
    if (!row || !row.image_data) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    // Re-sniff at serve time too — trust the stored bytes, not what we think
    // we stored. If the DB is ever mutated out-of-band this stays safe.
    const mime = sniffUploadMime(row.image_data) === row.image_mime
      ? row.image_mime
      : 'application/octet-stream';
    const ext = mime === 'image/jpeg' ? '.jpg' : (mime === 'application/pdf' ? '.pdf' : '');
    writeSecureFileHeaders(res, mime, row.image_data.length, (row.title || 'certificate') + ext);
    res.end(row.image_data);
    return true;
  }

  // DELETE /api/certificates/:id — only external certs, only by the owner
  const delMatch = urlPath.match(/^\/api\/certificates\/([a-z0-9_]+)$/);
  if (delMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const id = delMatch[1];
    const r = await db.query(
      'SELECT account_id, source FROM va_certificates WHERE id = $1',
      [id]
    );
    const row = r.rows[0];
    if (!row || row.account_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    if (row.source === 'academy') {
      return sendJson(res, 403, { ok: false, error: 'Academy certificates cannot be removed manually.' });
    }
    await db.query('DELETE FROM va_certificates WHERE id = $1', [id]);
    return sendJson(res, 200, { ok: true });
  }

  // POST /api/academy/complete — auto-issue a certificate when a logged-in VA
  // passes an Academy quiz. Course key must be a known one. Re-passing the same
  // course is idempotent thanks to the partial unique index on (account_id, academy_course).
  if (urlPath === '/api/academy/complete' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'Only VA accounts can earn Academy certificates.' });

    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }

    const course = String(body.course || '').trim().toLowerCase();
    const score = String(body.score || '').trim().slice(0, 20) || null;
    const meta = ACADEMY_COURSES[course];
    if (!meta) return sendJson(res, 400, { ok: false, error: 'Unknown course key.' });

    const existing = await db.query(
      'SELECT id FROM va_certificates WHERE account_id = $1 AND academy_course = $2 AND source = $3',
      [user.id, course, 'academy']
    );
    if (existing.rows.length) {
      return sendJson(res, 200, { ok: true, alreadyIssued: true, certificateId: existing.rows[0].id });
    }

    const id = 'cert_' + crypto.randomBytes(8).toString('hex');
    const today = new Date().toISOString().slice(0, 10);
    await db.query(
      `INSERT INTO va_certificates
         (id, account_id, source, title, issuer, issue_date, academy_course, academy_score, created_at)
       VALUES ($1,$2,'academy',$3,$4,$5,$6,$7,$8)`,
      [id, user.id, meta.title, meta.issuer, today, course, score, Date.now()]
    );
    return sendJson(res, 200, { ok: true, certificateId: id, title: meta.title });
  }

  return false;
}

// ============================================================
// Profile avatar: POST /api/me/avatar, DELETE /api/me/avatar,
// GET /api/avatar/:accountId. Stored as bytea on accounts so there's
// no new table and no external object store to configure. JPG/PNG only,
// 1 MB cap, magic-byte validated. Served inline (unlike cert downloads)
// so <img src> can render it directly.
// ============================================================

const AVATAR_MAX_BYTES  = 1 * 1024 * 1024;
const AVATAR_JSON_LIMIT = Math.round(AVATAR_MAX_BYTES * 1.5) + 8 * 1024;
const AVATAR_ALLOWED_MIME = new Set(['image/jpeg', 'image/png']);

async function handleAvatar(req, res, urlPath) {
  // POST /api/me/avatar — upload or replace the signed-in user's avatar
  if (urlPath === '/api/me/avatar' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });

    let body;
    try { body = JSON.parse(await readBody(req, AVATAR_JSON_LIMIT)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON or file too large (1 MB max).' }); }

    const declared = String(body.imageMime || '').toLowerCase();
    if (!AVATAR_ALLOWED_MIME.has(declared)) {
      return sendJson(res, 400, { ok: false, error: 'Only JPG or PNG photos are allowed.' });
    }
    if (!body.imageBase64) return sendJson(res, 400, { ok: false, error: 'No image provided.' });

    let buf;
    try { buf = Buffer.from(String(body.imageBase64), 'base64'); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Could not decode uploaded file.' }); }
    if (buf.length === 0)                 return sendJson(res, 400, { ok: false, error: 'Uploaded file is empty.' });
    if (buf.length > AVATAR_MAX_BYTES)    return sendJson(res, 400, { ok: false, error: 'Photo is larger than 1 MB.' });

    const sniffed = sniffUploadMime(buf);
    if (!sniffed || sniffed !== declared || !AVATAR_ALLOWED_MIME.has(sniffed)) {
      return sendJson(res, 400, { ok: false, error: 'File contents are not a valid JPG or PNG.' });
    }
    if (containsHtmlInjection(buf)) {
      return sendJson(res, 400, { ok: false, error: 'File rejected: contains disallowed markup.' });
    }

    await db.query(
      'UPDATE accounts SET avatar_data = $1, avatar_mime = $2 WHERE id = $3',
      [buf, sniffed, user.id]
    );
    return sendJson(res, 200, { ok: true, avatarUrl: `/api/avatar/${user.id}?v=${Date.now()}` });
  }

  // DELETE /api/me/avatar — clear it
  if (urlPath === '/api/me/avatar' && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    await db.query('UPDATE accounts SET avatar_data = NULL, avatar_mime = NULL WHERE id = $1', [user.id]);
    return sendJson(res, 200, { ok: true });
  }

  // GET /api/avatar/:accountId — public; the id itself is unguessable (16 hex),
  // and it only exposes a photo the user chose to upload.
  const getMatch = urlPath.match(/^\/api\/avatar\/([a-z0-9_]+)$/);
  if (getMatch && req.method === 'GET') {
    const id = getMatch[1];
    const r = await db.query('SELECT avatar_data, avatar_mime FROM accounts WHERE id = $1', [id]);
    const row = r.rows[0];
    if (!row || !row.avatar_data) return sendJson(res, 404, { ok: false, error: 'No avatar.' });
    // Trust the stored bytes over the stored mime — re-sniff at serve time.
    const mime = sniffUploadMime(row.avatar_data) === row.avatar_mime
      ? row.avatar_mime : 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': row.avatar_data.length,
      'Content-Disposition': 'inline',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'private, max-age=300',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(row.avatar_data);
    return true;
  }

  return false;
}

// ============================================================
// VA Portfolio / Work Samples: /api/portfolio (list/create),
// /:id/file (view), /:id (delete). Uses the same JPG/PDF-only
// policy as certificates with full magic-byte validation.
// ============================================================

const PORTFOLIO_CATEGORIES = new Set([
  'Admin / Operations', 'Social Media', 'Content Writing',
  'Design', 'Data / Research', 'eCommerce', 'Other',
]);

function portfolioRowToJson(row) {
  return {
    id: row.id,
    title: row.title,
    category: row.category,
    description: row.description,
    linkUrl: row.link_url,
    role: row.role || null,
    completedOn: row.completed_on || null,
    skillsUsed: Array.isArray(row.skills_used) ? row.skills_used : [],
    hasFile: !!row.has_file,
    fileUrl: row.has_file ? `/api/portfolio/${row.id}/file` : null,
    fileMime: row.file_mime || null,
    createdAt: Number(row.created_at),
  };
}

async function handlePortfolio(req, res, urlPath) {
  if (urlPath === '/api/portfolio' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'Only VA accounts have a portfolio.' });
    const r = await db.query(
      `SELECT id, title, category, description, link_url, role, completed_on, skills_used, file_mime,
              (file_data IS NOT NULL) AS has_file, created_at
         FROM va_portfolio WHERE account_id = $1 ORDER BY created_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, { ok: true, samples: r.rows.map(portfolioRowToJson) });
  }

  if (urlPath === '/api/portfolio' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'Only VA accounts can add work samples.' });

    let body;
    try { body = JSON.parse(await readBody(req, UPLOAD_JSON_LIMIT)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON or file too large (2 MB max).' }); }

    const title = String(body.title || '').trim().slice(0, 150);
    const category = String(body.category || '').trim().slice(0, 50);
    const description = String(body.description || '').trim().slice(0, 2000) || null;
    const linkUrl = String(body.linkUrl || '').trim().slice(0, 500) || null;
    const role = String(body.role || '').trim().slice(0, 120) || null;
    const completedOn = String(body.completedOn || '').trim().slice(0, 20) || null;
    const skillsUsed = Array.isArray(body.skillsUsed)
      ? body.skillsUsed.map(s => String(s || '').trim()).filter(Boolean).slice(0, 15).map(s => s.slice(0, 60))
      : [];

    if (!title) return sendJson(res, 400, { ok: false, errors: { title: 'Title is required.' } });
    if (category && !PORTFOLIO_CATEGORIES.has(category)) {
      return sendJson(res, 400, { ok: false, errors: { category: 'Invalid category.' } });
    }
    if (linkUrl && !/^https?:\/\//i.test(linkUrl)) {
      return sendJson(res, 400, { ok: false, errors: { linkUrl: 'Must be a full https:// URL.' } });
    }

    let fileBuf = null;
    let fileMime = null;
    if (body.fileBase64) {
      const declared = String(body.fileMime || '').toLowerCase();
      if (!ALLOWED_UPLOAD_MIME.has(declared)) {
        return sendJson(res, 400, { ok: false, errors: { file: 'Only JPG or PDF files are allowed.' } });
      }
      try { fileBuf = Buffer.from(String(body.fileBase64), 'base64'); }
      catch (e) { return sendJson(res, 400, { ok: false, errors: { file: 'Could not decode uploaded file.' } }); }
      if (fileBuf.length === 0) return sendJson(res, 400, { ok: false, errors: { file: 'Uploaded file is empty.' } });
      if (fileBuf.length > MAX_UPLOAD_BYTES) return sendJson(res, 400, { ok: false, errors: { file: 'File is larger than 2 MB.' } });
      const sniffed = sniffUploadMime(fileBuf);
      if (!sniffed || sniffed !== declared) {
        return sendJson(res, 400, { ok: false, errors: { file: 'File contents are not a valid JPG or PDF.' } });
      }
      if (containsHtmlInjection(fileBuf)) {
        return sendJson(res, 400, { ok: false, errors: { file: 'File rejected: contains disallowed markup.' } });
      }
      fileMime = sniffed;
    }

    const id = 'wk_' + crypto.randomBytes(8).toString('hex');
    await db.query(
      `INSERT INTO va_portfolio
         (id, account_id, title, category, description, link_url, role, completed_on, skills_used,
          file_data, file_mime, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, user.id, title, category || null, description, linkUrl, role, completedOn,
       JSON.stringify(skillsUsed), fileBuf, fileMime, Date.now()]
    );
    return sendJson(res, 200, {
      ok: true,
      sample: {
        id, title, category: category || null, description, linkUrl,
        role, completedOn, skillsUsed,
        hasFile: !!fileBuf,
        fileUrl: fileBuf ? `/api/portfolio/${id}/file` : null,
        fileMime,
        createdAt: Date.now(),
      },
    });
  }

  const fileMatch = urlPath.match(/^\/api\/portfolio\/([a-z0-9_]+)\/file$/);
  if (fileMatch && req.method === 'GET') {
    const id = fileMatch[1];
    const r = await db.query(
      'SELECT file_data, file_mime, title FROM va_portfolio WHERE id = $1',
      [id]
    );
    const row = r.rows[0];
    if (!row || !row.file_data) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    const mime = sniffUploadMime(row.file_data) === row.file_mime
      ? row.file_mime
      : 'application/octet-stream';
    // JPG portfolio images serve inline so <img src> tags on the public VA
    // profile actually render them; PDFs still download as attachments.
    if (mime === 'image/jpeg') {
      res.writeHead(200, {
        'Content-Type': mime,
        'Content-Length': row.file_data.length,
        'Content-Disposition': 'inline',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'public, max-age=86400',
        'Referrer-Policy': 'no-referrer',
      });
      res.end(row.file_data);
      return true;
    }
    const ext = mime === 'application/pdf' ? '.pdf' : '';
    writeSecureFileHeaders(res, mime, row.file_data.length, (row.title || 'sample') + ext);
    res.end(row.file_data);
    return true;
  }

  const delMatch = urlPath.match(/^\/api\/portfolio\/([a-z0-9_]+)$/);
  if (delMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const id = delMatch[1];
    const r = await db.query('SELECT account_id FROM va_portfolio WHERE id = $1', [id]);
    const row = r.rows[0];
    if (!row || row.account_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    await db.query('DELETE FROM va_portfolio WHERE id = $1', [id]);
    return sendJson(res, 200, { ok: true });
  }

  return false;
}

// ============================================================
// Marketplace: jobs, applications, threads/messages
// ============================================================

const JOB_CATEGORIES = new Set([
  'Virtual Assistant / Admin Support', 'Social Media Management', 'Bookkeeping / Accounting',
  'Content Writing / Copywriting', 'Graphic Design', 'Customer Support', 'Web Development',
  'Video Editing', 'Digital Marketing / SEO', 'Data Entry / Research',
  'eCommerce / Shopify / Amazon', 'Other',
]);
const JOB_TYPES = new Set(['fulltime', 'parttime', 'project', 'contract']);
const SHIFTS = new Set(['us-east', 'us-west', 'uk', 'au', 'ph', 'flex']);
const START_MODES = new Set(['trial', 'direct']);

// Server-side scam heuristics — same spirit as post-job.html's client-side scan.
// If a post trips any of these, we save it with status='flagged' and hide it
// from the public listing until Trust & Safety reviews it.
const JOB_SCAM_RULES = [
  { re: /\b(registration|training|processing|application|membership|starter kit|reservation)\s*fee\b|\bpay\s+(a|an|the)?\s*(fee|deposit)\b|\b(laptop|equipment|security|refundable)\s+deposit\b/i,
    msg: 'Asks applicants to pay a fee or deposit' },
  { re: /\b(telegram|whatsapp|signal|viber|wechat)\b/i, msg: 'Moves conversation off-platform' },
  { re: /\b(send|transfer)\b.{0,20}\b(money|gcash|maya|payment)\b|\bgcash me\b/i, msg: 'Asks applicants to send money' },
  { re: /\b(crypto|bitcoin|usdt|forex|investment opportunity)\b/i, msg: 'Mentions crypto or investments' },
  { re: /\b(buy|purchase)\b.{0,25}\b(laptop|equipment|software|kit)\b.{0,25}\b(from us|reimburse)/i, msg: 'Asks applicants to buy equipment from you' },
];

// Off-platform contact regex for messages & cover letters.
const OFF_PLATFORM_REGEX = /\b(telegram|whatsapp|viber|signal|wechat|gcash me|pay (you )?outside|outside (the )?(platform|jobseekers)|paypal me|send (me )?(your )?(otp|password|bank))\b/i;

const JOB_COLUMNS = `
  j.id, j.client_id AS "clientId", j.title, j.category, j.job_type AS "jobType",
  j.shift, j.description, j.pay_min AS "payMin", j.pay_max AS "payMax",
  j.experience_level AS "experienceLevel", j.english_level AS "englishLevel",
  j.skills, j.screening_questions AS "screeningQuestions",
  j.application_deadline AS "applicationDeadline",
  j.start_mode AS "startMode", j.trial_days AS "trialDays", j.trial_hours AS "trialHours",
  j.trial_scope AS "trialScope", j.company_name AS "companyName", j.status,
  j.created_at AS "createdAt", j.updated_at AS "updatedAt"`;

function normalizeJobRow(row) {
  // Coerce Postgres numeric → Number so the frontend doesn't have to parse strings.
  return {
    ...row,
    payMin: row.payMin == null ? null : Number(row.payMin),
    payMax: row.payMax == null ? null : Number(row.payMax),
    createdAt: Number(row.createdAt),
    updatedAt: Number(row.updatedAt),
  };
}

async function handleJobs(req, res, urlPath) {
  // POST /api/jobs — client creates a new job
  if (urlPath === '/api/jobs' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Only clients can post jobs.' });
    if (!user.verified) return sendJson(res, 403, { ok: false, error: 'Verify your email before posting a job.' });
    if (!rateLimit('post-job:' + user.id, 10, 60 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many jobs posted in the last hour.' });
    }

    let body;
    try { body = JSON.parse(await readBody(req, 64 * 1024)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }

    const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
    const title       = str(body.title, 150);
    const category    = str(body.category, 80);
    const jobType     = str(body.jobType, 20);
    const shift       = str(body.shift, 20);
    const description = str(body.description, 8000);
    const payMin      = body.payMin !== undefined && body.payMin !== '' ? Number(body.payMin) : null;
    const payMax      = body.payMax !== undefined && body.payMax !== '' ? Number(body.payMax) : null;
    const experienceLevel     = str(body.experienceLevel, 50) || null;
    const englishLevel        = str(body.englishLevel, 30) || null;
    const applicationDeadline = str(body.applicationDeadline, 20) || null;
    const startMode   = str(body.startMode, 20) || null;
    const trialDays   = body.trialDays ? Math.max(1, Math.min(14, Number(body.trialDays) | 0)) : null;
    const trialHours  = body.trialHours ? Math.max(1, Math.min(12, Number(body.trialHours) | 0)) : null;
    const trialScope  = str(body.trialScope, 2000) || null;
    const companyName = str(body.companyName, 150) || user.companyName || null;

    const skills = Array.isArray(body.skills)
      ? body.skills.map(s => String(s || '').trim()).filter(Boolean).slice(0, 20).map(s => s.slice(0, 60))
      : [];
    const screeningQuestions = Array.isArray(body.screeningQuestions)
      ? body.screeningQuestions.map(q => String(q || '').trim()).filter(Boolean).slice(0, 10).map(q => q.slice(0, 400))
      : [];

    const errors = {};
    if (!title) errors.title = 'Job title is required.';
    if (category && !JOB_CATEGORIES.has(category)) errors.category = 'Pick a valid category.';
    if (!JOB_TYPES.has(jobType)) errors.jobType = 'Pick a job type.';
    if (!SHIFTS.has(shift)) errors.shift = 'Pick working hours.';
    if (description.length < 60) errors.description = 'Describe the role in a bit more detail (60+ characters).';
    if (payMin == null || !isFinite(payMin) || payMin < 0 || payMin > 500) errors.payMin = 'Enter an hourly rate (0–500).';
    if (payMax != null && (!isFinite(payMax) || payMax < payMin || payMax > 500)) errors.payMax = 'Max rate must be ≥ min and ≤ 500.';
    if (startMode && !START_MODES.has(startMode)) errors.startMode = 'Invalid start mode.';
    if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });

    const scam = JOB_SCAM_RULES.filter(r => r.re.test(description)).map(r => r.msg);
    const status = scam.length ? 'flagged' : 'open';
    const id = 'job_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();

    await db.query(
      `INSERT INTO jobs (id, client_id, title, category, job_type, shift, description,
         pay_min, pay_max, experience_level, english_level, skills, screening_questions,
         application_deadline, start_mode, trial_days, trial_hours, trial_scope,
         company_name, status, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$21)`,
      [id, user.id, title, category || null, jobType, shift, description,
       payMin, payMax, experienceLevel, englishLevel,
       JSON.stringify(skills), JSON.stringify(screeningQuestions),
       applicationDeadline, startMode, trialDays, trialHours, trialScope,
       companyName, status, now]
    );
    return sendJson(res, 200, { ok: true, id, status, flagged: scam.length > 0, flagReasons: scam });
  }

  // GET /api/jobs/mine — current client's own jobs (checked before /api/jobs/:id)
  if (urlPath === '/api/jobs/mine' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    const r = await db.query(
      `SELECT ${JOB_COLUMNS},
              (SELECT COUNT(*)::int FROM applications a WHERE a.job_id = j.id AND a.status <> 'withdrawn') AS applicant_count,
              (SELECT COUNT(*)::int FROM applications a WHERE a.job_id = j.id AND a.status = 'submitted') AS new_count
         FROM jobs j
        WHERE j.client_id = $1
        ORDER BY j.created_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, {
      ok: true,
      jobs: r.rows.map(row => ({
        ...normalizeJobRow(row),
        applicantCount: row.applicant_count,
        newCount: row.new_count,
        applicant_count: undefined, new_count: undefined,
      })),
    });
  }

  // GET /api/jobs — public list with filters
  if (urlPath === '/api/jobs' && req.method === 'GET') {
    const url = new URL(req.url, 'http://localhost');
    const q      = (url.searchParams.get('q')        || '').trim().toLowerCase();
    const shift  = (url.searchParams.get('shift')    || '').trim();
    const type   = (url.searchParams.get('type')     || '').trim();
    const cat    = (url.searchParams.get('category') || '').trim();
    const page   = Math.max(1, parseInt(url.searchParams.get('page')  || '1', 10) || 1);
    const limit  = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') || '20', 10) || 20));

    const where = [`j.status = 'open'`];
    const params = [];
    if (q) {
      params.push('%' + q + '%');
      where.push(`(LOWER(j.title) LIKE $${params.length} OR LOWER(j.description) LIKE $${params.length} OR LOWER(COALESCE(j.company_name,'')) LIKE $${params.length})`);
    }
    if (shift && SHIFTS.has(shift))        { params.push(shift); where.push(`j.shift = $${params.length}`); }
    if (type  && JOB_TYPES.has(type))      { params.push(type);  where.push(`j.job_type = $${params.length}`); }
    if (cat   && JOB_CATEGORIES.has(cat))  { params.push(cat);   where.push(`j.category = $${params.length}`); }

    const whereSql = where.join(' AND ');
    const countR = await db.query(`SELECT COUNT(*)::int AS n FROM jobs j WHERE ${whereSql}`, params);
    const total = countR.rows[0].n;

    params.push(limit);
    params.push((page - 1) * limit);
    const listR = await db.query(
      `SELECT ${JOB_COLUMNS},
              (SELECT COUNT(*)::int FROM applications a WHERE a.job_id = j.id AND a.status <> 'withdrawn') AS applicant_count,
              a.verified AS "clientVerified"
         FROM jobs j JOIN accounts a ON a.id = j.client_id
        WHERE ${whereSql}
        ORDER BY j.created_at DESC
        LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    return sendJson(res, 200, {
      ok: true, total, page, limit, pages: Math.max(1, Math.ceil(total / limit)),
      jobs: listR.rows.map(row => ({
        ...normalizeJobRow(row),
        applicantCount: row.applicant_count,
        applicant_count: undefined,
      })),
    });
  }

  // GET /api/jobs/:id — single job
  const getMatch = urlPath.match(/^\/api\/jobs\/([a-z0-9_]+)$/);
  if (getMatch && req.method === 'GET') {
    const id = getMatch[1];
    const r = await db.query(
      `SELECT ${JOB_COLUMNS},
              (SELECT COUNT(*)::int FROM applications a WHERE a.job_id = j.id AND a.status <> 'withdrawn') AS applicant_count,
              a.verified AS "clientVerified", a.first_name AS "clientFirstName",
              a.company_size AS "clientCompanySize", a.created_at AS "clientCreatedAt",
              (SELECT COUNT(*)::int FROM applications a
                 JOIN jobs j2 ON j2.id = a.job_id
                WHERE j2.client_id = j.client_id AND a.status = 'hired')  AS "clientHireCount",
              (SELECT COUNT(*)::int FROM jobs j3
                WHERE j3.client_id = j.client_id AND j3.status = 'open') AS "clientOpenJobs",
              (SELECT COUNT(*)::int FROM jobs j4
                WHERE j4.client_id = j.client_id)                        AS "clientTotalJobs"
         FROM jobs j JOIN accounts a ON a.id = j.client_id
        WHERE j.id = $1`,
      [id]
    );
    const job = r.rows[0];
    if (!job) return sendJson(res, 404, { ok: false, error: 'Not found' });

    // Non-open jobs are only visible to their owner.
    if (job.status !== 'open') {
      const user = await currentUser(req);
      if (!user || user.id !== job.clientId) return sendJson(res, 404, { ok: false, error: 'Not found' });
    }

    const out = normalizeJobRow({ ...job, applicantCount: job.applicant_count });
    delete out.applicant_count;
    out.clientCreatedAt = Number(out.clientCreatedAt);
    return sendJson(res, 200, { ok: true, job: out });
  }

  // PATCH /api/jobs/:id — owner only. Accepts either:
  //  { status: 'open' | 'closed' }  — quick open/close
  //  { ...any job fields... }       — full edit; re-runs validation + scam check
  if (getMatch && req.method === 'PATCH') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const id = getMatch[1];
    const r = await db.query('SELECT client_id, status FROM jobs WHERE id = $1', [id]);
    const row = r.rows[0];
    if (!row || row.client_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found' });
    if (row.status === 'removed') {
      return sendJson(res, 403, { ok: false, error: 'This job has been removed and cannot be edited.' });
    }

    let body;
    try { body = JSON.parse(await readBody(req, 64 * 1024)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }

    // Status-only quick toggle (keeps existing clients working).
    const keys = Object.keys(body);
    if (keys.length === 1 && keys[0] === 'status') {
      const status = String(body.status || '').trim();
      if (!['open', 'closed'].includes(status)) return sendJson(res, 400, { ok: false, error: 'Invalid status' });
      if (row.status === 'flagged') {
        return sendJson(res, 403, { ok: false, error: 'This job is held by Trust & Safety and cannot be reopened.' });
      }
      await db.query('UPDATE jobs SET status = $1, updated_at = $2 WHERE id = $3', [status, Date.now(), id]);
      return sendJson(res, 200, { ok: true, status });
    }

    // Full edit path — reuse the same validation as POST.
    const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
    const title       = str(body.title, 150);
    const category    = str(body.category, 80);
    const jobType     = str(body.jobType, 20);
    const shift       = str(body.shift, 20);
    const description = str(body.description, 8000);
    const payMin      = body.payMin !== undefined && body.payMin !== '' ? Number(body.payMin) : null;
    const payMax      = body.payMax !== undefined && body.payMax !== '' ? Number(body.payMax) : null;
    const experienceLevel     = str(body.experienceLevel, 50) || null;
    const englishLevel        = str(body.englishLevel, 30) || null;
    const applicationDeadline = str(body.applicationDeadline, 20) || null;
    const startMode   = str(body.startMode, 20) || null;
    const trialDays   = body.trialDays ? Math.max(1, Math.min(14, Number(body.trialDays) | 0)) : null;
    const trialHours  = body.trialHours ? Math.max(1, Math.min(12, Number(body.trialHours) | 0)) : null;
    const trialScope  = str(body.trialScope, 2000) || null;
    const companyName = str(body.companyName, 150) || user.companyName || null;

    const skills = Array.isArray(body.skills)
      ? body.skills.map(s => String(s || '').trim()).filter(Boolean).slice(0, 20).map(s => s.slice(0, 60))
      : [];
    const screeningQuestions = Array.isArray(body.screeningQuestions)
      ? body.screeningQuestions.map(q => String(q || '').trim()).filter(Boolean).slice(0, 10).map(q => q.slice(0, 400))
      : [];

    const errors = {};
    if (!title) errors.title = 'Job title is required.';
    if (category && !JOB_CATEGORIES.has(category)) errors.category = 'Pick a valid category.';
    if (!JOB_TYPES.has(jobType)) errors.jobType = 'Pick a job type.';
    if (!SHIFTS.has(shift)) errors.shift = 'Pick working hours.';
    if (description.length < 60) errors.description = 'Describe the role in a bit more detail (60+ characters).';
    if (payMin == null || !isFinite(payMin) || payMin < 0 || payMin > 500) errors.payMin = 'Enter an hourly rate (0–500).';
    if (payMax != null && (!isFinite(payMax) || payMax < payMin || payMax > 500)) errors.payMax = 'Max rate must be ≥ min and ≤ 500.';
    if (startMode && !START_MODES.has(startMode)) errors.startMode = 'Invalid start mode.';
    if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });

    const scam = JOB_SCAM_RULES.filter(r => r.re.test(description)).map(r => r.msg);
    // A clean edit lifts a prior auto-flag; a dirty edit re-flags.
    const newStatus = scam.length ? 'flagged' : (row.status === 'flagged' ? 'open' : row.status);

    await db.query(
      `UPDATE jobs SET
         title = $1, category = $2, job_type = $3, shift = $4, description = $5,
         pay_min = $6, pay_max = $7, experience_level = $8, english_level = $9,
         skills = $10, screening_questions = $11, application_deadline = $12,
         start_mode = $13, trial_days = $14, trial_hours = $15, trial_scope = $16,
         company_name = $17, status = $18, updated_at = $19
       WHERE id = $20`,
      [title, category || null, jobType, shift, description,
       payMin, payMax, experienceLevel, englishLevel,
       JSON.stringify(skills), JSON.stringify(screeningQuestions),
       applicationDeadline, startMode, trialDays, trialHours, trialScope,
       companyName, newStatus, Date.now(), id]
    );
    return sendJson(res, 200, { ok: true, id, status: newStatus, flagged: scam.length > 0, flagReasons: scam });
  }

  return false;
}

// ============================================================
// Applications: VA applies / lists own; client lists per job / updates status.
// ============================================================

const APPLICATION_STATUSES = new Set(['submitted', 'viewed', 'interview', 'trial', 'trialing', 'hired', 'rejected', 'withdrawn']);

function applicationRowToJson(row) {
  return {
    id: row.id,
    jobId: row.job_id,
    vaId: row.va_id,
    cover: row.cover,
    rate: row.rate == null ? null : Number(row.rate),
    canStart: row.can_start,
    answers: Array.isArray(row.answers) ? row.answers : [],
    shiftOk: !!row.shift_ok,
    openToTrial: !!row.open_to_trial,
    attachProfile: !!row.attach_profile,
    status: row.status,
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
    // Optional joined fields — present on client-facing responses only.
    vaFirstName: row.va_first_name ?? undefined,
    vaLastName:  row.va_last_name  ?? undefined,
    vaCity:      row.va_city       ?? undefined,
    vaSkill:     row.va_skill      ?? undefined,
    vaTitle:     row.va_title      ?? undefined,
    vaYears:     row.va_years      ?? undefined,
    jobTitle:    row.job_title     ?? undefined,
    jobCompany:  row.job_company   ?? undefined,
    jobStatus:   row.job_status    ?? undefined,
  };
}

async function handleApplications(req, res, urlPath) {
  // POST /api/applications — VA applies to a job
  if (urlPath === '/api/applications' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'Only VAs can apply to jobs.' });
    if (!user.verified) return sendJson(res, 403, { ok: false, error: 'Verify your email before applying.' });
    if (!rateLimit('apply:' + user.id, 30, 60 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many applications in the last hour.' });
    }

    let body;
    try { body = JSON.parse(await readBody(req, 32 * 1024)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }

    const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
    const jobId = str(body.jobId, 60);
    const cover = str(body.cover, 4000);
    const rate  = Number(body.rate);
    const canStart = str(body.canStart, 40) || null;
    const answers = Array.isArray(body.answers)
      ? body.answers.map(a => String(a || '').trim().slice(0, 2000)).slice(0, 10)
      : [];
    const shiftOk = !!body.shiftOk;
    const openToTrial = !!body.openToTrial;
    const attachProfile = body.attachProfile !== false;

    const errors = {};
    if (!jobId) errors.jobId = 'Missing jobId.';
    if (cover.length < 100) errors.cover = 'Cover letter must be at least 100 characters.';
    if (!isFinite(rate) || rate < 3 || rate > 500) errors.rate = 'Enter a rate between $3 and $500.';
    if (OFF_PLATFORM_REGEX.test(cover)) errors.cover = 'Please remove outside contact details (Telegram, WhatsApp, etc.). Keep chats on Jobseekers.ph.';
    if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });

    const jr = await db.query('SELECT id, client_id, status FROM jobs WHERE id = $1', [jobId]);
    const job = jr.rows[0];
    if (!job) return sendJson(res, 404, { ok: false, error: 'Job not found.' });
    if (job.status !== 'open') return sendJson(res, 409, { ok: false, error: 'This job is no longer open.' });
    if (job.client_id === user.id) return sendJson(res, 403, { ok: false, error: 'You cannot apply to your own job.' });

    const id = 'app_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    try {
      await db.query(
        `INSERT INTO applications (id, job_id, va_id, cover, rate, can_start, answers,
            shift_ok, open_to_trial, attach_profile, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'submitted',$11,$11)`,
        [id, jobId, user.id, cover, rate, canStart, JSON.stringify(answers),
         shiftOk, openToTrial, attachProfile, now]
      );
    } catch (err) {
      if (err && err.code === '23505') return sendJson(res, 409, { ok: false, error: 'You already applied to this job.' });
      throw err;
    }
    // Notify the job owner that a new application arrived.
    const jobR = await db.query('SELECT title FROM jobs WHERE id = $1', [jobId]);
    const jobTitle = jobR.rows[0] ? jobR.rows[0].title : 'your job';
    await createNotification(job.client_id, 'application',
      'New applicant',
      `${user.firstName || 'A VA'} applied to "${jobTitle}".`,
      `/applicants?jobId=${jobId}`);
    return sendJson(res, 200, { ok: true, id });
  }

  // GET /api/applications — list; VA sees own, client sees ?jobId=X
  if (urlPath === '/api/applications' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const url = new URL(req.url, 'http://localhost');
    const jobId = (url.searchParams.get('jobId') || '').trim();

    if (user.role === 'va') {
      const r = await db.query(
        `SELECT a.*, j.title AS job_title, j.company_name AS job_company, j.status AS job_status
           FROM applications a JOIN jobs j ON j.id = a.job_id
          WHERE a.va_id = $1
          ORDER BY a.created_at DESC`,
        [user.id]
      );
      return sendJson(res, 200, { ok: true, applications: r.rows.map(applicationRowToJson) });
    }

    // Client flow: must supply jobId and own the job.
    if (!jobId) return sendJson(res, 400, { ok: false, error: 'Missing jobId.' });
    const jr = await db.query('SELECT client_id FROM jobs WHERE id = $1', [jobId]);
    const job = jr.rows[0];
    if (!job || job.client_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });

    const r = await db.query(
      `SELECT a.*, acc.first_name AS va_first_name, acc.last_name AS va_last_name,
              acc.city AS va_city, acc.skill AS va_skill, acc.title AS va_title, acc.years AS va_years
         FROM applications a JOIN accounts acc ON acc.id = a.va_id
        WHERE a.job_id = $1
        ORDER BY a.created_at DESC`,
      [jobId]
    );
    return sendJson(res, 200, { ok: true, applications: r.rows.map(applicationRowToJson) });
  }

  // PATCH /api/applications/:id — client updates status; VA can only withdraw.
  const match = urlPath.match(/^\/api\/applications\/([a-z0-9_]+)$/);
  if (match && req.method === 'PATCH') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const id = match[1];

    const r = await db.query(
      `SELECT a.*, j.client_id FROM applications a JOIN jobs j ON j.id = a.job_id WHERE a.id = $1`,
      [id]
    );
    const row = r.rows[0];
    if (!row) return sendJson(res, 404, { ok: false, error: 'Not found.' });

    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const status = String(body.status || '').trim();
    if (!APPLICATION_STATUSES.has(status)) return sendJson(res, 400, { ok: false, error: 'Invalid status.' });

    if (user.id === row.va_id) {
      if (status !== 'withdrawn') return sendJson(res, 403, { ok: false, error: 'VAs can only withdraw.' });
    } else if (user.id === row.client_id) {
      if (status === 'withdrawn') return sendJson(res, 403, { ok: false, error: 'Only the VA can withdraw.' });
    } else {
      return sendJson(res, 404, { ok: false, error: 'Not found.' });
    }

    await db.query('UPDATE applications SET status = $1, updated_at = $2 WHERE id = $3', [status, Date.now(), id]);
    // Notify the other party on meaningful status changes.
    if (user.id !== row.va_id && ['interview', 'trial', 'hired', 'rejected'].includes(status)) {
      const jr = await db.query('SELECT title FROM jobs WHERE id = $1', [row.job_id]);
      const jt = jr.rows[0] ? jr.rows[0].title : 'a role';
      const label = status === 'hired' ? 'You were hired' :
                    status === 'rejected' ? 'Application update' :
                    status === 'trial' ? 'Trial offer' : 'Interview invitation';
      const body = status === 'hired' ? `Congratulations — the client hired you for "${jt}".` :
                   status === 'rejected' ? `The client has closed your application for "${jt}".` :
                   status === 'trial' ? `The client invited you to a trial for "${jt}".` :
                   `The client wants to interview you for "${jt}".`;
      await createNotification(row.va_id, 'application', label, body, '/my-applications');
    }
    return sendJson(res, 200, { ok: true, status });
  }

  return false;
}

// ============================================================
// Threads & messages: open a thread with another user, read/write messages.
// Threads are deduped per (client, va, job). job_id may be null for a general
// thread. Off-platform content is flagged per-message, not blocked.
// ============================================================

function threadRowToJson(row, viewerId) {
  return {
    id: row.id,
    clientId: row.client_id,
    vaId: row.va_id,
    jobId: row.job_id,
    lastMessageAt: Number(row.last_message_at),
    createdAt: Number(row.created_at),
    otherFirstName: row.other_first_name,
    otherLastName:  row.other_last_name,
    otherRole:      row.other_role,
    otherCompany:   row.other_company_name,
    jobTitle:       row.job_title,
    unreadCount:    Number(row.unread_count || 0),
    lastMessage:    row.last_body ? {
      body: row.last_body,
      senderId: row.last_sender_id,
      mine: row.last_sender_id === viewerId,
      createdAt: Number(row.last_created_at),
      offPlatform: !!row.last_off_platform,
    } : null,
  };
}

async function handleThreads(req, res, urlPath) {
  // GET /api/threads — list threads for current user
  if (urlPath === '/api/threads' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });

    const r = await db.query(
      `SELECT t.id, t.client_id, t.va_id, t.job_id, t.last_message_at, t.created_at,
              other.first_name  AS other_first_name,
              other.last_name   AS other_last_name,
              other.role        AS other_role,
              other.company_name AS other_company_name,
              j.title           AS job_title,
              (SELECT COUNT(*)::int FROM messages m
                 WHERE m.thread_id = t.id AND m.sender_id <> $1 AND m.read_at IS NULL) AS unread_count,
              lm.body           AS last_body,
              lm.sender_id      AS last_sender_id,
              lm.created_at     AS last_created_at,
              lm.off_platform_flag AS last_off_platform
         FROM threads t
         JOIN accounts other ON other.id = (CASE WHEN t.client_id = $1 THEN t.va_id ELSE t.client_id END)
         LEFT JOIN jobs j ON j.id = t.job_id
         LEFT JOIN LATERAL (
           SELECT body, sender_id, created_at, off_platform_flag
             FROM messages m WHERE m.thread_id = t.id
             ORDER BY m.created_at DESC LIMIT 1
         ) lm ON TRUE
        WHERE t.client_id = $1 OR t.va_id = $1
        ORDER BY t.last_message_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, { ok: true, threads: r.rows.map(row => threadRowToJson(row, user.id)) });
  }

  // POST /api/threads — open (or reuse) a thread with another user
  if (urlPath === '/api/threads' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const otherId = String(body.otherId || '').trim();
    const jobId   = body.jobId ? String(body.jobId).trim() : null;
    if (!otherId) return sendJson(res, 400, { ok: false, error: 'Missing otherId.' });
    if (otherId === user.id) return sendJson(res, 400, { ok: false, error: 'You cannot message yourself.' });

    const otherR = await db.query('SELECT id, role FROM accounts WHERE id = $1', [otherId]);
    const other = otherR.rows[0];
    if (!other) return sendJson(res, 404, { ok: false, error: 'User not found.' });
    if (other.role === user.role) return sendJson(res, 400, { ok: false, error: 'Clients can only message VAs and vice-versa.' });

    const clientId = user.role === 'client' ? user.id : other.id;
    const vaId     = user.role === 'va'     ? user.id : other.id;

    // If jobId provided, validate it belongs to the client in this pair.
    if (jobId) {
      const jr = await db.query('SELECT id FROM jobs WHERE id = $1 AND client_id = $2', [jobId, clientId]);
      if (!jr.rows[0]) return sendJson(res, 400, { ok: false, error: 'Invalid jobId for this pair.' });
    }

    // Find-or-create. Separate unique indexes for job NULL and NOT NULL.
    let existing;
    if (jobId) {
      existing = await db.query('SELECT id FROM threads WHERE client_id = $1 AND va_id = $2 AND job_id = $3', [clientId, vaId, jobId]);
    } else {
      existing = await db.query('SELECT id FROM threads WHERE client_id = $1 AND va_id = $2 AND job_id IS NULL', [clientId, vaId]);
    }
    if (existing.rows[0]) return sendJson(res, 200, { ok: true, id: existing.rows[0].id, created: false });

    const id = 'th_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await db.query(
      'INSERT INTO threads (id, client_id, va_id, job_id, last_message_at, created_at) VALUES ($1,$2,$3,$4,$5,$5)',
      [id, clientId, vaId, jobId, now]
    );
    return sendJson(res, 200, { ok: true, id, created: true });
  }

  // GET /api/threads/:id/messages?after=TIMESTAMP — list messages in a thread
  const msgListMatch = urlPath.match(/^\/api\/threads\/([a-z0-9_]+)\/messages$/);
  if (msgListMatch && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const threadId = msgListMatch[1];

    const tr = await db.query('SELECT client_id, va_id, job_id FROM threads WHERE id = $1', [threadId]);
    const t = tr.rows[0];
    if (!t || (t.client_id !== user.id && t.va_id !== user.id)) {
      return sendJson(res, 404, { ok: false, error: 'Not found.' });
    }

    const url = new URL(req.url, 'http://localhost');
    const after = Number(url.searchParams.get('after') || 0);
    const mr = await db.query(
      `SELECT id, sender_id, body, off_platform_flag, read_at, created_at
         FROM messages WHERE thread_id = $1 AND created_at > $2
         ORDER BY created_at ASC LIMIT 500`,
      [threadId, after]
    );

    // Mark the other party's messages as read.
    await db.query(
      'UPDATE messages SET read_at = $1 WHERE thread_id = $2 AND sender_id <> $3 AND read_at IS NULL',
      [Date.now(), threadId, user.id]
    );

    return sendJson(res, 200, {
      ok: true,
      thread: { id: threadId, clientId: t.client_id, vaId: t.va_id, jobId: t.job_id },
      messages: mr.rows.map(m => ({
        id: m.id,
        senderId: m.sender_id,
        mine: m.sender_id === user.id,
        body: m.body,
        offPlatform: !!m.off_platform_flag,
        readAt: m.read_at == null ? null : Number(m.read_at),
        createdAt: Number(m.created_at),
      })),
    });
  }

  // POST /api/threads/:id/messages — send a message
  if (msgListMatch && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const threadId = msgListMatch[1];

    const tr = await db.query('SELECT client_id, va_id FROM threads WHERE id = $1', [threadId]);
    const t = tr.rows[0];
    if (!t || (t.client_id !== user.id && t.va_id !== user.id)) {
      return sendJson(res, 404, { ok: false, error: 'Not found.' });
    }

    if (!rateLimit('msg:' + user.id, 60, 5 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many messages. Slow down a bit.' });
    }

    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const text = String(body.body || '').trim().slice(0, 4000);
    if (!text) return sendJson(res, 400, { ok: false, error: 'Message is empty.' });

    const offPlatform = OFF_PLATFORM_REGEX.test(text);
    const id = 'msg_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await db.query(
      'INSERT INTO messages (id, thread_id, sender_id, body, off_platform_flag, created_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, threadId, user.id, text, offPlatform, now]
    );
    await db.query('UPDATE threads SET last_message_at = $1 WHERE id = $2', [now, threadId]);
    // Notify the other party once per minute at most; we don't want to spam
    // a bell for every single message in a fast back-and-forth.
    const otherId = t.client_id === user.id ? t.va_id : t.client_id;
    const recent = await db.query(
      `SELECT 1 FROM notifications
        WHERE account_id = $1 AND kind = 'message' AND created_at > $2 LIMIT 1`,
      [otherId, now - 60 * 1000]
    );
    if (!recent.rows[0]) {
      await createNotification(otherId, 'message',
        `New message from ${user.firstName || 'someone'}`,
        text.slice(0, 160),
        '/messages');
    }
    return sendJson(res, 200, {
      ok: true,
      message: { id, senderId: user.id, mine: true, body: text, offPlatform, readAt: null, createdAt: now },
    });
  }

  return false;
}

// ============================================================
// Settings: per-user preferences blob (settings.html).
// ============================================================

async function handleSettings(req, res, urlPath) {
  if (urlPath === '/api/settings' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query('SELECT data FROM user_settings WHERE account_id = $1', [user.id]);
    const data = r.rows[0] ? r.rows[0].data : {};
    return sendJson(res, 200, { ok: true, settings: data });
  }

  if (urlPath === '/api/settings' && req.method === 'PUT') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    let body;
    try { body = JSON.parse(await readBody(req, 16 * 1024)); }
    catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return sendJson(res, 400, { ok: false, error: 'Settings must be an object.' });
    }
    // Cap payload shape: only string, number, or boolean values at top level.
    const safe = {};
    for (const [k, v] of Object.entries(body)) {
      if (!/^[a-z0-9_]{1,40}$/i.test(k)) continue;
      if (typeof v === 'string')      safe[k] = v.slice(0, 500);
      else if (typeof v === 'number') safe[k] = Number.isFinite(v) ? v : 0;
      else if (typeof v === 'boolean')safe[k] = v;
    }
    await db.query(
      `INSERT INTO user_settings (account_id, data, updated_at)
       VALUES ($1, $2::jsonb, $3)
       ON CONFLICT (account_id) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at`,
      [user.id, JSON.stringify(safe), Date.now()]
    );
    return sendJson(res, 200, { ok: true, settings: safe });
  }
  return false;
}

// ============================================================
// Notifications
// ============================================================

async function createNotification(accountId, kind, title, body, link) {
  const id = 'ntf_' + crypto.randomBytes(8).toString('hex');
  await db.query(
    `INSERT INTO notifications (id, account_id, kind, title, body, link, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [id, accountId, kind, String(title).slice(0, 200),
     body == null ? null : String(body).slice(0, 1000),
     link == null ? null : String(link).slice(0, 500),
     Date.now()]
  );

  // Fire-and-forget email. Honours per-user settings:
  // user_settings.data.email_notifications === false silences all transactional
  // mail (verify/reset still go through — those use their own senders). Per-kind
  // pref_* keys (pref_applicants, pref_messages, etc.) opt out of specific kinds.
  (async () => {
    try {
      const r = await db.query(
        `SELECT a.email, a.first_name AS "firstName", a.verified, s.data AS settings
           FROM accounts a LEFT JOIN user_settings s ON s.account_id = a.id
          WHERE a.id = $1`,
        [accountId]
      );
      const row = r.rows[0];
      if (!row || !row.email || !row.verified) return;
      const s = row.settings || {};
      if (s.email_notifications === false) return;
      // Map notification kinds to pref keys so Settings toggles apply.
      const prefMap = {
        application: 'pref_applicants',
        message:     'pref_messages',
        interview:   'pref_interviews',
        timesheet:   'pref_timesheets',
        invoice:     'pref_invoices',
        trial:       'pref_trials',
        review:      'pref_reviews',
        team:        'pref_team',
      };
      const prefKey = prefMap[kind];
      if (prefKey && s[prefKey] === false) return;
      await sendNotificationEmail({
        to: row.email, firstName: row.firstName,
        heading: title, intro: body || title,
        ctaLabel: 'Open Jobseekers.ph', ctaPath: link || '/',
      });
    } catch (e) {
      console.error('[notify/email]', e && e.message ? e.message : e);
    }
  })();

  return id;
}

async function handleNotifications(req, res, urlPath) {
  if (urlPath === '/api/notifications' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query(
      `SELECT id, kind, title, body, link, read_at, created_at
         FROM notifications WHERE account_id = $1
         ORDER BY created_at DESC LIMIT 100`,
      [user.id]
    );
    const unread = r.rows.filter(n => !n.read_at).length;
    return sendJson(res, 200, {
      ok: true,
      unread,
      notifications: r.rows.map(n => ({
        id: n.id, kind: n.kind, title: n.title, body: n.body, link: n.link,
        readAt: n.read_at == null ? null : Number(n.read_at),
        createdAt: Number(n.created_at),
      })),
    });
  }

  if (urlPath === '/api/notifications/read-all' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    await db.query('UPDATE notifications SET read_at = $1 WHERE account_id = $2 AND read_at IS NULL', [Date.now(), user.id]);
    return sendJson(res, 200, { ok: true });
  }

  const readMatch = urlPath.match(/^\/api\/notifications\/([a-z0-9_]+)\/read$/);
  if (readMatch && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    await db.query('UPDATE notifications SET read_at = $1 WHERE id = $2 AND account_id = $3',
      [Date.now(), readMatch[1], user.id]);
    return sendJson(res, 200, { ok: true });
  }

  const delMatch = urlPath.match(/^\/api\/notifications\/([a-z0-9_]+)$/);
  if (delMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    await db.query('DELETE FROM notifications WHERE id = $1 AND account_id = $2', [delMatch[1], user.id]);
    return sendJson(res, 200, { ok: true });
  }

  return false;
}

// ============================================================
// Favorites (talent pool). Client-only.
// ============================================================

async function handleFavorites(req, res, urlPath) {
  if (urlPath === '/api/favorites' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    const r = await db.query(
      `SELECT f.id, f.saved_va_id, f.saved_va_slug, f.note, f.created_at,
              a.first_name, a.last_name, a.city, a.skill, a.title,
              (a.avatar_data IS NOT NULL) AS has_avatar
         FROM favorites f LEFT JOIN accounts a ON a.id = f.saved_va_id
        WHERE f.client_id = $1
        ORDER BY f.created_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, {
      ok: true,
      favorites: r.rows.map(row => ({
        id: row.id,
        savedVaId: row.saved_va_id,
        savedVaSlug: row.saved_va_slug,
        note: row.note,
        createdAt: Number(row.created_at),
        va: row.saved_va_id ? {
          id: row.saved_va_id,
          firstName: row.first_name, lastName: row.last_name,
          city: row.city, skill: row.skill, title: row.title,
          hasAvatar: !!row.has_avatar,
        } : null,
      })),
    });
  }

  if (urlPath === '/api/favorites' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const vaId   = body.savedVaId   ? String(body.savedVaId).trim()   : null;
    const vaSlug = body.savedVaSlug ? String(body.savedVaSlug).trim().toLowerCase().slice(0, 100) : null;
    const note   = body.note ? String(body.note).trim().slice(0, 500) : null;
    if (!vaId && !vaSlug) return sendJson(res, 400, { ok: false, error: 'Provide savedVaId or savedVaSlug.' });
    const id = 'fav_' + crypto.randomBytes(8).toString('hex');
    try {
      await db.query(
        `INSERT INTO favorites (id, client_id, saved_va_id, saved_va_slug, note, created_at)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [id, user.id, vaId, vaSlug, note, Date.now()]
      );
    } catch (err) {
      if (err && err.code === '23505') return sendJson(res, 409, { ok: false, error: 'Already in your talent pool.' });
      throw err;
    }
    return sendJson(res, 200, { ok: true, id });
  }

  const delMatch = urlPath.match(/^\/api\/favorites\/([a-z0-9_]+)$/);
  if (delMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    await db.query('DELETE FROM favorites WHERE id = $1 AND client_id = $2', [delMatch[1], user.id]);
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

// ============================================================
// Job templates. Client-only.
// ============================================================

async function handleTemplates(req, res, urlPath) {
  if (urlPath === '/api/templates' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    const r = await db.query(
      `SELECT id, name, data, created_at, updated_at FROM job_templates
        WHERE client_id = $1 ORDER BY updated_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, {
      ok: true,
      templates: r.rows.map(row => ({
        id: row.id, name: row.name, data: row.data || {},
        createdAt: Number(row.created_at), updatedAt: Number(row.updated_at),
      })),
    });
  }

  const idMatch = urlPath.match(/^\/api\/templates\/([a-z0-9_]+)$/);
  if (idMatch && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query('SELECT id, client_id, name, data, created_at, updated_at FROM job_templates WHERE id = $1', [idMatch[1]]);
    const row = r.rows[0];
    if (!row || row.client_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    return sendJson(res, 200, {
      ok: true,
      template: {
        id: row.id, name: row.name, data: row.data || {},
        createdAt: Number(row.created_at), updatedAt: Number(row.updated_at),
      },
    });
  }

  if (urlPath === '/api/templates' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    let body;
    try { body = JSON.parse(await readBody(req, 64 * 1024)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const name = String(body.name || '').trim().slice(0, 150);
    if (!name) return sendJson(res, 400, { ok: false, errors: { name: 'Name is required.' } });
    const data = body.data && typeof body.data === 'object' ? body.data : {};
    const id = 'tpl_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await db.query(
      `INSERT INTO job_templates (id, client_id, name, data, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$5)`,
      [id, user.id, name, JSON.stringify(data), now]
    );
    return sendJson(res, 200, { ok: true, id });
  }

  if (idMatch && req.method === 'PUT') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query('SELECT client_id FROM job_templates WHERE id = $1', [idMatch[1]]);
    const row = r.rows[0];
    if (!row || row.client_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    let body;
    try { body = JSON.parse(await readBody(req, 64 * 1024)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const name = String(body.name || '').trim().slice(0, 150);
    if (!name) return sendJson(res, 400, { ok: false, errors: { name: 'Name is required.' } });
    const data = body.data && typeof body.data === 'object' ? body.data : {};
    await db.query(
      'UPDATE job_templates SET name = $1, data = $2, updated_at = $3 WHERE id = $4',
      [name, JSON.stringify(data), Date.now(), idMatch[1]]
    );
    return sendJson(res, 200, { ok: true });
  }

  if (idMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    await db.query('DELETE FROM job_templates WHERE id = $1 AND client_id = $2', [idMatch[1], user.id]);
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

// ============================================================
// Interviews. Client creates; VA can view and update own status.
// ============================================================

const INTERVIEW_PLATFORMS = new Set(['zoom', 'meet', 'phone', 'inplatform']);
const INTERVIEW_STATUSES  = new Set(['upcoming', 'completed', 'cancelled', 'no-show']);

function interviewRowToJson(row) {
  return {
    id: row.id,
    clientId: row.client_id,
    vaId: row.va_id,
    jobId: row.job_id,
    applicationId: row.application_id,
    scheduledFor: Number(row.scheduled_for),
    durationMin: row.duration_min,
    platform: row.platform,
    meetingUrl: row.meeting_url,
    notes: row.notes,
    status: row.status,
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
    vaFirstName:     row.va_first_name     ?? undefined,
    vaLastName:      row.va_last_name      ?? undefined,
    clientFirstName: row.client_first_name ?? undefined,
    clientCompany:   row.client_company    ?? undefined,
    jobTitle:        row.job_title         ?? undefined,
  };
}

async function handleInterviews(req, res, urlPath) {
  if (urlPath === '/api/interviews' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query(
      `SELECT i.*, va.first_name AS va_first_name, va.last_name AS va_last_name,
              cli.first_name AS client_first_name, cli.company_name AS client_company,
              j.title AS job_title
         FROM interviews i
         JOIN accounts va  ON va.id  = i.va_id
         JOIN accounts cli ON cli.id = i.client_id
         LEFT JOIN jobs j  ON j.id = i.job_id
        WHERE i.client_id = $1 OR i.va_id = $1
        ORDER BY i.scheduled_for ASC`,
      [user.id]
    );
    return sendJson(res, 200, { ok: true, interviews: r.rows.map(interviewRowToJson) });
  }

  if (urlPath === '/api/interviews' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Only clients can schedule interviews.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const vaId = String(body.vaId || '').trim();
    const jobId = body.jobId ? String(body.jobId).trim() : null;
    const applicationId = body.applicationId ? String(body.applicationId).trim() : null;
    const scheduledFor = Number(body.scheduledFor);
    const durationMin = Math.max(15, Math.min(240, Number(body.durationMin) || 30));
    const platform = String(body.platform || 'zoom').trim().toLowerCase();
    const meetingUrl = body.meetingUrl ? String(body.meetingUrl).trim().slice(0, 500) : null;
    const notes = body.notes ? String(body.notes).trim().slice(0, 2000) : null;

    const errors = {};
    if (!vaId) errors.vaId = 'Pick a VA.';
    if (!isFinite(scheduledFor) || scheduledFor < Date.now() - 60 * 1000) errors.scheduledFor = 'Pick a future date/time.';
    if (!INTERVIEW_PLATFORMS.has(platform)) errors.platform = 'Invalid platform.';
    if (meetingUrl && !/^https?:\/\//i.test(meetingUrl)) errors.meetingUrl = 'Must be a full https:// URL.';
    if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });

    const vaR = await db.query('SELECT id, role FROM accounts WHERE id = $1', [vaId]);
    if (!vaR.rows[0] || vaR.rows[0].role !== 'va') return sendJson(res, 400, { ok: false, error: 'VA not found.' });

    if (jobId) {
      const jr = await db.query('SELECT id FROM jobs WHERE id = $1 AND client_id = $2', [jobId, user.id]);
      if (!jr.rows[0]) return sendJson(res, 400, { ok: false, error: 'Job not yours or not found.' });
    }

    const id = 'itv_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await db.query(
      `INSERT INTO interviews (id, client_id, va_id, job_id, application_id, scheduled_for,
          duration_min, platform, meeting_url, notes, status, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'upcoming',$11,$11)`,
      [id, user.id, vaId, jobId, applicationId, scheduledFor, durationMin, platform, meetingUrl, notes, now]
    );

    // Also bump the application status to 'interview' when one is attached.
    if (applicationId) {
      await db.query(
        `UPDATE applications SET status = 'interview', updated_at = $1
          WHERE id = $2 AND status IN ('submitted','viewed')`,
        [now, applicationId]
      );
    }

    await createNotification(vaId, 'interview',
      'Interview scheduled',
      `${user.firstName || 'A client'} scheduled an interview with you.`,
      '/calendar');

    return sendJson(res, 200, { ok: true, id });
  }

  const idMatch = urlPath.match(/^\/api\/interviews\/([a-z0-9_]+)$/);
  if (idMatch && req.method === 'PATCH') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query('SELECT * FROM interviews WHERE id = $1', [idMatch[1]]);
    const row = r.rows[0];
    if (!row || (row.client_id !== user.id && row.va_id !== user.id)) {
      return sendJson(res, 404, { ok: false, error: 'Not found.' });
    }
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const status = String(body.status || '').trim();
    if (!INTERVIEW_STATUSES.has(status)) return sendJson(res, 400, { ok: false, error: 'Invalid status.' });
    await db.query('UPDATE interviews SET status = $1, updated_at = $2 WHERE id = $3', [status, Date.now(), idMatch[1]]);
    return sendJson(res, 200, { ok: true });
  }

  if (idMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query('SELECT client_id FROM interviews WHERE id = $1', [idMatch[1]]);
    if (!r.rows[0] || r.rows[0].client_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    await db.query('DELETE FROM interviews WHERE id = $1', [idMatch[1]]);
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

// ============================================================
// Timesheets. VA creates; client approves/rejects.
// ============================================================

function timesheetRowToJson(row) {
  return {
    id: row.id,
    clientId: row.client_id,
    vaId: row.va_id,
    jobId: row.job_id,
    weekStart: row.week_start,
    minutes: row.minutes,
    hours: Math.round((row.minutes / 60) * 100) / 100,
    rate: row.rate == null ? null : Number(row.rate),
    summary: row.summary,
    status: row.status,
    decidedAt: row.decided_at == null ? null : Number(row.decided_at),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
    vaFirstName:     row.va_first_name     ?? undefined,
    vaLastName:      row.va_last_name      ?? undefined,
    clientFirstName: row.client_first_name ?? undefined,
    clientCompany:   row.client_company    ?? undefined,
    jobTitle:        row.job_title         ?? undefined,
  };
}

async function handleTimesheets(req, res, urlPath) {
  if (urlPath === '/api/timesheets' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query(
      `SELECT t.*, va.first_name AS va_first_name, va.last_name AS va_last_name,
              cli.first_name AS client_first_name, cli.company_name AS client_company,
              j.title AS job_title
         FROM timesheets t
         JOIN accounts va  ON va.id  = t.va_id
         JOIN accounts cli ON cli.id = t.client_id
         LEFT JOIN jobs j  ON j.id = t.job_id
        WHERE t.client_id = $1 OR t.va_id = $1
        ORDER BY t.week_start DESC, t.created_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, { ok: true, timesheets: r.rows.map(timesheetRowToJson) });
  }

  if (urlPath === '/api/timesheets' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'VAs submit timesheets.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const clientId = String(body.clientId || '').trim();
    const jobId = body.jobId ? String(body.jobId).trim() : null;
    const weekStart = String(body.weekStart || '').trim().slice(0, 10);
    const minutes = Math.max(1, Math.min(60 * 24 * 7, Number(body.minutes) | 0));
    const rate = Number(body.rate);
    const summary = body.summary ? String(body.summary).trim().slice(0, 2000) : null;
    const errors = {};
    if (!clientId) errors.clientId = 'Pick a client.';
    if (!/^\d{4}-\d{2}-\d{2}$/.test(weekStart)) errors.weekStart = 'Use YYYY-MM-DD.';
    if (!isFinite(rate) || rate < 1 || rate > 500) errors.rate = 'Rate must be 1–500.';
    if (!Number.isFinite(minutes) || minutes <= 0) errors.minutes = 'Enter minutes worked.';
    if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });

    const cr = await db.query('SELECT id, role FROM accounts WHERE id = $1', [clientId]);
    if (!cr.rows[0] || cr.rows[0].role !== 'client') return sendJson(res, 400, { ok: false, error: 'Client not found.' });

    const id = 'ts_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await db.query(
      `INSERT INTO timesheets (id, client_id, va_id, job_id, week_start, minutes, rate, summary,
          status, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$9)`,
      [id, clientId, user.id, jobId, weekStart, minutes, rate, summary, now]
    );
    await createNotification(clientId, 'timesheet',
      'New timesheet to approve',
      `${user.firstName || 'A VA'} submitted a timesheet for week of ${weekStart}.`,
      '/timesheets');
    return sendJson(res, 200, { ok: true, id });
  }

  const idMatch = urlPath.match(/^\/api\/timesheets\/([a-z0-9_]+)$/);
  if (idMatch && req.method === 'PATCH') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query('SELECT * FROM timesheets WHERE id = $1', [idMatch[1]]);
    const row = r.rows[0];
    if (!row || row.client_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const status = String(body.status || '').trim();
    if (!['approved', 'rejected'].includes(status)) return sendJson(res, 400, { ok: false, error: 'Invalid status.' });
    const now = Date.now();
    await db.query(
      'UPDATE timesheets SET status = $1, decided_at = $2, updated_at = $2 WHERE id = $3',
      [status, now, idMatch[1]]
    );
    await createNotification(row.va_id, 'timesheet',
      status === 'approved' ? 'Timesheet approved' : 'Timesheet needs changes',
      status === 'approved'
        ? `Your timesheet for week of ${row.week_start} was approved.`
        : `Your timesheet for week of ${row.week_start} was rejected.`,
      '/timesheets');
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

// ============================================================
// Invoices. VA creates; client marks paid.
// ============================================================

const INVOICE_STATUSES = new Set(['draft', 'sent', 'paid', 'void']);

function invoiceRowToJson(row) {
  return {
    id: row.id,
    clientId: row.client_id,
    vaId: row.va_id,
    jobId: row.job_id,
    invoiceNo: row.invoice_no,
    issuedOn: row.issued_on,
    dueOn: row.due_on,
    currency: row.currency,
    subtotal: Number(row.subtotal),
    total: Number(row.total),
    items: Array.isArray(row.items) ? row.items : [],
    notes: row.notes,
    status: row.status,
    paidAt: row.paid_at == null ? null : Number(row.paid_at),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
    vaFirstName:     row.va_first_name     ?? undefined,
    vaLastName:      row.va_last_name      ?? undefined,
    clientFirstName: row.client_first_name ?? undefined,
    clientCompany:   row.client_company    ?? undefined,
  };
}

async function handleInvoices(req, res, urlPath) {
  if (urlPath === '/api/invoices' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query(
      `SELECT i.*, va.first_name AS va_first_name, va.last_name AS va_last_name,
              cli.first_name AS client_first_name, cli.company_name AS client_company
         FROM invoices i
         JOIN accounts va  ON va.id  = i.va_id
         JOIN accounts cli ON cli.id = i.client_id
        WHERE i.client_id = $1 OR i.va_id = $1
        ORDER BY i.created_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, { ok: true, invoices: r.rows.map(invoiceRowToJson) });
  }

  if (urlPath === '/api/invoices' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'VAs create invoices.' });
    let body;
    try { body = JSON.parse(await readBody(req, 64 * 1024)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const clientId  = String(body.clientId || '').trim();
    const jobId     = body.jobId ? String(body.jobId).trim() : null;
    const invoiceNo = String(body.invoiceNo || '').trim().slice(0, 40) || ('INV-' + Date.now().toString(36).toUpperCase());
    const issuedOn  = String(body.issuedOn  || new Date().toISOString().slice(0, 10)).slice(0, 10);
    const dueOn     = body.dueOn ? String(body.dueOn).trim().slice(0, 10) : null;
    const currency  = String(body.currency || 'USD').trim().slice(0, 3).toUpperCase();
    const notes     = body.notes ? String(body.notes).trim().slice(0, 2000) : null;

    const items = Array.isArray(body.items)
      ? body.items.slice(0, 50).map(it => ({
          description: String(it && it.description || '').trim().slice(0, 300),
          qty:  Number((it && it.qty) || 1),
          rate: Number((it && it.rate) || 0),
          amount: Number((it && it.amount) || 0),
        })).filter(it => it.description)
      : [];
    const subtotal = items.reduce((s, it) => s + (isFinite(it.amount) ? it.amount : 0), 0);
    const total = Number(body.total) || subtotal;
    const errors = {};
    if (!clientId) errors.clientId = 'Pick a client.';
    if (!/^\d{4}-\d{2}-\d{2}$/.test(issuedOn)) errors.issuedOn = 'Use YYYY-MM-DD.';
    if (!items.length) errors.items = 'Add at least one line item.';
    if (!isFinite(total) || total <= 0) errors.total = 'Total must be positive.';
    if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });

    const cr = await db.query('SELECT id, role FROM accounts WHERE id = $1', [clientId]);
    if (!cr.rows[0] || cr.rows[0].role !== 'client') return sendJson(res, 400, { ok: false, error: 'Client not found.' });

    const id = 'inv_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await db.query(
      `INSERT INTO invoices (id, client_id, va_id, job_id, invoice_no, issued_on, due_on,
          currency, subtotal, total, items, notes, status, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'sent',$13,$13)`,
      [id, clientId, user.id, jobId, invoiceNo, issuedOn, dueOn,
       currency, subtotal, total, JSON.stringify(items), notes, now]
    );
    await createNotification(clientId, 'invoice',
      'New invoice received',
      `${user.firstName || 'A VA'} sent invoice ${invoiceNo} for ${currency} ${total.toFixed(2)}.`,
      '/invoices');
    return sendJson(res, 200, { ok: true, id, invoiceNo });
  }

  const idMatch = urlPath.match(/^\/api\/invoices\/([a-z0-9_]+)$/);
  if (idMatch && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query(
      `SELECT i.*, va.first_name AS va_first_name, va.last_name AS va_last_name,
              cli.first_name AS client_first_name, cli.company_name AS client_company
         FROM invoices i
         JOIN accounts va  ON va.id  = i.va_id
         JOIN accounts cli ON cli.id = i.client_id
        WHERE i.id = $1`,
      [idMatch[1]]
    );
    const row = r.rows[0];
    if (!row || (row.client_id !== user.id && row.va_id !== user.id)) {
      return sendJson(res, 404, { ok: false, error: 'Not found.' });
    }
    return sendJson(res, 200, { ok: true, invoice: invoiceRowToJson(row) });
  }

  if (idMatch && req.method === 'PATCH') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query('SELECT * FROM invoices WHERE id = $1', [idMatch[1]]);
    const row = r.rows[0];
    if (!row || (row.client_id !== user.id && row.va_id !== user.id)) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const status = String(body.status || '').trim();
    if (!INVOICE_STATUSES.has(status)) return sendJson(res, 400, { ok: false, error: 'Invalid status.' });
    // Client can mark paid/void; VA can mark void or draft→sent.
    if (user.id === row.client_id && !['paid', 'void'].includes(status)) {
      return sendJson(res, 403, { ok: false, error: 'Clients can only mark paid or void.' });
    }
    if (user.id === row.va_id && status === 'paid') {
      return sendJson(res, 403, { ok: false, error: 'Only the client can mark an invoice paid.' });
    }
    const now = Date.now();
    await db.query(
      'UPDATE invoices SET status = $1, paid_at = $2, updated_at = $3 WHERE id = $4',
      [status, status === 'paid' ? now : row.paid_at, now, idMatch[1]]
    );
    if (status === 'paid') {
      await createNotification(row.va_id, 'invoice',
        'Invoice paid',
        `Invoice ${row.invoice_no} was marked paid.`,
        '/invoices');
    }
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

// ============================================================
// Reviews. Mutual rating between a client and VA.
// ============================================================

async function handleReviews(req, res, urlPath) {
  if (urlPath === '/api/reviews' && req.method === 'GET') {
    const url = new URL(req.url, 'http://localhost');
    const subjectId = (url.searchParams.get('subjectId') || '').trim();
    if (!subjectId) return sendJson(res, 400, { ok: false, error: 'Missing subjectId.' });
    const r = await db.query(
      `SELECT r.id, r.reviewer_id, r.rating, r.body, r.created_at,
              a.first_name AS reviewer_first_name, a.last_name AS reviewer_last_name,
              a.role AS reviewer_role, a.company_name AS reviewer_company
         FROM reviews r JOIN accounts a ON a.id = r.reviewer_id
        WHERE r.subject_id = $1 ORDER BY r.created_at DESC LIMIT 50`,
      [subjectId]
    );
    const avg = r.rows.length
      ? Math.round((r.rows.reduce((s, x) => s + x.rating, 0) / r.rows.length) * 10) / 10
      : null;
    return sendJson(res, 200, {
      ok: true,
      count: r.rows.length,
      average: avg,
      reviews: r.rows.map(row => ({
        id: row.id,
        reviewerId: row.reviewer_id,
        reviewerFirstName: row.reviewer_first_name,
        reviewerLastName: row.reviewer_last_name,
        reviewerRole: row.reviewer_role,
        reviewerCompany: row.reviewer_company,
        rating: row.rating,
        body: row.body,
        createdAt: Number(row.created_at),
      })),
    });
  }

  if (urlPath === '/api/reviews' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const subjectId = String(body.subjectId || '').trim();
    const jobId = body.jobId ? String(body.jobId).trim() : null;
    const rating = Math.max(1, Math.min(5, Number(body.rating) | 0));
    const text = body.body ? String(body.body).trim().slice(0, 2000) : null;
    if (!subjectId || subjectId === user.id) return sendJson(res, 400, { ok: false, error: 'Invalid subject.' });
    if (!rating) return sendJson(res, 400, { ok: false, error: 'Rating must be 1–5.' });
    // Must have at least one shared hire/thread/completed trial to review.
    const gate = await db.query(
      `SELECT 1 FROM applications a JOIN jobs j ON j.id = a.job_id
        WHERE a.status IN ('hired','trialing','trial')
          AND ((j.client_id = $1 AND a.va_id = $2) OR (j.client_id = $2 AND a.va_id = $1))
        LIMIT 1`,
      [user.id, subjectId]
    );
    if (!gate.rows[0]) {
      return sendJson(res, 403, { ok: false, error: 'You can only review someone you have worked with.' });
    }
    const id = 'rv_' + crypto.randomBytes(8).toString('hex');
    try {
      await db.query(
        `INSERT INTO reviews (id, reviewer_id, subject_id, job_id, rating, body, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [id, user.id, subjectId, jobId, rating, text, Date.now()]
      );
    } catch (err) {
      if (err && err.code === '23505') return sendJson(res, 409, { ok: false, error: 'You already reviewed this person for this job.' });
      throw err;
    }
    await createNotification(subjectId, 'review',
      'You received a review',
      `${user.firstName || 'Someone'} left you a ${rating}-star review.`, null);
    return sendJson(res, 200, { ok: true, id });
  }
  return false;
}

// ============================================================
// Teams. Client owner invites others by email. If the email already belongs
// to a client account, the row is 'active'; otherwise 'invited' (they'll be
// promoted when they sign up).
// ============================================================

async function getOrCreateTeamForOwner(ownerId, ownerFirstName) {
  const r = await db.query('SELECT id, name FROM teams WHERE owner_id = $1 LIMIT 1', [ownerId]);
  if (r.rows[0]) return r.rows[0];
  const id = 'tm_' + crypto.randomBytes(8).toString('hex');
  const name = (ownerFirstName || 'My') + "'s Team";
  await db.query('INSERT INTO teams (id, owner_id, name, created_at) VALUES ($1,$2,$3,$4)',
    [id, ownerId, name, Date.now()]);
  // Seed owner as a team_member so the list includes them.
  const mid = 'tmm_' + crypto.randomBytes(8).toString('hex');
  await db.query(
    `INSERT INTO team_members (id, team_id, account_id, invite_email, role, status, created_at)
     VALUES ($1,$2,$3,NULL,'owner','active',$4)`,
    [mid, id, ownerId, Date.now()]
  );
  return { id, name };
}

async function handleTeam(req, res, urlPath) {
  if (urlPath === '/api/team' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    const team = await getOrCreateTeamForOwner(user.id, user.firstName);
    const r = await db.query(
      `SELECT m.id, m.account_id, m.invite_email, m.role, m.status, m.created_at,
              a.first_name, a.last_name, a.email, a.company_name,
              (a.avatar_data IS NOT NULL) AS has_avatar
         FROM team_members m LEFT JOIN accounts a ON a.id = m.account_id
        WHERE m.team_id = $1
        ORDER BY m.created_at ASC`,
      [team.id]
    );
    return sendJson(res, 200, {
      ok: true,
      team: { id: team.id, name: team.name },
      members: r.rows.map(row => ({
        id: row.id,
        accountId: row.account_id,
        inviteEmail: row.invite_email,
        role: row.role,
        status: row.status,
        createdAt: Number(row.created_at),
        firstName: row.first_name, lastName: row.last_name,
        email: row.email || row.invite_email,
        company: row.company_name,
        hasAvatar: !!row.has_avatar,
      })),
    });
  }

  if (urlPath === '/api/team/invite' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const email = String(body.email || '').trim().toLowerCase();
    const role = ['admin', 'member'].includes(body.role) ? body.role : 'member';
    if (!EMAIL_RE.test(email)) return sendJson(res, 400, { ok: false, errors: { email: 'Enter a valid email.' } });
    const team = await getOrCreateTeamForOwner(user.id, user.firstName);
    const existing = await findAccountByEmail(email);
    const id = 'tmm_' + crypto.randomBytes(8).toString('hex');
    try {
      await db.query(
        `INSERT INTO team_members (id, team_id, account_id, invite_email, role, status, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [id, team.id, existing ? existing.id : null, existing ? null : email,
         role, existing ? 'active' : 'invited', Date.now()]
      );
    } catch (err) {
      if (err && err.code === '23505') return sendJson(res, 409, { ok: false, error: 'Already on your team.' });
      throw err;
    }
    if (existing) {
      await createNotification(existing.id, 'team',
        'Added to a team',
        `${user.firstName || 'Someone'} added you to their team.`, '/team');
    }
    return sendJson(res, 200, { ok: true, id, status: existing ? 'active' : 'invited' });
  }

  const idMatch = urlPath.match(/^\/api\/team\/members\/([a-z0-9_]+)$/);
  if (idMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    // Only the team owner can remove members, and not themselves.
    const r = await db.query(
      `SELECT m.id, m.role, t.owner_id FROM team_members m JOIN teams t ON t.id = m.team_id
        WHERE m.id = $1`, [idMatch[1]]);
    const row = r.rows[0];
    if (!row || row.owner_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    if (row.role === 'owner') return sendJson(res, 403, { ok: false, error: 'Cannot remove the owner.' });
    await db.query('DELETE FROM team_members WHERE id = $1', [idMatch[1]]);
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

// ============================================================
// Trials. Starts a trial from an application; records outcome.
// ============================================================

async function handleTrials(req, res, urlPath) {
  if (urlPath === '/api/trials' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query(
      `SELECT t.*, j.title AS job_title, j.trial_days, j.trial_hours,
              va.first_name AS va_first_name, va.last_name AS va_last_name,
              cli.first_name AS client_first_name, cli.company_name AS client_company
         FROM trials t JOIN jobs j ON j.id = t.job_id
         JOIN accounts va  ON va.id  = t.va_id
         JOIN accounts cli ON cli.id = t.client_id
        WHERE t.client_id = $1 OR t.va_id = $1
        ORDER BY t.ends_at DESC`,
      [user.id]
    );
    return sendJson(res, 200, {
      ok: true,
      trials: r.rows.map(row => ({
        id: row.id,
        applicationId: row.application_id,
        jobId: row.job_id,
        clientId: row.client_id,
        vaId: row.va_id,
        startedAt: Number(row.started_at),
        endsAt: Number(row.ends_at),
        scope: row.scope,
        outcome: row.outcome,
        decidedAt: row.decided_at == null ? null : Number(row.decided_at),
        createdAt: Number(row.created_at),
        jobTitle: row.job_title,
        trialDays: row.trial_days,
        trialHours: row.trial_hours,
        vaFirstName: row.va_first_name, vaLastName: row.va_last_name,
        clientFirstName: row.client_first_name, clientCompany: row.client_company,
      })),
    });
  }

  if (urlPath === '/api/trials' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const applicationId = String(body.applicationId || '').trim();
    if (!applicationId) return sendJson(res, 400, { ok: false, error: 'Missing applicationId.' });
    const ar = await db.query(
      `SELECT a.id, a.job_id, a.va_id, j.client_id, j.trial_days, j.trial_hours, j.trial_scope
         FROM applications a JOIN jobs j ON j.id = a.job_id WHERE a.id = $1`,
      [applicationId]
    );
    const app = ar.rows[0];
    if (!app || app.client_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Application not found.' });

    const days = Math.max(1, Math.min(14, Number(body.days || app.trial_days || 3)));
    const scope = String(body.scope || app.trial_scope || '').slice(0, 2000) || null;
    const now = Date.now();
    const endsAt = now + days * 86400 * 1000;
    const id = 'tr_' + crypto.randomBytes(8).toString('hex');
    try {
      await db.query(
        `INSERT INTO trials (id, application_id, job_id, client_id, va_id, started_at, ends_at,
            scope, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [id, applicationId, app.job_id, user.id, app.va_id, now, endsAt, scope, now]
      );
    } catch (err) {
      if (err && err.code === '23505') return sendJson(res, 409, { ok: false, error: 'Trial already started for this application.' });
      throw err;
    }
    await db.query(
      `UPDATE applications SET status = 'trialing', updated_at = $1 WHERE id = $2`,
      [now, applicationId]
    );
    await createNotification(app.va_id, 'trial',
      'Trial started',
      `A client started a ${days}-day paid trial with you.`, '/my-applications');
    return sendJson(res, 200, { ok: true, id, endsAt });
  }

  const idMatch = urlPath.match(/^\/api\/trials\/([a-z0-9_]+)$/);
  if (idMatch && req.method === 'PATCH') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query('SELECT * FROM trials WHERE id = $1', [idMatch[1]]);
    const row = r.rows[0];
    if (!row || row.client_id !== user.id) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const outcome = String(body.outcome || '').trim();
    if (!['hired', 'passed', 'cancelled'].includes(outcome)) return sendJson(res, 400, { ok: false, error: 'Invalid outcome.' });
    const now = Date.now();
    await db.query('UPDATE trials SET outcome = $1, decided_at = $2 WHERE id = $3', [outcome, now, idMatch[1]]);
    const nextAppStatus = outcome === 'hired' ? 'hired' : 'rejected';
    await db.query('UPDATE applications SET status = $1, updated_at = $2 WHERE id = $3',
      [nextAppStatus, now, row.application_id]);
    await createNotification(row.va_id, 'trial',
      outcome === 'hired' ? 'You were hired!' : 'Trial ended',
      outcome === 'hired'
        ? 'The client decided to hire you after the trial.'
        : (outcome === 'passed' ? 'The client decided not to continue after the trial.' : 'The trial was cancelled.'),
      '/my-applications');
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

// ============================================================
// Academy progress (course step tracking).
// ============================================================

async function handleAcademyProgress(req, res, urlPath) {
  if (urlPath === '/api/academy/progress' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    const r = await db.query(
      'SELECT course, step, score, updated_at FROM academy_progress WHERE account_id = $1',
      [user.id]
    );
    return sendJson(res, 200, {
      ok: true,
      progress: r.rows.map(row => ({
        course: row.course, step: row.step, score: row.score,
        updatedAt: Number(row.updated_at),
      })),
    });
  }

  if (urlPath === '/api/academy/progress' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'va') return sendJson(res, 403, { ok: false, error: 'VAs only.' });
    let body;
    try { body = JSON.parse(await readBody(req)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const course = String(body.course || '').trim().toLowerCase();
    if (!ACADEMY_COURSES[course]) return sendJson(res, 400, { ok: false, error: 'Unknown course.' });
    const step = Math.max(0, Math.min(50, Number(body.step) | 0));
    const score = body.score != null ? Math.max(0, Math.min(100, Number(body.score) | 0)) : null;
    await db.query(
      `INSERT INTO academy_progress (account_id, course, step, score, updated_at)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (account_id, course) DO UPDATE
         SET step = GREATEST(academy_progress.step, EXCLUDED.step),
             score = COALESCE(EXCLUDED.score, academy_progress.score),
             updated_at = EXCLUDED.updated_at`,
      [user.id, course, step, score, Date.now()]
    );
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

// ============================================================
// Contact form. Public; rate-limited per IP.
// ============================================================

async function handleContact(req, res, urlPath) {
  if (urlPath !== '/api/contact' || req.method !== 'POST') return false;
  if (!rateLimit('contact:' + clientKey(req), 5, 60 * 60 * 1000)) {
    return sendJson(res, 429, { ok: false, error: 'Too many messages. Try again later.' });
  }
  let body;
  try { body = JSON.parse(await readBody(req, 16 * 1024)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
  const name = String(body.name || '').trim().slice(0, 120);
  const email = String(body.email || '').trim().toLowerCase().slice(0, 160);
  const subject = body.subject ? String(body.subject).trim().slice(0, 200) : null;
  const text = String(body.body || body.message || '').trim().slice(0, 4000);
  const errors = {};
  if (!name) errors.name = 'Name is required.';
  if (!EMAIL_RE.test(email)) errors.email = 'Enter a valid email.';
  if (text.length < 10) errors.body = 'Message must be at least 10 characters.';
  if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });
  const id = 'cm_' + crypto.randomBytes(8).toString('hex');
  await db.query(
    `INSERT INTO contact_messages (id, name, email, subject, body, ip, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [id, name, email, subject, text, clientKey(req), Date.now()]
  );
  return sendJson(res, 200, { ok: true });
}

// ============================================================
// Admin. Lightweight dashboard-backing endpoints. role === 'admin'.
// ============================================================

async function requireAdmin(req, res) {
  const user = await currentUser(req);
  if (!user) { sendJson(res, 401, { ok: false, error: 'Not signed in.' }); return null; }
  if (user.role !== 'admin') { sendJson(res, 403, { ok: false, error: 'Admin only.' }); return null; }
  return user;
}

async function handleAdmin(req, res, urlPath) {
  if (!urlPath.startsWith('/api/admin/')) return false;

  if (urlPath === '/api/admin/stats' && req.method === 'GET') {
    const admin = await requireAdmin(req, res); if (!admin) return true;
    const [accounts, jobs, apps, flagged, contact] = await Promise.all([
      db.query(`SELECT role, COUNT(*)::int AS n FROM accounts GROUP BY role`),
      db.query(`SELECT status, COUNT(*)::int AS n FROM jobs GROUP BY status`),
      db.query(`SELECT COUNT(*)::int AS n FROM applications`),
      db.query(`SELECT COUNT(*)::int AS n FROM jobs WHERE status = 'flagged'`),
      db.query(`SELECT COUNT(*)::int AS n FROM contact_messages`),
    ]);
    return sendJson(res, 200, {
      ok: true,
      accounts: Object.fromEntries(accounts.rows.map(r => [r.role, r.n])),
      jobs: Object.fromEntries(jobs.rows.map(r => [r.status, r.n])),
      applications: apps.rows[0].n,
      flaggedJobs: flagged.rows[0].n,
      contactMessages: contact.rows[0].n,
    });
  }

  if (urlPath === '/api/admin/flagged-jobs' && req.method === 'GET') {
    const admin = await requireAdmin(req, res); if (!admin) return true;
    const r = await db.query(
      `SELECT j.id, j.title, j.description, j.company_name, j.created_at, j.status,
              a.email AS client_email, a.first_name AS client_first_name
         FROM jobs j JOIN accounts a ON a.id = j.client_id
        WHERE j.status = 'flagged' ORDER BY j.created_at DESC LIMIT 100`
    );
    return sendJson(res, 200, {
      ok: true,
      jobs: r.rows.map(row => ({
        id: row.id, title: row.title, description: row.description,
        companyName: row.company_name, createdAt: Number(row.created_at),
        status: row.status, clientEmail: row.client_email, clientFirstName: row.client_first_name,
      })),
    });
  }

  const jobDecisionMatch = urlPath.match(/^\/api\/admin\/jobs\/([a-z0-9_]+)\/(approve|remove)$/);
  if (jobDecisionMatch && req.method === 'POST') {
    const admin = await requireAdmin(req, res); if (!admin) return true;
    const [_, jobId, action] = jobDecisionMatch;
    const newStatus = action === 'approve' ? 'open' : 'removed';
    await db.query('UPDATE jobs SET status = $1, updated_at = $2 WHERE id = $3',
      [newStatus, Date.now(), jobId]);
    return sendJson(res, 200, { ok: true, status: newStatus });
  }

  if (urlPath === '/api/admin/contact-messages' && req.method === 'GET') {
    const admin = await requireAdmin(req, res); if (!admin) return true;
    const r = await db.query(
      'SELECT id, name, email, subject, body, created_at FROM contact_messages ORDER BY created_at DESC LIMIT 200'
    );
    return sendJson(res, 200, {
      ok: true,
      messages: r.rows.map(row => ({
        id: row.id, name: row.name, email: row.email, subject: row.subject,
        body: row.body, createdAt: Number(row.created_at),
      })),
    });
  }

  if (urlPath === '/api/admin/accounts' && req.method === 'GET') {
    const admin = await requireAdmin(req, res); if (!admin) return true;
    const url = new URL(req.url, 'http://localhost');
    const q = (url.searchParams.get('q') || '').trim().toLowerCase();
    const params = [];
    let where = '';
    if (q) { params.push('%' + q + '%'); where = `WHERE LOWER(email) LIKE $1 OR LOWER(first_name || ' ' || last_name) LIKE $1`; }
    const r = await db.query(
      `SELECT id, role, email, first_name, last_name, company_name, verified, created_at
         FROM accounts ${where} ORDER BY created_at DESC LIMIT 200`, params);
    return sendJson(res, 200, {
      ok: true,
      accounts: r.rows.map(row => ({
        id: row.id, role: row.role, email: row.email,
        firstName: row.first_name, lastName: row.last_name,
        companyName: row.company_name, verified: !!row.verified,
        createdAt: Number(row.created_at),
      })),
    });
  }

  return false;
}

// ============================================================
// Reports (client spend summary + CSV export).
// ============================================================

async function handleReports(req, res, urlPath) {
  if (urlPath === '/api/reports/summary' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    const [paid, pending, hires] = await Promise.all([
      db.query(`SELECT COALESCE(SUM(total),0) AS s FROM invoices WHERE client_id = $1 AND status = 'paid'`, [user.id]),
      db.query(`SELECT COALESCE(SUM(total),0) AS s FROM invoices WHERE client_id = $1 AND status = 'sent'`, [user.id]),
      db.query(`SELECT COUNT(*)::int AS n FROM applications a JOIN jobs j ON j.id = a.job_id
                 WHERE j.client_id = $1 AND a.status = 'hired'`, [user.id]),
    ]);
    return sendJson(res, 200, {
      ok: true,
      paidTotal: Number(paid.rows[0].s),
      pendingTotal: Number(pending.rows[0].s),
      totalHires: hires.rows[0].n,
    });
  }

  if (urlPath === '/api/reports/export.csv' && req.method === 'GET') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Not signed in.' });
    if (user.role !== 'client') return sendJson(res, 403, { ok: false, error: 'Clients only.' });
    const r = await db.query(
      `SELECT i.invoice_no, i.issued_on, i.currency, i.total, i.status, i.paid_at,
              va.first_name || ' ' || va.last_name AS va_name
         FROM invoices i JOIN accounts va ON va.id = i.va_id
        WHERE i.client_id = $1 ORDER BY i.issued_on DESC`,
      [user.id]
    );
    const rows = [['Invoice', 'Issued', 'VA', 'Currency', 'Total', 'Status', 'Paid At']];
    for (const row of r.rows) {
      rows.push([
        row.invoice_no, row.issued_on, row.va_name, row.currency,
        Number(row.total).toFixed(2), row.status,
        row.paid_at ? new Date(Number(row.paid_at)).toISOString() : '',
      ]);
    }
    const csv = rows.map(cells => cells.map(c => {
      const s = String(c == null ? '' : c);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }).join(',')).join('\r\n');
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="jobseekers-report-${new Date().toISOString().slice(0,10)}.csv"`,
      'Cache-Control': 'no-store',
    });
    res.end(csv);
    return true;
  }
  return false;
}

// ============================================================
// Community forum: threads + replies. Anyone can read; signed-in
// users can post. Scam/off-platform content is auto-flagged and
// hidden from the public list until moderated.
// ============================================================

const FORUM_CATEGORIES = new Set([
  'Newbies', 'Night Shift', 'Taxes', 'Rates', 'Tools', 'Scam Alert', 'Stories', 'General',
]);

function threadRowToForumJson(row) {
  return {
    id: row.id,
    authorId: row.author_id,
    authorFirstName: row.author_first_name,
    authorLastName: row.author_last_name,
    authorHasAvatar: !!row.author_has_avatar,
    category: row.category,
    title: row.title,
    body: row.body,
    views: row.views,
    status: row.status,
    replyCount: Number(row.reply_count || 0),
    lastReplyAt: Number(row.last_reply_at),
    createdAt: Number(row.created_at),
  };
}

async function handleForum(req, res, urlPath) {
  if (!urlPath.startsWith('/api/forum')) return false;

  // GET /api/forum/threads — public list with filters + pagination
  if (urlPath === '/api/forum/threads' && req.method === 'GET') {
    const url = new URL(req.url, 'http://localhost');
    const cat = (url.searchParams.get('category') || '').trim();
    const q   = (url.searchParams.get('q') || '').trim().toLowerCase();
    const page  = Math.max(1, parseInt(url.searchParams.get('page')  || '1', 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') || '20', 10) || 20));

    const where = [`t.status IN ('open', 'closed')`];
    const params = [];
    if (cat && cat !== 'all' && FORUM_CATEGORIES.has(cat)) {
      params.push(cat); where.push(`t.category = $${params.length}`);
    }
    if (q) {
      params.push('%' + q + '%');
      where.push(`(LOWER(t.title) LIKE $${params.length} OR LOWER(COALESCE(t.body,'')) LIKE $${params.length})`);
    }
    const whereSql = where.join(' AND ');

    const countR = await db.query(`SELECT COUNT(*)::int AS n FROM forum_threads t WHERE ${whereSql}`, params);
    const total = countR.rows[0].n;

    params.push(limit);
    params.push((page - 1) * limit);
    const listR = await db.query(
      `SELECT t.id, t.author_id, t.category, t.title, t.body, t.views, t.status,
              t.last_reply_at, t.created_at,
              a.first_name AS author_first_name, a.last_name AS author_last_name,
              (a.avatar_data IS NOT NULL) AS author_has_avatar,
              (SELECT COUNT(*)::int FROM forum_replies r WHERE r.thread_id = t.id AND r.flagged = FALSE) AS reply_count
         FROM forum_threads t
         JOIN accounts a ON a.id = t.author_id
        WHERE ${whereSql}
        ORDER BY t.last_reply_at DESC
        LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    return sendJson(res, 200, {
      ok: true, total, page, limit, pages: Math.max(1, Math.ceil(total / limit)),
      threads: listR.rows.map(threadRowToForumJson),
    });
  }

  // POST /api/forum/threads — signed-in, verified users
  if (urlPath === '/api/forum/threads' && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Sign in to post.' });
    if (!user.verified) return sendJson(res, 403, { ok: false, error: 'Verify your email first.' });
    if (!rateLimit('forum-thread:' + user.id, 10, 60 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many topics in the last hour.' });
    }

    let body;
    try { body = JSON.parse(await readBody(req, 32 * 1024)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const title = String(body.title || '').trim().slice(0, 200);
    const text  = String(body.body  || '').trim().slice(0, 8000);
    const cat   = String(body.category || '').trim();
    const errors = {};
    if (title.length < 10) errors.title = 'Give your topic a descriptive title (10+ characters).';
    if (!FORUM_CATEGORIES.has(cat)) errors.category = 'Pick a category.';
    if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });

    // Content safety: reuse the job-post scam rules + off-platform regex.
    // Scam Alert threads are allowed to quote scam patterns (people warn the
    // community) so we don't auto-flag that category.
    const content = title + '\n\n' + text;
    const scam = cat === 'Scam Alert' ? [] : JOB_SCAM_RULES.filter(r => r.re.test(content)).map(r => r.msg);
    const offPlatform = OFF_PLATFORM_REGEX.test(content);
    const status = (scam.length || offPlatform) ? 'flagged' : 'open';

    const id = 'ft_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await db.query(
      `INSERT INTO forum_threads (id, author_id, category, title, body, status, last_reply_at, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`,
      [id, user.id, cat, title, text || null, status, now]
    );
    return sendJson(res, 200, {
      ok: true, id, status,
      flagged: status === 'flagged',
      flagReasons: [...scam, ...(offPlatform ? ['Contains off-platform contact details'] : [])],
    });
  }

  // GET /api/forum/threads/:id — single thread + replies (bumps view)
  const idMatch = urlPath.match(/^\/api\/forum\/threads\/([a-z0-9_]+)$/);
  if (idMatch && req.method === 'GET') {
    const id = idMatch[1];
    const r = await db.query(
      `SELECT t.id, t.author_id, t.category, t.title, t.body, t.views, t.status,
              t.last_reply_at, t.created_at,
              a.first_name AS author_first_name, a.last_name AS author_last_name,
              (a.avatar_data IS NOT NULL) AS author_has_avatar,
              0 AS reply_count
         FROM forum_threads t JOIN accounts a ON a.id = t.author_id
        WHERE t.id = $1`,
      [id]
    );
    const row = r.rows[0];
    if (!row || row.status === 'removed') return sendJson(res, 404, { ok: false, error: 'Not found' });
    // Flagged threads are only visible to the author + admins.
    if (row.status === 'flagged') {
      const user = await currentUser(req);
      if (!user || (user.id !== row.author_id && user.role !== 'admin')) {
        return sendJson(res, 404, { ok: false, error: 'Not found' });
      }
    }

    // Bump the view count. Don't await — minor stat, don't gate the response.
    db.query('UPDATE forum_threads SET views = views + 1 WHERE id = $1', [id]).catch(() => {});

    const rr = await db.query(
      `SELECT r.id, r.author_id, r.body, r.flagged, r.created_at,
              a.first_name AS author_first_name, a.last_name AS author_last_name,
              (a.avatar_data IS NOT NULL) AS author_has_avatar
         FROM forum_replies r JOIN accounts a ON a.id = r.author_id
        WHERE r.thread_id = $1 AND r.flagged = FALSE
        ORDER BY r.created_at ASC
        LIMIT 500`,
      [id]
    );
    return sendJson(res, 200, {
      ok: true,
      thread: threadRowToForumJson(row),
      replies: rr.rows.map(x => ({
        id: x.id,
        authorId: x.author_id,
        authorFirstName: x.author_first_name,
        authorLastName: x.author_last_name,
        authorHasAvatar: !!x.author_has_avatar,
        body: x.body,
        createdAt: Number(x.created_at),
      })),
    });
  }

  // POST /api/forum/threads/:id/replies — signed-in reply
  const replyMatch = urlPath.match(/^\/api\/forum\/threads\/([a-z0-9_]+)\/replies$/);
  if (replyMatch && req.method === 'POST') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Sign in to reply.' });
    if (!user.verified) return sendJson(res, 403, { ok: false, error: 'Verify your email first.' });
    if (!rateLimit('forum-reply:' + user.id, 60, 60 * 60 * 1000)) {
      return sendJson(res, 429, { ok: false, error: 'Too many replies in the last hour.' });
    }
    const threadId = replyMatch[1];
    const tr = await db.query('SELECT id, status, author_id, title, category FROM forum_threads WHERE id = $1', [threadId]);
    const t = tr.rows[0];
    if (!t || t.status === 'removed') return sendJson(res, 404, { ok: false, error: 'Thread not found.' });
    if (t.status === 'closed') return sendJson(res, 403, { ok: false, error: 'This thread is closed.' });
    if (t.status === 'flagged') return sendJson(res, 403, { ok: false, error: 'This thread is under review.' });

    let body;
    try { body = JSON.parse(await readBody(req, 16 * 1024)); } catch (e) { return sendJson(res, 400, { ok: false, error: 'Invalid JSON' }); }
    const text = String(body.body || '').trim().slice(0, 4000);
    if (text.length < 2) return sendJson(res, 400, { ok: false, errors: { body: 'Reply is too short.' } });

    const scam = t.category === 'Scam Alert' ? [] : JOB_SCAM_RULES.filter(r => r.re.test(text)).map(r => r.msg);
    const offPlatform = OFF_PLATFORM_REGEX.test(text);
    const flagged = scam.length > 0 || offPlatform;

    const id = 'fr_' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await db.query(
      `INSERT INTO forum_replies (id, thread_id, author_id, body, flagged, created_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, threadId, user.id, text, flagged, now]
    );
    if (!flagged) {
      await db.query('UPDATE forum_threads SET last_reply_at = $1 WHERE id = $2', [now, threadId]);
      // Notify the thread author (unless they replied to themselves).
      if (t.author_id !== user.id) {
        await createNotification(t.author_id, 'forum',
          `New reply on "${t.title}"`,
          text.slice(0, 160),
          '/community?thread=' + encodeURIComponent(threadId));
      }
    }
    return sendJson(res, 200, { ok: true, id, flagged });
  }

  // DELETE /api/forum/threads/:id — author only (or admin)
  if (idMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Sign in.' });
    const id = idMatch[1];
    const r = await db.query('SELECT author_id FROM forum_threads WHERE id = $1', [id]);
    const row = r.rows[0];
    if (!row) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    if (row.author_id !== user.id && user.role !== 'admin') return sendJson(res, 403, { ok: false, error: 'Not yours.' });
    await db.query(`UPDATE forum_threads SET status = 'removed' WHERE id = $1`, [id]);
    return sendJson(res, 200, { ok: true });
  }

  // DELETE /api/forum/replies/:id — author only (or admin)
  const delReplyMatch = urlPath.match(/^\/api\/forum\/replies\/([a-z0-9_]+)$/);
  if (delReplyMatch && req.method === 'DELETE') {
    const user = await currentUser(req);
    if (!user) return sendJson(res, 401, { ok: false, error: 'Sign in.' });
    const id = delReplyMatch[1];
    const r = await db.query('SELECT author_id FROM forum_replies WHERE id = $1', [id]);
    const row = r.rows[0];
    if (!row) return sendJson(res, 404, { ok: false, error: 'Not found.' });
    if (row.author_id !== user.id && user.role !== 'admin') return sendJson(res, 403, { ok: false, error: 'Not yours.' });
    await db.query('DELETE FROM forum_replies WHERE id = $1', [id]);
    return sendJson(res, 200, { ok: true });
  }

  return false;
}

// Speed test endpoints for setup-check.html
const SPEED_CHUNK = crypto.randomBytes(1024 * 1024); // random so it can't be compressed
const MAX_TEST_BYTES = 50 * 1024 * 1024;
const NO_CACHE = { 'Cache-Control': 'no-store, no-cache, must-revalidate' };

function handleSpeedTest(req, res, urlPath) {
  if (urlPath === '/api/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...NO_CACHE });
    res.end('pong');
    return true;
  }

  if (urlPath === '/api/speedtest/download') {
    const requested = parseInt(new URL(req.url, 'http://localhost').searchParams.get('bytes'), 10) || 5 * 1024 * 1024;
    let remaining = Math.min(Math.max(requested, 1024), MAX_TEST_BYTES);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': remaining, ...NO_CACHE });
    const write = () => {
      while (remaining > 0) {
        const chunk = remaining >= SPEED_CHUNK.length ? SPEED_CHUNK : SPEED_CHUNK.subarray(0, remaining);
        remaining -= chunk.length;
        if (!res.write(chunk)) { res.once('drain', write); return; }
      }
      res.end();
    };
    write();
    return true;
  }

  if (urlPath === '/api/speedtest/upload' && req.method === 'POST') {
    let received = 0;
    req.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_TEST_BYTES) req.destroy();
    });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', ...NO_CACHE });
      res.end(JSON.stringify({ bytes: received }));
    });
    return true;
  }

  return false;
}

const server = http.createServer(async (req, res) => {
  let urlPath = req.url.split('?')[0];
  if (NOINDEX) {
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
    if (urlPath === '/robots.txt') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('User-agent: *\nDisallow: /\n');
      return;
    }
  }
  if (handleSpeedTest(req, res, urlPath)) return;
  if (urlPath.startsWith('/api/')) {
    try {
      const handledVaDir = await handleVaDirectory(req, res, urlPath);
      if (handledVaDir) return;
      if (handleAiMatch(req, res, urlPath)) return;
      const handledCerts = await handleCertificates(req, res, urlPath);
      if (handledCerts) return;
      const handledAvatar = await handleAvatar(req, res, urlPath);
      if (handledAvatar) return;
      const handledPortfolio = await handlePortfolio(req, res, urlPath);
      if (handledPortfolio) return;
      const handledJobs = await handleJobs(req, res, urlPath);
      if (handledJobs) return;
      const handledApps = await handleApplications(req, res, urlPath);
      if (handledApps) return;
      const handledThreads = await handleThreads(req, res, urlPath);
      if (handledThreads) return;
      const handledSettings = await handleSettings(req, res, urlPath);
      if (handledSettings) return;
      const handledNotifications = await handleNotifications(req, res, urlPath);
      if (handledNotifications) return;
      const handledFavorites = await handleFavorites(req, res, urlPath);
      if (handledFavorites) return;
      const handledTemplates = await handleTemplates(req, res, urlPath);
      if (handledTemplates) return;
      const handledInterviews = await handleInterviews(req, res, urlPath);
      if (handledInterviews) return;
      const handledTimesheets = await handleTimesheets(req, res, urlPath);
      if (handledTimesheets) return;
      const handledInvoices = await handleInvoices(req, res, urlPath);
      if (handledInvoices) return;
      const handledReviews = await handleReviews(req, res, urlPath);
      if (handledReviews) return;
      const handledTeam = await handleTeam(req, res, urlPath);
      if (handledTeam) return;
      const handledTrials = await handleTrials(req, res, urlPath);
      if (handledTrials) return;
      const handledAcademyProg = await handleAcademyProgress(req, res, urlPath);
      if (handledAcademyProg) return;
      const handledContact = await handleContact(req, res, urlPath);
      if (handledContact) return;
      const handledAdmin = await handleAdmin(req, res, urlPath);
      if (handledAdmin) return;
      const handledReports = await handleReports(req, res, urlPath);
      if (handledReports) return;
      const handledForum = await handleForum(req, res, urlPath);
      if (handledForum) return;
      const handled = await handleAuth(req, res, urlPath);
      if (handled) return;
    } catch (err) {
      console.error('[api error]', err);
      if (!res.headersSent) sendJson(res, 500, { ok: false, error: 'Server error' });
      return;
    }
    return sendJson(res, 404, { ok: false, error: 'Unknown endpoint' });
  }
  if (urlPath === '/') urlPath = '/index.html';

  const filePath = path.join(ROOT, urlPath);
  // Never serve files from outside the site folder (e.g. /../secret)
  if (!filePath.startsWith(ROOT + path.sep)) return notFound(res);

  // Try exact path first; if no extension, try appending .html; and finally
  // treat the path as a VA slug (/leimarzona → va-profile.html for Lei).
  // The slug lookup only runs when nothing else matched, so static files and
  // page .html files always win.
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (!err) {
      tryServe(res, filePath);
      return;
    }
    if (path.extname(urlPath) !== '') {
      notFound(res);
      return;
    }
    fs.access(filePath + '.html', fs.constants.F_OK, async (htmlErr) => {
      if (!htmlErr) {
        tryServe(res, filePath + '.html');
        return;
      }
      const maybeSlug = urlPath.slice(1); // strip leading '/'
      if (!/^[a-z0-9][a-z0-9-]*$/i.test(maybeSlug)) { notFound(res); return; }
      const slugLower = maybeSlug.toLowerCase();
      if (VAS_BY_SLUG.has(slugLower)) {
        tryServe(res, path.join(ROOT, 'va-profile.html'));
        return;
      }
      // Check real VA accounts too so signed-up users have a vanity URL.
      try {
        const acc = await findVaAccountBySlug(slugLower);
        if (acc) { tryServe(res, path.join(ROOT, 'va-profile.html')); return; }
      } catch (e) { /* fall through to 404 */ }
      notFound(res);
    });
  });
});

db.initSchema()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`\n  Jobseekers.ph running on port ${PORT}\n`);
    });
  })
  .catch(err => {
    console.error('[boot] schema init failed:', err);
    process.exit(1);
  });
