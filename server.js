const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { sendVerificationEmail, sendPasswordResetEmail } = require('./mail');
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
    // Keep HTML/JS/CSS fresh in dev so edits show up without a hard refresh.
    // Fonts/images can still be cached normally.
    const dynamic = ext === '.html' || ext === '.js' || ext === '.css';
    const headers = { 'Content-Type': mime };
    if (dynamic) headers['Cache-Control'] = 'no-cache';
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
  mobile, city, skill, years, title, tagline, profile_data AS "profileData", created_at AS "createdAt"`;

// Same column list, but qualified with the accounts alias — needed whenever
// we JOIN another table that also has an `id` column (e.g. sessions).
const ACCOUNT_COLUMNS_A = `a.id, a.role, a.email, a.password_hash AS "passwordHash", a.password_salt AS "passwordSalt",
  a.first_name AS "firstName", a.last_name AS "lastName", a.verified,
  a.verify_token_hash AS "verifyTokenHash", a.verify_expires AS "verifyExpires",
  a.company_name AS "companyName", a.company_size AS "companySize", a.source,
  a.mobile, a.city, a.skill, a.years, a.title, a.tagline, a.profile_data AS "profileData", a.created_at AS "createdAt"`;

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

function handleVaDirectory(req, res, urlPath) {
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
    const ext = mime === 'image/jpeg' ? '.jpg' : (mime === 'application/pdf' ? '.pdf' : '');
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
      if (handleVaDirectory(req, res, urlPath)) return;
      if (handleAiMatch(req, res, urlPath)) return;
      const handledCerts = await handleCertificates(req, res, urlPath);
      if (handledCerts) return;
      const handledPortfolio = await handlePortfolio(req, res, urlPath);
      if (handledPortfolio) return;
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
    fs.access(filePath + '.html', fs.constants.F_OK, (htmlErr) => {
      if (!htmlErr) {
        tryServe(res, filePath + '.html');
        return;
      }
      const maybeSlug = urlPath.slice(1); // strip leading '/'
      if (/^[a-z0-9][a-z0-9-]*$/i.test(maybeSlug) && VAS_BY_SLUG.has(maybeSlug.toLowerCase())) {
        tryServe(res, path.join(ROOT, 'va-profile.html'));
        return;
      }
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
