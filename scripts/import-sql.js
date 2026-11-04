#!/usr/bin/env node
/*
  Import the training-center SQL dump into data/vas.json.

  Streams db/pudscd_db.sql line by line, parses INSERT rows for:
    users, user_skills, user_services, user_certificates
  then joins them, filters to active + verified + has-skills profiles,
  and writes a lean JSON file the Node server can read on boot.

  Run once (or whenever the dump refreshes):
    node scripts/import-sql.js
*/

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const ROOT = path.resolve(__dirname, '..');
const SQL_FILE      = path.join(ROOT, 'db', 'pudscd_db.sql');
const OUT_LIST_FILE = path.join(ROOT, 'data', 'vas.json');       // lean, drives /api/vas list
const OUT_FULL_FILE = path.join(ROOT, 'data', 'vas-full.json');  // deep, drives /api/vas/:slug

const TABLES = {
  users: {
    cols: ['id','first_name','middle_name','last_name','photo','username','email','password','title','phone','city','state','address','country','remember_token','featured','feature_time','status','online_status','verification_link','email_verified','created_at','updated_at','subdomain_status'],
    store: new Map(),
  },
  user_skills:       { cols: ['id','title','slug','percentage','color','serial_number','language_id','user_id','created_at','updated_at'], store: new Map() },
  user_services:     { cols: ['id','image','icon','name','slug','content','serial_number','featured','detail_page','lang_id','user_id','meta_keywords','meta_description','created_at','updated_at'], store: new Map() },
  user_certificates: { cols: ['id','user_id','title','slug','image','created_at','updated_at'], store: new Map() },
  // Deep-profile tables (Phase 2)
  job_experiences:   { cols: ['id','company_name','designation','content','start_date','end_date','is_continue','serial_number','lang_id','user_id','created_at','updated_at'], store: new Map() },
  user_educations:   { cols: ['id','degree_name','slug','short_description','start_date','end_date','graduated','serial_number','user_id','lang_id','created_at','updated_at'], store: new Map() },
  user_portfolios:   { cols: ['id','title','slug','image','content','serial_number','featured','language_id','category_id','user_id','meta_keywords','meta_description','created_at','updated_at'], store: new Map() },
  user_testimonials: { cols: ['id','image','name','occupation','content','serial_number','lang_id','user_id','created_at','updated_at'], store: new Map() },
  user_socials:      { cols: ['id','icon','url','serial_number','user_id','created_at','updated_at'], store: new Map() },
};

// Scrub user-supplied HTML (portfolio content). We let safe inline formatting
// through — <p>, <br>, <strong>, <em>, <ul>, <img>, YouTube <iframe> embeds —
// but strip <script>, event handlers, and javascript: URLs so nothing injected
// in the old platform's forms years ago can bite us now.
function sanitizeHtml(html) {
  if (!html) return '';
  let s = String(html);
  s = s.replace(/<script[\s\S]*?<\/script>/gi, '');
  s = s.replace(/<style[\s\S]*?<\/style>/gi, '');
  s = s.replace(/ on[a-z]+\s*=\s*"[^"]*"/gi, '');
  s = s.replace(/ on[a-z]+\s*=\s*'[^']*'/gi, '');
  s = s.replace(/javascript:/gi, '');
  // Allow only YouTube/Vimeo iframes; drop any other iframe
  s = s.replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, (m) => {
    return /src\s*=\s*["']?(?:https?:)?\/\/(?:www\.)?(youtube\.com|youtube-nocookie\.com|player\.vimeo\.com)/i.test(m) ? m : '';
  });
  // Trim: portfolios can be 50 KB — enough to render well, no need for a novel
  if (s.length > 4000) s = s.slice(0, 4000) + '…';
  return s.trim();
}

// Parse a MySQL VALUES tuple like  (1,'foo\\'s',NULL,'2022-01-01 10:00:00')
// into an array of JS values (string | number | null). Handles escaped quotes
// and backslashes in the MySQL dump dialect.
function parseTuple(src, start) {
  const values = [];
  let i = start; // caller passes index of the opening '('
  if (src[i] !== '(') throw new Error('expected ( at ' + i);
  i++;
  while (i < src.length) {
    // skip leading spaces
    while (i < src.length && src[i] === ' ') i++;
    if (src[i] === ')') return { values, end: i + 1 };
    if (src[i] === "'") {
      // string
      i++;
      let out = '';
      while (i < src.length) {
        const c = src[i];
        if (c === '\\') {
          const n = src[i + 1];
          if      (n === 'n')  out += '\n';
          else if (n === 'r')  out += '\r';
          else if (n === 't')  out += '\t';
          else if (n === '0')  out += '\0';
          else                 out += n;
          i += 2;
        } else if (c === "'") {
          // doubled single-quote means literal '
          if (src[i + 1] === "'") { out += "'"; i += 2; }
          else { i++; break; }
        } else {
          out += c;
          i++;
        }
      }
      values.push(out);
    } else if (src[i] === 'N' && src.substr(i, 4) === 'NULL') {
      values.push(null);
      i += 4;
    } else {
      // number / unquoted literal, read until , or )
      let out = '';
      while (i < src.length && src[i] !== ',' && src[i] !== ')') { out += src[i]; i++; }
      out = out.trim();
      if (out === '') values.push(null);
      else if (/^-?\d+$/.test(out)) values.push(parseInt(out, 10));
      else if (/^-?\d+\.\d+$/.test(out)) values.push(parseFloat(out));
      else values.push(out);
    }
    // separator
    while (i < src.length && src[i] === ' ') i++;
    if (src[i] === ',') { i++; continue; }
    if (src[i] === ')') return { values, end: i + 1 };
  }
  throw new Error('unterminated tuple at ' + start);
}

// A single row-line in the dump looks like:
//   INSERT INTO `users` (col, col, ...) VALUES (1,'foo',...);
//   (2,'bar',...),
//   (3,'baz',...);
// On INSERT lines the first '(' belongs to the column list, so we have to
// skip past "VALUES " to find the real tuple. On continuation lines the
// first '(' is the tuple.
function tupleFromLine(line) {
  let i;
  if (/^INSERT INTO/.test(line)) {
    const v = line.indexOf(' VALUES ');
    if (v < 0) return null;
    i = line.indexOf('(', v);
  } else {
    i = line.indexOf('(');
  }
  if (i < 0) return null;
  try {
    return parseTuple(line, i).values;
  } catch (e) {
    return null;
  }
}

function obj(cols, vals) {
  const o = {};
  for (let k = 0; k < cols.length; k++) o[cols[k]] = vals[k];
  return o;
}

async function main() {
  if (!fs.existsSync(SQL_FILE)) {
    console.error('SQL dump not found at ' + SQL_FILE);
    console.error('Decompress db/pudscd_db.sql.gz first.');
    process.exit(1);
  }

  console.log('Streaming ' + path.relative(ROOT, SQL_FILE) + ' ...');
  const rl = readline.createInterface({ input: fs.createReadStream(SQL_FILE), crlfDelay: Infinity });

  let currentTable = null;
  let lineCount = 0;
  let rowCount = 0;

  const want = new Set(Object.keys(TABLES));

  for await (const line of rl) {
    lineCount++;
    if (lineCount % 100000 === 0) process.stdout.write('.');

    // Table switch markers from the dump
    const lock = line.match(/^LOCK TABLES `([^`]+)` WRITE;/);
    if (lock) { currentTable = want.has(lock[1]) ? lock[1] : null; continue; }
    if (/^UNLOCK TABLES;/.test(line)) { currentTable = null; continue; }
    if (!currentTable) continue;

    // Rows: either start with "INSERT INTO ... VALUES (" or just "("
    if (line[0] !== '(' && !/^INSERT INTO/.test(line)) continue;
    const vals = tupleFromLine(line);
    if (!vals) continue;

    const spec = TABLES[currentTable];
    if (vals.length !== spec.cols.length) continue; // malformed row — skip
    const row = obj(spec.cols, vals);

    if (currentTable === 'users') {
      spec.store.set(row.id, row);
    } else {
      const uid = row.user_id;
      if (uid == null) continue;
      let arr = spec.store.get(uid);
      if (!arr) { arr = []; spec.store.set(uid, arr); }
      arr.push(row);
    }
    rowCount++;
  }

  process.stdout.write('\n');
  console.log('Lines read:        ' + lineCount.toLocaleString());
  console.log('Rows captured:     ' + rowCount.toLocaleString());
  console.log('users:             ' + TABLES.users.store.size.toLocaleString());
  console.log('user_skills:       ' + TABLES.user_skills.store.size.toLocaleString() + ' users with skills');
  console.log('user_services:     ' + TABLES.user_services.store.size.toLocaleString() + ' users with services');
  console.log('user_certificates: ' + TABLES.user_certificates.store.size.toLocaleString() + ' users with certs');
  console.log('job_experiences:   ' + TABLES.job_experiences.store.size.toLocaleString() + ' users with work history');
  console.log('user_educations:   ' + TABLES.user_educations.store.size.toLocaleString() + ' users with education');
  console.log('user_portfolios:   ' + TABLES.user_portfolios.store.size.toLocaleString() + ' users with portfolio');
  console.log('user_testimonials: ' + TABLES.user_testimonials.store.size.toLocaleString() + ' users with testimonials');
  console.log('user_socials:      ' + TABLES.user_socials.store.size.toLocaleString() + ' users with social links');

  // Join + filter.
  const out = [];
  const outFull = {};
  let dropNoName = 0, dropNotVerified = 0, dropInactive = 0, dropNoSkills = 0, dropDupeEmail = 0;
  const emailsSeen = new Set();

  for (const u of TABLES.users.store.values()) {
    if (u.status !== 1)         { dropInactive++;   continue; }
    if (u.email_verified !== 1) { dropNotVerified++; continue; }
    const first = (u.first_name || '').trim();
    const last  = (u.last_name  || '').trim();
    if (!first || first === '.' || first === '-') { dropNoName++; continue; }

    const skills   = (TABLES.user_skills.store.get(u.id)       || []).map(r => r.title).filter(Boolean);
    const services = (TABLES.user_services.store.get(u.id)     || []).map(r => r.name).filter(Boolean);
    const certs    = (TABLES.user_certificates.store.get(u.id) || []).map(r => r.title).filter(Boolean);

    // Dedupe (DB has lots of per-user duplicates from form resubmits)
    const uniqSkills   = [...new Set(skills.map(s => s.trim()).filter(Boolean))];
    const uniqServices = [...new Set(services.map(s => s.trim()).filter(Boolean))];
    const uniqCerts    = [...new Set(certs.map(s => s.trim()).filter(Boolean))];

    if (uniqSkills.length < 1) { dropNoSkills++; continue; }

    const email = (u.email || '').trim().toLowerCase();
    if (email && emailsSeen.has(email)) { dropDupeEmail++; continue; }
    if (email) emailsSeen.add(email);

    const name = [first, last].filter(Boolean).join(' ');
    const slug = (u.username && String(u.username).trim())
      ? String(u.username).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
      : name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

    const finalSlug = slug || ('va-' + u.id);
    const lean = {
      id:        u.id,
      slug:      finalSlug,
      name,
      firstName: first,
      lastName:  last,
      title:     (u.title || '').trim() || 'Virtual Assistant',
      city:      (u.city  || '').trim(),
      state:     (u.state || '').trim(),
      country:   (u.country || 'Philippines').trim(),
      featured:  u.featured ? 1 : 0,
      createdAt: u.created_at || null,
      skills:    uniqSkills.slice(0, 12),
      services:  uniqServices.slice(0, 6),
      certs:     uniqCerts.slice(0, 6),
    };
    out.push(lean);

    // ---- Deep profile (vas-full.json) ----
    const expRows = TABLES.job_experiences.store.get(u.id) || [];
    const eduRows = TABLES.user_educations.store.get(u.id) || [];
    const porRows = TABLES.user_portfolios.store.get(u.id) || [];
    const tstRows = TABLES.user_testimonials.store.get(u.id) || [];
    const socRows = TABLES.user_socials.store.get(u.id) || [];

    const experience = expRows
      .filter(r => r.company_name && r.designation)
      .map(r => ({
        company:   String(r.company_name).trim(),
        role:      String(r.designation).trim(),
        content:   (r.content || '').trim().slice(0, 1200),
        startDate: r.start_date || '',
        endDate:   r.is_continue ? 'Present' : (r.end_date || ''),
      }))
      .slice(0, 8);

    const education = eduRows
      .filter(r => r.degree_name)
      .map(r => ({
        degree:   String(r.degree_name).trim(),
        school:   (r.short_description || '').trim(),
        year:     (r.graduated || '').trim(),
      }))
      .slice(0, 5);

    const portfolio = porRows
      .filter(r => r.title)
      .map(r => ({
        title:    String(r.title).trim(),
        image:    r.image || null,     // storage filename — not available locally
        content:  sanitizeHtml(r.content),
        featured: r.featured ? 1 : 0,
      }))
      .slice(0, 12);

    const testimonials = tstRows
      .filter(r => r.name && r.content)
      .map(r => ({
        name:       String(r.name).trim(),
        occupation: (r.occupation || '').trim(),
        content:    String(r.content).trim().slice(0, 600),
      }))
      .slice(0, 10);

    const socials = socRows
      .filter(r => r.url && /^https?:/i.test(r.url) || /^skype:/i.test(r.url || ''))
      .map(r => ({ icon: (r.icon || 'fas fa-link').trim(), url: r.url.trim() }))
      .slice(0, 8);

    outFull[finalSlug] = {
      ...lean,
      experience,
      education,
      portfolio,
      testimonials,
      socials,
    };
  }

  // Sort: featured first, then by created_at desc (newest polished profiles up top)
  out.sort((a, b) => {
    if (b.featured !== a.featured) return b.featured - a.featured;
    return String(b.createdAt || '').localeCompare(String(a.createdAt || ''));
  });

  fs.writeFileSync(OUT_LIST_FILE, JSON.stringify(out));
  fs.writeFileSync(OUT_FULL_FILE, JSON.stringify(outFull));

  console.log('\nFiltered out:');
  console.log('  inactive status:    ' + dropInactive.toLocaleString());
  console.log('  email not verified: ' + dropNotVerified.toLocaleString());
  console.log('  no first name:      ' + dropNoName.toLocaleString());
  console.log('  no skills listed:   ' + dropNoSkills.toLocaleString());
  console.log('  duplicate email:    ' + dropDupeEmail.toLocaleString());
  console.log('\nWrote ' + out.length.toLocaleString() + ' VAs');
  console.log('  ' + path.relative(ROOT, OUT_LIST_FILE) + '  (' + (fs.statSync(OUT_LIST_FILE).size / 1024 / 1024).toFixed(2) + ' MB)');
  console.log('  ' + path.relative(ROOT, OUT_FULL_FILE) + ' (' + (fs.statSync(OUT_FULL_FILE).size / 1024 / 1024).toFixed(2) + ' MB)');
}

main().catch(err => { console.error(err); process.exit(1); });
