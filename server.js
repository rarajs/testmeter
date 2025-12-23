'use strict';

const fs = require('fs');
const path = require('path');

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const basicAuth = require('basic-auth');

const { Pool } = require('pg');
const { DateTime } = require('luxon');
const { v4: uuidv4 } = require('uuid');

const app = express();

// ===================== ENV =====================
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;

const TZ = 'Europe/Riga';
const ENFORCE_WINDOW = String(process.env.ENFORCE_WINDOW || '0') === '1';

const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || '').trim(); // https://radijumi.jurmalasudens.lv

const ADMIN_KEY = (process.env.ADMIN_KEY || '').trim();
const ADMIN_USER = process.env.ADMIN_USER || '';
const ADMIN_PASS = process.env.ADMIN_PASS || '';

const RATE_LIMIT_SUBMIT_PER_10MIN = parseInt(process.env.RATE_LIMIT_SUBMIT_PER_10MIN || '20', 10);
const RATE_LIMIT_ADDR_PER_MIN = parseInt(process.env.RATE_LIMIT_ADDR_PER_MIN || '120', 10);

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is missing');
  process.exit(1);
}

// ===================== DB =====================
const pool = new Pool({ connectionString: DATABASE_URL });

// ===================== middleware =====================
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));

// ===================== block direct CSV access =====================
app.get('/adreses.csv', (req, res) => res.status(404).end());

// ===================== static frontend =====================
app.use(express.static(path.join(__dirname, 'public'), { etag: true, maxAge: '1h' }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ===================== rate limiters =====================
const submitLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: RATE_LIMIT_SUBMIT_PER_10MIN,
  standardHeaders: true,
  legacyHeaders: false,
});

const addressesLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: RATE_LIMIT_ADDR_PER_MIN,
  standardHeaders: true,
  legacyHeaders: false,
});

// ===================== helpers =====================
function getSubmissionWindow(now = DateTime.now().setZone(TZ)) {
  const start = now.startOf('month').plus({ days: 24 }).startOf('day'); // 25th 00:00
  const end = now.endOf('month'); // last day 23:59:59.999
  const isOpen = now >= start && now <= end;
  return { timezone: TZ, now: now.toISO(), start: start.toISO(), end: end.toISO(), isOpen };
}

function isWindowOpen() {
  if (!ENFORCE_WINDOW) return true;
  return getSubmissionWindow().isOpen;
}

function getClientIp(req) {
  return req.ip || null;
}

function getOriginOrReferer(req) {
  return {
    origin: (req.get('origin') || '').trim(),
    referer: (req.get('referer') || '').trim(),
  };
}

// Strict: only allow submit from PUBLIC_ORIGIN
function enforceSameOrigin(req, res) {
  if (!PUBLIC_ORIGIN) {
    return res.status(500).json({ ok: false, error: 'Server misconfigured: PUBLIC_ORIGIN missing' });
  }

  const { origin, referer } = getOriginOrReferer(req);

  if (origin) {
    if (origin !== PUBLIC_ORIGIN) return res.status(403).json({ ok: false, error: 'Forbidden origin' });
    return null;
  }
  if (referer) {
    if (!referer.startsWith(PUBLIC_ORIGIN + '/')) return res.status(403).json({ ok: false, error: 'Forbidden referer' });
    return null;
  }

  return res.status(403).json({ ok: false, error: 'Missing origin/referer' });
}

// CSV injection guard
function csvSanitize(value) {
  const s = value == null ? '' : String(value);
  return /^[=+\-@]/.test(s) ? "'" + s : s;
}
function csvEscape(value) {
  const s = value == null ? '' : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function toCSVRow(fields) {
  return fields.map(v => csvEscape(csvSanitize(v))).join(',') + '\n';
}

// Subscriber code – COMPAT + robust.
// Accepts:
// - new: subscriber_code
// - old: abonenta_numurs
// - also: subscriberCode
// Returns 8-digit string with leading zeros preserved.
// NOTE: does NOT "invent" digits; only normalizes.
function pickSubscriberCode(body) {
  let v = body?.subscriber_code ?? body?.abonenta_numurs ?? body?.subscriberCode ?? body?.subscriber;

  if (Array.isArray(v)) v = v.join('');
  if (v && typeof v === 'object' && Array.isArray(v.digits)) v = v.digits.join('');

  let digits = String(v ?? '').trim().replace(/\D+/g, '');

  // If frontend accidentally duplicated prefix (012012xxxxx), collapse to one prefix.
  if (digits.length === 11 && digits.startsWith('012012')) {
    const fixed = '012' + digits.slice(6); // keep one 012 + last 5
    if (/^\d{8}$/.test(fixed)) return fixed;
  }

  if (/^\d{8}$/.test(digits)) return digits;
  if (/^\d{5}$/.test(digits)) return '012' + digits;

  // leading zeros lost (numeric input) -> restore to 8
  if (/^\d{6,7}$/.test(digits)) return digits.padStart(8, '0');

  return null;
}

// Reading parser: accept 123.45 or 123,45, max 2 decimals, >=0
function parseReading(value) {
  const s = String(value ?? '').trim().replace(',', '.');
  if (!/^\d+(\.\d{1,2})?$/.test(s)) return null;
  const num = Number(s);
  if (!Number.isFinite(num) || num < 0) return null;
  return s;
}

function normalizeMeterNo(v) {
  const s = String(v ?? '').trim();
  if (!/^\d+$/.test(s)) return null;
  return s;
}

function requireAdminBearer(req, res, next) {
  if (!ADMIN_KEY) return res.status(500).send('Server misconfigured: ADMIN_KEY missing');
  const auth = req.get('authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).send('Unauthorized');
  if (m[1].trim() !== ADMIN_KEY) return res.status(403).send('Forbidden');
  next();
}

function requireBasicAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) return res.status(500).send('Server misconfigured: ADMIN_USER/ADMIN_PASS missing');
  const creds = basicAuth(req);
  if (!creds || creds.name !== ADMIN_USER || creds.pass !== ADMIN_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="Admin Export"');
    return res.status(401).send('Unauthorized');
  }
  next();
}

// ===================== addresses loader =====================
// IMPORTANT: repo contains Data/adreses.csv (uppercase D)
const ADDR_FILE = path.join(__dirname, 'data', 'adreses.csv');

let addrCache = { loadedAt: 0, rows: [] };

function normalizeForSearch(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function tokenizeQuery(q) {
  // normalize and split into tokens, keep digits and letters; allow "12 aba" etc.
  const s = normalizeForSearch(q)
    .replace(/[^\p{L}\p{N}\s]+/gu, ' ') // keep letters/numbers/spaces (unicode)
    .replace(/\s+/g, ' ')
    .trim();

  if (!s) return [];
  const parts = s.split(' ').filter(Boolean);

  // keep tokens length>=2 OR pure digits
  return parts.filter(t => t.length >= 2 || /^\d+$/.test(t));
}

function loadAddressesIfNeeded() {
  if (!fs.existsSync(ADDR_FILE)) {
    if (addrCache.loadedAt === 0) console.warn(`ADDR_FILE missing on server: ${ADDR_FILE}`);
    addrCache = { loadedAt: Date.now(), rows: [] };
    return;
  }

  const stat = fs.statSync(ADDR_FILE);
  const mtime = stat.mtimeMs;

  if (addrCache.loadedAt && addrCache.loadedAt >= mtime && addrCache.rows.length) return;

  const content = fs.readFileSync(ADDR_FILE, 'utf8').replace(/^\uFEFF/, '');
  const lines = content.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

  const rows = [];
  for (const line of lines) {
    // one line = one address, keep full line (commas inside)
    const addr = line.includes(';') ? line.split(';')[0].trim() : line.trim();
    if (!addr) continue;
    rows.push({ norm: normalizeForSearch(addr), original: addr });
  }

  addrCache = { loadedAt: Date.now(), rows };
  console.log(`ADDR_FILE loaded: ${rows.length} addresses`);
}

// ===================== routes =====================

app.get('/health', async (req, res) => {
  try {
    const r = await pool.query('SELECT 1 AS ok');
    res.json({ ok: true, db: r.rows[0].ok === 1 });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'db failed' });
  }
});

// window – return BOTH formats (new + old)
app.get('/api/window', (req, res) => {
  const info = getSubmissionWindow();
  res.json({
    ok: true,
    enforce: ENFORCE_WINDOW,
    timezone: TZ,
    now: info.now,
    start: info.start,
    end: info.end,
    isOpen: info.isOpen,
    is_open: info.isOpen,
  });
});

function matchToken(words, t) {
  if (/^\d+$/.test(t)) {
    // number must be a whole word (e.g. "12")
    return words.includes(t);
  }
  // text token must match start of a word (prefix)
  return words.some(w => w.startsWith(t));
}

app.get('/api/addresses', addressesLimiter, (req, res) => {
  loadAddressesIfNeeded();

  const q = String(req.query.q || '').trim();
  if (!q) return res.json({ ok: true, results: [], items: [] });

  const tokens = tokenizeQuery(q);
  if (!tokens.length) return res.json({ ok: true, results: [], items: [] });

  const results = [];
  for (const r of addrCache.rows) {
    const words = r.norm.split(' ').filter(Boolean);

    if (tokens.every(t => matchToken(words, t))) {
      results.push(r.original);
      if (results.length >= 20) break;
    }
  }

  res.json({ ok: true, results, items: results });
});

// submit – COMPAT with old frontend + new backend payloads
app.post('/api/submit', submitLimiter, async (req, res) => {
  // Origin/Referer check
  const originError = enforceSameOrigin(req, res);
  if (originError) return;

  // Time window check
  if (!isWindowOpen()) {
    const info = getSubmissionWindow();
    return res.status(403).json({ ok: false, error: 'Submission window closed', window: info });
  }

  // Honeypot (old/new)
  const hp = String(req.body.website || req.body.honeypot || '').trim();
  if (hp) return res.status(400).json({ ok: false, error: 'Rejected' });

  const subscriber_code = pickSubscriberCode(req.body);
  if (!subscriber_code) {
    console.warn('Invalid subscriber_code. Keys:', Object.keys(req.body || {}));
    console.warn('Raw values:', req.body?.subscriber_code, req.body?.abonenta_numurs, req.body?.subscriberCode);
    return res.status(400).json({ ok: false, error: 'Invalid subscriber_code (must be 8 digits)' });
  }

  const rawLines = Array.isArray(req.body.lines) ? req.body.lines : [];
  if (!rawLines.length || rawLines.length > 200) {
    return res.status(400).json({ ok: false, error: 'Invalid lines' });
  }

  // Address:
  // new: req.body.address
  // old: per-line adrese. store submission address = first line's adrese.
  const bodyAddress = String(req.body.address || '').trim();
  const lineAddress = String(rawLines[0]?.adrese || rawLines[0]?.address || '').trim();
  const address = (bodyAddress || lineAddress || '').trim();

  if (!address || address.length < 3 || address.length > 300) {
    return res.status(400).json({ ok: false, error: 'Invalid address' });
  }

  // Normalize lines to DB fields
  const cleanLines = [];
  for (const l of rawLines) {
    const meter_no = normalizeMeterNo(l.meter_no ?? l.skaititaja_numurs ?? l.skaititajaNr);
    if (!meter_no) return res.status(400).json({ ok: false, error: 'Invalid meter_no (digits only)' });

    const readingStr = parseReading(l.reading ?? l.radijums);
    if (readingStr == null) return res.status(400).json({ ok: false, error: 'Invalid reading (max 2 decimals, >=0)' });

    let prevStr = null;
    if (l.previous_reading != null && String(l.previous_reading).trim() !== '') {
      const p = parseReading(l.previous_reading);
      if (p == null) return res.status(400).json({ ok: false, error: 'Invalid previous_reading' });
      prevStr = p;
    }

    cleanLines.push({ meter_no, reading: readingStr, previous_reading: prevStr });
  }

  // Idempotency key
  let client_submission_id = String(req.body.client_submission_id || req.body.clientSubmissionId || '').trim();
  if (client_submission_id) {
    if (!/^[0-9a-fA-F-]{36}$/.test(client_submission_id)) {
      return res.status(400).json({ ok: false, error: 'Invalid client_submission_id' });
    }
  } else {
    client_submission_id = uuidv4();
  }

  const ip = getClientIp(req);
  const ua = req.get('user-agent') || null;
  const { origin, referer } = getOriginOrReferer(req);
  const source_origin = origin || (referer ? referer.slice(0, 500) : null);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const insertSubmissionSql = `
      INSERT INTO submissions (client_submission_id, subscriber_code, address, source_origin, user_agent, ip, client_meta)
      VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
      ON CONFLICT (client_submission_id)
      DO UPDATE SET client_submission_id = EXCLUDED.client_submission_id
      RETURNING id
    `;

    const clientMeta = {
      referer: referer || null,
      origin: origin || null,
      compat: {
        abonenta_numurs: req.body?.abonenta_numurs ?? null,
      }
    };

    const subRes = await client.query(insertSubmissionSql, [
      client_submission_id,
      subscriber_code,
      address,
      source_origin,
      ua,
      ip,
      JSON.stringify(clientMeta),
    ]);

    const submissionId = subRes.rows[0].id;

    // Replace lines for idempotency
    await client.query('DELETE FROM submission_lines WHERE submission_id = $1', [submissionId]);

    const insertLineSql = `
      INSERT INTO submission_lines (submission_id, meter_no, previous_reading, reading)
      VALUES ($1, $2, $3::numeric, $4::numeric)
    `;

    for (const l of cleanLines) {
      await client.query(insertLineSql, [submissionId, l.meter_no, l.previous_reading, l.reading]);
    }

    await client.query('COMMIT');
    return res.json({ ok: true, submission_id: submissionId, client_submission_id });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('submit error', err);
    return res.status(500).json({ ok: false, error: 'Internal error' });
  } finally {
    client.release();
  }
});

// Exports from DB
app.get('/api/export.csv', requireAdminBearer, async (req, res) => exportCsv(res));
app.get('/admin/export.csv', requireBasicAuth, async (req, res) => exportCsv(res));

async function exportCsv(res) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="export.csv"');

  res.write(toCSVRow([
    'submission_id',
    'client_submission_id',
    'subscriber_code',
    'address',
    'submitted_at_utc',
    'meter_no',
    'previous_reading',
    'reading',
    'ip',
    'user_agent',
    'source_origin'
  ]));

  const client = await pool.connect();
  try {
    const sql = `
      SELECT
        s.id AS submission_id,
        s.client_submission_id,
        s.subscriber_code,
        s.address,
        (s.submitted_at AT TIME ZONE 'UTC') AS submitted_at_utc,
        l.meter_no,
        l.previous_reading,
        l.reading,
        s.ip,
        s.user_agent,
        s.source_origin
      FROM submissions s
      JOIN submission_lines l ON l.submission_id = s.id
      ORDER BY s.submitted_at DESC, s.id DESC, l.id ASC
    `;

    const result = await client.query(sql);
    for (const r of result.rows) {
      res.write(toCSVRow([
        r.submission_id,
        r.client_submission_id,
        r.subscriber_code,
        r.address,
        r.submitted_at_utc instanceof Date ? r.submitted_at_utc.toISOString() : String(r.submitted_at_utc),
        r.meter_no,
        r.previous_reading == null ? '' : r.previous_reading,
        r.reading,
        r.ip == null ? '' : r.ip,
        r.user_agent == null ? '' : r.user_agent,
        r.source_origin == null ? '' : r.source_origin,
      ]));
    }
    res.end();
  } catch (err) {
    console.error('export error', err);
    if (!res.headersSent) res.status(500);
    res.end('Export failed');
  } finally {
    client.release();
  }
}

// ===================== start =====================
app.listen(PORT, () => {
  console.log(`testmeter listening on :${PORT} (enforceWindow=${ENFORCE_WINDOW}, tz=${TZ})`);
});
