'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { DateTime } = require('luxon');
const { v4: uuidv4 } = require('uuid');
const basicAuth = require('basic-auth');

const app = express();

// ===== ENV =====
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;

const ENFORCE_WINDOW = String(process.env.ENFORCE_WINDOW || '0') === '1';
const TZ = 'Europe/Riga';

const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || '').trim(); // https://radijumi.jurmalasudens.lv

const ADMIN_KEY = (process.env.ADMIN_KEY || '').trim();
const ADMIN_USER = process.env.ADMIN_USER || '';
const ADMIN_PASS = process.env.ADMIN_PASS || '';

const RATE_LIMIT_SUBMIT_PER_10MIN = parseInt(process.env.RATE_LIMIT_SUBMIT_PER_10MIN || '20', 10);
const RATE_LIMIT_ADDR_PER_MIN = parseInt(process.env.RATE_LIMIT_ADDR_PER_MIN || '60', 10);

// ===== sanity =====
if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is missing');
  process.exit(1);
}

// ===== DB pool =====
const pool = new Pool({
  connectionString: DATABASE_URL,
});

// ===== middleware =====
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
}));

app.use(express.json({ limit: '128kb' }));
app.use(express.urlencoded({ extended: false, limit: '128kb' }));

// ===== static frontend (IMPORTANT: your repo uses "Public" folder on Linux) =====
app.use(express.static(path.join(__dirname, 'Public'), {
  etag: true,
  maxAge: '1h'
}));

// Always serve index.html on /
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'Public', 'index.html'));
});

// ===== rate limiters =====
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

// ===== helpers =====
function getSubmissionWindow(now = DateTime.now().setZone(TZ)) {
  const start = now.startOf('month').plus({ days: 24 }).startOf('day'); // 25th 00:00
  const end = now.endOf('month'); // last day 23:59:59.999
  const isOpen = now >= start && now <= end;

  return {
    timezone: TZ,
    now: now.toISO(),
    start: start.toISO(),
    end: end.toISO(),
    isOpen,
  };
}

function isWindowOpen() {
  if (!ENFORCE_WINDOW) return true;
  return getSubmissionWindow().isOpen;
}

// Robust subscriber code normalization:
// - Accept 8 digits OR last 5 digits (prefix 012)
// - Preserve leading zeros by left-padding if length < 8 and > 5
// - Tolerate numeric input or spaced input
function normalizeSubscriberCode(input) {
  // Some UIs might send an array of digits -> join
  let s;
  if (Array.isArray(input)) s = input.join('');
  else s = String(input ?? '').trim();

  // Keep digits only
  let digits = s.replace(/\D+/g, '');

  // Accept last 5 digits -> prefix 012
  if (/^\d{5}$/.test(digits)) return '012' + digits;

  // If 8 digits -> OK
  if (/^\d{8}$/.test(digits)) return digits;

  // If user entered 8 digits but client sent as number, leading zeros can be lost (7 digits etc.)
  // We restore by left-padding to 8 (this keeps the "0" in front for billing exports).
  if (/^\d{6,7}$/.test(digits)) {
    digits = digits.padStart(8, '0');
    if (/^\d{8}$/.test(digits)) return digits;
  }

  return null;
}

function normalizeMeterNo(meterNo) {
  const s = String(meterNo ?? '').trim();
  if (!/^\d+$/.test(s)) return null;
  return s;
}

function parseReading(value) {
  const s = String(value ?? '').trim().replace(',', '.');
  if (!/^\d+(\.\d{1,2})?$/.test(s)) return null;
  const num = Number(s);
  if (!Number.isFinite(num) || num < 0) return null;
  return s;
}

function getClientIp(req) {
  return req.ip || null;
}

function getOriginOrReferer(req) {
  const origin = (req.get('origin') || '').trim();
  const referer = (req.get('referer') || '').trim();
  return { origin, referer };
}

function enforceSameOrigin(req, res) {
  if (!PUBLIC_ORIGIN) {
    return res.status(500).json({ ok: false, error: 'Server misconfigured: PUBLIC_ORIGIN missing' });
  }

  const { origin, referer } = getOriginOrReferer(req);

  if (origin) {
    if (origin !== PUBLIC_ORIGIN) {
      return res.status(403).json({ ok: false, error: 'Forbidden origin' });
    }
    return null;
  }

  if (referer) {
    if (!referer.startsWith(PUBLIC_ORIGIN + '/')) {
      return res.status(403).json({ ok: false, error: 'Forbidden referer' });
    }
    return null;
  }

  return res.status(403).json({ ok: false, error: 'Missing origin/referer' });
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

// CSV injection guard: if starts with = + - @, prefix with apostrophe
function csvSanitize(value) {
  const s = value == null ? '' : String(value);
  if (/^[=+\-@]/.test(s)) return "'" + s;
  return s;
}

function csvEscape(value) {
  const s = value == null ? '' : String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function toCSVRow(fields) {
  return fields.map(v => csvEscape(csvSanitize(v))).join(',') + '\n';
}

// ===== addresses file loader (cached) =====
// IMPORTANT: your "adreses.csv" is actually one address per line (with commas inside address).
const ADDR_FILE = path.join(__dirname, 'data', 'adreses.csv');

let addrCache = {
  loadedAt: 0,
  rows: [], // { norm, original }
};

function normalizeForSearch(s) {
  return String(s || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

function loadAddressesIfNeeded() {
  if (!fs.existsSync(ADDR_FILE)) {
    // If file is missing on server, autocomplete returns empty.
    // We keep it silent but also log once per start.
    if (addrCache.loadedAt === 0) {
      console.warn(`ADDR_FILE missing on server: ${ADDR_FILE}`);
    }
    addrCache = { loadedAt: Date.now(), rows: [] };
    return;
  }

  const stat = fs.statSync(ADDR_FILE);
  const mtime = stat.mtimeMs;

  // If already loaded and file not changed, keep cache
  if (addrCache.loadedAt && addrCache.loadedAt >= mtime && addrCache.rows.length) return;

  const content = fs.readFileSync(ADDR_FILE, 'utf8');

  // remove BOM if present
  const cleaned = content.replace(/^\uFEFF/, '');

  const lines = cleaned
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(Boolean);

  const rows = [];
  for (const line of lines) {
    // Your file is "one line = one address". Do NOT split by commas.
    // If ever semicolon-separated appears, take left side, else take full line.
    const addr = line.includes(';') ? line.split(';')[0].trim() : line.trim();
    if (!addr) continue;
    rows.push({ norm: normalizeForSearch(addr), original: addr });
  }

  addrCache = { loadedAt: Date.now(), rows };
  console.log(`ADDR_FILE loaded: ${rows.length} addresses`);
}

// ===== routes =====
app.get('/api/window', (req, res) => {
  const info = getSubmissionWindow();
  res.json({
    ok: true,
    enforce: ENFORCE_WINDOW,
    ...info,
  });
});

app.get('/api/addresses', addressesLimiter, (req, res) => {
  loadAddressesIfNeeded();

  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.json({ ok: true, results: [] });

  const nq = normalizeForSearch(q);

  const results = [];
  for (const r of addrCache.rows) {
    if (r.norm.includes(nq)) {
      results.push(r.original);
      if (results.length >= 20) break;
    }
  }
  res.json({ ok: true, results });
});

app.post('/api/submit', submitLimiter, async (req, res) => {
  // Origin/Referer check (SPAM protection)
  const originError = enforceSameOrigin(req, res);
  if (originError) return;

  // Time window check
  if (!isWindowOpen()) {
    const info = getSubmissionWindow();
    return res.status(403).json({ ok: false, error: 'Submission window closed', window: info });
  }

  // Honeypot
  const hp = String(req.body.website || '').trim();
  if (hp) {
    return res.status(400).json({ ok: false, error: 'Rejected' });
  }

  // Be compatible with possible frontend keys
  const subscriber_code = normalizeSubscriberCode(
    req.body.subscriber_code ?? req.body.subscriberCode ?? req.body.subscriber
  );

  if (!subscriber_code) {
    console.warn('Invalid subscriber_code received:', req.body.subscriber_code, req.body.subscriberCode, req.body.subscriber);
    return res.status(400).json({ ok: false, error: 'Invalid subscriber_code (must be 8 digits)' });
  }

  const address = String(req.body.address || '').trim();
  if (!address || address.length < 3 || address.length > 300) {
    return res.status(400).json({ ok: false, error: 'Invalid address' });
  }

  const lines = Array.isArray(req.body.lines) ? req.body.lines : [];
  if (!lines.length || lines.length > 50) {
    return res.status(400).json({ ok: false, error: 'Invalid lines' });
  }

  // Idempotency key
  let client_submission_id = String(req.body.client_submission_id || '').trim();
  if (client_submission_id) {
    if (!/^[0-9a-fA-F-]{36}$/.test(client_submission_id)) {
      return res.status(400).json({ ok: false, error: 'Invalid client_submission_id' });
    }
  } else {
    client_submission_id = uuidv4();
  }

  // Validate lines
  const cleanLines = [];
  for (const l of lines) {
    const meter_no = normalizeMeterNo(l.meter_no);
    if (!meter_no) return res.status(400).json({ ok: false, error: 'Invalid meter_no (digits only)' });

    const readingStr = parseReading(l.reading);
    if (readingStr == null) return res.status(400).json({ ok: false, error: 'Invalid reading (0.., max 2 decimals)' });

    let prevStr = null;
    if (l.previous_reading != null && String(l.previous_reading).trim() !== '') {
      const p = parseReading(l.previous_reading);
      if (p == null) return res.status(400).json({ ok: false, error: 'Invalid previous_reading' });
      prevStr = p;
    }

    cleanLines.push({
      meter_no,
      reading: readingStr,
      previous_reading: prevStr,
    });
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

    // Idempotency: replace lines for the same client_submission_id
    await client.query('DELETE FROM submission_lines WHERE submission_id = $1', [submissionId]);

    const insertLineSql = `
      INSERT INTO submission_lines (submission_id, meter_no, previous_reading, reading)
      VALUES ($1, $2, $3::numeric, $4::numeric)
    `;

    for (const l of cleanLines) {
      await client.query(insertLineSql, [
        submissionId,
        l.meter_no,
        l.previous_reading,
        l.reading,
      ]);
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

// Admin export: API with Bearer token
app.get('/api/export.csv', requireAdminBearer, async (req, res) => {
  await exportCsv(res);
});

// Admin export: browser with Basic Auth
app.get('/admin/export.csv', requireBasicAuth, async (req, res) => {
  await exportCsv(res);
});

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

// Health endpoint
app.get('/health', async (req, res) => {
  try {
    const r = await pool.query('SELECT 1 AS ok');
    res.json({ ok: true, db: r.rows[0].ok === 1 });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'db failed' });
  }
});

// ===== start =====
app.listen(PORT, () => {
  if (!PUBLIC_ORIGIN) {
    console.warn('WARN: PUBLIC_ORIGIN is not set (Origin/Referer checks will be strict-failing submit).');
  }
  console.log(`testmeter listening on :${PORT} (enforceWindow=${ENFORCE_WINDOW}, tz=${TZ})`);
});
