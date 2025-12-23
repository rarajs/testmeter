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
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

const ENFORCE_WINDOW = String(process.env.ENFORCE_WINDOW || '0') === '1';
const TZ = 'Europe/Riga';

const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || '').trim(); // e.g. https://radijumi.jurmalasudens.lv

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
if (!PUBLIC_ORIGIN) {
  console.warn('WARN: PUBLIC_ORIGIN is not set (Origin/Referer checks will be strict-failing submit).');
}

// ===== DB pool =====
const pool = new Pool({
  connectionString: DATABASE_URL,
  // Railway internal usually uses plain connection; SSL typically not required inside Railway.
  // If you later move to public network, you may need ssl: { rejectUnauthorized: false }
});

// ===== middleware =====
app.set('trust proxy', 1); // Railway is behind a proxy; needed for correct IP + rate-limit

app.use(helmet({
  contentSecurityPolicy: false, // keep simple; frontend is static; adjust if you want CSP
}));

app.use(express.json({ limit: '128kb' })); // protect from huge payloads
app.use(express.urlencoded({ extended: false, limit: '128kb' }));

// Static frontend
app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  maxAge: '1h'
}));

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
  // Window: from day 25 00:00 to last day 23:59:59 (Europe/Riga)
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

function normalizeSubscriberCode(code) {
  // Backend requirement: MUST be 8 digits
  const s = String(code || '').trim();
  if (!/^\d{8}$/.test(s)) return null;
  return s;
}

function normalizeMeterNo(meterNo) {
  const s = String(meterNo || '').trim();
  if (!/^\d+$/.test(s)) return null;
  return s;
}

function parseReading(value) {
  // Accept "123.45" or "123,45" up to 2 decimals
  const s = String(value || '').trim().replace(',', '.');
  if (!/^\d+(\.\d{1,2})?$/.test(s)) return null;
  const num = Number(s);
  if (!Number.isFinite(num) || num < 0) return null;
  // Keep 2 decimals (DB numeric(12,2) will enforce anyway)
  return s;
}

function getClientIp(req) {
  // Express trust proxy enabled; req.ip should be ok
  return req.ip || null;
}

function getOriginOrReferer(req) {
  const origin = (req.get('origin') || '').trim();
  const referer = (req.get('referer') || '').trim();
  return { origin, referer };
}

function enforceSameOrigin(req, res) {
  // Only enforce for submit route (public form)
  if (!PUBLIC_ORIGIN) {
    return res.status(500).json({ ok: false, error: 'Server misconfigured: PUBLIC_ORIGIN missing' });
  }

  const { origin, referer } = getOriginOrReferer(req);

  // If Origin header exists: must match exactly
  if (origin) {
    if (origin !== PUBLIC_ORIGIN) {
      return res.status(403).json({ ok: false, error: 'Forbidden origin' });
    }
    return null;
  }

  // If no Origin, fall back to Referer host prefix check
  if (referer) {
    if (!referer.startsWith(PUBLIC_ORIGIN + '/')) {
      return res.status(403).json({ ok: false, error: 'Forbidden referer' });
    }
    return null;
  }

  // If neither present -> reject (prevents random scripts/curl from anywhere)
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

// ===== addresses.csv loader (cached) =====
const ADDR_FILE = path.join(__dirname, 'data', 'adreses.csv');
let addrCache = {
  loadedAt: 0,
  rows: [], // { norm: '...', original: '...' }
};

function normalizeForSearch(s) {
  return String(s || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

function loadAddressesIfNeeded() {
  const stat = fs.existsSync(ADDR_FILE) ? fs.statSync(ADDR_FILE) : null;
  if (!stat) {
    addrCache = { loadedAt: Date.now(), rows: [] };
    return;
  }
  const mtime = stat.mtimeMs;
  if (addrCache.loadedAt && addrCache.loadedAt >= mtime && addrCache.rows.length) return;

  const content = fs.readFileSync(ADDR_FILE, 'utf8');
  const lines = content.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

  // Very simple CSV reading:
  // Expect: one address per line OR "address;..." - we keep first column
  const rows = [];
  for (const line of lines) {
    const firstCol = line.split(/[;,]/)[0].trim();
    if (firstCol) rows.push({ norm: normalizeForSearch(firstCol), original: firstCol });
  }

  addrCache = { loadedAt: Date.now(), rows };
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
  // return up to 20 matches
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
  if (originError) return; // response already sent

  // Time window check
  if (!isWindowOpen()) {
    const info = getSubmissionWindow();
    return res.status(403).json({ ok: false, error: 'Submission window closed', window: info });
  }

  // Honeypot (frontend should send e.g. "website" empty)
  const hp = String(req.body.website || '').trim();
  if (hp) {
    // treat as spam
    return res.status(400).json({ ok: false, error: 'Rejected' });
  }

  const subscriber_code = normalizeSubscriberCode(req.body.subscriber_code);
  if (!subscriber_code) {
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

  // Idempotency key (client_submission_id)
  let client_submission_id = String(req.body.client_submission_id || '').trim();
  if (client_submission_id) {
    // Basic UUID v4 format check (allow any UUID)
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

    // Insert submission with idempotency
    // If client_submission_id already exists -> return existing id
    const insertSubmissionSql = `
      INSERT INTO submissions (client_submission_id, subscriber_code, address, source_origin, user_agent, ip, client_meta)
      VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
      ON CONFLICT (client_submission_id)
      DO UPDATE SET client_submission_id = EXCLUDED.client_submission_id
      RETURNING id
    `;

    const clientMeta = {
      // Keep minimal. Add more if needed.
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

    // If this was a repeated submit (same client_submission_id), we should avoid duplicate lines:
    // simplest: delete existing lines for that submission id, then insert fresh.
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

    // Critical: respond only after COMMIT
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

// ===== export implementation =====
async function exportCsv(res) {
  // Stream CSV response
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="export.csv"');

  // Header row
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

// ===== health =====
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
  console.log(`testmeter listening on :${PORT} (enforceWindow=${ENFORCE_WINDOW}, tz=${TZ})`);
});
