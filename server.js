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

/* ===================== ENV ===================== */
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;

const TZ = 'Europe/Riga';
const ENFORCE_WINDOW = String(process.env.ENFORCE_WINDOW || '0') === '1';

const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || '').trim(); // https://radijumi.jurmalasudens.lv

const ADMIN_KEY = (process.env.ADMIN_KEY || '').trim();         // optional (only for /api/export.csv)
const ADMIN_USER = process.env.ADMIN_USER || '';               // required for /admin/*
const ADMIN_PASS = process.env.ADMIN_PASS || '';

const RATE_LIMIT_SUBMIT_PER_10MIN = parseInt(process.env.RATE_LIMIT_SUBMIT_PER_10MIN || '20', 10);
const RATE_LIMIT_ADDR_PER_MIN = parseInt(process.env.RATE_LIMIT_ADDR_PER_MIN || '120', 10);

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is missing');
  process.exit(1);
}

/* ===================== DB ===================== */
const pool = new Pool({ connectionString: DATABASE_URL });

/* ===================== middleware ===================== */
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));

/* Block direct access to any addresses CSV by name */
app.get('/adreses.csv', (req, res) => res.status(404).end());

/* Static frontend from ./public */
app.use(express.static(path.join(__dirname, 'public'), { etag: true, maxAge: '1h' }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

/* ===================== rate limiters ===================== */
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

/* ===================== helpers ===================== */
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

/* Strict submit origin check */
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

/* CSV injection guard */
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

/* Basic auth middleware */
function requireBasicAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) return res.status(500).send('Server misconfigured: ADMIN_USER/ADMIN_PASS missing');
  const creds = basicAuth(req);
  if (!creds || creds.name !== ADMIN_USER || creds.pass !== ADMIN_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Unauthorized');
  }
  next();
}

/* Bearer auth middleware */
function requireAdminBearer(req, res, next) {
  if (!ADMIN_KEY) return res.status(500).send('Server misconfigured: ADMIN_KEY missing');
  const auth = req.get('authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).send('Unauthorized');
  if (m[1].trim() !== ADMIN_KEY) return res.status(403).send('Forbidden');
  next();
}

/* Subscriber code: only 8 digits */
function pickSubscriberCode(body) {
  const v = body?.subscriber_code ?? body?.abonenta_numurs ?? body?.subscriberCode ?? body?.subscriber;
  const digits = String(v ?? '').trim().replace(/\D+/g, '');
  if (/^\d{8}$/.test(digits)) return digits;
  return null;
}

/* Meter no digits only */
function normalizeMeterNo(v) {
  const s = String(v ?? '').trim();
  if (!/^\d+$/.test(s)) return null;
  return s;
}

/* Reading: allow 123 / 123.4 / 123.45 / 123,45 (max 2 decimals) */
function parseReading(value) {
  const s = String(value ?? '').trim().replace(',', '.');
  if (!/^\d+(\.\d{1,2})?$/.test(s)) return null;
  const num = Number(s);
  if (!Number.isFinite(num) || num < 0) return null;
  return s;
}

/* Diacritics helper (Ausekļa -> ausekla) */
function stripDiacritics(s) {
  return String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

/* ===================== addresses loader ===================== */
const ADDR_FILE = path.join(__dirname, 'data', 'adreses.csv');

let addrCache = { loadedAt: 0, rows: [] };

function normalizeForSearch(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
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
    // one line = one address (already cleaned: no city/postcode)
    const addr = line.includes(';') ? line.split(';')[0].trim() : line.trim();
    if (!addr) continue;

    const norm = normalizeForSearch(addr);
    const key = stripDiacritics(norm); // for search comparisons
    rows.push({ norm, key, original: addr });
  }

  addrCache = { loadedAt: Date.now(), rows };
  console.log(`ADDR_FILE loaded: ${rows.length} addresses`);
}

/* Helpers for the new "12 au" behavior */
function parseQuery(qRaw) {
  const q = stripDiacritics(normalizeForSearch(qRaw))
    .replace(/[^\p{L}\p{N}\s]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const parts = q ? q.split(' ').filter(Boolean) : [];
  const nums = parts.filter(t => /^\d+$/.test(t));
  const words = parts.filter(t => /[a-z]/i.test(t));
  return { q, parts, nums, words };
}

// house number match: num not adjacent to other digits, optional one letter suffix (12a)
function hasHouseNumber(key, num) {
  const re = new RegExp(`(^|[^0-9])${num}[a-z]?([^0-9]|$)`, 'i');
  return re.test(key);
}

/* ===================== DB: months list ===================== */
async function listAvailableMonths() {
  const client = await pool.connect();
  try {
    const sql = `
      SELECT to_char(date_trunc('month', submitted_at AT TIME ZONE $1), 'YYYY-MM') AS month
      FROM submissions
      GROUP BY 1
      ORDER BY 1 DESC
    `;
    const r = await client.query(sql, [TZ]);
    return r.rows.map(x => x.month);
  } finally {
    client.release();
  }
}

/* ===================== routes ===================== */

app.get('/health', async (req, res) => {
  try {
    const r = await pool.query('SELECT 1 AS ok');
    res.json({ ok: true, db: r.rows[0].ok === 1 });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'db failed' });
  }
});

app.get('/api/window', (req, res) => {
  const info = getSubmissionWindow();
  res.json({
    ok: true,
    enforce: ENFORCE_WINDOW,
    timezone: TZ,
    now: info.now,
    start: info.start,
    end: info.end,
    is_open: info.isOpen,
    isOpen: info.isOpen,
  });
});

/* ✅ Addresses search:
   - if query has BOTH number(s) and word(s): street MUST start with words (prefix), and house number must match number(s)
   - else: token anywhere (but tokens len>=2 or digits) */
app.get('/api/addresses', addressesLimiter, (req, res) => {
  loadAddressesIfNeeded();

  const qRaw = String(req.query.q || '').trim();
  if (!qRaw) return res.json({ ok: true, items: [], results: [] });

  const { parts, nums, words } = parseQuery(qRaw);
  const out = [];

  // Special mode: "12 au" => street prefix "au" + house number 12
  if (nums.length && words.length) {
    const prefix = words.join(' '); // "au" or "abavas"

    for (const r of addrCache.rows) {
      if (!r.key.startsWith(prefix)) continue;
      if (!nums.every(n => hasHouseNumber(r.key, n))) continue;

      out.push(r.original);
      if (out.length >= 20) break;
    }

    return res.json({ ok: true, items: out, results: out });
  }

  // Fallback: token-anywhere search
  const tokens = parts.filter(t => t.length >= 2 || /^\d+$/.test(t));
  if (!tokens.length) return res.json({ ok: true, items: [], results: [] });

  for (const r of addrCache.rows) {
    if (tokens.every(t => r.key.includes(t))) {
      out.push(r.original);
      if (out.length >= 20) break;
    }
  }

  return res.json({ ok: true, items: out, results: out });
});

/* Submit */
app.post('/api/submit', submitLimiter, async (req, res) => {
  const originError = enforceSameOrigin(req, res);
  if (originError) return;

  if (!isWindowOpen()) {
    const info = getSubmissionWindow();
    return res.status(403).json({ ok: false, error: 'Submission window closed', window: info });
  }

  const hp = String(req.body.website || req.body.honeypot || '').trim();
  if (hp) return res.status(400).json({ ok: false, error: 'Rejected' });

  const subscriber_code = pickSubscriberCode(req.body);
  if (!subscriber_code) {
    return res.status(400).json({ ok: false, error: 'Invalid subscriber_code (must be 8 digits)' });
  }

  const rawLines = Array.isArray(req.body.lines) ? req.body.lines : [];
  if (!rawLines.length || rawLines.length > 200) {
    return res.status(400).json({ ok: false, error: 'Invalid lines' });
  }

  const bodyAddress = String(req.body.address || '').trim();
  const lineAddress = String(rawLines[0]?.adrese || rawLines[0]?.address || '').trim();
  const address = (bodyAddress || lineAddress || '').trim();

  if (!address || address.length < 2 || address.length > 200) {
    return res.status(400).json({ ok: false, error: 'Invalid address' });
  }

  const cleanLines = [];
  for (const l of rawLines) {
    const meter_no = normalizeMeterNo(l.meter_no ?? l.skaititaja_numurs ?? l.skaititajaNr);
    if (!meter_no) return res.status(400).json({ ok: false, error: 'Invalid meter_no (digits only)' });

    const readingStr = parseReading(l.reading ?? l.radijums);
    if (readingStr == null) return res.status(400).json({ ok: false, error: 'Invalid reading (max 2 decimals, >=0)' });

    cleanLines.push({ meter_no, reading: readingStr });
  }

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

    const clientMeta = { referer: referer || null, origin: origin || null };

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

    await client.query('DELETE FROM submission_lines WHERE submission_id = $1', [submissionId]);

    const insertLineSql = `
      INSERT INTO submission_lines (submission_id, meter_no, previous_reading, reading)
      VALUES ($1, $2, $3::numeric, $4::numeric)
    `;

    for (const l of cleanLines) {
      await client.query(insertLineSql, [submissionId, l.meter_no, null, l.reading]);
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

/* ===================== Admin UI ===================== */

app.get('/admin', requireBasicAuth, async (req, res) => {
  try {
    const months = await listAvailableMonths();

    const optionsHtml = months.length
      ? months.map((m, i) => `<option value="${m}" ${i === 0 ? 'selected' : ''}>${m}</option>`).join('')
      : `<option value="" disabled selected>Nav datu</option>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(`
<!doctype html>
<html lang="lv">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Eksports</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 24px; }
    .card { max-width: 560px; border: 1px solid #ddd; border-radius: 12px; padding: 16px; }
    label { display:block; margin: 10px 0 6px; font-weight: 800; }
    select, input, button { width: 100%; padding: 10px; font-size: 16px; }
    button { margin-top: 12px; font-weight: 900; cursor: pointer; }
    .muted { color:#666; font-size: 13px; margin-top: 10px; }
    .danger { margin-top: 18px; border-top: 1px solid #eee; padding-top: 14px; }
    .danger h3 { margin: 0 0 8px; color: #b00020; }
    .danger small { color:#666; display:block; margin-top: 6px; }
    .danger button { background:#b00020; color:#fff; border:none; border-radius:10px; }
    .danger button:hover { opacity:.92; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Eksports (CSV)</h2>

    <form method="GET" action="/admin/export.csv">
      <label for="month">Mēnesis</label>
      <select id="month" name="month" ${months.length ? '' : 'disabled'}>
        ${optionsHtml}
      </select>
      <button type="submit" ${months.length ? '' : 'disabled'}>Eksportēt</button>
    </form>

    <div class="muted">
      Sarakstā ir tikai mēneši, par kuriem DB ir iesniegumi (pēc ${TZ} laika).
    </div>

    <div class="danger">
      <h3>Dzēst visus iesniegumus</h3>
      <div class="muted">Šī darbība neatgriezeniski izdzēsīs visus iesniegumus no DB.</div>
      <form method="POST" action="/admin/clear">
        <label for="confirm">Ieraksti <b>DELETE</b>, lai apstiprinātu</label>
        <input id="confirm" name="confirm" autocomplete="off" />
        <button type="submit">Dzēst visu</button>
        <small>Drošībai: bez “DELETE” ievades dzēšana nenotiks.</small>
      </form>
    </div>
  </div>
</body>
</html>
    `);
  } catch (e) {
    console.error('admin page error', e);
    res.status(500).send('Admin page error');
  }
});

app.post('/admin/clear', requireBasicAuth, async (req, res) => {
  const confirm = String(req.body.confirm || '').trim();
  if (confirm !== 'DELETE') {
    res.status(400);
    return res.send('Nepareizs apstiprinājums. Ieraksti DELETE.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('TRUNCATE TABLE submission_lines, submissions RESTART IDENTITY CASCADE;');
    await client.query('COMMIT');

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.end(`
<!doctype html>
<html lang="lv">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OK</title>
<style>body{font-family:system-ui;margin:24px}a{display:inline-block;margin-top:12px}</style>
</head>
<body>
  <h2>OK — visi iesniegumi dzēsti</h2>
  <div>DB tabulas ir iztīrītas (submissions + submission_lines).</div>
  <a href="/admin">Atpakaļ uz admin</a>
</body>
</html>
    `);
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('admin clear error', e);
    return res.status(500).send('Dzēšana neizdevās.');
  } finally {
    client.release();
  }
});

/* ===================== Export CSV ===================== */

async function exportCsv(res, req) {
  const month = String(req?.query?.month || '').trim(); // YYYY-MM

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="export.csv"');

  res.write(toCSVRow([
    'submission_id',
    'client_submission_id',
    'subscriber_code',
    'address',
    'submitted_at_utc',
    'meter_no',
    'reading',
    'ip',
    'user_agent',
    'source_origin'
  ]));

  const client = await pool.connect();
  try {
    let sql = `
      SELECT
        s.id AS submission_id,
        s.client_submission_id,
        s.subscriber_code,
        s.address,
        (s.submitted_at AT TIME ZONE 'UTC') AS submitted_at_utc,
        l.meter_no,
        l.reading,
        s.ip,
        s.user_agent,
        s.source_origin
      FROM submissions s
      JOIN submission_lines l ON l.submission_id = s.id
    `;

    const params = [];
    if (/^\d{4}-\d{2}$/.test(month)) {
      sql += ` WHERE to_char(date_trunc('month', s.submitted_at AT TIME ZONE $1), 'YYYY-MM') = $2`;
      params.push(TZ, month);
    }

    sql += ` ORDER BY s.submitted_at DESC, s.id DESC, l.id ASC`;

    const result = await client.query(sql, params);
    for (const r of result.rows) {
      res.write(toCSVRow([
        r.submission_id,
        r.client_submission_id,
        r.subscriber_code,
        r.address,
        r.submitted_at_utc instanceof Date ? r.submitted_at_utc.toISOString() : String(r.submitted_at_utc),
        r.meter_no,
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

app.get('/admin/export.csv', requireBasicAuth, async (req, res) => {
  await exportCsv(res, req);
});

app.get('/api/export.csv', requireAdminBearer, async (req, res) => {
  await exportCsv(res, req);
});

/* ===================== start ===================== */
app.listen(PORT, () => {
  console.log(`server listening on :${PORT} (enforceWindow=${ENFORCE_WINDOW}, tz=${TZ})`);
});
