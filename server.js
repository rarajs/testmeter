const fs = require("fs");
const path = require("path");
const express = require("express");
const { DateTime } = require("luxon");

const app = express();
app.use(express.json({ limit: "1mb" }));

// ====== CONFIG ======
const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;

// TEST: default key (easy). PROD: set this via environment.
const ADMIN_KEY = process.env.ADMIN_KEY || "JurmalasUd3ns2026!";

// TEST: allow submits anytime. PROD: set ENFORCE_WINDOW=1 to enforce 25..end.
const ENFORCE_WINDOW = process.env.ENFORCE_WINDOW === "1";

const TZ = "Europe/Riga";

const DATA_DIR = path.join(__dirname, "data");
const PUBLIC_DIR = path.join(__dirname, "public");
const EXPORT_DIR = path.join(__dirname, "exports");

const ADDRESSES_CSV = path.join(DATA_DIR, "adreses.csv");  // private
const SUBMISSIONS_FILE = path.join(__dirname, "submissions.ndjson");

if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });

// ====== Submission window (for PROD) ======
function getSubmissionWindow(dt = DateTime.now().setZone(TZ)) {
  const start = dt.startOf("month").plus({ days: 24 }); // 25th 00:00
  const end = dt.endOf("month");                        // last day 23:59:59.999
  return { start, end };
}
function isWindowOpen(dt = DateTime.now().setZone(TZ)) {
  const { start, end } = getSubmissionWindow(dt);
  return dt >= start && dt <= end;
}

// ====== Utilities ======
function fold(s) {
  return (s || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^\p{L}\p{N}\s,.-]/gu, "")
    .trim();
}

function tokenize(s) {
  return fold(s).replace(/[,.-]/g, " ").split(/\s+/).filter(Boolean);
}

function detectDelimiter(line) {
  const commas = (line.match(/,/g) || []).length;
  const semis = (line.match(/;/g) || []).length;
  return semis > commas ? ";" : ",";
}

// Minimal CSV parser (supports delimiter + quotes)
function parseCsv(text) {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const delim = detectDelimiter(lines[0] || "");
  const rows = [];

  let cur = "";
  let row = [];
  let inQ = false;

  const pushCell = () => { row.push(cur); cur = ""; };
  const pushRow = () => { rows.push(row); row = []; };

  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
        else inQ = !inQ;
      } else if (c === delim && !inQ) {
        pushCell();
      } else {
        cur += c;
      }
    }
    if (!inQ) {
      pushCell();
      if (row.length > 1 || (row.length === 1 && row[0].trim() !== "")) pushRow();
      else row = [];
    } else {
      cur += "\n";
    }
  }
  return rows;
}

// ====== Load addresses into memory (server-side only) ======
let ADDRESS_LIST = []; // [{ text, fold }]
function loadAddresses() {
  const raw = fs.readFileSync(ADDRESSES_CSV, "utf8");
  const rows = parseCsv(raw);
  if (!rows.length) throw new Error("adreses.csv is empty");

  const header = rows[0].map(x => (x || "").trim());
  const idx = header.indexOf("STD");
  if (idx === -1) throw new Error("adreses.csv must contain column 'STD'");

  const data = rows.slice(1);

  const seen = new Set();
  const out = [];
  for (const r of data) {
    const v = (r[idx] || "").trim();
    if (!v) continue;
    const k = fold(v);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ text: v, fold: k });
  }
  out.sort((a, b) => a.text.localeCompare(b.text, "lv"));
  ADDRESS_LIST = out;

  console.log(`Loaded addresses: ${ADDRESS_LIST.length}`);
}

// Address scoring (supports "num first" smart behavior)
function parseStreetHouse(addrFold) {
  const firstPart = (addrFold.split(",")[0] || addrFold).trim();
  const parts = firstPart.split(/\s+/).filter(Boolean);

  let streetTokens = parts;
  let houseToken = "";
  for (let i = 0; i < parts.length; i++) {
    if (/\d/.test(parts[i])) {
      houseToken = parts[i];
      streetTokens = parts.slice(0, i);
      break;
    }
  }
  return {
    streetText: streetTokens.join(" "),
    streetFirst: (streetTokens[0] || ""),
    houseToken
  };
}

function scoreMatch(qTokens, addrFold) {
  const { streetText, streetFirst, houseToken } = parseStreetHouse(addrFold);
  const startsWithNumber = qTokens.length > 0 && /^\d/.test(qTokens[0]);

  if (startsWithNumber) {
    const houseQ = qTokens[0];
    const streetQ = qTokens.slice(1);

    if (!houseToken || !houseToken.startsWith(houseQ)) return -1;
    if (streetQ.length > 0 && !streetFirst.startsWith(streetQ[0])) return -1;

    for (let i = 1; i < streetQ.length; i++) {
      if (!streetText.includes(streetQ[i])) return -1;
    }

    let score = 70 + (streetQ.length > 0 ? 50 : 0);
    if (houseToken === houseQ) score += 10;
    return score;
  }

  let score = 0;
  for (const tok of qTokens) {
    if (!addrFold.includes(tok)) return -1;
    score += 10;
    if (/^\d+[a-z]?$/i.test(tok) && houseToken && houseToken.startsWith(tok)) score += 15;
  }
  if (qTokens.length > 0 && streetFirst.startsWith(qTokens[0])) score += 8;

  return score;
}

function searchAddresses(q, limit = 12) {
  const qTokens = tokenize(q);
  if (!qTokens.length) return [];

  const hits = [];
  for (const a of ADDRESS_LIST) {
    const s = scoreMatch(qTokens, a.fold);
    if (s >= 0) hits.push({ text: a.text, score: s });
  }
  hits.sort((x, y) => (y.score - x.score) || x.text.localeCompare(y.text, "lv"));
  return hits.slice(0, limit).map(h => h.text);
}

// ====== AUTO EXPORT (monthly) ======
function buildCsvForMonth(monthYYYYMM) {
  const from = DateTime.fromISO(monthYYYYMM + "-01", { zone: TZ }).startOf("month");
  const to = from.endOf("month");

  function inMonth(isoUtc) {
    const t = DateTime.fromISO(isoUtc, { zone: "utc" }).setZone(TZ);
    return t >= from && t <= to;
  }

  const exportedAt = DateTime.now().setZone(TZ).toISO();

  let out =
    `# exported_at=${exportedAt}; export_month=${monthYYYYMM}; tz=${TZ}\n` +
    "abonenta_numurs,adrese,skaititaja_numurs,radijums,submitted_at\n";

  if (!fs.existsSync(SUBMISSIONS_FILE)) return out;

  const lines = fs.readFileSync(SUBMISSIONS_FILE, "utf8").split("\n").filter(Boolean);

  for (const l of lines) {
    let rec;
    try { rec = JSON.parse(l); } catch { continue; }
    if (!rec?.submitted_at || !inMonth(rec.submitted_at)) continue;

    const submitted_at = rec.submitted_at || "";
    const abon = rec.abonenta_numurs || "";
    const arr = Array.isArray(rec.lines) ? rec.lines : [];

    for (const item of arr) {
      const adrese = (item.adrese || "").toString().replace(/"/g,'""');
      const meter = (item.skaititaja_numurs || "").toString().replace(/"/g,'""');
      const reading = (item.radijums ?? "").toString().replace(/"/g,'""');

      out += `"${abon}","${adrese}","${meter}","${reading}","${submitted_at}"\n`;
    }
  }

  return out;
}

function writeMonthlyExport(monthYYYYMM) {
  const csv = buildCsvForMonth(monthYYYYMM);
  const filePath = path.join(EXPORT_DIR, `radijumi_${monthYYYYMM}.csv`);
  fs.writeFileSync(filePath, csv, "utf8");
  console.log(`[AUTO-EXPORT] Wrote ${filePath}`);
  return filePath;
}

let exportTimer = null;
function scheduleNextAutoExport() {
  if (exportTimer) clearTimeout(exportTimer);

  const now = DateTime.now().setZone(TZ);
  const runAt = now.endOf("month").plus({ seconds: 10 });

  const ms = Math.max(1000, runAt.toMillis() - now.toMillis());
  console.log(`[AUTO-EXPORT] Next run at ${runAt.toISO()} (${Math.round(ms/1000)}s)`);

  exportTimer = setTimeout(() => {
    try {
      const prevMonth = DateTime.now().setZone(TZ).minus({ months: 1 }).toFormat("yyyy-MM");
      writeMonthlyExport(prevMonth);
    } catch (e) {
      console.error("[AUTO-EXPORT] Failed:", e);
    } finally {
      scheduleNextAutoExport();
    }
  }, ms);
}

// ====== API ======
app.get("/api/window", (req, res) => {
  const now = DateTime.now().setZone(TZ);
  const { start, end } = getSubmissionWindow(now);

  res.json({
    tz: TZ,
    now: now.toISO(),
    start: start.toISO(),
    end: end.toISO(),
    is_open: isWindowOpen(now),
    enforce: ENFORCE_WINDOW
  });
});

// Addresses API (private CSV behind server)
app.get("/api/addresses", (req, res) => {
  const q = (req.query.q || "").toString().trim();
  const limit = Math.min(50, Math.max(1, Number(req.query.limit || 12)));

  if (q.length < 2) return res.json({ items: [] });
  const items = searchAddresses(q, limit);
  res.json({ items });
});

// Submit readings
app.post("/api/submit", (req, res) => {
  // TEST mode: allow anytime. PROD: set ENFORCE_WINDOW=1
  if (ENFORCE_WINDOW) {
    const now = DateTime.now().setZone(TZ);
    if (!isWindowOpen(now)) {
      const { start, end } = getSubmissionWindow(now);
      return res.status(403).json({
        ok: false,
        error: "Submission window closed",
        tz: TZ,
        window_start: start.toISO(),
        window_end: end.toISO()
      });
    }
  }

  const body = req.body || {};
  const abon = (body.abonenta_numurs || "").toString().trim();
  const lines = Array.isArray(body.lines) ? body.lines : [];

  if (!/^\d{8}$/.test(abon)) {
    return res.status(400).json({ ok:false, error:"Invalid abonenta_numurs (must be 8 digits)" });
  }
  if (!lines.length) {
    return res.status(400).json({ ok:false, error:"No lines provided" });
  }

  const cleaned = [];
  for (const [i, line] of lines.entries()) {
    const adrese = (line.adrese || "").toString().trim();
    const meter = (line.skaititaja_numurs || "").toString().trim();
    const readingRaw = (line.radijums ?? "").toString().trim();

    if (!adrese) return res.status(400).json({ ok:false, error:`Line ${i+1}: missing adrese` });
    if (!/^\d+$/.test(meter)) return res.status(400).json({ ok:false, error:`Line ${i+1}: skaititaja_numurs must be digits` });
    if (!/^\d+$/.test(readingRaw)) return res.status(400).json({ ok:false, error:`Line ${i+1}: radijums must be an integer` });

    const reading = Number(readingRaw);
    if (!Number.isFinite(reading)) return res.status(400).json({ ok:false, error:`Line ${i+1}: invalid radijums` });

    cleaned.push({ adrese, skaititaja_numurs: meter, radijums: reading });
  }

  const record = {
    submitted_at: new Date().toISOString(),
    abonenta_numurs: abon,
    ip: req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.socket.remoteAddress || "",
    user_agent: req.headers["user-agent"] || "",
    lines: cleaned
  };

  fs.appendFileSync(SUBMISSIONS_FILE, JSON.stringify(record) + "\n", "utf8");
  res.json({ ok:true });
});

// Manual export (protected)
app.get("/api/export.csv", (req, res) => {
  if (ADMIN_KEY) {
    const key = (req.query.key || "").toString();
    if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");
  }

  if (!fs.existsSync(SUBMISSIONS_FILE)) {
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="billing_export.csv"');
    return res.send("abonenta_numurs,adrese,skaititaja_numurs,radijums,submitted_at\n");
  }

  const lines = fs.readFileSync(SUBMISSIONS_FILE, "utf8").split("\n").filter(Boolean);

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="billing_export.csv"');

  let out = "abonenta_numurs,adrese,skaititaja_numurs,radijums,submitted_at\n";

  for (const l of lines) {
    let rec;
    try { rec = JSON.parse(l); } catch { continue; }
    const submitted_at = rec.submitted_at || "";
    const abon = rec.abonenta_numurs || "";
    const arr = Array.isArray(rec.lines) ? rec.lines : [];

    for (const item of arr) {
      const adrese = (item.adrese || "").toString().replace(/"/g,'""');
      const meter = (item.skaititaja_numurs || "").toString().replace(/"/g,'""');
      const reading = (item.radijums ?? "").toString().replace(/"/g,'""');
      out += `"${abon}","${adrese}","${meter}","${reading}","${submitted_at}"\n`;
    }
  }

  res.send(out);
});

// Serve public files
app.use("/", express.static(PUBLIC_DIR));

// Startup
try {
  loadAddresses();
} catch (e) {
  console.error("Failed to load addresses:", e.message);
  process.exit(1);
}

app.listen(PORT, () => {
  console.log(`testmeter running: http://localhost:${PORT}`);
  console.log(`ADMIN_KEY (test): ${ADMIN_KEY ? "[set]" : "[empty]"}`);
  console.log(`ENFORCE_WINDOW: ${ENFORCE_WINDOW ? "ON" : "OFF (test mode)"}`);
  console.log(`export CSV: http://localhost:${PORT}/api/export.csv?key=${encodeURIComponent(ADMIN_KEY)}`);
  scheduleNextAutoExport();
});
