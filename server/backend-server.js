/**
 * ShieldScan — Backend Threat Logging Server
 * A minimal Node.js / Express server that receives threats from antidebug.js
 * and logs them to a JSON file (or database).
 *
 * Usage:
 *   npm install express cors
 *   node backend-server.js
 *
 * Then configure antidebug.js with:
 *   ShieldScan.protect({ reportUrl: 'https://shieldscan-api.onrender.com/api/threats', reportToken: 'shared-secret' });
 */

const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, 'threats.json');
const API_KEY = process.env.SHIELDSCAN_API_KEY || '';
const ALLOWED_ORIGINS = (process.env.SHIELDSCAN_ALLOWED_ORIGINS || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = parseInt(process.env.SHIELDSCAN_RATE_LIMIT || '120', 10);
const requestCounts = new Map();

function isAllowedOrigin(origin) {
  if (!origin) return true;
  if (!ALLOWED_ORIGINS.length) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

function normalizeUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) return '';
  try {
    return new URL(value).toString();
  } catch (error) {
    return '';
  }
}

function cleanupRateLimit(now) {
  requestCounts.forEach((entry, key) => {
    if (now - entry.windowStart > RATE_WINDOW_MS) requestCounts.delete(key);
  });
}

function verifyApiKey(req, res, next) {
  if (!API_KEY) return next();
  const token = req.get('x-shieldscan-key') || (req.body && req.body.token) || req.query.token;
  if (token !== API_KEY) {
    return res.status(401).json({ error: 'Missing or invalid API key' });
  }
  return next();
}

function rateLimit(req, res, next) {
  const now = Date.now();
  cleanupRateLimit(now);
  const key = req.ip || 'unknown';
  const entry = requestCounts.get(key);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    requestCounts.set(key, { count: 1, windowStart: now });
    return next();
  }
  if (entry.count >= RATE_LIMIT) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }
  entry.count += 1;
  return next();
}

function validatePayload(body) {
  if (!body || body.type !== 'shieldscan-event') {
    return { ok: false, error: 'Invalid payload type' };
  }
  if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 120) {
    return { ok: false, error: 'Invalid threat name' };
  }
  if (!['DETECTED', 'CLEAN', 'UNKNOWN'].includes(body.status)) {
    return { ok: false, error: 'Invalid status' };
  }
  if (!Number.isFinite(body.confidence) || body.confidence < 0 || body.confidence > 100) {
    return { ok: false, error: 'Invalid confidence' };
  }
  if (typeof body.detail !== 'string' || body.detail.length > 2000) {
    return { ok: false, error: 'Invalid detail' };
  }
  if (typeof body.timestamp !== 'string' || Number.isNaN(Date.parse(body.timestamp))) {
    return { ok: false, error: 'Invalid timestamp' };
  }
  const url = normalizeUrl(body.url);
  const origin = normalizeUrl(body.origin);
  if (!url || !origin) {
    return { ok: false, error: 'Invalid url/origin' };
  }
  return {
    ok: true,
    value: {
      eventId: typeof body.eventId === 'string' && body.eventId ? body.eventId : `${origin}::${body.name}::${body.timestamp}`,
      name: body.name.trim(),
      status: body.status,
      confidence: body.confidence,
      detail: body.detail,
      url,
      origin,
      timestamp: body.timestamp
    }
  };
}

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(cors({
  origin(origin, callback) {
    if (isAllowedOrigin(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by ShieldScan'));
  }
}));
app.use(express.json({ limit: '32kb' })); // parse JSON bodies
app.use(express.static(__dirname));     // serve your HTML/JS files

// ── Root Health Check ───────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.send('ShieldScan Backend API is running!');
});

// ── In-memory threat store (also persisted to threats.json) ─────────────────
let threats = [];
try {
  const raw = fs.readFileSync(LOG_FILE, 'utf8');
  threats = JSON.parse(raw);
} catch (e) { /* first run — file doesn't exist yet */ }

// ── POST /api/threats — receive a threat from antidebug.js ──────────────────
app.post('/api/threats', verifyApiKey, rateLimit, (req, res) => {
  const validation = validatePayload(req.body);
  if (!validation.ok) {
    return res.status(400).json({ error: validation.error });
  }
  const body = validation.value;

  const threat = {
    id:         body.eventId,
    eventId:    body.eventId,
    name:       body.name,
    status:     body.status,
    confidence: body.confidence,
    detail:     body.detail,
    url:        body.url,
    origin:     body.origin,
    timestamp:  body.timestamp,
    serverTime: new Date().toISOString(),
    ip:         req.ip
  };

  threats.push(threat);

  // Keep last 10,000 entries
  if (threats.length > 10000) threats.splice(0, threats.length - 10000);

  // Persist to file
  fs.writeFile(LOG_FILE, JSON.stringify(threats, null, 2), () => {});

  console.log(`[THREAT] ${threat.name} — ${threat.url} @ ${threat.serverTime}`);

  res.status(201).json({ ok: true, id: threat.id });
});

// ── GET /api/threats — retrieve all logged threats ───────────────────────────
app.get('/api/threats', (req, res) => {
  const limit  = parseInt(req.query.limit)  || 100;
  const offset = parseInt(req.query.offset) || 0;
  const url    = req.query.url;

  let results = [...threats].reverse(); // newest first
  if (url) results = results.filter(t => t.url.includes(url));

  res.json({
    total:   threats.length,
    count:   Math.min(limit, results.length - offset),
    threats: results.slice(offset, offset + limit)
  });
});

// ── DELETE /api/threats — clear all threat logs ──────────────────────────────
app.delete('/api/threats', (req, res) => {
  threats = [];
  fs.writeFile(LOG_FILE, '[]', () => {});
  res.json({ ok: true, message: 'All threats cleared' });
});

// ── GET /api/stats — quick statistics ───────────────────────────────────────
app.get('/api/stats', (req, res) => {
  const byType = {};
  const byUrl  = {};
  threats.forEach(t => {
    byType[t.name] = (byType[t.name] || 0) + 1;
    const domain = (() => { try { return new URL(t.url).hostname; } catch(e) { return t.url; } })();
    byUrl[domain]  = (byUrl[domain]  || 0) + 1;
  });
  res.json({ total: threats.length, byType, byUrl });
});

// ── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`ShieldScan backend running at http://localhost:${PORT}`);
  console.log(`  POST /api/threats   — receive threats from antidebug.js`);
  console.log(`  GET  /api/threats   — list all threats (supports ?limit=N&url=...)`);
  console.log(`  GET  /api/stats     — type/domain breakdown`);
  console.log(`  DELETE /api/threats — clear log`);
  console.log(`\nConfigure antidebug.js:`);
  console.log(`  ShieldScan.protect({ reportUrl: 'https://shieldscan-api.onrender.com/api/threats', reportToken: 'shared-secret' });`);
});
