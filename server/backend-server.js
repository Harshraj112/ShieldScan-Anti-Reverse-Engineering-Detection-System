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
 *   ShieldScan.protect({ reportUrl: 'http://localhost:3000/api/threats' });
 */

const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = 3000;
const LOG_FILE = path.join(__dirname, 'threats.json');

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(cors());                        // allow cross-origin requests from any site
app.use(express.json());                // parse JSON bodies
app.use(express.static(__dirname));     // serve your HTML/JS files

// ── In-memory threat store (also persisted to threats.json) ─────────────────
let threats = [];
try {
  const raw = fs.readFileSync(LOG_FILE, 'utf8');
  threats = JSON.parse(raw);
} catch (e) { /* first run — file doesn't exist yet */ }

// ── POST /api/threats — receive a threat from antidebug.js ──────────────────
app.post('/api/threats', (req, res) => {
  const body = req.body;

  // Validate required fields
  if (!body || body.type !== 'shieldscan-event') {
    return res.status(400).json({ error: 'Invalid payload' });
  }

  const threat = {
    id:         Date.now(),
    name:       body.name       || 'Unknown',
    status:     body.status     || 'DETECTED',
    confidence: body.confidence || 0,
    detail:     body.detail     || '',
    url:        body.url        || '',
    origin:     body.origin     || '',
    timestamp:  body.timestamp  || new Date().toISOString(),
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
  console.log(`  ShieldScan.protect({ reportUrl: 'http://localhost:${PORT}/api/threats' });`);
});
