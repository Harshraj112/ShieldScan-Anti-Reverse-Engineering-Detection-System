
const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const app  = express();
const PORT = process.env.PORT || 3000;
const THREATS_FILE = path.join(__dirname, 'threats.json');
const BLOCKED_FILE = path.join(__dirname, 'blocked.json');
const DASHBOARD_PASS = process.env.SHIELDSCAN_PASS || 'admin123';
const DASHBOARD_PASS_HASH = crypto.createHash('sha256').update(DASHBOARD_PASS).digest('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = parseInt(process.env.SHIELDSCAN_RATE_LIMIT || '120', 10);
const requestCounts = new Map();
let threats = [];
let blockedIps = {};  
function loadFile(filePath, defaultVal) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch (e) { return defaultVal; }
}
threats    = loadFile(THREATS_FILE, []);
blockedIps = loadFile(BLOCKED_FILE, {});
function saveThreats()  { fs.writeFile(THREATS_FILE, JSON.stringify(threats,    null, 2), () => {}); }
function saveBlocked()  { fs.writeFile(BLOCKED_FILE, JSON.stringify(blockedIps, null, 2), () => {}); }
function normalizeUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) return '';
  try { return new URL(value).toString(); } catch (e) { return value.slice(0, 2048); }
}
function htmlEscape(str) {
  return String(str || '').replace(/[&<>"']/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[c]);
}
function cleanupRateLimit(now) {
  requestCounts.forEach((e, k) => { if (now - e.windowStart > RATE_WINDOW_MS) requestCounts.delete(k); });
}
function rateLimit(req, res, next) {
  const now = Date.now(); cleanupRateLimit(now);
  const key = req.ip || 'unknown';
  const entry = requestCounts.get(key);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    requestCounts.set(key, { count: 1, windowStart: now }); return next();
  }
  if (entry.count >= RATE_LIMIT) return res.status(429).json({ error: 'Rate limit exceeded' });
  entry.count++; next();
}
const activeSessions = new Set();
function makeToken() {
  const t = crypto.randomBytes(24).toString('hex');
  activeSessions.add(t);
  setTimeout(() => activeSessions.delete(t), 10 * 60 * 1000); 
  return t;
}
function requireAuth(req, res, next) {
  const token = req.headers['x-shieldscan-token'] || req.query.token;
  if (activeSessions.has(token)) return next();
  return res.status(401).json({ error: 'Unauthorized. POST /api/auth to login.' });
}
app.use(cors({ origin: '*', methods: ['GET','POST','DELETE','OPTIONS'] }));
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, '..', 'demo'))); 
app.use('/src', express.static(path.join(__dirname, '..', 'src'))); 
app.use('/dist', express.static(path.join(__dirname, '..', 'dist'))); 
app.get('/api/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), threats: threats.length, blocked: Object.keys(blockedIps).length });
});
app.post('/api/auth', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Password required' });
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  if (hash !== DASHBOARD_PASS_HASH) return res.status(401).json({ error: 'Invalid password' });
  res.json({ ok: true, token: makeToken() });
});
app.post('/api/threats', rateLimit, (req, res) => {
  const body = req.body || {};
  if (!body.name && !body.violationType) {
    return res.status(400).json({ error: 'Missing threat name/violationType' });
  }
  let ip = body.ip;
  if (!ip || ip === 'unavailable' || ip === 'unknown') {
    ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.ip || 'unknown';
  }
  if (ip === '::1') ip = '127.0.0.1';
  if (ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
  let isBlocked = !!blockedIps[ip];
  if (body.triggerBlock && ip && ip !== 'unknown') {
    if (!isBlocked) {
      blockedIps[ip] = { blockedAt: new Date().toISOString(), reason: 'Auto-blocked (Threat Threshold Reached)' };
      saveBlocked();
      isBlocked = true;
    }
  }
  const threat = {
    id:               body.eventId || `${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    name:             htmlEscape(body.name || body.violationType || 'Unknown'),
    violationType:    htmlEscape(body.violationType || body.name || 'Unknown'),
    status:           ['DETECTED','CLEAN','UNKNOWN'].includes(body.status) ? body.status : 'DETECTED',
    confidence:       Number.isFinite(body.confidence) ? body.confidence : 90,
    detail:           htmlEscape(String(body.detail || '').slice(0, 500)),
    ip:               String(ip).slice(0, 100),
    userAgent:        htmlEscape(String(body.userAgent || '').slice(0, 300)),
    screenResolution: htmlEscape(String(body.screenResolution || '').slice(0, 20)),
    referrer:         htmlEscape(String(body.referrer || '').slice(0, 500)),
    pageUrl:          String(body.pageUrl || body.url || '').slice(0, 2048),
    url:              String(body.url || body.pageUrl || '').slice(0, 2048),
    website:          htmlEscape(String(body.website || '').slice(0, 200)),
    origin:           String(body.origin || '').slice(0, 200),
    sessionId:        String(body.sessionId || '').slice(0, 64),
    timestamp:        typeof body.timestamp === 'string' && !isNaN(Date.parse(body.timestamp))
                        ? body.timestamp : new Date().toISOString(),
    serverTime:       new Date().toISOString(),
    serverIp:         req.ip,
    autoBlocked:      isBlocked
  };
  threats.push(threat);
  if (threats.length > 10000) threats.splice(0, threats.length - 10000);
  saveThreats();
  console.log(`[THREAT] ${threat.violationType} | ${threat.ip} | ${threat.website} | ${threat.serverTime}`);
  res.status(201).json({ ok: true, id: threat.id, blocked: isBlocked });
});
app.get('/api/threats', requireAuth, (req, res) => {
  const limit   = Math.min(parseInt(req.query.limit)  || 100, 500);
  const offset  = parseInt(req.query.offset) || 0;
  const website = req.query.website;
  const ip      = req.query.ip;
  const date    = req.query.date; 
  let results = [...threats].reverse();
  if (website) results = results.filter(t => (t.website || t.origin || t.url || '').includes(website));
  if (ip)      results = results.filter(t => t.ip === ip);
  if (date)    results = results.filter(t => t.timestamp && t.timestamp.startsWith(date));
  res.json({
    total:   results.length,
    count:   Math.min(limit, Math.max(0, results.length - offset)),
    threats: results.slice(offset, offset + limit)
  });
});
app.delete('/api/threats', requireAuth, (req, res) => {
  threats = [];
  saveThreats();
  res.json({ ok: true, message: 'All threats cleared' });
});
app.get('/api/stats', (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const byType = {}, byDomain = {}, uniqueIps = new Set();
  let todayCount = 0;
  threats.forEach(t => {
    const type = t.violationType || t.name || 'Unknown';
    byType[type]  = (byType[type] || 0) + 1;
    const domain = t.website || (() => { try { return new URL(t.url || t.origin || '').hostname; } catch(e) { return t.origin || t.url || 'unknown'; } })();
    byDomain[domain] = (byDomain[domain] || 0) + 1;
    if (t.ip) uniqueIps.add(t.ip);
    if (t.timestamp && t.timestamp.startsWith(today)) todayCount++;
  });
  res.json({
    total:       threats.length,
    todayCount,
    uniqueIps:   uniqueIps.size,
    blockedIps:  Object.keys(blockedIps).length,
    byType,
    byDomain
  });
});
app.get('/api/blocked', requireAuth, (req, res) => {
  res.json({ blocked: blockedIps });
});
app.get('/api/blocked/check/:ip', (req, res) => {
  const ip = req.params.ip;
  res.json({ blocked: !!blockedIps[ip], ip });
});
app.post('/api/blocked/:ip', requireAuth, (req, res) => {
  const ip = req.params.ip;
  blockedIps[ip] = { blockedAt: new Date().toISOString(), reason: req.body && req.body.reason || 'Manual block' };
  saveBlocked();
  console.log(`[BLOCK] IP ${ip} blocked`);
  res.json({ ok: true, ip, blockedAt: blockedIps[ip].blockedAt });
});
app.delete('/api/blocked/:ip', requireAuth, (req, res) => {
  const ip = req.params.ip;
  if (!blockedIps[ip]) return res.status(404).json({ error: 'IP not in blocked list' });
  delete blockedIps[ip];
  saveBlocked();
  console.log(`[UNBLOCK] IP ${ip} unblocked`);
  res.json({ ok: true, ip, message: 'IP unblocked successfully' });
});
app.listen(PORT, () => {
  console.log(`\n🛡  ShieldScan Backend v2.0 — http://localhost:${PORT}`);
  console.log(`\n  Dashboard password: ${DASHBOARD_PASS} (set SHIELDSCAN_PASS env to change)`);
  console.log(`\n  POST   /api/auth              — login (password: "${DASHBOARD_PASS}")`);
  console.log(`  POST   /api/threats           — receive violations from embed.js`);
  console.log(`  GET    /api/threats           — list threats (auth required)`);
  console.log(`  GET    /api/stats             — public stats`);
  console.log(`  GET    /api/blocked           — list blocked IPs (auth required)`);
  console.log(`  POST   /api/blocked/:ip       — block IP (auth required)`);
  console.log(`  DELETE /api/blocked/:ip       — unblock IP (auth required)`);
  console.log(`  GET    /api/blocked/check/:ip — check if IP is blocked (public)`);
  console.log(`\n`);
});
