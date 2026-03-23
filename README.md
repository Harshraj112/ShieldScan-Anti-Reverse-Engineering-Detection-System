# 🛡️ ShieldScan — Anti-Reverse-Engineering Detection System

**ShieldScan** detects browser DevTools, debuggers, automation bots, and prototype tampering in real time — surfacing likely inspection, tampering, and automation signals for your JavaScript application.

---

## 🔐 Important limitation

ShieldScan can **detect and respond to suspicious browser-side inspection attempts**, but it cannot make already-downloaded client-side code truly secret. If logic or secrets must remain private, move them server-side.

## 📁 Project Files

| File | Description |
|------|-------------|
| `src/antiDebug.js` | Core detection library source — `ShieldScan` + `AntiDebugEngine` |
| `dist/antiDebug.min.js` | Obfuscated/minified production build |
| `demo/index.html` | Live dashboard — real-time threat monitoring |
| `demo/normal-demo.html` | Demo site showing an aggressive response mode |
| `demo/embed-snippet.html` | Copy-paste embed guide with syntax highlighting |
| `demo/example-usage.html` | Minimal working example with `onDetected` callback |
| `server/backend-server.js` | Node.js Express server for cross-origin threat logging |

---

## 🚀 Quick Start

### Option 1: Using Free CDN (No download required)
```html
<script src="https://cdn.jsdelivr.net/gh/Harshraj112/ShieldScan-Anti-Reverse-Engineering-Detection-System@main/dist/antiDebug.min.js"></script>
<script>ShieldScan.protect();</script>
```

### Option 2: Self-hosted (Download `dist/antiDebug.min.js`)
```html
<script src="dist/antiDebug.min.js"></script>
<script>ShieldScan.protect();</script>
```

### With options (CDN example)
```html
<script src="https://cdn.jsdelivr.net/gh/Harshraj112/ShieldScan-Anti-Reverse-Engineering-Detection-System@main/dist/antiDebug.min.js"></script>
<script>
  ShieldScan.protect({
    action:        'warn',     // what to do on detection
    interval:      1000,       // scan every 1 second
    minConfidence: 40,         // only act if ≥40% confident
    report:        true,       // send to demo/index.html
    debuggerTrap:  false,      // set true to disrupt stepping
    onDetected: function(r) {
      console.log('[THREAT]', r.name, r.detail, r.url);
    }
  });
</script>
```

### Manual `reportThreat()` anywhere in your code
```js
// Call this yourself when you detect suspicious behaviour
reportThreat('Clipboard copy blocked');   // appears in the monitor instantly
reportThreat('Form tamper attempt', window.location.href);
```

---

## 🔍 Detection Checks (10 total)

| # | Check | What It Catches |
|---|-------|-----------------|
| 1 | **DevTools Timing** | `console.log` avg >3ms = panel open |
| 2 | **DevTools Object Trap** | Element `id` getter fires when inspector reads it |
| 3 | **Window Size Delta** | `outerWidth` vs `innerWidth` gap >100px |
| 4 | **Debugger Statement** | Wall-clock pause >100ms around `debugger` |
| 5 | **Prototype Tampering** | `console.log.toString()` not `[native code]` |
| 6 | **FP.toString Override** | `Function.prototype.toString` was replaced |
| 7 | **Browser Automation** | `navigator.webdriver`, Selenium/Puppeteer globals |
| 8 | **Headless Browser** | PhantomJS, Cypress, missing plugins |
| 9 | **Timing Anomaly** | 100k-iteration loop suspiciously slow |
| 10 | **iframe Sandbox** | `window !== top`, or analysis platforms like CodePen |

---

## ⚙️ Configuration Options

```js
ShieldScan.protect({                    // OR: new AntiDebugEngine({...}).start()
  // Detection
  interval:      1000,    // ms between scans
  minConfidence: 40,      // 0–100 threshold to trigger action
  checks:        ['all'], // or e.g. ['devtools-timing', 'webdriver']
  // Response
  action:        'warn',  // see Actions table below
  redirectUrl:   '',      // used when action = 'redirect'
  silent:        false,   // true = detect but do nothing
  // Disruption
  debuggerTrap:  false,   // continuous debugger loop
  debuggerMs:    200,     // trap fire interval ms
  // Reporting
  report:        true,    // broadcast to demo/index.html
  reportUrl:     '',      // POST endpoint (cross-origin)
  reportToken:   '',      // shared secret for your backend (optional)
  channelName:   'shieldscan-monitor',
  // Callback
  onDetected: function(result) {
    // result: { name, status, confidence, detail, url, timestamp }
  }
})
```

### Response Actions

| Action | Behaviour |
|--------|-----------|
| `warn` | `console.warn` once per check (default) |
| `silent` | Detect only — no user-visible effect |
| `redirect` | Navigate to `redirectUrl` |
| `corrupt` | Silently break `Math.random` and `parseInt` |
| `freeze` | Disable pointer events + dark overlay |
| `nuke` | ⛔ Remove all `<script>` tags + show fullscreen warning |

---

## 📊 Monitor Dashboard Features

- **Live sidebar** — 10 check badges (SAFE / THREAT), confidence bars, detail text
- **Metric cards** — Total Scans, Threats Found, Avg Confidence, Uptime
- **Live event log** — Logs local scan output continuously and deduplicates remote replay/storage events
- **⚠ VIEW THREATS button** — Opens a modal listing every detected threat with exact timestamp, check name, and confidence
- **Controls** — START / STOP / RUN ONCE / CLEAR LOG

---

## 🧠 How event deduplication works

Local scans are shown continuously so you can watch detector output over time. Remote events received through `BroadcastChannel` or `localStorage` are deduplicated by `eventId`, so historical replays and storage updates do not inflate the threat ledger.

The **Threats modal** keeps a permanent ledger of unique DETECTED events until you clear it.

---

## 🌐 Embed in Any Website — Cross-Site Monitoring

**Full embed guide:** open `demo/embed-snippet.html` in your browser.

### How it works

```
Your Website (Tab A)        Your Other Site (Tab B)
  antiDebug.js                 antiDebug.js
       │                            │
       └────── BroadcastChannel 'shieldscan-monitor' ─────┐
                                                           ▼
                                              demo/index.html (Tab C)
                                              Dashboard shows all threats
                                              with URL + type + timestamp
```

### 5-Line Embed Snippet

Paste before `</body>` in any page:

```html
<script src="dist/antiDebug.min.js"></script>
<script>
  new AntiDebugEngine({
    action:        'warn',   // or 'nuke', 'freeze', 'redirect'
    interval:      1000,     // scan every 1 second
    minConfidence: 40,       // alert threshold
    report:        true,     // broadcast to the monitor ← new
  }).start();
</script>
```

### What happens

1. Visitor opens DevTools on your site
2. `antiDebug.js` detects it (within 1 second)
3. Threat is **broadcast** via `BroadcastChannel('shieldscan-monitor')` AND saved to `localStorage['shieldscan_events']`
4. `demo/index.html` (open in any tab) receives it **instantly** and shows:
   - `[REMOTE]` badge in the live log
   - Source URL (`FROM: https://your-site.com/page`)
   - Check name, confidence %, detail, timestamp
   - **VIEW THREATS** modal updated with full incident
   - **Connected Sites** chip in topbar shows how many sites are reporting

### Transport Layers

| Method | When used | Range |
|--------|-----------|-------|
| `BroadcastChannel` | Default | Same browser, any tab |
| `localStorage` events | Fallback | Same origin, cross-tab |
| `sendBeacon` | When `reportUrl` set | Cross-origin, sends JSON to your server |

### Cross-Origin / Server Mode

To collect threats from a different domain, set up a simple POST endpoint and configure:

```js
new AntiDebugEngine({
  report:    true,
  reportUrl: 'https://your-server.com/shieldscan/events',
  reportToken: 'shared-secret-for-your-server',
}).start();
```

The payload POSTed is `application/json`:

```json
{
  "type":       "shieldscan-event",
  "eventId":    "https://your-site.com::https://your-site.com/page::DevTools Timing::DETECTED::2025-03-23T08:30:01Z::85",
  "name":       "DevTools Timing",
  "status":     "DETECTED",
  "confidence": 85,
  "detail":     "console.log avg 6.2ms — panel open",
  "url":        "https://your-site.com/page",
  "timestamp":  "2025-03-23T08:30:01Z",
  "origin":     "https://your-site.com",
  "token":      "shared-secret-for-your-server"
}
```

---

## 🛡️ Code Obfuscation (Recommended)

Protect your code BEFORE serving it. Use these tools with `antidebug.js`:

### Option 1 — javascript-obfuscator (full obfuscation)
```bash
npm install -g javascript-obfuscator
javascript-obfuscator src/antiDebug.js \
  --output dist/antiDebug.obfuscated.js \
  --compact true \
  --string-array true \
  --rotate-string-array true \
  --string-array-encoding base64 \
  --self-defending true \
  --control-flow-flattening true
```

### Option 2 — UglifyJS (minification only, faster)
```bash
npm install -g uglify-js
uglifyjs src/antiDebug.js -o dist/antiDebug.min.js \
  --compress --mangle
```

### Workflow
```
src/antiDebug.js (source)
      │
      ▼ javascript-obfuscator / uglifyjs
      │
dist/antiDebug.min.js  ← serve this file
```

Then change your embed tag to:
```html
<script src="dist/antiDebug.min.js"></script>
```

---

## 🖥️ Backend Server (Optional)

For cross-origin reporting, run the included Express server:

```bash
cd server
npm install express cors
node backend-server.js
# → Listening on http://localhost:3000
```

Then configure:
```js
ShieldScan.protect({
  reportUrl: 'http://localhost:3000/api/threats',
  reportToken: 'shared-secret'
});
```

API endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/threats` | Receive a threat (called by `sendBeacon`) |
| `GET` | `/api/threats` | List all threats (`?limit=N&url=...`) |
| `GET` | `/api/stats` | Count by type and domain |
| `DELETE` | `/api/threats` | Clear the log |

---

## 🌐 Browser Compatibility

| Browser | Support |
|---------|---------|
| Chrome / Brave | ✅ Full |
| Firefox | ✅ Full |
| Safari | ✅ Full |
| Edge | ✅ Full |

> No npm, no build step, no server required.

---

## 📄 License

MIT — free to use, modify, and embed in commercial projects.
