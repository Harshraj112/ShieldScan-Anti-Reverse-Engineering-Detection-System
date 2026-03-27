# ShieldScan v2.0
> Advanced Client-Side Intellectual Property Rights Protection System

ShieldScan is a lightweight JavaScript library and Node.js backend that protects websites from content scraping, reverse-engineering, and intellectual property theft.

It detects when visitors open DevTools, right-click, try to view source, or use browser automation, immediately reporting their IP and device info to a secure real-time dashboard. After repeated violations, the page is programmatically locked down until an administrator provides an unlock token.

## Repository Structure

- `src/embed.js` — The core protection script that website owners add to their pages.
- `dist/embed.min.js` — The obfuscated, production-ready version of the script.
- `server/` — Node.js / Express backend that receives threats and manages blocked IPs.
- `dashboard/` — Secure React dashboard for monitoring threats in real-time.
- `demo/` — Example HTML pages showing how to integrate the script.
- `build.js` — Build script that obfuscates the embed script.

---

## 1. Starting the Backend Server

The backend receives generic threat reports, stores them, and serves the dashboard API.

```bash
cd server
npm install
npm start
```

By default it listens on port `3000`.
To change the default dashboard password (`admin123`), set the `SHIELDSCAN_PASS` environment variable:
```bash
SHIELDSCAN_PASS="mySuperSecretPass" npm start
```

---

## 2. Starting the React Dashboard

The dashboard provides a real-time view of all attacks, unique IPs, and allows you to manually or automatically block malicious users.

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:5173` in your browser. Logs in with the password configured on your backend (default: `admin123`).

## 3. Protecting Your Website

To protect a website, just add the `embed.min.js` script just before the closing `</body>` tag on your HTML pages. 

Configure it using `data-` attributes:

```html
<script src="path/to/embed.min.js"
        data-report-url="http://your-server:3000/api/threats"
        data-token="my-website-name"
        data-action="freeze"
        data-threshold="3"
        data-unlock-key="secret-unlock-code">
</script>
```

### Configuration Options:

| Attribute | Default | Description |
|-----------|---------|-------------|
| `data-report-url` | `""` | The full URL to your backend `/api/threats` endpoint. |
| `data-token` | `""` | An identifier for your website (e.g., `store-frontend`). |
| `data-action` | `freeze` | What to do upon a single violation. Valid options are: `warn` (console only), `freeze` (blocks mouse clicks/selection with a transparent overlay), `redirect`, or `nuke` (completely blanks the DOM). |
| `data-threshold` | `3` | Number of violations from the same IP/session before the page triggers the hard **Block Overlay**. |
| `data-unlock-key` | `""` | The password required to dismiss the Block Overlay once triggered. |
| `data-redirect-url` | `/` | Where to send the user if `data-action="redirect"` is used. |

---

## Testing the System

1. Start both the backend and frontend using: `npm run start:all` (or start them independently).
2. Open the React Dashboard and log in.
3. Open `demo/example-usage.html` in your browser via `file://` or a local server.
4. On the demo page, Right-Click, Press F12, or press Ctrl+U.
5. Watch the threat instantly appear in the React Dashboard.
6. Trigger 3 violations to test the Hard Block overlay mechanism.

---

## Building the Obfuscated Script

If you make modifications to `src/embed.js`, rebuild the minified/obfuscated version by running:

```bash
node build.js
```

This uses `javascript-obfuscator` to scramble the code, making it incredibly difficult for attackers to read or disable the protection logic.
