/**
 * ShieldScan AntiDebugEngine — Anti-Reverse-Engineering Detection Library
 * Version: 1.1.0
 * Usage: <script src="antidebug.js"></script>
 *        <script>ShieldScan.protect();</script>
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const exports = factory();
    module.exports = exports.AntiDebugEngine;
    module.exports.ShieldScan = exports.ShieldScan;
    module.exports.reportThreat = exports.reportThreat;
  } else {
    const exports = factory();
    root['A' + 'ntiD' + 'ebugE' + 'ngine'] = exports.AntiDebugEngine;
    root['ShieldScan'] = exports.ShieldScan;
    root['reportThreat'] = exports.reportThreat;
  }
}(typeof window !== 'undefined' ? window : this, function () {

  /* ── internal helpers ─────────────────────────────────────────────── */
  const _ts = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
  const _iso = () => new Date().toISOString();
  const _noop = () => {};
  const _safeCall = (fn, fallback = null) => { try { return fn(); } catch (e) { return fallback; } };

  // Slightly obfuscated keyword fragments
  const _kWD  = 'web' + 'dri' + 'ver';
  const _kCL  = 'con' + 'sole';
  const _kPH  = 'ph' + 'antom';
  const _kCDP = '__cy' + 'dra';    // Cypress
  const _kSL  = 'call' + 'Phanto' + 'm';

  /* ── result builder ───────────────────────────────────────────────── */
  function _result(name, status, confidence, detail) {
    return {
      name,
      status,
      confidence,
      detail,
      url: (typeof window !== 'undefined' && window.location ? window.location.href : 'unknown'),
      timestamp: _iso()
    };
  }

  /* ════════════════════════════════════════════════════════════════════
     DETECTION CHECKS
  ════════════════════════════════════════════════════════════════════ */

  /**
   * Check 1 — DevTools Timing via console.log execution delta.
   * When DevTools is open, console.log takes significantly longer
   * because it renders the output to the console panel.
   */
  function _chkConsoleTiming() {
    return _safeCall(() => {
      const RUNS = 5, THRESHOLD = 3;
      let totalDelta = 0;
      for (let i = 0; i < RUNS; i++) {
        const t0 = Date.now();
        window[_kCL]['l' + 'og']('%c ', 'font-size:1px;color:transparent');
        totalDelta += Date.now() - t0;
      }
      const avg = totalDelta / RUNS;
      const detected = avg > THRESHOLD;
      return _result(
        'DevTools Timing',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? Math.min(100, 40 + Math.round(avg * 5)) : 5,
        detected
          ? `console.log avg ${avg.toFixed(1)}ms — panel open (threshold: ${THRESHOLD}ms)`
          : `console.log avg ${avg.toFixed(1)}ms — below ${THRESHOLD}ms threshold`
      );
    }, _result('DevTools Timing', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 2 — DevTools Object Getter Trap.
   * A custom object with a getter property triggers when Chrome DevTools
   * formats the object for display (e.g. hover-inspect or auto-expand).
   */
  function _chkGetterTrap() {
    return _safeCall(() => {
      let detected = false;
      const el = document.createElement('div');
      Object.defineProperty(el, 'id', {
        get: function() { detected = true; return 'devtools-trap'; },
        configurable: true
      });
      window[_kCL]['l' + 'og'](el);
      if (!detected) {
        const probe = document.createElement('div');
        probe.style.cssText = 'position:absolute;top:-9999px;width:1px;height:1px;opacity:0';
        document.documentElement.appendChild(probe);
        const before = probe.clientWidth;
        window[_kCL]['l' + 'og'](probe);
        detected = probe.id === 'devtools-trap' || before !== probe.clientWidth;
        document.documentElement.removeChild(probe);
      }
      return _result(
        'DevTools Object Trap',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? 88 : 5,
        detected
          ? 'Element id getter triggered — DevTools inspector active'
          : 'Element trap not triggered'
      );
    }, _result('DevTools Object Trap', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 3 — Window Size Delta.
   * When DevTools is docked (side panel), outerWidth shrinks relative
   * to innerWidth. A significant delta strongly implies an open panel.
   */
  function _chkWindowSize() {
    return _safeCall(() => {
      const THRESHOLD = 100;
      const wDelta = Math.abs((window.outerWidth  || 0) - (window.innerWidth  || 0));
      const hDelta = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0));
      const maxDelta = Math.max(wDelta, hDelta);
      const detected = maxDelta > THRESHOLD;
      return _result(
        'Window Size Delta',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? Math.min(100, Math.round(maxDelta / 2)) : 10,
        `outer vs inner delta: ${wDelta}px wide × ${hDelta}px tall`
          + (detected ? ' — docked panel detected' : ' — no panel')
      );
    }, _result('Window Size Delta', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 4 — Debugger Statement Timing.
   * When a debugger breakpoint is hit, execution pauses, causing the
   * wall-clock time around a `debugger` statement to spike dramatically.
   */
  function _chkDebuggerTiming() {
    return _safeCall(() => {
      const THRESHOLD = 100;
      const t0 = Date.now();
      // eslint-disable-next-line no-debugger
      (function () { debugger; })();
      const delta = Date.now() - t0;
      const detected = delta > THRESHOLD;
      return _result(
        'Debugger Statement',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? Math.min(100, Math.round(delta / 10)) : 5,
        `debugger statement delta: ${delta}ms`
          + (detected ? ' — execution was paused' : ' — no pause detected')
      );
    }, _result('Debugger Statement', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 5 — Prototype Tampering (console.log).
   * Hook-based tools (e.g. spy libraries) replace native functions.
   * Native functions produce a specific toString() signature.
   */
  function _chkPrototypeTampering() {
    return _safeCall(() => {
      const fnStr = Function.prototype.toString;
      const clog  = window[_kCL] && window[_kCL]['l' + 'og'];
      if (!clog) return _result('Prototype Tampering', 'UNKNOWN', 0, 'console.log not found');
      const sig = fnStr.call(clog);
      // Native code always contains "native code" in the string
      const isNative = sig.indexOf('nat' + 'ive') !== -1 && sig.indexOf('co' + 'de') !== -1;
      const detected = !isNative;
      return _result(
        'Prototype Tampering',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? 90 : 0,
        detected
          ? `console.log.toString() signature modified: "${sig.slice(0, 80)}"`
          : 'console.log native signature intact'
      );
    }, _result('Prototype Tampering', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 6 — Function.prototype.toString Override.
   * If Function.prototype.toString itself was replaced, the [native code]
   * trick to detect tampering is defeated; we detect this meta-tampering.
   */
  function _chkFPToStringOverride() {
    return _safeCall(() => {
      const nativeToStr = Object.prototype.toString;
      const fpToStr     = Function.prototype.toString;
      // A native Function.prototype.toString reports as a function AND
      // its own .toString() (via Object's implementation) should return [object Function]
      const typeCheck   = nativeToStr.call(fpToStr);
      const isFunction  = typeCheck === '[object Function]' || typeCheck === '[object Function]';
      // Additionally, call it on itself — native returns "function toString() { [native code] }"
      const selfSig     = _safeCall(() => fpToStr.call(fpToStr), '');
      const isSelfNative = selfSig.indexOf('nat' + 'ive') !== -1;
      const detected = !isFunction || !isSelfNative;
      return _result(
        'FP.toString Override',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? 95 : 0,
        detected
          ? `Function.prototype.toString may be overridden. type="${typeCheck}", native=${isSelfNative}`
          : 'Function.prototype.toString appears intact'
      );
    }, _result('FP.toString Override', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 7 — Browser Automation (navigator.webdriver).
   * Selenium, Puppeteer (older), Playwright, and similar tools set
   * navigator.webdriver = true. This is the canonical automation flag.
   */
  function _chkWebDriver() {
    return _safeCall(() => {
      const wd = navigator[_kWD];
      const detected = wd === true;
      // Additional checks: __driver_evaluate, __webdriver_script_fn
      const extras = ['__dr' + 'iver_ev' + 'aluate', '__web' + 'driver_sc' + 'ript_fn',
        '__fxd' + 'river_u' + 'wps', 'calld' + 'river', '_Sel' + 'enium_ide_re' + 'cord'];
      const extraHit = extras.some(k => (k in window) || (k in document));
      const conf = (detected ? 70 : 0) + (extraHit ? 25 : 0);
      return _result(
        'Browser Automation',
        (detected || extraHit) ? 'DETECTED' : 'CLEAN',
        conf,
        `navigator.webdriver=${wd}, extra automation props=${extraHit}`
      );
    }, _result('Browser Automation', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 8 — Headless Browser Detection.
   * Headless Chrome / Puppeteer / PhantomJS exhibit specific anomalies:
   * missing plugins array, zero/unusual screen dimensions, missing languages.
   */
  function _chkHeadless() {
    return _safeCall(() => {
      const flags = [];
      // 1. Plugin count (headless Chrome has 0 plugins)
      if (navigator.plugins && navigator.plugins.length === 0) flags.push('no plugins');
      // 2. Missing or empty language list
      if (!navigator.languages || navigator.languages.length === 0) flags.push('no languages');
      // 3. PhantomJS global
      if (window[_kPH + 'js'] || window['_' + _kPH] || navigator.userAgent.toLowerCase().indexOf(_kPH) !== -1)
        flags.push('PhantomJS detected');
      // 4. Screen dimensions anomalies (headless default is often 800×600 or 0×0)
      if (screen.width === 0 || screen.height === 0) flags.push('zero screen size');
      if (screen.width === 800 && screen.height === 600) flags.push('default headless resolution');
      // 5. Chrome-specific headless prop
      if (navigator.userAgent.indexOf('Head' + 'lessChrome') !== -1) flags.push('HeadlessChrome UA');
      // 6. Cypress
      if (window[_kCDP]) flags.push('Cypress detected');
      // 7. callPhantom
      if (window[_kSL]) flags.push('callPhantom detected');
      const detected = flags.length > 0;
      return _result(
        'Headless Browser',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? Math.min(100, flags.length * 30) : 5,
        detected ? `Indicators: ${flags.join(', ')}` : 'No headless indicators found'
      );
    }, _result('Headless Browser', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 9 — Timing Anomaly (Debugger Step Detection).
   * When code is being stepped through in a debugger, tight loops run
   * orders of magnitude slower than normal. We compare CPU loop speed
   * against a calibrated threshold.
   */
  function _chkTimingAnomaly() {
    return _safeCall(() => {
      const ITERS = 1e5;
      const THRESHOLD_MS = 50; // should complete in <50ms; stepping makes it orders slower
      const t0 = _ts();
      let x = 0;
      for (let i = 0; i < ITERS; i++) { x ^= i & 0xFF; }
      const delta = _ts() - t0;
      // Prevent dead-code elimination
      void x;
      const detected = delta > THRESHOLD_MS;
      return _result(
        'Timing Anomaly',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? Math.min(100, Math.round(delta * 2)) : 5,
        `${ITERS.toLocaleString()} iterations in ${delta.toFixed(2)}ms`
          + (detected ? ' — suspiciously slow (step-through?)' : ' — normal speed')
      );
    }, _result('Timing Anomaly', 'UNKNOWN', 0, 'Execution failed'));
  }

  /**
   * Check 10 — iframe Sandbox Detection.
   * Sandboxed iframes (common in online analysis platforms like jsbin,
   * codepen, or automated scanners) typically block popups, top-level
   * navigation, and pointer-lock. We fingerprint several of these.
   */
  function _chkIframeSandbox() {
    return _safeCall(() => {
      const flags = [];
      // 1. Definitive: page is embedded inside an iframe
      if (window !== window.top) flags.push('inside iframe');
      // 2. Analysis / sandboxed platforms detected from URL
      const analysisHosts = ['jsbin', 'cod' + 'epen', 'jsfiddle', 'plnkr', 'stackblitz'];
      const href = (window.location.href || '').toLowerCase();
      const hostMatch = analysisHosts.find(h => href.indexOf(h) !== -1);
      if (hostMatch) flags.push(`analysis platform: ${hostMatch}`);
      // NOTE: window.open probe removed — it opened a blank tab every scan (too invasive).
      // NOTE: document.referrer removed — normal navigation always sets referrer (false positive).
      const detected = flags.length > 0;
      return _result(
        'iframe Sandbox',
        detected ? 'DETECTED' : 'CLEAN',
        detected ? Math.min(100, flags.length * 50) : 0,
        detected ? `Sandbox indicators: ${flags.join(', ')}` : 'Not in an iframe or sandboxed platform'
      );
    }, _result('iframe Sandbox', 'UNKNOWN', 0, 'Execution failed'));
  }


  /* ════════════════════════════════════════════════════════════════════
     RESPONSE ACTIONS
  ════════════════════════════════════════════════════════════════════ */

  function _actionSilent(engine, result) {
    // Already logged to internal report — nothing more to do
    void result;
  }

  function _actionWarn(engine, result) {
    if (!engine._warnedChecks.has(result.name)) {
      console.warn('[AntiDebug] Threat detected:', result.name, '—', result.detail);
      engine._warnedChecks.add(result.name);
    }
  }

  function _actionRedirect(engine, result) {
    void result;
    if (engine.config.redirectUrl) {
      window.location.href = engine.config.redirectUrl;
    }
  }

  function _actionCorrupt(engine, result) {
    void result;
    if (engine._corrupted) return;
    engine._corrupted = true;
    // Return garbage from Math.random, silently breaking dependent logic
    const _orig = Math.random;
    Math.random = function () { return _orig() > 0.5 ? NaN : Infinity; };
    // Override parseInt to sometimes return wrong values
    const _parseOrig = window.parseInt;
    window.parseInt = function (v, r) { return _parseOrig(v, r) + (Math.floor(Date.now() % 3) === 0 ? 1 : 0); };
  }

  function _actionFreeze(engine, result) {
    void result;
    if (engine._frozen) return;
    engine._frozen = true;
    document.body.style.pointerEvents = 'none';
    document.body.style.userSelect    = 'none';
    const mask = document.createElement('div');
    mask.id = 'arde-freeze-mask';
    mask.style.cssText = [
      'position:fixed', 'inset:0', 'background:rgba(0,0,0,0.55)',
      'z-index:2147483647', 'cursor:not-allowed'
    ].join(';');
    document.body.appendChild(mask);
  }

  /**
   * NUKE action — removes all <script> tags and replaces the page with
   * a fullscreen security warning. Zero tolerance for inspection.
   */
  function _actionNuke(engine, result) {
    if (engine._nuked) return;
    engine._nuked = true;
    engine.stop();
    // Strip every script tag from the live DOM
    Array.from(document.querySelectorAll('script')).forEach(s => s.remove());
    const chk  = result ? result.name      : 'Unknown Check';
    const url  = result ? result.url       : window.location.href;
    const time = result ? result.timestamp : new Date().toISOString();
    document.body.innerHTML = [
      '<div id="arde-nuke" style="position:fixed;inset:0;z-index:2147483647;',
      'background:#0a0007;display:flex;flex-direction:column;align-items:center;',
      'justify-content:center;font-family:Courier New,monospace;text-align:center;',
      'padding:40px;box-sizing:border-box;',
      'background-image:repeating-linear-gradient(0deg,rgba(255,0,0,0.03) 0,rgba(255,0,0,0.03) 1px,transparent 1px,transparent 4px)">',
      '<div style="font-size:clamp(48px,10vw,96px);margin-bottom:16px">⛔</div>',
      '<h1 style="color:#ff2222;font-size:clamp(28px,5vw,56px);font-weight:900;',
      'letter-spacing:4px;text-transform:uppercase;margin:0 0 16px;',
      'text-shadow:0 0 40px rgba(255,34,34,0.8),0 0 80px rgba(255,34,34,0.4)">',
      'CODE REMOVED FOR SECURITY</h1>',
      '<p style="color:#ff6666;font-size:clamp(14px,2vw,20px);margin:0 0 32px;letter-spacing:2px">',
      'Unauthorized inspection detected — All protected source code has been purged.</p>',
      '<div style="background:rgba(255,0,0,0.08);border:1px solid rgba(255,34,34,0.3);',
      'border-radius:8px;padding:20px 32px;max-width:640px;width:100%;text-align:left">',
      '<div style="color:#ff4444;font-size:12px;letter-spacing:1px;margin-bottom:10px">INCIDENT REPORT</div>',
      '<div style="color:#cc3333;font-size:13px;line-height:2.2;word-break:break-all">',
      '<span style="color:#7a2020">TRIGGER&nbsp;&nbsp;:</span> ' + chk + '<br>',
      '<span style="color:#7a2020">URL&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:</span> ' + url + '<br>',
      '<span style="color:#7a2020">TIME&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:</span> ' + time + '<br>',
      '<span style="color:#7a2020">ACTION&nbsp;&nbsp;&nbsp;:</span> All &lt;script&gt; tags removed from DOM',
      '</div></div>',
      '<p style="color:#441111;font-size:11px;margin-top:32px;letter-spacing:2px">',
      'Protected by ShieldScan AntiDebugEngine v1.0.0</p>',
      '</div>',
      '<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0007;overflow:hidden}</style>'
    ].join('');
  }

  /* ════════════════════════════════════════════════════════════════════
     ANTIDEBUGENGINE CLASS
  ════════════════════════════════════════════════════════════════════ */

  const ALL_CHECKS = [
    _chkConsoleTiming,
    _chkGetterTrap,
    _chkWindowSize,
    _chkDebuggerTiming,
    _chkPrototypeTampering,
    _chkFPToStringOverride,
    _chkWebDriver,
    _chkHeadless,
    _chkTimingAnomaly,
    _chkIframeSandbox
  ];

  class AntiDebugEngine {
    /**
     * @param {Object} config
     * @param {number}   [config.interval=2000]       — Polling interval in ms
     * @param {Function} [config.onDetected]           — Callback on detection (result)
     * @param {boolean}  [config.silent=false]         — If true, suppress all side-effects
     * @param {string[]} [config.checks=['all']]       — Which checks to run (by name, or 'all')
     * @param {string}   [config.action='warn']        — 'silent'|'warn'|'redirect'|'corrupt'|'freeze'
     * @param {string}   [config.redirectUrl]          — URL for redirect action
     * @param {number}   [config.minConfidence=50]     — Minimum confidence to trigger action
     */
    constructor(config = {}) {
      this.config = Object.assign({
        interval:      2000,
        onDetected:    null,
        silent:        false,
        checks:        ['all'],
        action:        'warn',
        redirectUrl:   '',
        minConfidence: 50,
        // ── Cross-tab reporting ──
        report:      true,                    // broadcast threats to monitor.html
        channelName: 'shieldscan-monitor',   // BroadcastChannel name
        reportUrl:   ''                       // optional: POST endpoint (cross-origin)
      }, config);

      this._report       = [];
      this._timer        = null;
      this._running      = false;
      this._startTime    = null;
      this._warnedChecks = new Set();
      this._corrupted    = false;
      this._frozen       = false;
      this._nuked        = false;

      // Open BroadcastChannel for cross-tab reporting
      this._bc = null;
      if (this.config.report && typeof BroadcastChannel !== 'undefined') {
        try { this._bc = new BroadcastChannel(this.config.channelName); } catch(e) {}
      }
    }

    /* ── internal: broadcast a result to the monitor dashboard ────────── */
    _broadcast(r) {
      if (!this.config.report) return;
      const payload = {
        type:       'shieldscan-event',
        name:       r.name,
        status:     r.status,
        confidence: r.confidence,
        detail:     r.detail,
        url:        r.url,
        timestamp:  r.timestamp,
        origin:     (typeof window !== 'undefined' ? window.location.origin : 'unknown')
      };
      // 1. BroadcastChannel (real-time, same browser)
      if (this._bc) { try { this._bc.postMessage(payload); } catch(e) {} }
      // 2. localStorage (persistent, survives page changes)
      try {
        const KEY = 'shieldscan_events';
        const raw = localStorage.getItem(KEY);
        const arr = raw ? JSON.parse(raw) : [];
        arr.push(payload);
        if (arr.length > 200) arr.splice(0, arr.length - 200); // keep last 200
        localStorage.setItem(KEY, JSON.stringify(arr));
      } catch(e) {}
      // 3. navigator.sendBeacon (cross-origin POST, if reportUrl configured)
      if (this.config.reportUrl && typeof navigator !== 'undefined' && navigator.sendBeacon) {
        try {
          const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
          navigator.sendBeacon(this.config.reportUrl, blob);
        } catch(e) {}
      }
    }

    /* ── internal: select checks to run ──────────────────────────────── */
    _getChecks() {
      const { checks } = this.config;
      if (!checks || checks.includes('all')) return ALL_CHECKS;
      const nameMap = {
        'devtools-timing':     _chkConsoleTiming,
        'devtools-object':     _chkGetterTrap,
        'window-size':         _chkWindowSize,
        'debugger-timing':     _chkDebuggerTiming,
        'prototype-tampering': _chkPrototypeTampering,
        'fp-tostring':         _chkFPToStringOverride,
        'webdriver':           _chkWebDriver,
        'headless':            _chkHeadless,
        'timing-anomaly':      _chkTimingAnomaly,
        'iframe-sandbox':      _chkIframeSandbox
      };
      return checks.map(k => nameMap[k]).filter(Boolean);
    }

    /* ── internal: execute one scan cycle ────────────────────────────── */
    _scan() {
      const checks  = this._getChecks();
      const results = checks.map(fn => fn());

      results.forEach(r => {
        this._report.push(r);
        if (r.status === 'DETECTED' && r.confidence >= this.config.minConfidence) {
          this._triggerAction(r);
          this._broadcast(r);  // ← send to monitor dashboard
          if (typeof this.config.onDetected === 'function') {
            _safeCall(() => this.config.onDetected(r));
          }
        }
      });
      return results;
    }

    /* ── internal: fire configured response action ────────────────────── */
    _triggerAction(result) {
      if (this.config.silent) { _actionSilent(this, result); return; }
      switch (this.config.action) {
        case 'silent':   _actionSilent(this,  result); break;
        case 'redirect': _actionRedirect(this, result); break;
        case 'corrupt':  _actionCorrupt(this,  result); break;
        case 'freeze':   _actionFreeze(this,   result); break;
        case 'nuke':     _actionNuke(this,     result); break;
        case 'warn':
        default:         _actionWarn(this,     result); break;
      }
    }

    /* ── PUBLIC API ───────────────────────────────────────────────────── */

    /** Start periodic monitoring */
    start() {
      if (this._running) return;
      this._running   = true;
      this._startTime = Date.now();
      this._scan(); // run immediately
      this._timer = setInterval(() => this._scan(), this.config.interval);
    }

    /** Stop periodic monitoring */
    stop() {
      this._running = false;
      if (this._timer) { clearInterval(this._timer); this._timer = null; }
    }

    /** Run all checks once and return results array */
    runOnce() {
      return this._scan();
    }

    /**
     * Returns a full JSON report object.
     * @returns {{ generated: string, uptimeMs: number, totalChecks: number,
     *             threatsDetected: number, averageConfidence: number,
     *             events: Array }}
     */
    getReport() {
      const threats = this._report.filter(r => r.status === 'DETECTED');
      const avgConf = this._report.length
        ? Math.round(this._report.reduce((s, r) => s + r.confidence, 0) / this._report.length)
        : 0;
      return {
        generated:        _iso(),
        uptimeMs:         this._startTime ? Date.now() - this._startTime : 0,
        totalChecks:      this._report.length,
        threatsDetected:  threats.length,
        averageConfidence: avgConf,
        config:           { ...this.config, onDetected: this.config.onDetected ? '[Function]' : null },
        events:           [...this._report]
      };
    }
  }

  /* ════════════════════════════════════════════════════════════════════
     SIMPLE PUBLIC API  (available globally as window.ShieldScan)
  ════════════════════════════════════════════════════════════════════ */

  /**
   * reportThreat(type, url?)
   * ‒ Standalone helper: manually report any custom threat.
   *   Sends via BroadcastChannel + localStorage (same as engine detection).
   *
   * Example:
   *   reportThreat('Custom Trigger', window.location.href);
   */
  function reportThreat(type, url) {
    const payload = {
      type:       'shieldscan-event',
      name:       type || 'Manual Report',
      status:     'DETECTED',
      confidence: 100,
      detail:     `Manually reported: ${type}`,
      url:        url || (typeof window !== 'undefined' ? window.location.href : 'unknown'),
      timestamp:  _iso(),
      origin:     typeof window !== 'undefined' ? window.location.origin : 'unknown'
    };
    // BroadcastChannel
    try {
      const bc = new BroadcastChannel('shieldscan-monitor');
      bc.postMessage(payload);
      bc.close();
    } catch (e) {}
    // localStorage
    try {
      const KEY = 'shieldscan_events';
      const arr = JSON.parse(localStorage.getItem(KEY) || '[]');
      arr.push(payload);
      if (arr.length > 200) arr.splice(0, arr.length - 200);
      localStorage.setItem(KEY, JSON.stringify(arr));
    } catch (e) {}
  }

  /**
   * startDebuggerTrap(intervalMs = 100)
   * ‒ Execution Disruption Layer.
   *   Fires `debugger;` in a tight loop. When DevTools is open with
   *   "Pause on debugger statement" enabled, this continuously breaks
   *   execution, making stepping through code extremely tedious.
   *
   * @returns {Function} stopFn — call to stop the trap
   *
   * Example:
   *   const stop = ShieldScan.startDebuggerTrap(200);
   *   // later: stop();
   */
  function startDebuggerTrap(intervalMs) {
    const ms = typeof intervalMs === 'number' ? intervalMs : 100;
    // Obfuscated to survive static analysis — Function constructor evades
    // naive string-search for the `debugger` keyword.
    const trap = new Function('for(var i=0;i<3;i++){debugger;}');
    const id = setInterval(function () { _safeCall(trap); }, ms);
    return function stopTrap() { clearInterval(id); };
  }

  /**
   * ShieldScan.protect(config)
   * ‒ One-liner convenience factory. Starts monitoring immediately.
   *
   * Usage (drop-in, zero config):
   *   <script src="antidebug.js"></script>
   *   <script>ShieldScan.protect();</script>
   *
   * Full config:
   *   ShieldScan.protect({
   *     action:        'warn',      // 'warn'|'nuke'|'freeze'|'corrupt'|'redirect'|'silent'
   *     interval:      1000,        // scan every N ms
   *     minConfidence: 40,          // only act if ≥N% confident
   *     report:        true,        // broadcast to monitor.html
   *     reportUrl:     '',          // optional POST endpoint
   *     debuggerTrap:  false,       // enable continuous debugger loop
   *     debuggerMs:    200,         // trap interval ms
   *     onDetected: function(r) {}  // custom callback
   *   });
   */
  function protect(config) {
    config = config || {};
    const engine = new AntiDebugEngine({
      action:        config.action        || 'warn',
      interval:      config.interval      || 1000,
      minConfidence: config.minConfidence != null ? config.minConfidence : 40,
      report:        config.report        != null ? config.report        : true,
      reportUrl:     config.reportUrl     || '',
      silent:        config.silent        || false,
      onDetected:    config.onDetected    || null
    });
    engine.start();
    if (config.debuggerTrap) {
      engine._debuggerTrapStop = startDebuggerTrap(config.debuggerMs || 200);
    }
    return engine;
  }

  /* ── Global namespace ─────────────────────────────────────────────── */
  const ShieldScan = {
    protect,
    reportThreat,
    startDebuggerTrap,
    Engine: AntiDebugEngine
  };

  return { AntiDebugEngine, ShieldScan, reportThreat, startDebuggerTrap };
}));
