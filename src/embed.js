
(function () {
  'use strict';
  var _script = document.currentScript ||
    (function () {
      var s = document.getElementsByTagName('script');
      return s[s.length - 1];
    })();
  var CFG = {
    reportUrl:  (_script && _script.getAttribute('data-report-url'))  || '',
    token:      (_script && _script.getAttribute('data-token'))        || '',
    unlockKey:  (_script && _script.getAttribute('data-unlock-key'))   || '',
    action:     (_script && _script.getAttribute('data-action'))       || 'freeze',
    threshold:  parseInt((_script && _script.getAttribute('data-threshold')) || '3', 10),
    interval:   parseInt((_script && _script.getAttribute('data-interval'))  || '2000', 10)
  };
  var _clientIp       = null;   
  var _ipFetching     = false;
  var _sessionKey     = 'ss_vc_' + (CFG.token || 'default');
  var _seenEvents     = {};     
  var _blocked        = false;
  var _scanTimer      = null;
  var _warnedChecks   = {};
  function _getCount() {
    try { return parseInt(sessionStorage.getItem(_sessionKey) || '0', 10); } catch(e) { return 0; }
  }
  function _incCount() {
    try { sessionStorage.setItem(_sessionKey, String(_getCount() + 1)); } catch(e) {}
  }
  function _fetchIp(cb) {
    if (_clientIp) { cb(_clientIp); return; }
    try {
      var cached = sessionStorage.getItem('ss_ip');
      if (cached) { _clientIp = cached; cb(_clientIp); return; }
    } catch(e) {}
    if (_ipFetching) { setTimeout(function() { _fetchIp(cb); }, 300); return; }
    _ipFetching = true;
    try {
      fetch('https://api.ipify.org?format=json')
        .then(function(r) { return r.json(); })
        .then(function(d) {
          _clientIp = d.ip || 'unknown';
          try { sessionStorage.setItem('ss_ip', _clientIp); } catch(e) {}
          _ipFetching = false;
          cb(_clientIp);
        })
        .catch(function() {
          _clientIp = 'unavailable';
          _ipFetching = false;
          cb(_clientIp);
        });
    } catch(e) {
      _clientIp = 'unavailable';
      _ipFetching = false;
      cb(_clientIp);
    }
  }
  function _buildPayload(violationType, ip, extra) {
    return {
      type:             'shieldscan-event',
      name:             violationType,
      status:           'DETECTED',
      confidence:       extra && extra.confidence != null ? extra.confidence : 90,
      detail:           extra && extra.detail ? extra.detail : violationType + ' detected',
      violationType:    violationType,
      ip:               ip || 'unknown',
      timestamp:        new Date().toISOString(),
      userAgent:        navigator.userAgent || 'unknown',
      screenResolution: screen.width + 'x' + screen.height,
      colorDepth:       screen.colorDepth || 0,
      referrer:         document.referrer || '',
      pageUrl:          window.location.href,
      url:              window.location.href,
      origin:           window.location.origin,
      website:          window.location.hostname,
      sessionId:        _getSessionId(),
      token:            CFG.token || undefined,
      eventId:          [window.location.origin, window.location.href, violationType, new Date().toISOString()].join('::')
    };
  }
  function _getSessionId() {
    try {
      var sid = sessionStorage.getItem('ss_sid');
      if (!sid) {
        sid = Math.random().toString(36).slice(2) + Date.now().toString(36);
        sessionStorage.setItem('ss_sid', sid);
      }
      return sid;
    } catch(e) { return 'unknown'; }
  }
  function _sendReport(payload) {
    if (!CFG.reportUrl) return;
    try {
      fetch(CFG.reportUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        keepalive: true
      }).catch(function() {});
    } catch(e) {}
    try {
      var bc = new BroadcastChannel('shieldscan-monitor');
      bc.postMessage(payload);
      bc.close();
    } catch(e) {}
    try {
      var KEY = 'shieldscan_events';
      var arr = JSON.parse(localStorage.getItem(KEY) || '[]');
      arr.push(payload);
      if (arr.length > 200) arr.splice(0, arr.length - 200);
      localStorage.setItem(KEY, JSON.stringify(arr));
    } catch(e) {}
  }
  function _showBlockOverlay() {
    if (_blocked) return;
    _blocked = true;
    _stopPeriodicScan();
    var overlay = document.createElement('div');
    overlay.id = '__ss_block_overlay__';
    overlay.style.cssText = [
      'position:fixed','inset:0','z-index:2147483647',
      'background:rgba(5,8,15,0.97)',
      'display:flex','flex-direction:column',
      'align-items:center','justify-content:center',
      'font-family:system-ui,sans-serif',
      'color:#c9d1d9','text-align:center','padding:40px'
    ].join(';');
    var iconBox = document.createElement('div');
    iconBox.style.cssText = 'font-size:64px;margin-bottom:24px;animation:ss_spin 4s linear infinite';
    iconBox.textContent = '🛡';
    var title = document.createElement('h1');
    title.style.cssText = 'font-size:28px;font-weight:700;color:#ff4444;margin-bottom:12px;letter-spacing:2px';
    title.textContent = 'ACCESS BLOCKED';
    var sub = document.createElement('p');
    sub.style.cssText = 'font-size:15px;color:#6e7681;margin-bottom:32px;max-width:440px;line-height:1.6';
    sub.textContent = 'Suspicious activity detected on this page. Your IP address has been flagged and blocked. Content is protected under intellectual property rights. Contact the site administrator to request access.';
    var style = document.createElement('style');
    style.textContent = '@keyframes ss_spin{0%{transform:rotate(0deg) scale(1)}50%{transform:rotate(180deg) scale(1.1)}100%{transform:rotate(360deg) scale(1)}}';
    overlay.appendChild(style);
    overlay.appendChild(iconBox);
    overlay.appendChild(title);
    overlay.appendChild(sub);
    document.documentElement.appendChild(overlay);
  }
  function _showWarningToast() {
    var id = '__ss_warning_toast__';
    if (document.getElementById(id)) return;
    var toast = document.createElement('div');
    toast.id = id;
    toast.style.cssText = [
      'position:fixed', 'bottom:24px', 'right:24px', 'z-index:2147483647',
      'background:rgba(17,24,39,0.95)', 'backdrop-filter:blur(10px)',
      'border:1px solid rgba(239,68,68,0.3)', 'border-left:4px solid #ef4444',
      'border-radius:8px', 'padding:16px 20px', 'max-width:340px',
      'box-shadow:0 10px 40px rgba(0,0,0,0.5), 0 0 20px rgba(239,68,68,0.2)',
      'font-family:system-ui,sans-serif', 'color:#f9fafb',
      'transform:translateX(120%)', 'transition:transform 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
      'display:flex', 'flex-direction:column', 'gap:6px'
    ].join(';');
    var title = document.createElement('div');
    title.style.cssText = 'font-size:14px;font-weight:700;color:#ef4444;letter-spacing:0.5px;display:flex;align-items:center;gap:8px';
    title.innerHTML = '<span style="font-size:16px">⚠️</span> Security Warning';
    var msg = document.createElement('div');
    msg.style.cssText = 'font-size:13px;color:#d1d5db;line-height:1.5';
    msg.textContent = 'This is a prototype. We cannot disclose our codebase. If you do this intentionally, your account will be blocked.';
    toast.appendChild(title);
    toast.appendChild(msg);
    if (document.body) {
      document.body.appendChild(toast);
    } else {
      document.documentElement.appendChild(toast);
    }
    setTimeout(function() { toast.style.transform = 'translateX(0)'; }, 50);
    setTimeout(function() {
      toast.style.transform = 'translateX(120%)';
      setTimeout(function() { toast.remove(); }, 400);
    }, 6000);
  }
  function _applyAction(violationType, extra) {
    var isUser = extra && extra.isUserAction;
    switch (CFG.action) {
      case 'nuke':
        if (!_blocked && isUser) {
          _blocked = true;
          _stopPeriodicScan();
          try { Array.from(document.querySelectorAll('script')).forEach(function(s){ s.remove(); }); } catch(e) {}
          if (document.head) document.head.innerHTML = '';
          if (document.body) document.body.innerHTML = '';
        }
        break;
      case 'redirect':
        if (isUser) {
          var redirectTo = (_script && _script.getAttribute('data-redirect-url')) || '/';
          window.location.href = redirectTo;
        }
        break;
      case 'freeze':
        if (!_blocked && isUser) {
          _blocked = true;
          _stopPeriodicScan();
          document.body.style.pointerEvents = 'none';
          document.body.style.userSelect = 'none';
          var mask = document.createElement('div');
          mask.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:2147483647;cursor:not-allowed';
          document.body.appendChild(mask);
        }
        break;
      case 'warn':
      default:
        if (isUser && !_warnedChecks[violationType]) {
          _warnedChecks[violationType] = true;
          console.warn('[ShieldScan] Violation:', violationType);
          _showWarningToast();
        }
        break;
    }
  }
  function _handleViolation(violationType, extra) {
    _checkServerBlocked();
    _fetchIp(function(ip) {
      var payload = _buildPayload(violationType, ip, extra);
      if (extra && extra.isUserAction) {
        _incCount();
      }
      var count = _getCount();
      if (count >= CFG.threshold) {
        payload.triggerBlock = true;
        _sendReport(payload);
        _showBlockOverlay();
      } else {
        _sendReport(payload);
        _applyAction(violationType, extra);
      }
    });
  }
  function _checkServerBlocked() {
    if (!CFG.reportUrl || _blocked) return;
    try {
      var baseUrl = CFG.reportUrl.replace(/\/api\/threats.*/, '');
      _fetchIp(function(ip) {
        if (ip === 'unknown' || ip === 'unavailable') return;
        fetch(baseUrl + '/api/blocked/check/' + encodeURIComponent(ip))
          .then(function(r) { return r.json(); })
          .then(function(d) {
            if (d && d.blocked) { _showBlockOverlay(); }
          })
          .catch(function() {});
      });
    } catch(e) {}
  }
  function _dedup(key, fn) {
    var now = Date.now();
    if (_seenEvents[key] && (now - _seenEvents[key]) < 1000) return;
    _seenEvents[key] = now;
    fn();
  }
  document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    _dedup('rightclick', function() {
      _handleViolation('Right-Click Attempt', {
        confidence: 80,
        isUserAction: true,
        detail: 'Right-click context menu opened on ' + window.location.href
      });
    });
    return false;
  }, true);
  document.addEventListener('keydown', function(e) {
    var key = e.key || '';
    var ctrl = e.ctrlKey || e.metaKey;
    var shift = e.shiftKey;
    if (key === 'F12') {
      e.preventDefault();
      _dedup('f12', function() {
        _handleViolation('F12 DevTools', {
          confidence: 95,
          isUserAction: true,
          detail: 'F12 key pressed — DevTools open attempt'
        });
      });
      return false;
    }
    if (ctrl && shift && (key === 'I' || key === 'i')) {
      e.preventDefault();
      _dedup('ctrlshifti', function() {
        _handleViolation('DevTools Inspect', {
          confidence: 95,
          isUserAction: true,
          detail: 'Ctrl+Shift+I pressed — DevTools inspect attempt'
        });
      });
      return false;
    }
    if (ctrl && shift && (key === 'J' || key === 'j')) {
      e.preventDefault();
      _dedup('ctrlshiftj', function() {
        _handleViolation('DevTools Console', {
          confidence: 95,
          isUserAction: true,
          detail: 'Ctrl+Shift+J pressed — DevTools console attempt'
        });
      });
      return false;
    }
    if (ctrl && shift && (key === 'C' || key === 'c')) {
      e.preventDefault();
      _dedup('ctrlshiftc', function() {
        _handleViolation('DevTools Element Picker', {
          confidence: 90,
          isUserAction: true,
          detail: 'Ctrl+Shift+C pressed — element inspector attempt'
        });
      });
      return false;
    }
    if (ctrl && !shift && (key === 'U' || key === 'u')) {
      e.preventDefault();
      _dedup('ctrlu', function() {
        _handleViolation('View Source Attempt', {
          confidence: 95,
          isUserAction: true,
          detail: 'Ctrl+U pressed — view-source attempt blocked'
        });
      });
      return false;
    }
    if (ctrl && !shift && (key === 'S' || key === 's')) {
      e.preventDefault();
      _dedup('ctrls', function() {
        _handleViolation('Save Page Attempt', {
          confidence: 70,
          detail: 'Ctrl+S pressed — page save attempt blocked'
        });
      });
      return false;
    }
    if (ctrl && !shift && (key === 'P' || key === 'p')) {
      e.preventDefault();
      _dedup('ctrlp', function() {
        _handleViolation('Print Attempt', {
          confidence: 60,
          detail: 'Ctrl+P pressed — print/screenshot attempt blocked'
        });
      });
      return false;
    }
  }, true);
  function _scanHeadless() {
    if (_blocked) return;
    var isHeadless = false;
    var reason = '';
    if (navigator.webdriver) {
      isHeadless = true;
      reason = 'navigator.webdriver evaluates to true';
    } else if (/HeadlessChrome/i.test(navigator.userAgent)) {
      isHeadless = true;
      reason = 'HeadlessChrome explicit in User-Agent';
    } else if (
      window.callPhantom || 
      window._phantom ||
      window.__nightmare ||
      window.document.__selenium_unwrapped ||
      window.document.__webdriver_evaluate ||
      window.document.__driver_evaluate ||
      window.__puppeteer_evaluation_script__
    ) {
      isHeadless = true;
      reason = 'Automation framework window signatures detected (Puppeteer/Selenium/PhantomJS)';
    } else if (navigator.languages === '' && navigator.plugins.length === 0) {
      isHeadless = true;
      reason = 'Zero plugins and empty languages array (Common basic Headless signal)';
    }
    if (isHeadless) {
      _dedup('headless', function() {
        _handleViolation('Crawler/Bot Detected', {
          confidence: 99,
          detail: reason
        });
      });
    }
  }
  function _scanDevTools() {
    if (_blocked) return;
    _scanHeadless();
    var wDelta = Math.abs((window.outerWidth  || 0) - (window.innerWidth  || 0));
    var hDelta = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0));
    if (Math.max(wDelta, hDelta) > 160) {
      _dedup('wsize', function() {
        _handleViolation('DevTools Panel Open', {
          confidence: Math.min(100, Math.round(Math.max(wDelta, hDelta) / 2.5)),
          detail: 'Window/viewport delta ' + wDelta + 'px × ' + hDelta + 'px — docked panel detected'
        });
      });
    }
    var t0 = Date.now();
    try {
      console.log && console.log('%c ', 'font-size:1px;color:transparent;');
    } catch(e) {}
    var dt = Date.now() - t0;
    if (dt > 100) {
      _dedup('ctiming', function() {
        _handleViolation('DevTools Timing', {
          confidence: Math.min(100, 40 + Math.round(dt)),
          detail: 'console.log avg ' + dt + 'ms — panel open (threshold: 100ms)'
        });
      });
    }
    try {
      var d0 = Date.now();
      (function() { debugger; })();
      var dd = Date.now() - d0;
      if (dd > 100) {
        _dedup('dbtiming', function() {
          _handleViolation('Debugger Pause Detected', {
            confidence: Math.min(100, Math.round(dd / 10)),
            detail: 'Debugger statement paused for ' + dd + 'ms — step-through detected'
          });
        });
      }
    } catch(e) {}
  }
  function _startPeriodicScan() {
    if (_scanTimer) return;
    _scanTimer = setInterval(_scanDevTools, CFG.interval);
  }
  function _stopPeriodicScan() {
    if (_scanTimer) { clearInterval(_scanTimer); _scanTimer = null; }
  }
  function _init() {
    setTimeout(_checkServerBlocked, 2000);
    if (_getCount() >= CFG.threshold) {
      _showBlockOverlay();
      return;
    }
    _startPeriodicScan();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _init);
  } else {
    _init();
  }
})();
