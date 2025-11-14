// background.js - MV3 service worker with hover-check handler and host-only logging
// Integrates heuristics, proxy/direct checks, navigation interception, and CHECK_URL_HOVER message.

const SUSPICIOUS_TLDS = ['tk','ml','ga','cf','gq'];
let blocklist = [];
let enabled = true;
let allowlist = [];
let useCloudLookup = false;   // proxy
let useDirectLookup = false;  // direct API (insecure)
let directApiKey = '';        // stored in chrome.storage.local when user supplies it

const PROXY_CHECK_BASE = 'http://localhost:3000';
const PROXY_LOG_ENDPOINT = PROXY_CHECK_BASE + '/log';

// Hover cache
const HOVER_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const hoverCache = new Map(); // url -> { status, reason, ts }

// Simple logging helpers
function logSW(...args) { console.log('[Anti-Phish Guard SW]', ...args); }
function warnSW(...args) { console.warn('[Anti-Phish Guard SW]', ...args); }
function errorSW(...args) { console.error('[Anti-Phish Guard SW]', ...args); }

async function loadState() {
  logSW('loadState: start');
  try {
    if (!chrome || !chrome.storage || !chrome.storage.local || !chrome.storage.local.get) {
      warnSW('chrome.storage.local not available — using defaults');
      enabled = true;
      allowlist = [];
      useCloudLookup = false;
      useDirectLookup = false;
      directApiKey = '';
    } else {
      const s = await chrome.storage.local.get(['enabled','allowlist','useCloudLookup','useDirectLookup','directApiKey']);
      enabled = s.enabled !== undefined ? s.enabled : true;
      allowlist = s.allowlist || [];
      useCloudLookup = s.useCloudLookup || false;
      useDirectLookup = s.useDirectLookup || false;
      directApiKey = s.directApiKey || '';
      logSW('loadState: storage loaded', { enabled, allowlistLen: allowlist.length, useCloudLookup, useDirectLookup });
    }

    // load packaged blocklist if present
    try {
      const resp = await fetch(chrome.runtime.getURL('blocklist.json'));
      if (resp.ok) {
        blocklist = await resp.json();
        logSW('blocklist loaded, entries=', blocklist.length);
      } else {
        logSW('no packaged blocklist or fetch non-OK', resp.status);
        blocklist = [];
      }
    } catch (e) {
      warnSW('failed to load blocklist.json', e);
      blocklist = [];
    }
  } catch (e) {
    warnSW('loadState failed, applying defaults', e);
    enabled = true;
    allowlist = [];
    useCloudLookup = false;
    useDirectLookup = false;
    directApiKey = '';
    blocklist = [];
  } finally {
    logSW('loadState: finished');
  }
}

// heuristics: return reason string if suspicious, otherwise null
function runHeuristics(urlStr) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    if (!host) return null;
    if (urlStr.startsWith(chrome.runtime.getURL('warning.html'))) return null;
    if (allowlist.includes(host)) return null;
    if (blocklist.includes(host)) return 'Domain is on the local blocklist';
    if (host.includes('xn--')) return 'Punycode (possible homograph attack)';
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return 'IP address used as host';
    if (host.length > 24) return 'Unusually long hostname';
    const parts = host.split('.');
    const tld = parts[parts.length - 1];
    if (SUSPICIOUS_TLDS.includes(tld)) return `Suspicious TLD (.${tld})`;
    const brandTokens = ['paypal','google','apple','amazon','microsoft','facebook','netflix','bank'];
    for (const b of brandTokens) {
      if (host.includes(b) && !host.endsWith(b + '.com')) {
        return `Contains brand token "${b}" (possible impersonation)`;
      }
    }
  } catch (e) {
    warnSW('runHeuristics parse failed for', urlStr, e);
  }
  return null;
}

// Call local proxy check
async function checkWithProxy(url) {
  try {
    const encoded = encodeURIComponent(url);
    const resp = await fetch(`${PROXY_CHECK_BASE}/check?url=${encoded}`, { method: 'GET' });
    if (!resp.ok) {
      warnSW('Proxy lookup non-OK', resp.status);
      return null;
    }
    const json = await resp.json();
    if (json.safe === false) {
      return 'Matches proxy (Safe Browsing / feeds)';
    }
    return null;
  } catch (e) {
    warnSW('Proxy lookup error', e);
    return null;
  }
}

// Direct Safe Browsing (insecure when key stored client-side)
async function checkWithSafeBrowsingDirect(apiKey, url) {
  if (!apiKey) return null;
  const body = {
    client: { clientId: 'antiphish-guard', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'POTENTIALLY_HARMFUL_APPLICATION',
        'UNWANTED_SOFTWARE'
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  try {
    const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!resp.ok) {
      warnSW('Safe Browsing direct non-OK', resp.status);
      return null;
    }
    const json = await resp.json();
    if (json.matches && json.matches.length) {
      return 'Matches Google Safe Browsing (direct)';
    }
    return null;
  } catch (e) {
    warnSW('Safe Browsing direct error', e);
    return null;
  }
}

// Host-only logging to proxy (best-effort)
async function sendLogToProxyHostOnly(logObj) {
  try {
    const payload = {
      timestamp: logObj.timestamp,
      tabId: logObj.tabId,
      host: logObj.host,
      blocked: !!logObj.blocked,
      reason: logObj.reason || '',
      heuristicsOnly: !!logObj.heuristicsOnly,
      extra: logObj.extra || null
    };
    await fetch(PROXY_LOG_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    // ignore but log locally
    warnSW('sendLogToProxyHostOnly failed', e);
  }
}

// hover cache helpers
function getHoverCached(url) {
  const v = hoverCache.get(url);
  if (!v) return null;
  if (Date.now() - v.ts > HOVER_CACHE_TTL) { hoverCache.delete(url); return null; }
  return v;
}
function setHoverCached(url, status, reason) {
  hoverCache.set(url, { status, reason, ts: Date.now() });
}

// Message handler for hover checks
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== 'CHECK_URL_HOVER') return;
  (async () => {
    const url = msg.url;
    if (!url) { sendResponse({ status: 'unknown', reason: 'no url' }); return; }

    const cached = getHoverCached(url);
    if (cached) {
      sendResponse({ status: cached.status, reason: cached.reason, cached: true });
      return;
    }

    // Local heuristics first
    try {
      let reason = runHeuristics(url);
      if (reason) {
        setHoverCached(url, 'unsafe', reason);
        sendResponse({ status: 'unsafe', reason });
        return;
      }

      // Only call proxy on hover if cloud lookup is enabled (avoid network flood)
      if (useCloudLookup) {
        const cloudReason = await checkWithProxy(url);
        if (cloudReason) {
          setHoverCached(url, 'unsafe', cloudReason);
          sendResponse({ status: 'unsafe', reason: cloudReason });
          return;
        }
      }

      // Optionally direct lookup if enabled
      if (useDirectLookup && directApiKey) {
        const directReason = await checkWithSafeBrowsingDirect(directApiKey, url);
        if (directReason) {
          setHoverCached(url, 'unsafe', directReason);
          sendResponse({ status: 'unsafe', reason: directReason });
          return;
        }
      }

      // safe
      setHoverCached(url, 'safe', '');
      sendResponse({ status: 'safe' });
    } catch (e) {
      sendResponse({ status: 'unknown', reason: e && e.message ? e.message : String(e) });
    }
  })();
  return true; // indicates we'll call sendResponse asynchronously
});

// Navigation interception: run heuristics and proxy/direct checks, then redirect to warning page when needed
async function onBeforeNavigate(details) {
  try {
    if (details.frameId !== 0) return;
    if (!enabled) return;
    if (!details.url) return;
    if (details.url.startsWith(chrome.runtime.getURL('warning.html'))) return;

    logSW('onBeforeNavigate', details.url, 'tab=' + details.tabId);

    let reason = runHeuristics(details.url);

    if (!reason && useCloudLookup) {
      try {
        const cloudReason = await checkWithProxy(details.url);
        if (cloudReason) reason = cloudReason;
      } catch (e) {
        warnSW('cloud lookup failed', e);
      }
    }

    if (!reason && useDirectLookup) {
      try {
        const directReason = await checkWithSafeBrowsingDirect(directApiKey, details.url);
        if (directReason) reason = directReason;
      } catch (e) {
        warnSW('direct lookup failed', e);
      }
    }

    const blocked = !!reason;
    // host-only for logging
    let hostOnly = '<invalid-host>';
    try { hostOnly = new URL(details.url).hostname.toLowerCase(); } catch (e) {}
    // Log to SW console
    logSW('NAV HOST LOG', { ts: new Date().toISOString(), tabId: details.tabId, host: hostOnly, blocked, reason });

    // Best-effort: send host-only to proxy
    sendLogToProxyHostOnly({
      timestamp: new Date().toISOString(),
      tabId: details.tabId,
      host: hostOnly,
      blocked,
      reason,
      heuristicsOnly: !!reason && !useCloudLookup && !useDirectLookup,
      extra: { from: 'extension' }
    });

    if (reason) {
      const warningUrl = chrome.runtime.getURL('warning.html') +
        `?url=${encodeURIComponent(details.url)}&reason=${encodeURIComponent(reason)}`;
      try {
        await chrome.tabs.update(details.tabId, { url: warningUrl });
      } catch (e) {
        errorSW('chrome.tabs.update failed', e);
      }
    }
  } catch (e) {
    errorSW('onBeforeNavigate unexpected', e);
  }
}

// Register navigation listener
try {
  chrome.webNavigation.onBeforeNavigate.addListener(
    onBeforeNavigate,
    { url: [{ schemes: ['http','https'] }] }
  );
} catch (e) {
  warnSW('Failed to register webNavigation listener', e);
}

// storage change listener
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local') {
    if (changes.enabled) enabled = changes.enabled.newValue;
    if (changes.allowlist) allowlist = changes.allowlist.newValue || [];
    if (changes.useCloudLookup) useCloudLookup = changes.useCloudLookup.newValue || false;
    if (changes.useDirectLookup) useDirectLookup = changes.useDirectLookup.newValue || false;
    if (changes.directApiKey) directApiKey = changes.directApiKey.newValue || '';
    logSW('storage.onChanged updated', { enabled, allowlistLen: allowlist.length, useCloudLookup, useDirectLookup });
  }
});

// initialize
(async () => {
  try {
    logSW('Service worker starting up');
    await loadState();
    logSW('Service worker initialized');
  } catch (e) {
    errorSW('Service worker startup failed', e);
  }
})();

// Expose debugDump for SW console
self.debugDump = async function() {
  try {
    const s = chrome && chrome.storage ? await chrome.storage.local.get(null) : {};
    console.log('[Anti-Phish Guard SW] debugDump storage:', s);
    console.log('[Anti-Phish Guard SW] blocklist len:', blocklist.length);
    console.log('[Anti-Phish Guard SW] hoverCache size:', hoverCache.size);
    return { storage: s, blocklistLen: blocklist.length, hoverCacheSize: hoverCache.size };
  } catch (e) {
    console.warn('[Anti-Phish Guard SW] debugDump failed', e);
    return { storage: null, blocklistLen: blocklist.length, hoverCacheSize: hoverCache.size };
  }
};