// background.js - MV3 service worker (strict Safe-Browsing-only mode)
// Behavior change implemented per request:
// - When "Use Google Safe Browsing only" (useSafeBrowsingOnly) is enabled the extension
//   will NOT fall back to the proxy. It will only call Google Safe Browsing directly
//   (if a direct API key is configured). If no direct key is present it will fall back
//   to local heuristics (NOT proxy).
//
// Other features retained:
// - Host-level cache persisted to chrome.storage.local to avoid repeated checks per host.
// - Hover host-only checks (never call Google Safe Browsing).
// - Logging to proxy /log includes apiUsed and decision source.

const SUSPICIOUS_TLDS = ['tk','ml','ga','cf','gq'];
let blocklist = [];
let enabled = true;
let allowlist = [];
let useCloudLookup = false;   // proxy checks enabled (only used when not in strict Safe-only)
let useDirectLookup = false;  // direct Safe Browsing API usage (set when API key present)
let directApiKey = '';        // Safe Browsing API key (set from popup)
let useSafeBrowsingOnly = false; // When true, DO NOT use proxy fallback; require direct API to call Google SB

const PROXY_BASE = 'http://localhost:3000';
const PROXY_LOG_ENDPOINT = PROXY_BASE + '/log';
const PROXY_CHECK_HOST = PROXY_BASE + '/checkHost';
const PROXY_CHECK_URL = PROXY_BASE + '/check';

// --- Host cache configuration ---
const HOST_CHECK_TTL_MS = 60 * 60 * 1000; // 1 hour host-level TTL

// In-memory host cache: host -> { safe: boolean, reason: string, ts: number, source: string }
const hostCache = new Map();
const STORAGE_HOST_CACHE_KEY = 'hostCheckCache';

// Hover cache (compat)
const HOVER_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const hoverCache = new Map(); // host -> { status, reason, ts, source }

// Logging helpers
function logSW(...args) { console.log('[Anti-Phish Guard SW]', ...args); }
function warnSW(...args) { console.warn('[Anti-Phish Guard SW]', ...args); }
function errorSW(...args) { console.error('[Anti-Phish Guard SW]', ...args); }

async function persistHostCache() {
  try {
    const obj = Object.create(null);
    for (const [h, v] of hostCache.entries()) {
      obj[h] = { safe: !!v.safe, reason: v.reason || '', ts: v.ts || 0, source: v.source || '' };
    }
    await chrome.storage.local.set({ [STORAGE_HOST_CACHE_KEY]: obj });
    logSW('persistHostCache saved count=', Object.keys(obj).length);
  } catch (e) {
    warnSW('persistHostCache failed', e);
  }
}

async function loadPersistedHostCache() {
  try {
    const s = await chrome.storage.local.get([STORAGE_HOST_CACHE_KEY]);
    const obj = (s && s[STORAGE_HOST_CACHE_KEY]) || {};
    const now = Date.now();
    let loaded = 0;
    for (const [h, v] of Object.entries(obj)) {
      if (!v || !v.ts) continue;
      if ((now - v.ts) > HOST_CHECK_TTL_MS) continue; // expired
      hostCache.set(h, { safe: !!v.safe, reason: v.reason || '', ts: v.ts, source: v.source || 'cache' });
      loaded++;
    }
    logSW('loadPersistedHostCache loaded=', loaded);
  } catch (e) {
    warnSW('loadPersistedHostCache failed', e);
  }
}

function getHostCacheEntry(host) {
  try {
    const e = hostCache.get(host);
    if (!e) return null;
    if ((Date.now() - e.ts) > HOST_CHECK_TTL_MS) {
      hostCache.delete(host);
      return null;
    }
    return e;
  } catch (e) {
    return null;
  }
}
function setHostCacheEntry(host, safe, reason, source = '') {
  try {
    hostCache.set(host, { safe: !!safe, reason: reason || '', ts: Date.now(), source: source || '' });
    persistHostCache().catch(err => warnSW('persistHostCache err', err));
  } catch (e) {
    warnSW('setHostCacheEntry failed', e);
  }
}

// heuristics: return reason string if suspicious, otherwise null
// skipLocalDb: when true, don't consult packaged blocklist.json
function runHeuristics(urlStr, skipLocalDb = false) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    if (!host) return null;
    if (urlStr.startsWith(chrome.runtime.getURL('warning.html'))) return null;
    if (allowlist.includes(host)) return null;
    if (!skipLocalDb && blocklist.includes(host)) return 'Domain is on the local blocklist';
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

// call proxy host-only check (for hover) - returns { reason, source } or null
async function checkHostWithProxy(host) {
  if (!host) return null;
  try {
    const encoded = encodeURIComponent(host);
    const resp = await fetch(`${PROXY_CHECK_HOST}?host=${encoded}`, { method: 'GET' });
    if (!resp.ok) {
      warnSW('Proxy host check non-OK', resp.status);
      return null;
    }
    const json = await resp.json();
    if (json.unsafe) {
      return { reason: `Matched feed host: ${json.matchedHost || host}`, source: 'feed' };
    }
    return { reason: null, source: 'feeds-none' };
  } catch (e) {
    warnSW('Proxy host lookup error', e);
    return null;
  }
}

// Direct Safe Browsing (returns { match: bool, reason })
async function checkWithSafeBrowsingDirect(apiKey, url) {
  if (!apiKey) return { match: false, error: 'no-key' };
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
      return { match: false, error: 'sb-nonok' };
    }
    const json = await resp.json();
    const matched = json.matches && json.matches.length;
    return { match: !!matched, reason: matched ? 'Matches Google Safe Browsing (direct)' : null };
  } catch (e) {
    warnSW('Safe Browsing direct error', e);
    return { match: false, error: 'sb-error' };
  }
}

// Host-only logging to proxy (best-effort). Includes apiUsed flag and source.
async function sendLogToProxyHostOnly(logObj) {
  try {
    const payload = {
      timestamp: logObj.timestamp,
      tabId: logObj.tabId,
      host: logObj.host,
      blocked: !!logObj.blocked,
      reason: logObj.reason || '',
      heuristicsOnly: !!logObj.heuristicsOnly,
      apiUsed: !!logObj.apiUsed,
      event: logObj.event || 'visit',
      source: logObj.source || '',
      extra: logObj.extra || null
    };
    await fetch(PROXY_LOG_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    warnSW('sendLogToProxyHostOnly failed', e);
  }
}

// hover cache helpers
function getHoverCached(host) {
  const v = hoverCache.get(host);
  if (!v) return null;
  if (Date.now() - v.ts > HOVER_CACHE_TTL) { hoverCache.delete(host); return null; }
  return v;
}
function setHoverCached(host, status, reason, source='') {
  hoverCache.set(host, { status, reason, ts: Date.now(), source });
}

// Message handler for host-only hover checks (uses hostCache first).
// Returns { status: 'safe'|'unsafe'|'unknown', reason, source }
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;
  if (msg.type === 'CHECK_HOST_HOVER') {
    (async () => {
      const host = (msg.host || '').toString().toLowerCase();
      if (!host) { sendResponse({ status: 'unknown', reason: 'no host', source: 'unknown' }); return; }

      // 1) allowlist
      if (allowlist.includes(host)) {
        setHoverCached(host, 'safe', 'allowlist', 'allowlist');
        sendLogToProxyHostOnly({
          timestamp: new Date().toISOString(),
          tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
          host,
          blocked: false,
          reason: 'allowlist',
          heuristicsOnly: true,
          apiUsed: false,
          event: 'hover',
          source: 'allowlist'
        });
        sendResponse({ status: 'safe', reason: 'allowlist', source: 'allowlist' });
        return;
      }

      // 2) host cache
      const cachedHost = getHostCacheEntry(host);
      if (cachedHost) {
        const status = cachedHost.safe ? 'safe' : 'unsafe';
        sendLogToProxyHostOnly({
          timestamp: new Date().toISOString(),
          tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
          host,
          blocked: !cachedHost.safe,
          reason: cachedHost.reason || '',
          heuristicsOnly: false,
          apiUsed: false,
          event: 'hover',
          source: cachedHost.source || 'cache'
        });
        sendResponse({ status, reason: cachedHost.reason || '', source: cachedHost.source || 'cache', cached: true });
        return;
      }

      // 3) heuristics (skip local DB if useSafeBrowsingOnly)
      try {
        const fakeUrl = 'https://' + host + '/';
        const hReason = runHeuristics(fakeUrl, useSafeBrowsingOnly);
        if (hReason) {
          setHostCacheEntry(host, false, hReason, 'heuristic');
          setHoverCached(host, 'unsafe', hReason, 'heuristic');
          sendLogToProxyHostOnly({
            timestamp: new Date().toISOString(),
            tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
            host,
            blocked: true,
            reason: hReason,
            heuristicsOnly: true,
            apiUsed: false,
            event: 'hover',
            source: 'heuristic'
          });
          sendResponse({ status: 'unsafe', reason: hReason, source: 'heuristic' });
          return;
        }

        // 4) proxy host-only feed match: only if useCloudLookup and NOT in strict Safe-only (we enforce strict when useSafeBrowsingOnly is true)
        if (useCloudLookup && !useSafeBrowsingOnly) {
          const hostRes = await checkHostWithProxy(host);
          if (hostRes && hostRes.reason) {
            setHostCacheEntry(host, false, hostRes.reason, 'feed');
            setHoverCached(host, 'unsafe', hostRes.reason, 'feed');
            sendLogToProxyHostOnly({
              timestamp: new Date().toISOString(),
              tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
              host,
              blocked: true,
              reason: hostRes.reason,
              heuristicsOnly: false,
              apiUsed: false,
              event: 'hover',
              source: 'feed'
            });
            sendResponse({ status: 'unsafe', reason: hostRes.reason, source: 'feed' });
            return;
          }
        }

        // 5) Safe: cache host as safe
        setHostCacheEntry(host, true, '', 'safe');
        setHoverCached(host, 'safe', '', 'safe');
        sendLogToProxyHostOnly({
          timestamp: new Date().toISOString(),
          tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
          host,
          blocked: false,
          reason: '',
          heuristicsOnly: false,
          apiUsed: false,
          event: 'hover',
          source: 'safe'
        });
        sendResponse({ status: 'safe', reason: '', source: 'safe' });
      } catch (e) {
        sendResponse({ status: 'unknown', reason: e && e.message ? e.message : String(e), source: 'error' });
      }
    })();
    return true; // async
  }
});

// Navigation interception: strict Safe-only enforcement implemented here.
// When useSafeBrowsingOnly === true we will NOT call the proxy. We will call Google SB directly
// if a direct API key is present. If no key is present we fall back to heuristics (local only).
async function onBeforeNavigate(details) {
  try {
    if (details.frameId !== 0) return;
    if (!enabled) return;
    if (!details.url) return;
    if (details.url.startsWith(chrome.runtime.getURL('warning.html'))) return;

    logSW('onBeforeNavigate', details.url, 'tab=' + details.tabId);

    let reason = null;
    let source = '';
    let hostOnly = '<invalid-host>';
    try { hostOnly = new URL(details.url).hostname.toLowerCase(); } catch (e) {}

    let apiUsedForThisVisit = false;

    // allowlist short-circuit
    if (allowlist.includes(hostOnly)) {
      source = 'allowlist';
      reason = null;
      setHostCacheEntry(hostOnly, true, '', source);
      logSW('Allowlist hit, permitting', hostOnly);
    } else {
      const c = getHostCacheEntry(hostOnly);
      if (c) {
        source = c.source || 'cache';
        if (!c.safe) {
          reason = c.reason || 'Host previously flagged';
        } else {
          logSW('Host cache (safe) skipping checks for', hostOnly);
        }
      }
    }

    // Strict Safe-only behavior: if enabled, only direct Safe Browsing is allowed (no proxy fallback).
    if (!reason && useSafeBrowsingOnly) {
      if (useDirectLookup && directApiKey) {
        // Call Google Safe Browsing directly
        const sb = await checkWithSafeBrowsingDirect(directApiKey, details.url);
        apiUsedForThisVisit = true;
        if (sb.match) {
          reason = sb.reason || 'Matches Google Safe Browsing (direct)';
          source = 'safebrowsing';
          setHostCacheEntry(hostOnly, false, reason, source);
        } else {
          // safe according to Google SB
          setHostCacheEntry(hostOnly, true, '', 'safebrowsing-safe');
        }
      } else {
        // No direct key: strict Safe-only prevents proxy fallback by design.
        // We fall back to heuristics (local only) rather than calling proxy.
        logSW('Safe-only enabled but no direct API key present: falling back to local heuristics (proxy disabled by strict mode).');
        const h = runHeuristics(details.url, true); // skip packaged blocklist if user intended SB-only
        if (h) {
          reason = h;
          source = 'heuristic';
          setHostCacheEntry(hostOnly, false, reason, source);
        } else {
          setHostCacheEntry(hostOnly, true, '', 'heuristic-clear');
        }
      }
    } else if (!reason) {
      // Normal behavior (not strict Safe-only): heuristics -> proxy -> direct last-resort
      const h = runHeuristics(details.url, false);
      if (h) {
        reason = h;
        source = 'heuristic';
        setHostCacheEntry(hostOnly, false, reason, source);
      } else if (useCloudLookup) {
        try {
          const encoded = encodeURIComponent(details.url);
          const resp = await fetch(`${PROXY_CHECK_URL}?url=${encoded}`, { method: 'GET' });
          if (resp.ok) {
            const json = await resp.json();
            const sbUsed = !!json.safebrowsing_used;
            apiUsedForThisVisit = apiUsedForThisVisit || sbUsed;
            if (json.safe === false) {
              if (json.matches && json.matches.feeds && json.matches.feeds.matchedHost) {
                source = 'feed';
                reason = `Matched feed: ${json.matches.feeds.matchedHost}`;
                setHostCacheEntry(hostOnly, false, reason, 'feed');
              } else {
                source = sbUsed ? 'safebrowsing' : 'proxy-unsafe';
                reason = 'Matches proxy (feeds or Safe Browsing)';
                setHostCacheEntry(hostOnly, false, reason, source);
              }
            } else {
              setHostCacheEntry(hostOnly, true, '', 'proxy-safe');
            }
          } else {
            warnSW('Proxy /check non-OK', resp.status);
          }
        } catch (e) {
          warnSW('cloud lookup failed', e);
        }
      }

      // direct lookup last-resort if enabled
      if (!reason && useDirectLookup && directApiKey) {
        try {
          const sb = await checkWithSafeBrowsingDirect(directApiKey, details.url);
          apiUsedForThisVisit = apiUsedForThisVisit || true;
          if (sb.match) {
            reason = sb.reason || 'Matches Google Safe Browsing (direct)';
            source = 'safebrowsing';
            setHostCacheEntry(hostOnly, false, reason, source);
          } else {
            setHostCacheEntry(hostOnly, true, '', 'safebrowsing-safe');
          }
        } catch (e) {
          warnSW('direct lookup failed', e);
        }
      }
    }

    const blocked = !!reason;

    // Log to SW console and proxy (include apiUsed flag & source)
    logSW('NAV HOST LOG', { ts: new Date().toISOString(), tab: details.tabId, host: hostOnly, blocked, reason, apiUsed: apiUsedForThisVisit, source, useSafeBrowsingOnly });

    // Send host-only to proxy log
    sendLogToProxyHostOnly({
      timestamp: new Date().toISOString(),
      tabId: details.tabId,
      host: hostOnly,
      blocked,
      reason,
      heuristicsOnly: (source === 'heuristic'),
      apiUsed: apiUsedForThisVisit,
      event: 'visit',
      source,
      extra: { from: 'extension', useSafeBrowsingOnly }
    });

    if (reason) {
      // include source in the warning URL so warning.html can show the decision source
      const warningUrl = chrome.runtime.getURL('warning.html') +
        `?url=${encodeURIComponent(details.url)}&reason=${encodeURIComponent(reason)}&source=${encodeURIComponent(source)}`;
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
    if (changes.useSafeBrowsingOnly) useSafeBrowsingOnly = changes.useSafeBrowsingOnly.newValue || false;
    logSW('storage.onChanged updated', { enabled, allowlistLen: allowlist.length, useCloudLookup, useDirectLookup, useSafeBrowsingOnly });
  }
});

// initialization
(async () => {
  try {
    logSW('Service worker starting up');
    // Load persisted options and caches
    try {
      const s = await chrome.storage.local.get(['enabled','allowlist','useCloudLookup','useDirectLookup','directApiKey','useSafeBrowsingOnly']);
      enabled = s.enabled !== undefined ? s.enabled : true;
      allowlist = s.allowlist || [];
      useCloudLookup = s.useCloudLookup || false;
      useDirectLookup = s.useDirectLookup || false;
      directApiKey = s.directApiKey || '';
      useSafeBrowsingOnly = s.useSafeBrowsingOnly || false;
      logSW('loadState initial', { enabled, allowlistLen: allowlist.length, useCloudLookup, useDirectLookup, useSafeBrowsingOnly });
    } catch (e) {
      warnSW('initial storage load failed', e);
    }

    // Load blocklist.json (packaged)
    try {
      const resp = await fetch(chrome.runtime.getURL('blocklist.json'));
      if (resp.ok) {
        blocklist = await resp.json();
        logSW('blocklist loaded, entries=', blocklist.length);
      } else {
        blocklist = [];
        logSW('no packaged blocklist or fetch non-OK', resp.status);
      }
    } catch (e) {
      warnSW('failed to load blocklist.json', e);
      blocklist = [];
    }

    // Load persisted host cache entries
    await loadPersistedHostCache();

    logSW('Service worker initialized (strict Safe-only enforces no-proxy fallback when enabled)');
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
    console.log('[Anti-Phish Guard SW] hostCache size:', hostCache.size);
    console.log('[Anti-Phish Guard SW] hoverCache size:', hoverCache.size);
    console.log('[Anti-Phish Guard SW] useSafeBrowsingOnly:', useSafeBrowsingOnly);
    return { storage: s, blocklistLen: blocklist.length, hostCacheSize: hostCache.size, hoverCacheSize: hoverCache.size, useSafeBrowsingOnly };
  } catch (e) {
    console.warn('[Anti-Phish Guard SW] debugDump failed', e);
    return { storage: null, blocklistLen: blocklist.length, hostCacheSize: hostCache.size, hoverCacheSize: hoverCache.size };
  }
};