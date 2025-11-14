// background.js - MV3 service worker with host-level caching, hover host-only checks,
// Safe Browsing only mode, and API-usage logging.
//
// Replace your current background.js with this file and reload the extension.
//
// Features:
// - Host-level cache persisted to chrome.storage.local to avoid repeated checks per host.
// - Hover checks remain host-only (heuristics + proxy feeds) and do not call Google Safe Browsing.
// - Navigation supports useSafeBrowsingOnly: prefers Google SB (direct or proxy) first.
// - Logs visits and hovers to local proxy /log with apiUsed flag so the proxy terminal shows whether SB was used.
// - Exposes self.debugDump() for quick inspection in the SW console.

const SUSPICIOUS_TLDS = ['tk','ml','ga','cf','gq'];
let blocklist = [];
let enabled = true;
let allowlist = [];
let useCloudLookup = false;   // proxy checks enabled
let useDirectLookup = false;  // direct Safe Browsing API usage
let directApiKey = '';        // stored in chrome.storage.local when user supplies it
let useSafeBrowsingOnly = false; // when true, navigations prefer Safe Browsing and skip local DB

const PROXY_BASE = 'http://localhost:3000';
const PROXY_LOG_ENDPOINT = PROXY_BASE + '/log';
const PROXY_CHECK_HOST = PROXY_BASE + '/checkHost';
const PROXY_CHECK_URL = PROXY_BASE + '/check';

// --- Host cache configuration ---
const HOST_CHECK_TTL_MS = 60 * 60 * 1000; // 1 hour host-level TTL

// In-memory host cache: host -> { safe: boolean, reason: string, ts: number }
const hostCache = new Map();
const STORAGE_HOST_CACHE_KEY = 'hostCheckCache';

// Hover cache (compat)
const HOVER_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const hoverCache = new Map(); // host -> { status, reason, ts }

// Simple logging helpers
function logSW(...args) { console.log('[Anti-Phish Guard SW]', ...args); }
function warnSW(...args) { console.warn('[Anti-Phish Guard SW]', ...args); }
function errorSW(...args) { console.error('[Anti-Phish Guard SW]', ...args); }

// Persist hostCache to chrome.storage.local (best-effort)
async function persistHostCache() {
  try {
    const obj = Object.create(null);
    for (const [h, v] of hostCache.entries()) {
      obj[h] = { safe: !!v.safe, reason: v.reason || '', ts: v.ts || 0 };
    }
    await chrome.storage.local.set({ [STORAGE_HOST_CACHE_KEY]: obj });
    logSW('persistHostCache saved count=', Object.keys(obj).length);
  } catch (e) {
    warnSW('persistHostCache failed', e);
  }
}

// Load persisted hostCache from storage and prune expired
async function loadPersistedHostCache() {
  try {
    const s = await chrome.storage.local.get([STORAGE_HOST_CACHE_KEY]);
    const obj = (s && s[STORAGE_HOST_CACHE_KEY]) || {};
    const now = Date.now();
    let loaded = 0;
    for (const [h, v] of Object.entries(obj)) {
      if (!v || !v.ts) continue;
      if ((now - v.ts) > HOST_CHECK_TTL_MS) continue; // expired
      hostCache.set(h, { safe: !!v.safe, reason: v.reason || '', ts: v.ts });
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
function setHostCacheEntry(host, safe, reason) {
  try {
    hostCache.set(host, { safe: !!safe, reason: reason || '', ts: Date.now() });
    persistHostCache().catch(err => warnSW('persistHostCache err', err));
  } catch (e) {
    warnSW('setHostCacheEntry failed', e);
  }
}

// heuristics: return reason string if suspicious, otherwise null
// skipLocalDb: when true, skip checks that read packaged local DB (blocklist)
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

// call proxy host-only check (for hover) - returns reason string if unsafe, null otherwise
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
      // proxy indicates feed match; safebrowsing_used is false for host-only checks
      return `Matched feed host: ${json.matchedHost || host}`;
    }
    return null;
  } catch (e) {
    warnSW('Proxy host lookup error', e);
    return null;
  }
}

// Direct Safe Browsing (insecure when key stored client-side) - used for navigation when configured
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

// Host-only logging to proxy (best-effort). Includes apiUsed flag and event type.
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

// hover cache helpers (compat)
function getHoverCached(host) {
  const v = hoverCache.get(host);
  if (!v) return null;
  if (Date.now() - v.ts > HOVER_CACHE_TTL) { hoverCache.delete(host); return null; }
  return v;
}
function setHoverCached(host, status, reason) {
  hoverCache.set(host, { status, reason, ts: Date.now() });
}

// Message handler for host-only hover checks (uses hostCache first)
// Respects useSafeBrowsingOnly (skips local DB checks on hover when enabled)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;
  if (msg.type === 'CHECK_HOST_HOVER') {
    (async () => {
      const host = (msg.host || '').toString().toLowerCase();
      if (!host) { sendResponse({ status: 'unknown', reason: 'no host' }); return; }

      // 1) If host in allowlist -> safe immediately
      if (allowlist.includes(host)) {
        setHoverCached(host, 'safe', 'allowlist');
        sendLogToProxyHostOnly({
          timestamp: new Date().toISOString(),
          tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
          host,
          blocked: false,
          reason: 'allowlist',
          heuristicsOnly: true,
          apiUsed: false,
          event: 'hover'
        });
        sendResponse({ status: 'safe', reason: 'allowlist' });
        return;
      }

      // 2) Check persisted/in-memory hostCache (host-level TTL)
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
          event: 'hover'
        });
        sendResponse({ status, reason: cachedHost.reason || '', cached: true });
        return;
      }

      // 3) Run heuristics (skip local DB if useSafeBrowsingOnly)
      try {
        const fakeUrl = 'https://' + host + '/';
        let reason = runHeuristics(fakeUrl, useSafeBrowsingOnly); // skip local DB when configured
        if (reason) {
          setHostCacheEntry(host, false, reason);
          setHoverCached(host, 'unsafe', reason);
          sendLogToProxyHostOnly({
            timestamp: new Date().toISOString(),
            tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
            host,
            blocked: true,
            reason,
            heuristicsOnly: true,
            apiUsed: false,
            event: 'hover'
          });
          sendResponse({ status: 'unsafe', reason });
          return;
        }

        // 4) Ask proxy for host-only feed match only if useCloudLookup and NOT useSafeBrowsingOnly
        if (useCloudLookup && !useSafeBrowsingOnly) {
          const hostReason = await checkHostWithProxy(host);
          if (hostReason) {
            setHostCacheEntry(host, false, hostReason);
            setHoverCached(host, 'unsafe', hostReason);
            sendLogToProxyHostOnly({
              timestamp: new Date().toISOString(),
              tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
              host,
              blocked: true,
              reason: hostReason,
              heuristicsOnly: false,
              apiUsed: false,
              event: 'hover'
            });
            sendResponse({ status: 'unsafe', reason: hostReason });
            return;
          }
        }

        // 5) No feed/heuristic match -> mark host as safe in hostCache
        setHostCacheEntry(host, true, '');
        setHoverCached(host, 'safe', '');
        sendLogToProxyHostOnly({
          timestamp: new Date().toISOString(),
          tabId: (sender && sender.tab && sender.tab.id) ? sender.tab.id : -1,
          host,
          blocked: false,
          reason: '',
          heuristicsOnly: false,
          apiUsed: false,
          event: 'hover'
        });
        sendResponse({ status: 'safe' });
      } catch (e) {
        sendResponse({ status: 'unknown', reason: e && e.message ? e.message : String(e) });
      }
    })();
    return true; // sendResponse async
  }
  // ignore other message types here
});

// Navigation interception: run heuristics and proxy/direct checks, then redirect to warning page when needed.
// This implementation prefers Safe Browsing when useSafeBrowsingOnly is true (direct or proxy), otherwise uses
// the normal local-first logic. It logs whether the Safe Browsing API was used.
async function onBeforeNavigate(details) {
  try {
    if (details.frameId !== 0) return;
    if (!enabled) return;
    if (!details.url) return;
    if (details.url.startsWith(chrome.runtime.getURL('warning.html'))) return;

    logSW('onBeforeNavigate', details.url, 'tab=' + details.tabId);

    // host-only cache check and setup
    let reason = null;
    let hostOnly = '<invalid-host>';
    try { hostOnly = new URL(details.url).hostname.toLowerCase(); } catch (e) {}

    let apiUsedForThisVisit = false;

    // If user enabled Safe-Only mode, prefer calling Safe Browsing (direct or via proxy) first
    if (useSafeBrowsingOnly) {
      // Try direct Safe Browsing (direct API key configured and direct lookup enabled)
      if (useDirectLookup && directApiKey) {
        try {
          const directReason = await checkWithSafeBrowsingDirect(directApiKey, details.url);
          apiUsedForThisVisit = true;
          if (directReason) {
            reason = directReason;
            setHostCacheEntry(hostOnly, false, directReason);
          } else {
            setHostCacheEntry(hostOnly, true, '');
          }
        } catch (e) {
          warnSW('direct Safe Browsing failed', e);
        }
      } else if (useCloudLookup) {
        // No direct key: fall back to proxy /check
        try {
          const encoded = encodeURIComponent(details.url);
          const resp = await fetch(`${PROXY_CHECK_URL}?url=${encoded}`, { method: 'GET' });
          if (resp.ok) {
            const json = await resp.json();
            const sbUsed = !!json.safebrowsing_used;
            apiUsedForThisVisit = sbUsed;
            if (json.safe === false) {
              reason = 'Matches proxy (feeds or Safe Browsing)';
              try {
                if (json.matches && json.matches.feeds && json.matches.feeds.matchedHost) {
                  setHostCacheEntry(hostOnly, false, `Matched feed: ${json.matches.feeds.matchedHost}`);
                } else {
                  setHostCacheEntry(hostOnly, false, 'Proxy reported unsafe');
                }
              } catch (e) { /* ignore cache set errors */ }
            } else {
              setHostCacheEntry(hostOnly, true, '');
            }
          } else {
            warnSW('Proxy /check non-OK', resp.status);
          }
        } catch (e) {
          warnSW('cloud lookup failed', e);
        }
      } else {
        // No direct key and no proxy available — fall back to heuristics (will not call SB)
        logSW('useSafeBrowsingOnly enabled but no direct key and no proxy: falling back to heuristics');
        const hReason = runHeuristics(details.url, true); // skip local DB if desired
        if (hReason) reason = hReason;
      }
    } else {
      // Normal mode: heuristics/local checks first (existing behavior)
      reason = runHeuristics(details.url);
      if (!reason && useCloudLookup) {
        try {
          const encoded = encodeURIComponent(details.url);
          const resp = await fetch(`${PROXY_CHECK_URL}?url=${encoded}`, { method: 'GET' });
          if (resp.ok) {
            const json = await resp.json();
            if (json.safe === false) {
              reason = 'Matches proxy (feeds or Safe Browsing)';
              try {
                if (json.matches && json.matches.feeds && json.matches.feeds.matchedHost) {
                  setHostCacheEntry(hostOnly, false, `Matched feed: ${json.matches.feeds.matchedHost}`);
                } else {
                  setHostCacheEntry(hostOnly, false, 'Proxy reported unsafe');
                }
              } catch (e) { /* ignore cache set errors */ }
            } else {
              setHostCacheEntry(hostOnly, true, '');
            }
          } else {
            warnSW('Proxy /check non-OK', resp.status);
          }
        } catch (e) {
          warnSW('cloud lookup failed', e);
        }
      }

      // If still no reason and direct lookup is enabled as last resort:
      if (!reason && useDirectLookup && directApiKey) {
        try {
          const directReason = await checkWithSafeBrowsingDirect(directApiKey, details.url);
          apiUsedForThisVisit = true;
          if (directReason) {
            reason = directReason;
            setHostCacheEntry(hostOnly, false, directReason);
          } else {
            setHostCacheEntry(hostOnly, true, '');
          }
        } catch (e) {
          warnSW('direct lookup failed', e);
        }
      }
    }

    const blocked = !!reason;

    // Log to SW console and proxy (include apiUsed flag)
    logSW('NAV HOST LOG', { ts: new Date().toISOString(), tabId: details.tabId, host: hostOnly, blocked, reason, apiUsed: apiUsedForThisVisit, useSafeBrowsingOnly });

    // Best-effort: send host-only to proxy, include apiUsed flag and event=visit
    sendLogToProxyHostOnly({
      timestamp: new Date().toISOString(),
      tabId: details.tabId,
      host: hostOnly,
      blocked,
      reason,
      heuristicsOnly: !!reason && !useCloudLookup && !useDirectLookup,
      apiUsed: apiUsedForThisVisit,
      event: 'visit',
      extra: { from: 'extension', useSafeBrowsingOnly }
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
    if (changes.useSafeBrowsingOnly) useSafeBrowsingOnly = changes.useSafeBrowsingOnly.newValue || false;
    logSW('storage.onChanged updated', { enabled, allowlistLen: allowlist.length, useCloudLookup, useDirectLookup, useSafeBrowsingOnly });
  }
});

// initialization
(async () => {
  try {
    logSW('Service worker starting up');
    // Load persisted options & caches
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

    // Load packaged blocklist if present
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
    console.log('[Anti-Phish Guard SW] hostCache size:', hostCache.size);
    console.log('[Anti-Phish Guard SW] hoverCache size:', hoverCache.size);
    console.log('[Anti-Phish Guard SW] useSafeBrowsingOnly:', useSafeBrowsingOnly);
    return { storage: s, blocklistLen: blocklist.length, hostCacheSize: hostCache.size, hoverCacheSize: hoverCache.size, useSafeBrowsingOnly };
  } catch (e) {
    console.warn('[Anti-Phish Guard SW] debugDump failed', e);
    return { storage: null, blocklistLen: blocklist.length, hostCacheSize: hostCache.size, hoverCacheSize: hoverCache.size };
  }
};