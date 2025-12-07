// background.js - Direct Google Safe Browsing checks (API key stored in extension)
// Replaces navigation decision logic to call Google Safe Browsing for each top-frame navigation.
// WARNING: Storing API key in the extension is insecure. Use only for local/dev testing.

const SAFE_BROWSING_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=';
const HOST_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const HOVER_CACHE_TTL_MS = 5 * 60 * 1000;  // preserved if needed
const persistedHostCacheKey = 'hostCheckCache';

// Runtime state
let blocklist = []; // packaged blocklist (normalized hosts)
const hostCache = new Map(); // host -> { safe: bool, reason, ts, source }
const hoverCache = new Map();
let cfg = { directApiKey: '', enabled: true };

// Logging helpers
function logSW(...args) { console.log('[Anti-Phish Guard SW]', ...args); }
function warnSW(...args) { console.warn('[Anti-Phish Guard SW]', ...args); }

// Normalize host and URL helpers
const normalizeHost = h => (h || '').toString().trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
function normalizeUrl(u) {
  try {
    const url = new URL(u);
    url.hash = '';
    return url.toString();
  } catch (e) {
    return u;
  }
}

// Safe chrome.tabs.update wrapper
async function safeUpdateTab(tabId, updateProps) {
  if (typeof chrome === 'undefined' || !chrome.tabs || typeof chrome.tabs.update !== 'function') {
    warnSW('safeUpdateTab: chrome.tabs.update unavailable');
    return { ok: false, reason: 'no-chrome-tabs' };
  }
  if (!Number.isFinite(tabId)) {
    warnSW('safeUpdateTab: invalid tabId', tabId);
    return { ok: false, reason: 'invalid-tabid' };
  }
  return new Promise((resolve) => {
    try {
      chrome.tabs.update(tabId, updateProps, (tab) => {
        if (chrome.runtime.lastError) {
          warnSW('safeUpdateTab error', chrome.runtime.lastError.message);
          resolve({ ok: false, reason: chrome.runtime.lastError.message });
        } else {
          resolve({ ok: true, tab });
        }
      });
    } catch (e) {
      warnSW('safeUpdateTab exception', String(e));
      resolve({ ok: false, reason: String(e) });
    }
  });
}

// Persist / load host cache (debounced)
let persistTimer = null;
function persistHostCacheDebounced() {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(async () => {
    try {
      const obj = {};
      for (const [k, v] of hostCache.entries()) obj[k] = v;
      await chrome.storage.local.set({ [persistedHostCacheKey]: obj });
      logSW('hostCache persisted', Object.keys(obj).length);
    } catch (e) {
      warnSW('persistHostCache failed', e);
    }
  }, 300);
}

async function loadPersistedHostCache() {
  try {
    const s = await chrome.storage.local.get(persistedHostCacheKey);
    const raw = s && s[persistedHostCacheKey] ? s[persistedHostCacheKey] : {};
    const now = Date.now();
    for (const [k, v] of Object.entries(raw)) {
      if (v && v.ts && (now - v.ts) < HOST_CACHE_TTL_MS) hostCache.set(k, v);
    }
    logSW('loaded persisted hostCache size=', hostCache.size);
  } catch (e) {
    warnSW('loadPersistedHostCache failed', e);
  }
}

function setHostCacheEntry(host, safe, reason = '', source = '') {
  const n = normalizeHost(host);
  const entry = { safe: !!safe, reason: reason || '', ts: Date.now(), source: source || '' };
  hostCache.set(n, entry);
  persistHostCacheDebounced();
  logSW('setHostCacheEntry', n, entry);
}

function getHostCacheEntry(host) {
  const n = normalizeHost(host);
  const ent = hostCache.get(n);
  if (!ent) return null;
  if ((Date.now() - ent.ts) > HOST_CACHE_TTL_MS) {
    hostCache.delete(n);
    persistHostCacheDebounced();
    return null;
  }
  return ent;
}

// Load packaged blocklist.json (if present)
async function loadPackagedBlocklist() {
  try {
    const url = chrome.runtime.getURL('blocklist.json');
    const r = await fetch(url);
    if (!r.ok) { blocklist = []; logSW('no packaged blocklist'); return; }
    const raw = await r.json();
    if (!Array.isArray(raw)) { blocklist = []; warnSW('blocklist not array'); return; }
    blocklist = raw.map(x => {
      try {
        let s = (x || '').toString().trim().toLowerCase();
        if (s.startsWith('http://') || s.startsWith('https://')) {
          try { return new URL(s).hostname.replace(/^www\./, ''); } catch (_) {}
        }
        s = s.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
        return s;
      } catch (e) {
        return '';
      }
    }).filter(Boolean);
    logSW('blocklist loaded entries=', blocklist.length);
  } catch (e) {
    blocklist = [];
    warnSW('loadPackagedBlocklist failed', e);
  }
}

// Call Google Safe Browsing v4 (threatMatches.find)
async function callSafeBrowsingDirect(apiKey, url) {
  if (!apiKey) return { error: 'no-api-key' };
  try {
    const body = {
      client: { clientId: 'antiphish-guard', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'POTENTIALLY_HARMFUL_APPLICATION', 'UNWANTED_SOFTWARE'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      }
    };
    const resp = await fetch(SAFE_BROWSING_ENDPOINT + encodeURIComponent(apiKey), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      return { error: 'sb-nonok', status: resp.status, body: text };
    }
    const j = await resp.json();
    // If j.matches exists and non-empty -> threat matched
    const match = !!(j && j.matches && j.matches.length > 0);
    return { match, raw: j };
  } catch (e) {
    return { error: 'sb-error', exception: String(e) };
  }
}

// Message handler: check arbitrary URL via GSB (useful for content-script requests)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return;
  (async () => {
    try {
      if (msg.type === 'CHECK_URL_SAFE_BROWSING') {
        const url = (msg.url || '').toString();
        if (!url) { sendResponse({ error: 'no-url' }); return; }
        const apiKey = (await chrome.storage.local.get('directApiKey')).directApiKey || '';
        if (!apiKey) { sendResponse({ error: 'no-api-key' }); return; }
        const sb = await callSafeBrowsingDirect(apiKey, url);
        if (sb.error) sendResponse({ error: sb.error, raw: sb });
        else if (sb.match) sendResponse({ safe: false, reason: 'Google Safe Browsing match', raw: sb.raw });
        else sendResponse({ safe: true, reason: 'No match', raw: sb.raw });
        return;
      }
    } catch (e) {
      try { sendResponse({ error: String(e) }); } catch (_) {}
      return;
    }
  })();
  return true;
});

// onBeforeNavigate: check every top-frame navigation with GSB (direct)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  (async () => {
    try {
      if (!details || details.frameId !== 0 || !details.url) return;
      // skip if extension disabled
      const s0 = await chrome.storage.local.get(['enabled']);
      if (s0.enabled === false) return;

      const urlStr = details.url;
      const tabId = details.tabId;
      const u = new URL(urlStr);
      const hostOnly = normalizeHost(u.hostname);

      // allowlist override
      const s = await chrome.storage.local.get('allowlist');
      const allowlist = s && s.allowlist ? s.allowlist.map(normalizeHost) : [];
      if (allowlist.includes(hostOnly)) {
        logSW('allowlist', hostOnly);
        return;
      }

      // packaged blocklist precedence
      if (blocklist.includes(hostOnly)) {
        const reason = 'Domain is on the packaged blocklist';
        setHostCacheEntry(hostOnly, false, reason, 'local-blocklist');
        logSW('blocked (local blocklist)', hostOnly);
        await safeUpdateTab(tabId, { url: chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(urlStr)}&reason=${encodeURIComponent(reason)}&source=local-blocklist` });
        return;
      }

      // host cache short-circuit
      const cached = getHostCacheEntry(hostOnly);
      if (cached) {
        logSW('hostCache hit', hostOnly, cached);
        if (!cached.safe) {
          await safeUpdateTab(tabId, { url: chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(urlStr)}&reason=${encodeURIComponent(cached.reason)}&source=${encodeURIComponent(cached.source)}` });
          return;
        } else {
          return; // safe cached
        }
      }

      // Get API key from storage
      const kobj = await chrome.storage.local.get('directApiKey');
      const apiKey = kobj && kobj.directApiKey ? kobj.directApiKey : '';
      if (!apiKey) {
        // no API key configured -> allow (or you could choose to block)
        logSW('no directApiKey configured, allowing navigation for', hostOnly);
        setHostCacheEntry(hostOnly, true, '', 'no-api-key');
        return;
      }

      // Call Google Safe Browsing
      const sb = await callSafeBrowsingDirect(apiKey, urlStr);
      if (sb.error) {
        // On error, do not block by default; mark safe to avoid repeated failing calls
        warnSW('GSB error for', hostOnly, sb);
        setHostCacheEntry(hostOnly, true, '', 'gsb-error');
        return;
      }

      if (sb.match) {
        const reason = 'Matches Google Safe Browsing';
        setHostCacheEntry(hostOnly, false, reason, 'safebrowsing');
        logSW('Blocked by Google Safe Browsing', hostOnly);
        await safeUpdateTab(tabId, { url: chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(urlStr)}&reason=${encodeURIComponent(reason)}&source=safebrowsing` });
        return;
      } else {
        setHostCacheEntry(hostOnly, true, '', 'safebrowsing');
        return;
      }

    } catch (e) {
      warnSW('onBeforeNavigate error', e);
      return;
    }
  })();
});

// storage change listener: capture directApiKey and enabled toggles
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.directApiKey) {
    cfg.directApiKey = changes.directApiKey.newValue;
    logSW('directApiKey updated');
  }
  if (changes.enabled) {
    cfg.enabled = !!changes.enabled.newValue;
  }
});

// debug helper
async function debugDump() {
  const s = await chrome.storage.local.get();
  logSW('debugDump storage:', s);
  logSW('blocklist len:', blocklist.length);
  logSW('hostCache size:', hostCache.size);
  return { storage: s, blocklistLen: blocklist.length, hostCacheSize: hostCache.size };
}
self.debugDump = debugDump;

// initialization
(async function init() {
  await loadPackagedBlocklist();
  await loadPersistedHostCache();
  const s = await chrome.storage.local.get(['directApiKey','enabled']);
  cfg.directApiKey = s.directApiKey || '';
  cfg.enabled = s.enabled !== undefined ? s.enabled : true;
  logSW('initialized', { hasApiKey: !!cfg.directApiKey, enabled: cfg.enabled });
})();