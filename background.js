// background.js - Direct Google Safe Browsing with hover analysis
// Replaces existing background.js. Adds CHECK_HOST_HOVER handling for content-script hover checks.
// WARNING: Keeps the API key in extension storage (directApiKey) — only for local testing.

const SAFE_BROWSING_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=';
const HOST_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour for host cache
const HOVER_CACHE_TTL_MS = 5 * 60 * 1000; // short TTL for hover results
const persistedHostCacheKey = 'hostCheckCache';


const SAFE_DOMAIN_WHITELIST = [
  'google.com',
  'www.google.com',
  'youtube.com',
  'www.youtube.com',
  'play.google.com',
  'store.google.com',
  'gmail.com',
  'maps.google.com'
  // add other trusted domains you use frequently
];


// Runtime state
let blocklist = []; // packaged blocklist (normalized hosts)
const hostCache = new Map(); // host -> { safe: bool, reason, ts, source }
const hoverCache = new Map(); // host -> { classification, reason, source, ts, raw }
let cfg = { directApiKey: '', enabled: true };

// Logging helpers
function logSW(...args) { console.log('[Anti-Phish Guard SW]', ...args); }
function warnSW(...args) { console.warn('[Anti-Phish Guard SW]', ...args); }

// Normalize helpers
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

// Safe chrome.tabs.update wrapper (keeps SW stable)
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

// Persist / load host cache
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

// Load packaged blocklist.json and normalize entries
async function loadPackagedBlocklist() {
  try {
    const url = chrome.runtime.getURL('blocklist.json');
    const r = await fetch(url);
    if (!r.ok) {
      blocklist = [];
      logSW('No packaged blocklist found (fetch non-OK)', r.status);
      return;
    }
    const raw = await r.json();
    if (!Array.isArray(raw)) {
      blocklist = [];
      warnSW('packaged blocklist is not an array');
      return;
    }
    // Normalize entries: extract host if a URL, strip www, lowercase
    blocklist = raw.map(x => {
      try {
        let s = (x || '').toString().trim().toLowerCase();
        // if the entry looks like a URL, extract hostname
        if (s.startsWith('http://') || s.startsWith('https://')) {
          try {
            return new URL(s).hostname.replace(/^www\./, '');
          } catch (_) { /* fall back */ }
        }
        // strip path, strip www
        s = s.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
        return s;
      } catch (e) {
        return '';
      }
    }).filter(Boolean);
    logSW('blocklist loaded, entries=', blocklist.length);
  } catch (e) {
    blocklist = [];
    warnSW('failed to load packaged blocklist.json', e);
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
    const match = !!(j && j.matches && j.matches.length > 0);
    return { match, raw: j };
  } catch (e) {
    return { error: 'sb-error', exception: String(e) };
  }
}

// Adult content heuristic (keyword-based) — used only for labeling
function detectAdultContent(url) {
  try {
    const u = new URL(url);
    const host = (u.hostname || '').toLowerCase();

    // If host is on the explicit safe whitelist, do not classify as adult.
    for (const safe of SAFE_DOMAIN_WHITELIST) {
      if (host === safe || host.endsWith('.' + safe)) {
        return false;
      }
    }

    // If TLD is .xxx, treat as adult.
    const tld = host.split('.').slice(-1)[0];
    if (tld === 'xxx') return true;

    // Conservative keyword set (only longer, specific words or high-precision short tokens)
    const keywords = new Set([
      'porn', 'xxx', 'adult', 'sex', 'fetish', 'escort', 'hentai', 'erotic', 'pornhub',
      'xnxx', 'xvideos', 'sexvideos', 'nsfw', 'camgirl', 'cams'
    ]);

    // Tokenize path and search/query string on non-alphanumeric separators
    const path = (u.pathname || '').toLowerCase();
    const query = (u.search || '').toLowerCase();

    function tokenize(s) {
      return s.split(/[^a-z0-9]+/).filter(Boolean);
    }

    const pathTokens = tokenize(path);
    const queryTokens = tokenize(query);

    // Check tokens for exact keyword matches (conservative)
    for (const t of pathTokens) {
      if (keywords.has(t)) return true;
    }
    for (const t of queryTokens) {
      if (keywords.has(t)) return true;
    }

    // Also check filename token (last segment) for keywords
    const lastSeg = path.split('/').filter(Boolean).slice(-1)[0] || '';
    if (lastSeg && keywords.has(lastSeg.toLowerCase())) return true;

    // No matches
    return false;
  } catch (e) {
    // On parse error, be conservative and return false (not adult)
    return false;
  }
}

// Message handlers: add hover analysis and direct-safe-browsing check
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return;
  (async () => {
    try {
      if (msg.type === 'CHECK_URL_SAFE_BROWSING') {
        const url = (msg.url || '').toString();
        if (!url) { sendResponse({ error: 'no-url' }); return; }
        const kobj = await chrome.storage.local.get('directApiKey');
        const apiKey = kobj && kobj.directApiKey ? kobj.directApiKey : '';
        if (!apiKey) { sendResponse({ error: 'no-api-key' }); return; }
        const sb = await callSafeBrowsingDirect(apiKey, url);
        if (sb.error) sendResponse({ error: sb.error, raw: sb });
        else if (sb.match) sendResponse({ safe: false, reason: 'Google Safe Browsing match', raw: sb.raw });
        else sendResponse({ safe: true, reason: 'No match', raw: sb.raw });
        return;
      } else if (msg.type === 'CHECK_HOST_HOVER') {
        // msg.href is the hovered URL from content script (may be relative)
        const href = (msg.href || '').toString();
        if (!href) { sendResponse({ classification: 'unknown', reason: 'no-href' }); return; }
        // resolve URL relative to page if sender.tab exists (content script should send absolute)
        let finalUrl = href;
        try {
          finalUrl = new URL(href, 'https://example.invalid').toString();
        } catch (_) {
          // fallback
          finalUrl = href;
        }
        // try to parse to get host
        let host = null;
        try { host = new URL(finalUrl).hostname; } catch (_) { host = null; }
        const hostOnly = normalizeHost(host);

        // 1) allowlist
        const st = await chrome.storage.local.get('allowlist');
        const allowlist = st && st.allowlist ? st.allowlist.map(normalizeHost) : [];
        if (allowlist.includes(hostOnly)) {
          sendResponse({ classification: 'safe', reason: 'allowlist', source: 'allowlist' });
          return;
        }

        // 2) packaged blocklist
        if (blocklist.includes(hostOnly)) {
          sendResponse({ classification: 'unsafe', reason: 'packaged blocklist', source: 'local-blocklist' });
          return;
        }

        // 3) hover cache
        const hc = hoverCache.get(hostOnly);
        if (hc && (Date.now() - hc.ts) < HOVER_CACHE_TTL_MS) {
          sendResponse({ classification: hc.classification, reason: hc.reason, source: hc.source, raw: hc.raw });
          return;
        }

        // 4) hostCache short-circuit
        const cached = getHostCacheEntry(hostOnly);
        if (cached) {
          if (!cached.safe) {
            // host previously determined unsafe
            const classification = 'unsafe';
            const reason = cached.reason || 'hostCache';
            sendResponse({ classification, reason, source: cached.source || 'hostCache' });
            // persist hoverCache
            hoverCache.set(hostOnly, { classification, reason, source: cached.source || 'hostCache', ts: Date.now(), raw: null });
            return;
          } else {
            // safe cached host
            const classification = 'safe';
            const reason = cached.reason || 'hostCache';
            hoverCache.set(hostOnly, { classification, reason, source: cached.source || 'hostCache', ts: Date.now(), raw: null });
            sendResponse({ classification, reason, source: cached.source || 'hostCache' });
            return;
          }
        }

        // 5) If API key available, call GSB (host-level cache will be filled from navigation checks too)
        const kobj2 = await chrome.storage.local.get('directApiKey');
        const apiKey = kobj2 && kobj2.directApiKey ? kobj2.directApiKey : '';
        if (apiKey) {
          const sb = await callSafeBrowsingDirect(apiKey, finalUrl);
          if (sb.error) {
            // on error, fallback to adult heuristic or unknown
            const isAdult = detectAdultContent(finalUrl);
            const classification = isAdult ? 'adult' : 'unknown';
            const reason = sb.error || 'gsb-error';
            hoverCache.set(hostOnly, { classification, reason, source: 'gsb-error', ts: Date.now(), raw: sb });
            sendResponse({ classification, reason, source: 'gsb-error', raw: sb });
            return;
          }
          if (sb.match) {
            const classification = 'unsafe';
            const reason = 'Google Safe Browsing match';
            hoverCache.set(hostOnly, { classification, reason, source: 'safebrowsing', ts: Date.now(), raw: sb.raw });
            // also update hostCache as unsafe
            setHostCacheEntry(hostOnly, false, reason, 'safebrowsing');
            sendResponse({ classification, reason, source: 'safebrowsing', raw: sb.raw });
            return;
          } else {
            // GSB says no match -> consider safe, but still detect adult
            const isAdult = detectAdultContent(finalUrl);
            const classification = isAdult ? 'adult' : 'safe';
            const reason = isAdult ? 'adult-heuristic' : 'No Safe Browsing match';
            hoverCache.set(hostOnly, { classification, reason, source: 'safebrowsing', ts: Date.now(), raw: sb.raw });
            // update hostCache as safe
            setHostCacheEntry(hostOnly, true, '', 'safebrowsing');
            sendResponse({ classification, reason, source: 'safebrowsing', raw: sb.raw });
            return;
          }
        }

        // 6) No API key: fall back to adult heuristic or unknown
        const isAdult = detectAdultContent(finalUrl);
        const classification = isAdult ? 'adult' : 'unknown';
        const reason = isAdult ? 'adult-heuristic' : 'no-api-key';
        hoverCache.set(hostOnly, { classification, reason, source: 'no-api-key', ts: Date.now(), raw: null });
        sendResponse({ classification, reason, source: 'no-api-key' });
        return;
      }
    } catch (e) {
      try { sendResponse({ classification: 'unknown', reason: String(e) }); } catch (_) {}
      return;
    }
  })();
  return true; // indicate async response
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
  logSW('hoverCache size:', hoverCache.size);
  return { storage: s, blocklistLen: blocklist.length, hostCacheSize: hostCache.size, hoverCacheSize: hoverCache.size };
}
self.debugDump = debugDump;

// init
(async function init() {
  await loadPackagedBlocklist().catch(() => {});
  await loadPersistedHostCache().catch(() => {});
  const s = await chrome.storage.local.get(['directApiKey','enabled']);
  cfg.directApiKey = s.directApiKey || '';
  cfg.enabled = s.enabled !== undefined ? s.enabled : true;
  logSW('initialized', { hasApiKey: !!cfg.directApiKey, enabled: cfg.enabled });
})();