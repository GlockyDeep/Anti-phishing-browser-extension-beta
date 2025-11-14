// server.js
// Safe Browsing proxy + OpenPhish feed fetching + local URLhaus hostlist (read-only).
// Added: safebrowsing_used flag on /check responses; /log prints apiUsed when present.
//
// Usage:
//   NODE_API_KEY=YOUR_GOOGLE_KEY node server.js
// Optional:
//   PHISHTANK_API_KEY=YOUR_PHISHTANK_KEY node server.js

const express = require('express');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const app = express();

const API_KEY = process.env.NODE_API_KEY; // Google Safe Browsing
const PHISHTANK_KEY = process.env.PHISHTANK_API_KEY; // Optional PhishTank app_key
if (!API_KEY) {
  console.error('Set NODE_API_KEY env var and restart: NODE_API_KEY=YOUR_KEY node server.js');
  process.exit(1);
}

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const URLHAUS_HOSTS_PATH = path.join(DATA_DIR, 'urlhaus_hosts.txt'); // local file only (read-only)
const OPENPHISH_URL = 'https://openphish.com/feed.txt';

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

app.use(express.json({ limit: '64kb' }));

// Simple in-memory cache and config
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes for check results
const cache = new Map();
let feedHostSet = new Set();
let feedsLastLoaded = 0;

const FEED_UPDATE_INTERVAL_MS = 10 * 60 * 1000; // refresh every 10 minutes (OpenPhish only)
let lastFeedUpdateTs = 0;

// Helper: extract hostname from a URL string
function hostnameFromUrl(urlStr) {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch (e) {
    return null;
  }
}

// Fetch OpenPhish feed (plain text, one URL per line)
async function fetchOpenPhishFeed() {
  try {
    const resp = await fetch(OPENPHISH_URL, { method: 'GET' });
    if (!resp.ok) {
      console.warn('OpenPhish fetch non-OK', resp.status);
      return [];
    }
    const txt = await resp.text();
    const lines = txt.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const hosts = lines.map(hostnameFromUrl).filter(Boolean);
    return hosts;
  } catch (err) {
    console.warn('OpenPhish fetch failed', err);
    return [];
  }
}

// Read local URLhaus hosts (no network). Returns array of hosts.
function readLocalUrlhausHosts() {
  try {
    if (!fs.existsSync(URLHAUS_HOSTS_PATH)) return [];
    const txt = fs.readFileSync(URLHAUS_HOSTS_PATH, 'utf8');
    const lines = txt.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    return lines.map(h => h.toLowerCase());
  } catch (e) {
    console.warn('Failed to read local urlhaus hosts file', e);
    return [];
  }
}

// Update feeds: fetch OpenPhish, load local URLhaus file, merge into in-memory set (read-only file behavior).
async function updateFeeds() {
  try {
    console.log('[Proxy] Updating OpenPhish and reloading local URLhaus hosts (read-only)...');

    // fetch OpenPhish
    const openHosts = await fetchOpenPhishFeed();

    // read local URLhaus hosts file (if present)
    const localUrlhausHosts = readLocalUrlhausHosts();

    // merge into in-memory set only
    const merged = new Set();
    for (const h of openHosts) merged.add(h);
    for (const h of localUrlhausHosts) merged.add(h);

    feedHostSet = new Set(Array.from(merged));
    feedsLastLoaded = Date.now();
    lastFeedUpdateTs = Date.now();

    console.log(`[Proxy] Feeds updated: OpenPhish ${openHosts.length}, local URLhaus ${localUrlhausHosts.length}, total hosts ${feedHostSet.size}`);
    return { ok: true, openphish: openHosts.length, localUrlhaus: localUrlhausHosts.length, total: feedHostSet.size };
  } catch (err) {
    console.warn('[Proxy] updateFeeds failed', err);
    return { ok: false, error: err && err.message ? err.message : String(err) };
  }
}

// Kick off initial update and periodic refresh (OpenPhish only)
(async () => {
  try {
    await updateFeeds();
  } catch (e) {
    console.warn('Initial feed update failed', e);
  }
})();
setInterval(() => {
  updateFeeds().catch(e => console.warn('Scheduled feed update failed', e));
}, FEED_UPDATE_INTERVAL_MS);

// helper to check host in set with suffix matching
function findMatchingHostInSet(host) {
  if (!host) return null;
  host = host.toLowerCase();
  if (feedHostSet.has(host)) return host;
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const suffix = parts.slice(i).join('.');
    if (feedHostSet.has(suffix)) return suffix;
  }
  return null;
}

// -- Safe Browsing body builder --
function buildSafeBrowsingBody(url) {
  return {
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
}

// helper for PhishTank (optional)
async function checkPhishTank(url) {
  if (!PHISHTANK_KEY) return null;
  try {
    const form = new URLSearchParams();
    form.append('url', url);
    form.append('format', 'json');
    form.append('app_key', PHISHTANK_KEY);

    const ptResp = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString()
    });

    if (!ptResp.ok) {
      const text = await ptResp.text();
      console.warn('PhishTank non-OK response', ptResp.status, text);
      return { error: `non-OK ${ptResp.status}` };
    }
    const ptJson = await ptResp.json();
    return ptJson.results || null;
  } catch (err) {
    console.warn('PhishTank request failed', err);
    return { error: err && err.message ? err.message : String(err) };
  }
}

// POST /refresh-feeds - manual trigger to refresh OpenPhish and reload local URLhaus file (read-only)
app.post('/refresh-feeds', async (req, res) => {
  setCorsHeaders(res);
  try {
    const now = Date.now();
    // Avoid extremely frequent manual refreshes (2s)
    if ((now - lastFeedUpdateTs) < 2000) {
      return res.json({ ok: false, reason: 'rate_limited', lastUpdateMsAgo: now - lastFeedUpdateTs });
    }
    const r = await updateFeeds();
    return res.json(r);
  } catch (e) {
    console.warn('Manual refresh failed', e);
    return res.status(500).json({ ok: false, error: e && e.message ? e.message : String(e) });
  }
});

// GET /checkHost?host=...  <-- host-only checks (used by hover)
app.options('/checkHost', (req, res) => {
  setCorsHeaders(res);
  res.sendStatus(204);
});
app.get('/checkHost', (req, res) => {
  setCorsHeaders(res);
  const host = (req.query.host || '').toString().toLowerCase().trim();
  if (!host) return res.status(400).json({ error: 'missing host' });
  try {
    const matched = findMatchingHostInSet(host);
    if (matched) {
      return res.json({ unsafe: true, matchedHost: matched, source: 'feeds', safebrowsing_used: false });
    }
    return res.json({ unsafe: false, safebrowsing_used: false });
  } catch (e) {
    console.warn('checkHost failed', e);
    return res.status(500).json({ error: 'checkHost failed' });
  }
});

// POST /log - receive navigation/hover logs and print host-only to console
app.post('/log', (req, res) => {
  setCorsHeaders(res);
  try {
    const body = req.body || {};
    let host = null;
    if (body.host) {
      host = String(body.host).toLowerCase();
    } else if (body.url) {
      try { host = new URL(String(body.url)).hostname.toLowerCase(); } catch (e) { host = '<invalid-host>'; }
    } else {
      host = '<no-host>';
    }

    const ts = body.timestamp || new Date().toISOString();
    const tabId = body.tabId !== undefined ? String(body.tabId) : '-';
    const blocked = !!body.blocked;
    const reason = body.reason || '';
    const event = body.event || 'visit';
    const heuristicsOnly = !!body.heuristicsOnly;
    const apiUsed = body.apiUsed === true;
    const extra = body.extra || null;

    const parts = [
      `[NAV] ${ts}`,
      `event=${event}`,
      `tab=${tabId}`,
      `host=${host}`,
      `blocked=${blocked}`,
      apiUsed ? `apiUsed=true` : `apiUsed=false`,
      reason ? `reason=${reason}` : '',
      heuristicsOnly ? `heuristicsOnly=true` : '',
      extra ? `extra=${JSON.stringify(extra)}` : ''
    ].filter(Boolean).join(' | ');

    console.log(parts);
    // append host-only to navigation_hosts.log
    try {
      const logPath = path.join(DATA_DIR, 'navigation_hosts.log');
      fs.appendFileSync(logPath, parts + '\n', 'utf8');
    } catch (e) {
      // ignore
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('Error handling /log', e);
    res.status(500).json({ error: 'log failed' });
  }
});

// GET /check?url=...
app.options('/check', (req, res) => {
  setCorsHeaders(res);
  res.sendStatus(204);
});

app.get('/check', async (req, res) => {
  setCorsHeaders(res);

  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'missing url' });

  const key = String(url);
  const now = Date.now();

  // cache check
  const c = cache.get(key);
  if (c && (now - c.ts) < CACHE_TTL_MS) {
    // preserve safebrowsing_used if cached
    return res.json({ safe: c.safe, matches: c.matches, cached: true, safebrowsing_used: !!c.safebrowsing_used });
  }

  let combinedMatches = { feeds: null, safebrowsing: null, phishtank: null };
  let safe = true;
  let safebrowsing_used = false; // will be true only if we call Google Safe Browsing

  // 1) Quick local check: merged feeds (OpenPhish + local URLhaus in-memory)
  try {
    const host = (() => {
      try { return new URL(url).hostname.toLowerCase(); } catch (e) { return null; }
    })();

    if (host) {
      const matchedHost = findMatchingHostInSet(host);
      if (matchedHost) {
        combinedMatches.feeds = { matchedHost, source: 'feeds' };
        safe = false;
        cache.set(key, { safe, matches: combinedMatches, ts: Date.now(), safebrowsing_used: false });
        return res.json({ safe, matches: combinedMatches, cached: false, safebrowsing_used: false });
      }
    }
  } catch (e) {
    console.warn('Local feeds check failed', e);
  }

  // 2) Google Safe Browsing (only if local feeds didn't match)
  try {
    safebrowsing_used = true;
    const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildSafeBrowsingBody(url)),
    });
    if (!resp.ok) {
      const text = await resp.text();
      console.error('Safe Browsing non-OK response', resp.status, text);
      // treat as safe for now but indicate safebrowsing_used
      cache.set(key, { safe: true, matches: combinedMatches, ts: Date.now(), safebrowsing_used: safebrowsing_used });
      return res.json({ safe: true, matches: combinedMatches, cached: false, safebrowsing_used });
    }
    const j = await resp.json();
    const sbMatches = j.matches || null;
    combinedMatches.safebrowsing = sbMatches;
    if (sbMatches) {
      safe = false;
      cache.set(key, { safe, matches: combinedMatches, ts: Date.now(), safebrowsing_used });
      return res.json({ safe, matches: combinedMatches, cached: false, safebrowsing_used: safebrowsing_used });
    }
  } catch (err) {
    console.error('Safe Browsing request failed', err);
    // On SB failure, return safe:true but indicate SB was attempted
    cache.set(key, { safe: true, matches: combinedMatches, ts: Date.now(), safebrowsing_used });
    return res.json({ safe: true, matches: combinedMatches, cached: false, safebrowsing_used });
  }

  // 3) Optional PhishTank
  if (PHISHTANK_KEY) {
    try {
      const pt = await checkPhishTank(url);
      combinedMatches.phishtank = pt;
      if (pt && pt.in_database && pt.valid) {
        safe = false;
        cache.set(key, { safe, matches: combinedMatches, ts: Date.now(), safebrowsing_used });
        return res.json({ safe, matches: combinedMatches, cached: false, safebrowsing_used });
      }
    } catch (e) {
      console.warn('PhishTank check failed', e);
    }
  }

  // no matches -> safe
  cache.set(key, { safe, matches: combinedMatches, ts: Date.now(), safebrowsing_used });
  return res.json({ safe, matches: combinedMatches, cached: false, safebrowsing_used });
});

// Health endpoint
app.get('/health', (req, res) => {
  setCorsHeaders(res);
  res.json({
    ok: true,
    phishtankConfigured: !!PHISHTANK_KEY,
    feedsCount: feedHostSet.size,
    feedsLoadedAt: feedsLastLoaded || null,
    lastFeedUpdateMsAgo: Date.now() - (lastFeedUpdateTs || 0)
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SafeBrowsing proxy listening on http://localhost:${PORT} (feeds loaded: ${feedHostSet.size})`));