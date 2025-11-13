// server.js
// Safe Browsing proxy + URLhaus checks with host-only logging (no paths/queries).
//
// Usage (local demo):
//   NODE_API_KEY=YOUR_GOOGLE_KEY [PHISHTANK_API_KEY=YOUR_KEY] node server.js
//
// It expects server/data/urlhaus_hosts.txt to exist (one hostname per line).
// You can create that with: node update_urlhaus.js

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

// Simple in-memory cache: key -> { safe: boolean, matches: object|null, ts }
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const cache = new Map();

// URLhaus hosts data
const URLHAUS_HOSTS_PATH = path.join(__dirname, 'data', 'urlhaus_hosts.txt');
let urlhausSet = new Set();
let urlhausLastLoaded = 0;

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// parse JSON bodies for POST /log
app.use(express.json({ limit: '64kb' }));

function loadUrlhausHosts() {
  try {
    if (!fs.existsSync(URLHAUS_HOSTS_PATH)) {
      console.warn('URLhaus hosts file not found at', URLHAUS_HOSTS_PATH);
      urlhausSet = new Set();
      urlhausLastLoaded = Date.now();
      return;
    }
    const txt = fs.readFileSync(URLHAUS_HOSTS_PATH, 'utf8');
    const lines = txt.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    urlhausSet = new Set(lines);
    urlhausLastLoaded = Date.now();
    console.log(`Loaded urlhaus hosts: ${urlhausSet.size} entries from ${URLHAUS_HOSTS_PATH}`);
  } catch (e) {
    console.warn('Failed to load urlhaus hosts', e);
    urlhausSet = new Set();
  }
}

// helper to check host and suffixes (so sub.example.com triggers example.com if present)
function findMatchingHostInSet(host) {
  if (!host) return null;
  host = host.toLowerCase();
  if (urlhausSet.has(host)) return host;
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const suffix = parts.slice(i).join('.');
    if (urlhausSet.has(suffix)) return suffix;
  }
  return null;
}

// initial load and periodic reload
loadUrlhausHosts();
setInterval(loadUrlhausHosts, 10 * 60 * 1000);

// -- Safe Browsing body builder --
function buildSafeBrowsingBody(url) {
  return {
    client: { clientId: 'previsit-ext', clientVersion: '1.0.0' },
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
    const ptResults = ptJson.results || null;
    return ptResults;
  } catch (err) {
    console.warn('PhishTank request failed', err);
    return { error: err && err.message ? err.message : String(err) };
  }
}

// POST /log - receive navigation logs from the extension and print host-only to console
app.post('/log', (req, res) => {
  setCorsHeaders(res);
  try {
    const body = req.body || {};
    // Accept either host field (preferred) or url and derive host; always store/print only the host
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
    const heuristicsOnly = !!body.heuristicsOnly;
    const extra = body.extra || null;

    // Compose a readable log line but only include host (no path/query)
    const parts = [
      `[NAV] ${ts}`,
      `tab=${tabId}`,
      `host=${host}`,
      `blocked=${blocked}`,
      reason ? `reason=${reason}` : '',
      heuristicsOnly ? `heuristicsOnly=true` : '',
      extra ? `extra=${JSON.stringify(extra)}` : ''
    ].filter(Boolean).join(' | ');

    console.log(parts);
    // Optionally append to server/data/navigation_hosts.log (host-only)
    try {
      const logPath = path.join(__dirname, 'data', 'navigation_hosts.log');
      fs.appendFileSync(logPath, parts + '\n', 'utf8');
    } catch (e) {
      // ignore file errors
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('Error handling /log', e);
    res.status(500).json({ error: 'log failed' });
  }
});

// main /check endpoint
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
    return res.json({ safe: c.safe, matches: c.matches, cached: true });
  }

  // 1) Quick local check: URLhaus hostlist
  let combinedMatches = { urlhaus: null, safebrowsing: null, phishtank: null };
  try {
    const host = (() => {
      try { return new URL(url).hostname.toLowerCase(); } catch (e) { return null; }
    })();

    if (host) {
      const matchedHost = findMatchingHostInSet(host);
      if (matchedHost) {
        combinedMatches.urlhaus = { matchedHost };
        const safe = false;
        cache.set(key, { safe, matches: combinedMatches, ts: Date.now() });
        return res.json({ safe, matches: combinedMatches, cached: false });
      }
    }
  } catch (e) {
    console.warn('Local urlhaus check failed', e);
  }

  // 2) Safe Browsing lookup
  try {
    const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildSafeBrowsingBody(url)),
    });
    if (!resp.ok) {
      const text = await resp.text();
      console.error('Safe Browsing non-OK response', resp.status, text);
      return res.status(500).json({ error: 'safe browsing lookup failed' });
    }
    const j = await resp.json();
    const sbMatches = j.matches || null;
    combinedMatches.safebrowsing = sbMatches;
    if (sbMatches) {
      const safe = false;
      cache.set(key, { safe, matches: combinedMatches, ts: Date.now() });
      return res.json({ safe, matches: combinedMatches, cached: false });
    }
  } catch (err) {
    console.error('Safe Browsing request failed', err);
    return res.status(500).json({ error: 'safe browsing lookup failed' });
  }

  // 3) Optional PhishTank lookup
  if (PHISHTANK_KEY) {
    try {
      const pt = await checkPhishTank(url);
      combinedMatches.phishtank = pt;
      if (pt && pt.in_database && pt.valid) {
        const safe = false;
        cache.set(key, { safe, matches: combinedMatches, ts: Date.now() });
        return res.json({ safe, matches: combinedMatches, cached: false });
      }
    } catch (e) {
      console.warn('PhishTank check failed', e);
      // continue; we consider phishtank optional
    }
  }

  // If no matches -> safe
  const safe = true;
  cache.set(key, { safe, matches: combinedMatches, ts: Date.now() });
  return res.json({ safe, matches: combinedMatches, cached: false });
});

app.get('/health', (req, res) => {
  setCorsHeaders(res);
  res.json({ ok: true, urlhausLoadedAt: urlhausLastLoaded || null, urlhausCount: urlhausSet.size, phishtankConfigured: !!PHISHTANK_KEY });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SafeBrowsing proxy listening on http://localhost:${PORT} (URLhaus hosts: ${urlhausSet.size})`));