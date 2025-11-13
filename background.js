// background.js - MV3 service worker with host-only logging to proxy
// Now extracts hostname only and sends that to the proxy/log endpoint (no path/query).
// WARNING: logs are still sensitive (hostnames visited). Keep enabled only for testing.

const SUSPICIOUS_TLDS = ['tk','ml','ga','cf','gq'];
let blocklist = [];
let enabled = true;
let allowlist = [];
let useCloudLookup = false; // persisted in storage
let useDirectLookup = false;
let directApiKey = '';

const PROXY_LOG_ENDPOINT = 'http://localhost:3000/log';

function logSW(...args) { console.log('[PreVisit SW]', ...args); }
function warnSW(...args) { console.warn('[PreVisit SW]', ...args); }
function errorSW(...args) { console.error('[PreVisit SW]', ...args); }

async function loadState() {
  try {
    const s = await chrome.storage.local.get(['enabled','allowlist','useCloudLookup','useDirectLookup','directApiKey']);
    enabled = s.enabled !== undefined ? s.enabled : true;
    allowlist = s.allowlist || [];
    useCloudLookup = s.useCloudLookup || false;
    useDirectLookup = s.useDirectLookup || false;
    directApiKey = s.directApiKey || '';
    const resp = await fetch(chrome.runtime.getURL('blocklist.json'));
    blocklist = await resp.json();
    logSW('state loaded', { enabled, allowlistLen: allowlist.length, useCloudLookup, useDirectLookup });
  } catch (e) {
    warnSW('loadState failed, using defaults', e);
    enabled = true;
    allowlist = [];
    useCloudLookup = false;
    useDirectLookup = false;
    blocklist = [];
  }
}

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
    warnSW('heuristic parse failed', e);
  }
  return null;
}

async function checkWithProxy(url) {
  try {
    const encoded = encodeURIComponent(url);
    const resp = await fetch(`http://localhost:3000/check?url=${encoded}`, { method: 'GET' });
    if (!resp.ok) {
      warnSW('Proxy lookup failed', resp.status);
      return null;
    }
    const json = await resp.json();
    if (json.safe === false) {
      return 'Matches Google Safe Browsing (proxy) or feed';
    }
    return null;
  } catch (e) {
    warnSW('Proxy lookup error', e);
    return null;
  }
}

async function checkWithSafeBrowsingDirect(apiKey, url) {
  if (!apiKey) return null;
  const body = {
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
    warnSW('Safe Browsing direct lookup error', e);
    return null;
  }
}

// send navigation log to proxy /log — host-only
async function sendLogToProxyHostOnly(logObj) {
  try {
    // Ensure we send only the host field
    const payload = {
      timestamp: logObj.timestamp,
      tabId: logObj.tabId,
      host: logObj.host,            // host only
      blocked: !!logObj.blocked,
      reason: logObj.reason || '',
      heuristicsOnly: !!logObj.heuristicsOnly,
      extra: logObj.extra || null
    };
    // best effort; do not block navigation on logging
    await fetch(PROXY_LOG_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    // ignore logging errors but print SW console
    warnSW('sendLogToProxyHostOnly failed', e);
  }
}

async function onBeforeNavigate(details) {
  try {
    if (details.frameId !== 0) return;
    if (!enabled) return;
    if (!details.url) return;
    if (details.url.startsWith(chrome.runtime.getURL('warning.html'))) return;

    // Extract host only
    let hostOnly = '<invalid-host>';
    try { hostOnly = new URL(details.url).hostname.toLowerCase(); } catch (e) { /* leave placeholder */ }

    logSW('onBeforeNavigate host=', hostOnly, 'tabId=' + details.tabId);

    // run local heuristics using full url but reasons are host-related; keep heuristics unchanged
    let reason = runHeuristics(details.url);

    if (!reason && useCloudLookup) {
      const cloudReason = await checkWithProxy(details.url);
      if (cloudReason) reason = cloudReason;
    }

    if (!reason && useDirectLookup && directApiKey) {
      const directReason = await checkWithSafeBrowsingDirect(directApiKey, details.url);
      if (directReason) reason = directReason;
    }

    const blocked = !!reason;

    // Log to SW console host-only
    logSW('NAV HOST LOG', { ts: new Date().toISOString(), tabId: details.tabId, host: hostOnly, blocked, reason });

    // Send host-only to proxy (best-effort)
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
      } catch (tabErr) {
        errorSW('chrome.tabs.update failed', tabErr);
      }
    }
  } catch (err) {
    errorSW('onBeforeNavigate unexpected error', err);
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(
  onBeforeNavigate,
  { url: [{ schemes: ['http','https'] }] }
);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local') {
    if (changes.enabled) enabled = changes.enabled.newValue;
    if (changes.allowlist) allowlist = changes.allowlist.newValue || [];
    if (changes.useCloudLookup) useCloudLookup = changes.useCloudLookup.newValue || false;
    if (changes.useDirectLookup) useDirectLookup = changes.useDirectLookup.newValue || false;
    if (changes.directApiKey) directApiKey = changes.directApiKey.newValue || '';
  }
});

// initialize
loadState();
chrome.runtime.onInstalled.addListener(loadState);