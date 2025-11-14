// popup.js - updated UI for Anti-Phish Guard
// - removed "Allow current site" button
// - added "Report this website" button that opens Google's report page and also POSTs to proxy /report (best-effort)

document.addEventListener('DOMContentLoaded', async () => {
  const toggle = document.getElementById('toggle');
  const useCloud = document.getElementById('useCloud');
  const useDirect = document.getElementById('useDirect');
  const apiKeyInput = document.getElementById('apiKey');
  const allowlistDiv = document.getElementById('allowlist');
  const reportBtn = document.getElementById('reportBtn');
  const refreshFeeds = document.getElementById('refreshFeeds');

  const PROXY_REPORT_ENDPOINT = 'http://localhost:3000/report'; // best-effort; proxy may not implement

  // load state
  const s = await chrome.storage.local.get(['enabled','allowlist','useCloudLookup','useDirectLookup','directApiKey']);
  toggle.checked = s.enabled !== undefined ? s.enabled : true;
  useCloud.checked = s.useCloudLookup || false;
  useDirect.checked = s.useDirectLookup || false;
  apiKeyInput.value = s.directApiKey || '';
  let allowlist = s.allowlist || [];
  renderAllowlist();

  toggle.addEventListener('change', () => {
    chrome.storage.local.set({enabled: toggle.checked});
  });

  useCloud.addEventListener('change', () => {
    chrome.storage.local.set({useCloudLookup: useCloud.checked});
  });

  useDirect.addEventListener('change', () => {
    chrome.storage.local.set({useDirectLookup: useDirect.checked});
  });

  apiKeyInput.addEventListener('input', () => {
    chrome.storage.local.set({directApiKey: apiKeyInput.value});
  });

  // Refresh feeds: best-effort ping to proxy to ask it to reload feeds (proxy may choose to implement)
  refreshFeeds.addEventListener('click', async () => {
    try {
      const resp = await fetch('http://localhost:3000/health');
      if (!resp.ok) {
        alert('Proxy not reachable on http://localhost:3000');
        return;
      }
      // Try calling a reload endpoint if the proxy offers it; fallback to health response
      try {
        // If your proxy has a refresh endpoint, it can be called here:
        await fetch('http://localhost:3000/refresh-feeds', { method: 'POST' });
        alert('Requested feed refresh (proxy must support /refresh-feeds).');
      } catch (e) {
        alert('Proxy is reachable. If you want to refresh feeds, run the updater on the server.');
      }
    } catch (e) {
      alert('Proxy not reachable on http://localhost:3000');
    }
  });

  // Report this website: open Google Safe Browsing report form in a new tab and POST to local proxy /report (best-effort)
  reportBtn.addEventListener('click', async () => {
    try {
      const tabs = await chrome.tabs.query({active: true, currentWindow: true});
      const tab = tabs[0];
      if (!tab || !tab.url) {
        alert('No active tab URL found.');
        return;
      }
      const url = tab.url;
      // Open Google's Safe Browsing report form pre-filled
      const reportUrl = 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + encodeURIComponent(url);
      chrome.tabs.create({ url: reportUrl });

      // Best-effort: send host-only report to local proxy for centralized reporting (proxy must implement POST /report).
      let host = null;
      try { host = new URL(url).hostname.toLowerCase(); } catch (e) { host = null; }
      if (host) {
        try {
          await fetch(PROXY_REPORT_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timestamp: new Date().toISOString(), host })
          });
        } catch (e) {
          // ignore if proxy doesn't implement /report or is unreachable
          console.warn('Proxy report failed (ignored)', e);
        }
      }
    } catch (e) {
      console.error('Report failed', e);
      alert('Report failed: ' + String(e));
    }
  });

  function renderAllowlist() {
    if (!allowlist.length) {
      allowlistDiv.textContent = '(none)';
      return;
    }
    allowlistDiv.innerHTML = '';
    allowlist.forEach(h => {
      const row = document.createElement('div');
      row.className = 'host-row';
      const span = document.createElement('span');
      span.textContent = h;
      const rm = document.createElement('button');
      rm.textContent = 'Remove';
      rm.className = 'btn-muted';
      rm.addEventListener('click', async () => {
        allowlist = allowlist.filter(x => x !== h);
        await chrome.storage.local.set({allowlist});
        renderAllowlist();
      });
      row.appendChild(span);
      row.appendChild(rm);
      allowlistDiv.appendChild(row);
    });
  }
});