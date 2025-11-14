// popup.js - updated UI for Anti-Phish Guard
// - Added "Use Google Safe Browsing only" toggle that saves useSafeBrowsingOnly
// - Warns user if they enable it without a direct API key

document.addEventListener('DOMContentLoaded', async () => {
  const toggle = document.getElementById('toggle');
  const useCloud = document.getElementById('useCloud');
  const useDirect = document.getElementById('useDirect');
  const apiKeyInput = document.getElementById('apiKey');
  const allowlistDiv = document.getElementById('allowlist');
  const reportBtn = document.getElementById('reportBtn');
  const refreshFeeds = document.getElementById('refreshFeeds');
  const useSafeOnly = document.getElementById('useSafeOnly');
  const safeOnlyWarning = document.getElementById('safeOnlyWarning');

  const PROXY_REPORT_ENDPOINT = 'http://localhost:3000/report'; // best-effort; proxy may not implement

  // load state
  const s = await chrome.storage.local.get(['enabled','allowlist','useCloudLookup','useDirectLookup','directApiKey','useSafeBrowsingOnly']);
  toggle.checked = s.enabled !== undefined ? s.enabled : true;
  useCloud.checked = s.useCloudLookup || false;
  useDirect.checked = s.useDirectLookup || false;
  apiKeyInput.value = s.directApiKey || '';
  useSafeOnly.checked = s.useSafeBrowsingOnly || false;
  let allowlist = s.allowlist || [];
  renderAllowlist();
  updateSafeOnlyWarning();

  toggle.addEventListener('change', () => {
    chrome.storage.local.set({enabled: toggle.checked});
  });

  useCloud.addEventListener('change', () => {
    chrome.storage.local.set({useCloudLookup: useCloud.checked});
  });

  useDirect.addEventListener('change', () => {
    chrome.storage.local.set({useDirectLookup: useDirect.checked});
    updateSafeOnlyWarning();
  });

  apiKeyInput.addEventListener('input', () => {
    chrome.storage.local.set({directApiKey: apiKeyInput.value});
    updateSafeOnlyWarning();
  });

  useSafeOnly.addEventListener('change', () => {
    const v = useSafeOnly.checked;
    chrome.storage.local.set({useSafeBrowsingOnly: v});
    updateSafeOnlyWarning();
    if (v && !apiKeyInput.value && !useDirect.checked) {
      // guide user to enable direct lookup & paste key
      alert('To ensure "Google-only" checks, enable "Use direct lookup" and paste a Safe Browsing API key. Without a direct key, the extension may fall back to the proxy which could consult local feeds.');
    }
  });

  // Refresh feeds: best-effort ping to proxy to ask it to reload feeds (proxy may choose to implement)
  refreshFeeds.addEventListener('click', async () => {
    try {
      const resp = await fetch('http://localhost:3000/health');
      if (!resp.ok) {
        alert('Proxy not reachable on http://localhost:3000');
        return;
      }
      try {
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
      const reportUrl = 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + encodeURIComponent(url);
      chrome.tabs.create({ url: reportUrl });

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

  function updateSafeOnlyWarning() {
    const hasKey = !!apiKeyInput.value;
    const directEnabled = useDirect.checked;
    if (useSafeOnly.checked && !hasKey && !directEnabled) {
      safeOnlyWarning.style.display = 'block';
    } else {
      safeOnlyWarning.style.display = 'none';
    }
  }
});