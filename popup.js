// popup.js - enforce strict mutual exclusivity between:
// - "Use cloud lookup (Safe Browsing proxy)" and
// - "Use Google Safe Browsing only (skip local DB for navigations)"
//
// Behavior:
// - You cannot have both checked simultaneously. Checking one will automatically uncheck the other.
// - If you paste an API key, cloud lookup will be disabled (with confirmation if cloud was active).
// - If you enable cloud lookup while an API key exists, you'll be asked to confirm clearing the key.
// - Visual inline notice explains the currently active mode.

document.addEventListener('DOMContentLoaded', async () => {
  const toggle = document.getElementById('toggle');
  const useCloud = document.getElementById('useCloud');
  const useSafeOnly = document.getElementById('useSafeOnly');
  const apiKeyInput = document.getElementById('apiKey');
  const secondaryControls = document.getElementById('secondaryControls');
  const safeOnlyWarning = document.getElementById('safeOnlyWarning');
  const reportBtn = document.getElementById('reportBtn');
  const refreshFeeds = document.getElementById('refreshFeeds');
  const allowlistDiv = document.getElementById('allowlist');
  const mutualNote = document.getElementById('mutualNote');
  const modeNotice = document.getElementById('modeNotice');

  // Load stored state
  const s = await chrome.storage.local.get([
    'enabled','useCloudLookup','directApiKey','useSafeBrowsingOnly','allowlist','useDirectLookup'
  ]);
  toggle.checked = s.enabled !== undefined ? s.enabled : true;
  useCloud.checked = s.useCloudLookup || false;
  apiKeyInput.value = s.directApiKey || '';
  useSafeOnly.checked = s.useSafeBrowsingOnly || false;
  let allowlist = s.allowlist || [];

  function setSecondaryEnabled(val) {
    if (!val) secondaryControls.classList.add('disabled'); else secondaryControls.classList.remove('disabled');
  }

  // Update mode notice text
  function updateModeNotice() {
    if (useCloud.checked) {
      modeNotice.textContent = 'Active mode: Cloud lookup (proxy + feeds → Google fallback)';
      modeNotice.style.display = 'block';
    } else if (useSafeOnly.checked) {
      const hasKey = !!apiKeyInput.value.trim();
      modeNotice.textContent = hasKey
        ? 'Active mode: Direct Google Safe Browsing (using API key)'
        : 'Active mode: Google-preferred (no key provided — will fall back to proxy or heuristics)';
      modeNotice.style.display = 'block';
    } else {
      modeNotice.textContent = 'Active mode: Local heuristics + host cache (no cloud/API selected)';
      modeNotice.style.display = 'block';
    }
  }

  // Initialize UI and mutual exclusivity on load
  function applyInitialState() {
    const hasKey = !!apiKeyInput.value.trim();
    // If both somehow set in storage, prefer API key -> keep useSafeOnly, clear cloud
    if (useCloud.checked && useSafeOnly.checked) {
      if (hasKey) {
        useCloud.checked = false;
        chrome.storage.local.set({ useCloudLookup: false });
      } else {
        // prefer cloud by default if no key
        useSafeOnly.checked = false;
        chrome.storage.local.set({ useSafeBrowsingOnly: false });
      }
    }
    // Disable API input when cloud is active
    apiKeyInput.disabled = useCloud.checked;
    // Update mutual note text
    mutualNote.textContent = useCloud.checked
      ? 'Cloud lookup is enabled — direct API input is disabled.'
      : (hasKey ? 'Direct API key present — enabling it will disable cloud lookup.' : 'Note: Cloud lookup and direct API are mutually exclusive.');
    updateModeNotice();
    setSecondaryEnabled(toggle.checked);
    renderAllowlist();
    // show warning if Safe-only without key and cloud disabled
    updateSafeOnlyWarning();
  }

  applyInitialState();

  toggle.addEventListener('change', () => {
    chrome.storage.local.set({ enabled: toggle.checked });
    setSecondaryEnabled(toggle.checked);
  });

  // When user toggles cloud checkbox
  useCloud.addEventListener('change', async () => {
    const enableCloud = useCloud.checked;
    if (enableCloud) {
      // If an API key exists, confirm clearing it
      const cur = await chrome.storage.local.get(['directApiKey']);
      const storedKey = (cur && cur.directApiKey) ? cur.directApiKey.trim() : '';
      if (storedKey) {
        const ok = confirm('Enabling cloud lookup will clear the stored Safe Browsing API key. Proceed and clear the key?');
        if (!ok) {
          useCloud.checked = false;
          return;
        }
        // clear key and enable cloud
        await chrome.storage.local.set({ useCloudLookup: true, directApiKey: '', useDirectLookup: false, useSafeBrowsingOnly: false });
        apiKeyInput.value = '';
        apiKeyInput.disabled = true;
        useSafeOnly.checked = false; // cannot have both
        mutualNote.textContent = 'Cloud lookup enabled — direct API key cleared.';
        updateModeNotice();
        return;
      }
      // No key stored — enable cloud simply
      await chrome.storage.local.set({ useCloudLookup: true });
      apiKeyInput.disabled = true;
      // If Safe-only was checked, uncheck it
      if (useSafeOnly.checked) {
        useSafeOnly.checked = false;
        await chrome.storage.local.set({ useSafeBrowsingOnly: false });
      }
      mutualNote.textContent = 'Cloud lookup enabled — direct API disabled.';
      updateModeNotice();
    } else {
      // Disabling cloud -> allow API input
      await chrome.storage.local.set({ useCloudLookup: false });
      apiKeyInput.disabled = false;
      mutualNote.textContent = 'Cloud lookup disabled — you may paste a direct API key.';
      updateModeNotice();
    }
  });

  // When user toggles Safe-only checkbox, automatically deselect cloud if necessary
  useSafeOnly.addEventListener('change', async () => {
    const enableSafeOnly = useSafeOnly.checked;
    if (enableSafeOnly) {
      // If cloud is currently enabled, uncheck cloud and update storage
      if (useCloud.checked) {
        // simply uncheck cloud (no need for confirmation since user explicitly chose Safe-only)
        useCloud.checked = false;
        await chrome.storage.local.set({ useCloudLookup: false });
        apiKeyInput.disabled = false;
      }
      await chrome.storage.local.set({ useSafeBrowsingOnly: true });
    } else {
      await chrome.storage.local.set({ useSafeBrowsingOnly: false });
    }
    updateModeNotice();
    updateSafeOnlyWarning();
  });

  // API key input: when user pastes a key, disable cloud lookup after confirmation if cloud is active.
  apiKeyInput.addEventListener('input', async () => {
    const key = apiKeyInput.value.trim();
    if (key) {
      const cloudState = (await chrome.storage.local.get(['useCloudLookup'])).useCloudLookup;
      if (cloudState) {
        const ok = confirm('Providing a direct API key will disable cloud lookup (proxy). Proceed and disable cloud lookup?');
        if (!ok) {
          apiKeyInput.value = '';
          return;
        }
      }
      // Save key and ensure cloud is disabled
      await chrome.storage.local.set({ directApiKey: key, useDirectLookup: true, useCloudLookup: false });
      useCloud.checked = false;
      apiKeyInput.disabled = false;
      mutualNote.textContent = 'Direct API key present — cloud lookup disabled.';
    } else {
      // cleared key -> remove direct lookup and re-enable cloud checkbox
      await chrome.storage.local.set({ directApiKey: '', useDirectLookup: false });
      useCloud.disabled = false;
      mutualNote.textContent = 'No API key — cloud lookup may be enabled.';
    }
    updateModeNotice();
    updateSafeOnlyWarning();
  });

  refreshFeeds.addEventListener('click', async () => {
    try {
      const resp = await fetch('http://localhost:3000/refresh-feeds', { method: 'POST' });
      if (resp.ok) {
        alert('Requested feed refresh (if proxy supports it).');
      } else {
        alert('Proxy refresh request failed or proxy not reachable.');
      }
    } catch (e) {
      alert('Proxy not reachable on http://localhost:3000');
    }
  });

  reportBtn.addEventListener('click', async () => {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (!tab || !tab.url) { alert('No active tab URL found.'); return; }
      const reportUrl = 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + encodeURIComponent(tab.url);
      chrome.tabs.create({ url: reportUrl });
    } catch (e) {
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
      row.style.display = 'flex';
      row.style.justifyContent = 'space-between';
      row.style.padding = '6px 0';
      const s = document.createElement('span'); s.textContent = h;
      const btn = document.createElement('button'); btn.textContent = 'Remove'; btn.className = 'btn-muted';
      btn.disabled = !toggle.checked;
      btn.addEventListener('click', async () => {
        allowlist = allowlist.filter(x => x !== h);
        await chrome.storage.local.set({ allowlist });
        renderAllowlist();
      });
      row.appendChild(s); row.appendChild(btn);
      allowlistDiv.appendChild(row);
    });
  }

  // updateSafeOnlyWarning is async so it can check storage/cloud status
  async function updateSafeOnlyWarning() {
    const hasKey = !!apiKeyInput.value.trim();
    const s = await chrome.storage.local.get('useCloudLookup');
    const cloud = !!s.useCloudLookup;
    if (useSafeOnly.checked && !hasKey && !cloud) {
      safeOnlyWarning.style.display = 'block';
    } else {
      safeOnlyWarning.style.display = 'none';
    }
  }

});