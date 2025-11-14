// popup.js - updated popup logic to allow enabling cloud lookup even when an API key exists
// - If you try to enable "Use cloud lookup" while a direct API key is present, prompt to confirm clearing the key.
// - Keeps mutual exclusivity (cloud vs direct) but gives user control to switch modes.
// - Prevents enabling strict Safe-only without a key.

document.addEventListener('DOMContentLoaded', async () => {
  const toggle = document.getElementById('toggle');
  const useCloud = document.getElementById('useCloud');
  const useSafeOnly = document.getElementById('useSafeOnly');
  const apiKeyInput = document.getElementById('apiKey');
  const strictSafeOnly = document.getElementById('strictSafeOnly');
  const preferGoogleFirst = document.getElementById('preferGoogleFirst');
  const secondaryControls = document.getElementById('secondaryControls');
  const safeOnlyWarning = document.getElementById('safeOnlyWarning');
  const reportBtn = document.getElementById('reportBtn');
  const refreshFeeds = document.getElementById('refreshFeeds');
  const allowlistDiv = document.getElementById('allowlist');
  const mutualNote = document.getElementById('mutualNote');

  // load state
  const s = await chrome.storage.local.get([
    'enabled','useCloudLookup','directApiKey','useSafeBrowsingOnly',
    'useSafeBrowsingOnlyStrict','preferGoogleFirst','allowlist','useDirectLookup'
  ]);
  toggle.checked = s.enabled !== undefined ? s.enabled : true;
  useCloud.checked = s.useCloudLookup || false;
  apiKeyInput.value = s.directApiKey || '';
  useSafeOnly.checked = s.useSafeBrowsingOnly || false;
  strictSafeOnly.checked = s.useSafeBrowsingOnlyStrict || false;
  preferGoogleFirst.checked = s.preferGoogleFirst || false;
  let allowlist = s.allowlist || [];

  function setSecondaryEnabled(val) {
    if (!val) secondaryControls.classList.add('disabled'); else secondaryControls.classList.remove('disabled');
  }

  // Initialize mutual-exclusivity and UI state
  function applyMutualExclusivityOnLoad() {
    const hasKey = !!apiKeyInput.value.trim();
    // If cloud is checked but key exists, prefer cloud but clear key (to keep storage consistent)
    if (useCloud.checked && hasKey) {
      // clear key silently on load if cloud is checked
      apiKeyInput.value = '';
      chrome.storage.local.set({ directApiKey: '', useDirectLookup: false });
    }
    // If cloud is checked -> disable api input
    apiKeyInput.disabled = useCloud.checked;
    strictSafeOnly.disabled = useCloud.checked; // strict mode only meaningful with direct API
    // If API key present -> disable cloud checkbox (but we allow explicit override when user clicks)
    useCloud.disabled = false; // we'll enforce mutual exclusivity via handlers and prompts, not by permanently disabling the control
    mutualNote.textContent = useCloud.checked
      ? 'Cloud lookup is enabled — direct API is disabled.'
      : (hasKey ? 'Direct API key present — cloud lookup will clear the key when enabled.' : 'Note: Cloud lookup and direct API are mutually exclusive.');
  }

  applyMutualExclusivityOnLoad();
  setSecondaryEnabled(toggle.checked);
  renderAllowlist();
  updateSafeOnlyWarning();

  toggle.addEventListener('change', () => {
    chrome.storage.local.set({ enabled: toggle.checked });
    setSecondaryEnabled(toggle.checked);
  });

  // When user toggles cloud checkbox
  useCloud.addEventListener('change', async () => {
    const val = useCloud.checked;

    // If enabling cloud and there's a stored API key, confirm with user first
    if (val) {
      const current = await chrome.storage.local.get(['directApiKey']);
      const storedKey = (current && current.directApiKey) ? current.directApiKey.trim() : '';
      if (storedKey) {
        const ok = confirm('Enabling cloud lookup will clear the stored Safe Browsing API key. Proceed and clear the key?');
        if (!ok) {
          // revert checkbox
          useCloud.checked = false;
          return;
        }
        // user confirmed: clear key and enable cloud
        await chrome.storage.local.set({ useCloudLookup: true, directApiKey: '', useDirectLookup: false, useSafeBrowsingOnlyStrict: false });
        apiKeyInput.value = '';
        apiKeyInput.disabled = true;
        strictSafeOnly.checked = false;
        strictSafeOnly.disabled = true;
        mutualNote.textContent = 'Cloud lookup enabled — direct API key cleared.';
        return;
      }
      // no stored key -> just enable cloud
      chrome.storage.local.set({ useCloudLookup: true });
      apiKeyInput.disabled = true;
      strictSafeOnly.disabled = true;
      mutualNote.textContent = 'Cloud lookup enabled — direct API disabled.';
    } else {
      // disabling cloud -> allow user to supply an API key again
      chrome.storage.local.set({ useCloudLookup: false });
      apiKeyInput.disabled = false;
      strictSafeOnly.disabled = false;
      mutualNote.textContent = 'Cloud lookup disabled — you may paste a direct API key.';
    }
  });

  // API key input: when user pastes a key, disable cloud lookup after confirmation.
  apiKeyInput.addEventListener('input', async () => {
    const key = apiKeyInput.value.trim();
    if (key) {
      // If cloud is currently enabled, prompt user before disabling cloud and saving key
      const cloudState = (await chrome.storage.local.get(['useCloudLookup'])).useCloudLookup;
      if (cloudState) {
        const ok = confirm('Providing a direct API key will disable cloud lookup (proxy). Proceed and disable cloud lookup?');
        if (!ok) {
          // revert input to empty to avoid accidental overwrite
          apiKeyInput.value = '';
          return;
        }
      }
      // Save key and ensure cloud is disabled
      await chrome.storage.local.set({ directApiKey: key, useDirectLookup: true, useCloudLookup: false });
      useCloud.checked = false;
      useCloud.disabled = false; // keep control interactive (user can still toggle and will be prompted)
      strictSafeOnly.disabled = false;
      mutualNote.textContent = 'Direct API key present — cloud lookup disabled.';
    } else {
      // cleared key -> remove direct lookup and re-enable cloud checkbox
      await chrome.storage.local.set({ directApiKey: '', useDirectLookup: false });
      useCloud.disabled = false;
      mutualNote.textContent = 'No API key — cloud lookup may be enabled.';
    }
    updateSafeOnlyWarning();
  });

  useSafeOnly.addEventListener('change', () => {
    chrome.storage.local.set({ useSafeBrowsingOnly: useSafeOnly.checked });
    // If user turned off Safe-only, nothing else should remain disabled by default.
    // Recompute mutual note/UI state based on whether a key exists
    const hasKey = !!apiKeyInput.value.trim();
    apiKeyInput.disabled = useCloud.checked;
    useCloud.disabled = !!apiKeyInput.value.trim(); // cloud disabled if key present, but user can still click to be prompted
    updateSafeOnlyWarning();
  });

  strictSafeOnly.addEventListener('change', async () => {
    const val = strictSafeOnly.checked;
    const hasKey = !!apiKeyInput.value.trim();
    if (val && !hasKey) {
      alert('Strict Google-only requires a Safe Browsing API key. Please paste a key before enabling.');
      strictSafeOnly.checked = false;
      return;
    }
    // If strict enabled, ensure cloud disabled (and inform user)
    if (val) {
      await chrome.storage.local.set({ useSafeBrowsingOnlyStrict: true, useCloudLookup: false });
      useCloud.checked = false;
      useCloud.disabled = true;
      mutualNote.textContent = 'Strict Google-only requires direct API and disables cloud lookup.';
    } else {
      await chrome.storage.local.set({ useSafeBrowsingOnlyStrict: false });
      // re-evaluate whether cloud checkbox should be enabled (depends on API presence)
      useCloud.disabled = !!apiKeyInput.value.trim();
      mutualNote.textContent = 'Safe-only strict disabled.';
    }
    updateSafeOnlyWarning();
  });

  preferGoogleFirst.addEventListener('change', () => {
    chrome.storage.local.set({ preferGoogleFirst: preferGoogleFirst.checked });
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

  function updateSafeOnlyWarning() {
    const hasKey = !!apiKeyInput.value.trim();
    if (useSafeOnly.checked && strictSafeOnly.checked && !hasKey) {
      safeOnlyWarning.style.display = 'block';
    } else {
      safeOnlyWarning.style.display = 'none';
    }
  }
});