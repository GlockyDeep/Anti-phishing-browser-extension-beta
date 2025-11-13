// popup.js - updated to require confirmation before enabling direct lookup
document.addEventListener('DOMContentLoaded', async () => {
  const toggle = document.getElementById('toggle');
  const useCloud = document.getElementById('useCloud');
  const useDirect = document.getElementById('useDirect');
  const apiKeyInput = document.getElementById('apiKey');
  const allowCurrentBtn = document.getElementById('allowCurrent');
  const allowlistDiv = document.getElementById('allowlist');

  const modal = document.getElementById('directWarningModal');
  const confirmDirectBtn = document.getElementById('confirmDirectBtn');
  const cancelDirectBtn = document.getElementById('cancelDirectBtn');

  // Load persisted state
  const s = await chrome.storage.local.get(['enabled','allowlist','useCloudLookup','useDirectLookup','directApiKey']);
  toggle.checked = s.enabled !== undefined ? s.enabled : true;
  useCloud.checked = s.useCloudLookup || false;
  useDirect.checked = s.useDirectLookup || false;
  // pendingApiKey holds the value typed into the input; we don't persist it until user confirms enabling direct lookup
  let pendingApiKey = s.directApiKey || '';
  apiKeyInput.value = pendingApiKey;
  let allowlist = s.allowlist || [];
  renderAllowlist();

  toggle.addEventListener('change', () => {
    chrome.storage.local.set({enabled: toggle.checked});
  });

  useCloud.addEventListener('change', () => {
    chrome.storage.local.set({useCloudLookup: useCloud.checked});
  });

  // When user toggles direct lookup on, show confirmation modal.
  useDirect.addEventListener('change', () => {
    if (useDirect.checked) {
      // populate pendingApiKey with current input (if any)
      pendingApiKey = apiKeyInput.value || '';
      showModal();
    } else {
      // turning direct lookup off: simply persist the off state (do not clear stored key automatically)
      chrome.storage.local.set({useDirectLookup: false});
    }
  });

  // Only update pendingApiKey (do not persist) until user confirms
  apiKeyInput.addEventListener('input', (e) => {
    pendingApiKey = e.target.value;
  });

  confirmDirectBtn.addEventListener('click', async () => {
    // Persist the API key and enable direct lookup
    await chrome.storage.local.set({useDirectLookup: true, directApiKey: pendingApiKey});
    useDirect.checked = true;
    hideModal();
  });

  cancelDirectBtn.addEventListener('click', async () => {
    // User cancelled: turn off direct toggle, clear input and do not persist key
    pendingApiKey = '';
    apiKeyInput.value = '';
    useDirect.checked = false;
    await chrome.storage.local.set({useDirectLookup: false, directApiKey: ''});
    hideModal();
  });

  allowCurrentBtn.addEventListener('click', async () => {
    const tabs = await chrome.tabs.query({active: true, currentWindow: true});
    const tab = tabs[0];
    if (!tab || !tab.url) return;
    try {
      const host = (new URL(tab.url)).hostname;
      if (!allowlist.includes(host)) {
        allowlist.push(host);
        await chrome.storage.local.set({allowlist});
        renderAllowlist();
      }
    } catch (e) {
      console.error('Invalid URL', e);
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
      rm.style.fontSize = '12px';
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

  function showModal() {
    modal.style.display = 'flex';
    modal.setAttribute('aria-hidden', 'false');
  }

  function hideModal() {
    modal.style.display = 'none';
    modal.setAttribute('aria-hidden', 'true');
  }
});