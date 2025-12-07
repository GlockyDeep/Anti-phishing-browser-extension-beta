// popup.js - simplified popup with "Test key on active tab" functionality.
// Uses background SW message CHECK_URL_SAFE_BROWSING to run the Safe Browsing check.

document.addEventListener('DOMContentLoaded', async () => {
  const apiKeyInput = document.getElementById('apiKey');
  const saveBtn = document.getElementById('saveBtn');
  const status = document.getElementById('status');
  const enabledCheckbox = document.getElementById('enabled');

  const testKeyBtn = document.getElementById('testKeyBtn');
  const testResult = document.getElementById('testResult');

  const allowlistItems = document.getElementById('allowlistItems');
  const allowInput = document.getElementById('allowInput');
  const addAllowBtn = document.getElementById('addAllowBtn');

  // Load stored values
  const s = await chrome.storage.local.get(['directApiKey', 'enabled', 'allowlist']);
  apiKeyInput.value = s.directApiKey || '';
  enabledCheckbox.checked = s.enabled !== undefined ? s.enabled : true;
  let allowlist = Array.isArray(s.allowlist) ? s.allowlist : [];

  function renderAllowlist() {
    if (!allowlist.length) {
      allowlistItems.textContent = '(none)';
      return;
    }
    allowlistItems.innerHTML = '';
    allowlist.forEach(h => {
      const row = document.createElement('div');
      row.className = 'allow-row';
      const span = document.createElement('span');
      span.textContent = h;
      const btn = document.createElement('button');
      btn.textContent = 'Remove';
      btn.className = 'btn-muted';
      btn.addEventListener('click', async () => {
        allowlist = allowlist.filter(x => x !== h);
        await chrome.storage.local.set({ allowlist });
        renderAllowlist();
      });
      row.appendChild(span);
      row.appendChild(btn);
      allowlistItems.appendChild(row);
    });
  }

  renderAllowlist();

  saveBtn.addEventListener('click', async () => {
    const key = apiKeyInput.value.trim();
    await chrome.storage.local.set({ directApiKey: key });
    status.textContent = key ? 'API key saved.' : 'API key cleared.';
    setTimeout(() => { status.textContent = ''; }, 2500);
  });

  enabledCheckbox.addEventListener('change', async () => {
    await chrome.storage.local.set({ enabled: enabledCheckbox.checked });
  });

  addAllowBtn.addEventListener('click', async () => {
    const v = (allowInput.value || '').trim().toLowerCase();
    if (!v) return;
    const normalized = v.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    if (!allowlist.includes(normalized)) {
      allowlist.push(normalized);
      await chrome.storage.local.set({ allowlist });
      allowInput.value = '';
      renderAllowlist();
    }
  });

  // Helper to display test result
  function showTestResult(kind, text, raw = null) {
    testResult.className = '';
    testResult.style.display = 'block';
    if (kind === 'ok') testResult.classList.add('ok');
    else if (kind === 'bad') testResult.classList.add('bad');
    else testResult.classList.add('info');
    testResult.innerHTML = `<strong>${text}</strong>`;
    if (raw) {
      const pre = document.createElement('pre');
      pre.style.marginTop = '8px';
      pre.style.maxHeight = '160px';
      pre.style.overflow = 'auto';
      pre.style.fontSize = '12px';
      pre.textContent = JSON.stringify(raw, null, 2);
      testResult.appendChild(pre);
    }
  }

  // Click handler: test the saved API key against the current active tab URL
  testKeyBtn.addEventListener('click', async () => {
    testResult.style.display = 'none';
    testResult.textContent = '';
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs && tabs[0];
      if (!tab || !tab.url) {
        showTestResult('info', 'No active tab URL found to test.');
        return;
      }

      // Quick client-side check for saved key
      const st = await chrome.storage.local.get('directApiKey');
      const apiKey = st && st.directApiKey ? st.directApiKey.trim() : '';
      if (!apiKey) {
        showTestResult('info', 'No API key saved. Paste your Google Safe Browsing API key and click Save first.');
        return;
      }

      showTestResult('info', 'Checking... (querying Safe Browsing)');

      // Send message to background to run the check (background implements CHECK_URL_SAFE_BROWSING)
      chrome.runtime.sendMessage({ type: 'CHECK_URL_SAFE_BROWSING', url: tab.url }, (resp) => {
        if (chrome.runtime.lastError) {
          showTestResult('info', 'Error: ' + chrome.runtime.lastError.message);
          return;
        }
        if (!resp) {
          showTestResult('info', 'No response from background script.');
          return;
        }
        if (resp.error) {
          showTestResult('info', `Error from checker: ${resp.error}`, resp.raw || null);
          return;
        }
        if (resp.safe === false) {
          const reason = resp.reason || 'Google Safe Browsing match';
          showTestResult('bad', `UNSAFE — ${reason}`, resp.raw || null);
        } else if (resp.safe === true) {
          showTestResult('ok', 'SAFE — No Safe Browsing match', resp.raw || null);
        } else {
          // older background message format might return { safe: true } or { safe: false }
          if (resp.safe === undefined && resp.raw && resp.raw.match) {
            showTestResult('bad', 'UNSAFE — Google Safe Browsing match', resp.raw || null);
          } else {
            showTestResult('info', 'No definitive result', resp.raw || null);
          }
        }
      });

    } catch (e) {
      showTestResult('info', 'Exception: ' + String(e));
    }
  });

});