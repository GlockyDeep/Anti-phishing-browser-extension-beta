// warning.js - show reason + decision source (source param from query: heuristic, feed, safebrowsing, cache, allowlist)
(function () {
  function qs(name) { const p = new URLSearchParams(window.location.search); return p.get(name); }

  const reasonTextEl = document.getElementById('reasonText');
  const destHostEl = document.getElementById('destHost');
  const destFullEl = document.getElementById('destFull');
  const decisionSourceEl = document.getElementById('decisionSource');
  const allowBtn = document.getElementById('allowBtn');
  const closeBtn = document.getElementById('closeBtn');

  const targetUrl = qs('url') || '';
  const reason = qs('reason') || 'Suspicious site detected';
  const source = qs('source') || 'unknown';
  let hostOnly = '<unknown>';
  try { hostOnly = new URL(targetUrl).hostname; } catch (e) {}

  reasonTextEl.textContent = reason;
  destHostEl.textContent = hostOnly;
  destFullEl.textContent = targetUrl;
  decisionSourceEl.textContent = source;

  allowBtn.addEventListener('click', async () => {
    try {
      const s = await chrome.storage.local.get(['allowlist']);
      const allowlist = s.allowlist || [];
      if (!allowlist.includes(hostOnly)) {
        allowlist.push(hostOnly);
        await chrome.storage.local.set({ allowlist });
      }
      // navigate current tab
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0] && tabs[0].id) {
        await chrome.tabs.update(tabs[0].id, { url: targetUrl });
        return;
      }
      window.location.href = targetUrl;
    } catch (e) {
      console.error('Allow failed', e);
      window.location.href = targetUrl;
    }
  });

  closeBtn.addEventListener('click', async () => {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0] && tabs[0].id) await chrome.tabs.remove(tabs[0].id);
      else window.close();
    } catch (e) { try { window.close(); } catch (err) {} }
  });

  allowBtn.focus();
})();