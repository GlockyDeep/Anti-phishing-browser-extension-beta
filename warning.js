// warning.js - warning page logic (matching the updated warning.html)
// Behavior:
// - Displays the reason and destination host from query params.
// - "Allow this host and proceed" adds the host to chrome.storage.local.allowlist and navigates to the original URL.
// - "Close tab" closes the current active tab.
// - "Report this website" opens Google's reporting page (host-only in URL), best-effort.

(function () {
  function qs(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name);
  }

  const reasonTextEl = document.getElementById('reasonText');
  const destHostEl = document.getElementById('destHost');
  const destFullEl = document.getElementById('destFull');
  const allowBtn = document.getElementById('allowBtn');
  const closeBtn = document.getElementById('closeBtn');
  const reportLink = document.getElementById('reportLink');

  const targetUrl = qs('url') || '';
  const reason = qs('reason') || 'Suspicious site detected';
  let hostOnly = '<unknown>';
  try {
    hostOnly = new URL(targetUrl).hostname;
  } catch (e) {
    // keep unknown
  }

  // Populate UI
  reasonTextEl.textContent = reason;
  destHostEl.textContent = hostOnly;
  destFullEl.textContent = targetUrl;

  // Report link opens Google Safe Browsing report page (prefilled)
  reportLink.addEventListener('click', (e) => {
    e.preventDefault();
    const reportUrl = 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + encodeURIComponent(targetUrl);
    window.open(reportUrl, '_blank', 'noopener');
  });

  // Allow: add host to allowlist and navigate to targetUrl
  allowBtn.addEventListener('click', async () => {
    try {
      // fetch existing allowlist, append host, and persist
      const s = await chrome.storage.local.get(['allowlist']);
      const allowlist = s.allowlist || [];
      if (!allowlist.includes(hostOnly)) {
        allowlist.push(hostOnly);
        await chrome.storage.local.set({ allowlist });
      }
      // navigate current tab to original URL
      try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs && tabs[0] && tabs[0].id) {
          await chrome.tabs.update(tabs[0].id, { url: targetUrl });
        } else {
          // fallback: open a new tab
          await chrome.tabs.create({ url: targetUrl });
        }
      } catch (err) {
        // fallback to location.href if chrome.tabs fails (shouldn't in extension context)
        window.location.href = targetUrl;
      }
    } catch (e) {
      console.error('Allow action failed', e);
      // attempt to navigate anyway
      window.location.href = targetUrl;
    }
  });

  // Close tab
  closeBtn.addEventListener('click', async () => {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0] && tabs[0].id) {
        await chrome.tabs.remove(tabs[0].id);
      } else {
        window.close();
      }
    } catch (e) {
      try { window.close(); } catch (err) { /* ignore */ }
    }
  });

  // Accessibility: focus first actionable button
  allowBtn.focus();
})();