// warning.js - handles the warning page controls

function qp(name) {
  return new URLSearchParams(location.search).get(name);
}
const originalUrl = qp('url') || '';
const reason = qp('reason') || 'Suspicious site';

document.getElementById('details').textContent = `${reason}\n\nTarget: ${originalUrl}`;

document.getElementById('proceed').addEventListener('click', async () => {
  if (!originalUrl) return;
  try {
    const tabs = await chrome.tabs.query({active: true, currentWindow: true});
    const tab = tabs[0];
    if (tab) {
      await chrome.tabs.update(tab.id, { url: originalUrl });
    }
  } catch (e) {
    console.error(e);
  }
});

document.getElementById('closeTab').addEventListener('click', async () => {
  try {
    const tabs = await chrome.tabs.query({active: true, currentWindow: true});
    const tab = tabs[0];
    if (tab) {
      await chrome.tabs.remove(tab.id);
    }
  } catch (e) {
    console.error(e);
  }
});

document.getElementById('allowAndProceed').addEventListener('click', async () => {
  try {
    if (!originalUrl) return;
    const host = (new URL(originalUrl)).hostname;
    const s = await chrome.storage.local.get(['allowlist']);
    const allowlist = s.allowlist || [];
    if (!allowlist.includes(host)) {
      allowlist.push(host);
      await chrome.storage.local.set({allowlist});
    }
    const tabs = await chrome.tabs.query({active: true, currentWindow: true});
    const tab = tabs[0];
    if (tab) {
      await chrome.tabs.update(tab.id, { url: originalUrl });
    }
  } catch (e) {
    console.error(e);
  }
});