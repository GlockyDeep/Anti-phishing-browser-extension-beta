// Add this snippet into your background.js (near other message/listener logic).
// It listens for messages of type 'CHECK_URL_HOVER' and returns {status, reason}.
// status is one of 'safe', 'unsafe', 'unknown'.

const HOVER_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const hoverCache = new Map(); // url -> { status, reason, ts }

function getHoverCached(url) {
  const v = hoverCache.get(url);
  if (!v) return null;
  if (Date.now() - v.ts > HOVER_CACHE_TTL) { hoverCache.delete(url); return null; }
  return v;
}
function setHoverCached(url, status, reason) {
  hoverCache.set(url, { status, reason, ts: Date.now() });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== 'CHECK_URL_HOVER') return; // not our message
  (async () => {
    const url = msg.url;
    if (!url) { sendResponse({ status: 'unknown', reason: 'no url' }); return; }

    // quick cached response
    const c = getHoverCached(url);
    if (c) { sendResponse({ status: c.status, reason: c.reason, cached: true }); return; }

    // run local heuristics first (fast)
    let reason = runHeuristics(url);
    if (reason) {
      setHoverCached(url, 'unsafe', reason);
      sendResponse({ status: 'unsafe', reason });
      return;
    }

    // Optional: consult URLhaus / feeds locally via your proxy server approach — but we don't want to call network on hover unless cloud lookup enabled
    // If extension has cloud lookup enabled, call proxy/cache
    try {
      if (useCloudLookup) {
        const cloudReason = await checkWithProxy(url);
        if (cloudReason) {
          setHoverCached(url, 'unsafe', cloudReason);
          sendResponse({ status: 'unsafe', reason: cloudReason });
          return;
        }
      }

      // Optional direct lookup (if enabled)
      if (useDirectLookup && directApiKey) {
        const directReason = await checkWithSafeBrowsingDirect(directApiKey, url);
        if (directReason) {
          setHoverCached(url, 'unsafe', directReason);
          sendResponse({ status: 'unsafe', reason: directReason });
          return;
        }
      }

      // no reason found — safe
      setHoverCached(url, 'safe', '');
      sendResponse({ status: 'safe' });
    } catch (e) {
      // on error, return unknown
      sendResponse({ status: 'unknown', reason: e && e.message ? e.message : String(e) });
    }
  })();
  // Return true to indicate we'll sendResponse asynchronously
  return true;
});