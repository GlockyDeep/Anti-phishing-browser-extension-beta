// content_script.js - host-only hover checks (robust to extension context invalidation)
// - Uses safeSendMessage to avoid unhandled promise rejections when the SW is restarted or extension reloaded.
// - Compatible with MV3: checks chrome.runtime.lastError in callback and times out gracefully.

(function () {
  // Only run on normal web pages (http/https/file). Bail out on chrome://, about:, extensions pages, etc.
  try {
    const allowed = /^https?:|^file:/.test(location.protocol);
    if (!allowed) return;
  } catch (e) {
    return;
  }

  const DEBOUNCE_MS = 300;
  const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
  const cache = new Map(); // host -> {status, reason, ts}

  // Create badge element (guarded)
  let badge = null;
  try {
    badge = document.createElement('div');
    badge.id = 'apg-hover-badge';
    badge.style.position = 'fixed';
    badge.style.zIndex = 2147483647;
    badge.style.pointerEvents = 'none';
    badge.style.padding = '4px 8px';
    badge.style.borderRadius = '12px';
    badge.style.fontSize = '12px';
    badge.style.fontFamily = 'system-ui, -apple-system, "Segoe UI", Roboto, Arial';
    badge.style.boxShadow = '0 2px 6px rgba(0,0,0,0.15)';
    badge.style.transition = 'opacity 120ms ease, transform 120ms ease';
    badge.style.opacity = '0';
    badge.style.transform = 'translateY(4px)';
    badge.style.display = 'none';
    // Append with try/catch: some pages may restrict DOM mutations
    try { document.documentElement.appendChild(badge); } catch (e) { badge = null; }
  } catch (e) {
    badge = null;
  }

  function showBadgeAt(x, y, text, color) {
    if (!badge) return;
    badge.textContent = text || '';
    badge.style.background = color || '#999';
    badge.style.color = '#fff';
    const offset = 16;
    const w = badge.offsetWidth || 80;
    const h = badge.offsetHeight || 24;
    let left = x + 10;
    let top = y - offset - h;
    if (left + w > window.innerWidth - 8) left = window.innerWidth - w - 8;
    if (left < 8) left = 8;
    if (top < 8) top = y + 16;
    badge.style.left = left + 'px';
    badge.style.top = top + 'px';
    badge.style.display = 'block';
    requestAnimationFrame(() => {
      badge.style.opacity = '1';
      badge.style.transform = 'translateY(0)';
    });
  }

  function hideBadge() {
    if (!badge) return;
    badge.style.opacity = '0';
    badge.style.transform = 'translateY(4px)';
    setTimeout(() => {
      if (badge) badge.style.display = 'none';
    }, 150);
  }

  function hostnameOf(url) {
    try {
      return new URL(url, document.baseURI).hostname.toLowerCase();
    } catch (e) {
      return null;
    }
  }

  function getCached(key) {
    const v = cache.get(key);
    if (!v) return null;
    if (Date.now() - v.ts > CACHE_TTL_MS) {
      cache.delete(key);
      return null;
    }
    return v;
  }
  function setCached(key, value) {
    value.ts = Date.now();
    cache.set(key, value);
  }

  // Robust sendMessage wrapper:
  // - Uses callback form to reliably see chrome.runtime.lastError
  // - Catches synchronous exceptions
  // - Times out after `timeoutMs` and returns an error object
  function safeSendMessage(message, timeoutMs = 1500) {
    return new Promise((resolve) => {
      let settled = false;
      try {
        chrome.runtime.sendMessage(message, (resp) => {
          if (settled) return;
          settled = true;
          if (chrome.runtime.lastError) {
            resolve({ error: chrome.runtime.lastError.message });
          } else {
            resolve({ resp });
          }
        });
      } catch (err) {
        // synchronous throw (e.g., extension context invalidated)
        if (!settled) {
          settled = true;
          resolve({ error: err && err.message ? err.message : String(err) });
        }
      }
      // timeout fallback
      setTimeout(() => {
        if (settled) return;
        settled = true;
        resolve({ error: 'timeout' });
      }, timeoutMs);
    });
  }

  // Host-only hover check using safeSendMessage; never throws unhandled rejections
  async function checkHost(host) {
    // host-only cache
    const cached = getCached(host);
    if (cached) return cached;

    try {
      const { resp, error } = await (async () => {
        const r = await safeSendMessage({ type: 'CHECK_HOST_HOVER', host }, 1500);
        // safeSendMessage returns { resp } or { error }
        return r;
      })();

      if (error) {
        // Known case: extension reloaded / SW restarted -> treat as unknown, cache lightly
        const fallback = { status: 'unknown', reason: error };
        setCached(host, fallback);
        return fallback;
      }

      const messageResp = (resp && resp.resp) ? resp.resp : resp; // safeSendMessage shape: { resp } or nested
      if (!messageResp) {
        const fallback = { status: 'unknown', reason: 'no-response' };
        setCached(host, fallback);
        return fallback;
      }
      const out = { status: messageResp.status || 'unknown', reason: messageResp.reason || '' };
      setCached(host, out);
      return out;
    } catch (e) {
      // Shouldn't happen because safeSendMessage never throws, but guard anyway
      const fallback = { status: 'unknown', reason: e && e.message ? e.message : String(e) };
      setCached(host, fallback);
      return fallback;
    }
  }

  function findLinkElement(el) {
    if (!el) return null;
    const a = el.closest && el.closest('a[href]');
    if (a) return a;
    if (el.getAttribute && (el.getAttribute('role') === 'link' || el.getAttribute('data-href'))) return el;
    return null;
  }

  let hoverTimer = null;
  let lastHostChecked = null;
  let lastMouse = { x: 0, y: 0 };

  // Keep badge positioned near cursor while visible
  try {
    document.addEventListener('mousemove', (ev) => {
      lastMouse.x = ev.clientX;
      lastMouse.y = ev.clientY;
      if (badge && badge.style.display === 'block') {
        showBadgeAt(lastMouse.x, lastMouse.y, badge.textContent, badge.style.background);
      }
    }, { passive: true });
  } catch (e) { /* ignore */ }

  try {
    document.addEventListener('mouseover', (ev) => {
      const linkEl = findLinkElement(ev.target);
      if (!linkEl) {
        if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
        hideBadge();
        return;
      }

      // Extract href (support anchors and data-href)
      let href = null;
      try {
        if (linkEl.tagName && linkEl.tagName.toLowerCase() === 'a') {
          href = linkEl.getAttribute('href');
        } else if (linkEl.getAttribute && linkEl.getAttribute('data-href')) {
          href = linkEl.getAttribute('data-href');
        } else if (linkEl.getAttribute && linkEl.getAttribute('href')) {
          href = linkEl.getAttribute('href');
        }
      } catch (e) {
        href = null;
      }

      // Resolve to absolute URL and extract host
      let host = null;
      try {
        const resolved = new URL(href, document.baseURI).href;
        host = hostnameOf(resolved);
      } catch (e) {
        host = null;
      }

      if (!host) {
        showBadgeAt(lastMouse.x, lastMouse.y, 'Unknown', '#6b7280');
        return;
      }

      if (host === lastHostChecked && badge && badge.style.display === 'block') {
        showBadgeAt(lastMouse.x, lastMouse.y, badge.textContent, badge.style.background);
        return;
      }

      if (hoverTimer) clearTimeout(hoverTimer);
      hoverTimer = setTimeout(async () => {
        hoverTimer = null;
        lastHostChecked = host;

        const cached = getCached(host);
        if (cached) {
          const color = cached.status === 'unsafe' ? '#d9534f' : (cached.status === 'safe' ? '#16a34a' : '#6b7280');
          showBadgeAt(lastMouse.x, lastMouse.y, cached.status.toUpperCase(), color);
          if (badge) badge.title = cached.reason || '';
          return;
        }

        showBadgeAt(lastMouse.x, lastMouse.y, 'Checking…', '#6b7280');

        const result = await checkHost(host);
        const s = result.status || 'unknown';
        const color = s === 'unsafe' ? '#d9534f' : (s === 'safe' ? '#16a34a' : '#6b7280');
        showBadgeAt(lastMouse.x, lastMouse.y, s.toUpperCase(), color);
        if (badge) badge.title = result.reason || '';
      }, DEBOUNCE_MS);
    }, true);
  } catch (e) { /* ignore */ }

  try {
    document.addEventListener('mouseout', (ev) => {
      if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
      hideBadge();
    }, true);
  } catch (e) { /* ignore */ }

  // Cleanup: pagehide is safer than unload on many pages; visibilitychange as backup.
  try {
    window.addEventListener('pagehide', () => {
      if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
      hideBadge();
    }, { passive: true });
  } catch (e) { /* ignore */ }

  try {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') {
        if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
        hideBadge();
      }
    }, { passive: true });
  } catch (e) { /* ignore */ }

  // Note: intentionally NOT using 'unload' to avoid permission-policy errors on privileged pages.
})();