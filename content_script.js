// content_script.js
// Shows a small host-only badge (green/red/gray) when hovering links.
// Debounced checks; calls background via chrome.runtime.sendMessage and uses a simple cache.
//
// Fixes:
// - Don't run on privileged/special pages (chrome://, about:, devtools, etc).
// - Avoid using 'unload' (permission policy violation on some pages). Use 'pagehide' / 'visibilitychange' with try/catch.
// - Guard DOM insertion with try/catch to avoid exceptions on restricted pages.

(function () {
  // Only run on normal web pages (http/https/file). Skip chrome://, about:, data:, etc.
  try {
    const allowed = /^https?:|^file:/.test(location.protocol);
    if (!allowed) {
      // Not a standard web page — bail out silently.
      // console.debug('[APG] content_script skipped on protocol', location.protocol);
      return;
    }
  } catch (e) {
    // If accessing location.protocol fails for any reason, bail out.
    return;
  }

  const DEBOUNCE_MS = 300;
  const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
  const cache = new Map(); // key -> {status, reason, ts}

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
    // Try to append; some pages may disallow DOM mutations — guard it
    try {
      document.documentElement.appendChild(badge);
    } catch (e) {
      // If append fails, disable badge usage
      badge = null;
    }
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

  function resolveHref(href) {
    try {
      return new URL(href, document.baseURI).href;
    } catch (e) {
      return null;
    }
  }

  function hostnameOf(url) {
    try {
      return new URL(url).hostname.toLowerCase();
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

  function checkUrl(url) {
    return new Promise((resolve) => {
      const cached = getCached(url);
      if (cached) return resolve({ status: cached.status, reason: cached.reason, source: 'cache' });

      chrome.runtime.sendMessage({ type: 'CHECK_URL_HOVER', url }, (resp) => {
        if (chrome.runtime.lastError) {
          resolve({ status: 'unknown', reason: 'extension unavailable' });
          return;
        }
        if (!resp) {
          resolve({ status: 'unknown', reason: 'no-response' });
          return;
        }
        const out = { status: resp.status || 'unknown', reason: resp.reason || '', raw: resp };
        setCached(url, { status: out.status, reason: out.reason });
        resolve(out);
      });
    });
  }

  function findLinkElement(el) {
    if (!el) return null;
    const a = el.closest && el.closest('a[href]');
    if (a) return a;
    if (el.getAttribute && (el.getAttribute('role') === 'link' || el.getAttribute('data-href'))) return el;
    return null;
  }

  let hoverTimer = null;
  let lastUrlChecked = null;
  let lastMouse = { x: 0, y: 0 };

  document.addEventListener('mousemove', (ev) => {
    lastMouse.x = ev.clientX;
    lastMouse.y = ev.clientY;
    if (badge && badge.style.display === 'block') {
      showBadgeAt(lastMouse.x, lastMouse.y, badge.textContent, badge.style.background);
    }
  }, { passive: true });

  document.addEventListener('mouseover', (ev) => {
    const linkEl = findLinkElement(ev.target);
    if (!linkEl) {
      if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
      hideBadge();
      return;
    }

    let href = null;
    if (linkEl.tagName && linkEl.tagName.toLowerCase() === 'a') {
      href = linkEl.getAttribute('href');
    } else if (linkEl.getAttribute && linkEl.getAttribute('data-href')) {
      href = linkEl.getAttribute('data-href');
    } else if (linkEl.getAttribute && linkEl.getAttribute('href')) {
      href = linkEl.getAttribute('href');
    }

    const resolved = resolveHref(href);
    if (!resolved) {
      showBadgeAt(lastMouse.x, lastMouse.y, 'Unknown', '#6b7280');
      return;
    }

    if (resolved === lastUrlChecked && badge && badge.style.display === 'block') {
      showBadgeAt(lastMouse.x, lastMouse.y, badge.textContent, badge.style.background);
      return;
    }

    if (hoverTimer) clearTimeout(hoverTimer);
    hoverTimer = setTimeout(async () => {
      hoverTimer = null;
      lastUrlChecked = resolved;

      const cached = getCached(resolved);
      if (cached) {
        const color = cached.status === 'unsafe' ? '#d9534f' : (cached.status === 'safe' ? '#16a34a' : '#6b7280');
        showBadgeAt(lastMouse.x, lastMouse.y, cached.status.toUpperCase(), color);
        if (badge) badge.title = cached.reason || '';
        return;
      }

      showBadgeAt(lastMouse.x, lastMouse.y, 'Checking…', '#6b7280');

      const result = await checkUrl(resolved);
      const s = result.status || 'unknown';
      const color = s === 'unsafe' ? '#d9534f' : (s === 'safe' ? '#16a34a' : '#6b7280');
      showBadgeAt(lastMouse.x, lastMouse.y, s.toUpperCase(), color);
      if (badge) badge.title = result.reason || '';
    }, DEBOUNCE_MS);
  }, true);

  document.addEventListener('mouseout', (ev) => {
    if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
    hideBadge();
  }, true);

  // Cleanup: pagehide is safer than unload on many pages; use visibilitychange as backup.
  try {
    window.addEventListener('pagehide', () => {
      if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
      hideBadge();
    }, { passive: true });
  } catch (e) {
    // ignore
  }
  try {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') {
        if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
        hideBadge();
      }
    }, { passive: true });
  } catch (e) {
    // ignore
  }

  // No unload listener due to permission policy on some pages.
})();