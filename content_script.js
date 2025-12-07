// content_script.js - hover link analyzer + badge UI
// Inject this content script (via manifest content_scripts) so it runs on pages and analyzes hovered links.
// It debounces hover events, requests classification from the background, and shows a small badge near the cursor.
//
// Notes:
// - Add to manifest.json:
//   "content_scripts": [
//     {
//       "matches": ["<all_urls>"],
//       "js": ["content_script.js"],
//       "run_at": "document_idle"
//     }
//   ]
//
// - The script uses chrome.runtime.sendMessage({type:'CHECK_HOST_HOVER', href}) to ask background for classification.

(() => {
  const DEBOUNCE_MS = 350;
  let debounceTimer = null;
  let lastHref = '';
  let currentAnchor = null;
  let lastMousePos = { x: 0, y: 0 };

  // create badge element
  const badge = document.createElement('div');
  badge.id = 'apg-hover-badge';
  Object.assign(badge.style, {
    position: 'fixed',
    zIndex: 2147483647,
    pointerEvents: 'none',
    padding: '6px 8px',
    borderRadius: '6px',
    fontSize: '12px',
    fontWeight: '600',
    boxShadow: '0 2px 6px rgba(0,0,0,0.2)',
    transition: 'opacity 120ms ease-in-out',
    opacity: '0',
    display: 'none',
  });
  document.documentElement.appendChild(badge);

  function showBadgeAt(x, y, text, cls) {
    badge.textContent = text;
    badge.className = '';
    badge.style.display = 'block';
    badge.style.opacity = '1';
    // style by classification
    if (cls === 'safe') {
      badge.style.background = '#e6ffed';
      badge.style.color = '#064';
      badge.style.border = '1px solid #b7f1c7';
    } else if (cls === 'unsafe') {
      badge.style.background = '#ffecec';
      badge.style.color = '#900';
      badge.style.border = '1px solid #f3b1b1';
    } else if (cls === 'adult') {
      badge.style.background = '#fff5e6';
      badge.style.color = '#7a4b00';
      badge.style.border = '1px solid #ffddb3';
    } else {
      badge.style.background = '#eef6ff';
      badge.style.color = '#044';
      badge.style.border = '1px solid #cfe3ff';
    }
    // position offset so badge doesn't overlap cursor
    const offsetX = 12;
    const offsetY = 18;
    const px = Math.min(window.innerWidth - 200, Math.max(6, x + offsetX));
    const py = Math.min(window.innerHeight - 40, Math.max(6, y + offsetY));
    badge.style.left = px + 'px';
    badge.style.top = py + 'px';
  }

  function hideBadge() {
    badge.style.opacity = '0';
    setTimeout(() => { badge.style.display = 'none'; }, 160);
  }

  function enqueueCheck(href) {
    if (!href) return;
    lastHref = href;
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(async () => {
      // If href hasn't changed, proceed
      const toCheck = lastHref;
      // send message to background
      chrome.runtime.sendMessage({ type: 'CHECK_HOST_HOVER', href: toCheck }, (resp) => {
        if (!resp) return;
        const cls = resp.classification || 'unknown';
        const reason = resp.reason || resp.source || '';
        // show badge near last mouse position
        showBadgeAt(lastMousePos.x, lastMousePos.y, cls.toUpperCase(), cls);
        // optionally set title for more detail on hover
        badge.title = reason ? `${reason} (${resp.source || ''})` : '';
      });
    }, DEBOUNCE_MS);
  }

  // Mousemove to record position and reposition badge if visible
  document.addEventListener('mousemove', (ev) => {
    lastMousePos = { x: ev.clientX, y: ev.clientY };
    if (badge && badge.style.display === 'block') {
      // reposition near cursor
      const offsetX = 12;
      const offsetY = 18;
      const px = Math.min(window.innerWidth - 200, Math.max(6, lastMousePos.x + offsetX));
      const py = Math.min(window.innerHeight - 40, Math.max(6, lastMousePos.y + offsetY));
      badge.style.left = px + 'px';
      badge.style.top = py + 'px';
    }
  }, { passive: true });

  // Mouseover/mouseout handling for anchors
  document.addEventListener('mouseover', (ev) => {
    const a = ev.target.closest && ev.target.closest('a[href]');
    if (!a) {
      currentAnchor = null;
      hideBadge();
      return;
    }
    currentAnchor = a;
    const href = (a.getAttribute('href') || '').toString();
    // ignore javascript: anchors
    if (!href || href.trim().toLowerCase().startsWith('javascript:')) {
      hideBadge();
      return;
    }
    // resolve absolute URL using anchor.href (browser resolves it)
    const abs = a.href;
    enqueueCheck(abs);
  });

  document.addEventListener('mouseout', (ev) => {
    const related = ev.relatedTarget;
    // if moving out of current anchor entirely, hide badge
    if (currentAnchor && !currentAnchor.contains(related)) {
      currentAnchor = null;
      if (debounceTimer) { clearTimeout(debounceTimer); debounceTimer = null; }
      hideBadge();
    }
  });

  // Clean up on page unload
  window.addEventListener('pagehide', () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    if (badge && badge.parentNode) badge.parentNode.removeChild(badge);
  });
})();