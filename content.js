(() => {
  const SHADOW_ID = '__url_message_scanner_overlay__';
  const BADGE_CLASS = '__url_message_scanner_badge__';
  const HOVER_DEBOUNCE_MS = 260;

  function getShadowHost() {
    let existing = document.getElementById(SHADOW_ID);
    if (existing) return existing;

    const host = document.createElement('div');
    host.id = SHADOW_ID;
    host.style.position = 'fixed';
    host.style.right = '18px';
    host.style.bottom = '18px';
    host.style.zIndex = '2147483647';
    host.style.pointerEvents = 'none';
    host.style.display = 'block';
    document.body.appendChild(host);
    return host;
  }

  function createTextNode(text, className) {
    const node = document.createElement('div');
    if (className) node.className = className;
    node.textContent = text;
    return node;
  }

  function showOverlay(result) {
    const host = getShadowHost();
    host.innerHTML = '';
    const shadow = host.attachShadow({ mode: 'open' });
    const wrapper = document.createElement('div');
    wrapper.style.width = 'min(340px, 72vw)';
    wrapper.style.background = 'rgba(26,26,26,0.96)';
    wrapper.style.color = '#fff';
    wrapper.style.borderRadius = '12px';
    wrapper.style.border = '1px solid rgba(255,255,255,0.12)';
    wrapper.style.boxShadow = '0 16px 44px rgba(0,0,0,0.25)';
    wrapper.style.overflow = 'hidden';
    wrapper.style.fontFamily = 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
    wrapper.style.pointerEvents = 'auto';

    const label = result?.label || 'Safe';
    const score = Number(result?.score || 0);
    const color = label === 'High Risk' ? '#d93025' : label === 'Suspicious' ? '#f9ab00' : '#188038';

    const topBar = document.createElement('div');
    topBar.style.display = 'flex';
    topBar.style.justifyContent = 'space-between';
    topBar.style.alignItems = 'center';
    topBar.style.padding = '12px 14px 8px';
    topBar.style.borderBottom = '1px solid rgba(255,255,255,0.08)';

    const heading = createTextNode('Scan result', 'title');
    heading.style.fontWeight = '700';
    heading.style.fontSize = '14px';

    const pill = document.createElement('span');
    pill.textContent = label;
    pill.style.display = 'inline-flex';
    pill.style.alignItems = 'center';
    pill.style.justifyContent = 'center';
    pill.style.minWidth = '78px';
    pill.style.borderRadius = '999px';
    pill.style.padding = '4px 8px';
    pill.style.background = color;
    pill.style.color = '#fff';
    pill.style.fontSize = '10px';
    pill.style.fontWeight = '700';
    pill.style.textTransform = 'uppercase';
    pill.style.letterSpacing = '0.04em';

    topBar.appendChild(heading);
    topBar.appendChild(pill);

    const body = document.createElement('div');
    body.style.padding = '12px 14px 14px';

    const summary = createTextNode(result?.summary || 'Review the item carefully before acting.');
    summary.style.fontSize = '13px';
    summary.style.lineHeight = '1.4';
    summary.style.marginBottom = '10px';
    summary.style.color = 'rgba(255,255,255,0.92)';

    const list = document.createElement('ul');
    list.style.listStyle = 'none';
    list.style.padding = '0';
    list.style.margin = '0';
    list.style.display = 'grid';
    list.style.gap = '6px';

    const items = Array.isArray(result?.findings) ? result.findings.slice(0, 4) : [];
    if (!items.length) {
      const li = document.createElement('li');
      li.style.padding = '7px 8px';
      li.style.borderRadius = '8px';
      li.style.background = 'rgba(255,255,255,0.04)';
      li.style.border = '1px solid rgba(255,255,255,0.08)';
      li.style.fontSize = '12px';
      li.textContent = 'No obvious issues found locally.';
      list.appendChild(li);
    } else {
      items.forEach((item) => {
        const li = document.createElement('li');
        li.style.padding = '7px 8px';
        li.style.borderRadius = '8px';
        li.style.background = 'rgba(255,255,255,0.04)';
        li.style.border = '1px solid rgba(255,255,255,0.08)';
        li.style.fontSize = '12px';
        li.style.lineHeight = '1.4';

        const severity = document.createElement('strong');
        severity.textContent = `${(item?.severity || 'medium').toUpperCase()} · `;
        const message = document.createTextNode(item?.message || 'Potential issue detected');
        const tag = document.createElement('span');
        tag.textContent = ` ${item?.source || 'Local rule'}`;
        tag.style.display = 'inline-block';
        tag.style.marginLeft = '6px';
        tag.style.padding = '2px 6px';
        tag.style.borderRadius = '999px';
        tag.style.background = 'rgba(255,255,255,0.08)';
        tag.style.fontSize = '10px';
        tag.style.fontWeight = '600';
        tag.style.verticalAlign = 'middle';

        li.appendChild(severity);
        li.appendChild(message);
        li.appendChild(tag);
        list.appendChild(li);
      });
    }

    body.appendChild(summary);
    body.appendChild(list);
    wrapper.appendChild(topBar);
    wrapper.appendChild(body);
    shadow.appendChild(wrapper);
    host.style.display = 'block';
  }

  function hideOverlay() {
    const host = document.getElementById(SHADOW_ID);
    if (host) host.remove();
  }

  function runLocalRiskCheck(url) {
    const cleaned = String(url || '').trim();
    if (!cleaned) return null;

    try {
      const parsed = new URL(cleaned.startsWith('http') ? cleaned : `https://${cleaned}`);
      const host = parsed.hostname.toLowerCase();
      let score = 0;

      if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) score += 35;
      if (host.includes('@')) score += 20;
      if (parsed.password || parsed.username) score += 15;
      if (parsed.port && !['80', '443'].includes(String(parsed.port))) score += 15;
      if (parsed.protocol !== 'https:') score += 20;
      if (/(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|ow\.ly|t\.ly)/i.test(host)) score += 18;
      if (/(\.zip|\.top|\.xyz|\.click|\.icu|\.info|\.loan|\.tk|\.cf)$/i.test(host)) score += 22;
      if ((host.match(/\./g) || []).length > 4) score += 10;
      if (decodeURIComponent(cleaned).length > 180) score += 10;
      if (/%[0-9A-Fa-f]{2}/.test(cleaned)) score += 12;
      if ((cleaned.match(/&/g) || []).length > 5) score += 8;
      if (/(login|verify|secure|update|wallet|password|kyc|bank|invoice)/i.test(cleaned)) score += 10;
      if (host.includes('xn--')) score += 16;

      if (score >= 70) return { label: 'High Risk', score };
      if (score >= 35) return { label: 'Suspicious', score };
      return { label: 'Safe', score };
    } catch (err) {
      return null;
    }
  }

  function ensureBadge(linkEl) {
    if (!linkEl || !linkEl.href) return;
    if (linkEl.dataset.scannerBadgeLoaded === 'true') return;

    const risk = runLocalRiskCheck(linkEl.href);
    const badge = document.createElement('span');
    badge.className = BADGE_CLASS;
    badge.setAttribute('role', 'status');
    badge.style.display = 'inline-block';
    badge.style.marginLeft = '6px';
    badge.style.padding = '2px 6px';
    badge.style.borderRadius = '999px';
    badge.style.fontSize = '10px';
    badge.style.lineHeight = '1';
    badge.style.fontWeight = '700';
    badge.style.verticalAlign = 'middle';
    badge.style.cursor = 'help';
    badge.style.border = '1px solid rgba(0,0,0,0.08)';
    badge.style.fontFamily = 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
    badge.textContent = risk ? (risk.label === 'High Risk' ? 'H' : risk.label === 'Suspicious' ? 'S' : 'L') : 'L';

    if (risk) {
      badge.style.background = risk.label === 'High Risk' ? '#d93025' : risk.label === 'Suspicious' ? '#f9ab00' : '#188038';
      badge.style.color = '#fff';

      if (risk.label !== 'Safe') {
        linkEl.style.outline = '2px solid ' + (risk.label === 'High Risk' ? '#d93025' : '#f9ab00');
        linkEl.style.outlineOffset = '1px';
      }
    }

    linkEl.dataset.scannerBadgeLoaded = 'true';
    linkEl.parentNode?.appendChild(badge);
  }

  let hoverTimer = null;

  document.addEventListener('mouseover', (event) => {
    const target = event.target;
    const link = target && target.closest ? target.closest('a[href]') : null;
    if (!link) return;
    if (hoverTimer) clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => { ensureBadge(link); }, HOVER_DEBOUNCE_MS);
  });

  document.addEventListener('mouseout', (event) => {
    const target = event.target;
    const link = target && target.closest ? target.closest('a[href]') : null;
    if (!link) return;
    const related = event.relatedTarget;
    if (related && related.closest && related.closest('a[href]') === link) return;
    const badge = link.parentNode?.querySelector(`.${BADGE_CLASS}`);
    if (badge) badge.remove();
    link.style.outline = '';
    link.style.outlineOffset = '';
  });

  function addMessageButtons() {
    try {
      const selectors = [
        'div[role="listitem"]',
        'div[data-message-id]',
        'div[data-id]',
        '.message',
        '.msg'
      ];

      selectors.forEach((selector) => {
        const nodes = Array.from(document.querySelectorAll(selector));
        nodes.forEach((node) => {
          if (node.dataset.scannerMessageButtonAdded === 'true') return;
          const text = (node.textContent || '').trim();
          if (!text || text.length < 20) return;

          const button = document.createElement('button');
          button.type = 'button';
          button.textContent = 'Scan this message';
          button.setAttribute('aria-label', 'Scan this message for scam indicators');
          button.style.margin = '6px 0 0 0';
          button.style.padding = '6px 10px';
          button.style.borderRadius = '8px';
          button.style.border = '1px solid rgba(0,0,0,0.12)';
          button.style.background = '#fff';
          button.style.color = '#111827';
          button.style.fontSize = '12px';
          button.style.cursor = 'pointer';
          button.style.fontWeight = '600';

          button.addEventListener('click', () => {
            chrome.runtime.sendMessage({ type: 'scan-message', text, source: 'content' }).catch(() => {});
          });

          node.appendChild(button);
          node.dataset.scannerMessageButtonAdded = 'true';
        });
      });
    } catch (err) {
      // Best-effort only.
    }
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'show-overlay') {
      showOverlay(message.result || {});
      sendResponse({ ok: true });
      return;
    }

    if (message.type === 'hide-overlay') {
      hideOverlay();
      sendResponse({ ok: true });
      return;
    }
  });

  try {
    const observer = new MutationObserver(() => {
      addMessageButtons();
    });
    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true
    });
  } catch (err) {
    // no-op
  }

  addMessageButtons();
})();
