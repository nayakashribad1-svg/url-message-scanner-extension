const SAFE_BROWSING_API = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const VT_API = 'https://www.virustotal.com/api/v3/urls';

function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  return fetch(url, {
    ...options,
    signal: controller.signal
  }).finally(() => clearTimeout(timeout));
}

function base64UrlEncode(str) {
  const encoded = btoa(unescape(encodeURIComponent(str)));
  return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function lookupSafeBrowsing(apiKey, url) {
  if (!apiKey || !url) {
    return { available: false, matches: [], reason: 'No Safe Browsing API key or URL provided.' };
  }

  const payload = {
    client: {
      clientId: 'url-message-scanner',
      clientVersion: '1.0.0'
    },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  const response = await fetchWithTimeout(`${SAFE_BROWSING_API}?key=${encodeURIComponent(apiKey)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Safe Browsing request failed (${response.status}): ${text || response.statusText}`);
  }

  const json = await response.json().catch(() => ({}));
  const matches = Array.isArray(json.matches) ? json.matches : [];
  return {
    available: true,
    matches,
    reason: matches.length ? '' : 'No Safe Browsing matches were found.'
  };
}

export async function lookupVirusTotal(apiKey, url) {
  if (!apiKey || !url) {
    return {
      available: false,
      detections: 0,
      total: 0,
      matches: [],
      reason: 'No VirusTotal API key or URL provided.'
    };
  }

  const urlId = base64UrlEncode(url);
  const response = await fetchWithTimeout(`${VT_API}/${urlId}`, {
    method: 'GET',
    headers: { 'x-apikey': apiKey }
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`VirusTotal request failed (${response.status}): ${text || response.statusText}`);
  }

  const json = await response.json().catch(() => ({}));
  const attrs = json?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const detections = Number(stats.malicious || 0) + Number(stats.suspicious || 0);
  const total = Number(stats.total || 0) || 90;
  const reportUrl = `https://www.virustotal.com/gui/url/${urlId}`;

  return {
    available: true,
    detections,
    total,
    matches: detections > 0 ? [{ detections, total, reportUrl }] : [],
    reportUrl,
    reason: detections > 0 ? '' : 'No VirusTotal detections were found.'
  };
}

export async function testProviderKeys({ safeBrowsingApiKey, virusTotalApiKey }) {
  const results = {
    safeBrowsing: { success: false, message: '' },
    virusTotal: { success: false, message: '' },
    message: ''
  };

  if (safeBrowsingApiKey) {
    try {
      await lookupSafeBrowsing(safeBrowsingApiKey, 'https://example.com');
      results.safeBrowsing.success = true;
      results.safeBrowsing.message = 'Safe Browsing key accepted.';
    } catch (err) {
      results.safeBrowsing.message = err?.message || 'Safe Browsing key failed.';
    }
  } else {
    results.safeBrowsing.message = 'No Safe Browsing key configured.';
  }

  if (virusTotalApiKey) {
    try {
      await lookupVirusTotal(virusTotalApiKey, 'https://example.com');
      results.virusTotal.success = true;
      results.virusTotal.message = 'VirusTotal key accepted.';
    } catch (err) {
      results.virusTotal.message = err?.message || 'VirusTotal key failed.';
    }
  } else {
    results.virusTotal.message = 'No VirusTotal key configured.';
  }

  results.message = [results.safeBrowsing.message, results.virusTotal.message].filter(Boolean).join(' | ');
  return results;
}
