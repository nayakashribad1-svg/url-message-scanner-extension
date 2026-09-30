import {
  defaultSettings,
  makeFindingsSummary,
  scoreMessage,
  scoreUrl,
  getRiskLevel
} from './lib/scoring.js';

import {
  lookupSafeBrowsing,
  lookupVirusTotal,
  testProviderKeys
} from './lib/intel.js';

const STORAGE_KEYS = {
  settings: 'settings',
  intelCache: 'intel-cache',
  onboarding: 'onboarding-seen'
};

const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000;
const intelQueue = [];
let activeIntelCalls = 0;

function getDefaultSettings() {
  return { ...defaultSettings };
}

async function readSettings() {
  const res = await chrome.storage.local.get([STORAGE_KEYS.settings]);
  return {
    ...getDefaultSettings(),
    ...(res[STORAGE_KEYS.settings] || {})
  };
}

async function saveSettings(settings) {
  await chrome.storage.local.set({
    [STORAGE_KEYS.settings]: settings
  });
}

async function getCachedIntel(url) {
  const res = await chrome.storage.local.get([STORAGE_KEYS.intelCache]);
  const cache = res[STORAGE_KEYS.intelCache] || {};
  const entry = cache[url];
  if (!entry) return null;
  if (Date.now() - entry.cachedAt > DEFAULT_CACHE_TTL_MS) {
    delete cache[url];
    await chrome.storage.local.set({ [STORAGE_KEYS.intelCache]: cache });
    return null;
  }
  return entry;
}

async function setCachedIntel(url, data) {
  const res = await chrome.storage.local.get([STORAGE_KEYS.intelCache]);
  const cache = res[STORAGE_KEYS.intelCache] || {};
  cache[url] = {
    ...data,
    cachedAt: Date.now()
  };
  await chrome.storage.local.set({ [STORAGE_KEYS.intelCache]: cache });
}

function scheduleIntelRequest(task) {
  intelQueue.push(task);
  if (intelQueue.length === 1) {
    setTimeout(ensureQueueDrain, 0);
  }
}

async function ensureQueueDrain() {
  if (activeIntelCalls >= 5) return;
  const next = intelQueue.shift();
  if (!next) return;
  activeIntelCalls += 1;
  try {
    await next();
  } finally {
    activeIntelCalls -= 1;
    if (intelQueue.length > 0) {
      setTimeout(ensureQueueDrain, 0);
    }
  }
}

function applyOnlineFindings(localResult, onlineReport) {
  const merged = {
    ...localResult,
    findings: [...(localResult.findings || [])],
    onlineStatus: '',
    intelMatches: []
  };

  const safeMatches = onlineReport?.safeBrowsing?.matches || [];
  const vtDetections = onlineReport?.virusTotal?.detections || 0;
  const vtTotal = onlineReport?.virusTotal?.total || 0;

  if (safeMatches.length > 0) {
    merged.findings.push({
      severity: 'critical',
      source: 'Safe Browsing',
      message: `Safe Browsing found ${safeMatches.length} threat match(s).`
    });
    merged.score = Math.max(merged.score, 96);
    merged.label = 'High Risk';
  }

  if (vtDetections >= 5 || (vtTotal >= 10 && vtDetections >= 2)) {
    merged.findings.push({
      severity: 'high',
      source: 'VirusTotal',
      message: `VirusTotal detected ${vtDetections} suspicious engine hit(s) out of ${vtTotal}.`
    });
    merged.score = Math.max(merged.score, 88);
    merged.label = 'High Risk';
  }

  if (onlineReport && onlineReport.reason) {
    merged.onlineStatus = `Online check unavailable: ${onlineReport.reason}`;
  } else if (onlineReport && onlineReport.available) {
    merged.onlineStatus = `Online check completed successfully. ${safeMatches.length ? 'Safe Browsing hit.' : ''} ${vtDetections ? `VirusTotal: ${vtDetections} detections.` : ''}`.trim();
  }

  if (merged.score >= 80) merged.label = 'High Risk';
  else if (merged.score >= 45) merged.label = 'Suspicious';
  else merged.label = 'Safe';

  merged.summary = makeFindingsSummary(merged.findings, merged.score, merged.label, merged.url);
  return merged;
}

async function runThreatIntelForUrl(url) {
  const settings = await readSettings();
  if (!settings.onlineThreatCheck) {
    return {
      available: false,
      reason: 'Online checks are disabled in settings.'
    };
  }

  const safeKey = (settings.safeBrowsingApiKey || '').trim();
  const vtKey = (settings.virusTotalApiKey || '').trim();
  if (!safeKey && !vtKey) {
    return {
      available: false,
      reason: 'No Safe Browsing or VirusTotal API key is configured.'
    };
  }

  const cached = await getCachedIntel(url);
  if (cached) {
    return { ...cached, cached: true };
  }

  const report = {
    safeBrowsing: { matches: [], available: false, reason: '' },
    virusTotal: { detections: 0, total: 0, available: false, reason: '', reportUrl: '' },
    available: false
  };

  const tasks = [];

  if (safeKey) {
    tasks.push(async () => {
      try {
        const result = await lookupSafeBrowsing(safeKey, url);
        report.safeBrowsing = result;
      } catch (err) {
        report.safeBrowsing.available = false;
        report.safeBrowsing.reason = err?.message || 'Safe Browsing request failed';
      }
    });
  }

  if (vtKey) {
    tasks.push(async () => {
      try {
        const result = await lookupVirusTotal(vtKey, url);
        report.virusTotal = result;
      } catch (err) {
        report.virusTotal.available = false;
        report.virusTotal.reason = err?.message || 'VirusTotal request failed';
      }
    });
  }

  for (const task of tasks) {
    await new Promise((resolve) => {
      scheduleIntelRequest(async () => {
        try {
          await task();
        } finally {
          resolve();
        }
      });
    });
  }

  while (activeIntelCalls > 0) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  if (!report.safeBrowsing.reason && !report.virusTotal.reason) {
    report.available = true;
  }

  if (report.safeBrowsing.reason && report.safeBrowsing.matches.length === 0 && report.virusTotal.reason && report.virusTotal.detections === 0) {
    report.reason = [report.safeBrowsing.reason, report.virusTotal.reason].filter(Boolean).join(' | ');
  } else if (report.safeBrowsing.reason && report.safeBrowsing.matches.length === 0) {
    report.reason = report.safeBrowsing.reason;
  } else if (report.virusTotal.reason && report.virusTotal.detections === 0) {
    report.reason = report.virusTotal.reason;
  }

  await setCachedIntel(url, { ...report });
  return report;
}

async function scanUrlAndScore(url, source = 'popup') {
  const local = scoreUrl(url);
  const settings = await readSettings();

  if (source === 'hover') {
    return {
      ...local,
      source: 'hover',
      onlineStatus: 'Hover scanning is local-only and does not perform network checks.'
    };
  }

  if (!settings.onlineThreatCheck) {
    return {
      ...local,
      onlineStatus: 'Online check disabled. Only local heuristics were used.'
    };
  }

  let online = { available: false, reason: 'Online checks are disabled or unavailable.' };
  try {
    online = await runThreatIntelForUrl(url);
  } catch (err) {
    online = {
      available: false,
      reason: err?.message || 'Unknown online check error.'
    };
  }

  if (online.available === false && online.reason) {
    return {
      ...local,
      onlineStatus: `Online check unavailable: ${online.reason}`,
      source
    };
  }

  const merged = applyOnlineFindings(local, online);
  merged.source = source;
  return merged;
}

async function scanMessageText(text, source = 'popup') {
  const local = scoreMessage(text, { region: (await readSettings()).region || 'IN' });
  const settings = await readSettings();
  const urls = [...new Set((text.match(/https?:\/\/[^\s]+|www\.[^\s]+/gi) || []).slice(0, 5))];

  if (!settings.onlineThreatCheck || !urls.length) {
    return {
      ...local,
      onlineStatus: settings.onlineThreatCheck ? 'No URLs found in the message to check online.' : 'Online check disabled. Only local heuristics were used.'
    };
  }

  const urlResults = [];
  for (const url of urls) {
    try {
      const result = await scanUrlAndScore(url, 'popup');
      urlResults.push({ url, result });
    } catch (err) {
      urlResults.push({
        url,
        result: {
          score: 0,
          label: 'Safe',
          summary: `Unable to scan URL: ${err.message || 'Unknown error'}`,
          findings: [],
          onlineStatus: 'Online check unavailable.'
        }
      });
    }
  }

  const combinedScores = urlResults.map((entry) => entry.result.score || 0);
  const maxScore = combinedScores.length ? Math.max(...combinedScores) : 0;
  const mergedFindings = [...(local.findings || [])];

  for (const entry of urlResults) {
    if ((entry.result.findings || []).length) {
      mergedFindings.push(...entry.result.findings.map((f) => ({
        ...f,
        message: `${f.message || 'Potential issue'} (${entry.url})`
      })));
    }
  }

  const overallScore = Math.min(Math.max(local.score || 0, maxScore), 100);
  const overallLabel = overallScore >= 80 ? 'High Risk' : overallScore >= 45 ? 'Suspicious' : 'Safe';

  return {
    ...local,
    score: overallScore,
    label: overallLabel,
    findings: mergedFindings,
    urls: urlResults,
    source,
    summary: makeFindingsSummary(mergedFindings, overallScore, overallLabel),
    nextSteps: 'Do not click or interact with suspicious links; verify the sender through an official channel.'
  };
}

function getBadgeText(label) {
  if (label === 'High Risk') return 'H';
  if (label === 'Suspicious') return 'S';
  return 'L';
}

function getBadgeColor(label) {
  if (label === 'High Risk') return '#d93025';
  if (label === 'Suspicious') return '#f9ab00';
  return '#188038';
}

async function updateToolbarBadge(tabId, tabUrl) {
  if (!tabId || !tabUrl) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  const local = scoreUrl(tabUrl);
  const text = getBadgeText(local.label);
  const color = getBadgeColor(local.label);
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function buildWarningUrl(targetUrl) {
  return chrome.runtime.getURL(`warning.html?target=${encodeURIComponent(targetUrl || '')}`);
}

chrome.runtime.onInstalled.addListener(async () => {
  const currentSettings = await readSettings();
  await chrome.storage.local.set({
    [STORAGE_KEYS.settings]: {
      ...getDefaultSettings(),
      ...currentSettings
    }
  });

  const seen = await chrome.storage.local.get([STORAGE_KEYS.onboarding]);
  if (!seen[STORAGE_KEYS.onboarding]) {
    try {
      await chrome.tabs.create({ url: chrome.runtime.getURL('onboarding.html') });
      await chrome.storage.local.set({ [STORAGE_KEYS.onboarding]: true });
    } catch (err) {
      console.warn('Unable to open onboarding page:', err);
    }
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message.type === 'scan-url') {
        const result = await scanUrlAndScore(message.url || '', message.source || 'popup');
        sendResponse({ ok: true, result });
        return;
      }

      if (message.type === 'scan-message') {
        const result = await scanMessageText(message.text || '', message.source || 'popup');
        sendResponse({ ok: true, result });
        return;
      }

      if (message.type === 'get-settings') {
        const settings = await readSettings();
        sendResponse({ ok: true, settings });
        return;
      }

      if (message.type === 'save-settings') {
        await saveSettings({ ...getDefaultSettings(), ...(message.settings || {}) });
        sendResponse({ ok: true });
        return;
      }

      if (message.type === 'clear-all-data') {
        await chrome.storage.local.clear();
        sendResponse({ ok: true });
        return;
      }

      if (message.type === 'test-keys') {
        const settings = await readSettings();
        const result = await testProviderKeys({
          safeBrowsingApiKey: settings.safeBrowsingApiKey || '',
          virusTotalApiKey: settings.virusTotalApiKey || ''
        });
        sendResponse({ ok: true, result });
        return;
      }

      if (message.type === 'scan-current-tab') {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const currentUrl = tabs?.[0]?.url || '';
        const result = await scanUrlAndScore(currentUrl, 'popup');
        sendResponse({ ok: true, result });
        return;
      }
    } catch (err) {
      sendResponse({ ok: false, error: err?.message || 'Background scan failed.' });
    }
  })();

  return true;
});

chrome.contextMenus.create({ id: 'scan-link', title: 'Scan this link', contexts: ['link'] });
chrome.contextMenus.create({ id: 'scan-selected-text', title: 'Scan selected text', contexts: ['selection'] });

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'scan-link') {
    const target = info.linkUrl || info.pageUrl || '';
    const result = await scanUrlAndScore(target, 'context-menu');

    if (tab?.id) {
      try {
        await chrome.tabs.sendMessage(tab.id, {
          type: 'show-overlay',
          result,
          source: 'context-menu'
        });
      } catch (err) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon-48.svg',
          title: 'Scan result',
          message: `${result.label}: ${result.summary || 'Review the link carefully.'}`
        });
      }
    }
    return;
  }

  if (info.menuItemId === 'scan-selected-text') {
    const text = (info.selectionText || '').trim();
    if (!text) return;

    const result = await scanMessageText(text, 'context-menu');

    if (tab?.id) {
      try {
        await chrome.tabs.sendMessage(tab.id, {
          type: 'show-overlay',
          result,
          source: 'context-menu'
        });
      } catch (err) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon-48.svg',
          title: 'Message scan',
          message: `${result.label}: ${result.summary || 'Suspicious language detected.'}`
        });
      }
    }
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  const url = changeInfo.url || tab?.url;
  if (!url) return;

  const settings = await readSettings();
  if (!settings.warningInterstitialEnabled) {
    updateToolbarBadge(tabId, url);
    return;
  }

  const local = scoreUrl(url);
  if (local.label === 'High Risk') {
    const warningUrl = buildWarningUrl(url);
    chrome.tabs.update(tabId, { url: warningUrl });
  }

  updateToolbarBadge(tabId, url);
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    updateToolbarBadge(activeInfo.tabId, tab.url);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.action.setBadgeText({ tabId, text: '' });
});
