import {
  allowlistDomains,
  brandLists,
  defaultSettings,
  phishingPhrases,
  publicSuffixes,
  riskyTlds,
  suspiciousKeywords,
  urgencyWords
} from './rules.js';

import { globalPack } from './packs/global.js';
import { indiaPack } from './packs/india.js';

export { defaultSettings };

function normalizeUrl(value) {
  if (!value || typeof value !== 'string') return '';
  return value.trim().replace(/[\u0000-\u001F\u007F]+/g, '');
}

export function extractUrls(text) {
  if (!text) return [];
  const regex = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"')]+|[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:\/[^\s<>"')]+)?/gi;
  const matches = text.match(regex) || [];
  return matches
    .filter(Boolean)
    .map((item) => item.replace(/[).,;!?]+$/, ''))
    .filter((item) => item.length > 4);
}

function getHostFromUrl(urlString) {
  try {
    const url = new URL(urlString.startsWith('http') ? urlString : `https://${urlString}`);
    return url.hostname.toLowerCase();
  } catch (err) {
    return '';
  }
}

function isAllowlisted(host) {
  if (!host) return false;
  const normalized = host.toLowerCase();
  return allowlistDomains.some((domain) => normalized === domain || normalized.endsWith(`.${domain}`));
}

function levenshteinDistance(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i += 1) dp[i][0] = i;
  for (let j = 0; j <= b.length; j += 1) dp[0][j] = j;

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }

  return dp[a.length][b.length];
}

function findBrandSimilarity(host, brandList) {
  const hostNoTld = host.split('.').slice(0, -1).join('.');
  if (!hostNoTld) return { matched: false, distance: 999 };

  for (const brand of brandList) {
    const brandNormalized = brand.toLowerCase().replace(/[^a-z0-9]/g, '');
    const hostNormalized = hostNoTld.toLowerCase().replace(/[^a-z0-9]/g, '');
    const distance = levenshteinDistance(hostNormalized, brandNormalized);
    if (distance <= 3 || hostNormalized.includes(brandNormalized) || brandNormalized.includes(hostNormalized)) {
      return { matched: true, distance };
    }
  }

  return { matched: false, distance: 999 };
}

function commonDomainParts(host) {
  const parts = host.split('.');
  if (parts.length >= 3) {
    const suffix = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (publicSuffixes.includes(suffix)) {
      return parts.slice(0, parts.length - 2);
    }
  }
  return parts.slice(0, -1);
}

function containsHomographOrPunycode(value) {
  const normalized = value.toLowerCase();
  const hasPunycode = normalized.includes('xn--');
  const homographChars = /[ｅｒｏｖｚｌｉｎｏｔａｓｄｆｇｈｊｋｌｑｗｅｒｔｙｕｉｏｐ]/.test(value);
  return hasPunycode || homographChars;
}

export function getRiskLevel(score) {
  if (score >= 80) return 'High Risk';
  if (score >= 45) return 'Suspicious';
  return 'Safe';
}

export function makeFindingsSummary(findings, score = 0, label = 'Safe') {
  if (!Array.isArray(findings) || findings.length === 0) {
    return label === 'High Risk'
      ? 'This link or message shows several high-risk behaviors; avoid opening or responding.'
      : label === 'Suspicious'
        ? 'This link or message has some suspicious indicators; double-check before taking any action.'
        : 'No obvious scam or phishing indicators were found in the local heuristic scan.';
  }

  const firstTwo = findings.slice(0, 2).map((f) => f.message || 'Potential issue').join(' ');
  return `${firstTwo || 'Potential issues found.'} The current assessment is ${label} (${score}/100).`;
}

export function getRiskDescription(label) {
  if (label === 'High Risk') {
    return 'Do not click, do not reply, and verify the message through the official contact method.';
  }
  if (label === 'Suspicious') {
    return 'Treat this as untrusted until confirmed. Check the destination carefully and verify with the official site or number.';
  }
  return 'No urgent action needed from the local scan, but stay alert for changes or unexpected follow-up messages.';
}

export function scoreUrl(rawUrl) {
  const url = normalizeUrl(rawUrl);
  const findings = [];
  let score = 0;

  if (!url) {
    return {
      url: '',
      score: 0,
      label: 'Safe',
      findings: [{ severity: 'info', source: 'Local rule', message: 'No URL was provided.' }],
      summary: 'No URL was provided.',
      nextSteps: getRiskDescription('Safe')
    };
  }

  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname || '';
    const query = parsed.search || '';

    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      score += 35;
      findings.push({ severity: 'high', source: 'Local rule', message: 'The host is an IP address rather than a standard domain name.' });
    }

    if (url.includes('@')) {
      score += 25;
      findings.push({ severity: 'high', source: 'Local rule', message: 'The URL contains an @ symbol, which can be used to hide the real destination.' });
    }

    if (parsed.username || parsed.password) {
      score += 15;
      findings.push({ severity: 'medium', source: 'Local rule', message: 'The URL contains embedded credentials.' });
    }

    if (parsed.protocol !== 'https:') {
      score += 22;
      findings.push({ severity: 'high', source: 'Local rule', message: 'The link is not using HTTPS.' });
    }

    if (parsed.port && !['80', '443'].includes(String(parsed.port))) {
      score += 12;
      findings.push({ severity: 'medium', source: 'Local rule', message: 'The URL uses an unusual port number.' });
    }

    if (/(tinyurl|bit\.ly|t\.co|goo\.gl|is\.gd|ow\.ly|t\.ly)/i.test(host)) {
      score += 20;
      findings.push({ severity: 'high', source: 'Local rule', message: 'The link appears to be a URL shortener; expand it before clicking.' });
    }

    const riskyTldMatch = riskyTlds.find((suffix) => host.endsWith(suffix));
    if (riskyTldMatch) {
      score += 28;
      findings.push({ severity: 'high', source: 'Local rule', message: `The host ends with a risky TLD (${riskyTldMatch}).` });
    }

    const subdomainParts = host.split('.');
    if (subdomainParts.length > 4) {
      score += 12;
      findings.push({ severity: 'medium', source: 'Local rule', message: 'The URL has an unusually deep subdomain structure.' });
    }

    if (url.length > 180) {
      score += 12;
      findings.push({ severity: 'medium', source: 'Local rule', message: 'The URL is unusually long for a normal web destination.' });
    }

    if (/%[0-9A-Fa-f]{2}/.test(url) || /%25/.test(url)) {
      score += 10;
      findings.push({ severity: 'medium', source: 'Local rule', message: 'The URL contains encoded characters that may be hiding the actual destination.' });
    }

    if ((url.match(/&/g) || []).length > 6) {
      score += 8;
      findings.push({ severity: 'medium', source: 'Local rule', message: 'The URL contains many query parameters, which is common in tracking or malicious redirects.' });
    }

    if (containsHomographOrPunycode(host)) {
      score += 24;
      findings.push({ severity: 'high', source: 'Local rule', message: 'The host contains punycode or lookalike characters that can impersonate a trusted domain.' });
    }

    const suspiciousKeywordMatch = suspiciousKeywords.find((keyword) => new RegExp(keyword, 'i').test(path + query));
    if (suspiciousKeywordMatch) {
      score += 10;
      findings.push({ severity: 'medium', source: 'Local rule', message: `Risky keyword detected: "${suspiciousKeywordMatch}".` });
    }

    const allBrands = [...brandLists.global, ...brandLists.IN];
    const similarity = findBrandSimilarity(host, allBrands);
    if (!isAllowlisted(host) && similarity.matched && similarity.distance <= 4) {
      score += 18;
      findings.push({ severity: 'high', source: 'Local rule', message: 'The domain looks similar to a reputable brand or financial service.' });
    }

    const hostParts = host.split('.');
    if (hostParts.length > 3 && !isAllowlisted(host)) {
      score += 6;
      findings.push({ severity: 'low', source: 'Local rule', message: 'The host uses multiple subdomains, which is uncommon for a legitimate site.' });
    }

    const domainName = host.replace(/^www\./, '');
    const brandMatch = /(sbi|hdfc|icici|axis|paytm|phonepe|googlepay|bank|upi|aadhar|aadhaar|pan|uidai|rbi|trai|epfo|income tax)/i;
    if (!isAllowlisted(host) && brandMatch.test(domainName + path + query)) {
      score += 14;
      findings.push({ severity: 'medium', source: 'Local rule', message: 'Brand names appear in the subdomain or URL path without matching the official registered domain.' });
    }
  } catch (err) {
    score += 25;
    findings.push({ severity: 'high', source: 'Local rule', message: 'The URL could not be parsed correctly and may be malformed or deceptive.' });
  }

  const label = getRiskLevel(Math.min(score, 100));
  const summary = makeFindingsSummary(findings, score, label);

  return {
    url,
    score: Math.min(score, 100),
    label,
    findings,
    summary,
    nextSteps: getRiskDescription(label)
  };
}

export function scoreMessage(text, options = {}) {
  const findings = [];
  let score = 0;
  const cleanText = (text || '').trim();

  if (!cleanText) {
    return {
      score: 0,
      label: 'Safe',
      findings: [{ severity: 'info', source: 'Local rule', message: 'No message was provided.' }],
      summary: 'No message was provided.',
      urls: [],
      nextSteps: getRiskDescription('Safe')
    };
  }

  const lowerText = cleanText.toLowerCase();

  if (urgencyWords.some((word) => lowerText.includes(word))) {
    score += 18;
    findings.push({ severity: 'high', source: 'Local rule', message: 'The message uses urgency and pressure language, which is common in scam attempts.' });
  }

  if (/(otp|one time password|pin|cvv|card details|bank details|upi pin|account number)/i.test(cleanText)) {
    score += 20;
    findings.push({ severity: 'high', source: 'Local rule', message: 'The message requests sensitive details such as OTP, PIN, card, or bank information.' });
  }

  if (/(refund|lottery|prize|winner|winning|cashback|bonus|job offer)/i.test(cleanText)) {
    score += 14;
    findings.push({ severity: 'medium', source: 'Local rule', message: 'The text uses prize, refund, bonus, or job-offer bait common in scam messages.' });
  }

  if (/(bank|government|delivery|post|dhl|fedex|irs|income tax|uidai|rbi|trai|epfo|police|cbi)/i.test(cleanText)) {
    score += 10;
    findings.push({ severity: 'medium', source: 'Local rule', message: 'The message impersonates a brand or authority figure.' });
  }

  if (/(install apk|scan qr|move to telegram|move to whatsapp|download app)/i.test(cleanText)) {
    score += 18;
    findings.push({ severity: 'high', source: 'Local rule', message: 'The message asks the user to install an app or scan a QR code, which is suspicious.' });
  }

  if (/(gift card|crypto|upi|bank transfer|send money|refund via qr)/i.test(cleanText)) {
    score += 15;
    findings.push({ severity: 'high', source: 'Local rule', message: 'The message requests payment via gift cards, crypto, or QR-based transfer.' });
  }

  const urlResults = extractUrls(cleanText).map((url) => {
    const result = scoreUrl(url);
    return { url, result };
  });

  const urlScores = urlResults.map((entry) => entry.result.score || 0);
  const maxUrlScore = urlScores.length ? Math.max(...urlScores) : 0;

  if (maxUrlScore >= 70) {
    score += 22;
    findings.push({ severity: 'high', source: 'Local rule', message: 'One or more extracted URLs appear high risk.' });
  } else if (maxUrlScore >= 45) {
    score += 14;
    findings.push({ severity: 'medium', source: 'Local rule', message: 'One or more extracted URLs appear suspicious.' });
  }

  const region = options.region || 'IN';
  const packRules = region === 'IN' ? indiaPack : globalPack;
  const packFindings = packRules.detectText(cleanText, urlResults);
  if (packFindings.length) {
    findings.push(...packFindings);
    score += packFindings.reduce((total, item) => total + (item.severity === 'high' ? 18 : item.severity === 'medium' ? 12 : 6), 0);
  }

  const finalScore = Math.min(score + maxUrlScore / 2, 100);
  const label = getRiskLevel(finalScore);

  return {
    score: finalScore,
    label,
    findings,
    summary: makeFindingsSummary(findings, finalScore, label),
    urls: urlResults,
    nextSteps: getRiskDescription(label)
  };
}

export function makeReportText(result) {
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const lines = [
    'URL & Message Scanner report',
    `Risk: ${result?.label || 'Safe'} (${result?.score || 0}/100)`,
    `Summary: ${result?.summary || 'No summary available.'}`,
    'Findings:'
  ];

  if (findings.length === 0) {
    lines.push(' - No findings.');
  } else {
    findings.forEach((finding) => {
      lines.push(` - [${finding.source || 'Local rule'}] ${finding.message || 'Potential issue'}`);
    });
  }

  return lines.join('\n');
}
