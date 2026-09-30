const SAMPLE_INPUTS = {
  safe: 'https://www.google.com/',
  phish: 'https://secure-login-updates-verify-account.co/verify?token=123',
  india: 'https://sbicard-kyc-update.eu/kyc?ref=verify-account',
  'message-safe': 'Hi team, the meeting is at 3 PM tomorrow. Please bring the updated file.',
  'message-phish': 'URGENT: Your bank account is blocked. Verify your PIN immediately or your funds will be frozen. https://secure-bank-verify.info/',
  'message-india': 'Dear customer, your SBI account is blocked. Please complete KYC immediately by clicking the link and entering your OTP. https://sbi-security-update.co.in/kyc'
};

const state = { activeTab: 'url' };

function setActiveTab(tabName) {
  state.activeTab = tabName;
  const isUrl = tabName === 'url';

  document.getElementById('url-panel').classList.toggle('active', isUrl);
  document.getElementById('message-panel').classList.toggle('active', !isUrl);
  document.getElementById('url-panel').hidden = !isUrl;
  document.getElementById('message-panel').hidden = isUrl;

  const urlTab = document.getElementById('urlTab');
  const messageTab = document.getElementById('messageTab');
  urlTab.classList.toggle('active', isUrl);
  urlTab.setAttribute('aria-selected', String(isUrl));
  messageTab.classList.toggle('active', !isUrl);
  messageTab.setAttribute('aria-selected', String(!isUrl));
}

function getRiskColor(label) {
  if (label === 'High Risk') return '#d93025';
  if (label === 'Suspicious') return '#f9ab00';
  return '#188038';
}

function applyGauge(score, label) {
  const gauge = document.getElementById('riskGauge');
  const valueEl = document.getElementById('riskGaugeValue');
  const badge = document.getElementById('riskBadge');

  valueEl.textContent = String(score);
  gauge.style.background = `conic-gradient(${getRiskColor(label)} ${score * 3.6}deg, rgba(255,255,255,0.12) 0deg)`;

  badge.textContent = label;
  badge.className = `badge ${label === 'High Risk' ? 'high' : label === 'Suspicious' ? 'suspicious' : 'safe'}`;
}

function updateResults(result) {
  const resultsCard = document.getElementById('resultsCard');
  const summaryEl = document.getElementById('riskSummary');
  const findingsList = document.getElementById('findingsList');
  const nextStepText = document.getElementById('nextStepText');

  const score = Number(result?.score || 0);
  const label = result?.label || 'Safe';
  const findings = Array.isArray(result?.findings) ? result.findings : [];

  resultsCard.classList.remove('hidden');
  applyGauge(score, label);
  summaryEl.textContent = result?.summary || 'Review the scan details.';
  nextStepText.textContent = result?.nextSteps || 'Review the report and verify before taking action.';

  findingsList.innerHTML = '';
  if (!findings.length) {
    const item = document.createElement('li');
    item.className = 'finding-item info';
    item.textContent = 'No local findings. Review the destination carefully.';
    findingsList.appendChild(item);
  } else {
    findings.slice(0, 6).forEach((finding) => {
      const item = document.createElement('li');
      item.className = `finding-item ${finding.severity || 'medium'}`;

      const tag = document.createElement('span');
      tag.className = 'finding-tag';
      tag.textContent = finding.source || 'Local rule';

      const text = document.createElement('span');
      text.textContent = `${finding.message || 'Potential problem detected'}`;

      const severity = document.createElement('span');
      severity.className = 'severity';
      severity.textContent = finding.severity ? `(Severity: ${finding.severity})` : '(Severity: medium)';

      item.appendChild(tag);
      item.appendChild(text);
      item.appendChild(severity);
      findingsList.appendChild(item);
    });
  }
}

async function scanPayload(payload, kind) {
  const message = {
    type: kind === 'url' ? 'scan-url' : 'scan-message',
    url: kind === 'url' ? payload : undefined,
    text: kind === 'message' ? payload : undefined,
    source: 'popup'
  };

  const response = await chrome.runtime.sendMessage(message);
  if (!response || !response.ok) {
    throw new Error(response?.error || 'Scan failed.');
  }
  return response.result;
}

document.getElementById('urlTab').addEventListener('click', () => setActiveTab('url'));
document.getElementById('messageTab').addEventListener('click', () => setActiveTab('message'));

document.querySelectorAll('.sample-btn').forEach((button) => {
  button.addEventListener('click', () => {
    const sampleKey = button.dataset.sample;
    const text = SAMPLE_INPUTS[sampleKey];
    if (state.activeTab === 'url') {
      document.getElementById('scanInput').value = text;
    } else {
      document.getElementById('messageInput').value = text;
    }
  });
});

document.getElementById('scanUrlBtn').addEventListener('click', async () => {
  const value = document.getElementById('scanInput').value.trim();
  if (!value) return;

  try {
    const result = await scanPayload(value, 'url');
    updateResults(result);
  } catch (err) {
    updateResults({
      score: 0,
      label: 'Safe',
      summary: `Unable to scan URL: ${err.message}`,
      findings: [{ severity: 'medium', source: 'Local rule', message: 'The extension could not finish the scan.' }]
    });
  }
});

document.getElementById('scanCurrentTabBtn').addEventListener('click', async () => {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'scan-current-tab' });
    if (!response || !response.ok) throw new Error(response?.error || 'Could not scan current tab.');
    updateResults(response.result);
  } catch (err) {
    updateResults({
      score: 0,
      label: 'Safe',
      summary: `Unable to scan current tab: ${err.message}`,
      findings: [{ severity: 'medium', source: 'Local rule', message: 'Current tab could not be scanned.' }]
    });
  }
});

document.getElementById('scanMessageBtn').addEventListener('click', async () => {
  const value = document.getElementById('messageInput').value.trim();
  if (!value) return;

  try {
    const result = await scanPayload(value, 'message');
    updateResults(result);
  } catch (err) {
    updateResults({
      score: 0,
      label: 'Safe',
      summary: `Unable to scan message: ${err.message}`,
      findings: [{ severity: 'medium', source: 'Local rule', message: 'The extension could not finish the message scan.' }]
    });
  }
});

document.getElementById('copyReportBtn').addEventListener('click', async () => {
  const riskBadge = document.getElementById('riskBadge').textContent;
  const summary = document.getElementById('riskSummary').textContent;
  const findings = Array.from(document.querySelectorAll('#findingsList li')).map((item) => item.textContent).join('\n');
  const report = `URL & Message Scanner report\nRisk: ${riskBadge}\nSummary: ${summary}\nFindings:\n${findings}`;
  await navigator.clipboard.writeText(report);
});

document.getElementById('clearBtn').addEventListener('click', () => {
  document.getElementById('scanInput').value = '';
  document.getElementById('messageInput').value = '';
  document.getElementById('resultsCard').classList.add('hidden');
});

setActiveTab('url');
