const defaultSettings = {
  region: 'IN',
  onlineThreatCheck: false,
  safeBrowsingApiKey: '',
  virusTotalApiKey: '',
  warningInterstitialEnabled: true
};

async function loadSettings() {
  const result = await chrome.storage.local.get('settings');
  const settings = {
    ...defaultSettings,
    ...(result.settings || {})
  };

  document.getElementById('regionSelect').value = settings.region;
  document.getElementById('onlineCheckToggle').checked = Boolean(settings.onlineThreatCheck);
  document.getElementById('safeBrowsingKey').value = settings.safeBrowsingApiKey || '';
  document.getElementById('virustotalKey').value = settings.virusTotalApiKey || '';
  document.getElementById('warningInterstitialToggle').checked = Boolean(settings.warningInterstitialEnabled);
}

function setStatus(message, isError = false) {
  const statusEl = document.getElementById('status');
  statusEl.textContent = message;
  statusEl.style.color = isError ? '#b91c1c' : '#0f766e';
}

async function saveSettings() {
  const settings = {
    region: document.getElementById('regionSelect').value,
    onlineThreatCheck: document.getElementById('onlineCheckToggle').checked,
    safeBrowsingApiKey: document.getElementById('safeBrowsingKey').value.trim(),
    virusTotalApiKey: document.getElementById('virustotalKey').value.trim(),
    warningInterstitialEnabled: document.getElementById('warningInterstitialToggle').checked
  };

  await chrome.storage.local.set({ settings });
  setStatus('Settings saved.');
}

document.getElementById('saveBtn').addEventListener('click', async () => {
  try {
    await saveSettings();
  } catch (err) {
    setStatus(`Failed to save: ${err.message}`, true);
  }
});

document.getElementById('testBtn').addEventListener('click', async () => {
  try {
    const settings = {
      region: document.getElementById('regionSelect').value,
      onlineThreatCheck: document.getElementById('onlineCheckToggle').checked,
      safeBrowsingApiKey: document.getElementById('safeBrowsingKey').value.trim(),
      virusTotalApiKey: document.getElementById('virustotalKey').value.trim(),
      warningInterstitialEnabled: document.getElementById('warningInterstitialToggle').checked
    };

    await chrome.storage.local.set({ settings });
    const response = await chrome.runtime.sendMessage({ type: 'test-keys' });
    if (!response || !response.ok) {
      throw new Error(response?.error || 'Key test failed.');
    }

    const result = response.result || {};
    if (result.safeBrowsing?.success || result.virusTotal?.success) {
      setStatus('API key test passed for one or more providers.');
    } else {
      setStatus(result.message || 'API key test failed.', true);
    }
  } catch (err) {
    setStatus(`Key test failed: ${err.message}`, true);
  }
});

document.getElementById('clearBtn').addEventListener('click', async () => {
  try {
    await chrome.storage.local.clear();
    await chrome.storage.local.set({ settings: { ...defaultSettings } });
    loadSettings();
    setStatus('All stored data and keys were cleared.');
  } catch (err) {
    setStatus(`Failed to clear data: ${err.message}`, true);
  }
});

loadSettings();
