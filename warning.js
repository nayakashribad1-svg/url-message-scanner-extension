const params = new URLSearchParams(window.location.search);
const target = params.get('target') || '';

const targetText = document.getElementById('targetText');
if (targetText) {
  targetText.textContent = `Target: ${target || 'unknown URL'}`;
}

document.getElementById('backBtn').addEventListener('click', async () => {
  if (chrome && chrome.tabs && typeof chrome.tabs.goBack === 'function') {
    try {
      await chrome.tabs.goBack();
      return;
    } catch (err) {
      // fall through
    }
  }

  window.history.back();
});

document.getElementById('proceedBtn').addEventListener('click', async () => {
  if (!target) {
    window.history.back();
    return;
  }

  if (chrome && chrome.tabs && chrome.tabs.update) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tabId = tabs[0]?.id;
    if (tabId) {
      chrome.tabs.update(tabId, { url: target });
      return;
    }
  }

  window.location.href = target;
});
