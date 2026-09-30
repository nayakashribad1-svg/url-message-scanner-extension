document.getElementById('continueBtn').addEventListener('click', async () => {
  await chrome.storage.local.set({ 'onboarding-seen': true });
  window.close();
});
