export const globalPack = {
  id: 'global',
  label: 'Global pack',
  detectText(message, urlResults = []) {
    const findings = [];
    const text = (message || '').toLowerCase();

    if (/(refund|winning|lottery|prize|claim)/i.test(text)) {
      findings.push({
        severity: 'medium',
        source: 'Global pack',
        message: 'The message contains prize, refund, or lottery bait, which is common in scam content.'
      });
    }

    if (/(otp|pin|cvv|password|card|bank details)/i.test(text)) {
      findings.push({
        severity: 'high',
        source: 'Global pack',
        message: 'The message requests sensitive login, payment, or bank information.'
      });
    }

    if (/(scan qr|install app|download apk|telegram|whatsapp)/i.test(text)) {
      findings.push({
        severity: 'high',
        source: 'Global pack',
        message: 'The message tries to move the user to unofficial apps or QR-based payment steps.'
      });
    }

    if (urlResults.length) {
      const suspiciousUrls = urlResults.filter((entry) => (entry.result?.score || 0) >= 45);
      if (suspiciousUrls.length) {
        findings.push({
          severity: 'medium',
          source: 'Global pack',
          message: `One or more extracted URLs are suspicious (${suspiciousUrls.length} found).`
        });
      }
    }

    return findings;
  }
};
