export const indiaPack = {
  id: 'IN',
  label: 'India pack',
  detectText(message, urlResults = []) {
    const findings = [];
    const text = (message || '').toLowerCase();

    const indiaScamPatterns = [
      'kyc', 'account blocked', 'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'google pay',
      'upi pin', 'enter upi pin', 'refund via qr', 'aadhar', 'aadhaar', 'pan update',
      'income tax', 'uidai', 'epfo', 'trai', 'rbi', 'police', 'cbi', 'digital arrest',
      'electricity', 'gas bill', 'disconnect', 'fedex', 'dhl', 'india post',
      'telegram job', 'task based', 'loan app', 'crypto group', 'apk', 'customer care',
      '1930', 'cybercrime', 'sancharsaathi'
    ];

    if (indiaScamPatterns.some((pattern) => text.includes(pattern))) {
      findings.push({
        severity: 'high',
        source: 'India pack',
        message: 'The message contains India-specific scam patterns linked to KYC, bank blocking, UPI, courier, or government impersonation.'
      });
    }

    if (/(sbi|hdfc|icici|axis|paytm|phonepe|google pay)/i.test(text)) {
      findings.push({
        severity: 'high',
        source: 'India pack',
        message: 'The message impersonates a major Indian bank or payment provider to pressure the user.'
      });
    }

    if (/(kyc|account blocked|upgrade now|verify immediately|block your account)/i.test(text)) {
      findings.push({
        severity: 'high',
        source: 'India pack',
        message: 'The wording matches common KYC or account-blocking scam scripts used in India.'
      });
    }

    if (/(refund via qr|upi pin|send money to this number|enter your upi pin)/i.test(text)) {
      findings.push({
        severity: 'high',
        source: 'India pack',
        message: 'The message pushes QR code or UPI collection requests, a common money-laundering scam pattern.'
      });
    }

    if (/(apk|telegram|whatsapp|customer care|cash bonus|task based job)/i.test(text)) {
      findings.push({
        severity: 'high',
        source: 'India pack',
        message: 'The message tries to lure the user with unofficial APKs, task jobs, or false customer care instructions.'
      });
    }

    if (urlResults.length) {
      const suspiciousUrls = urlResults.filter((entry) => (entry.result?.score || 0) >= 45);
      if (suspiciousUrls.length) {
        findings.push({
          severity: 'medium',
          source: 'India pack',
          message: `The message contains ${suspiciousUrls.length} suspicious link(s) that match current scam patterns.`
        });
      }
    }

    return findings;
  }
};
