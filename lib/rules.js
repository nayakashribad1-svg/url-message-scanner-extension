const defaultSettings = {
  region: 'IN',
  onlineThreatCheck: false,
  safeBrowsingApiKey: '',
  virusTotalApiKey: '',
  warningInterstitialEnabled: true,
  hoverProtectionEnabled: true,
  boldInlineWarnings: false
};

const allowlistDomains = [
  'google.com',
  'gmail.com',
  'microsoft.com',
  'outlook.com',
  'office.com',
  'facebook.com',
  'meta.com',
  'linkedin.com',
  'netflix.com',
  'amazon.com',
  'paypal.com',
  'stripe.com',
  'github.com',
  'discord.com',
  'bankofamerica.com',
  'chase.com',
  'wellsfargo.com',
  'citibank.com',
  'hdfcbank.com',
  'sbi.co.in',
  'sbi.in',
  'axisbank.com',
  'icicibank.com',
  'paytm.com',
  'phonepe.com',
  'googlepay.com',
  'airtel.in',
  'jio.com',
  'gov.in',
  'india.gov.in',
  'cybercrime.gov.in',
  'sancharsaathi.gov.in'
];

const riskyTlds = [
  '.zip', '.top', '.xyz', '.click', '.icu', '.download', '.loan', '.info', '.bid',
  '.cf', '.ga', '.gq', '.tk', '.club', '.shop', '.best', '.work', '.vip'
];

const suspiciousKeywords = [
  'login', 'verify', 'secure', 'update', 'wallet', 'password', 'kyc', 'otp',
  'account', 'confirm', 'immediately', 'urgent', 'cashback', 'refund', 'bonus',
  'invoice', 'alert', 'suspended', 'banking', 'dl'
];

const urgencyWords = [
  'urgent', 'immediately', 'today', 'now', 'asap', 'within 24 hours', 'alert',
  'final warning', 'required', 'suspended', 'blocked', 'deactivate', 'freeze'
];

const phishingPhrases = [
  'otp', 'pin', 'cvv', 'bank details', 'card details', 'upi pin', 'gift card',
  'scan qr code', 'install apk', 'move to whatsapp', 'customer care', 'wallet',
  'verify account', 'claim your refund', 'lottery', 'winning prize'
];

const brandLists = {
  global: [
    'google', 'microsoft', 'apple', 'amazon', 'paypal', 'dropbox', 'github',
    'meta', 'facebook', 'linkedin', 'netflix', 'stripe', 'adobe', 'zoom',
    'office', 'onedrive', 'icloud', 'bank', 'ebay'
  ],
  IN: [
    'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'google pay', 'gmail', 'upi',
    'irctc', 'uidai', 'epfo', 'rbi', 'trai', 'income tax', 'india post', 'dhl', 'fedex',
    'amazon pay', 'kotak', 'yes bank', 'aadhar', 'aadhaar', 'pan'
  ]
};

const publicSuffixes = [
  'co.in', 'co.uk', 'gov.in', 'nic.in', 'ac.in', 'com.in', 'org.in'
];

export {
  defaultSettings,
  allowlistDomains,
  riskyTlds,
  suspiciousKeywords,
  urgencyWords,
  phishingPhrases,
  brandLists,
  publicSuffixes
};
