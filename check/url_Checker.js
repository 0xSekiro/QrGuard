export const isMalicious = (url) => {
  const lowerUrl = url.toLowerCase();

  const blacklistedPatterns = [
    'free-money', 'login-steal', 'phish', 'creditcard', 'paypal-verify',
    'malware', 'ransom', 'hacktool', 'fakeupdate',
    '.ru', '.cn', '.tk', '.top', '.xyz'
  ];

  if (lowerUrl.startsWith('http://')) return true;

  for (const pattern of blacklistedPatterns) {
    if (lowerUrl.includes(pattern)) return true;
  }

  if (lowerUrl.startsWith('javascript:') || lowerUrl.startsWith('data:')) return true;

  return false;
};
