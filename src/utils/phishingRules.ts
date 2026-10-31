export type RiskCategory = 'Lower Indicators' | 'Suspicious' | 'High Risk';

export type ScanType = 'message' | 'url';

export type AnalysisEngineType =
  | 'local-offline-engine'
  | 'hybrid-gemini-and-rules'
  | 'rule-based-fallback';

export interface DetectedIndicator {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high';
  category: string;
  matchedSnippet?: string;
  explanation: string;
  source: 'rule' | 'ai' | 'both';
}

export interface SuspiciousPhraseAnalysis {
  phrase: string;
  tactic: string;
  whySuspicious: string;
}

export interface UrlStructureBreakdown {
  rawInput: string;
  normalizedUrl: string;
  protocol: string;
  hostname: string;
  subdomainCount: number;
  tld: string;
  port: string;
  pathLength: number;
  queryParamCount: number;
  hasIpAddressHost: boolean;
  hasAtSymbolRedirect: boolean;
  hasPunycode: boolean;
  isShortener: boolean;
  impersonatedBrand?: string;
}

export interface SensitiveDataDetection {
  hasSensitiveData: boolean;
  detectedTypes: string[];
  redactedText: string;
}

export interface ScanAnalysisResult {
  id: string;
  scanType: ScanType;
  timestamp: string;
  riskScore: number; // 0 to 100
  riskCategory: RiskCategory;
  ruleScore: number;
  aiScore: number | null;
  analysisEngine: AnalysisEngineType;
  fallbackReason?: string;
  summary: string;
  uncertaintyStatement: string;
  warningSigns: string[];
  indicators: DetectedIndicator[];
  suspiciousPhrases: SuspiciousPhraseAnalysis[];
  recommendedActions: string[];
  urlBreakdown?: UrlStructureBreakdown;
  privacySafeSnippet: string;
}

export interface ScanHistoryItem {
  id: string;
  scanType: ScanType;
  timestamp: string;
  riskScore: number;
  riskCategory: RiskCategory;
  privacySafeSnippet: string;
  indicatorCount: number;
  analysisEngine: AnalysisEngineType;
  fullResult: ScanAnalysisResult;
}

/**
 * Classifies a numeric 0-100 risk score into the three required categories:
 * 0-29: Lower Indicators
 * 30-59: Suspicious
 * 60-100: High Risk
 */
export function classifyRiskScore(score: number): RiskCategory {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  if (clamped <= 29) return 'Lower Indicators';
  if (clamped <= 59) return 'Suspicious';
  return 'High Risk';
}

/**
 * Detects if a user accidentally pasted sensitive credentials (OTPs, CVVs, card numbers, passwords)
 * and offers automatic client/server redaction so sensitive secrets are never exposed or stored.
 */
export function detectAndRedactSensitiveInput(input: string): SensitiveDataDetection {
  const detectedTypes: string[] = [];
  let redactedText = input;

  // Credit/debit card patterns (13-19 digits with optional spaces or dashes)
  const cardRegex = /\b(?:\d[ -]*?){13,19}\b/g;
  if (cardRegex.test(redactedText)) {
    detectedTypes.push('Payment Card Number');
    redactedText = redactedText.replace(cardRegex, '[REDACTED-CARD]');
  }

  // Explicit OTP / Verification codes (e.g., "OTP is 482910" or "verification code: 839201")
  const otpContextRegex = /\b(otp|verification code|security code|passcode|pin)\s*(?:is|:|-)?\s*(\d{4,8})\b/gi;
  if (otpContextRegex.test(redactedText)) {
    detectedTypes.push('One-Time Passcode (OTP)');
    redactedText = redactedText.replace(otpContextRegex, '$1: [REDACTED-OTP]');
  }

  // Explicit CVV / CVC
  const cvvRegex = /\b(cvv|cvc|security digits)\s*(?:is|:|-)?\s*(\d{3,4})\b/gi;
  if (cvvRegex.test(redactedText)) {
    detectedTypes.push('Card CVV/CVC');
    redactedText = redactedText.replace(cvvRegex, '$1: [REDACTED-CVV]');
  }

  // Explicit password values
  const passwordRegex = /\b(password|passphrase)\s*(?:is|:)\s*(\S{4,40})/gi;
  if (passwordRegex.test(redactedText)) {
    detectedTypes.push('Plaintext Password');
    redactedText = redactedText.replace(passwordRegex, '$1: [REDACTED-PASSWORD]');
  }

  return {
    hasSensitiveData: detectedTypes.length > 0,
    detectedTypes,
    redactedText,
  };
}

/**
 * Creates a privacy-preserving summary snippet for local SQLite Scan History so complete private
 * messages, email addresses, phone numbers, and numbers are never stored in full.
 */
export function createPrivacySafeSnippet(input: string, scanType: ScanType): string {
  const trimmed = input.trim().replace(/\s+/g, ' ');
  if (!trimmed) return '[Empty Input]';

  if (scanType === 'url') {
    try {
      const withProto = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed)
        ? trimmed
        : `http://${trimmed}`;
      const parsed = new URL(withProto);
      const maskedPath = parsed.pathname && parsed.pathname !== '/'
        ? `${parsed.pathname.slice(0, 18)}${parsed.pathname.length > 18 ? '…' : ''}`
        : '/';
      return `${parsed.protocol}//${parsed.hostname}${maskedPath}${parsed.search ? '?[params-redacted]' : ''}`;
    } catch {
      return trimmed.length > 52 ? `${trimmed.slice(0, 52)}…` : trimmed;
    }
  }

  // For messages: mask emails, phone numbers, and long digit sequences, then truncate to 68 chars
  const masked = detectAndRedactSensitiveInput(trimmed).redactedText
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[email-redacted]')
    .replace(/\+?\d[\d\s\-().]{7,}\d/g, '[phone-redacted]')
    .replace(/\b\d{4,}\b/g, '[digits-redacted]');

  return masked.length > 68 ? `${masked.slice(0, 68)}… [truncated for privacy]` : masked;
}

interface MessageRuleDefinition {
  id: string;
  title: string;
  category: string;
  severity: 'low' | 'medium' | 'high';
  weight: number;
  pattern: RegExp;
  tactic: string;
  explanation: string;
}

const MESSAGE_RULES: MessageRuleDefinition[] = [
  {
    id: 'msg-urgent-account-threat',
    title: 'Artificial Account Suspension or Closure Threat',
    category: 'Coercive Urgency',
    severity: 'high',
    weight: 28,
    pattern: /\b(account\s+(?:has\s+been\s+|will\s+be\s+|is\s+)?(?:suspended|locked|terminated|restricted|deactivated|frozen|closed)|immediate\s+verification\s+required|within\s+24\s+hours\s+or\s+your\s+account)\b/i,
    tactic: 'Fear & Coercive Urgency',
    explanation: 'Attackers manufacture panic by claiming your account is about to be suspended or locked unless you act immediately.',
  },
  {
    id: 'msg-credential-harvesting',
    title: 'Direct Request to Verify Credentials or Banking Details',
    category: 'Credential Harvesting',
    severity: 'high',
    weight: 30,
    pattern: /\b(verify\s+your\s+(?:identity|account|password|login|banking|billing|payment|card|ssn)|confirm\s+your\s+(?:credentials|password|pin|otp|cvv|bank\s+details)|update\s+your\s+payment\s+information\s+immediately)\b/i,
    tactic: 'Credential Harvesting',
    explanation: 'Legitimate organizations rarely ask you to confirm passwords, PINs, OTPs, or full payment details through an unsolicited link or message.',
  },
  {
    id: 'msg-mfa-otp-solicitation',
    title: 'Request to Share One-Time Passcode (OTP) or Security Code',
    category: 'MFA Bypass Scam',
    severity: 'high',
    weight: 32,
    pattern: /\b(reply\s+with\s+(?:the|your)\s+(?:code|otp|pin)|share\s+the\s+(?:\d-digit\s+)?(?:verification|security)\s+code|read\s+me\s+the\s+code\s+sent\s+to\s+your\s+phone|enter\s+the\s+otp\s+to\s+cancel)\b/i,
    tactic: 'Multi-Factor Authentication Interception',
    explanation: 'Scammers trigger a real login attempt on your account and trick you into handing over the 2FA/OTP code so they can take over your profile.',
  },
  {
    id: 'msg-financial-lure',
    title: 'Unclaimed Reward, Lottery, Tax Refund, or Crypto Giveaway',
    category: 'Financial Lure',
    severity: 'high',
    weight: 26,
    pattern: /\b(unclaimed\s+(?:reward|refund|package|inheritance|funds)|you\s+have\s+won|congratulations\s+winner|tax\s+refund\s+pending|claim\s+your\s+(?:prize|bonus|airdrop|bitcoin|crypto|gift\s+card))\b/i,
    tactic: 'Too-Good-To-Be-True Reward',
    explanation: 'Scammers dangle unexpected financial windfalls, tax refunds, or prizes to trick victims into paying advance fees or surrendering personal data.',
  },
  {
    id: 'msg-delivery-toll-scam',
    title: 'Smishing Parcel Delivery or Unpaid Road Toll Notice',
    category: 'SMS Delivery / Toll Scam',
    severity: 'medium',
    weight: 22,
    pattern: /\b(package\s+(?:could\s+not\s+be\s+delivered|is\s+on\s+hold|awaiting\s+delivery|held\s+at\s+customs)|incomplete\s+address\s+information|unpaid\s+toll\s+(?:fee|balance|invoice)|avoid\s+late\s+penalties)\b/i,
    tactic: 'Routine Logistics Impersonation',
    explanation: 'Fake parcel customs holds and unpaid toll texts are among the most common SMS phishing (smishing) lures used to steal credit card numbers.',
  },
  {
    id: 'msg-authority-impersonation',
    title: 'High-Authority or Security Department Impersonation',
    category: 'Authority Spoofing',
    severity: 'medium',
    weight: 16,
    pattern: /\b(irs\s+notice|federal\s+tax\s+bureau|fraud\s+prevention\s+department|security\s+alert\s+from\s+your\s+bank|unauthorized\s+sign-in\s+attempt\s+detected|apple\s+id\s+support|microsoft\s+security\s+team|ceo\s+urgent\s+request)\b/i,
    tactic: 'Authority Impersonation',
    explanation: 'Uses official-sounding security or government titles to discourage critical questioning.',
  },
  {
    id: 'msg-bec-executive-fraud',
    title: 'Business Email Compromise (BEC) / Urgent Executive Request',
    category: 'Workplace Impersonation',
    severity: 'medium',
    weight: 24,
    pattern: /\b(are\s+you\s+at\s+your\s+desk|i\s+am\s+in\s+a\s+meeting\s+and\s+cannot\s+talk|process\s+an\s+urgent\s+wire\s+transfer|keep\s+this\s+confidential|purchase\s+\d+\s+gift\s+cards\s+for\s+a\s+client)\b/i,
    tactic: 'Executive / CEO Fraud',
    explanation: 'Impersonates a manager or executive claiming to be in a meeting so you cannot call them to verify an urgent wire transfer or gift card purchase.',
  },
  {
    id: 'msg-dangerous-attachment',
    title: 'High-Risk Executable or Archive Attachment Reference',
    category: 'Malware Delivery',
    severity: 'high',
    weight: 28,
    pattern: /\b(\S+\.(?:exe|scr|iso|vbs|bat|cmd|ps1|msi|jar|hta)|invoice_\d+\.zip|password\s+to\s+open\s+the\s+archive\s+is)\b/i,
    tactic: 'Malicious Attachment Bait',
    explanation: 'Executable files (.exe, .scr, .msi), disk images (.iso), or password-protected .zip archives are commonly used to bypass email antivirus scanners.',
  },
  {
    id: 'msg-sender-mismatch',
    title: 'Brand Name Paired with Free Webmail Address',
    category: 'Sender Spoofing',
    severity: 'high',
    weight: 26,
    pattern: /\b(?:paypal|chase|apple|microsoft|amazon|netflix|bank|irs|usps|fedex|dhl)[^<\n]{0,30}<[a-z0-9._%+-]+@(?:gmail|yahoo|hotmail|outlook|aol|mail|protonmail)\.com>/i,
    tactic: 'Display Name Spoofing',
    explanation: 'The sender display name claims to be a major institution, but the actual email address belongs to a free personal webmail provider.',
  },
  {
    id: 'msg-generic-greeting',
    title: 'Impersonal Greeting Combined with Account Alert',
    category: 'Social Engineering',
    severity: 'low',
    weight: 10,
    pattern: /\b(dear\s+(?:valued\s+customer|account\s+holder|user|client|member|beneficiary))\b/i,
    tactic: 'Mass Phishing Template',
    explanation: 'Mass-blast phishing campaigns often use generic greetings like "Dear Valued Customer" instead of your registered name.',
  },
  {
    id: 'msg-high-pressure-time',
    title: 'High-Pressure Time Constraint',
    category: 'Time Pressure',
    severity: 'medium',
    weight: 16,
    pattern: /\b(act\s+now|urgent\s+action\s+required|respond\s+immediately|expires\s+in\s+\d+\s+(?:hours|minutes)|final\s+warning|last\s+notice\s+before\s+legal\s+action)\b/i,
    tactic: 'Countdown Pressure',
    explanation: 'Tight deadlines are designed to bypass your analytical thinking and force a hasty click.',
  },
  {
    id: 'msg-payment-irreversible',
    title: 'Irreversible Payment Method Demand (Gift Cards / Wire / Crypto)',
    category: 'Payment Fraud',
    severity: 'high',
    weight: 32,
    pattern: /\b(apple\s+gift\s+card|steam\s+card|google\s+play\s+card|wire\s+transfer\s+immediately|send\s+usdt|bitcoin\s+wallet|zelle\s+payment\s+required|western\s+union)\b/i,
    tactic: 'Irreversible Payment Extraction',
    explanation: 'Requests to pay via gift cards, cryptocurrency, or wire transfers are classic hallmarks of fraud because the funds cannot be reversed.',
  },
];

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link', 'zip', 'mov', 'rest', 'fit', 'buzz', 'icu', 'support', 'cam', 'sbs', 'cfd'
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'rb.gy', 'cutt.ly', 'shorturl.at'
]);

const PROTECTED_BRANDS = [
  { brand: 'PayPal', patterns: [/paypa[l1i]/i, /pay-?pal/i] },
  { brand: 'Microsoft', patterns: [/m[i1]crosoft/i, /micros0ft/i, /office365-login/i] },
  { brand: 'Apple', patterns: [/app[l1]e-?(?:id|support|icloud|verify)/i, /icloud-?verify/i] },
  { brand: 'Google', patterns: [/g[o0]{2}g[l1]e/i, /gmail-?(?:security|verify)/i] },
  { brand: 'Amazon', patterns: [/amaz[o0]n/i, /amzn-?(?:verify|prime|order)/i] },
  { brand: 'Netflix', patterns: [/netf[l1]ix/i, /netflix-?(?:billing|update)/i] },
  { brand: 'Chase / Banking', patterns: [/chase-?(?:verify|secure|online)/i, /wellsfarg[o0]/i, /bankofamer[i1]ca/i, /citibank-?login/i] },
  { brand: 'DHL / USPS / FedEx', patterns: [/usps-?(?:track|delivery|customs|redelivery)/i, /fedex-?(?:parcel|track)/i, /dhl-?(?:express|customs)/i] },
];

const OFFICIAL_BRAND_DOMAINS = new Set([
  'paypal.com', 'microsoft.com', 'live.com', 'office.com', 'apple.com', 'icloud.com',
  'google.com', 'gmail.com', 'amazon.com', 'netflix.com', 'chase.com', 'wellsfargo.com',
  'bankofamerica.com', 'citi.com', 'usps.com', 'fedex.com', 'dhl.com'
]);

/**
 * Inspects a URL string purely through local static lexical and structural analysis.
 * NEVER visits, fetches, or opens the submitted URL. Works 100% offline.
 */
export function inspectUrlStructure(rawUrl: string): {
  breakdown: UrlStructureBreakdown;
  indicators: DetectedIndicator[];
  suspiciousPhrases: SuspiciousPhraseAnalysis[];
  ruleScore: number;
} {
  const trimmed = rawUrl.trim();
  const indicators: DetectedIndicator[] = [];
  const suspiciousPhrases: SuspiciousPhraseAnalysis[] = [];
  let score = 0;

  // Check for dangerous non-HTTP schemes (javascript:, data:, vbscript:)
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  const rawProtocol = schemeMatch ? schemeMatch[1].toLowerCase() : 'http';

  if (['javascript', 'data', 'vbscript', 'file'].includes(rawProtocol)) {
    score += 75;
    indicators.push({
      id: 'url-dangerous-scheme',
      title: `Executable or Local URI Scheme (${rawProtocol}:)`,
      severity: 'high',
      category: 'Malicious URI Scheme',
      matchedSnippet: `${rawProtocol}:`,
      explanation: `The URL uses the "${rawProtocol}:" scheme, which can execute code or embed forged pages directly in the browser.`,
      source: 'rule',
    });
  }

  const normalizedInput = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed)
    ? trimmed
    : `http://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(normalizedInput);
  } catch {
    return {
      breakdown: {
        rawInput: trimmed,
        normalizedUrl: trimmed,
        protocol: rawProtocol,
        hostname: trimmed.split('/')[0] || trimmed,
        subdomainCount: 0,
        tld: '',
        port: '',
        pathLength: trimmed.length,
        queryParamCount: 0,
        hasIpAddressHost: false,
        hasAtSymbolRedirect: trimmed.includes('@'),
        hasPunycode: trimmed.toLowerCase().includes('xn--'),
        isShortener: false,
      },
      indicators: [
        ...indicators,
        {
          id: 'url-malformed',
          title: 'Malformed or Obfuscated URL Structure',
          severity: 'medium',
          category: 'Structural Anomaly',
          matchedSnippet: trimmed.slice(0, 50),
          explanation: 'The submitted URL does not conform to standard domain formatting, which often indicates obfuscation.',
          source: 'rule',
        },
      ],
      suspiciousPhrases,
      ruleScore: Math.min(100, Math.max(score, 45)),
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const hostParts = hostname.split('.').filter(Boolean);

  // Check if host is an IPv4 or IPv6 literal
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const isHexOrOctalIp = /^0x[0-9a-f]+$/i.test(hostname) || /^\d{8,10}$/.test(hostname);
  const hasIpAddressHost = ipv4Regex.test(hostname) || hostname.startsWith('[') || isHexOrOctalIp;

  const tld = !hasIpAddressHost && hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';
  const registrableDomain = !hasIpAddressHost && hostParts.length >= 2 ? `${hostParts[hostParts.length - 2]}.${tld}` : hostname;

  const subdomainCount = hasIpAddressHost ? 0 : Math.max(0, hostParts.length - 2);
  const hasAtSymbolRedirect = Boolean(parsed.username || parsed.password || trimmed.split('?')[0].includes('@'));
  const hasPunycode = hostname.includes('xn--');
  const isShortener = URL_SHORTENERS.has(registrableDomain) || URL_SHORTENERS.has(hostname);

  // 1. Raw IP address host check
  if (hasIpAddressHost) {
    score += 38;
    indicators.push({
      id: 'url-ip-host',
      title: 'Raw IP Address Used Instead of Domain Name',
      severity: 'high',
      category: 'Host Obfuscation',
      matchedSnippet: hostname,
      explanation: 'Legitimate consumer portals almost never direct users to a raw IP address (e.g., http://192.168.x.x). Phishing kits frequently run on temporary IP hosts.',
      source: 'rule',
    });
    suspiciousPhrases.push({
      phrase: hostname,
      tactic: 'IP Host Evasion',
      whySuspicious: 'Bypasses domain reputation filters by hosting directly on an IP address.',
    });
  }

  // 2. @ symbol credential / host redirection check
  if (hasAtSymbolRedirect) {
    score += 35;
    indicators.push({
      id: 'url-at-symbol',
      title: 'Embedded "@" Symbol Host Redirection',
      severity: 'high',
      category: 'URI Deception',
      matchedSnippet: '@',
      explanation: 'In URLs, everything before the "@" symbol is treated as a username, while the browser actually navigates to the host after "@". Attackers use this to disguise the true destination.',
      source: 'rule',
    });
    suspiciousPhrases.push({
      phrase: '@',
      tactic: 'Userinfo Host Masking',
      whySuspicious: 'Tricks users into reading the left side as the domain while routing to the right side.',
    });
  }

  // 3. Punycode / IDN homograph attack check
  if (hasPunycode) {
    score += 32;
    indicators.push({
      id: 'url-punycode',
      title: 'Internationalized Domain Name (Punycode "xn--")',
      severity: 'high',
      category: 'Homograph Spoofing',
      matchedSnippet: hostname,
      explanation: 'Domains starting with "xn--" use non-ASCII lookalike characters (such as Cyrillic "а" instead of Latin "a") to visually impersonate trusted brands.',
      source: 'rule',
    });
  }

  // 4. Brand impersonation / typosquatting check
  let impersonatedBrand: string | undefined;
  const fullUrlLower = `${hostname}${parsed.pathname}${parsed.search}`.toLowerCase();
  if (!OFFICIAL_BRAND_DOMAINS.has(registrableDomain)) {
    for (const entry of PROTECTED_BRANDS) {
      if (entry.patterns.some((rx) => rx.test(fullUrlLower))) {
        impersonatedBrand = entry.brand;
        score += 34;
        indicators.push({
          id: 'url-brand-impersonation',
          title: `Potential ${entry.brand} Brand Impersonation or Typosquatting`,
          severity: 'high',
          category: 'Brand Spoofing',
          matchedSnippet: hostname,
          explanation: `The URL references or mimics ${entry.brand} (e.g., lookalike spelling or brand keyword in subdomain/path), but the actual destination host is "${registrableDomain}".`,
          source: 'rule',
        });
        suspiciousPhrases.push({
          phrase: registrableDomain,
          tactic: `Impersonating ${entry.brand}`,
          whySuspicious: `Contains ${entry.brand}-related naming outside its official domain.`,
        });
        break;
      }
    }
  }

  // 5. High-risk TLD check
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 22;
    indicators.push({
      id: 'url-suspicious-tld',
      title: `High-Abuse Top-Level Domain (.${tld})`,
      severity: 'medium',
      category: 'Domain Reputation',
      matchedSnippet: `.${tld}`,
      explanation: `The ".${tld}" top-level domain is frequently abused in disposable phishing campaigns due to low registration barriers or misleading file-like extensions (.zip, .mov).`,
      source: 'rule',
    });
  }

  // 6. Excessive subdomains (e.g., login.secure.verify.account.example.com)
  if (subdomainCount >= 3) {
    score += 20;
    indicators.push({
      id: 'url-excessive-subdomains',
      title: `Deep Subdomain Chaining (${subdomainCount} Subdomains)`,
      severity: 'medium',
      category: 'Subdomain Masking',
      matchedSnippet: hostname,
      explanation: 'Attackers stack multiple subdomains (like "secure.login.account...") so mobile browsers push the real root domain out of view.',
      source: 'rule',
    });
  }

  // 7. Deceptive "https" token embedded inside hostname
  if (hostname.includes('https-') || hostname.includes('-https')) {
    score += 24;
    indicators.push({
      id: 'url-fake-https-token',
      title: 'Deceptive "https-" Keyword in Domain Name',
      severity: 'high',
      category: 'Transport Spoofing',
      matchedSnippet: 'https-',
      explanation: 'Attackers put "https-" inside the domain name itself to trick users into thinking the connection is encrypted and trusted.',
      source: 'rule',
    });
  }

  // 8. Unencrypted HTTP protocol check
  const hasSensitiveKeywordsInUrl = /(login|signin|verify|secure|account|update|banking|password|confirm|wallet|auth|unlock|invoice|payment)/i.test(fullUrlLower);
  if (parsed.protocol === 'http:') {
    const weight = hasSensitiveKeywordsInUrl ? 24 : 12;
    score += weight;
    indicators.push({
      id: 'url-insecure-http',
      title: hasSensitiveKeywordsInUrl
        ? 'Unencrypted HTTP on Login/Verification Path'
        : 'Unencrypted HTTP Protocol',
      severity: hasSensitiveKeywordsInUrl ? 'high' : 'low',
      category: 'Transport Security',
      matchedSnippet: 'http://',
      explanation: hasSensitiveKeywordsInUrl
        ? 'This link uses unencrypted HTTP while referencing account login or verification keywords. Any data entered would be transmitted in plaintext.'
        : 'The URL uses HTTP instead of HTTPS encryption.',
      source: 'rule',
    });
  }

  // 9. Suspicious credential/action keywords in hostname or path
  if (hasSensitiveKeywordsInUrl && !OFFICIAL_BRAND_DOMAINS.has(registrableDomain)) {
    score += 18;
    const matchedKeyword = fullUrlLower.match(/(login|signin|verify|secure|account|update|banking|password|confirm|wallet|auth|unlock|invoice|payment)/i)?.[0] || 'verify';
    indicators.push({
      id: 'url-deceptive-keywords',
      title: 'Authentication / Security Lure Keywords in URL',
      severity: 'medium',
      category: 'Lexical Lure',
      matchedSnippet: matchedKeyword,
      explanation: `Contains high-risk action keywords ("${matchedKeyword}") on an unrecognized domain ("${registrableDomain}").`,
      source: 'rule',
    });
    suspiciousPhrases.push({
      phrase: matchedKeyword,
      tactic: 'Security Keyword Bait',
      whySuspicious: 'Used in URL paths or subdomains to mimic an official authentication flow.',
    });
  }

  // 10. Open Redirect Parameter Check (?redirect=http..., ?url=http...)
  if (/[?&](?:redirect|url|next|return|dest|destination|continue)=(?:https?%3A|https?:|\/\/)/i.test(parsed.search)) {
    score += 22;
    indicators.push({
      id: 'url-open-redirect',
      title: 'External Redirect Parameter Detected in Query String',
      severity: 'medium',
      category: 'Open Redirect Abuse',
      matchedSnippet: parsed.search.slice(0, 42),
      explanation: 'This link contains a redirect parameter pointing to another URL, which scammers use to bounce victims through a legitimate site onto a phishing page.',
      source: 'rule',
    });
  }

  // 11. URL Shortener check
  if (isShortener) {
    score += 25;
    indicators.push({
      id: 'url-shortener',
      title: 'Obfuscated Destination via Link Shortener',
      severity: 'medium',
      category: 'Destination Hiding',
      matchedSnippet: hostname,
      explanation: `Link shorteners (${hostname}) hide the true final domain until after you click, a common technique in SMS phishing.`,
      source: 'rule',
    });
  }

  // 12. Non-standard port or overly long path/query
  if (parsed.port && !['80', '443'].includes(parsed.port)) {
    score += 18;
    indicators.push({
      id: 'url-nonstandard-port',
      title: `Non-Standard Network Port (:${parsed.port})`,
      severity: 'medium',
      category: 'Infrastructure Anomaly',
      matchedSnippet: `:${parsed.port}`,
      explanation: `Standard web services run on port 443 (HTTPS) or 80 (HTTP). Port :${parsed.port} often points to an ad-hoc server or compromised host.`,
      source: 'rule',
    });
  }

  if ((parsed.pathname.length + parsed.search.length) > 95) {
    score += 12;
    indicators.push({
      id: 'url-long-payload',
      title: 'Unusually Long Path or Encoded Query Parameters',
      severity: 'low',
      category: 'Tracking / Payload Obfuscation',
      matchedSnippet: `${parsed.pathname.slice(0, 32)}…`,
      explanation: 'Long query strings often embed victim email addresses, base64 tokens, or open-redirect targets.',
      source: 'rule',
    });
  }

  const queryParamCount = Array.from(parsed.searchParams.keys()).length;

  return {
    breakdown: {
      rawInput: trimmed,
      normalizedUrl: parsed.href,
      protocol: parsed.protocol.replace(':', ''),
      hostname,
      subdomainCount,
      tld,
      port: parsed.port || (parsed.protocol === 'https:' ? '443 (default)' : '80 (default)'),
      pathLength: parsed.pathname.length,
      queryParamCount,
      hasIpAddressHost,
      hasAtSymbolRedirect,
      hasPunycode,
      isShortener,
      impersonatedBrand,
    },
    indicators,
    suspiciousPhrases,
    ruleScore: Math.min(100, Math.round(score)),
  };
}

/**
 * Runs deterministic local rule-based phishing analysis on an email or SMS message.
 * Also extracts and statically inspects any embedded URLs inside the message.
 */
export function analyzeMessageRules(message: string): {
  ruleScore: number;
  indicators: DetectedIndicator[];
  suspiciousPhrases: SuspiciousPhraseAnalysis[];
  embeddedUrls: string[];
  urlBreakdown?: UrlStructureBreakdown;
} {
  const indicators: DetectedIndicator[] = [];
  const suspiciousPhrases: SuspiciousPhraseAnalysis[] = [];
  let totalScore = 0;

  for (const rule of MESSAGE_RULES) {
    const match = message.match(rule.pattern);
    if (match) {
      totalScore += rule.weight;
      const snippet = match[0];
      indicators.push({
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: rule.category,
        matchedSnippet: snippet,
        explanation: rule.explanation,
        source: 'rule',
      });
      suspiciousPhrases.push({
        phrase: snippet,
        tactic: rule.tactic,
        whySuspicious: rule.explanation,
      });
    }
  }

  // Extract embedded URLs in the message without visiting them
  const urlRegex = /\b((?:https?:\/\/|www\.)[^\s<>()"']+|[a-zA-Z0-9.-]+\.(?:com|net|org|edu|gov|io|co|uk|us|tk|ml|ga|cf|gq|xyz|top|click|link|zip|info|biz)(?:\/[^\s<>()"']*)?)/gi;
  const rawMatches = message.match(urlRegex) || [];
  const embeddedUrls = Array.from(new Set(rawMatches.map((u) => u.replace(/[.,;!?)]+$/, ''))));

  let firstUrlBreakdown: UrlStructureBreakdown | undefined;
  if (embeddedUrls.length > 0) {
    const primaryUrl = embeddedUrls[0];
    const urlInspection = inspectUrlStructure(primaryUrl);
    firstUrlBreakdown = urlInspection.breakdown;

    if (urlInspection.ruleScore > 0) {
      totalScore += Math.round(urlInspection.ruleScore * 0.65);
      for (const ind of urlInspection.indicators) {
        indicators.push({
          ...ind,
          id: `embedded-${ind.id}`,
          title: `Embedded Link: ${ind.title}`,
        });
      }
      suspiciousPhrases.push(...urlInspection.suspiciousPhrases);
    }
  }

  // Check for excessive exclamation marks or all-caps shouting
  const upperWords = (message.match(/\b[A-Z]{4,}\b/g) || []).filter(
    (w) => !['HTTP', 'HTTPS', 'HTML', 'USPS', 'FDIC', 'ASAP', 'NOTE', 'INFO', 'TEAM', 'SMTP'].includes(w)
  );
  if (upperWords.length >= 3) {
    totalScore += 10;
    indicators.push({
      id: 'msg-caps-urgency',
      title: 'Aggressive Capitalization / Visual Alarmism',
      severity: 'low',
      category: 'Formatting Pressure',
      matchedSnippet: upperWords.slice(0, 4).join(', '),
      explanation: 'Multiple all-caps words are commonly used to simulate emergency system alerts.',
      source: 'rule',
    });
  }

  const clampedScore = Math.min(100, Math.round(totalScore));
  return {
    ruleScore: clampedScore,
    indicators,
    suspiciousPhrases,
    embeddedUrls,
    urlBreakdown: firstUrlBreakdown,
  };
}

/**
 * Generates a natural, human-friendly summary offline based on the specific rules triggered.
 */
export function generateLocalDetailedSummary(
  scanType: ScanType,
  riskScore: number,
  riskCategory: RiskCategory,
  indicators: DetectedIndicator[],
  urlBreakdown?: UrlStructureBreakdown
): string {
  if (indicators.length === 0) {
    return scanType === 'url'
      ? `Static structural inspection of "${urlBreakdown?.hostname || 'this URL'}" found no known domain-spoofing, raw IP routing, or deceptive redirect patterns. Note: a low risk score does not guarantee a website is safe—always verify the address before entering login or financial details.`
      : 'No urgent coercion, credential harvesting requests, or deceptive links were detected in this message. Even with lower indicators, always confirm unexpected requests with the sender through a trusted channel.';
  }

  const topCategories = Array.from(new Set(indicators.map((i) => i.category))).slice(0, 3);
  const matchedSnippets = indicators
    .map((i) => i.matchedSnippet)
    .filter(Boolean)
    .slice(0, 2);

  if (scanType === 'url' && urlBreakdown) {
    const specifics: string[] = [];
    if (urlBreakdown.hasIpAddressHost) specifics.push(`routes to a raw IP address (${urlBreakdown.hostname})`);
    if (urlBreakdown.hasAtSymbolRedirect) specifics.push('uses an "@" redirect trick to disguise the real host');
    if (urlBreakdown.impersonatedBrand) specifics.push(`mimics ${urlBreakdown.impersonatedBrand} on an unofficial domain`);
    if (urlBreakdown.protocol === 'http') specifics.push('uses unencrypted HTTP');

    if (specifics.length > 0) {
      return `Structural URL inspection scored this link ${riskScore}/100 (${riskCategory}) because it ${specifics.join(', ')}. Do not open this link or enter login credentials.`;
    }
  }

  const snippetText =
    matchedSnippets.length > 0 ? ` (including "${matchedSnippets.join('" and "')}")` : '';

  if (riskCategory === 'High Risk') {
    return `Security analysis flagged ${indicators.length} high-risk warning sign(s) involving ${topCategories.join(', ')}${snippetText}. This strongly matches known phishing templates designed to steal credentials or payment details.`;
  }

  return `Security analysis detected ${indicators.length} warning sign(s) related to ${topCategories.join(' and ')}${snippetText}. Verify this request directly with the organization through an official website or phone number before acting.`;
}

export interface GeminiStructuredAssessment {
  aiRiskScore: number;
  summary: string;
  warningSigns: string[];
  suspiciousPhrases: SuspiciousPhraseAnalysis[];
  additionalIndicators: Array<{
    title: string;
    severity: 'low' | 'medium' | 'high';
    category: string;
    matchedSnippet?: string;
    explanation: string;
  }>;
  recommendedActions: string[];
  uncertaintyNote: string;
}

/**
 * Combines deterministic rule-based findings with Google Gemini AI analysis when available,
 * or produces a transparent rule-based result when Gemini AI is unavailable.
 */
export function buildFinalScanResult(params: {
  id: string;
  scanType: ScanType;
  rawInput: string;
  ruleScore: number;
  ruleIndicators: DetectedIndicator[];
  rulePhrases: SuspiciousPhraseAnalysis[];
  urlBreakdown?: UrlStructureBreakdown;
  aiAssessment?: GeminiStructuredAssessment | null;
  fallbackReason?: string;
  preferOfflineEngine?: boolean;
}): ScanAnalysisResult {
  const {
    id,
    scanType,
    rawInput,
    ruleScore,
    ruleIndicators,
    rulePhrases,
    urlBreakdown,
    aiAssessment,
    fallbackReason,
    preferOfflineEngine,
  } = params;

  const timestamp = new Date().toISOString();
  const privacySafeSnippet = createPrivacySafeSnippet(rawInput, scanType);

  let finalScore = ruleScore;
  let aiScore: number | null = null;
  let analysisEngine: AnalysisEngineType = preferOfflineEngine
    ? 'local-offline-engine'
    : 'rule-based-fallback';

  const combinedIndicators: DetectedIndicator[] = [...ruleIndicators];
  const combinedPhrases: SuspiciousPhraseAnalysis[] = [...rulePhrases];

  if (aiAssessment && typeof aiAssessment.aiRiskScore === 'number' && !preferOfflineEngine) {
    analysisEngine = 'hybrid-gemini-and-rules';
    aiScore = Math.max(0, Math.min(100, Math.round(aiAssessment.aiRiskScore)));

    // Weighted combination that never downgrades strong deterministic rule detections
    const blended = Math.round(aiScore * 0.55 + ruleScore * 0.45);
    finalScore = Math.max(blended, Math.round(ruleScore * 0.85));
    finalScore = Math.max(0, Math.min(100, finalScore));

    for (const [idx, aiInd] of (aiAssessment.additionalIndicators || []).entries()) {
      const duplicate = combinedIndicators.find(
        (existing) => existing.title.toLowerCase() === aiInd.title.toLowerCase()
      );
      if (duplicate) {
        duplicate.source = 'both';
      } else {
        combinedIndicators.push({
          id: `ai-ind-${idx}`,
          title: aiInd.title,
          severity: aiInd.severity || 'medium',
          category: aiInd.category || 'AI Linguistic Analysis',
          matchedSnippet: aiInd.matchedSnippet,
          explanation: aiInd.explanation,
          source: 'ai',
        });
      }
    }

    for (const phrase of aiAssessment.suspiciousPhrases || []) {
      const exists = combinedPhrases.some(
        (p) => p.phrase.toLowerCase() === phrase.phrase.toLowerCase()
      );
      if (!exists && phrase.phrase.trim()) {
        combinedPhrases.push(phrase);
      }
    }
  }

  const riskCategory = classifyRiskScore(finalScore);

  const defaultWarningSigns =
    combinedIndicators.length > 0
      ? combinedIndicators.map((ind) => ind.title)
      : [];

  const warningSigns =
    aiAssessment && aiAssessment.warningSigns && aiAssessment.warningSigns.length > 0 && !preferOfflineEngine
      ? Array.from(new Set([...aiAssessment.warningSigns, ...defaultWarningSigns])).slice(0, 6)
      : defaultWarningSigns.slice(0, 6);

  const localSummary = generateLocalDetailedSummary(
    scanType,
    finalScore,
    riskCategory,
    combinedIndicators,
    urlBreakdown
  );

  const defaultUncertainty =
    'Automated detection is probabilistic and cannot guarantee 100% accuracy. A low risk score does not guarantee a message or website is safe—always verify unexpected requests through an official website or phone number.';

  const defaultRecommendations =
    riskCategory === 'High Risk'
      ? [
          'Do not click any links, download attachments, or scan QR codes in this message.',
          'Never enter your password, OTP, PIN, CVV, or banking details on the linked page.',
          'Visit the organization independently by typing its official address into your browser or using its official app.',
          'Report the message as phishing (forward suspicious SMS to 7726) and delete it.',
        ]
      : riskCategory === 'Suspicious'
        ? [
            'Pause before acting—treat any sense of urgency or account threat with skepticism.',
            'Verify the request by contacting the sender or institution using a phone number or website you look up independently.',
            'Inspect the full sender address and domain spelling carefully for subtle character substitutions.',
          ]
        : [
            'Remember that a low risk score does not guarantee safety—always stay alert for unusual context.',
            'Confirm that the sender address matches your expected contact before replying or opening attachments.',
            'Keep multi-factor authentication (MFA) enabled on your important accounts.',
          ];

  return {
    id,
    scanType,
    timestamp,
    riskScore: finalScore,
    riskCategory,
    ruleScore,
    aiScore,
    analysisEngine,
    fallbackReason,
    summary: !preferOfflineEngine && aiAssessment?.summary ? aiAssessment.summary : localSummary,
    uncertaintyStatement: aiAssessment?.uncertaintyNote || defaultUncertainty,
    warningSigns,
    indicators: combinedIndicators,
    suspiciousPhrases: combinedPhrases.slice(0, 8),
    recommendedActions:
      !preferOfflineEngine && aiAssessment?.recommendedActions && aiAssessment.recommendedActions.length > 0
        ? aiAssessment.recommendedActions
        : defaultRecommendations,
    urlBreakdown,
    privacySafeSnippet,
  };
}
