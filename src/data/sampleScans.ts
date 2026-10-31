import {
  analyzeMessageRules,
  inspectUrlStructure,
  buildFinalScanResult,
  type ScanHistoryItem,
} from '../utils/phishingRules';

export interface SamplePreset {
  id: string;
  label: string;
  badge: string;
  type: 'message' | 'url';
  expectedRisk: 'High Risk' | 'Suspicious' | 'Lower Indicators';
  content: string;
}

export const MESSAGE_PRESETS: SamplePreset[] = [
  {
    id: 'preset-msg-high',
    label: 'Suspicious Banking Message',
    badge: 'Fictional Example · High Risk',
    type: 'message',
    expectedRisk: 'High Risk',
    content:
      '[Fictional Example] SECURITY NOTICE: Dear Valued Customer, your checking account has been suspended due to an unauthorized sign-in attempt detected. Verify your identity and password immediately within 24 hours at http://firstnational-secure-verify.tk/login or your account will be permanently closed.',
  },
  {
    id: 'preset-msg-suspicious',
    label: 'Fake Delivery Notification',
    badge: 'Fictional Example · Suspicious',
    type: 'message',
    expectedRisk: 'Suspicious',
    content:
      '[Fictional Example] Parcel Dispatch Alert: Your package #EX-4920-US is on hold at our regional sorting center due to incomplete street address information. Please respond immediately to confirm redelivery details and avoid return penalties.',
  },
  {
    id: 'preset-msg-low',
    label: 'Normal Conversation',
    badge: 'Fictional Example · Low Risk',
    type: 'message',
    expectedRisk: 'Lower Indicators',
    content:
      '[Fictional Example] Hi Alex, thanks for joining the product design review earlier today. I uploaded the updated sprint notes to our shared team folder. Let me know if you have any feedback before Thursday afternoon.',
  },
];

export const URL_PRESETS: SamplePreset[] = [
  {
    id: 'preset-url-high',
    label: 'Spoofed Banking IP Link',
    badge: 'Fictional Example · High Risk',
    type: 'url',
    expectedRisk: 'High Risk',
    content: 'http://paypal.com.account-verify@192.168.42.118:8080/paypaI-login/confirm?session=89f1a',
  },
  {
    id: 'preset-url-suspicious',
    label: 'Unusual .xyz Portal Link',
    badge: 'Fictional Example · Suspicious',
    type: 'url',
    expectedRisk: 'Suspicious',
    content: 'https://portal.auth.document.review-center.xyz/invoice/view',
  },
  {
    id: 'preset-url-low',
    label: 'Official Documentation URL',
    badge: 'Fictional Example · Low Risk',
    type: 'url',
    expectedRisk: 'Lower Indicators',
    content: 'https://www.microsoft.com/en-us/security/business/security-101/what-is-phishing',
  },
];

export function createInitialSeedHistory(): ScanHistoryItem[] {
  const highMsg = MESSAGE_PRESETS[0].content;
  const highMsgRules = analyzeMessageRules(highMsg);
  const highMsgResult = buildFinalScanResult({
    id: 'seed-scan-1',
    scanType: 'message',
    rawInput: highMsg,
    ruleScore: highMsgRules.ruleScore,
    ruleIndicators: highMsgRules.indicators,
    rulePhrases: highMsgRules.suspiciousPhrases,
    urlBreakdown: highMsgRules.urlBreakdown,
    aiAssessment: null,
    fallbackReason: 'Rule-based evaluation of fictional sample.',
  });

  const urlSample = URL_PRESETS[0].content;
  const urlRules = inspectUrlStructure(urlSample);
  const urlResult = buildFinalScanResult({
    id: 'seed-scan-2',
    scanType: 'url',
    rawInput: urlSample,
    ruleScore: urlRules.ruleScore,
    ruleIndicators: urlRules.indicators,
    rulePhrases: urlRules.suspiciousPhrases,
    urlBreakdown: urlRules.breakdown,
    aiAssessment: null,
    fallbackReason: 'Rule-based evaluation of fictional sample.',
  });

  const lowMsg = MESSAGE_PRESETS[2].content;
  const lowRules = analyzeMessageRules(lowMsg);
  const lowResult = buildFinalScanResult({
    id: 'seed-scan-3',
    scanType: 'message',
    rawInput: lowMsg,
    ruleScore: lowRules.ruleScore,
    ruleIndicators: lowRules.indicators,
    rulePhrases: lowRules.suspiciousPhrases,
    aiAssessment: null,
    fallbackReason: 'Rule-based evaluation of fictional sample.',
  });

  return [
    {
      id: highMsgResult.id,
      scanType: 'message',
      timestamp: highMsgResult.timestamp,
      riskScore: highMsgResult.riskScore,
      riskCategory: highMsgResult.riskCategory,
      privacySafeSnippet: highMsgResult.privacySafeSnippet,
      indicatorCount: highMsgResult.indicators.length,
      analysisEngine: highMsgResult.analysisEngine,
      fullResult: highMsgResult,
    },
    {
      id: urlResult.id,
      scanType: 'url',
      timestamp: urlResult.timestamp,
      riskScore: urlResult.riskScore,
      riskCategory: urlResult.riskCategory,
      privacySafeSnippet: urlResult.privacySafeSnippet,
      indicatorCount: urlResult.indicators.length,
      analysisEngine: urlResult.analysisEngine,
      fullResult: urlResult,
    },
    {
      id: lowResult.id,
      scanType: 'message',
      timestamp: lowResult.timestamp,
      riskScore: lowResult.riskScore,
      riskCategory: lowResult.riskCategory,
      privacySafeSnippet: lowResult.privacySafeSnippet,
      indicatorCount: lowResult.indicators.length,
      analysisEngine: lowResult.analysisEngine,
      fullResult: lowResult,
    },
  ];
}
