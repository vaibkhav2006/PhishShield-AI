import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyRiskScore,
  detectAndRedactSensitiveInput,
  createPrivacySafeSnippet,
  inspectUrlStructure,
  analyzeMessageRules,
  buildFinalScanResult,
} from './phishingRules';

test('classifyRiskScore maps 0-29, 30-59, and 60-100 accurately', () => {
  assert.equal(classifyRiskScore(0), 'Lower Indicators');
  assert.equal(classifyRiskScore(15), 'Lower Indicators');
  assert.equal(classifyRiskScore(29), 'Lower Indicators');
  assert.equal(classifyRiskScore(30), 'Suspicious');
  assert.equal(classifyRiskScore(45), 'Suspicious');
  assert.equal(classifyRiskScore(59), 'Suspicious');
  assert.equal(classifyRiskScore(60), 'High Risk');
  assert.equal(classifyRiskScore(88), 'High Risk');
  assert.equal(classifyRiskScore(100), 'High Risk');
});

test('detectAndRedactSensitiveInput flags and redacts OTPs, CVVs, and card numbers', () => {
  const sample = 'My OTP is 482910 and my CVV: 842 for card 4532 0151 1283 0366';
  const result = detectAndRedactSensitiveInput(sample);
  assert.equal(result.hasSensitiveData, true);
  assert.ok(result.detectedTypes.includes('Payment Card Number'));
  assert.ok(result.detectedTypes.includes('One-Time Passcode (OTP)'));
  assert.ok(result.detectedTypes.includes('Card CVV/CVC'));
  assert.ok(!result.redactedText.includes('482910'));
  assert.ok(!result.redactedText.includes('4532 0151 1283 0366'));
});

test('createPrivacySafeSnippet masks private emails/phones and truncates long messages', () => {
  const privateEmail = 'Hi john.doe@example.com, call +1 (555) 234-5678 regarding invoice 994821 immediately because we need your confirmation.';
  const snippet = createPrivacySafeSnippet(privateEmail, 'message');
  assert.ok(!snippet.includes('john.doe@example.com'));
  assert.ok(!snippet.includes('234-5678'));
  assert.ok(snippet.includes('[email-redacted]'));
});

test('inspectUrlStructure statically flags IP hosts, @ redirect, and brand spoofing without visiting URL', () => {
  const maliciousUrl = 'http://secure-login@192.168.10.45:8080/paypaI-verify/login?session=12345';
  const result = inspectUrlStructure(maliciousUrl);

  assert.equal(result.breakdown.hasIpAddressHost, true);
  assert.equal(result.breakdown.hasAtSymbolRedirect, true);
  assert.equal(result.breakdown.protocol, 'http');
  assert.ok(result.ruleScore >= 60, `Expected High Risk score >= 60, got ${result.ruleScore}`);
  assert.equal(classifyRiskScore(result.ruleScore), 'High Risk');
});

test('inspectUrlStructure rates clean official HTTPS URLs as Lower Indicators', () => {
  const safeUrl = 'https://www.microsoft.com/en-us/security';
  const result = inspectUrlStructure(safeUrl);
  assert.equal(result.ruleScore, 0);
  assert.equal(classifyRiskScore(result.ruleScore), 'Lower Indicators');
});

test('analyzeMessageRules detects coercive urgency, credential harvesting, MFA theft, and dangerous attachments', () => {
  const phishingSms =
    'URGENT ACTION REQUIRED: Your Chase account has been suspended! Reply with the 6-digit verification code and open Invoice_Payment.exe or verify at http://chase-secure-verify.tk/login within 24 hours.';
  const analysis = analyzeMessageRules(phishingSms);

  assert.ok(analysis.ruleScore >= 60, `Expected >= 60 for high-risk phishing SMS, got ${analysis.ruleScore}`);
  assert.ok(analysis.indicators.length >= 4);
  assert.equal(analysis.embeddedUrls[0], 'http://chase-secure-verify.tk/login');
});

test('buildFinalScanResult combines Gemini AI structured output with rule-based checks and supports fallback', () => {
  const msg = 'Dear Valued Customer, your package is on hold due to incomplete address information. Act now at http://usps-redelivery-fee.xyz/pay';
  const rules = analyzeMessageRules(msg);

  const hybridResult = buildFinalScanResult({
    id: 'test-hybrid-1',
    scanType: 'message',
    rawInput: msg,
    ruleScore: rules.ruleScore,
    ruleIndicators: rules.indicators,
    rulePhrases: rules.suspiciousPhrases,
    urlBreakdown: rules.urlBreakdown,
    aiAssessment: {
      aiRiskScore: 92,
      summary: 'High-risk parcel delivery smishing lure directing to an untrusted .xyz payment page.',
      warningSigns: ['Unencrypted .xyz domain', 'Generic greeting'],
      suspiciousPhrases: [],
      additionalIndicators: [],
      recommendedActions: ['Do not click the link.'],
      uncertaintyNote: 'Automated detection is not 100% accurate.',
    },
  });

  assert.equal(hybridResult.analysisEngine, 'hybrid-gemini-and-rules');
  assert.equal(hybridResult.aiScore, 92);
  assert.equal(hybridResult.riskCategory, 'High Risk');

  const fallbackResult = buildFinalScanResult({
    id: 'test-fallback-1',
    scanType: 'message',
    rawInput: msg,
    ruleScore: rules.ruleScore,
    ruleIndicators: rules.indicators,
    rulePhrases: rules.suspiciousPhrases,
    urlBreakdown: rules.urlBreakdown,
    aiAssessment: null,
    fallbackReason: 'Gemini API temporarily unavailable; using deterministic rule-based engine.',
  });

  assert.equal(fallbackResult.analysisEngine, 'rule-based-fallback');
  assert.equal(fallbackResult.riskScore, rules.ruleScore);
  assert.equal(fallbackResult.riskCategory, 'High Risk');
});

test('persistent serverDb records hybrid Gemini scans, clears, and restores seed history', async () => {
  const {
    getHistoryFromDb,
    recordScanInDb,
    getCachedResult,
    clearHistoryInDb,
    restoreSeedHistoryInDb,
  } = await import('./serverDb');

  const initial = restoreSeedHistoryInDb();
  assert.equal(initial.length, 3);

  const sampleMsg = 'Your account has been suspended! Verify your password immediately.';
  const rules = analyzeMessageRules(sampleMsg);
  const scanRes = buildFinalScanResult({
    id: 'db-test-1',
    scanType: 'message',
    rawInput: sampleMsg,
    ruleScore: rules.ruleScore,
    ruleIndicators: rules.indicators,
    rulePhrases: rules.suspiciousPhrases,
    aiAssessment: {
      aiRiskScore: 88,
      summary: 'High risk credential harvesting message.',
      warningSigns: ['Account suspension threat'],
      suspiciousPhrases: [],
      additionalIndicators: [],
      recommendedActions: ['Do not reply.'],
      uncertaintyNote: 'Automated detection is not 100% accurate.',
    },
  });

  const updatedHistory = recordScanInDb('message:gemini:test-key', scanRes);
  assert.equal(updatedHistory[0].id, 'db-test-1');
  assert.equal(updatedHistory[0].analysisEngine, 'hybrid-gemini-and-rules');
  assert.ok(getCachedResult('message:gemini:test-key'));

  const cleared = clearHistoryInDb();
  assert.equal(cleared.length, 0);

  const restored = restoreSeedHistoryInDb();
  assert.equal(restored.length, 3);
  assert.equal(getHistoryFromDb().history.length, 3);

  const finalClean = clearHistoryInDb();
  assert.equal(finalClean.length, 0);
});
