import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  Globe,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Clock,
  Link2,
  UserX,
  KeyRound,
  FileWarning,
  SlidersHorizontal,
  Sparkles,
} from 'lucide-react';
import type {
  ScanAnalysisResult,
  RiskCategory,
  AnalysisEngineType,
  DetectedIndicator,
} from '../utils/phishingRules';

interface ResultsDashboardProps {
  result: ScanAnalysisResult | null;
  isScanning: boolean;
  onRunQuickSample?: () => void;
}

function formatEngineLabel(engine: AnalysisEngineType): string {
  if (engine === 'hybrid-gemini-and-rules') {
    return 'Google Gemini AI + Rule Engine';
  }
  return 'Deterministic Rule Engine';
}

function getIndicatorIcon(category: string, title: string) {
  const combined = `${category} ${title}`.toLowerCase();
  if (combined.includes('urgent') || combined.includes('urgency') || combined.includes('threat') || combined.includes('caps')) {
    return Clock;
  }
  if (combined.includes('url') || combined.includes('link') || combined.includes('redirect') || combined.includes('domain') || combined.includes('ip') || combined.includes('http') || combined.includes('tld') || combined.includes('shortener')) {
    return Link2;
  }
  if (combined.includes('impersonat') || combined.includes('spoof') || combined.includes('brand') || combined.includes('authority') || combined.includes('greeting') || combined.includes('executive')) {
    return UserX;
  }
  if (combined.includes('credential') || combined.includes('password') || combined.includes('otp') || combined.includes('mfa') || combined.includes('payment') || combined.includes('financial')) {
    return KeyRound;
  }
  return FileWarning;
}

function getRiskTheme(category: RiskCategory) {
  switch (category) {
    case 'High Risk':
      return {
        textClass: 'text-rose-400',
        badgeBg: 'bg-rose-500/15 text-rose-300 border-rose-500/35',
        bannerBg: 'bg-gradient-to-br from-rose-950/45 via-[#14213A]/90 to-[#101A2E] border-rose-500/35',
        verdictTitle: 'High Risk — Strong Phishing or Scam Indicators Detected',
        verdictSubtitle: 'Do not click links, download attachments, reply, or share personal information.',
        strokeColor: '#FB7185',
        Icon: ShieldAlert,
      };
    case 'Suspicious':
      return {
        textClass: 'text-amber-300',
        badgeBg: 'bg-amber-500/15 text-amber-200 border-amber-400/35',
        bannerBg: 'bg-gradient-to-br from-amber-950/40 via-[#14213A]/90 to-[#101A2E] border-amber-400/35',
        verdictTitle: 'Suspicious — Caution & Independent Verification Advised',
        verdictSubtitle: 'Warning signs were detected. Verify this request with the sender through an official channel.',
        strokeColor: '#FBBF24',
        Icon: AlertTriangle,
      };
    default:
      return {
        textClass: 'text-emerald-300',
        badgeBg: 'bg-emerald-500/15 text-emerald-200 border-emerald-400/35',
        bannerBg: 'bg-gradient-to-br from-emerald-950/35 via-[#14213A]/90 to-[#101A2E] border-emerald-400/35',
        verdictTitle: 'Lower Indicators — No High-Risk Signatures Triggered',
        verdictSubtitle: 'A low score does not guarantee safety—always verify unexpected links or requests independently.',
        strokeColor: '#34D399',
        Icon: ShieldCheck,
      };
  }
}

export const ResultsDashboard: React.FC<ResultsDashboardProps> = ({
  result,
  isScanning,
  onRunQuickSample,
}) => {
  const [copiedReport, setCopiedReport] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  // Useful Empty State before the user performs their first scan
  if (!result) {
    return (
      <section
        id="results"
        aria-labelledby="results-heading"
        className="scroll-mt-28 h-full"
      >
        <div className="saas-card rounded-3xl p-6 sm:p-8 h-full flex flex-col justify-between animate-fade-up">
          <div className="space-y-6">
            <div className="flex items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
              <div>
                <div className="inline-flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-[#55E6C1] mb-1.5">
                  <SlidersHorizontal className="w-3.5 h-3.5" />
                  <span>Threat Intelligence Report</span>
                </div>
                <h2 id="results-heading" className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                  Ready for Threat Analysis
                </h2>
                <p className="text-sm text-slate-300 mt-1">
                  Submit a message or URL on the left to generate a live risk assessment.
                </p>
              </div>
            </div>

            {/* Empty State Visual Overview */}
            <div className="rounded-2xl bg-[#080E1C]/70 border border-slate-800/90 p-6 sm:p-8 text-center space-y-5">
              <div className="w-16 h-16 rounded-2xl bg-[#14213A] border border-[#35C6F4]/30 flex items-center justify-center mx-auto shadow-lg shadow-[#35C6F4]/10">
                <ShieldCheck className="w-8 h-8 text-[#35C6F4]" />
              </div>

              <div className="space-y-2 max-w-lg mx-auto">
                <h3 className="text-lg font-bold text-white">
                  No Scan Performed Yet
                </h3>
                <p className="text-sm text-slate-300 leading-relaxed">
                  Paste an email, SMS text, or website link into the scanner—or select one of the fictional sample scenarios—to view a complete risk score (0–100), detected warning sign cards, recommended safety actions, and technical scoring details.
                </p>
              </div>

              {onRunQuickSample && (
                <div className="pt-1">
                  <button
                    type="button"
                    onClick={onRunQuickSample}
                    className="interactive-lift inline-flex items-center gap-2 px-5 py-2.5 text-xs font-bold text-slate-950 bg-gradient-to-r from-[#35C6F4] to-[#55E6C1] rounded-xl shadow-md shadow-[#35C6F4]/15 cursor-pointer"
                  >
                    <Sparkles className="w-4 h-4" />
                    <span>Test with Fictional Banking Sample</span>
                  </button>
                </div>
              )}
            </div>

            {/* Risk Category Reference Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="saas-subcard rounded-2xl p-4 space-y-1">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-emerald-300 font-bold">0–29</span>
                  <span className="text-emerald-300">Lower Indicators</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  No common phishing patterns matched. Still verify unexpected senders.
                </p>
              </div>

              <div className="saas-subcard rounded-2xl p-4 space-y-1">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-amber-300 font-bold">30–59</span>
                  <span className="text-amber-300">Suspicious</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Contains pressure tactics or unusual patterns. Confirm via official channels.
                </p>
              </div>

              <div className="saas-subcard rounded-2xl p-4 space-y-1">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-rose-300 font-bold">60–100</span>
                  <span className="text-rose-300">High Risk</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Strong phishing or spoofing indicators. Avoid clicking links or replying.
                </p>
              </div>
            </div>
          </div>

          <div className="pt-4 mt-6 border-t border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-300">
            <Info className="w-4 h-4 text-[#35C6F4] shrink-0 mt-0.5" />
            <span>
              Automated analysis evaluates language patterns and URL structure without ever opening submitted links.
            </span>
          </div>
        </div>
      </section>
    );
  }

  const theme = getRiskTheme(result.riskCategory);
  const StatusIcon = theme.Icon;

  // Circular SVG gauge geometry
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (result.riskScore / 100) * circumference;

  const handleCopySummary = async () => {
    const textToCopy = [
      `PhishShield AI Threat Analysis Report`,
      `Risk Score: ${result.riskScore}/100 (${result.riskCategory})`,
      `Analysis Engine: ${formatEngineLabel(result.analysisEngine)}`,
      `Summary: ${result.summary}`,
      `Detected Warning Signs: ${result.indicators.map((i) => i.title).join('; ') || 'None'}`,
      `Recommended Actions: ${result.recommendedActions.join(' ')}`,
    ].join('\n');

    try {
      await navigator.clipboard.writeText(textToCopy);
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    } catch {
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    }
  };

  return (
    <section
      id="results"
      aria-labelledby="results-heading"
      className="scroll-mt-28 h-full"
    >
      <div
        key={result.id}
        className="saas-card rounded-3xl p-6 sm:p-8 space-y-6 animate-fade-up h-full flex flex-col justify-between"
      >
        <div className="space-y-6">
          {/* Header Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
            <div>
              <div className="inline-flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-[#55E6C1] mb-1">
                <SlidersHorizontal className="w-3.5 h-3.5" />
                <span>Threat Intelligence Report</span>
              </div>
              <h2 id="results-heading" className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Threat Analysis Results
              </h2>
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-300 mt-1">
                <span>{result.scanType === 'url' ? 'Static URL Inspection' : 'Message & Linguistic Scan'}</span>
                <span aria-hidden="true">·</span>
                <span data-testid="analysis-engine-label" className="text-[#35C6F4] font-medium">
                  {formatEngineLabel(result.analysisEngine)}
                </span>
                {isScanning && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span className="text-[#55E6C1] font-medium">Updating analysis...</span>
                  </>
                )}
              </div>
            </div>

            <button
              type="button"
              onClick={handleCopySummary}
              className="interactive-lift inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:text-white bg-[#101A2E] hover:bg-slate-800 border border-slate-700/80 rounded-xl whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copiedReport ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[#55E6C1]" />
                  <span>Copied Report</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Report</span>
                </>
              )}
            </button>
          </div>

          {/* A. Risk Score Circular Progress + B. Threat Summary */}
          <div className={`rounded-2xl border p-5 sm:p-6 ${theme.bannerBg}`}>
            <div className="grid grid-cols-1 sm:grid-cols-12 gap-6 items-center">
              {/* Circular Gauge (4 Cols) */}
              <div className="sm:col-span-4 flex flex-col items-center justify-center">
                <div className="relative w-36 h-36 flex items-center justify-center">
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128" aria-hidden="true">
                    <circle
                      cx="64"
                      cy="64"
                      r={radius}
                      fill="transparent"
                      stroke="rgba(8, 14, 28, 0.75)"
                      strokeWidth="10"
                    />
                    <circle
                      cx="64"
                      cy="64"
                      r={radius}
                      fill="transparent"
                      stroke={theme.strokeColor}
                      strokeWidth="10"
                      strokeLinecap="round"
                      strokeDasharray={circumference}
                      strokeDashoffset={dashOffset}
                      className="gauge-ring-animate"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                    <span
                      data-testid="risk-score-value"
                      className="text-3xl sm:text-4xl font-extrabold font-mono tabular-nums text-white"
                    >
                      {result.riskScore}
                    </span>
                    <span className="text-[11px] font-mono text-slate-300">/ 100 RISK</span>
                  </div>
                </div>

                <div className={`mt-2.5 inline-flex items-center gap-1.5 px-3 py-1 rounded-lg border text-xs font-bold ${theme.badgeBg}`}>
                  <StatusIcon className="w-3.5 h-3.5 shrink-0" />
                  <span data-testid="risk-category-label">{result.riskCategory}</span>
                </div>
              </div>

              {/* Threat Summary (8 Cols) */}
              <div className="sm:col-span-8 space-y-3">
                <h3 className={`text-base sm:text-lg font-bold ${theme.textClass}`}>
                  {theme.verdictTitle}
                </h3>
                <p className="text-sm text-slate-100 leading-relaxed">
                  {result.summary}
                </p>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {theme.verdictSubtitle}
                </p>
              </div>
            </div>
          </div>

          {/* C. Detected Warning Signs (Individual Warning Cards with Icons) */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Detected Warning Signs ({result.indicators.length})
              </h3>
              <span className="text-xs text-slate-400">
                {result.indicators.length === 0
                  ? '0 rules triggered'
                  : `${result.indicators.length} indicator(s) matched`}
              </span>
            </div>

            {result.indicators.length === 0 ? (
              <div className="saas-subcard rounded-2xl p-4 flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-emerald-300 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <p className="font-semibold text-white">
                    No Phishing or Scam Warning Signs Triggered
                  </p>
                  <p className="text-slate-300 leading-relaxed">
                    The analysis engine did not detect coercive urgency, credential harvesting, or domain-spoofing patterns in this input. Note: a low risk score does not guarantee a website or sender is safe.
                  </p>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {result.indicators.slice(0, 6).map((ind: DetectedIndicator) => {
                  const CardIcon = getIndicatorIcon(ind.category, ind.title);
                  const severityColor =
                    ind.severity === 'high'
                      ? 'text-rose-300 border-rose-500/30 bg-rose-500/10'
                      : ind.severity === 'medium'
                        ? 'text-amber-300 border-amber-400/30 bg-amber-500/10'
                        : 'text-[#35C6F4] border-[#35C6F4]/30 bg-[#35C6F4]/10';

                  return (
                    <div
                      key={ind.id}
                      className="saas-subcard rounded-2xl p-4 space-y-2 flex flex-col justify-between"
                    >
                      <div className="space-y-1.5">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <div className={`w-7 h-7 rounded-lg border flex items-center justify-center shrink-0 ${severityColor}`}>
                              <CardIcon className="w-3.5 h-3.5" />
                            </div>
                            <h4 className="text-xs font-bold text-white leading-snug">
                              {ind.title}
                            </h4>
                          </div>
                          <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded border border-slate-700 text-slate-300 shrink-0">
                            {ind.severity}
                          </span>
                        </div>

                        <p className="text-xs text-slate-300 leading-relaxed">
                          {ind.explanation}
                        </p>
                      </div>

                      {ind.matchedSnippet && (
                        <div className="pt-1.5 border-t border-slate-800/80 text-[11px] font-mono text-[#35C6F4] truncate" title={ind.matchedSnippet}>
                          Evidence: &ldquo;{ind.matchedSnippet}&rdquo;
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* D. Recommended Safety Actions */}
          <div className="saas-subcard rounded-2xl p-5 space-y-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Recommended Safety Actions
            </h3>
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {result.recommendedActions.map((action, idx) => (
                <li
                  key={idx}
                  className="flex items-start gap-2.5 text-xs text-slate-200 leading-relaxed bg-[#080E1C]/60 border border-slate-800/80 rounded-xl p-3"
                >
                  <CheckCircle2 className="w-4 h-4 text-[#55E6C1] shrink-0 mt-0.5" />
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* E. Expandable Technical Details Section */}
          <div className="rounded-2xl bg-[#080E1C]/80 border border-slate-800 overflow-hidden">
            <button
              type="button"
              aria-expanded={showTechnicalDetails}
              onClick={() => setShowTechnicalDetails((prev) => !prev)}
              className="w-full px-5 py-3.5 flex items-center justify-between text-left text-xs font-bold text-slate-200 hover:text-white hover:bg-[#101A2E]/70 transition-colors cursor-pointer"
            >
              <span className="flex items-center gap-2 font-mono uppercase tracking-wider">
                <SlidersHorizontal className="w-3.5 h-3.5 text-[#35C6F4]" />
                <span>Technical Details &amp; Scoring Breakdown</span>
              </span>
              <span className="inline-flex items-center gap-1 text-[#35C6F4]">
                <span>{showTechnicalDetails ? 'Hide Details' : 'Expand Details'}</span>
                {showTechnicalDetails ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </span>
            </button>

            {showTechnicalDetails && (
              <div className="px-5 pb-5 pt-2 border-t border-slate-800/90 space-y-4 animate-fade-in text-xs">
                {/* Score Attribution Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-xl bg-[#101A2E] border border-slate-800">
                    <span className="text-slate-400 block">Final Calibrated Score</span>
                    <span className="text-base font-bold font-mono tabular-nums text-white mt-0.5 block">
                      {result.riskScore} / 100 ({result.riskCategory})
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-[#101A2E] border border-slate-800">
                    <span className="text-slate-400 block">Deterministic Rule Score</span>
                    <span className="text-base font-bold font-mono tabular-nums text-[#35C6F4] mt-0.5 block">
                      {result.ruleScore} / 100
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-[#101A2E] border border-slate-800">
                    <span className="text-slate-400 block">Google Gemini AI Score</span>
                    <span className="text-base font-bold font-mono tabular-nums text-[#55E6C1] mt-0.5 block">
                      {result.aiScore !== null ? `${result.aiScore} / 100` : 'Not Used (Rule Engine)'}
                    </span>
                  </div>
                </div>

                {/* URL Structural Breakdown if available */}
                {result.urlBreakdown && (
                  <div className="p-4 rounded-xl bg-[#101A2E]/90 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-[#35C6F4]" />
                        <span>Static URL Lexical Anatomy (Zero-Visit)</span>
                      </span>
                      <span className="font-mono text-slate-400">
                        {result.urlBreakdown.protocol.toUpperCase()} · Port {result.urlBreakdown.port}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono">
                      <div>
                        <span className="text-slate-400 block font-sans">Hostname</span>
                        <span className="text-white truncate block">{result.urlBreakdown.hostname}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block font-sans">Top-Level Domain</span>
                        <span className="text-white block">
                          {result.urlBreakdown.tld ? `.${result.urlBreakdown.tld}` : 'Raw IP / None'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block font-sans">Raw IP Host</span>
                        <span className={result.urlBreakdown.hasIpAddressHost ? 'text-rose-300 font-bold' : 'text-emerald-300'}>
                          {result.urlBreakdown.hasIpAddressHost ? 'Yes (High Risk)' : 'No'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block font-sans">&ldquo;@&rdquo; Redirect Trick</span>
                        <span className={result.urlBreakdown.hasAtSymbolRedirect ? 'text-rose-300 font-bold' : 'text-emerald-300'}>
                          {result.urlBreakdown.hasAtSymbolRedirect ? 'Yes (Deceptive)' : 'No'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block font-sans">Subdomain Depth</span>
                        <span className="text-white">{result.urlBreakdown.subdomainCount}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block font-sans">Brand Impersonation</span>
                        <span className={result.urlBreakdown.impersonatedBrand ? 'text-rose-300 font-bold' : 'text-emerald-300'}>
                          {result.urlBreakdown.impersonatedBrand || 'None Detected'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Suspicious Phrases Breakdown if any */}
                {result.suspiciousPhrases.length > 0 && (
                  <div className="space-y-2">
                    <span className="font-bold text-white block">
                      Flagged Wording &amp; Social Engineering Tactics
                    </span>
                    <div className="divide-y divide-slate-800 rounded-xl bg-[#101A2E]/80 border border-slate-800 px-3.5">
                      {result.suspiciousPhrases.map((item, idx) => (
                        <div key={idx} className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div>
                            <span className="font-mono text-amber-300 font-semibold">
                              &ldquo;{item.phrase}&rdquo;
                            </span>
                            <p className="text-slate-300 mt-0.5">{item.whySuspicious}</p>
                          </div>
                          <span className="text-[11px] font-mono text-[#35C6F4] shrink-0">
                            {item.tactic}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Uncertainty Disclosure */}
        <div className="pt-4 border-t border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-300 leading-relaxed">
          <Info className="w-4 h-4 text-[#35C6F4] shrink-0 mt-0.5" />
          <p>
            <strong className="text-white">Confidence &amp; Uncertainty Note:</strong>{' '}
            {result.uncertaintyStatement}
          </p>
        </div>
      </div>
    </section>
  );
};
