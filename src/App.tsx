import { useState, useEffect, useMemo, useRef } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Mail,
  Link2,
  AlertTriangle,
  KeyRound,
  CreditCard,
  Globe,
  FileWarning,
  PhoneCall,
  Activity,
  Menu,
  X,
  ArrowRight,
  BookOpen,
} from 'lucide-react';
import {
  analyzeMessageRules,
  inspectUrlStructure,
  buildFinalScanResult,
  detectAndRedactSensitiveInput,
  type ScanType,
  type ScanAnalysisResult,
  type ScanHistoryItem,
} from './utils/phishingRules';
import { MESSAGE_PRESETS } from './data/sampleScans';
import { ScannerWorkspace } from './components/ScannerWorkspace';
import { ResultsDashboard } from './components/ResultsDashboard';
import { ScanHistory } from './components/ScanHistory';

type NavSectionId = 'dashboard' | 'scanner' | 'results' | 'history' | 'safety-guide';

export default function App() {
  // Start with actual history from backend (empty on a clean start — never show fabricated results)
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [activeTab, setActiveTab] = useState<ScanType>('message');
  const [activeNav, setActiveNav] = useState<NavSectionId>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  const [messageInput, setMessageInput] = useState<string>('');
  const [urlInput, setUrlInput] = useState<string>('');
  // Start with null before the user performs their first scan (shows useful Empty State)
  const [currentResult, setCurrentResult] = useState<ScanAnalysisResult | null>(null);

  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [redactionNotice, setRedactionNotice] = useState<string | null>(null);
  const [statusBanner, setStatusBanner] = useState<string | null>(null);

  const messageInputRef = useRef<HTMLTextAreaElement | null>(null);
  const urlInputRef = useRef<HTMLInputElement | null>(null);

  // Sync actual scan history from the backend database on mount
  useEffect(() => {
    let active = true;
    fetch('/api/history')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!active || !data) return;
        if (Array.isArray(data.history)) {
          setHistory(data.history);
        }
      })
      .catch(() => {
        // Keep empty initial state if network request fails
      });
    return () => {
      active = false;
    };
  }, []);

  // Connect the 4 Analytics Dashboard cards strictly to actual application data
  const securityStats = useMemo(() => {
    const totalScans = history.length;
    const suspiciousMessages = history.filter(
      (h) =>
        h.scanType === 'message' &&
        (h.riskCategory === 'Suspicious' || h.riskCategory === 'High Risk')
    ).length;
    const highRiskCount = history.filter((h) => h.riskCategory === 'High Risk').length;
    const urlsAnalyzed = history.filter((h) => h.scanType === 'url').length;

    return {
      totalScans,
      suspiciousMessages,
      highRiskCount,
      urlsAnalyzed,
    };
  }, [history]);

  const scrollToSection = (sectionId: NavSectionId) => {
    setActiveNav(sectionId);
    setMobileMenuOpen(false);
    document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  // Real Message Scanning (Rule Engine + Google Gemini AI if configured)
  const handleScanMessage = async (overrideMessage?: string) => {
    setValidationError(null);
    setRedactionNotice(null);
    setStatusBanner(null);

    const textToScan = (overrideMessage !== undefined ? overrideMessage : messageInput).trim();
    if (!textToScan) {
      setValidationError('Please paste an email or SMS message before analyzing.');
      messageInputRef.current?.focus();
      return;
    }
    if (textToScan.length < 6) {
      setValidationError('Please enter at least 6 characters so we have enough text to analyze.');
      messageInputRef.current?.focus();
      return;
    }

    // 1. Instant rule-based evaluation while backend completes full analysis
    const sensitiveCheck = detectAndRedactSensitiveInput(textToScan);
    const safeContent = sensitiveCheck.redactedText;
    const instantRules = analyzeMessageRules(safeContent);
    const instantResult = buildFinalScanResult({
      id: `instant-msg-${Date.now()}`,
      scanType: 'message',
      rawInput: safeContent,
      ruleScore: instantRules.ruleScore,
      ruleIndicators: instantRules.indicators,
      rulePhrases: instantRules.suspiciousPhrases,
      urlBreakdown: instantRules.urlBreakdown,
      aiAssessment: null,
      fallbackReason: 'Evaluated by deterministic rule engine.',
    });
    setCurrentResult(instantResult);
    setActiveNav('results');

    if (sensitiveCheck.hasSensitiveData) {
      setRedactionNotice(
        `Privacy guard: Sensitive details (${sensitiveCheck.detectedTypes.join(', ')}) were automatically masked before analysis.`
      );
    }

    // 2. Call backend API (runs Gemini AI if configured, records scan in database)
    setIsScanning(true);
    try {
      const response = await fetch('/api/scan/message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: textToScan }),
      });

      const data = await response.json();
      if (!response.ok) {
        setValidationError(data.error || 'Could not analyze this message.');
        setIsScanning(false);
        return;
      }

      if (data.result) {
        setCurrentResult(data.result);
      }
      if (Array.isArray(data.history)) {
        setHistory(data.history);
      }
    } catch {
      // Keep instant rule-based result and record locally in state if offline
      const fallbackItem: ScanHistoryItem = {
        id: instantResult.id,
        scanType: 'message',
        timestamp: instantResult.timestamp,
        riskScore: instantResult.riskScore,
        riskCategory: instantResult.riskCategory,
        privacySafeSnippet: instantResult.privacySafeSnippet,
        indicatorCount: instantResult.indicators.length,
        analysisEngine: instantResult.analysisEngine,
        fullResult: instantResult,
      };
      setHistory((prev) => [fallbackItem, ...prev.slice(0, 29)]);
    } finally {
      setIsScanning(false);
    }
  };

  // Real Static URL Inspection (Zero-Visit Rule Engine + Google Gemini AI if configured)
  const handleScanUrl = async (overrideUrl?: string) => {
    setValidationError(null);
    setRedactionNotice(null);
    setStatusBanner(null);

    const linkToScan = (overrideUrl !== undefined ? overrideUrl : urlInput).trim();
    if (!linkToScan) {
      setValidationError('Please enter a URL or website domain to inspect.');
      urlInputRef.current?.focus();
      return;
    }
    if (linkToScan.length < 4 || (!linkToScan.includes('.') && !linkToScan.includes(':') && !linkToScan.includes('/'))) {
      setValidationError('Please enter a valid web address (for example: https://example.com/login).');
      urlInputRef.current?.focus();
      return;
    }

    // 1. Instant static URL evaluation without visiting the URL
    const instantUrlRules = inspectUrlStructure(linkToScan);
    const instantResult = buildFinalScanResult({
      id: `instant-url-${Date.now()}`,
      scanType: 'url',
      rawInput: linkToScan,
      ruleScore: instantUrlRules.ruleScore,
      ruleIndicators: instantUrlRules.indicators,
      rulePhrases: instantUrlRules.suspiciousPhrases,
      urlBreakdown: instantUrlRules.breakdown,
      aiAssessment: null,
      fallbackReason: 'Evaluated by static URL rule engine.',
    });
    setCurrentResult(instantResult);
    setActiveNav('results');

    // 2. Call backend API
    setIsScanning(true);
    try {
      const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: linkToScan }),
      });

      const data = await response.json();
      if (!response.ok) {
        setValidationError(data.error || 'Could not inspect this link.');
        setIsScanning(false);
        return;
      }

      if (data.result) {
        setCurrentResult(data.result);
      }
      if (Array.isArray(data.history)) {
        setHistory(data.history);
      }
    } catch {
      const fallbackItem: ScanHistoryItem = {
        id: instantResult.id,
        scanType: 'url',
        timestamp: instantResult.timestamp,
        riskScore: instantResult.riskScore,
        riskCategory: instantResult.riskCategory,
        privacySafeSnippet: instantResult.privacySafeSnippet,
        indicatorCount: instantResult.indicators.length,
        analysisEngine: instantResult.analysisEngine,
        fullResult: instantResult,
      };
      setHistory((prev) => [fallbackItem, ...prev.slice(0, 29)]);
    } finally {
      setIsScanning(false);
    }
  };

  const handleClearHistory = async () => {
    setHistory([]);
    try {
      const res = await fetch('/api/history', { method: 'DELETE' });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.history)) {
          setHistory(data.history);
        }
      }
    } catch {
      // Ignore network error
    }
  };

  const handleStartNewScan = (targetTab?: ScanType) => {
    const nextTab = targetTab || activeTab;
    setActiveTab(nextTab);
    setActiveNav('scanner');
    setMobileMenuOpen(false);
    setValidationError(null);
    setRedactionNotice(null);

    if (nextTab === 'message') {
      setMessageInput('');
      setStatusBanner('Scanner ready — paste a suspicious email or SMS below, or click a fictional sample.');
    } else {
      setUrlInput('');
      setStatusBanner('URL Scanner ready — paste a website link below for zero-visit structural inspection.');
    }

    document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => {
      if (nextTab === 'message') {
        messageInputRef.current?.focus();
      } else {
        urlInputRef.current?.focus();
      }
    }, 120);
  };

  const navItems: Array<{ id: NavSectionId; label: string }> = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'scanner', label: 'Scanner' },
    { id: 'results', label: 'Results' },
    { id: 'history', label: 'History' },
    { id: 'safety-guide', label: 'Safety Guide' },
  ];

  return (
    <div className="min-h-screen text-slate-100 flex flex-col relative">
      {/* 2. PREMIUM NAVIGATION BAR */}
      <header className="sticky top-0 z-40 bg-[#080E1C]/88 backdrop-blur-xl border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4 px-4 sm:px-6 py-3.5">
          {/* Left: Modern Shield Logo + PhishShield AI + SECURITY INTELLIGENCE */}
          <a
            href="#dashboard"
            onClick={(e) => {
              e.preventDefault();
              scrollToSection('dashboard');
            }}
            className="flex items-center gap-3 group shrink-0"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#35C6F4]/25 to-[#55E6C1]/15 border border-[#35C6F4]/40 flex items-center justify-center shadow-md shadow-[#35C6F4]/10 group-hover:border-[#35C6F4] transition-colors">
              <Shield className="w-5 h-5 text-[#35C6F4]" />
            </div>
            <div>
              <span className="text-base sm:text-lg font-extrabold tracking-tight text-white font-display block leading-none">
                PhishShield AI
              </span>
              <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#55E6C1] block mt-1">
                SECURITY INTELLIGENCE
              </span>
            </div>
          </a>

          {/* Center: Desktop Navigation Links with Active Indicators */}
          <nav
            aria-label="Primary Navigation"
            className="hidden md:flex items-center gap-1 p-1 rounded-2xl bg-[#101A2E]/90 border border-slate-800/90"
          >
            {navItems.map((item) => {
              const isActive = activeNav === item.id;
              return (
                <a
                  key={item.id}
                  href={`#${item.id}`}
                  onClick={(e) => {
                    e.preventDefault();
                    scrollToSection(item.id);
                  }}
                  className={`px-3.5 py-2 text-xs font-semibold rounded-xl transition-all whitespace-nowrap shrink-0 ${
                    isActive
                      ? 'bg-[#14213A] text-[#35C6F4] border border-[#35C6F4]/30 shadow-sm'
                      : 'text-slate-300 hover:text-white hover:bg-[#14213A]/50'
                  }`}
                >
                  {item.label}
                </a>
              );
            })}
          </nav>

          {/* Right: New Scan Button + Mobile Navigation Toggle */}
          <div className="flex items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => handleStartNewScan()}
              className="interactive-lift px-4 py-2.5 text-xs font-bold text-slate-950 bg-gradient-to-r from-[#35C6F4] to-[#55E6C1] hover:brightness-105 rounded-xl shadow-md shadow-[#35C6F4]/15 whitespace-nowrap shrink-0 cursor-pointer"
            >
              New Scan
            </button>

            <button
              type="button"
              aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={mobileMenuOpen}
              onClick={() => setMobileMenuOpen((prev) => !prev)}
              className="md:hidden p-2.5 rounded-xl bg-[#101A2E] border border-slate-700/80 text-slate-200 hover:text-white cursor-pointer"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Responsive Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <nav
            aria-label="Mobile Navigation"
            className="md:hidden border-t border-slate-800 bg-[#080E1C]/95 px-4 py-3 space-y-1 animate-fade-in"
          >
            {navItems.map((item) => (
              <a
                key={item.id}
                href={`#${item.id}`}
                onClick={(e) => {
                  e.preventDefault();
                  scrollToSection(item.id);
                }}
                className={`block px-4 py-2.5 rounded-xl text-sm font-semibold ${
                  activeNav === item.id
                    ? 'bg-[#14213A] text-[#35C6F4] border border-[#35C6F4]/30'
                    : 'text-slate-200 hover:bg-[#101A2E]'
                }`}
              >
                {item.label}
              </a>
            ))}
          </nav>
        )}
      </header>

      {/* Main Content Container */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 sm:py-10 space-y-12">
        {/* 3. HERO SECTION & 6. MODERN ANALYTICS DASHBOARD */}
        <section
          id="dashboard"
          aria-labelledby="hero-heading"
          className="space-y-8 scroll-mt-28 animate-fade-up"
        >
          <div className="saas-card rounded-3xl p-6 sm:p-10 lg:p-12 relative overflow-hidden">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-10 items-center">
              {/* Left Side: Badge, Heading, Subtitle, Action Buttons */}
              <div className="lg:col-span-7 space-y-5">
                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[#101A2E] border border-[#35C6F4]/35 text-[11px] font-mono font-semibold uppercase tracking-wider text-[#35C6F4]">
                  <ShieldCheck className="w-3.5 h-3.5 text-[#55E6C1]" />
                  <span>SMART CYBERSECURITY PROTECTION</span>
                </div>

                <h1
                  id="hero-heading"
                  className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-white leading-[1.12]"
                >
                  Think Before You Click.{' '}
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#35C6F4] to-[#55E6C1] block sm:inline">
                    Stay Protected Online.
                  </span>
                </h1>

                <p className="text-base sm:text-lg text-slate-300 max-w-2xl leading-relaxed">
                  Detect suspicious messages, phishing attempts, and malicious-looking links with intelligent security analysis.
                </p>

                <div className="pt-2 flex flex-wrap items-center gap-3.5">
                  <button
                    type="button"
                    onClick={() => scrollToSection('scanner')}
                    className="interactive-lift inline-flex items-center gap-2 px-6 py-3.5 text-sm font-bold text-slate-950 bg-gradient-to-r from-[#35C6F4] to-[#55E6C1] hover:brightness-105 rounded-2xl shadow-lg shadow-[#35C6F4]/20 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <span>Start Scanning</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>

                  <button
                    type="button"
                    onClick={() => scrollToSection('safety-guide')}
                    className="interactive-lift inline-flex items-center gap-2 px-5 py-3.5 text-sm font-semibold text-slate-100 bg-[#101A2E] hover:bg-[#14213A] border border-slate-700/80 rounded-2xl whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <BookOpen className="w-4 h-4 text-[#35C6F4]" />
                    <span>Explore Safety Guide</span>
                  </button>
                </div>
              </div>

              {/* Right Side: Animated 3D-Style Shield Illustration + Floating Security Elements */}
              <div className="lg:col-span-5 flex items-center justify-center">
                <div className="relative w-full max-w-[340px] aspect-square rounded-3xl bg-[#080E1C]/80 border border-slate-800/90 cyber-grid-bg flex items-center justify-center p-6 shadow-inner">
                  {/* Soft Ambient Glow Behind Shield */}
                  <div
                    aria-hidden="true"
                    className="w-44 h-44 rounded-full bg-gradient-to-tr from-[#35C6F4]/20 to-[#55E6C1]/20 blur-2xl absolute"
                  />

                  {/* 3D-Style Layered SVG Shield */}
                  <div className="relative z-10 animate-float-slow flex flex-col items-center">
                    <svg
                      viewBox="0 0 180 200"
                      className="w-36 h-40 sm:w-40 sm:h-44 drop-shadow-[0_18px_28px_rgba(53,198,244,0.22)]"
                      aria-label="PhishShield 3D Security Shield Illustration"
                      role="img"
                    >
                      <defs>
                        <linearGradient id="shieldOuterGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                          <stop offset="0%" stopColor="#35C6F4" />
                          <stop offset="55%" stopColor="#14213A" />
                          <stop offset="100%" stopColor="#55E6C1" />
                        </linearGradient>
                        <linearGradient id="shieldInnerLeft" x1="0%" y1="0%" x2="100%" y2="100%">
                          <stop offset="0%" stopColor="#1E3358" />
                          <stop offset="100%" stopColor="#0E1930" />
                        </linearGradient>
                        <linearGradient id="shieldInnerRight" x1="0%" y1="0%" x2="100%" y2="100%">
                          <stop offset="0%" stopColor="#14213A" />
                          <stop offset="100%" stopColor="#080E1C" />
                        </linearGradient>
                        <linearGradient id="coreAccentGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                          <stop offset="0%" stopColor="#35C6F4" />
                          <stop offset="100%" stopColor="#55E6C1" />
                        </linearGradient>
                      </defs>

                      {/* Outer Beveled Shield Rim */}
                      <path
                        d="M90 10 L162 40 V98 C162 145 131 178 90 192 C49 178 18 145 18 98 V40 L90 10 Z"
                        fill="url(#shieldOuterGrad)"
                        stroke="#35C6F4"
                        strokeWidth="1.5"
                      />

                      {/* Inner Left 3D Facet */}
                      <path
                        d="M90 20 L28 46 V98 C28 139 55 168 90 181 V20 Z"
                        fill="url(#shieldInnerLeft)"
                      />

                      {/* Inner Right 3D Facet */}
                      <path
                        d="M90 20 L152 46 V98 C152 139 125 168 90 181 V20 Z"
                        fill="url(#shieldInnerRight)"
                      />

                      {/* Center glowing check emblem */}
                      <circle
                        cx="90"
                        cy="98"
                        r="30"
                        fill="#080E1C"
                        stroke="url(#coreAccentGrad)"
                        strokeWidth="2.5"
                      />
                      <path
                        d="M77 98 L86 107 L105 88"
                        fill="none"
                        stroke="url(#coreAccentGrad)"
                        strokeWidth="5"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  </div>

                  {/* Floating Security Element 1: Email Icon (Top-Left) */}
                  <div className="absolute top-5 left-5 animate-float-delayed rounded-2xl bg-[#14213A]/95 border border-[#35C6F4]/35 px-3 py-2 flex items-center gap-2 shadow-lg">
                    <Mail className="w-4 h-4 text-[#35C6F4]" />
                    <span className="text-[11px] font-mono text-slate-200">Email Guard</span>
                  </div>

                  {/* Floating Security Element 2: Link Icon (Top-Right) */}
                  <div className="absolute top-6 right-5 animate-float-slow rounded-2xl bg-[#14213A]/95 border border-[#55E6C1]/35 px-3 py-2 flex items-center gap-2 shadow-lg">
                    <Link2 className="w-4 h-4 text-[#55E6C1]" />
                    <span className="text-[11px] font-mono text-slate-200">URL Inspector</span>
                  </div>

                  {/* Floating Security Element 3: Security Check Icon (Bottom-Left) */}
                  <div className="absolute bottom-5 left-5 animate-float-slow rounded-2xl bg-[#14213A]/95 border border-emerald-400/35 px-3 py-2 flex items-center gap-2 shadow-lg">
                    <ShieldCheck className="w-4 h-4 text-emerald-300" />
                    <span className="text-[11px] font-mono text-slate-200">AI + Rules</span>
                  </div>

                  {/* Floating Security Element 4: Warning Icon (Bottom-Right) */}
                  <div className="absolute bottom-6 right-5 animate-float-delayed rounded-2xl bg-[#14213A]/95 border border-amber-400/35 px-3 py-2 flex items-center gap-2 shadow-lg">
                    <AlertTriangle className="w-4 h-4 text-amber-300" />
                    <span className="text-[11px] font-mono text-slate-200">Risk Alerts</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* 6. MODERN ANALYTICS DASHBOARD (4 Statistic Cards Connected to Real Data) */}
          <div
            aria-label="Security Analytics Overview"
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-5"
          >
            {/* Card 1: Total Scans */}
            <div className="saas-card-interactive rounded-2xl p-5 flex items-start justify-between gap-4">
              <div className="space-y-1">
                <span className="text-xs font-medium text-slate-300">Total Scans</span>
                <div
                  data-testid="stat-total-scans"
                  className="text-3xl font-extrabold font-mono tabular-nums text-white"
                >
                  {securityStats.totalScans}
                </div>
                <p className="text-[11px] text-slate-400">
                  Completed session inspections
                </p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-[#35C6F4]/15 border border-[#35C6F4]/30 flex items-center justify-center text-[#35C6F4] shrink-0">
                <Activity className="w-5 h-5" />
              </div>
            </div>

            {/* Card 2: Suspicious Messages */}
            <div className="saas-card-interactive rounded-2xl p-5 flex items-start justify-between gap-4">
              <div className="space-y-1">
                <span className="text-xs font-medium text-slate-300">Suspicious Messages</span>
                <div
                  data-testid="stat-suspicious-messages"
                  className="text-3xl font-extrabold font-mono tabular-nums text-amber-300"
                >
                  {securityStats.suspiciousMessages}
                </div>
                <p className="text-[11px] text-slate-400">
                  Flagged emails &amp; SMS texts
                </p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-amber-400/15 border border-amber-400/30 flex items-center justify-center text-amber-300 shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
            </div>

            {/* Card 3: High-Risk Detections */}
            <div className="saas-card-interactive rounded-2xl p-5 flex items-start justify-between gap-4">
              <div className="space-y-1">
                <span className="text-xs font-medium text-slate-300">High-Risk Detections</span>
                <div
                  data-testid="stat-high-risk"
                  className="text-3xl font-extrabold font-mono tabular-nums text-rose-400"
                >
                  {securityStats.highRiskCount}
                </div>
                <p className="text-[11px] text-slate-400">
                  Critical phishing signatures (60+)
                </p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0">
                <ShieldAlert className="w-5 h-5" />
              </div>
            </div>

            {/* Card 4: URLs Analyzed */}
            <div className="saas-card-interactive rounded-2xl p-5 flex items-start justify-between gap-4">
              <div className="space-y-1">
                <span className="text-xs font-medium text-slate-300">URLs Analyzed</span>
                <div
                  data-testid="stat-url-scans"
                  className="text-3xl font-extrabold font-mono tabular-nums text-[#55E6C1]"
                >
                  {securityStats.urlsAnalyzed}
                </div>
                <p className="text-[11px] text-slate-400">
                  Zero-visit link inspections
                </p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-[#55E6C1]/15 border border-[#55E6C1]/30 flex items-center justify-center text-[#55E6C1] shrink-0">
                <Link2 className="w-5 h-5" />
              </div>
            </div>
          </div>
        </section>

        {/* 4. MODERN SCANNER INTERFACE & 5. PROFESSIONAL THREAT ANALYSIS RESULTS */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          <div className="lg:col-span-5">
            <ScannerWorkspace
              activeTab={activeTab}
              onTabChange={(tab) => {
                setActiveTab(tab);
                setValidationError(null);
                setStatusBanner(null);
              }}
              messageInput={messageInput}
              onMessageChange={(val) => {
                setMessageInput(val);
                if (validationError) setValidationError(null);
                if (statusBanner) setStatusBanner(null);
              }}
              urlInput={urlInput}
              onUrlChange={(val) => {
                setUrlInput(val);
                if (validationError) setValidationError(null);
                if (statusBanner) setStatusBanner(null);
              }}
              onScanMessage={handleScanMessage}
              onScanUrl={handleScanUrl}
              isScanning={isScanning}
              validationError={validationError}
              redactionNotice={redactionNotice}
              statusBanner={statusBanner}
              messageInputRef={messageInputRef}
              urlInputRef={urlInputRef}
            />
          </div>

          <div className="lg:col-span-7">
            <ResultsDashboard
              result={currentResult}
              isScanning={isScanning}
              onRunQuickSample={() => {
                const sample = MESSAGE_PRESETS[0];
                setActiveTab('message');
                setMessageInput(sample.content);
                handleScanMessage(sample.content);
              }}
            />
          </div>
        </div>

        {/* 7. SCAN HISTORY TABLE */}
        <ScanHistory
          history={history}
          activeResultId={currentResult?.id ?? null}
          onSelectHistoryItem={(item) => {
            setCurrentResult(item.fullResult);
            setActiveNav('results');
            document.getElementById('results')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }}
          onClearHistory={handleClearHistory}
        />

        {/* 8. SAFETY GUIDE ("Stay Safe in the Digital World") */}
        <section
          id="safety-guide"
          aria-labelledby="safety-guide-heading"
          className="scroll-mt-28 saas-card rounded-3xl p-6 sm:p-8 lg:p-10 space-y-6 animate-fade-up"
        >
          <div className="pb-5 border-b border-slate-800/80">
            <span className="text-[11px] font-mono uppercase tracking-wider text-[#55E6C1] block mb-1">
              Essential Cybersecurity Best Practices
            </span>
            <h2
              id="safety-guide-heading"
              className="text-xl sm:text-2xl font-bold text-white tracking-tight"
            >
              Stay Safe in the Digital World
            </h2>
            <p className="text-sm text-slate-300 mt-1">
              Five simple habits that protect your accounts, identity, and finances against modern phishing attacks.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {/* Guide Card 1 */}
            <div className="saas-card-interactive rounded-2xl p-5 space-y-2.5">
              <div className="w-10 h-10 rounded-xl bg-[#35C6F4]/15 border border-[#35C6F4]/30 flex items-center justify-center text-[#35C6F4]">
                <KeyRound className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-bold text-white">
                Never Share OTPs or Passwords
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Real banks, delivery carriers, and support teams will never ask you to read back a one-time passcode (OTP), PIN, CVV, or password.
              </p>
            </div>

            {/* Guide Card 2 */}
            <div className="saas-card-interactive rounded-2xl p-5 space-y-2.5">
              <div className="w-10 h-10 rounded-xl bg-[#55E6C1]/15 border border-[#55E6C1]/30 flex items-center justify-center text-[#55E6C1]">
                <CreditCard className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-bold text-white">
                Verify Suspicious Payment Requests
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Treat urgent demands for gift cards, wire transfers, cryptocurrency, or unexpected redelivery fees as major red flags.
              </p>
            </div>

            {/* Guide Card 3 */}
            <div className="saas-card-interactive rounded-2xl p-5 space-y-2.5">
              <div className="w-10 h-10 rounded-xl bg-sky-400/15 border border-sky-400/30 flex items-center justify-center text-sky-300">
                <Globe className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-bold text-white">
                Check Website Addresses Carefully
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Look closely at the actual domain name before logging in. Scammers often use lookalike letters, raw IP addresses, or unusual domain endings.
              </p>
            </div>

            {/* Guide Card 4 */}
            <div className="saas-card-interactive rounded-2xl p-5 space-y-2.5">
              <div className="w-10 h-10 rounded-xl bg-amber-400/15 border border-amber-400/30 flex items-center justify-center text-amber-300">
                <FileWarning className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-bold text-white">
                Avoid Unknown Attachments
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Never open unexpected `.exe`, `.zip`, `.iso`, or macro-enabled invoice attachments from unfamiliar or unverified senders.
              </p>
            </div>

            {/* Guide Card 5 */}
            <div className="saas-card-interactive rounded-2xl p-5 space-y-2.5">
              <div className="w-10 h-10 rounded-xl bg-emerald-400/15 border border-emerald-400/30 flex items-center justify-center text-emerald-300">
                <PhoneCall className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-bold text-white">
                Verify Through Official Channels
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                When in doubt, do not reply to the message. Open the organization&apos;s official app or call the number printed on the back of your card.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Footer with Required Tagline & Accuracy Disclaimer */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-[#080E1C] py-8 px-4 sm:px-6 mt-12">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <p className="text-sm font-bold text-white font-display">
              PhishShield AI - Stay Alert. Stay Protected.
            </p>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl leading-relaxed">
              Disclaimer: Automated detection is not 100% accurate. A low risk score does not guarantee that a message or website is safe. Always verify unexpected requests directly through an organization&apos;s official website or phone number.
            </p>
          </div>
          <div className="text-xs font-mono text-slate-300 whitespace-nowrap shrink-0">
            0–29 Lower Indicators · 30–59 Suspicious · 60–100 High Risk
          </div>
        </div>
      </footer>
    </div>
  );
}
