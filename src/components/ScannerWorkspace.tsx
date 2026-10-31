import React, { useMemo } from 'react';
import {
  Mail,
  Link2,
  Search,
  RotateCcw,
  Lock,
  AlertTriangle,
  EyeOff,
  Loader2,
  Check,
  Sparkles,
  Shield,
} from 'lucide-react';
import {
  detectAndRedactSensitiveInput,
  type ScanType,
} from '../utils/phishingRules';
import { MESSAGE_PRESETS, URL_PRESETS, type SamplePreset } from '../data/sampleScans';

interface ScannerWorkspaceProps {
  activeTab: ScanType;
  onTabChange: (tab: ScanType) => void;
  messageInput: string;
  onMessageChange: (val: string) => void;
  urlInput: string;
  onUrlChange: (val: string) => void;
  onScanMessage: (overrideMessage?: string) => void;
  onScanUrl: (overrideUrl?: string) => void;
  isScanning: boolean;
  validationError: string | null;
  redactionNotice: string | null;
  statusBanner: string | null;
  messageInputRef: React.RefObject<HTMLTextAreaElement | null>;
  urlInputRef: React.RefObject<HTMLInputElement | null>;
}

export const ScannerWorkspace: React.FC<ScannerWorkspaceProps> = ({
  activeTab,
  onTabChange,
  messageInput,
  onMessageChange,
  urlInput,
  onUrlChange,
  onScanMessage,
  onScanUrl,
  isScanning,
  validationError,
  redactionNotice,
  statusBanner,
  messageInputRef,
  urlInputRef,
}) => {
  const liveSensitiveCheck = useMemo(() => {
    if (activeTab !== 'message' || !messageInput.trim()) {
      return { hasSensitiveData: false, detectedTypes: [], redactedText: messageInput };
    }
    return detectAndRedactSensitiveInput(messageInput);
  }, [activeTab, messageInput]);

  const handleLoadAndScanPreset = (preset: SamplePreset) => {
    if (preset.type === 'message') {
      onTabChange('message');
      onMessageChange(preset.content);
      onScanMessage(preset.content);
    } else {
      onTabChange('url');
      onUrlChange(preset.content);
      onScanUrl(preset.content);
    }
  };

  const handleApplyClientRedaction = () => {
    onMessageChange(liveSensitiveCheck.redactedText);
  };

  const activeContent = activeTab === 'message' ? messageInput.trim() : urlInput.trim();

  return (
    <div
      id="scanner"
      className="saas-card rounded-3xl p-6 sm:p-8 flex flex-col justify-between h-full scroll-mt-28 relative overflow-hidden"
    >
      {/* Top Scanning Progress Bar Animation */}
      {isScanning && (
        <div
          aria-hidden="true"
          className="absolute top-0 left-0 right-0 h-1 bg-[#101A2E] overflow-hidden"
        >
          <div className="w-2/5 h-full bg-gradient-to-r from-transparent via-[#35C6F4] to-[#55E6C1] animate-scan-bar" />
        </div>
      )}

      <div className="space-y-6">
        {/* Scanner Header */}
        <div className="flex flex-col gap-4 pb-5 border-b border-slate-800/80">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="inline-flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-[#35C6F4] mb-1.5">
                <Shield className="w-3.5 h-3.5" />
                <span>Interactive Threat Scanner</span>
              </div>
              <h2
                id="scanner-heading"
                className="text-xl sm:text-2xl font-bold text-white tracking-tight"
              >
                Analyze a Suspicious Message
              </h2>
              <p className="text-sm text-slate-300 mt-1">
                Check before you click, reply, or share personal information.
              </p>
            </div>
          </div>

          {/* Two Modern Segmented Tabs */}
          <div
            role="tablist"
            aria-label="Scanner Mode"
            className="grid grid-cols-2 gap-2 p-1.5 bg-[#080E1C]/90 border border-slate-800 rounded-2xl"
          >
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'message'}
              onClick={() => onTabChange('message')}
              className={`interactive-lift flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-semibold rounded-xl whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === 'message'
                  ? 'bg-gradient-to-r from-[#35C6F4] to-[#55E6C1] text-slate-950 shadow-md shadow-[#35C6F4]/15'
                  : 'text-slate-300 hover:text-white hover:bg-[#14213A]/60'
              }`}
            >
              <Mail className="w-4 h-4 shrink-0" />
              <span>Message Scanner</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'url'}
              onClick={() => onTabChange('url')}
              className={`interactive-lift flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-semibold rounded-xl whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === 'url'
                  ? 'bg-gradient-to-r from-[#35C6F4] to-[#55E6C1] text-slate-950 shadow-md shadow-[#35C6F4]/15'
                  : 'text-slate-300 hover:text-white hover:bg-[#14213A]/60'
              }`}
            >
              <Link2 className="w-4 h-4 shrink-0" />
              <span>URL Scanner</span>
            </button>
          </div>
        </div>

        {/* Sample Testing Buttons (Clearly Identified Fictional Examples) */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between text-xs text-slate-300">
            <span className="font-medium flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-[#35C6F4]" />
              <span>Test with a fictional sample scenario:</span>
            </span>
            <span className="text-[11px] font-mono text-slate-400">Fictional Examples</span>
          </div>

          <div className="flex flex-wrap gap-2">
            {MESSAGE_PRESETS.map((preset) => {
              const isPresetActive = activeTab === 'message' && activeContent === preset.content.trim();
              return (
                <button
                  key={preset.id}
                  type="button"
                  disabled={isScanning}
                  onClick={() => handleLoadAndScanPreset(preset)}
                  className={`interactive-lift inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-xl border whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 ${
                    isPresetActive
                      ? 'bg-[#35C6F4]/15 border-[#35C6F4]/60 text-white shadow-sm'
                      : 'bg-[#080E1C]/80 hover:bg-[#101A2E] text-slate-200 hover:text-white border-slate-700/80'
                  }`}
                >
                  {isPresetActive && <Check className="w-3.5 h-3.5 text-[#55E6C1] shrink-0" />}
                  <span>{preset.label}</span>
                </button>
              );
            })}

            {activeTab === 'url' &&
              URL_PRESETS.map((preset) => {
                const isPresetActive = activeTab === 'url' && activeContent === preset.content.trim();
                return (
                  <button
                    key={preset.id}
                    type="button"
                    disabled={isScanning}
                    onClick={() => handleLoadAndScanPreset(preset)}
                    className={`interactive-lift inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-xl border whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 ${
                      isPresetActive
                        ? 'bg-[#55E6C1]/15 border-[#55E6C1]/60 text-white shadow-sm'
                        : 'bg-[#080E1C]/80 hover:bg-[#101A2E] text-[#55E6C1] hover:text-white border-slate-700/80'
                    }`}
                  >
                    {isPresetActive && <Check className="w-3.5 h-3.5 text-[#55E6C1] shrink-0" />}
                    <span>{preset.label}</span>
                  </button>
                );
              })}
          </div>
        </div>

        {statusBanner && (
          <div className="rounded-2xl bg-[#101A2E] border border-[#35C6F4]/35 px-4 py-3 text-xs text-sky-100 animate-fade-in">
            {statusBanner}
          </div>
        )}

        {/* Active Scanner Form */}
        {activeTab === 'message' ? (
          <form
            key="message-form"
            onSubmit={(e) => {
              e.preventDefault();
              onScanMessage();
            }}
            className="space-y-4 animate-fade-in"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <label
                  htmlFor="suspicious-message-input"
                  className="text-sm font-semibold text-slate-100"
                >
                  Suspicious Email or SMS Content
                </label>
                <span className="text-xs font-mono tabular-nums text-slate-400">
                  {messageInput.length.toLocaleString()} / 8,000 chars
                </span>
              </div>

              <textarea
                ref={messageInputRef}
                id="suspicious-message-input"
                rows={6}
                value={messageInput}
                onChange={(e) => onMessageChange(e.target.value)}
                placeholder="Paste a suspicious email, bank alert, delivery text, or message here to inspect for phishing indicators..."
                className="w-full rounded-2xl bg-[#080E1C]/95 border border-slate-700/80 focus:border-[#35C6F4] focus:outline-none focus:ring-3 focus:ring-[#35C6F4]/20 p-4 text-sm text-white placeholder:text-slate-400 leading-relaxed transition-all resize-y"
              />
            </div>

            {/* Live Client-Side Sensitive Credential Guardrail */}
            {liveSensitiveCheck.hasSensitiveData && (
              <div
                role="alert"
                className="rounded-2xl bg-amber-950/50 border border-amber-400/40 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 animate-fade-in"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-amber-200 text-xs font-semibold">
                    <EyeOff className="w-4 h-4 shrink-0" />
                    <span>Sensitive data detected ({liveSensitiveCheck.detectedTypes.join(', ')})</span>
                  </div>
                  <p className="text-xs text-amber-100/80">
                    Never share real OTPs, CVVs, or card numbers. Click to redact them now, or they will be masked automatically before scanning.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleApplyClientRedaction}
                  className="interactive-lift px-3.5 py-2 text-xs font-semibold bg-amber-400 text-slate-950 rounded-xl hover:bg-amber-300 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Redact Sensitive Data
                </button>
              </div>
            )}

            {redactionNotice && (
              <div className="rounded-2xl bg-[#101A2E] border border-[#35C6F4]/35 px-4 py-3 text-xs text-sky-100 animate-fade-in">
                {redactionNotice}
              </div>
            )}

            {validationError && (
              <div
                role="alert"
                className="rounded-2xl bg-rose-950/60 border border-rose-400/40 px-4 py-3 flex items-center gap-2.5 text-sm text-rose-100 animate-fade-in"
              >
                <AlertTriangle className="w-4 h-4 text-rose-300 shrink-0" />
                <span>{validationError}</span>
              </div>
            )}

            <div className="flex items-center gap-3 pt-1">
              <button
                type="button"
                onClick={() => {
                  onMessageChange('');
                  messageInputRef.current?.focus();
                }}
                disabled={!messageInput || isScanning}
                className="interactive-lift flex items-center justify-center gap-1.5 px-4 py-3 text-sm font-medium text-slate-200 hover:text-white bg-[#101A2E] hover:bg-slate-800 border border-slate-700/80 rounded-2xl disabled:opacity-40 disabled:pointer-events-none whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RotateCcw className="w-4 h-4" />
                <span>Clear Input</span>
              </button>

              <button
                type="submit"
                disabled={isScanning}
                className="interactive-lift flex-1 flex items-center justify-center gap-2 px-6 py-3 text-sm font-bold text-slate-950 bg-gradient-to-r from-[#35C6F4] to-[#55E6C1] hover:brightness-105 rounded-2xl shadow-lg shadow-[#35C6F4]/15 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {isScanning ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Search className="w-4 h-4" />
                )}
                <span>{isScanning ? 'Scanning Message...' : 'Analyze Message'}</span>
              </button>
            </div>
          </form>
        ) : (
          /* URL SCANNER VIEW */
          <form
            key="url-form"
            onSubmit={(e) => {
              e.preventDefault();
              onScanUrl();
            }}
            className="space-y-4 animate-fade-in"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <label
                  htmlFor="suspicious-url-input"
                  className="text-sm font-semibold text-slate-100"
                >
                  Suspicious Website Link (URL)
                </label>
                <span className="text-xs text-[#55E6C1] font-medium">
                  Zero-Visit Static Inspection
                </span>
              </div>

              <input
                ref={urlInputRef}
                id="suspicious-url-input"
                type="text"
                value={urlInput}
                onChange={(e) => onUrlChange(e.target.value)}
                placeholder="https://example-login-verify.tk/account/confirm"
                className="w-full rounded-2xl bg-[#080E1C]/95 border border-slate-700/80 focus:border-[#35C6F4] focus:outline-none focus:ring-3 focus:ring-[#35C6F4]/20 px-4 py-3.5 text-sm font-mono text-white placeholder:text-slate-400 transition-all"
              />
            </div>

            {validationError && (
              <div
                role="alert"
                className="rounded-2xl bg-rose-950/60 border border-rose-400/40 px-4 py-3 flex items-center gap-2.5 text-sm text-rose-100 animate-fade-in"
              >
                <AlertTriangle className="w-4 h-4 text-rose-300 shrink-0" />
                <span>{validationError}</span>
              </div>
            )}

            <div className="flex items-center gap-3 pt-1">
              <button
                type="button"
                onClick={() => {
                  onUrlChange('');
                  urlInputRef.current?.focus();
                }}
                disabled={!urlInput || isScanning}
                className="interactive-lift flex items-center justify-center gap-1.5 px-4 py-3 text-sm font-medium text-slate-200 hover:text-white bg-[#101A2E] hover:bg-slate-800 border border-slate-700/80 rounded-2xl disabled:opacity-40 disabled:pointer-events-none whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RotateCcw className="w-4 h-4" />
                <span>Clear Input</span>
              </button>

              <button
                type="submit"
                disabled={isScanning}
                className="interactive-lift flex-1 flex items-center justify-center gap-2 px-6 py-3 text-sm font-bold text-slate-950 bg-gradient-to-r from-[#35C6F4] to-[#55E6C1] hover:brightness-105 rounded-2xl shadow-lg shadow-[#35C6F4]/15 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {isScanning ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Search className="w-4 h-4" />
                )}
                <span>{isScanning ? 'Inspecting URL...' : 'Inspect URL'}</span>
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Bottom Privacy & Safety Reassurance */}
      <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-300">
        <Lock className="w-4 h-4 text-[#55E6C1] shrink-0 mt-0.5" />
        <span>
          {activeTab === 'message'
            ? 'Privacy-first analysis: Never enter real passwords, OTPs, or CVVs. Complete private messages are never stored.'
            : 'Safe zero-visit inspection: PhishShield AI analyzes the URL structure without ever opening or visiting the destination site.'}
        </span>
      </div>
    </div>
  );
};
