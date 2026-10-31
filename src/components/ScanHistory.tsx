import React, { useState, useMemo } from 'react';
import {
  Trash2,
  ArrowUpRight,
  ShieldOff,
  Search,
  Mail,
  Link2,
  X,
} from 'lucide-react';
import type { ScanHistoryItem, RiskCategory } from '../utils/phishingRules';

interface ScanHistoryProps {
  history: ScanHistoryItem[];
  activeResultId: string | null;
  onSelectHistoryItem: (item: ScanHistoryItem) => void;
  onClearHistory: () => void;
}

type HistoryFilter = 'all' | RiskCategory;

export const ScanHistory: React.FC<ScanHistoryProps> = ({
  history,
  activeResultId,
  onSelectHistoryItem,
  onClearHistory,
}) => {
  const [filter, setFilter] = useState<HistoryFilter>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredHistory = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return history.filter((item) => {
      const matchesFilter = filter === 'all' || item.riskCategory === filter;
      if (!matchesFilter) return false;
      if (!query) return true;
      return (
        item.privacySafeSnippet.toLowerCase().includes(query) ||
        item.riskCategory.toLowerCase().includes(query) ||
        item.scanType.toLowerCase().includes(query) ||
        String(item.riskScore).includes(query)
      );
    });
  }, [history, filter, searchQuery]);

  return (
    <section
      id="history"
      aria-labelledby="history-heading"
      className="scroll-mt-28 animate-fade-up"
    >
      <div className="saas-card rounded-3xl p-6 sm:p-8 space-y-6">
        {/* Header + Search + Risk Filter + Clear Action */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-[#35C6F4] block mb-1">
              Privacy-Preserving Audit Log
            </span>
            <h2 id="history-heading" className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Scan History
            </h2>
            <p className="text-sm text-slate-300 mt-1">
              Recent message and URL inspections with personal emails, phone numbers, and full texts redacted.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative flex-1 sm:flex-initial sm:w-56">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                aria-label="Search scan history"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search history..."
                className="w-full rounded-xl bg-[#080E1C]/90 border border-slate-700/80 focus:border-[#35C6F4] focus:outline-none pl-9 pr-8 py-2 text-xs text-white placeholder:text-slate-400"
              />
              {searchQuery && (
                <button
                  type="button"
                  aria-label="Clear search"
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Filter by Risk Level */}
            <div
              role="group"
              aria-label="Filter Scan History by Risk Category"
              className="flex flex-wrap items-center gap-1 p-1 bg-[#080E1C] border border-slate-800 rounded-xl"
            >
              {(['all', 'High Risk', 'Suspicious', 'Lower Indicators'] as HistoryFilter[]).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setFilter(tab)}
                  className={`interactive-lift px-3 py-1.5 text-xs font-semibold rounded-lg whitespace-nowrap shrink-0 cursor-pointer ${
                    filter === tab
                      ? 'bg-[#35C6F4]/20 text-[#35C6F4]'
                      : 'text-slate-300 hover:text-white'
                  }`}
                >
                  {tab === 'all' ? 'All' : tab}
                </button>
              ))}
            </div>

            {/* Clear History Button */}
            <button
              type="button"
              onClick={onClearHistory}
              disabled={history.length === 0}
              className="interactive-lift flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-rose-200 hover:text-white bg-rose-950/50 hover:bg-rose-900/70 border border-rose-500/30 rounded-xl disabled:opacity-40 disabled:pointer-events-none whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear History</span>
            </button>
          </div>
        </div>

        {/* Modern Dashboard Table or Empty State */}
        {filteredHistory.length === 0 ? (
          <div className="py-12 text-center space-y-3 animate-fade-in">
            <div className="w-12 h-12 rounded-2xl bg-[#101A2E] border border-slate-800 flex items-center justify-center mx-auto">
              <ShieldOff className="w-6 h-6 text-slate-400" />
            </div>
            <div className="space-y-1">
              <h3 className="text-base font-bold text-white">
                {history.length === 0
                  ? 'No Scans Recorded Yet'
                  : 'No Matching History Entries'}
              </h3>
              <p className="text-xs sm:text-sm text-slate-300 max-w-md mx-auto leading-relaxed">
                {history.length === 0
                  ? 'Run a message or URL scan above to populate your security audit log. Every completed scan will appear here.'
                  : 'Try clearing your search query or switching the risk filter above.'}
              </p>
            </div>
            {history.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  setFilter('all');
                  setSearchQuery('');
                }}
                className="interactive-lift inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-[#35C6F4] hover:text-white bg-[#101A2E] border border-slate-700 rounded-xl cursor-pointer"
              >
                <span>Reset Filters</span>
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  <th className="pb-3 pr-4 font-semibold">Scan Type &amp; Redacted Preview</th>
                  <th className="pb-3 px-4 font-semibold whitespace-nowrap">Date &amp; Time</th>
                  <th className="pb-3 px-4 font-semibold whitespace-nowrap">Risk Score</th>
                  <th className="pb-3 px-4 font-semibold whitespace-nowrap">Risk Category</th>
                  <th className="pb-3 pl-4 font-semibold text-right whitespace-nowrap">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-xs sm:text-sm">
                {filteredHistory.map((item) => {
                  const isSelected = item.id === activeResultId;
                  const categoryColor =
                    item.riskCategory === 'High Risk'
                      ? 'text-rose-300 bg-rose-500/10 border-rose-500/30'
                      : item.riskCategory === 'Suspicious'
                        ? 'text-amber-300 bg-amber-500/10 border-amber-400/30'
                        : 'text-emerald-300 bg-emerald-500/10 border-emerald-400/30';

                  const scoreColor =
                    item.riskCategory === 'High Risk'
                      ? 'text-rose-300'
                      : item.riskCategory === 'Suspicious'
                        ? 'text-amber-300'
                        : 'text-emerald-300';

                  const dateObj = new Date(item.timestamp);
                  const formattedDate = dateObj.toLocaleDateString([], {
                    month: 'short',
                    day: 'numeric',
                  });
                  const formattedTime = dateObj.toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                  });

                  return (
                    <tr
                      key={item.id}
                      className={`transition-colors ${
                        isSelected ? 'bg-[#35C6F4]/10' : 'hover:bg-[#101A2E]/60'
                      }`}
                    >
                      <td className="py-4 pr-4 max-w-xs sm:max-w-md">
                        <div className="flex items-center gap-2.5">
                          <div className="w-8 h-8 rounded-xl bg-[#080E1C] border border-slate-800 flex items-center justify-center shrink-0 text-[#35C6F4]">
                            {item.scanType === 'url' ? (
                              <Link2 className="w-4 h-4" />
                            ) : (
                              <Mail className="w-4 h-4" />
                            )}
                          </div>
                          <div className="min-w-0">
                            <div className="text-xs font-semibold text-white">
                              {item.scanType === 'url' ? 'URL Inspection' : 'Message Scan'}
                            </div>
                            <p className="text-xs font-mono text-slate-300 truncate mt-0.5">
                              {item.privacySafeSnippet}
                            </p>
                          </div>
                        </div>
                      </td>

                      <td className="py-4 px-4 font-mono tabular-nums text-xs text-slate-300 whitespace-nowrap">
                        {formattedDate}, {formattedTime}
                      </td>

                      <td className="py-4 px-4 font-mono tabular-nums whitespace-nowrap">
                        <span className={`text-sm font-bold ${scoreColor}`}>
                          {item.riskScore}
                        </span>
                        <span className="text-xs text-slate-400"> / 100</span>
                      </td>

                      <td className="py-4 px-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-lg border text-xs font-semibold ${categoryColor}`}>
                          {item.riskCategory}
                        </span>
                      </td>

                      <td className="py-4 pl-4 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => onSelectHistoryItem(item)}
                          className={`interactive-lift inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl border cursor-pointer ${
                            isSelected
                              ? 'bg-[#35C6F4]/20 text-[#35C6F4] border-[#35C6F4]/50'
                              : 'text-slate-200 hover:text-slate-950 bg-[#101A2E] hover:bg-[#35C6F4] border-slate-700 hover:border-[#35C6F4]'
                          }`}
                        >
                          <span>{isSelected ? 'Viewing Report' : 'View Report'}</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
};
