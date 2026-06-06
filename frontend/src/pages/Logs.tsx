import { useState, useEffect, useMemo, useCallback } from 'react';
import { Search, X, Download, Info, ChevronRight, ChevronLeft } from 'lucide-react';
import { format } from 'date-fns';
import { toast } from 'sonner';
import { analysisService } from '../services/api';
import { LoadingSpinner, EmptyState } from '../components/LoadingState';
import MetricCard from '../components/Card';
import { getThreatInfo } from '../utils/threats';

/* ---------------------------------------------------------------
   Detections — refined detection log view.

   Replaces the previous "SECURITY LOGS" page entirely:
   • Sentence case throughout, no ALL CAPS shouting.
   • Tabular figures on all numbers.
   • Asymmetric stat row — threats get prominence.
   • Right slide-over panel instead of centered modal.
   • Threat column color-coded by severity (subtle, not screaming).
   • No glassmorphism. Solid surfaces, subtle borders.
   --------------------------------------------------------------- */

interface LogEntry {
  id: number;
  timestamp: string;
  category: string;
  target: string;
  verdict: string;
  score: number;
  report_data?: {
    raw_class?: string;
    reason?: string;
    details?: string;
    title?: string;
    osint_data?: Array<{ title: string; snippet: string }>;
    scrape_data?: { text?: string; title?: string; error?: string };
    raw_input?: Record<string, unknown>;
    sensor_name?: string;
  };
}

const PAGE_SIZE = 50;

export default function Logs() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [stats, setStats] = useState({ total_scans: 0, threats_detected: 0, clean_scans: 0 });
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [loading, setLoading] = useState(true);
  const [isFeedbacking, setIsFeedbacking] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(0); // 0-indexed; page 0 is the newest

  const fetchPage = useCallback(async (targetPage: number) => {
    setLoading(true);
    try {
      const offset = targetPage * PAGE_SIZE;
      const [history, stat] = await Promise.all([
        analysisService.getHistory(PAGE_SIZE, offset),
        analysisService.getStats(),
      ]);
      setLogs(history.data || []);
      setStats(stat.data);
    } catch {
      toast.error('Could not load detections.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPage(page);
  }, [page, fetchPage]);

  // Helper used by the feedback handler — refresh the current page.
  const refreshCurrent = useCallback(() => fetchPage(page), [page, fetchPage]);

  async function handleFeedback(logId: number, isCorrect: boolean, corrected: string) {
    setIsFeedbacking(true);
    try {
      await analysisService.submitLogFeedback(logId, {
        is_correct: isCorrect,
        corrected_verdict: corrected,
      });
      toast.success('Feedback recorded.');
      setSelectedLog(null);
      await refreshCurrent();
    } catch {
      toast.error('Could not submit feedback.');
    } finally {
      setIsFeedbacking(false);
    }
  }

  function exportCsv() {
    if (logs.length === 0) {
      toast.info('No detections to export.');
      return;
    }
    const rows = logs.map(l => `${l.timestamp},${l.category},${l.target},${l.verdict},${l.score}`);
    const blob = new Blob(
      ['timestamp,category,target,verdict,score\n' + rows.join('\n')],
      { type: 'text/csv' }
    );
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pleroma-detections-${format(new Date(), 'yyyy-MM-dd')}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  }

  const filteredLogs = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return logs;
    return logs.filter(l =>
      [l.target, l.verdict, l.report_data?.raw_class].some(s =>
        (s ?? '').toString().toLowerCase().includes(q)
      )
    );
  }, [logs, searchTerm]);

  const threatPct = stats.total_scans > 0
    ? Math.round((stats.threats_detected / stats.total_scans) * 1000) / 10
    : 0;

  return (
    <main id="main" className="space-y-7">
      {/* Header */}
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-display-md font-medium text-ink">Detections</h1>
          <p className="mt-1 text-sm text-ink-subtle">
            Every scan and sensor flow recorded by the classifier — most recent first.
          </p>
        </div>
        <button
          onClick={exportCsv}
          className="inline-flex items-center gap-2 text-xs text-ink-muted hover:text-ink px-3 py-1.5 rounded-soft border border-surface-border hover:border-surface-border-strong bg-surface-card transition-colors duration-200 ease-crisp"
        >
          <Download className="w-3.5 h-3.5" />
          Export CSV
        </button>
      </div>

      {/* Asymmetric stat row — Threats gets prominence */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="md:col-span-1 md:row-span-2">
          <MetricCard
            label="Threats detected"
            value={stats.threats_detected.toLocaleString()}
            hint={`${threatPct}% of all scans flagged as malicious or suspicious`}
            tone="danger"
            size="lg"
          />
        </div>
        <MetricCard
          label="Total scans"
          value={stats.total_scans.toLocaleString()}
          hint="Across URL scans and sensor flows"
          tone="neutral"
        />
        <MetricCard
          label="Clean traffic"
          value={stats.clean_scans.toLocaleString()}
          hint="Flows classified normal"
          tone="ok"
        />
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-dim pointer-events-none" />
        <input
          type="text"
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          placeholder="Search by target, verdict, or threat type"
          className="w-full pl-10 pr-4 py-2.5 bg-surface-card border border-surface-border rounded-soft text-sm text-ink placeholder:text-ink-dim focus:outline-none focus:border-accent-border focus:shadow-focus-ring transition-shadow"
        />
      </div>

      {/* Page header — only shows when not on first page or when there's more */}
      {(page > 0 || logs.length === PAGE_SIZE) && (
        <div className="flex items-center justify-between text-2xs text-ink-subtle px-1">
          <span className="tabular">
            Page <span className="text-ink">{page + 1}</span>
            {stats.total_scans > 0 && (
              <> — showing {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + logs.length} of {stats.total_scans.toLocaleString()}</>
            )}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0 || loading}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-soft border border-surface-border bg-surface-card text-ink-muted hover:text-ink disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" /> Newer
            </button>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={logs.length < PAGE_SIZE || loading}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-soft border border-surface-border bg-surface-card text-ink-muted hover:text-ink disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Older <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Detection list */}
      <section className="bg-surface-card border border-surface-border rounded-card overflow-hidden">
        {loading ? (
          <div className="p-8 space-y-3">
            <LoadingSpinner />
          </div>
        ) : filteredLogs.length === 0 ? (
          <EmptyState
            title={searchTerm ? 'No detections match that query.' : 'No detections yet.'}
            description={
              searchTerm
                ? 'Try a different target name or threat label.'
                : 'When a sensor flags traffic or you run a URL scan, results land here.'
            }
          />
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-surface-border text-2xs uppercase tracking-micro text-ink-dim">
                <th className="px-4 py-3 font-normal">When</th>
                <th className="px-4 py-3 font-normal">Source</th>
                <th className="px-4 py-3 font-normal">Threat</th>
                <th className="px-4 py-3 font-normal">Target</th>
                <th className="px-4 py-3 font-normal text-right">Confidence</th>
                <th className="px-4 py-3 font-normal w-10" aria-label="Actions" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {filteredLogs.map(log => {
                const threat = getThreatInfo(log.report_data?.raw_class);
                const severity = threat?.severity ?? 'normal';
                const verdictTone =
                  severity === 'malicious'
                    ? 'text-signal-danger'
                    : severity === 'suspicious'
                    ? 'text-signal-warning'
                    : log.verdict.toLowerCase() === 'normal' || log.verdict.toLowerCase() === 'safe'
                    ? 'text-signal-ok'
                    : 'text-ink-muted';

                return (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-surface-hover/30 transition-colors duration-150 ease-crisp cursor-pointer group"
                  >
                    <td className="px-4 py-3 text-xs text-ink-subtle tabular font-mono">
                      {format(new Date(log.timestamp), 'MMM dd · HH:mm:ss')}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-2xs uppercase tracking-micro text-ink-dim">
                        {log.category === 'URL_SCAN' ? 'URL' : 'Network'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {threat ? (
                        <div className="flex items-center gap-2">
                          <span
                            className={`w-1.5 h-1.5 rounded-pill ${
                              severity === 'malicious'
                                ? 'bg-signal-danger'
                                : severity === 'suspicious'
                                ? 'bg-signal-warning'
                                : 'bg-signal-ok'
                            }`}
                            aria-hidden
                          />
                          <span className={`text-sm font-medium ${verdictTone}`}>
                            {threat.name}
                          </span>
                        </div>
                      ) : log.category === 'URL_SCAN' ? (
                        <span className="text-sm text-ink-muted">URL inspection</span>
                      ) : (
                        <span className="text-sm text-ink-dim">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-ink-muted truncate max-w-[280px]" title={log.target}>
                      {log.target}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-2.5">
                        <div className="w-14 h-1 bg-surface-border rounded-pill overflow-hidden">
                          <div
                            className={`h-full ${
                              severity === 'malicious'
                                ? 'bg-signal-danger'
                                : severity === 'suspicious'
                                ? 'bg-signal-warning'
                                : 'bg-accent'
                            }`}
                            style={{ width: `${Math.min(100, log.score * 100)}%` }}
                          />
                        </div>
                        <span className="text-xs text-ink-muted tabular w-8 text-right">
                          {Math.round(log.score * 100)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <ChevronRight className="w-4 h-4 text-ink-dim group-hover:text-ink-muted transition-colors" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>

      {/* Slide-over detail panel — replaces centered modal */}
      {selectedLog && (
        <DetailPanel
          log={selectedLog}
          onClose={() => setSelectedLog(null)}
          onFeedback={handleFeedback}
          isFeedbacking={isFeedbacking}
        />
      )}
    </main>
  );
}

/* ============================================================
   Slide-over detail panel
   ============================================================ */

function DetailPanel({
  log,
  onClose,
  onFeedback,
  isFeedbacking,
}: {
  log: LogEntry;
  onClose: () => void;
  onFeedback: (id: number, correct: boolean, corrected: string) => void;
  isFeedbacking: boolean;
}) {
  const threat = getThreatInfo(log.report_data?.raw_class);
  const severityTint =
    threat?.severity === 'malicious'
      ? 'bg-signal-danger-bg border-signal-danger-border/40'
      : threat?.severity === 'suspicious'
      ? 'bg-signal-warning-bg border-signal-warning-border/40'
      : 'bg-signal-ok-bg border-signal-ok-border/40';

  const severityText =
    threat?.severity === 'malicious'
      ? 'text-signal-danger'
      : threat?.severity === 'suspicious'
      ? 'text-signal-warning'
      : 'text-signal-ok';

  return (
    <div className="fixed inset-0 z-50 flex" role="dialog" aria-modal="true">
      <button
        type="button"
        className="flex-1 bg-surface-base/70 backdrop-blur-sm scrim-enter"
        onClick={onClose}
        aria-label="Close detail panel"
      />
      <aside className="relative w-full sm:max-w-[560px] h-dvh bg-surface-base border-l border-surface-border flex flex-col panel-enter shadow-lift">
        {/* Header */}
        <header className="flex items-center justify-between gap-4 px-6 h-14 border-b border-surface-border shrink-0">
          <div className="flex items-center gap-3">
            <span className="text-2xs uppercase tracking-micro text-ink-dim tabular">
              ID #{log.id}
            </span>
            <span className="text-2xs uppercase tracking-micro text-ink-dim">
              {log.category === 'URL_SCAN' ? 'URL Scan' : 'Network Flow'}
            </span>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 rounded-soft text-ink-subtle hover:text-ink hover:bg-surface-card transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </header>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          {/* What happened */}
          {threat && (
            <section className={`border ${severityTint} rounded-card p-5`}>
              <p className="text-2xs uppercase tracking-micro text-ink-dim mb-2">
                What happened
              </p>
              <h2 className={`text-display-sm font-medium ${severityText} mb-3`}>
                {threat.name}
              </h2>
              <p className="text-sm text-ink-muted leading-relaxed">
                {threat.description}
              </p>
              {log.report_data?.raw_class && (
                <p className="mt-4 text-2xs font-mono text-ink-dim">
                  Classifier: <span className="text-ink-subtle">{log.report_data.raw_class}</span>
                </p>
              )}
            </section>
          )}

          {/* Stats row */}
          <section className="grid grid-cols-3 gap-2.5">
            <Stat label="Verdict" value={log.verdict} tone={severityText} />
            <Stat
              label="Confidence"
              value={`${(log.score * 100).toFixed(1)}%`}
              tone="text-ink"
              tabular
            />
            <Stat
              label="When"
              value={format(new Date(log.timestamp), 'MMM dd HH:mm')}
              tone="text-ink-muted"
              tabular
            />
          </section>

          {/* Target */}
          <section>
            <p className="text-2xs uppercase tracking-micro text-ink-dim mb-2">Target</p>
            <p className="text-sm font-mono text-ink break-all bg-surface-card border border-surface-border rounded-soft px-3 py-2.5">
              {log.target}
            </p>
          </section>

          {/* AI / heuristic explanation */}
          {(log.report_data?.reason || log.report_data?.details) && (
            <section>
              <p className="text-2xs uppercase tracking-micro text-ink-dim mb-2">
                Analyst note
              </p>
              <p className="text-sm text-ink-muted leading-relaxed bg-surface-card border border-surface-border rounded-card p-4">
                {log.report_data?.reason || log.report_data?.details}
              </p>
            </section>
          )}

          {/* URL scan specifics */}
          {log.category === 'URL_SCAN' && log.report_data?.osint_data && log.report_data.osint_data.length > 0 && (
            <section>
              <p className="text-2xs uppercase tracking-micro text-ink-dim mb-2">
                Open-source mentions
              </p>
              <div className="space-y-2">
                {log.report_data.osint_data.slice(0, 3).map((item, i) => (
                  <div key={i} className="bg-surface-card border border-surface-border rounded-soft px-3 py-2.5">
                    <p className="text-xs font-medium text-ink truncate">{item.title}</p>
                    <p className="mt-1 text-xs text-ink-subtle line-clamp-2 leading-snug">
                      {item.snippet}
                    </p>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Network feature vector */}
          {log.category === 'NETWORK_TRAFFIC' && log.report_data?.raw_input && (
            <section>
              <p className="text-2xs uppercase tracking-micro text-ink-dim mb-2">
                Flow features
              </p>
              <div className="grid grid-cols-2 gap-1.5 max-h-64 overflow-y-auto bg-surface-card border border-surface-border rounded-card p-3">
                {Object.entries(log.report_data.raw_input).slice(0, 30).map(([k, v]) => (
                  <div key={k} className="flex items-baseline justify-between gap-2 px-2 py-1 text-xs">
                    <span className="text-ink-dim font-mono truncate">{k}</span>
                    <span className="text-ink-muted font-mono tabular truncate">
                      {String(v).slice(0, 14)}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>

        {/* Footer — feedback actions */}
        <footer className="px-6 py-4 border-t border-surface-border bg-surface-base shrink-0 space-y-2">
          <p className="text-2xs uppercase tracking-micro text-ink-dim">Was this verdict correct?</p>
          <div className="flex gap-2">
            <button
              onClick={() => onFeedback(log.id, true, log.verdict)}
              disabled={isFeedbacking}
              className="flex-1 inline-flex items-center justify-center gap-2 px-3 py-2 rounded-soft text-xs font-medium text-signal-ok bg-signal-ok-bg hover:brightness-110 border border-signal-ok-border/40 transition disabled:opacity-50"
            >
              Confirm
            </button>
            <button
              onClick={() => onFeedback(log.id, false, 'Safe')}
              disabled={isFeedbacking}
              className="flex-1 inline-flex items-center justify-center gap-2 px-3 py-2 rounded-soft text-xs font-medium text-signal-warning bg-signal-warning-bg hover:brightness-110 border border-signal-warning-border/40 transition disabled:opacity-50"
            >
              False positive
            </button>
          </div>
        </footer>
      </aside>
    </div>
  );
}

function Stat({
  label, value, tone = 'text-ink', tabular,
}: {
  label: string;
  value: string;
  tone?: string;
  tabular?: boolean;
}) {
  return (
    <div className="bg-surface-card border border-surface-border rounded-soft px-3 py-2.5">
      <p className="text-2xs uppercase tracking-micro text-ink-dim">{label}</p>
      <p className={`mt-1 text-sm font-medium ${tone} ${tabular ? 'tabular' : ''}`}>
        {value}
      </p>
    </div>
  );
}

// Keep the Info icon referenced so tree-shaking doesn't complain (used by other imports historically).
void Info;
