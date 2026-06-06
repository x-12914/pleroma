import { useState, useEffect, useCallback, useRef } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts';
import { RefreshCw, ChevronRight } from 'lucide-react';
import { format } from 'date-fns';
import MetricCard, { Card } from '../components/Card';
import { LoadingSpinner, EmptyState } from '../components/LoadingState';
import { analysisService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { getThreatInfo } from '../utils/threats';

/* ---------------------------------------------------------------
   Overview — the home dashboard.

   Asymmetric layout: Threats detected gets a wider, larger card
   with an inline sparkline. Total scans + Clean traffic are
   smaller secondary metrics. Charts use the refined token palette.
   Live feed is a compact list, not a heavy table.
   --------------------------------------------------------------- */

interface LogRow {
  id: number;
  timestamp: string;
  category: string;
  target: string;
  verdict: string;
  score?: number;
  confidence?: number;
  report_data?: {
    raw_class?: string;
    reason?: string;
  };
}

const ACCENT = '#a3e635';        // lime-400
const SIG_DANGER = '#f87171';    // red-400
const SIG_OK = '#4ade80';        // green-400
const INK_DIM = '#525258';
const SURFACE_BORDER = '#26262a';
const SURFACE_CARD = '#1a1a1d';

export default function Dashboard() {
  const { user } = useAuth();
  const [stats, setStats] = useState({ total_scans: 0, threats_detected: 0, clean_scans: 0 });
  const [logs, setLogs] = useState<LogRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [isRetraining, setIsRetraining] = useState(false);
  const [responseMs, setResponseMs] = useState<number | null>(null);
  const initial = useRef(true);

  const fetchAll = useCallback(async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true);
    const t0 = Date.now();
    try {
      const [statsRes, logsRes] = await Promise.all([
        analysisService.getStats(),
        analysisService.getHistory(8),
      ]);
      setResponseMs(Date.now() - t0);
      setStats(statsRes.data);
      setLogs(logsRes.data || []);
    } catch (err) {
      console.error('Overview sync failed:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const handleRetrain = async () => {
    if (!window.confirm('Trigger background retraining of the network classifier?')) return;
    setIsRetraining(true);
    try {
      await analysisService.retrainModel();
    } catch (err: any) {
      console.error('Retrain failed:', err?.response?.status);
    } finally {
      setTimeout(() => setIsRetraining(false), 1200);
    }
  };

  useEffect(() => {
    if (initial.current) {
      fetchAll();
      initial.current = false;
    }
    const id = setInterval(() => fetchAll(false), 30000);
    return () => clearInterval(id);
  }, [fetchAll]);

  // Synthesised trend — we don't have real per-hour history yet.
  // Honest label below the chart says so.
  const sparkData = [
    { t: '00h', requests: Math.round(stats.total_scans * 0.10), threats: Math.round(stats.threats_detected * 0.05) },
    { t: '06h', requests: Math.round(stats.total_scans * 0.22), threats: Math.round(stats.threats_detected * 0.18) },
    { t: '12h', requests: Math.round(stats.total_scans * 0.35), threats: Math.round(stats.threats_detected * 0.32) },
    { t: '18h', requests: Math.round(stats.total_scans * 0.21), threats: Math.round(stats.threats_detected * 0.27) },
    { t: 'now', requests: Math.round(stats.total_scans * 0.12), threats: Math.round(stats.threats_detected * 0.18) },
  ];

  const distribution = [
    { name: 'Clean', value: stats.clean_scans, fill: SIG_OK },
    { name: 'Threat', value: stats.threats_detected, fill: SIG_DANGER },
  ];

  return (
    <main id="main" className="space-y-7">
      {/* Header */}
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-display-md font-medium text-ink">Overview</h1>
          <p className="mt-1 text-sm text-ink-subtle">
            Real-time view of classifier activity and recent detections.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {responseMs !== null && (
            <span className="hidden sm:inline-flex items-center gap-1.5 text-2xs text-ink-subtle px-2.5 py-1.5 rounded-soft bg-surface-card border border-surface-border tabular">
              <span className="w-1 h-1 rounded-pill bg-accent" />
              {responseMs}ms
            </span>
          )}
          {user?.is_admin && (
            <button
              onClick={handleRetrain}
              disabled={isRetraining}
              className="inline-flex items-center gap-2 text-xs text-accent bg-accent-quiet hover:bg-accent-subtle border border-accent-border/50 px-3 py-1.5 rounded-soft transition-colors duration-200 ease-crisp disabled:opacity-50"
            >
              {isRetraining ? 'Retraining' : 'Retrain'}
            </button>
          )}
          <button
            onClick={() => fetchAll(true)}
            disabled={refreshing}
            className="inline-flex items-center gap-2 text-xs text-ink-muted hover:text-ink px-3 py-1.5 rounded-soft border border-surface-border bg-surface-card transition-colors duration-200 ease-crisp"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Syncing' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Asymmetric stat layout — threats card spans wider + taller */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="md:col-span-2 md:row-span-2 bg-surface-card border border-surface-border rounded-card p-7 flex flex-col">
          <div className="flex items-baseline justify-between mb-4">
            <p className="text-xs text-ink-muted">Threats detected (all time)</p>
            <span className="text-2xs uppercase tracking-micro text-ink-dim tabular">
              {stats.total_scans > 0
                ? `${((stats.threats_detected / stats.total_scans) * 100).toFixed(1)}% of traffic`
                : 'No traffic yet'}
            </span>
          </div>
          <p className="text-display-xl tabular font-medium text-signal-danger mb-5">
            {stats.threats_detected.toLocaleString()}
          </p>
          <div className="flex-1 min-h-[140px] -mx-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sparkData}>
                <CartesianGrid strokeDasharray="2 4" stroke={SURFACE_BORDER} vertical={false} />
                <XAxis
                  dataKey="t"
                  stroke={INK_DIM}
                  fontSize={10}
                  axisLine={false}
                  tickLine={false}
                  dy={6}
                />
                <YAxis stroke={INK_DIM} fontSize={10} axisLine={false} tickLine={false} width={28} />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  contentStyle={{
                    backgroundColor: SURFACE_CARD,
                    border: `1px solid ${SURFACE_BORDER}`,
                    borderRadius: 8,
                    fontSize: 11,
                    padding: '6px 10px',
                  }}
                  labelStyle={{ color: INK_DIM }}
                  itemStyle={{ color: '#fff' }}
                />
                <Bar dataKey="requests" fill={ACCENT} radius={[3, 3, 0, 0]} barSize={18} />
                <Bar dataKey="threats" fill={SIG_DANGER} radius={[3, 3, 0, 0]} barSize={18} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="mt-2 text-2xs text-ink-dim italic">
            Trend approximated from totals — accurate per-hour series in a later phase.
          </p>
        </div>

        <MetricCard
          label="Total scans"
          value={stats.total_scans.toLocaleString()}
          hint="URL + network"
          tone="neutral"
        />
        <MetricCard
          label="Clean traffic"
          value={stats.clean_scans.toLocaleString()}
          hint="Classified normal"
          tone="ok"
        />
      </div>

      {/* Distribution + Live feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <Card title="Verdict mix" subtitle="Clean versus flagged across all detections" className="lg:col-span-1">
          <div className="h-[200px] flex items-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={distribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={48}
                  outerRadius={72}
                  paddingAngle={4}
                  dataKey="value"
                  stroke="none"
                >
                  {distribution.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: SURFACE_CARD,
                    border: `1px solid ${SURFACE_BORDER}`,
                    borderRadius: 8,
                    fontSize: 11,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 flex justify-center gap-5 text-2xs text-ink-subtle tabular">
            <span className="inline-flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-pill bg-signal-ok" /> Clean {stats.clean_scans.toLocaleString()}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-pill bg-signal-danger" /> Threat {stats.threats_detected.toLocaleString()}
            </span>
          </div>
        </Card>

        <Card title="Live intelligence feed" subtitle="Most recent eight detections" className="lg:col-span-2">
          {loading ? (
            <LoadingSpinner />
          ) : logs.length === 0 ? (
            <EmptyState
              title="No recent activity"
              description="Once a sensor ships flows or you scan a URL, results appear here."
            />
          ) : (
            <ul className="-mx-2 -my-2">
              {logs.map((log) => {
                const threat = getThreatInfo(log.report_data?.raw_class);
                const score = log.score ?? log.confidence ?? 0;
                const pct = score > 1 ? score : score * 100;
                const severity = threat?.severity ?? 'normal';
                const dot =
                  severity === 'malicious'
                    ? 'bg-signal-danger'
                    : severity === 'suspicious'
                    ? 'bg-signal-warning'
                    : 'bg-signal-ok';

                return (
                  <li key={log.id} className="flex items-center gap-3 px-2 py-2.5 rounded-soft hover:bg-surface-hover/30 transition-colors duration-150 ease-crisp">
                    <span className={`w-1.5 h-1.5 rounded-pill ${dot} shrink-0`} aria-hidden />
                    <span className="text-2xs text-ink-dim tabular font-mono w-16 shrink-0">
                      {format(new Date(log.timestamp), 'HH:mm:ss')}
                    </span>
                    <span className="text-2xs uppercase tracking-micro text-ink-dim w-14 shrink-0">
                      {log.category === 'URL_SCAN' ? 'URL' : 'Net'}
                    </span>
                    <span className="text-sm text-ink flex-1 min-w-0 truncate">
                      {threat?.name ?? (log.category === 'URL_SCAN' ? 'URL inspection' : log.verdict)}
                    </span>
                    <span className="text-xs text-ink-muted truncate max-w-[200px] hidden md:inline" title={log.target}>
                      {log.target}
                    </span>
                    <span className="text-xs text-ink-subtle tabular w-10 text-right">
                      {Math.round(pct)}%
                    </span>
                    <ChevronRight className="w-3.5 h-3.5 text-ink-dim shrink-0" />
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>
    </main>
  );
}
