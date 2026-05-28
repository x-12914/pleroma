import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell 
} from 'recharts';
import { Activity, AlertTriangle, ShieldCheck, Clock, RefreshCw, Database } from 'lucide-react';
import MetricCard, { SimpleCard } from '../components/Card';
import Table from '../components/Table';
import { LoadingSpinner } from '../components/LoadingState';
import { analysisService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { format } from 'date-fns';

interface Stats {
  total_scans: number;
  threats_detected: number;
  clean_scans: number;
}

interface TimeSeriesPoint {
  time: string;
  requests: number;
  threats: number;
}

export default function Dashboard() {
  const { user } = useAuth();
  const [stats, setStats] = useState<Stats>({ total_scans: 0, threats_detected: 0, clean_scans: 0 });
  const [timeSeriesData, setTimeSeriesData] = useState<TimeSeriesPoint[]>([]);
  const [recentLogs, setRecentLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isRetraining, setIsRetraining] = useState(false);
  const [responseTime, setResponseTime] = useState<number | null>(null);
  
  const isInitialMount = useRef(true);

  const threatDistribution = [
    { name: 'Normal', value: stats.clean_scans || 0, fill: '#22c55e' },
    { name: 'Threat', value: stats.threats_detected || 0, fill: '#ef4444' },
  ];

  const fetchData = useCallback(async (showLoading = false) => {
    if (showLoading) setIsRefreshing(true);
    const startTime = Date.now();
    
    try {
      // Fetch Stats and History in parallel
      const [statsRes, logsRes] = await Promise.all([
        analysisService.getStats(),
        analysisService.getHistory(5)
      ]);

      setResponseTime(Date.now() - startTime);
      const data = statsRes.data;
      setStats(data);

      const resolveSystemAction = (verdict: string) => {
        if (verdict === 'Malicious') return 'Blocked';
        if (verdict === 'ERROR') return 'Review Required';
        return 'Allowed';
      };

      // Map backend logs to Table rows
      const formattedLogs = logsRes.data.map((log: any) => ({
        time: format(new Date(log.timestamp), 'HH:mm:ss'),
        type: log.category === 'URL_SCAN' ? 'URL' : 'Net',
        source: log.target,
        port: log.category === 'URL_SCAN' ? (log.target.startsWith('https') ? 'HTTPS' : 'HTTP') : 'N/A',
        action: resolveSystemAction(log.verdict),
        verdict: log.verdict,
        // FIX: Extract confidence from score (0-1) or confidence (0-100)
        displayConfidence: log.score ? Math.round(log.score * 100) : (log.confidence || 0),
        // Check if this came from a Guard (high confidence override)
        isShieldTriggered: (log.score && log.score >= 0.85) || (log.confidence && log.confidence >= 85),
      }));
      setRecentLogs(formattedLogs);

      // Derive visual trend data from real totals
      const trend = [
        { time: '00:00', requests: Math.floor(data.total_scans * 0.1), threats: Math.floor(data.threats_detected * 0.05) },
        { time: '08:00', requests: Math.floor(data.total_scans * 0.3), threats: Math.floor(data.threats_detected * 0.4) },
        { time: '16:00', requests: Math.floor(data.total_scans * 0.4), threats: Math.floor(data.threats_detected * 0.3) },
        { time: 'now', requests: data.total_scans, threats: data.threats_detected },
      ];
      setTimeSeriesData(trend);

    } catch (error) {
      console.error('Dashboard sync error:', error);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  const handleRetrain = async () => {
    if (!window.confirm("Initialize ML Engine Retraining? This will update the Random Forest model with new data.")) return;

    setIsRetraining(true);
    try {
      await analysisService.retrainModel();
      alert("Success: Retraining initiated in the background.");
    } catch (error: any) {
      const msg = error.response?.status === 403 ? "Unauthorized: Admin privileges required." : "Failed to contact engine.";
      alert(msg);
    } finally {
      setIsRetraining(false);
    }
  };

  useEffect(() => {
    if (isInitialMount.current) {
      fetchData();
      isInitialMount.current = false;
    }

    const interval = setInterval(() => fetchData(), 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  return (
    <div className="space-y-4 md:space-y-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl md:text-4xl font-black text-white mb-1 tracking-tighter uppercase">SOC Dashboard</h1>
          <p className="text-xs font-bold text-gray-500 uppercase tracking-widest">Real-time threat detection overview</p>
        </div>
        <div className="flex items-center gap-3 w-full sm:w-auto">
          {responseTime !== null && (
            <div className="flex items-center gap-2 px-3 py-2 bg-dark-900 border border-white/5 rounded-xl text-[10px] font-bold uppercase tracking-widest text-gray-400">
              <Clock className="w-3 h-3 text-cyber-blue" />
              <span>Latency: <span className="text-cyber-blue">{responseTime}ms</span></span>
            </div>
          )}

          {user?.is_admin && (
            <button
              onClick={handleRetrain}
              disabled={isRetraining}
              className={`flex items-center gap-2 px-4 py-2 bg-cyber-purple/10 hover:bg-cyber-purple/20 border border-cyber-purple/40 text-cyber-purple rounded-xl transition-all text-xs font-bold uppercase ${isRetraining ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <Database className={`w-3.5 h-3.5 ${isRetraining ? 'animate-bounce' : ''}`} />
              {isRetraining ? 'Retraining...' : 'Retrain ML Engine'}
            </button>
          )}

          <button 
            onClick={() => fetchData(true)}
            disabled={isRefreshing}
            className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 text-white rounded-xl transition-all text-xs font-bold uppercase"
          >
            <RefreshCw className={`w-3 h-3 ${isRefreshing ? 'animate-spin' : ''}`} />
            {isRefreshing ? 'Syncing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <MetricCard
          title="Total Scans"
          value={stats.total_scans.toLocaleString()}
          icon={<Activity className="w-6 h-6 text-cyber-blue" />}
          trend={12}
          status="info"
          subtext="System total"
        />
        <MetricCard
          title="Threats Blocked"
          value={stats.threats_detected}
          icon={<AlertTriangle className="w-6 h-6 text-cyber-red" />}
          trend={5}
          status="danger"
          subtext="Critical events"
        />
        <MetricCard
          title="Safe Traffic"
          value={stats.clean_scans.toLocaleString()}
          icon={<ShieldCheck className="w-6 h-6 text-cyber-green" />}
          trend={-2}
          status="success"
          subtext="Verified clean"
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <SimpleCard title="Traffic Volume (Trend)" className="lg:col-span-2">
          <div className="h-[300px] mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={timeSeriesData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                <XAxis dataKey="time" stroke="#666" fontSize={10} axisLine={false} tickLine={false} />
                <YAxis stroke="#666" fontSize={10} axisLine={false} tickLine={false} />
                <Tooltip
                  cursor={{fill: 'rgba(255,255,255,0.05)'}}
                  contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #333', borderRadius: '12px', fontSize: '10px' }}
                />
                <Bar dataKey="requests" fill="#00f2ff" radius={[4, 4, 0, 0]} barSize={40} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </SimpleCard>

        <SimpleCard title="Threat Distribution">
          <div className="h-[300px] flex flex-col items-center justify-center">
            <ResponsiveContainer width="100%" height="80%">
              <PieChart>
                <Pie 
                  data={threatDistribution} 
                  cx="50%" 
                  cy="50%" 
                  innerRadius={60} 
                  outerRadius={80} 
                  paddingAngle={8} 
                  dataKey="value"
                >
                  {threatDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} stroke="none" />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex gap-4 text-[10px] font-bold uppercase tracking-widest mt-4">
                <div className="flex items-center gap-2"><div className="w-2 h-2 bg-cyber-green rounded-full" /> Safe</div>
                <div className="flex items-center gap-2"><div className="w-2 h-2 bg-cyber-red rounded-full" /> Malicious</div>
            </div>
          </div>
        </SimpleCard>
      </div>

      {/* Recent Activity Table */}
      <SimpleCard title="Live Intelligence Feed">
        {loading ? (
          <div className="py-20 flex justify-center"><LoadingSpinner /></div>
        ) : (
          <Table
            columns={[
              { key: 'time', label: 'Timestamp', className: 'text-gray-500 font-mono' },
              {
                key: 'type',
                label: 'Sensor',
                render: (value) => (
                  <span className={`px-2 py-0.5 rounded-[4px] text-[10px] font-black uppercase tracking-widest ${value === 'URL' ? 'bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/20' : 'bg-cyber-purple/10 text-cyber-purple border border-cyber-purple/20'}`}>
                    {value}
                  </span>
                ),
              },
              {
                key: 'source',
                label: 'Target / Domain',
                render: (value, row) => {
                  const isExfil = row.report_data?.raw_input?.out_bytes > 10000000;  // > 10MB
                  const isShieldTriggered = row.isShieldTriggered;
                  return (
                    <div className="flex flex-col">
                      <span className="max-w-[200px] truncate font-medium text-gray-300">
                        {value}
                      </span>
                      {isShieldTriggered && (
                        <span className="text-[7px] bg-cyber-red/20 text-cyber-red px-1 py-0.5 rounded w-fit font-black mt-1 animate-pulse">
                          Shield Triggered: Expert Rule Override
                        </span>
                      )}
                      {isExfil && !isShieldTriggered && (
                        <span className="text-[7px] bg-cyber-red/20 text-cyber-red px-1 py-0.5 rounded w-fit font-black mt-1 animate-pulse">
                          ⚠️ HEAVY OUTBOUND DATA
                        </span>
                      )}
                      {row.report_data?.reason && !isExfil && !isShieldTriggered && (
                        <span className="text-[8px] text-gray-500 truncate max-w-[180px] italic">
                          AI: {row.report_data.reason}
                        </span>
                      )}
                    </div>
                  );
                },
              },
              {
                key: 'confidence',
                label: 'Confidence',
                render: (_value, row) => {
                  const score = row.displayConfidence || 0;
                  const color = score < 50 ? 'text-cyber-yellow' : 'text-cyber-blue';
                  return (
                    <span className={`${color} font-mono font-bold`}>
                      {score < 50 ? '⚠ ' : ''}{score}%
                    </span>
                  );
                },
              },
              { key: 'port', label: 'Protocol', className: 'hidden sm:table-cell text-gray-500' },
              {
                key: 'action',
                label: 'System Action',
                render: (_value, row) => {
                  // 1. Determine the severity level
                  const verdict = row.verdict?.toLowerCase() || '';
                  const confidence = row.confidence || 0;
                  const isMalicious = verdict === 'malicious' || verdict === 'neptune' || verdict === 'satan';
                  const isSuspicious = verdict === 'suspicious' || confidence < 0.50;
                  const isError = verdict === 'error';

                  // 2. Map color and text
                  let colorClass = "text-cyber-green";
                  let statusText = "Allowed";
                  let dotClass = "bg-cyber-green";

                  if (isMalicious) {
                    colorClass = "text-cyber-red font-black";
                    statusText = "Blocked";
                    dotClass = "bg-cyber-red animate-pulse";
                  } else if (isSuspicious) {
                    colorClass = "text-cyber-yellow";
                    statusText = "Flagged for Review";
                    dotClass = "bg-cyber-yellow animate-pulse";
                  } else if (isError) {
                    colorClass = "text-gray-500";
                    statusText = "Isolated";
                    dotClass = "bg-gray-500";
                  }

                  return (
                    <span className={`flex items-center gap-2 text-[10px] uppercase tracking-tighter ${colorClass}`}>
                      <div className={`w-1 h-1 rounded-full ${dotClass}`} />
                      {statusText}
                    </span>
                  );
                },
              },
            ]}
            data={recentLogs}
          />
        )}
      </SimpleCard>
    </div>
  );
}