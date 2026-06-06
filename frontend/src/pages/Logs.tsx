import { useState, useEffect } from 'react';
import { Info, X, Terminal, Globe, Activity, ShieldAlert, FileDown, Search } from 'lucide-react';
import { format } from 'date-fns';
import { analysisService } from '../services/api';
import { SimpleCard } from '../components/Card';
import { LoadingSpinner } from '../components/LoadingState';
import { getThreatInfo } from '../utils/threats';

export default function Logs() {
  const [logs, setLogs] = useState<any[]>([]);
  const [stats, setStats] = useState({ total_scans: 0, threats_detected: 0, clean_scans: 0 });
  const [selectedLog, setSelectedLog] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [isFeedbacking, setIsFeedbacking] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchLogs();
    fetchStats();
  }, []);

  const fetchLogs = async () => {
    try {
      const { data } = await analysisService.getHistory(100);
      setLogs(data || []);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const { data } = await analysisService.getStats();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const handleFeedback = async (logId: number, isCorrect: boolean, correctedVerdict: string) => {
    setIsFeedbacking(true);
    try {
      await analysisService.submitLogFeedback(logId, {
        is_correct: isCorrect,
        corrected_verdict: correctedVerdict,
      });
      await fetchLogs();
      setSelectedLog(null);
      alert('Feedback submitted successfully.');
    } catch (error) {
      console.error('Failed to submit feedback:', error);
      alert('Unable to submit feedback.');
    } finally {
      setIsFeedbacking(false);
    }
  };

  const exportToCSV = () => {
    const headers = ['Timestamp,Category,Target,Verdict,Score\n'];
    const rows = logs.map(
      (l) => `${l.timestamp},${l.category},${l.target},${l.verdict},${l.score}\n`
    );
    const blob = new Blob([...headers, ...rows], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aicds-logs-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const filteredLogs = logs.filter((log) =>
    log.target?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-700">
      {/* Header with Actions */}
      <div className="flex justify-between items-center bg-dark-900/50 p-6 rounded-2xl border border-white/5">
        <div>
          <h1 className="text-3xl font-black tracking-tighter text-white">SECURITY LOGS</h1>
          <p className="text-gray-500 text-xs uppercase tracking-widest font-bold">
            Historical Threat Intelligence
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={exportToCSV}
            className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-gray-300 rounded-xl border border-white/10 transition-all text-xs font-bold uppercase"
          >
            <FileDown size={16} /> Export CSV
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <SimpleCard title="Total Scans">
          <p className="text-3xl font-black text-white">{stats.total_scans}</p>
        </SimpleCard>
        <SimpleCard title="Threats Detected">
          <p className="text-3xl font-black text-cyber-red">{stats.threats_detected}</p>
        </SimpleCard>
        <SimpleCard title="Clean Traffic">
          <p className="text-3xl font-black text-cyber-green">{stats.clean_scans}</p>
        </SimpleCard>
      </div>

      {/* Search Bar */}
      <div className="flex gap-3">
        <input
          type="text"
          placeholder="Search by target URL or IP..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="flex-1 bg-dark-900 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue transition-colors text-sm"
        />
      </div>

      {/* Logs Table */}
      <div className="bg-dark-900/30 rounded-2xl border border-white/5 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center p-12">
            <LoadingSpinner />
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="p-12 text-center text-gray-500">
            <p className="text-sm uppercase tracking-widest font-bold">No logs found</p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-white/5 text-[10px] uppercase tracking-widest font-black text-gray-400">
                <th className="p-4">Timestamp</th>
                <th className="p-4">Type</th>
                <th className="p-4">Threat</th>
                <th className="p-4">Source</th>
                <th className="p-4">Verdict</th>
                <th className="p-4">Confidence</th>
                <th className="p-4">Action</th>
              </tr>
            </thead>
            <tbody className="text-sm">
              {filteredLogs.map((log: any) => {
                const threat = getThreatInfo(log.report_data?.raw_class);
                return (
                <tr
                  key={log.id}
                  className="border-t border-white/5 hover:bg-white/[0.02] transition-colors cursor-pointer"
                >
                  <td className="p-4 font-mono text-xs text-gray-500">
                    {format(new Date(log.timestamp), 'MMM dd, HH:mm:ss')}
                  </td>
                  <td className="p-4">
                    <span
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase ${
                        log.category === 'URL_SCAN'
                          ? 'bg-cyber-blue/10 text-cyber-blue'
                          : 'bg-cyber-purple/10 text-cyber-purple'
                      }`}
                    >
                      {log.category.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="p-4 font-medium">
                    {threat ? (
                      <span
                        className={`${
                          threat.severity === 'malicious'
                            ? 'text-cyber-red'
                            : threat.severity === 'suspicious'
                            ? 'text-cyber-yellow'
                            : 'text-cyber-green'
                        }`}
                      >
                        {threat.name}
                      </span>
                    ) : log.category === 'URL_SCAN' ? (
                      <span className="text-cyber-blue">URL Inspection</span>
                    ) : (
                      <span className="text-gray-500 italic">—</span>
                    )}
                  </td>
                  <td className="p-4 font-medium text-gray-300 truncate max-w-[250px]">
                    {log.target}
                  </td>
                  <td className="p-4">
                    <div
                      className={`flex items-center gap-2 font-bold ${
                        log.verdict === 'Malicious'
                          ? 'text-cyber-red'
                          : log.verdict === 'ERROR'
                          ? 'text-gray-400'
                          : 'text-cyber-green'
                      }`}
                    >
                      <div
                        className={`w-1.5 h-1.5 rounded-full ${
                          log.verdict === 'Malicious'
                            ? 'bg-cyber-red animate-pulse'
                            : log.verdict === 'ERROR'
                            ? 'bg-gray-500'
                            : 'bg-cyber-green'
                        }`}
                      />
                      {log.verdict.toUpperCase()}
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-white/5 h-1 rounded-full overflow-hidden">
                        <div
                          className="bg-cyber-blue h-full"
                          style={{ width: `${log.score * 100}%` }}
                        />
                      </div>
                      <span className={`text-xs font-mono ${log.score * 100 < 50 ? 'text-cyber-yellow' : 'text-cyber-blue'}`}>
                        {log.score * 100 < 50 ? '⚠ ' : ''}{(log.score * 100).toFixed(0)}%
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <button
                      onClick={() => setSelectedLog(log)}
                      className="p-2 hover:bg-cyber-blue/10 text-gray-500 hover:text-cyber-blue rounded-lg transition-colors"
                    >
                      <Info size={18} />
                    </button>
                  </td>
                </tr>
              );})}
            </tbody>
          </table>
        )}
      </div>

      {/* MODAL: Intelligence Briefing */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-md">
          <div className="bg-dark-900 border border-white/10 w-full max-w-4xl max-h-[90vh] rounded-3xl overflow-hidden flex flex-col shadow-[0_0_50px_rgba(0,0,0,0.5)] animate-in zoom-in duration-300">
            {/* Modal Header */}
            <div className="p-6 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
              <div className="flex items-center gap-4">
                <div
                  className={`p-3 rounded-2xl ${
                    selectedLog.verdict === 'Malicious'
                      ? 'bg-cyber-red/20 text-cyber-red'
                      : selectedLog.verdict === 'ERROR'
                      ? 'bg-gray-700/30 text-gray-300'
                      : 'bg-cyber-green/20 text-cyber-green'
                  }`}
                >
                  <ShieldAlert size={24} />
                </div>
                <div>
                  <h2 className="text-xl font-black text-white tracking-tighter uppercase">
                    Intelligence Briefing
                  </h2>
                  <p className="text-cyber-blue font-mono text-xs">ID: {selectedLog.id}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-2 hover:bg-white/10 rounded-full text-gray-400 transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Content - Scrollable */}
            <div className="p-8 overflow-y-auto space-y-8 flex-1">
              {/* What Happened — friendly threat description */}
              {(() => {
                const threat = getThreatInfo(selectedLog.report_data?.raw_class);
                if (!threat) return null;
                const severityColor =
                  threat.severity === 'malicious'
                    ? 'text-cyber-red border-cyber-red/30 bg-cyber-red/5'
                    : threat.severity === 'suspicious'
                    ? 'text-cyber-yellow border-cyber-yellow/30 bg-cyber-yellow/5'
                    : 'text-cyber-green border-cyber-green/30 bg-cyber-green/5';
                return (
                  <div className={`p-6 rounded-2xl border ${severityColor}`}>
                    <div className="text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-2">
                      What Happened
                    </div>
                    <h3 className="text-2xl font-black tracking-tighter mb-3">
                      {threat.name}
                    </h3>
                    <p className="text-sm leading-relaxed text-gray-300">
                      {threat.description}
                    </p>
                    {selectedLog.report_data?.raw_class && (
                      <p className="mt-3 text-[10px] font-mono text-gray-500">
                        Classifier label:{' '}
                        <span className="text-gray-400">{selectedLog.report_data.raw_class}</span>
                      </p>
                    )}
                  </div>
                );
              })()}

              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-white/5 rounded-2xl border border-white/5">
                  <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                    Verdict
                  </span>
                  <p
                    className={`text-lg font-black ${
                      selectedLog.verdict === 'Malicious'
                        ? 'text-cyber-red'
                        : selectedLog.verdict === 'ERROR'
                        ? 'text-gray-300'
                        : 'text-cyber-green'
                    }`}
                  >
                    {selectedLog.verdict.toUpperCase()}
                  </p>
                </div>
                <div className="p-4 bg-white/5 rounded-2xl border border-white/5">
                  <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                    AI Confidence
                  </span>
                  <p className="text-lg font-black text-white">
                    {(selectedLog.score * 100).toFixed(2)}%
                  </p>
                </div>
                <div className="p-4 bg-white/5 rounded-2xl border border-white/5">
                  <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                    Category
                  </span>
                  <p className="text-lg font-black text-cyber-blue">{selectedLog.category}</p>
                </div>
              </div>

              {/* AI Analysis Reasoning */}
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-gray-400">
                  <Terminal size={16} />
                  <span className="text-xs font-bold uppercase tracking-widest">
                    AI Analysis Reasoning
                  </span>
                </div>
                <div className="p-6 bg-black/40 rounded-2xl border border-white/5 font-mono text-sm leading-relaxed text-gray-300 shadow-inner">
                  <span className="text-cyber-red mr-2">➜</span>
                  {selectedLog.report_data?.reason ||
                    selectedLog.report_data?.details ||
                    'No explanation provided for this verdict.'}
                </div>
                {/* Shield Triggered Badge */}
                {selectedLog.score >= 0.85 && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-cyber-red/20 text-cyber-red text-[8px] font-black uppercase rounded border border-cyber-red/30 animate-pulse">
                      Shield Triggered: Expert Rule Override
                    </span>
                  </div>
                )}
              </div>

              {/* URL Scan Details */}
              {selectedLog.category === 'URL_SCAN' && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-gray-400">
                    <Globe size={16} />
                    <span className="text-xs font-bold uppercase tracking-widest">
                      Scraped Metadata
                    </span>
                  </div>
                  <div className="space-y-2 p-4 bg-white/5 rounded-2xl border border-white/5">
                    <div className="flex justify-between py-2 border-b border-white/5">
                      <span className="text-xs text-gray-500">Target URL</span>
                      <span className="text-xs text-gray-300 truncate max-w-[300px]">
                        {selectedLog.target}
                      </span>
                    </div>
                    <div className="flex justify-between py-2 border-b border-white/5">
                      <span className="text-xs text-gray-500">Page Title</span>
                      <span className="text-xs text-gray-300">
                        {selectedLog.report_data?.title || 'N/A'}
                      </span>
                    </div>
                    <div className="flex justify-between py-2">
                      <span className="text-xs text-gray-500">Timestamp</span>
                      <span className="text-xs text-gray-300">
                        {format(new Date(selectedLog.timestamp), 'PPpp')}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* OSINT / SERPER RESULTS */}
              {selectedLog.category === 'URL_SCAN' && selectedLog.report_data?.osint_data && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-gray-400">
                    <Search size={16} />
                    <span className="text-xs font-bold uppercase tracking-widest">Google OSINT (Serper)</span>
                  </div>
                  <div className="space-y-2">
                    {selectedLog.report_data.osint_data.length > 0 ? (
                      selectedLog.report_data.osint_data.map((item: any, i: number) => (
                        <div key={i} className="p-3 bg-white/5 rounded-xl border border-white/5">
                          <p className="text-[10px] text-cyber-blue font-bold truncate">{item.title}</p>
                          <p className="text-[9px] text-gray-500 mt-1 line-clamp-2">{item.snippet}</p>
                        </div>
                      ))
                    ) : (
                      <p className="text-xs text-gray-600 italic px-2">No negative digital footprint found.</p>
                    )}
                  </div>
                </div>
              )}

              {/* WEB SCRAPER RESULTS */}
              {selectedLog.category === 'URL_SCAN' && selectedLog.report_data?.scrape_data && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-gray-400">
                    <Globe size={16} />
                    <span className="text-xs font-bold uppercase tracking-widest">Scraper Findings</span>
                  </div>
                  <div className="p-4 bg-black/20 rounded-2xl border border-white/5 space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-gray-500 font-bold uppercase">Status</span>
                      <span className={`text-[10px] font-bold ${selectedLog.report_data?.scrape_data?.error ? 'text-cyber-red' : 'text-cyber-green'}`}>
                        {selectedLog.report_data?.scrape_data?.error ? 'OFFLINE / BLOCKED' : 'ONLINE'}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-gray-500 font-bold uppercase">Title</span>
                      <span className="text-[10px] text-gray-300 truncate max-w-[150px]">
                        {selectedLog.report_data?.scrape_data?.title || 'N/A'}
                      </span>
                    </div>
                    <div className="pt-2 border-t border-white/5">
                      <span className="text-[8px] text-gray-600 font-bold uppercase block mb-1">Content Snippet</span>
                      <p className="text-[10px] text-gray-500 line-clamp-3 leading-relaxed">
                        {selectedLog.report_data?.scrape_data?.text || 'No text content extracted.'}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Network Scan Feature Vector */}
              {selectedLog.category === 'NETWORK_TRAFFIC' && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-gray-400">
                    <Activity size={16} />
                    <span className="text-xs font-bold uppercase tracking-widest">
                      Feature Vector (20 Parameters)
                    </span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2 p-4 bg-white/5 rounded-2xl border border-white/5 max-h-64 overflow-y-auto">
                    {Object.entries(selectedLog.report_data?.raw_input || {}).map(
                      ([key, val]: any) => (
                        <div key={key} className="flex flex-col p-2 bg-black/40 rounded-lg">
                          <span className="text-[8px] text-gray-500 uppercase font-bold">
                            {key}
                          </span>
                          <span className="text-xs font-mono text-cyber-blue">{val}</span>
                        </div>
                      )
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/5 bg-white/[0.01] flex flex-col gap-4">
              <div className="flex gap-4">
                <button
                  onClick={() => handleFeedback(selectedLog.id, false, 'Safe')}
                  disabled={isFeedbacking}
                  className="flex-1 py-3 bg-cyber-yellow/10 hover:bg-cyber-yellow/20 text-cyber-yellow font-bold uppercase text-[10px] rounded-xl border border-cyber-yellow/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Mark as False Positive
                </button>

                <button
                  onClick={() => handleFeedback(selectedLog.id, true, selectedLog.verdict)}
                  disabled={isFeedbacking}
                  className="flex-1 py-3 bg-cyber-green/10 hover:bg-cyber-green/20 text-cyber-green font-bold uppercase text-[10px] rounded-xl border border-cyber-green/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Confirm AI Verdict
                </button>
              </div>

              <button
                onClick={() => setSelectedLog(null)}
                className="w-full py-4 bg-cyber-blue/10 hover:bg-cyber-blue/20 text-cyber-blue font-black uppercase tracking-widest text-xs rounded-2xl border border-cyber-blue/20 transition-all"
              >
                Acknowledge and Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
