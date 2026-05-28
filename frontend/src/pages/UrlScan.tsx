import React, { useState } from 'react';
import { Globe, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import { SimpleCard } from '../components/Card';
import { LoadingSpinner, ErrorState } from '../components/LoadingState';
import { analysisService } from '../services/api';

export default function UrlScan() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysisStatus, setAnalysisStatus] = useState<string | null>(null);

  const timeout = (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms));

  const normalizeVerdict = (value: string | undefined) => {
    if (!value) return 'clean';
    const lower = value.toLowerCase();
    if (lower.includes('malicious') || lower.includes('threat')) return 'malicious';
    if (lower.includes('suspicious')) return 'suspicious';
    return 'clean';
  };

  const mapResult = (payload: any) => {
    setResult(payload);

    const verdict = String(payload?.verdict || payload?.prediction || '').toLowerCase();
    if (verdict.includes('malicious') || verdict.includes('threat')) {
      toast.error('Malicious URL detected. Block immediately.');
    } else {
      toast.success('URL scan complete.');
    }
  };

  const pollStatus = async (taskId: string, attempt = 0): Promise<void> => {
    if (attempt >= 20) {
      throw new Error('Analysis timed out. Please try again later.');
    }

    const statusResponse = await analysisService.getTaskStatus(taskId);
    const { status, result: payload, error: statusError } = statusResponse.data;

    setAnalysisStatus(`Analysis status: ${status}`);

    if (status === 'completed') {
      mapResult(payload);
      return;
    }

    if (status === 'failed') {
      throw new Error(statusError || 'Analysis failed on the server.');
    }

    await timeout(1500);
    return pollStatus(taskId, attempt + 1);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setAnalysisStatus('Submitting URL for inspection...');
    setLoading(true);

    try {
      const res = await analysisService.startUrlScan(url.trim());
      toast('Task started. URL inspection is underway.');
      const taskId = res.data.task_id;
      await pollStatus(taskId);
      setLoading(false);
    } catch (err) {
      setLoading(false);
      toast.error('Unable to complete the URL scan.');
      setError('Unable to complete the URL scan. Please verify the URL and try again.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-4xl font-black text-white mb-2 tracking-tighter flex items-center gap-3">
            <Globe className="w-10 h-10 text-cyber-blue" />
            URL INTELLIGENCE
          </h1>
          <p className="text-gray-400 font-medium">Inspect suspicious URLs with AI-driven threat classification.</p>
        </div>
        <div className="bg-dark-800 px-4 py-2 rounded-lg border border-dark-700 flex items-center gap-3">
          <div className="w-3 h-3 bg-cyber-green rounded-full animate-pulse"></div>
          <span className="text-xs font-bold text-gray-300 uppercase tracking-widest">Model: FraudLens</span>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 space-y-6">
          <SimpleCard title="URL Threat Inspection">
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <label htmlFor="url" className="text-sm font-semibold text-gray-300">Enter URL to scan</label>
                <input
                  id="url"
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com/login"
                  disabled={loading}
                  className="w-full bg-dark-900 border border-dark-700 rounded-xl px-4 py-3 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-cyber-blue/40"
                />
              </div>

              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="w-full py-4 bg-cyber-blue/20 hover:bg-cyber-blue/30 border border-cyber-blue/50 text-cyber-blue font-bold rounded-xl transition-all uppercase tracking-widest disabled:opacity-50"
              >
                {loading ? 'Scanning URL...' : 'Scan URL'}
              </button>
            </form>
          </SimpleCard>
        </div>

        <div className="space-y-6">
          <SimpleCard title="Scan Status">
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 bg-dark-900 rounded-lg border border-dark-700">
                <span className="text-xs text-gray-400 uppercase font-bold">State</span>
                <span className="text-xs font-mono text-cyber-blue">{analysisStatus || 'Idle'}</span>
              </div>
              <div className="flex items-center justify-between p-3 bg-dark-900 rounded-lg border border-dark-700">
                <span className="text-xs text-gray-400 uppercase font-bold">Engine</span>
                <span className="text-xs font-mono text-cyber-green">ThreatLens</span>
              </div>
            </div>
          </SimpleCard>

          {error && <ErrorState message={error} onRetry={() => {}} />}

          {result && (
            <div className={`p-6 rounded-2xl border-2 transition-all duration-500 animate-in fade-in slide-in-from-bottom-4 ${
              normalizeVerdict(result.verdict) === 'malicious'
                ? 'bg-cyber-red/10 border-cyber-red/40 shadow-[0_0_30px_rgba(239,68,68,0.2)]'
                : normalizeVerdict(result.verdict) === 'suspicious'
                ? 'bg-cyber-yellow/10 border-cyber-yellow/40 shadow-[0_0_30px_rgba(234,179,8,0.2)]'
                : 'bg-cyber-green/10 border-cyber-green/40 shadow-[0_0_30px_rgba(34,197,94,0.2)]'
            }`}>
              <div className="flex flex-col items-center text-center space-y-4">
                {normalizeVerdict(result.verdict) === 'malicious' ? (
                  <ShieldAlert className="w-16 h-16 text-cyber-red animate-bounce" />
                ) : normalizeVerdict(result.verdict) === 'suspicious' ? (
                  <AlertTriangle className="w-16 h-16 text-cyber-yellow animate-pulse" />
                ) : (
                  <ShieldCheck className="w-16 h-16 text-cyber-green" />
                )}

                <div>
                  <h3 className={`text-2xl font-black uppercase tracking-tighter ${
                    normalizeVerdict(result.verdict) === 'malicious'
                      ? 'text-cyber-red'
                      : normalizeVerdict(result.verdict) === 'suspicious'
                      ? 'text-cyber-yellow'
                      : 'text-cyber-green'
                  }`}>
                    {normalizeVerdict(result.verdict) === 'malicious'
                      ? 'Malicious URL'
                      : normalizeVerdict(result.verdict) === 'suspicious'
                      ? 'Suspicious URL'
                      : 'URL Safe'}
                  </h3>
                  <p className="text-gray-400 text-sm mt-1">Detailed verdict from the AI URL intelligence engine.</p>
                </div>

                <div className="w-full bg-dark-900 rounded-full h-4 overflow-hidden border border-dark-700">
                  <div
                    className={`h-full transition-all duration-1000 ${
                      normalizeVerdict(result.verdict) === 'malicious'
                        ? 'bg-cyber-red'
                        : normalizeVerdict(result.verdict) === 'suspicious'
                        ? 'bg-cyber-yellow'
                        : 'bg-cyber-green'
                    }`}
                    style={{ width: `${Math.min(100, Math.max(0, Number(result.confidence ?? 0) * 100))}%` }}
                  />
                </div>
                <div className="flex justify-between w-full text-[10px] font-bold uppercase tracking-widest text-gray-500">
                  <span>Confidence</span>
                  <span>{Math.min(100, Math.max(0, Number(result.confidence ?? 0) * 100)).toFixed(1)}%</span>
                </div>
              </div>
            </div>
          )}

          {result?.reason && (
            <div className="mt-6 w-full animate-in fade-in zoom-in duration-500">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-2 h-2 bg-cyber-red rounded-full animate-ping"></div>
                <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">AI Reasoning</span>
              </div>
              <div className="bg-black/50 border border-white/5 rounded-xl p-4 font-mono text-xs text-cyber-blue/90 leading-relaxed shadow-inner">
                <span className="text-cyber-red mr-2">➜</span>
                {result.reason}
              </div>
            </div>
          )}

          {!result && !loading && !error && (
            <div className="p-12 border-2 border-dashed border-dark-700 rounded-2xl flex flex-col items-center justify-center text-center opacity-40">
              <AlertTriangle className="w-12 h-12 text-gray-500 mb-4" />
              <p className="text-sm font-bold text-gray-500 uppercase tracking-widest">Awaiting URL input</p>
            </div>
          )}

          {loading && (
            <div className="p-12 bg-dark-800/50 border border-dark-700 rounded-2xl flex flex-col items-center justify-center text-center">
              <LoadingSpinner />
              <p className="text-sm font-bold text-cyber-blue mt-4 uppercase animate-pulse tracking-widest">Scanning URL...</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
