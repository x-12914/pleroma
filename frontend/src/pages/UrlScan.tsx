import React, { useState } from 'react';
import { Globe, ShieldCheck, AlertTriangle, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { Card } from '../components/Card';
import { ErrorState } from '../components/LoadingState';
import { analysisService } from '../services/api';
import { getThreatInfo } from '../utils/threats';

/* ---------------------------------------------------------------
   URL scan — drops "URL INTELLIGENCE" / "Model: FraudLens" / shield
   bouncing animations. Single column on mobile, two columns on
   desktop with the form on the left and result on the right.
   --------------------------------------------------------------- */

type Verdict = 'malicious' | 'suspicious' | 'safe';

function classify(value: string | undefined): Verdict {
  if (!value) return 'safe';
  const lower = value.toLowerCase();
  if (lower.includes('malicious') || lower.includes('threat')) return 'malicious';
  if (lower.includes('suspicious')) return 'suspicious';
  return 'safe';
}

export default function UrlScan() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusText, setStatusText] = useState<string | null>(null);

  const timeout = (ms: number) => new Promise(r => setTimeout(r, ms));

  const pollStatus = async (taskId: string, attempt = 0): Promise<void> => {
    if (attempt >= 20) throw new Error('Analysis timed out.');
    const res = await analysisService.getTaskStatus(taskId);
    const { status, result: payload, error: serverError } = res.data;
    setStatusText(`Backend status: ${status}`);
    if (status === 'completed') {
      setResult(payload);
      const v = classify(payload?.verdict || payload?.prediction);
      if (v === 'malicious') toast.error('Malicious — review immediately.');
      else if (v === 'suspicious') toast.warning('Suspicious — review recommended.');
      else toast.success('Looks safe.');
      return;
    }
    if (status === 'failed') throw new Error(serverError || 'Analysis failed.');
    await timeout(1500);
    return pollStatus(taskId, attempt + 1);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) return;
    setError(null);
    setResult(null);
    setStatusText('Submitting');
    setLoading(true);
    try {
      const res = await analysisService.startUrlScan(trimmed);
      const taskId = res.data.task_id;
      await pollStatus(taskId);
    } catch (err: any) {
      setError(err?.message || 'Could not complete the scan. Check the URL and try again.');
    } finally {
      setLoading(false);
    }
  };

  const verdict = result ? classify(result.verdict || result.prediction) : null;
  const confidence = result ? Math.round(Math.max(0, Math.min(100, Number(result.confidence ?? 0) * 100))) : 0;
  const threat = result?.raw_class ? getThreatInfo(result.raw_class) : null;

  return (
    <main id="main" className="space-y-7">
      <div>
        <h1 className="text-display-md font-medium text-ink">URL scan</h1>
        <p className="mt-1 text-sm text-ink-subtle">
          Submit a URL for OSINT, page-scrape, and LLM-driven classification. Result usually within 15 seconds.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-5">
        {/* Form */}
        <Card title="Submit a URL" subtitle="The classifier checks OSINT mentions, scrapes the live page, and asks an LLM for a verdict." className="xl:col-span-3">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="url" className="block text-xs text-ink-muted mb-1.5">URL</label>
              <input
                id="url"
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/login"
                disabled={loading}
                required
                className="w-full px-3 py-2.5 bg-surface-base border border-surface-border rounded-soft text-sm text-ink placeholder:text-ink-dim transition-shadow focus:outline-none focus:border-accent-border focus:shadow-focus-ring font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="w-full inline-flex items-center justify-center gap-2 py-2.5 bg-accent hover:bg-accent-hi text-surface-base font-medium rounded-soft transition-colors duration-200 ease-crisp disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading && <Loader2 className="w-4 h-4 animate-spin" />}
              {loading ? 'Scanning' : 'Scan URL'}
            </button>
            {statusText && (
              <p className="text-2xs text-ink-dim tabular">{statusText}</p>
            )}
          </form>
        </Card>

        {/* Result */}
        <div className="xl:col-span-2 space-y-3">
          {error && <ErrorState message={error} />}

          {!error && !result && !loading && (
            <div className="bg-surface-card border border-dashed border-surface-border rounded-card p-10 text-center">
              <Globe className="w-8 h-8 mx-auto text-ink-dim mb-3" />
              <p className="text-sm text-ink-muted">Awaiting a URL</p>
              <p className="mt-1 text-xs text-ink-subtle">The verdict appears here.</p>
            </div>
          )}

          {!error && loading && !result && (
            <div className="bg-surface-card border border-surface-border rounded-card p-10 text-center">
              <Loader2 className="w-6 h-6 mx-auto text-accent animate-spin mb-3" />
              <p className="text-sm text-ink-muted">Analysing…</p>
              <p className="mt-1 text-xs text-ink-subtle">OSINT lookup, scrape, LLM call.</p>
            </div>
          )}

          {result && verdict && (
            <>
              <div
                className={`border rounded-card p-5 ${
                  verdict === 'malicious'
                    ? 'border-signal-danger-border/40 bg-signal-danger-bg'
                    : verdict === 'suspicious'
                    ? 'border-signal-warning-border/40 bg-signal-warning-bg'
                    : 'border-signal-ok-border/40 bg-signal-ok-bg'
                }`}
              >
                <div className="flex items-center gap-2 mb-3">
                  {verdict === 'malicious' ? (
                    <AlertTriangle className="w-4 h-4 text-signal-danger" />
                  ) : verdict === 'suspicious' ? (
                    <AlertTriangle className="w-4 h-4 text-signal-warning" />
                  ) : (
                    <ShieldCheck className="w-4 h-4 text-signal-ok" />
                  )}
                  <p className="text-2xs uppercase tracking-micro text-ink-dim">Verdict</p>
                </div>
                <h2
                  className={`text-display-sm font-medium ${
                    verdict === 'malicious'
                      ? 'text-signal-danger'
                      : verdict === 'suspicious'
                      ? 'text-signal-warning'
                      : 'text-signal-ok'
                  }`}
                >
                  {threat?.name ?? (verdict === 'malicious'
                    ? 'Malicious'
                    : verdict === 'suspicious'
                    ? 'Suspicious'
                    : 'Looks safe')}
                </h2>
                {threat?.description && (
                  <p className="mt-2 text-sm text-ink-muted leading-relaxed">{threat.description}</p>
                )}

                <div className="mt-5 space-y-1.5">
                  <div className="flex justify-between text-2xs uppercase tracking-micro text-ink-dim">
                    <span>Confidence</span>
                    <span className="tabular">{confidence}%</span>
                  </div>
                  <div className="h-1.5 bg-surface-border rounded-pill overflow-hidden">
                    <div
                      className={`h-full transition-all duration-700 ease-spring ${
                        verdict === 'malicious'
                          ? 'bg-signal-danger'
                          : verdict === 'suspicious'
                          ? 'bg-signal-warning'
                          : 'bg-signal-ok'
                      }`}
                      style={{ width: `${confidence}%` }}
                    />
                  </div>
                </div>
              </div>

              {result.reason && (
                <Card title="Analyst note" subtitle="LLM explanation of the verdict">
                  <p className="text-sm text-ink-muted leading-relaxed font-mono">
                    {result.reason}
                  </p>
                </Card>
              )}
            </>
          )}
        </div>
      </div>
    </main>
  );
}
