import { useState, useEffect, type FormEvent } from 'react';
import { Plus, Copy, Trash2, Check, X, Radio } from 'lucide-react';
import { format } from 'date-fns';
import { toast } from 'sonner';
import { Card } from '../components/Card';
import { LoadingSpinner, EmptyState } from '../components/LoadingState';
import { sensorService } from '../services/api';

/* ---------------------------------------------------------------
   Sensors — register, list, revoke. Drops ALL CAPS, glass cards,
   centered modal. Key reveal is a focused slide-over on the right
   matching the Detections detail panel. Inline confirmation on
   revoke instead of window.confirm.
   --------------------------------------------------------------- */

interface Sensor {
  id: number;
  name: string;
  created_at: string;
  last_seen: string | null;
}

interface NewSensorResult extends Sensor {
  api_key: string;
}

export default function Sensors() {
  const [sensors, setSensors] = useState<Sensor[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [revealedKey, setRevealedKey] = useState<NewSensorResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [pendingRevoke, setPendingRevoke] = useState<number | null>(null);

  useEffect(() => {
    fetchSensors();
  }, []);

  async function fetchSensors() {
    try {
      const { data } = await sensorService.list();
      setSensors(data);
    } catch {
      toast.error('Could not load sensors.');
    } finally {
      setLoading(false);
    }
  }

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    const name = newName.trim();
    if (!name) return;
    setCreating(true);
    try {
      const { data } = await sensorService.create(name);
      setRevealedKey(data);
      setNewName('');
      await fetchSensors();
    } catch (err: any) {
      toast.error(err?.response?.data?.detail ?? 'Could not create sensor.');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (sensor: Sensor) => {
    try {
      await sensorService.remove(sensor.id);
      toast.success(`${sensor.name} revoked.`);
      await fetchSensors();
    } catch {
      toast.error('Could not revoke sensor.');
    } finally {
      setPendingRevoke(null);
    }
  };

  const copyKey = async (key: string) => {
    try {
      await navigator.clipboard.writeText(key);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      toast.error('Clipboard blocked — copy the key manually.');
    }
  };

  return (
    <main id="main" className="space-y-7">
      {/* Header */}
      <div>
        <h1 className="text-display-md font-medium text-ink">Sensors</h1>
        <p className="mt-1 text-sm text-ink-subtle">
          Registered agents shipping flow records to the ingest endpoint.
        </p>
      </div>

      {/* Register form */}
      <Card title="Register a sensor" subtitle="Each registration mints one API key, shown once.">
        <form onSubmit={handleCreate} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="e.g. home-laptop, office-pi"
            disabled={creating}
            maxLength={64}
            className="flex-1 px-3 py-2.5 bg-surface-base border border-surface-border rounded-soft text-sm text-ink placeholder:text-ink-dim transition-shadow focus:outline-none focus:border-accent-border focus:shadow-focus-ring"
          />
          <button
            type="submit"
            disabled={creating || !newName.trim()}
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-accent hover:bg-accent-hi text-surface-base font-medium rounded-soft text-sm transition-colors duration-200 ease-crisp disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Plus className="w-4 h-4" />
            {creating ? 'Registering' : 'Register'}
          </button>
        </form>
        <p className="mt-3 text-xs text-ink-subtle">
          The key is hashed before storage — losing it means deleting the sensor and creating a new one.
        </p>
      </Card>

      {/* Sensor list */}
      <Card title="Active sensors">
        {loading ? (
          <LoadingSpinner />
        ) : sensors.length === 0 ? (
          <EmptyState
            title="No sensors yet"
            description="Register one above to start ingesting flow records."
          />
        ) : (
          <table className="w-full text-left -mx-1">
            <thead>
              <tr className="text-2xs uppercase tracking-micro text-ink-dim">
                <th className="px-2 py-2 font-normal">Name</th>
                <th className="px-2 py-2 font-normal">Created</th>
                <th className="px-2 py-2 font-normal">Last seen</th>
                <th className="px-2 py-2 font-normal w-32 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {sensors.map((s) => (
                <tr key={s.id} className="hover:bg-surface-hover/30 transition-colors duration-150 ease-crisp">
                  <td className="px-2 py-3 text-sm text-ink font-medium">{s.name}</td>
                  <td className="px-2 py-3 text-xs text-ink-subtle tabular font-mono">
                    {format(new Date(s.created_at), 'MMM dd, HH:mm')}
                  </td>
                  <td className="px-2 py-3 text-xs tabular font-mono">
                    {s.last_seen ? (
                      <span className="text-signal-ok">
                        {format(new Date(s.last_seen), 'MMM dd, HH:mm:ss')}
                      </span>
                    ) : (
                      <span className="text-ink-dim italic">never</span>
                    )}
                  </td>
                  <td className="px-2 py-3 text-right">
                    {pendingRevoke === s.id ? (
                      <span className="inline-flex items-center gap-1.5 text-2xs">
                        <button
                          onClick={() => setPendingRevoke(null)}
                          className="text-ink-muted hover:text-ink px-2 py-1 rounded-soft"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={() => handleDelete(s)}
                          className="text-signal-danger bg-signal-danger-bg hover:brightness-110 border border-signal-danger-border/40 px-2.5 py-1 rounded-soft font-medium"
                        >
                          Confirm revoke
                        </button>
                      </span>
                    ) : (
                      <button
                        onClick={() => setPendingRevoke(s.id)}
                        title="Revoke sensor"
                        className="p-1.5 rounded-soft text-ink-subtle hover:text-signal-danger hover:bg-signal-danger-bg transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* Key reveal — slide-over panel */}
      {revealedKey && (
        <div className="fixed inset-0 z-50 flex" role="dialog" aria-modal="true">
          <button
            type="button"
            className="flex-1 bg-surface-base/70 backdrop-blur-sm scrim-enter"
            onClick={() => { setRevealedKey(null); setCopied(false); }}
            aria-label="Close"
          />
          <aside className="relative w-full sm:max-w-[480px] h-dvh bg-surface-base border-l border-surface-border flex flex-col panel-enter shadow-lift">
            <header className="flex items-center justify-between gap-4 px-6 h-14 border-b border-surface-border">
              <div className="flex items-center gap-3">
                <Radio className="w-4 h-4 text-accent" />
                <span className="text-sm text-ink font-medium">Sensor registered</span>
              </div>
              <button
                onClick={() => { setRevealedKey(null); setCopied(false); }}
                aria-label="Close"
                className="p-1.5 rounded-soft text-ink-subtle hover:text-ink hover:bg-surface-card transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </header>

            <div className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
              <div className="border border-signal-warning-border/40 bg-signal-warning-bg rounded-card p-5">
                <p className="text-2xs uppercase tracking-micro text-ink-dim mb-2">
                  Copy now or lose forever
                </p>
                <h2 className="text-base text-signal-warning font-medium mb-2">
                  The key is shown once.
                </h2>
                <p className="text-sm text-ink-muted leading-relaxed">
                  Store it on the sensor host (e.g.{' '}
                  <code className="px-1.5 py-0.5 rounded-soft bg-surface-card text-accent text-2xs font-mono">/etc/pleroma-sensor/key</code>)
                  and send as the{' '}
                  <code className="px-1.5 py-0.5 rounded-soft bg-surface-card text-accent text-2xs font-mono">X-Sensor-Key</code>{' '}
                  header on every{' '}
                  <code className="px-1.5 py-0.5 rounded-soft bg-surface-card text-accent text-2xs font-mono">POST /api/v1/ingest/flow</code>.
                </p>
              </div>

              <div>
                <p className="text-2xs uppercase tracking-micro text-ink-dim mb-2">API key</p>
                <div className="bg-surface-card border border-surface-border rounded-card p-3 flex items-center gap-3">
                  <code className="font-mono text-xs text-accent break-all flex-1">
                    {revealedKey.api_key}
                  </code>
                  <button
                    onClick={() => copyKey(revealedKey.api_key)}
                    className={`shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-soft text-xs font-medium transition-colors ${
                      copied
                        ? 'bg-signal-ok-bg text-signal-ok border border-signal-ok-border/40'
                        : 'bg-accent-quiet text-accent border border-accent-border/50 hover:bg-accent-subtle'
                    }`}
                  >
                    {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              <div>
                <p className="text-2xs uppercase tracking-micro text-ink-dim mb-2">Sensor name</p>
                <p className="text-sm text-ink font-medium">{revealedKey.name}</p>
              </div>
            </div>

            <footer className="px-6 py-4 border-t border-surface-border">
              <button
                onClick={() => { setRevealedKey(null); setCopied(false); }}
                className="w-full py-2.5 bg-surface-card hover:bg-surface-hover/50 border border-surface-border text-ink rounded-soft text-sm font-medium transition-colors"
              >
                I've stored it safely
              </button>
            </footer>
          </aside>
        </div>
      )}
    </main>
  );
}
