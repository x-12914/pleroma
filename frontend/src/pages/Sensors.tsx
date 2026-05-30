import { useState, useEffect, type FormEvent } from 'react';
import { Plus, Copy, Trash2, Radio, Check, AlertCircle } from 'lucide-react';
import { format } from 'date-fns';
import { toast } from 'sonner';
import { SimpleCard } from '../components/Card';
import { LoadingSpinner } from '../components/LoadingState';
import { sensorService } from '../services/api';

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

  useEffect(() => {
    fetchSensors();
  }, []);

  const fetchSensors = async () => {
    try {
      const { data } = await sensorService.list();
      setSensors(data);
    } catch {
      toast.error('Failed to load sensors.');
    } finally {
      setLoading(false);
    }
  };

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
      toast.error(err?.response?.data?.detail ?? 'Failed to create sensor.');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (sensor: Sensor) => {
    if (!window.confirm(`Revoke sensor "${sensor.name}"? It will lose access immediately and cannot be undone.`)) {
      return;
    }
    try {
      await sensorService.remove(sensor.id);
      toast.success(`Revoked ${sensor.name}.`);
      await fetchSensors();
    } catch {
      toast.error('Failed to revoke sensor.');
    }
  };

  const copyKey = async (key: string) => {
    try {
      await navigator.clipboard.writeText(key);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      toast.error('Clipboard access denied — copy the key manually.');
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl md:text-4xl font-black text-white tracking-tighter uppercase flex items-center gap-3">
            <Radio className="w-8 h-8 text-cyber-blue" />
            Sensors
          </h1>
          <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mt-1">
            Registered flow producers
          </p>
        </div>
      </div>

      {/* Create form */}
      <SimpleCard title="Register a new sensor">
        <form onSubmit={handleCreate} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="e.g. home-laptop, office-pi, gateway-vps"
            disabled={creating}
            maxLength={64}
            className="flex-1 bg-dark-900 border border-white/10 rounded-xl px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue/40"
          />
          <button
            type="submit"
            disabled={creating || !newName.trim()}
            className="px-6 py-3 bg-cyber-blue/20 hover:bg-cyber-blue/30 border border-cyber-blue/50 text-cyber-blue font-bold rounded-xl transition-all uppercase tracking-widest text-xs flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Plus size={16} />
            {creating ? 'Creating...' : 'Register'}
          </button>
        </form>
        <p className="mt-3 text-[11px] text-gray-500">
          A new API key is generated server-side and shown <span className="text-cyber-yellow font-bold">once</span>. Copy it immediately — it cannot be recovered later.
        </p>
      </SimpleCard>

      {/* Sensor list */}
      <SimpleCard title="Registered sensors">
        {loading ? (
          <div className="py-12 flex justify-center"><LoadingSpinner /></div>
        ) : sensors.length === 0 ? (
          <div className="py-16 text-center text-gray-500">
            <Radio className="w-12 h-12 mx-auto mb-4 opacity-30" />
            <p className="text-sm font-bold uppercase tracking-widest">No sensors yet</p>
            <p className="text-xs mt-2 text-gray-600">Register one above to start ingesting flows.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-white/5 text-[10px] uppercase tracking-widest font-black text-gray-400">
                  <th className="p-4">Name</th>
                  <th className="p-4">Created</th>
                  <th className="p-4">Last seen</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="text-sm">
                {sensors.map((s) => (
                  <tr key={s.id} className="border-t border-white/5 hover:bg-white/[0.02] transition-colors">
                    <td className="p-4 font-medium text-white">{s.name}</td>
                    <td className="p-4 font-mono text-xs text-gray-500">
                      {format(new Date(s.created_at), 'MMM dd, HH:mm')}
                    </td>
                    <td className="p-4 font-mono text-xs">
                      {s.last_seen ? (
                        <span className="text-cyber-green">
                          {format(new Date(s.last_seen), 'MMM dd, HH:mm:ss')}
                        </span>
                      ) : (
                        <span className="text-gray-600 italic">never</span>
                      )}
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => handleDelete(s)}
                        className="p-2 text-gray-500 hover:text-cyber-red hover:bg-cyber-red/10 rounded-lg transition-colors"
                        title="Revoke sensor"
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SimpleCard>

      {/* Key reveal modal — blocking on purpose */}
      {revealedKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-md">
          <div className="bg-dark-900 border border-cyber-yellow/30 w-full max-w-2xl rounded-3xl p-8 space-y-6 animate-in zoom-in duration-200">
            <div className="flex items-center gap-3">
              <AlertCircle className="w-8 h-8 text-cyber-yellow shrink-0" />
              <h2 className="text-xl font-black text-white tracking-tighter uppercase">
                Copy the sensor key now
              </h2>
            </div>

            <p className="text-sm text-gray-400 leading-relaxed">
              This is the <span className="text-cyber-yellow font-bold">only</span> time this key
              will be shown. Store it securely on the sensor host (e.g.{' '}
              <code className="bg-black/40 px-1.5 py-0.5 rounded text-cyber-blue text-xs">/etc/pleroma-sensor/key</code>)
              and send it as the{' '}
              <code className="bg-black/40 px-1.5 py-0.5 rounded text-cyber-blue text-xs">X-Sensor-Key</code> header
              on every{' '}
              <code className="bg-black/40 px-1.5 py-0.5 rounded text-cyber-blue text-xs">POST /api/v1/ingest/flow</code> request.
              If you lose it, delete this sensor and register a new one.
            </p>

            <div className="bg-black/60 border border-cyber-blue/30 rounded-xl p-4 flex items-center justify-between gap-3">
              <code className="font-mono text-xs text-cyber-blue break-all flex-1">
                {revealedKey.api_key}
              </code>
              <button
                onClick={() => copyKey(revealedKey.api_key)}
                className={`shrink-0 px-3 py-2 rounded-lg flex items-center gap-2 text-xs font-bold uppercase tracking-widest transition-colors ${
                  copied
                    ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/40'
                    : 'bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/40 hover:bg-cyber-blue/30'
                }`}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>

            <button
              onClick={() => { setRevealedKey(null); setCopied(false); }}
              className="w-full py-4 bg-white/5 hover:bg-white/10 border border-white/10 text-gray-300 rounded-2xl uppercase text-xs font-bold tracking-widest transition-colors"
            >
              I've stored it safely
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
