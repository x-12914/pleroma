import React, { useState } from 'react';

export interface DetectionInput {
  // Basic Features
  duration: number;
  protocol_type: string;
  service: string;
  flag: string;
  src_bytes: number;
  dst_bytes: number;

  // Traffic Features (Critical for detecting Floods/DDoS)
  count: number;
  srv_count: number;
  serror_rate: number;
  rerror_rate: number;
  same_srv_rate: number;
  diff_srv_rate: number;

  // Host-based Features (Critical for detecting Probes/Scans)
  dst_host_count: number;
  dst_host_srv_count: number;
  dst_host_same_srv_rate: number;
  dst_host_serror_rate: number;

  // Additional ports for better detection
  dst_port?: number;
}

const initialData: DetectionInput = {
  // Basic
  duration: 0,
  protocol_type: 'tcp',
  service: 'http',
  flag: 'SF',
  src_bytes: 0,
  dst_bytes: 0,

  // Traffic (Critical for Floods/DDoS)
  count: 1,
  srv_count: 1,
  serror_rate: 0,
  rerror_rate: 0,
  same_srv_rate: 1,
  diff_srv_rate: 0,

  // Host-based (Critical for Probes/Scans)
  dst_host_count: 1,
  dst_host_srv_count: 1,
  dst_host_same_srv_rate: 1,
  dst_host_serror_rate: 0,
};

interface Props {
  onSubmit: (data: DetectionInput) => void;
  loading?: boolean;
}

const DetectionForm: React.FC<Props> = ({ onSubmit, loading = false }) => {
  const [formData, setFormData] = useState<DetectionInput>(initialData);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'number' ? parseFloat(value) || 0 : value,
    }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Basic Connection Features */}
      <div className="space-y-4">
        <h3 className="text-sm font-bold text-cyber-blue uppercase tracking-widest">Basic Connection</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label htmlFor="duration" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Duration (ms)
            </label>
            <input
              id="duration"
              name="duration"
              type="number"
              value={formData.duration}
              onChange={handleChange}
              disabled={loading}
              className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="protocol_type" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Protocol
            </label>
            <select
              id="protocol_type"
              name="protocol_type"
              value={formData.protocol_type}
              onChange={handleChange}
              disabled={loading}
              className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>

          <div className="space-y-2">
            <label htmlFor="service" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Service
            </label>
            <input
              id="service"
              name="service"
              type="text"
              value={formData.service}
              onChange={handleChange}
              disabled={loading}
              className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="flag" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Flag
            </label>
            <select
              id="flag"
              name="flag"
              value={formData.flag}
              onChange={handleChange}
              disabled={loading}
              className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
            >
              <option value="SF">SF (Normal)</option>
              <option value="S0">S0 (SYN Flood)</option>
              <option value="REJ">REJ (Rejected)</option>
              <option value="RSTO">RSTO (Reset)</option>
              <option value="RSTR">RSTR (Reset)</option>
            </select>
          </div>

          <div className="space-y-2">
            <label htmlFor="src_bytes" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Source Bytes
            </label>
            <input
              id="src_bytes"
              name="src_bytes"
              type="number"
              value={formData.src_bytes}
              onChange={handleChange}
              disabled={loading}
              className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="dst_bytes" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Destination Bytes
            </label>
            <input
              id="dst_bytes"
              name="dst_bytes"
              type="number"
              value={formData.dst_bytes}
              onChange={handleChange}
              disabled={loading}
              className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
            />
          </div>
        </div>
      </div>

      {/* Advanced Traffic Features */}
      <div className="space-y-4">
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-2 text-sm font-semibold text-cyber-blue hover:text-cyber-blue/80 transition-colors"
        >
          <span className={`transform transition-transform ${showAdvanced ? 'rotate-90' : ''}`}>▶</span>
          Advanced Network Metrics
        </button>

        {showAdvanced && (
          <div className="space-y-4 p-4 bg-dark-800/50 rounded-lg border border-dark-700">
            {/* Traffic Statistics */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Traffic Statistics</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label htmlFor="count" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Connection Count
                  </label>
                  <input
                    id="count"
                    name="count"
                    type="number"
                    value={formData.count}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="srv_count" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Service Count
                  </label>
                  <input
                    id="srv_count"
                    name="srv_count"
                    type="number"
                    value={formData.srv_count}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="serror_rate" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    SYN Error Rate (0-1)
                  </label>
                  <input
                    id="serror_rate"
                    name="serror_rate"
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    value={formData.serror_rate}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="rerror_rate" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    RST Error Rate (0-1)
                  </label>
                  <input
                    id="rerror_rate"
                    name="rerror_rate"
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    value={formData.rerror_rate}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="same_srv_rate" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Same Service Rate (0-1)
                  </label>
                  <input
                    id="same_srv_rate"
                    name="same_srv_rate"
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    value={formData.same_srv_rate}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="diff_srv_rate" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Different Service Rate (0-1)
                  </label>
                  <input
                    id="diff_srv_rate"
                    name="diff_srv_rate"
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    value={formData.diff_srv_rate}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>
              </div>
            </div>

            {/* Host-based Statistics */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Host-based Statistics</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label htmlFor="dst_host_count" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Destination Host Count
                  </label>
                  <input
                    id="dst_host_count"
                    name="dst_host_count"
                    type="number"
                    value={formData.dst_host_count}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="dst_host_srv_count" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Host Service Count
                  </label>
                  <input
                    id="dst_host_srv_count"
                    name="dst_host_srv_count"
                    type="number"
                    value={formData.dst_host_srv_count}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="dst_host_same_srv_rate" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Host Same Service Rate (0-1)
                  </label>
                  <input
                    id="dst_host_same_srv_rate"
                    name="dst_host_same_srv_rate"
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    value={formData.dst_host_same_srv_rate}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="dst_host_serror_rate" className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Host SYN Error Rate (0-1)
                  </label>
                  <input
                    id="dst_host_serror_rate"
                    name="dst_host_serror_rate"
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    value={formData.dst_host_serror_rate}
                    onChange={handleChange}
                    disabled={loading}
                    className="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-cyber-blue/50"
                  />
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full py-4 bg-cyber-blue/20 hover:bg-cyber-blue/30 border border-cyber-blue/50 text-cyber-blue font-bold rounded-xl transition-all uppercase tracking-widest disabled:opacity-50"
      >
        {loading ? 'Processing Network Vector...' : '🚀 Run Network Threat Detection'}
      </button>
    </form>
  );
};

export default DetectionForm;
