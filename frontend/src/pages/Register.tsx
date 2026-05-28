import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldCheck, Mail, Lock, ArrowRight, Loader2 } from 'lucide-react';
import { authService } from '../services/api';

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await authService.register({ email, password });
      // Redirect to login after successful registration
      navigate('/login', { state: { message: 'Registration successful! Please login.' } });
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Registration failed. Try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-6 bg-[url('/grid.svg')] bg-center">
      <div className="w-full max-w-md space-y-8 bg-dark-900/50 p-10 rounded-3xl border border-white/5 backdrop-blur-xl shadow-2xl">
        <div className="text-center">
          <div className="inline-flex p-4 rounded-2xl bg-cyber-blue/10 text-cyber-blue mb-4">
            <ShieldCheck size={40} />
          </div>
          <h1 className="text-3xl font-black text-white tracking-tighter uppercase">Join AICDS</h1>
          <p className="text-gray-500 text-xs font-bold uppercase tracking-widest mt-2">Create your SOC Analyst account</p>
        </div>

        <form onSubmit={handleRegister} className="space-y-6">
          <div className="space-y-4">
            <div className="relative group">
              <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-cyber-blue transition-colors" size={18} />
              <input
                type="email"
                placeholder="Work Email"
                required
                className="w-full bg-black/40 border border-white/10 p-4 pl-12 rounded-xl text-white outline-none focus:border-cyber-blue/50 transition-all"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div className="relative group">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-cyber-blue transition-colors" size={18} />
              <input
                type="password"
                placeholder="Secure Password"
                required
                className="w-full bg-black/40 border border-white/10 p-4 pl-12 rounded-xl text-white outline-none focus:border-cyber-blue/50 transition-all"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          {error && (
            <div className="p-4 bg-cyber-red/10 border border-cyber-red/20 rounded-xl text-cyber-red text-xs font-bold uppercase text-center">
              {error}
            </div>
          )}

          <button
            disabled={loading}
            className="w-full py-4 bg-cyber-blue text-black font-black uppercase tracking-widest text-xs rounded-xl hover:bg-blue-400 transition-all flex items-center justify-center gap-2"
          >
            {loading ? <Loader2 className="animate-spin" size={18} /> : (
              <>Create Account <ArrowRight size={18} /></>
            )}
          </button>
        </form>

        <p className="text-center text-gray-500 text-xs font-bold uppercase tracking-widest">
          Already have access? <Link to="/login" className="text-cyber-blue hover:underline">Sign In</Link>
        </p>
      </div>
    </div>
  );
}