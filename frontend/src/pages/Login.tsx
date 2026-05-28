import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Loader } from 'lucide-react';
import { toast } from 'sonner';

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (location.state?.message) {
      toast.success(location.state.message);
    }
  }, [location.state]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed. Please check your credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-6 bg-[url('/grid.svg')] bg-center">
      <div className="w-full max-w-md space-y-8 bg-dark-900/50 p-10 rounded-3xl border border-white/5 backdrop-blur-xl shadow-2xl">
        <div className="text-center">
          <div className="inline-flex p-4 rounded-2xl bg-cyber-blue/10 text-cyber-blue mb-4">
            <Shield size={40} />
          </div>
          <h1 className="text-3xl font-black text-white tracking-tighter uppercase">AICDS</h1>
          <p className="text-gray-500 text-xs font-bold uppercase tracking-widest mt-2">AI Cybersecurity Defense System</p>
          <p className="text-gray-600 text-xs font-bold uppercase tracking-widest">Secure Operator Portal</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-4">
            {/* Email Input */}
            <div className="relative group">
              <input
                type="email"
                placeholder="Work Email"
                required
                className="w-full bg-black/40 border border-white/10 p-4 rounded-xl text-white outline-none focus:border-cyber-blue/50 transition-all"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={isLoading}
              />
            </div>

            {/* Password Input */}
            <div className="relative group">
              <input
                type="password"
                placeholder="Secure Password"
                required
                className="w-full bg-black/40 border border-white/10 p-4 rounded-xl text-white outline-none focus:border-cyber-blue/50 transition-all"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isLoading}
              />
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-4 bg-cyber-red/10 border border-cyber-red/20 rounded-xl text-cyber-red text-xs font-bold uppercase text-center">
              {error}
            </div>
          )}

          {/* Login Button */}
          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-4 bg-cyber-blue text-black font-black uppercase tracking-widest text-xs rounded-xl hover:bg-blue-400 transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? <Loader className="animate-spin" size={18} /> : 'Sign In'}
          </button>
        </form>

        <p className="text-center text-gray-500 text-xs font-bold uppercase tracking-widest">
          New to AICDS? <a href="/register" className="text-cyber-blue hover:underline">Sign Up</a>
        </p>
      </div>
    </div>
  );
};

export default Login;
