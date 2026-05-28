import { useState, useEffect } from 'react';
import { Activity, AlertTriangle, LogOut } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { checkSystemHealth } from '../services/api';

export default function Navbar() {
  const [time, setTime] = useState(new Date().toLocaleTimeString());
  const [isOnline, setIsOnline] = useState<boolean>(false);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toLocaleTimeString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const checkConnection = async () => {
      try {
        const response = await checkSystemHealth();
        if (response.status === 200) {
          setIsOnline(true);
        } else {
          setIsOnline(false);
        }
      } catch {
        setIsOnline(false);
      }
    };
    checkConnection();
    const interval = setInterval(checkConnection, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="glass-card rounded-none border-b border-dark-700 sticky top-0 z-50">
      <div className="flex items-center justify-between px-4 md:px-8 py-3">
        <div className="flex items-center gap-3">
          <div className="relative flex-shrink-0">
            <AlertTriangle className="w-6 h-6 md:w-8 md:h-8 text-cyber-red animate-pulse" />
            <span className="absolute top-0 right-0 w-2 h-2 bg-cyber-red rounded-full animate-pulse"></span>
          </div>
          <div className="hidden sm:block">
            <h1 className="text-xl md:text-2xl font-bold text-white">AICDS</h1>
            <p className="text-[10px] md:text-xs text-gray-400">Security Operations Center</p>
          </div>
        </div>

        <div className="flex items-center gap-3 md:gap-6">
          <div className="hidden lg:flex items-center gap-2 text-sm">
            <Activity className={`w-4 h-4 ${isOnline ? 'text-cyber-green' : 'text-red-400'}`} />
            <span className="text-gray-300">Status</span>
            <span className={`${isOnline ? 'text-cyber-green' : 'text-red-400'} font-semibold`}>
              {isOnline ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
          <div className="text-xs md:text-sm text-gray-400 font-mono">{time}</div>

          {/* User info */}
          {user && (
            <div className="hidden md:block text-sm text-gray-300">
              {user.email}
            </div>
          )}

          {/* Logout Button */}
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-200 rounded-lg transition-colors text-sm font-medium border border-red-500/50"
          >
            <LogOut className="w-4 h-4" />
            <span className="hidden sm:inline">Logout</span>
          </button>
        </div>
      </div>

      {/* Status bar - hidden on very small screens, scrollable on others */}
      <div className="border-t border-dark-700 px-4 md:px-8 py-2 flex gap-4 md:gap-6 text-[10px] md:text-xs overflow-x-auto no-scrollbar whitespace-nowrap">
        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"></div>
          <span className="text-gray-400">Active Monitoring</span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"></div>
          <span className="text-gray-400">All Systems Operational</span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="w-2 h-2 bg-cyber-yellow rounded-full animate-pulse"></div>
          <span className="text-gray-400">3 Recent Alerts</span>
        </div>
      </div>
    </nav>
  );
}
