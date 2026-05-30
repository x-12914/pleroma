import { Link, useLocation } from "react-router-dom";
import { LayoutDashboard, AlertCircle, FileText, Globe, Menu, X, Loader2, Radio } from 'lucide-react';
import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { analysisService } from '../services/api';

export default function Sidebar() {
  const location = useLocation();
  const { user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [isRetraining, setIsRetraining] = useState(false);
  const [retrainProgress, setRetrainProgress] = useState(0);

  const menuItems = [
    { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/url-scan', icon: Globe, label: 'URL Scan' },
    { path: '/sensors', icon: Radio, label: 'Sensors' },
    { path: '/logs', icon: FileText, label: 'Logs' },
  ];

  const isActive = (path: string) => location.pathname === path;

  const handleRetrain = async () => {
    if (isRetraining) return;
    setIsRetraining(true);
    setRetrainProgress(8);

    const progressTimer = window.setInterval(() => {
      setRetrainProgress((current) => Math.min(92, current + 8));
    }, 400);

    try {
      await analysisService.retrainModel();
      setRetrainProgress(100);
    } catch (error) {
      console.error('Retrain request failed:', error);
    } finally {
      window.clearInterval(progressTimer);
      setTimeout(() => {
        setIsRetraining(false);
        setRetrainProgress(0);
      }, 1200);
    }
  };

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="lg:hidden fixed bottom-6 right-6 z-40 p-3 glass-card bg-cyber-blue/20 border-cyber-blue/50"
      >
        {isOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Sidebar */}
      <aside
        className={`fixed lg:static left-0 top-0 h-screen w-64 glass border-r border-dark-700 p-6 transform transition-transform duration-300 z-30 lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        } lg:z-0`}
      >
        {/* Logo section */}
        <div className="mb-12 hidden lg:block">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-gradient-to-br from-cyber-red to-cyber-purple rounded-lg flex items-center justify-center">
              <AlertCircle className="w-5 h-5 text-white" />
            </div>
            <span className="text-lg font-bold text-white">SOC</span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="space-y-2">
          {menuItems.map(({ path, icon: Icon, label }) => (
            <Link
              key={path}
              to={path}
              onClick={() => setIsOpen(false)}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                isActive(path)
                  ? 'bg-cyber-blue/20 border border-cyber-blue/50 text-cyber-blue'
                  : 'text-gray-400 hover:text-gray-300 hover:bg-dark-800 border border-transparent'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="font-medium">{label}</span>
              {isActive(path) && (
                <div className="ml-auto w-2 h-2 bg-cyber-blue rounded-full animate-pulse"></div>
              )}
            </Link>
          ))}
        </nav>

        {user?.is_admin && (
          <div className="mt-6 p-4 bg-dark-900 rounded-2xl border border-dark-700">
            <div className="flex items-center justify-between gap-3 mb-4">
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-widest">Admin</p>
                <p className="text-sm font-semibold text-white">Retrain RF Model</p>
              </div>
              <button
                type="button"
                onClick={handleRetrain}
                disabled={isRetraining}
                className="inline-flex items-center gap-2 px-3 py-2 text-[11px] font-semibold uppercase tracking-widest rounded-lg border border-cyber-blue/30 bg-cyber-blue/10 text-cyber-blue hover:bg-cyber-blue/20 disabled:opacity-50"
              >
                {isRetraining ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Retrain'}
              </button>
            </div>
            <div className="h-2 w-full rounded-full bg-dark-800 overflow-hidden border border-dark-700">
              <div
                className="h-full bg-cyber-blue transition-all duration-300"
                style={{ width: `${retrainProgress}%` }}
              />
            </div>
            <p className="mt-2 text-[11px] text-gray-400">
              {isRetraining ? 'Model retraining in progress...' : 'Run a fresh Random Forest build.'}
            </p>
          </div>
        )}

        {/* Footer info */}
        <div className="absolute bottom-6 left-6 right-6 p-4 bg-dark-800 rounded-lg border border-dark-700">
          <p className="text-xs text-gray-400 mb-2">Status</p>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"></div>
            <span className="text-sm text-cyber-green font-semibold">Online</span>
          </div>
        </div>
      </aside>

      {/* Mobile overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-20 lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}
    </>
  );
}
