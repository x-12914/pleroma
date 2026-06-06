import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, FileText, Globe, Radio, Menu, X, Loader2 } from 'lucide-react';
import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { analysisService } from '../services/api';

/* ---------------------------------------------------------------
   Sidebar — sentence case labels, refined surfaces, no pulsing
   indicators. The "SOC" logo block + "Status: Online" pip are gone
   (Navbar handles status). Admin retrain block is restrained.
   --------------------------------------------------------------- */

const menu = [
  { path: '/',         icon: LayoutDashboard, label: 'Overview' },
  { path: '/url-scan', icon: Globe,           label: 'URL scan' },
  { path: '/sensors',  icon: Radio,           label: 'Sensors' },
  { path: '/logs',     icon: FileText,        label: 'Detections' },
];

export default function Sidebar() {
  const location = useLocation();
  const { user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [isRetraining, setIsRetraining] = useState(false);

  const isActive = (path: string) =>
    path === '/' ? location.pathname === '/' : location.pathname.startsWith(path);

  const handleRetrain = async () => {
    if (isRetraining) return;
    if (!window.confirm('Trigger model retraining? This runs in the background and may take several minutes.')) return;
    setIsRetraining(true);
    try {
      await analysisService.retrainModel();
    } catch (err) {
      console.error('Retrain failed:', err);
    } finally {
      setTimeout(() => setIsRetraining(false), 1200);
    }
  };

  return (
    <>
      {/* Mobile menu toggle — bottom-right, subtle */}
      <button
        onClick={() => setIsOpen(v => !v)}
        aria-label={isOpen ? 'Close menu' : 'Open menu'}
        className="lg:hidden fixed bottom-5 right-5 z-40 w-11 h-11 grid place-items-center rounded-pill bg-surface-card border border-surface-border text-ink-muted shadow-panel"
      >
        {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {/* Sidebar */}
      <aside
        className={`fixed lg:static left-0 top-0 h-dvh w-60 bg-surface-base border-r border-surface-border z-30 transform transition-transform duration-300 ease-crisp ${
          isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
        aria-label="Primary navigation"
      >
        <div className="flex flex-col h-full">
          {/* Header — wordmark only on desktop, mirrors Navbar */}
          <div className="hidden lg:flex items-center gap-2 px-5 h-14 border-b border-surface-border">
            <div className="w-1.5 h-1.5 rounded-pill bg-accent" />
            <span className="text-sm font-medium text-ink tracking-tighter-2">
              pleroma
            </span>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-3 py-4 space-y-0.5" aria-label="Sections">
            <p className="px-3 pt-2 pb-2 text-2xs uppercase tracking-micro text-ink-dim">
              Sections
            </p>
            {menu.map(({ path, icon: Icon, label }) => {
              const active = isActive(path);
              return (
                <Link
                  key={path}
                  to={path}
                  onClick={() => setIsOpen(false)}
                  className={`flex items-center gap-3 px-3 py-2 rounded-soft text-sm transition-colors duration-200 ease-crisp ${
                    active
                      ? 'text-ink bg-surface-card border border-surface-border'
                      : 'text-ink-muted hover:text-ink hover:bg-surface-card/50 border border-transparent'
                  }`}
                  aria-current={active ? 'page' : undefined}
                >
                  <Icon className={`w-4 h-4 ${active ? 'text-accent' : 'text-ink-subtle group-hover:text-ink-muted'}`} />
                  <span>{label}</span>
                </Link>
              );
            })}
          </nav>

          {/* Admin panel — restrained */}
          {user?.is_admin && (
            <div className="px-3 pb-3">
              <div className="rounded-card bg-surface-card border border-surface-border p-4">
                <p className="text-2xs uppercase tracking-micro text-ink-dim mb-1.5">Admin</p>
                <p className="text-sm text-ink mb-3">Retrain classifier</p>
                <button
                  onClick={handleRetrain}
                  disabled={isRetraining}
                  className="w-full inline-flex items-center justify-center gap-2 px-3 py-1.5 rounded-soft text-xs font-medium text-accent bg-accent-quiet hover:bg-accent-subtle border border-accent-border/50 transition-colors duration-200 ease-crisp disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isRetraining ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : null}
                  {isRetraining ? 'Retraining' : 'Trigger retrain'}
                </button>
                <p className="mt-2 text-2xs text-ink-dim leading-snug">
                  Runs in the background. Active classifier is hot-swapped on completion.
                </p>
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* Mobile scrim */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-surface-base/70 backdrop-blur-sm z-20 lg:hidden scrim-enter"
          onClick={() => setIsOpen(false)}
          aria-hidden
        />
      )}
    </>
  );
}
