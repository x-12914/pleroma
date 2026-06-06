import { useState, useEffect } from 'react';
import { LogOut } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { checkSystemHealth } from '../services/api';

/* ---------------------------------------------------------------
   Navbar — minimal. Drops "AICDS / Security Operations Center"
   branding, the bouncing alert icon, both pulsing status pills,
   and the hardcoded "3 Recent Alerts" string.

   What's left: wordmark, online status pip, current time, user
   email, logout. Nothing pulses.
   --------------------------------------------------------------- */

export default function Navbar() {
  const [time, setTime] = useState(formatTime(new Date()));
  const [isOnline, setIsOnline] = useState<boolean | null>(null);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const t = setInterval(() => setTime(formatTime(new Date())), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const probe = async () => {
      try {
        const r = await checkSystemHealth();
        if (!cancelled) setIsOnline(r.status === 200);
      } catch {
        if (!cancelled) setIsOnline(false);
      }
    };
    probe();
    const i = setInterval(probe, 12000);
    return () => { cancelled = true; clearInterval(i); };
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="sticky top-0 z-30 bg-surface-base/90 backdrop-blur-sm border-b border-surface-border">
      <div className="flex items-center justify-between gap-4 px-4 lg:px-8 h-14">
        {/* Wordmark — minimal, no pulsing icons */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-2.5">
            <div className="w-2 h-2 rounded-pill bg-accent" aria-hidden />
            <span className="font-medium text-ink tracking-tighter-2 text-base">
              pleroma
            </span>
            <span className="hidden sm:inline-block text-2xs text-ink-subtle tabular ml-1">
              detection · v1
            </span>
          </div>
        </div>

        {/* Right cluster: status + time + user + logout */}
        <div className="flex items-center gap-2 lg:gap-5">
          <StatusPill online={isOnline} />

          <span className="hidden lg:inline text-xs text-ink-subtle tabular">
            {time}
          </span>

          {user && (
            <span className="hidden md:inline text-xs text-ink-muted truncate max-w-[180px]">
              {user.email}
            </span>
          )}

          <button
            onClick={handleLogout}
            aria-label="Log out"
            className="inline-flex items-center gap-2 text-xs text-ink-muted hover:text-ink px-2.5 py-1.5 rounded-soft border border-transparent hover:border-surface-border transition-colors duration-200 ease-crisp"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Sign out</span>
          </button>
        </div>
      </div>
    </header>
  );
}

function StatusPill({ online }: { online: boolean | null }) {
  const tone =
    online === null
      ? 'text-ink-subtle bg-surface-raised border-surface-border'
      : online
      ? 'text-signal-ok bg-signal-ok-bg border-signal-ok-border'
      : 'text-signal-danger bg-signal-danger-bg border-signal-danger-border';
  const label =
    online === null ? 'Connecting' : online ? 'Online' : 'Offline';

  return (
    <span
      className={`inline-flex items-center gap-1.5 text-2xs font-medium px-2 py-1 rounded-pill border ${tone}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-pill ${
          online === null
            ? 'bg-ink-subtle'
            : online
            ? 'bg-signal-ok'
            : 'bg-signal-danger'
        }`}
      />
      {label}
    </span>
  );
}

function formatTime(d: Date) {
  return d.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}
