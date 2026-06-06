import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';

/* ---------------------------------------------------------------
   Login — pared back. No shield icon, no "Secure Operator Portal"
   subtitle, no all-caps button. Inline validation, inline errors,
   single accent. Two fields, one button.
   --------------------------------------------------------------- */

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({});
  const [authError, setAuthError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (location.state?.message) {
      toast.success(location.state.message);
    }
  }, [location.state]);

  function validate(): boolean {
    const errs: typeof fieldErrors = {};
    const trimmed = email.trim();
    if (!trimmed) errs.email = 'Email required.';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) errs.email = "That doesn't look like an email.";
    if (!password) errs.password = 'Password required.';
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    if (!validate()) return;
    setIsLoading(true);
    try {
      await login(email.trim(), password);
      navigate('/');
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      setAuthError(detail || 'Incorrect email or password.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main id="main" className="min-h-dvh grid place-items-center bg-surface-base px-4 py-12">
      <div className="w-full max-w-sm space-y-8">
        {/* Wordmark */}
        <div className="flex items-center justify-center gap-2.5">
          <div className="w-2 h-2 rounded-pill bg-accent" />
          <span className="text-base font-medium text-ink tracking-tighter-2">pleroma</span>
        </div>

        {/* Heading */}
        <div className="text-center space-y-1.5">
          <h1 className="text-display-md font-medium text-ink">Sign in</h1>
          <p className="text-sm text-ink-subtle">
            Use the credentials provided by your administrator.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <Field
            id="email"
            type="email"
            label="Email"
            value={email}
            onChange={setEmail}
            error={fieldErrors.email}
            autoComplete="email"
            disabled={isLoading}
          />
          <Field
            id="password"
            type="password"
            label="Password"
            value={password}
            onChange={setPassword}
            error={fieldErrors.password}
            autoComplete="current-password"
            disabled={isLoading}
          />

          {authError && (
            <div
              className="text-sm text-signal-danger bg-signal-danger-bg border border-signal-danger-border/40 rounded-soft px-3 py-2.5"
              role="alert"
            >
              {authError}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 bg-accent hover:bg-accent-hi text-surface-base font-medium rounded-soft transition-colors duration-200 ease-crisp flex items-center justify-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {isLoading && <Loader2 className="animate-spin w-4 h-4" />}
            {isLoading ? 'Signing in' : 'Sign in'}
          </button>
        </form>

        {/* Register link */}
        <p className="text-center text-xs text-ink-subtle">
          No account yet?{' '}
          <Link to="/register" className="text-accent hover:text-accent-hi underline-offset-4 hover:underline">
            Create one
          </Link>
        </p>
      </div>
    </main>
  );
}

/* ---------- Field ---------- */

function Field({
  id, type, label, value, onChange, error, autoComplete, disabled,
}: {
  id: string;
  type: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  error?: string;
  autoComplete?: string;
  disabled?: boolean;
}) {
  return (
    <div>
      <label htmlFor={id} className="block text-xs text-ink-muted mb-1.5">{label}</label>
      <input
        id={id}
        type={type}
        value={value}
        autoComplete={autoComplete}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        aria-invalid={!!error}
        className={`w-full px-3 py-2.5 bg-surface-card border rounded-soft text-sm text-ink placeholder:text-ink-dim transition-shadow focus:outline-none focus:shadow-focus-ring ${
          error ? 'border-signal-danger-border/60' : 'border-surface-border focus:border-accent-border'
        }`}
      />
      {error && (
        <p className="mt-1 text-2xs text-signal-danger">{error}</p>
      )}
    </div>
  );
}
