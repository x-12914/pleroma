import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { authService } from '../services/api';

/* ---------------------------------------------------------------
   Register — same shape as Login. Inline validation. Drops
   "JOIN AICDS" / "SOC Analyst account" branding. bcrypt 72-byte
   limit enforced client-side so the user finds out before the
   server rejects.
   --------------------------------------------------------------- */

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({});
  const [authError, setAuthError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  function validate(): boolean {
    const errs: typeof fieldErrors = {};
    const trimmed = email.trim();
    if (!trimmed) errs.email = 'Email required.';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) errs.email = "That doesn't look like an email.";
    if (!password) errs.password = 'Password required.';
    else if (password.length < 8) errs.password = 'Use at least 8 characters.';
    else if (new TextEncoder().encode(password).length > 72) {
      errs.password = 'Maximum 72 bytes (bcrypt limit).';
    }
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  }

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    if (!validate()) return;
    setLoading(true);
    try {
      await authService.register({ email: email.trim(), password });
      navigate('/login', {
        state: { message: 'Account created. Sign in to continue.' },
      });
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      setAuthError(detail || 'Could not register. Try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main id="main" className="min-h-dvh grid place-items-center bg-surface-base px-4 py-12">
      <div className="w-full max-w-sm space-y-8">
        <div className="flex items-center justify-center gap-2.5">
          <div className="w-2 h-2 rounded-pill bg-accent" />
          <span className="text-base font-medium text-ink tracking-tighter-2">pleroma</span>
        </div>

        <div className="text-center space-y-1.5">
          <h1 className="text-display-md font-medium text-ink">Create an account</h1>
          <p className="text-sm text-ink-subtle">Takes a moment. No email verification.</p>
        </div>

        <form onSubmit={handleRegister} className="space-y-4" noValidate>
          <Field
            id="email"
            type="email"
            label="Email"
            value={email}
            onChange={setEmail}
            error={fieldErrors.email}
            autoComplete="email"
            disabled={loading}
          />
          <Field
            id="password"
            type="password"
            label="Password"
            value={password}
            onChange={setPassword}
            error={fieldErrors.password}
            autoComplete="new-password"
            disabled={loading}
            hint="At least 8 characters. Up to 72 bytes."
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
            disabled={loading}
            className="w-full py-2.5 bg-accent hover:bg-accent-hi text-surface-base font-medium rounded-soft transition-colors duration-200 ease-crisp flex items-center justify-center gap-2 disabled:opacity-60"
          >
            {loading && <Loader2 className="animate-spin w-4 h-4" />}
            {loading ? 'Creating account' : 'Create account'}
          </button>
        </form>

        <p className="text-center text-xs text-ink-subtle">
          Already have an account?{' '}
          <Link to="/login" className="text-accent hover:text-accent-hi underline-offset-4 hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </main>
  );
}

function Field({
  id, type, label, value, onChange, error, autoComplete, disabled, hint,
}: {
  id: string;
  type: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  error?: string;
  autoComplete?: string;
  disabled?: boolean;
  hint?: string;
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
      {error ? (
        <p className="mt-1 text-2xs text-signal-danger">{error}</p>
      ) : hint ? (
        <p className="mt-1 text-2xs text-ink-dim">{hint}</p>
      ) : null}
    </div>
  );
}
