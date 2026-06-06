import type { ReactNode } from 'react';

/* -----------------------------------------------------------------
   Surface primitives.

   The old version overloaded `glass-card` with glassmorphism and
   forced an icon + trend + colored border into every metric. The new
   version is opinion-free: a plain surface you compose into anything.
   ----------------------------------------------------------------- */

interface MetricCardProps {
  label: string;
  value: ReactNode;
  hint?: string;
  trend?: { delta: number; suffix?: string } | null;
  tone?: 'neutral' | 'danger' | 'warning' | 'ok' | 'accent';
  size?: 'sm' | 'md' | 'lg';
}

const toneRing: Record<NonNullable<MetricCardProps['tone']>, string> = {
  neutral: 'border-surface-border',
  danger:  'border-surface-border ring-1 ring-signal-danger-border/40',
  warning: 'border-surface-border ring-1 ring-signal-warning-border/40',
  ok:      'border-surface-border ring-1 ring-signal-ok-border/40',
  accent:  'border-surface-border ring-1 ring-accent-border/60',
};

const toneValueColor: Record<NonNullable<MetricCardProps['tone']>, string> = {
  neutral: 'text-ink',
  danger:  'text-signal-danger',
  warning: 'text-signal-warning',
  ok:      'text-signal-ok',
  accent:  'text-accent',
};

export default function MetricCard({
  label,
  value,
  hint,
  trend,
  tone = 'neutral',
  size = 'md',
}: MetricCardProps) {
  const sizePad =
    size === 'lg' ? 'p-7' : size === 'sm' ? 'p-4' : 'p-5';
  const valueSize =
    size === 'lg' ? 'text-display-lg' : size === 'sm' ? 'text-2xl' : 'text-display-sm';

  return (
    <div className={`bg-surface-card border ${toneRing[tone]} rounded-card ${sizePad} transition-colors duration-300 ease-crisp`}>
      <div className="flex items-baseline justify-between gap-3 mb-3">
        <p className="text-xs text-ink-muted tracking-wide">{label}</p>
        {trend != null && (
          <span
            className={`text-2xs font-medium tabular ${
              trend.delta >= 0 ? 'text-signal-danger' : 'text-signal-ok'
            }`}
          >
            {trend.delta >= 0 ? '↑' : '↓'} {Math.abs(trend.delta).toFixed(1)}{trend.suffix ?? '%'}
          </span>
        )}
      </div>
      <div className={`${valueSize} ${toneValueColor[tone]} tabular font-medium`}>
        {value}
      </div>
      {hint && (
        <p className="mt-2 text-xs text-ink-subtle">{hint}</p>
      )}
    </div>
  );
}

/* ---------- Generic card ---------- */

interface CardProps {
  children: ReactNode;
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  className?: string;
  bodyClassName?: string;
}

export function Card({ children, title, subtitle, actions, className = '', bodyClassName = '' }: CardProps) {
  return (
    <section className={`bg-surface-card border border-surface-border rounded-card ${className}`}>
      {(title || actions) && (
        <header className="flex items-end justify-between gap-4 px-5 pt-5 pb-3">
          <div>
            {title && (
              <h3 className="text-base font-medium text-ink">{title}</h3>
            )}
            {subtitle && (
              <p className="mt-1 text-xs text-ink-subtle">{subtitle}</p>
            )}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={`px-5 pb-5 ${title ? 'pt-2' : 'pt-5'} ${bodyClassName}`}>
        {children}
      </div>
    </section>
  );
}

/* Legacy alias — older pages still import `SimpleCard`. Same component now. */
export const SimpleCard = Card;
