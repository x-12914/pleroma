import { AlertCircle, RefreshCw } from 'lucide-react';

/* ---- Skeleton loader — matches the layout shape, not a generic spinner ---- */

export function LoadingSpinner() {
  return (
    <div className="space-y-2 py-2" aria-busy="true" aria-live="polite">
      <div className="skeleton h-4 w-3/4" />
      <div className="skeleton h-4 w-1/2" />
      <div className="skeleton h-4 w-2/3" />
    </div>
  );
}

export function SkeletonRow() {
  return (
    <div className="flex items-center gap-3">
      <div className="skeleton h-3 flex-1" />
    </div>
  );
}

export function SkeletonStat() {
  return (
    <div className="bg-surface-card border border-surface-border rounded-card p-5 space-y-3">
      <div className="skeleton h-3 w-20" />
      <div className="skeleton h-8 w-32" />
    </div>
  );
}

/* ---- Error state — direct copy, single action ---- */

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="bg-surface-card border border-signal-danger-border/40 rounded-card p-6">
      <div className="flex gap-3 items-start">
        <AlertCircle className="w-5 h-5 text-signal-danger shrink-0 mt-0.5" />
        <div className="flex-1">
          <p className="text-sm text-ink">{message}</p>
          {onRetry && (
            <button
              onClick={onRetry}
              className="mt-3 inline-flex items-center gap-2 text-xs text-ink-muted hover:text-ink transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Try again
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function WarningState({ message }: { message: string }) {
  return (
    <div className="bg-surface-card border border-signal-warning-border/40 rounded-card p-4">
      <div className="flex gap-3 items-start">
        <AlertCircle className="w-5 h-5 text-signal-warning shrink-0 mt-0.5" />
        <p className="text-sm text-ink-muted">{message}</p>
      </div>
    </div>
  );
}

/* ---- Empty state — for tables and lists ---- */

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="px-6 py-16 text-center">
      <p className="text-base text-ink font-medium">{title}</p>
      {description && (
        <p className="mt-2 text-sm text-ink-subtle max-w-md mx-auto">{description}</p>
      )}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}
