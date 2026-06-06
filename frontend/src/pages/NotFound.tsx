import { Link } from 'react-router-dom';

/* ---------------------------------------------------------------
   404 — small, helpful, branded. Replaces the silent redirect
   that used to bounce unknown paths back to /.
   --------------------------------------------------------------- */

export default function NotFound() {
  return (
    <main id="main" className="min-h-dvh grid place-items-center bg-surface-base px-4">
      <div className="w-full max-w-md text-center space-y-6">
        <div className="flex items-center justify-center gap-2.5">
          <div className="w-2 h-2 rounded-pill bg-accent" />
          <span className="text-base font-medium text-ink tracking-tighter-2">pleroma</span>
        </div>

        <div className="space-y-2">
          <p className="text-2xs uppercase tracking-micro text-ink-dim tabular">404</p>
          <h1 className="text-display-md font-medium text-ink">Page not found</h1>
          <p className="text-sm text-ink-subtle">
            The route you tried doesn't exist on this dashboard.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-2 justify-center pt-2">
          <Link
            to="/"
            className="inline-flex items-center justify-center px-4 py-2 bg-accent hover:bg-accent-hi text-surface-base text-sm font-medium rounded-soft transition-colors duration-200 ease-crisp"
          >
            Back to overview
          </Link>
          <Link
            to="/logs"
            className="inline-flex items-center justify-center px-4 py-2 bg-surface-card hover:bg-surface-hover/50 border border-surface-border text-ink-muted hover:text-ink text-sm font-medium rounded-soft transition-colors duration-200 ease-crisp"
          >
            Recent detections
          </Link>
        </div>
      </div>
    </main>
  );
}
