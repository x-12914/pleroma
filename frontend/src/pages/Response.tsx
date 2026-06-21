import { useState, useEffect, useCallback, useMemo, type FormEvent } from 'react';
import {
  ShieldAlert, ShieldCheck, Eye, OctagonX, Power, Plus, Trash2,
  Check, X, RefreshCw, AlertTriangle,
} from 'lucide-react';
import { format } from 'date-fns';
import { toast } from 'sonner';
import { Card } from '../components/Card';
import { LoadingSpinner, EmptyState } from '../components/LoadingState';
import { useAuth } from '../context/AuthContext';
import {
  responseService,
  type EnforcementState,
  type ResponseMode,
  type AllowlistEntry,
  type PolicyRule,
  type ResponseAction,
  type ActionStatus,
} from '../services/api';

/* ---------------------------------------------------------------
   Response — autonomous-response control panel (Phase 2).

   Matches the refined token palette used by Detections/Sensors:
   solid surfaces, subtle borders, sentence case, tabular figures.

   Safety-first framing per docs/CONTRACTS.md design invariants:
   • Kill switch is the visual emergency stop (forces OFF).
   • dry_run is calm (observing only); auto is the warning state.
   • Allowlisted IPs are "never acted on".
   • Non-admins see everything read-only.
   --------------------------------------------------------------- */

/* ---- Mode presentation metadata ---- */

interface ModeMeta {
  label: string;
  blurb: string;
  icon: typeof Eye;
  // tailwind token classes for the banner skin
  ring: string;
  bg: string;
  text: string;
  dot: string;
}

const MODE_META: Record<ResponseMode, ModeMeta> = {
  off: {
    label: 'Off',
    blurb: 'Response engine is disabled. No decisions are made.',
    icon: Power,
    ring: 'border-surface-border',
    bg: 'bg-surface-card',
    text: 'text-ink-muted',
    dot: 'bg-ink-dim',
  },
  dry_run: {
    label: 'Dry run',
    blurb: 'Observing only — nothing is blocked. Actions are logged as "would-have".',
    icon: Eye,
    ring: 'ring-1 ring-signal-ok-border/40 border-surface-border',
    bg: 'bg-signal-ok-bg',
    text: 'text-signal-ok',
    dot: 'bg-signal-ok',
  },
  recommend: {
    label: 'Recommend',
    blurb: 'Awaiting your approval — actions queue as pending until an admin acts.',
    icon: ShieldCheck,
    ring: 'ring-1 ring-accent-border/60 border-surface-border',
    bg: 'bg-accent-quiet',
    text: 'text-accent',
    dot: 'bg-accent',
  },
  auto: {
    label: 'Auto',
    blurb: 'Actively enforcing — matching traffic is blocked or throttled automatically.',
    icon: ShieldAlert,
    ring: 'ring-1 ring-signal-warning-border/40 border-surface-border',
    bg: 'bg-signal-warning-bg',
    text: 'text-signal-warning',
    dot: 'bg-signal-warning',
  },
};

const MODE_ORDER: ResponseMode[] = ['off', 'dry_run', 'recommend', 'auto'];

/* ---- Action status presentation ---- */

const STATUS_TONE: Record<ActionStatus, string> = {
  would_apply: 'text-ink-muted',
  pending: 'text-accent',
  active: 'text-signal-warning',
  expired: 'text-ink-dim',
  reverted: 'text-ink-subtle',
  rejected: 'text-ink-subtle',
  failed: 'text-signal-danger',
};

const STATUS_LABEL: Record<ActionStatus, string> = {
  would_apply: 'Would apply',
  pending: 'Pending',
  active: 'Active',
  expired: 'Expired',
  reverted: 'Reverted',
  rejected: 'Rejected',
  failed: 'Failed',
};

// Filter tabs. "Live" (default) merges the three actionable states.
type FilterTab = 'live' | ActionStatus;

const FILTER_TABS: { key: FilterTab; label: string }[] = [
  { key: 'live', label: 'Live' },
  { key: 'would_apply', label: 'Would apply' },
  { key: 'pending', label: 'Pending' },
  { key: 'active', label: 'Active' },
  { key: 'expired', label: 'Expired' },
  { key: 'reverted', label: 'Reverted' },
  { key: 'rejected', label: 'Rejected' },
  { key: 'failed', label: 'Failed' },
];

const LIVE_STATUSES: ActionStatus[] = ['would_apply', 'pending', 'active'];

export default function Response() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole('admin');

  const [state, setState] = useState<EnforcementState | null>(null);
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([]);
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [actions, setActions] = useState<ResponseAction[]>([]);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [savingState, setSavingState] = useState(false);

  const [filter, setFilter] = useState<FilterTab>('live');

  // Allowlist add form
  const [newCidr, setNewCidr] = useState('');
  const [newReason, setNewReason] = useState('');
  const [addingAllow, setAddingAllow] = useState(false);
  const [pendingAllowDelete, setPendingAllowDelete] = useState<number | null>(null);

  // Per-row busy flags for action mutations
  const [busyAction, setBusyAction] = useState<number | null>(null);
  const [busyPolicy, setBusyPolicy] = useState<number | null>(null);

  const fetchAll = useCallback(async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true);
    try {
      const [stateRes, allowRes, policyRes, actionRes] = await Promise.all([
        responseService.getState(),
        responseService.getAllowlist(),
        responseService.getPolicy(),
        responseService.getActions(),
      ]);
      setState(stateRes.data);
      setAllowlist(allowRes.data || []);
      setPolicies(policyRes.data || []);
      setActions(actionRes.data || []);
    } catch {
      toast.error('Could not load response control state.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(() => fetchAll(false), 30000);
    return () => clearInterval(id);
  }, [fetchAll]);

  /* ---- State mutations (admin) ---- */

  const persistState = async (next: { mode: ResponseMode; kill_switch: boolean }) => {
    if (!isAdmin) return;
    setSavingState(true);
    // optimistic
    const prev = state;
    setState((s) => (s ? { ...s, ...next } : s));
    try {
      const { data } = await responseService.updateState(next);
      setState(data);
      toast.success('Response state updated.');
    } catch {
      setState(prev);
      toast.error('Could not update response state.');
    } finally {
      setSavingState(false);
    }
  };

  const changeMode = (mode: ResponseMode) => {
    if (!state || mode === state.mode) return;
    if (mode === 'auto') {
      if (!window.confirm(
        'Switch to AUTO? Matching traffic will be blocked or throttled automatically. ' +
        'Allowlisted, own, and admin IPs are always protected.'
      )) return;
    }
    persistState({ mode, kill_switch: state.kill_switch });
  };

  const toggleKillSwitch = () => {
    if (!state) return;
    const next = !state.kill_switch;
    if (next && !window.confirm(
      'Engage the KILL SWITCH? This immediately forces the response engine OFF, ' +
      'overriding the current mode and every policy.'
    )) return;
    persistState({ mode: state.mode, kill_switch: next });
  };

  /* ---- Allowlist mutations (admin) ---- */

  const handleAddAllow = async (e: FormEvent) => {
    e.preventDefault();
    const cidr = newCidr.trim();
    const reason = newReason.trim();
    if (!cidr || !reason) return;
    setAddingAllow(true);
    try {
      await responseService.addAllowlist({ cidr, reason });
      setNewCidr('');
      setNewReason('');
      toast.success('Allowlist entry added.');
      await fetchAll();
    } catch (err: any) {
      toast.error(err?.response?.data?.detail ?? 'Could not add allowlist entry.');
    } finally {
      setAddingAllow(false);
    }
  };

  const handleDeleteAllow = async (entry: AllowlistEntry) => {
    try {
      await responseService.removeAllowlist(entry.id);
      toast.success(`${entry.cidr} removed from allowlist.`);
      await fetchAll();
    } catch {
      toast.error('Could not remove allowlist entry.');
    } finally {
      setPendingAllowDelete(null);
    }
  };

  /* ---- Policy mutations (admin) ---- */

  const togglePolicy = async (rule: PolicyRule) => {
    if (!isAdmin) return;
    setBusyPolicy(rule.id);
    try {
      await responseService.updatePolicy(rule.id, { enabled: !rule.enabled });
      toast.success(`Rule "${rule.name}" ${rule.enabled ? 'disabled' : 'enabled'}.`);
      await fetchAll();
    } catch {
      toast.error('Could not update policy rule.');
    } finally {
      setBusyPolicy(null);
    }
  };

  /* ---- Action mutations (admin) ---- */

  const runAction = async (
    id: number,
    fn: (id: number) => Promise<unknown>,
    okMsg: string,
  ) => {
    setBusyAction(id);
    try {
      await fn(id);
      toast.success(okMsg);
      await fetchAll();
    } catch {
      toast.error('Action failed.');
    } finally {
      setBusyAction(null);
    }
  };

  /* ---- Derived ---- */

  const filteredActions = useMemo(() => {
    if (filter === 'live') {
      return actions.filter((a) => LIVE_STATUSES.includes(a.status));
    }
    return actions.filter((a) => a.status === filter);
  }, [actions, filter]);

  const meta = state ? MODE_META[state.mode] : MODE_META.off;

  /* ---- Render ---- */

  if (loading) {
    return (
      <main id="main" className="space-y-7">
        <PageHeader refreshing={refreshing} onRefresh={() => fetchAll(true)} />
        <Card><LoadingSpinner /></Card>
      </main>
    );
  }

  return (
    <main id="main" className="space-y-7">
      <PageHeader refreshing={refreshing} onRefresh={() => fetchAll(true)} isAdmin={isAdmin} />

      {/* ============ STATUS BANNER ============ */}
      <section
        className={`rounded-card border ${meta.ring} ${
          state?.kill_switch ? 'bg-signal-danger-bg ring-1 ring-signal-danger-border/50 border-surface-border' : meta.bg
        } p-6`}
      >
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5">
          <div className="flex items-start gap-4">
            <div className={`shrink-0 w-11 h-11 grid place-items-center rounded-card border border-surface-border bg-surface-base/40`}>
              {state?.kill_switch ? (
                <OctagonX className="w-5 h-5 text-signal-danger" />
              ) : (
                <meta.icon className={`w-5 h-5 ${meta.text}`} />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className={`w-2 h-2 rounded-pill ${state?.kill_switch ? 'bg-signal-danger' : meta.dot}`} aria-hidden />
                <h2 className={`text-display-sm font-medium ${state?.kill_switch ? 'text-signal-danger' : meta.text}`}>
                  {state?.kill_switch ? 'Kill switch engaged' : meta.label}
                </h2>
              </div>
              <p className="mt-1.5 text-sm text-ink-muted max-w-xl leading-relaxed">
                {state?.kill_switch
                  ? 'The response engine is force-stopped. No traffic is acted on regardless of mode or policy. Disengage to restore the selected mode.'
                  : meta.blurb}
              </p>
              {state?.updated_at && (
                <p className="mt-2 text-2xs text-ink-dim tabular">
                  Last changed {format(new Date(state.updated_at), 'MMM dd, HH:mm')}
                  {state.updated_by ? ` by ${state.updated_by}` : ''}
                </p>
              )}
            </div>
          </div>

          {/* Kill switch — emergency stop, visually emphasised */}
          <div className="shrink-0">
            <button
              onClick={toggleKillSwitch}
              disabled={!isAdmin || savingState}
              title={!isAdmin ? 'Admin role required.' : undefined}
              className={`inline-flex items-center gap-2.5 px-5 py-3 rounded-card text-sm font-medium border transition-colors duration-200 ease-crisp disabled:opacity-50 disabled:cursor-not-allowed ${
                state?.kill_switch
                  ? 'bg-surface-card text-ink hover:bg-surface-hover/50 border-surface-border'
                  : 'bg-signal-danger-bg text-signal-danger hover:brightness-110 border-signal-danger-border/50'
              }`}
            >
              <Power className="w-4 h-4" />
              {state?.kill_switch ? 'Disengage kill switch' : 'Emergency stop'}
            </button>
          </div>
        </div>

        {/* Mode selector (admin) */}
        <div className="mt-6 pt-5 border-t border-surface-border/60">
          <div className="flex items-center justify-between gap-3 mb-3">
            <p className="text-2xs uppercase tracking-micro text-ink-dim">Operating mode</p>
            {!isAdmin && (
              <span className="text-2xs text-ink-dim">Read-only — admin role required to change</span>
            )}
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {MODE_ORDER.map((m) => {
              const mm = MODE_META[m];
              const selected = state?.mode === m;
              return (
                <button
                  key={m}
                  onClick={() => changeMode(m)}
                  disabled={!isAdmin || savingState || state?.kill_switch}
                  title={
                    state?.kill_switch
                      ? 'Disengage the kill switch first.'
                      : !isAdmin
                      ? 'Admin role required.'
                      : mm.blurb
                  }
                  className={`flex flex-col items-start gap-1 px-3 py-2.5 rounded-soft border text-left transition-colors duration-200 ease-crisp disabled:cursor-not-allowed ${
                    selected
                      ? `${mm.ring} ${mm.bg}`
                      : 'border-surface-border bg-surface-card hover:bg-surface-hover/40 disabled:opacity-50'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <mm.icon className={`w-3.5 h-3.5 ${selected ? mm.text : 'text-ink-subtle'}`} />
                    <span className={`text-sm font-medium ${selected ? mm.text : 'text-ink-muted'}`}>
                      {mm.label}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </section>

      {/* ============ ALLOWLIST ============ */}
      <Card
        title="Allowlist"
        subtitle="These IPs and CIDRs are never acted on — the engine hard-refuses to block them."
      >
        {isAdmin && (
          <form onSubmit={handleAddAllow} className="flex flex-col sm:flex-row gap-3 mb-5">
            <input
              type="text"
              value={newCidr}
              onChange={(e) => setNewCidr(e.target.value)}
              placeholder="CIDR or IP, e.g. 10.0.0.0/24"
              disabled={addingAllow}
              className="sm:w-56 px-3 py-2.5 bg-surface-base border border-surface-border rounded-soft text-sm text-ink font-mono placeholder:text-ink-dim placeholder:font-sans focus:outline-none focus:border-accent-border focus:shadow-focus-ring transition-shadow"
            />
            <input
              type="text"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              placeholder="Reason — e.g. office VPN range"
              disabled={addingAllow}
              maxLength={120}
              className="flex-1 px-3 py-2.5 bg-surface-base border border-surface-border rounded-soft text-sm text-ink placeholder:text-ink-dim focus:outline-none focus:border-accent-border focus:shadow-focus-ring transition-shadow"
            />
            <button
              type="submit"
              disabled={addingAllow || !newCidr.trim() || !newReason.trim()}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-accent hover:bg-accent-hi text-surface-base font-medium rounded-soft text-sm transition-colors duration-200 ease-crisp disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Plus className="w-4 h-4" />
              {addingAllow ? 'Adding' : 'Add'}
            </button>
          </form>
        )}

        {allowlist.length === 0 ? (
          <EmptyState
            title="Allowlist is empty"
            description="Install seeds loopback, the box's own IPs, and the admin CIDR. Add ranges that must never be blocked."
          />
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className="text-2xs uppercase tracking-micro text-ink-dim border-b border-surface-border">
                <th className="px-2 py-2 font-normal">CIDR / IP</th>
                <th className="px-2 py-2 font-normal">Reason</th>
                <th className="px-2 py-2 font-normal">Added</th>
                {isAdmin && <th className="px-2 py-2 font-normal w-32 text-right">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {allowlist.map((entry) => (
                <tr key={entry.id} className="hover:bg-surface-hover/30 transition-colors duration-150 ease-crisp">
                  <td className="px-2 py-3 text-sm text-accent font-mono">{entry.cidr}</td>
                  <td className="px-2 py-3 text-sm text-ink-muted">{entry.reason}</td>
                  <td className="px-2 py-3 text-xs text-ink-subtle tabular font-mono">
                    {entry.created_at ? format(new Date(entry.created_at), 'MMM dd, HH:mm') : '—'}
                  </td>
                  {isAdmin && (
                    <td className="px-2 py-3 text-right">
                      {pendingAllowDelete === entry.id ? (
                        <span className="inline-flex items-center gap-1.5 text-2xs">
                          <button
                            onClick={() => setPendingAllowDelete(null)}
                            className="text-ink-muted hover:text-ink px-2 py-1 rounded-soft"
                          >
                            Cancel
                          </button>
                          <button
                            onClick={() => handleDeleteAllow(entry)}
                            className="text-signal-danger bg-signal-danger-bg hover:brightness-110 border border-signal-danger-border/40 px-2.5 py-1 rounded-soft font-medium"
                          >
                            Confirm
                          </button>
                        </span>
                      ) : (
                        <button
                          onClick={() => setPendingAllowDelete(entry.id)}
                          title="Remove from allowlist"
                          className="p-1.5 rounded-soft text-ink-subtle hover:text-signal-danger hover:bg-signal-danger-bg transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* ============ POLICY RULES ============ */}
      <Card
        title="Policy rules"
        subtitle="Evaluated by priority. The first matching rule decides the action for an event."
      >
        {policies.length === 0 ? (
          <EmptyState
            title="No policy rules"
            description="Rules map detection classes to actions (block, throttle, alert, host) with repeat/window thresholds."
          />
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className="text-2xs uppercase tracking-micro text-ink-dim border-b border-surface-border">
                <th className="px-2 py-2 font-normal">Name</th>
                <th className="px-2 py-2 font-normal">Match</th>
                <th className="px-2 py-2 font-normal">Action</th>
                <th className="px-2 py-2 font-normal">Repeats / window</th>
                <th className="px-2 py-2 font-normal text-right">Enabled</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {policies.map((rule) => (
                <tr key={rule.id} className="hover:bg-surface-hover/30 transition-colors duration-150 ease-crisp">
                  <td className="px-2 py-3 text-sm text-ink font-medium">{rule.name}</td>
                  <td className="px-2 py-3 text-xs text-ink-muted font-mono">
                    {rule.match_raw_class || rule.match_verdict || <span className="text-ink-dim">any</span>}
                    {rule.min_confidence ? (
                      <span className="text-ink-dim"> · ≥{Math.round(rule.min_confidence * 100)}%</span>
                    ) : null}
                  </td>
                  <td className="px-2 py-3">
                    <span className="text-2xs uppercase tracking-micro text-ink-subtle px-2 py-0.5 rounded-pill border border-surface-border bg-surface-base">
                      {rule.action}
                    </span>
                  </td>
                  <td className="px-2 py-3 text-xs text-ink-subtle tabular">
                    {(rule.min_repeats ?? 1)}× / {rule.window_seconds ?? 600}s
                  </td>
                  <td className="px-2 py-3 text-right">
                    <ToggleSwitch
                      on={rule.enabled}
                      disabled={!isAdmin || busyPolicy === rule.id}
                      onClick={() => togglePolicy(rule)}
                      title={!isAdmin ? 'Admin role required.' : rule.enabled ? 'Disable rule' : 'Enable rule'}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* ============ ACTIONS ============ */}
      <Card
        title="Response actions"
        subtitle="Audit trail and work queue. Dry-run decisions appear as would-have actions."
      >
        {/* Filter tabs */}
        <div className="flex flex-wrap gap-1.5 mb-5 -mt-1">
          {FILTER_TABS.map((tab) => {
            const count = tab.key === 'live'
              ? actions.filter((a) => LIVE_STATUSES.includes(a.status)).length
              : actions.filter((a) => a.status === tab.key).length;
            const active = filter === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => setFilter(tab.key)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-soft text-xs transition-colors duration-150 ease-crisp border ${
                  active
                    ? 'text-ink bg-surface-card border-surface-border'
                    : 'text-ink-muted hover:text-ink border-transparent hover:bg-surface-card/50'
                }`}
              >
                {tab.label}
                <span className={`text-2xs tabular ${active ? 'text-accent' : 'text-ink-dim'}`}>{count}</span>
              </button>
            );
          })}
        </div>

        {filteredActions.length === 0 ? (
          <EmptyState
            title="No actions to show"
            description={
              filter === 'live'
                ? 'No would-apply, pending, or active actions right now. In dry run, decisions land here as would-have records.'
                : `No actions with status "${filter}".`
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-2xs uppercase tracking-micro text-ink-dim border-b border-surface-border">
                  <th className="px-2 py-2 font-normal">When</th>
                  <th className="px-2 py-2 font-normal">Source IP</th>
                  <th className="px-2 py-2 font-normal">Action</th>
                  <th className="px-2 py-2 font-normal">Class</th>
                  <th className="px-2 py-2 font-normal">Reason</th>
                  <th className="px-2 py-2 font-normal">Mode</th>
                  <th className="px-2 py-2 font-normal">Status</th>
                  <th className="px-2 py-2 font-normal">Expires</th>
                  {isAdmin && <th className="px-2 py-2 font-normal text-right w-40">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border">
                {filteredActions.map((a) => (
                  <tr key={a.id} className="hover:bg-surface-hover/30 transition-colors duration-150 ease-crisp">
                    <td className="px-2 py-3 text-xs text-ink-subtle tabular font-mono whitespace-nowrap">
                      {a.ts ? format(new Date(a.ts), 'MMM dd · HH:mm:ss') : '—'}
                    </td>
                    <td className="px-2 py-3 text-sm text-ink font-mono">{a.src_ip ?? '—'}</td>
                    <td className="px-2 py-3 text-xs text-ink-muted uppercase tracking-micro">{a.action_type}</td>
                    <td className="px-2 py-3 text-xs text-ink-muted font-mono">{a.raw_class ?? '—'}</td>
                    <td className="px-2 py-3 text-xs text-ink-subtle max-w-[220px] truncate" title={a.reason ?? ''}>
                      {a.reason ?? '—'}
                    </td>
                    <td className="px-2 py-3 text-2xs uppercase tracking-micro text-ink-dim">{a.mode}</td>
                    <td className="px-2 py-3">
                      <span className={`text-xs font-medium ${STATUS_TONE[a.status]}`}>
                        {STATUS_LABEL[a.status]}
                      </span>
                    </td>
                    <td className="px-2 py-3 text-xs text-ink-subtle tabular font-mono whitespace-nowrap">
                      {a.expires_at ? format(new Date(a.expires_at), 'MMM dd HH:mm') : '—'}
                    </td>
                    {isAdmin && (
                      <td className="px-2 py-3 text-right whitespace-nowrap">
                        {a.status === 'pending' && (
                          <span className="inline-flex items-center gap-1.5">
                            <button
                              onClick={() => runAction(a.id, responseService.approveAction, 'Action approved.')}
                              disabled={busyAction === a.id}
                              className="inline-flex items-center gap-1 text-2xs font-medium text-signal-ok bg-signal-ok-bg hover:brightness-110 border border-signal-ok-border/40 px-2.5 py-1 rounded-soft disabled:opacity-50"
                            >
                              <Check className="w-3 h-3" /> Approve
                            </button>
                            <button
                              onClick={() => runAction(a.id, responseService.rejectAction, 'Action rejected.')}
                              disabled={busyAction === a.id}
                              className="inline-flex items-center gap-1 text-2xs font-medium text-ink-muted hover:text-signal-danger border border-surface-border hover:border-signal-danger-border/40 px-2.5 py-1 rounded-soft disabled:opacity-50"
                            >
                              <X className="w-3 h-3" /> Reject
                            </button>
                          </span>
                        )}
                        {a.status === 'active' && (
                          <button
                            onClick={() => runAction(a.id, responseService.revertAction, 'Action reverted.')}
                            disabled={busyAction === a.id}
                            className="inline-flex items-center gap-1 text-2xs font-medium text-signal-warning bg-signal-warning-bg hover:brightness-110 border border-signal-warning-border/40 px-2.5 py-1 rounded-soft disabled:opacity-50"
                          >
                            <RefreshCw className="w-3 h-3" /> Revert
                          </button>
                        )}
                        {a.status !== 'pending' && a.status !== 'active' && (
                          <span className="text-2xs text-ink-dim">—</span>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Read-only footnote for non-admins */}
      {!isAdmin && (
        <div className="flex items-start gap-3 px-4 py-3 rounded-card border border-surface-border bg-surface-card">
          <AlertTriangle className="w-4 h-4 text-ink-dim shrink-0 mt-0.5" />
          <p className="text-xs text-ink-subtle leading-relaxed">
            You have read-only access to the response control panel. Changing the mode, kill switch,
            allowlist, policies, or approving actions requires an admin role.
          </p>
        </div>
      )}
    </main>
  );
}

/* ============================================================
   Sub-components
   ============================================================ */

function PageHeader({
  refreshing,
  onRefresh,
  isAdmin,
}: {
  refreshing: boolean;
  onRefresh: () => void;
  isAdmin?: boolean;
}) {
  return (
    <div className="flex items-end justify-between gap-4 flex-wrap">
      <div>
        <h1 className="text-display-md font-medium text-ink">Response</h1>
        <p className="mt-1 text-sm text-ink-subtle">
          Autonomous-response control — mode, allowlist, policy, and the action queue.
          {isAdmin === false && ' Read-only view.'}
        </p>
      </div>
      <button
        onClick={onRefresh}
        disabled={refreshing}
        className="inline-flex items-center gap-2 text-xs text-ink-muted hover:text-ink px-3 py-1.5 rounded-soft border border-surface-border bg-surface-card transition-colors duration-200 ease-crisp"
      >
        <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
        {refreshing ? 'Syncing' : 'Refresh'}
      </button>
    </div>
  );
}

function ToggleSwitch({
  on,
  disabled,
  onClick,
  title,
}: {
  on: boolean;
  disabled?: boolean;
  onClick: () => void;
  title?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`relative inline-flex h-5 w-9 items-center rounded-pill border transition-colors duration-200 ease-crisp disabled:opacity-40 disabled:cursor-not-allowed ${
        on
          ? 'bg-accent-quiet border-accent-border/60'
          : 'bg-surface-base border-surface-border'
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 rounded-pill transition-transform duration-200 ease-crisp ${
          on ? 'translate-x-4 bg-accent' : 'translate-x-0.5 bg-ink-dim'
        }`}
      />
    </button>
  );
}
