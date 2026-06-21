# Phase 2 Contracts — Autonomous Response

_Last updated: 2026-06-21 · status: LOCKED — foundation (models, types, guards,
bootstrap, config) implemented; Agents A/B/C build against it_

These are the shared interfaces that let the parallel build-agents (A: enforcement,
B: policy, C: frontend) work without colliding. Nothing here acts on real traffic:
the system ships in `dry_run` and only an explicit operator action enables `auto`.
All of this lives in the **data plane** (customer-hosted) and is **per-tenant**.

## Design invariants (non-negotiable, enforced in code)
1. **Safe-by-default**: global mode starts `dry_run`. Order of authority:
   `kill_switch` (force OFF) > `enforcement_state.mode` > `policy_rule.mode_override`.
2. **Never self-lock-out**: the enforcement *adapter* (lowest layer) refuses to act
   on any IP in the allowlist, the box's own IPs, or the current admin/SSH source —
   even if a policy says otherwise. Allowlist check is duplicated in the policy
   engine (fail fast) and the adapter (fail safe).
3. **Always reversible**: every action carries a TTL and auto-expires; every action
   is individually revertible. No permanent state.
4. **Fully audited**: every decision and state transition is recorded, including
   `dry_run` "would-have" actions.

## 1. Database tables (per-tenant, data plane)

```
enforcement_state            -- singleton row per tenant
  id, mode ENUM(off|dry_run|recommend|auto) default 'dry_run',
  kill_switch BOOL default false, updated_at, updated_by

allowlist
  id, cidr CIDR/text, reason, created_by, created_at
  -- seeded at install with: loopback, the box's own IPs, configured admin CIDR(s)

policy_rules
  id, name, enabled BOOL, priority INT,            -- lower priority = evaluated first
  match_raw_class TEXT/NULL, match_verdict TEXT/NULL,
  min_confidence FLOAT default 0, min_repeats INT default 1, window_seconds INT default 600,
  action ENUM(block|throttle|alert|host),
  action_params JSONB,                              -- e.g. {"ttl_seconds":3600,"rate":"10/s"}
  mode_override ENUM(off|dry_run|recommend|auto)/NULL,
  created_at, updated_at

response_actions                                   -- the audit + work queue
  id, ts, src_ip, action_type ENUM(block|throttle|alert|host), params JSONB,
  reason TEXT, raw_class TEXT, confidence FLOAT,
  triggering_log_id FK->detection_logs/NULL, policy_rule_id FK->policy_rules/NULL,
  mode ENUM(dry_run|auto|manual),
  status ENUM(would_apply|pending|active|expired|reverted|rejected|failed),
  expires_at, created_by TEXT('auto'|'analyst:<email>'),
  applied_at, reverted_at, error TEXT/NULL, audit JSONB
```

Status lifecycle:
- `dry_run` decision → `would_apply` (logged, never touches firewall)
- `recommend` decision → `pending` → operator → `active` | `rejected`
- `auto` decision → `active` (reconciler applies) → `expired` | `reverted` | `failed`

## 2. Enforcement adapter interface (Agent A)

One interface, many backends. `DryRunAdapter` is the universal default.

```python
@dataclass
class ActionResult: ok: bool; detail: str
@dataclass
class ActiveEntry: ip: str; action_type: str; expires_at: datetime | None
@dataclass
class AdapterHealth: ok: bool; backend: str; detail: str

class EnforcementAdapter(ABC):
    name: str
    def apply_block(self, ip: str, ttl_seconds: int) -> ActionResult: ...
    def remove_block(self, ip: str) -> ActionResult: ...
    def apply_throttle(self, ip: str, rate: str, ttl_seconds: int) -> ActionResult: ...
    def remove_throttle(self, ip: str) -> ActionResult: ...
    def list_active(self) -> list[ActiveEntry]: ...
    def health(self) -> AdapterHealth: ...
```

Backends (ship in order): `DryRunAdapter`, `NftablesAdapter`, then
`IptablesAdapter` / `FirewalldAdapter` / `CloudSGAdapter`. Adapter is chosen by
per-tenant config; `apply_*` MUST hard-refuse allowlisted/own/admin IPs.

**Reconciler** (root-owned service, Agent A): every N seconds — (a) apply
`status=active` actions not yet on the firewall, (b) expire past-TTL entries
(`active`→`expired`, remove from firewall), (c) drop firewall entries with no
backing active row (recover from manual drift / restart). The web backend (user
`opt`) never touches the firewall directly — it only writes `response_actions`.

## 3. Decision / policy engine (Agent B)

```python
@dataclass
class DetectionEvent:                # built at ingest, post-predict
    src_ip: str|None; dst_port: int|None; raw_class: str; verdict: str
    confidence: float; ts: datetime; sensor_id: int

@dataclass
class ActionDecision:
    action_type: str; params: dict; rule_id: int; mode: str; reason: str

def decide(event) -> ActionDecision | None:
    # 1. if src_ip is None or allowlisted/own/admin -> None
    # 2. rules ordered by priority; first whose match_* + min_confidence +
    #    min_repeats-in-window all hold -> build ActionDecision
    # 3. resolve mode: kill_switch->off; else state.mode unless rule.mode_override
    # 4. write a response_actions row (would_apply / pending / active per mode)
```

`min_repeats`/`window_seconds` is the **scan-noise control** (see findings): a
single short SYN probe alerts only; an IP that repeats N times in the window
escalates to throttle/block.

## 4. Feature-contract versioning (Agent B / sensor)
- Add `FEATURE_SCHEMA_VERSION` (int) beside `feature_names.joblib`.
- Sensor includes `schema_version` in the ingest payload.
- Engine logs/rejects on mismatch instead of silently scoring skewed features.

## 5. API (data-plane backend, admin-gated) — frontend contract (Agent C)
```
GET  /api/v1/response/state                 PUT /api/v1/response/state           # mode, kill_switch
GET  /api/v1/response/allowlist             POST/DELETE /api/v1/response/allowlist
GET  /api/v1/response/policy                POST/PUT/DELETE /api/v1/response/policy
GET  /api/v1/response/actions?status=...    # audit + would-have view
POST /api/v1/response/actions/{id}/approve  # pending -> active
POST /api/v1/response/actions/{id}/reject   # pending -> rejected
POST /api/v1/response/actions/{id}/revert   # active  -> reverted
```

## Open questions for review
- Throttle mechanism on Linux (nft `limit` vs `tc`) — pick during Agent A.
- Repeat-counter source: derive from `detection_logs`/`response_actions` vs a
  dedicated counter table (perf at high flow rates).
- Admin source IP(s) for the install-time allowlist seed (needed before `auto`).
