"""Decision / policy engine (Agent B).

Turns a `DetectionEvent` (built at ingest, post-predict) into an
`ActionDecision` by walking the operator-configured `policy_rules` table. This
layer is pure decision-making: it only READS the DB (rules, state, prior
detections) and never touches the firewall — `service.record_decision` persists
the resulting `response_actions` row and the reconciler (Agent A) picks up the
`active` ones separately.

Safe-by-default invariants (see docs/CONTRACTS.md §3):
  - allowlisted / unparseable / never-block IPs are dropped here (fail fast);
    the adapter re-checks (fail safe).
  - mode authority order: kill_switch (force OFF) > enforcement_state.mode,
    unless a matching rule sets an explicit mode_override.
  - a resolved mode of OFF means "do nothing" -> return None.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func

from app.core.config import settings
from app.db.models import DetectionLog, EnforcementState, PolicyRule
from app.services.response import guards
from app.services.response.types import ActionDecision, ActionType, DetectionEvent, Mode


def repeat_count(db, src_ip: str, raw_class: str, window_seconds: int) -> int:
    """Count how many times this (src_ip, raw_class) has been logged recently.

    This is the scan-noise control: a single short probe should only alert,
    while an IP that repeats N times in the window escalates to throttle/block.

    We count DetectionLog rows in the NETWORK_TRAFFIC category whose JSONB
    report_data matches the source IP and raw class within the window.

    NOTE: detection_logs has a 10-minute per-(sensor, src_ip, raw_class) dedup
    at ingest, so for windows around/under 10 minutes this is an UNDERCOUNT-
    leaning proxy (repeated identical events inside the dedup window collapse to
    one row). That biases the engine toward *under*-escalation, which is the safe
    direction for v1. A dedicated counter table is the future fix (CONTRACTS.md
    open questions).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    # report_data->>'key' extracts the JSONB value as text, matching how ingest
    # stores src_ip / raw_class inside the report blob.
    return (
        db.query(func.count(DetectionLog.id))
        .filter(
            DetectionLog.category == "NETWORK_TRAFFIC",
            DetectionLog.report_data["src_ip"].astext == src_ip,
            DetectionLog.report_data["raw_class"].astext == raw_class,
            DetectionLog.timestamp > cutoff,
        )
        .scalar()
        or 0
    )


def _rule_matches(db, rule: PolicyRule, event: DetectionEvent) -> bool:
    """True if every condition on `rule` holds for `event`.

    NULL match_* fields are wildcards. Confidence and repeat thresholds must both
    be met; repeat_count is only computed once the cheaper checks pass (it hits
    the DB).
    """
    if rule.match_raw_class is not None and rule.match_raw_class != event.raw_class:
        return False
    if rule.match_verdict is not None and rule.match_verdict != event.verdict:
        return False
    if event.confidence < (rule.min_confidence or 0.0):
        return False
    # min_repeats defaults to 1; with the default, any single event qualifies and
    # we still run the (cheap, indexed) count for consistency.
    count = repeat_count(db, event.src_ip, event.raw_class, rule.window_seconds)
    if count < (rule.min_repeats or 1):
        return False
    return True


def resolve_mode(state: Optional[EnforcementState], rule: PolicyRule) -> str:
    """Resolve the effective mode for a matched rule.

    Authority order (CONTRACTS.md invariant #1):
      kill_switch (force OFF) > rule.mode_override > state.mode.
    Defensive: if the singleton state row is somehow missing, fall back to the
    configured safe default mode.
    """
    if state is not None and state.kill_switch:
        return Mode.OFF
    if rule.mode_override:
        return rule.mode_override
    if state is not None and state.mode:
        return state.mode
    return settings.RESPONSE_DEFAULT_MODE


def _default_params(action: str) -> dict:
    """Sensible action_params when a rule leaves them unset."""
    if action in ActionType.ENFORCED:
        # block / throttle always need a TTL so every action auto-expires
        # (invariant #3: always reversible).
        return {"ttl_seconds": settings.RESPONSE_DEFAULT_BLOCK_TTL_SECONDS}
    return {}


def decide(event: DetectionEvent, db) -> Optional[ActionDecision]:
    """Decide what (if anything) to do about a detection event.

    Returns None when no action should be taken: missing/allowlisted IP, no
    matching rule, or a resolved mode of OFF. Otherwise returns the
    ActionDecision for the FIRST matching enabled rule (priority asc, id asc).
    """
    # 1. Fail-fast safety: never act without a usable, non-protected source IP.
    if event.src_ip is None or guards.is_allowlisted(event.src_ip, db):
        return None

    # Singleton enforcement_state row (bootstrap ensures it exists; resolve_mode
    # is defensive if it doesn't).
    state = db.query(EnforcementState).first()

    # 2. Enabled rules, lowest priority first, then id for a stable tiebreak.
    rules = (
        db.query(PolicyRule)
        .filter(PolicyRule.enabled.is_(True))
        .order_by(PolicyRule.priority.asc(), PolicyRule.id.asc())
        .all()
    )

    for rule in rules:
        if not _rule_matches(db, rule, event):
            continue

        # 3. Resolve mode; OFF means "do nothing" even though a rule matched.
        resolved_mode = resolve_mode(state, rule)
        if resolved_mode == Mode.OFF:
            return None

        params = rule.action_params or _default_params(rule.action)

        # Human-readable reason for the audit trail / UI.
        reason = (
            f"Rule '{rule.name}' (#{rule.id}) matched {event.raw_class}"
            f"/{event.verdict} from {event.src_ip} "
            f"(confidence {event.confidence:.2f}); action={rule.action}, "
            f"mode={resolved_mode}."
        )

        return ActionDecision(
            action_type=rule.action,
            params=params,
            rule_id=rule.id,
            mode=resolved_mode,
            reason=reason,
        )

    # No rule matched.
    return None
