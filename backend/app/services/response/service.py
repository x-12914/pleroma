"""Persistence + lifecycle for the response system (Agent B).

Everything here is DB-only: it writes/reads `response_actions`,
`enforcement_state`, `allowlist`, and `policy_rules`. It NEVER calls the
enforcement adapter or reconciler — the reconciler (Agent A) discovers `active`
rows on its own pass and applies/removes them at the firewall. Keeping the web
backend (user `opt`) firewall-free is a hard safety boundary (CONTRACTS.md §2).

Status mapping (CONTRACTS.md §1 lifecycle):
  dry_run   -> would_apply   (logged, never enforced)
  recommend -> pending       (awaits operator approve/reject)
  auto      -> active        (reconciler applies, then expires/reverts)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Allowlist, EnforcementState, PolicyRule, ResponseAction
from app.services.response.types import (
    ActionDecision,
    ActionStatus,
    ActionType,
    DetectionEvent,
    Mode,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- status mapping -------------------------------------------------------

# Mode -> the status a freshly recorded decision gets. Anything not enforced
# (alert/host) still follows the same status; the reconciler simply ignores
# non-enforced action types.
_MODE_TO_STATUS = {
    Mode.DRY_RUN: ActionStatus.WOULD_APPLY,
    Mode.RECOMMEND: ActionStatus.PENDING,
    Mode.AUTO: ActionStatus.ACTIVE,
}

# The mode value stored on the row (CONTRACTS.md §1: dry_run|auto|manual). We
# collapse recommend's *decision* into the row mode it operates under; the
# distinct status (pending) carries the recommend semantics.
_DECISION_ROW_MODE = {
    Mode.DRY_RUN: "dry_run",
    Mode.RECOMMEND: "dry_run",  # recommended-but-unapplied = no firewall change yet
    Mode.AUTO: "auto",
}


def _ttl_seconds(params: Optional[dict]) -> int:
    """TTL for an enforced action, defaulting to the configured block TTL.

    Every enforced action carries a TTL so it auto-expires (invariant #3:
    always reversible — no permanent state).
    """
    if params and isinstance(params.get("ttl_seconds"), (int, float)):
        return int(params["ttl_seconds"])
    return settings.RESPONSE_DEFAULT_BLOCK_TTL_SECONDS


def record_decision(
    db: Session, event: DetectionEvent, decision: ActionDecision
) -> ResponseAction:
    """Persist a decision as a response_actions row (audit + work queue).

    Records dry_run "would-have" actions too (invariant #4: fully audited). For
    enforced actions that start `active` we set expires_at now so the reconciler
    can expire them even if it never re-touches the row.
    """
    status = _MODE_TO_STATUS.get(decision.mode, ActionStatus.WOULD_APPLY)
    row_mode = _DECISION_ROW_MODE.get(decision.mode, "dry_run")

    # alert is purely informational: still recorded for audit, but the reconciler
    # ignores it (it only enforces block/throttle). No expiry needed.
    is_enforced = decision.action_type in ActionType.ENFORCED

    expires_at = None
    if is_enforced and status == ActionStatus.ACTIVE:
        expires_at = _now() + timedelta(seconds=_ttl_seconds(decision.params))

    action = ResponseAction(
        ts=_now(),
        src_ip=event.src_ip,
        action_type=decision.action_type,
        params=decision.params,
        reason=decision.reason,
        raw_class=event.raw_class,
        confidence=event.confidence,
        triggering_log_id=event.triggering_log_id,
        policy_rule_id=decision.rule_id,
        mode=row_mode,
        status=status,
        expires_at=expires_at,
        created_by="auto",
        audit={"recorded_at": _now().isoformat(), "decision_mode": decision.mode},
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


# --- enforcement state ----------------------------------------------------

def get_state(db: Session) -> EnforcementState:
    """Return the singleton enforcement_state row.

    Bootstrap normally creates it; we recreate defensively (safe-by-default
    dry_run) so callers never get None.
    """
    state = db.query(EnforcementState).first()
    if state is None:
        state = EnforcementState(
            mode=settings.RESPONSE_DEFAULT_MODE,
            kill_switch=False,
            updated_by="auto-bootstrap",
        )
        db.add(state)
        db.commit()
        db.refresh(state)
    return state


def set_state(
    db: Session, mode: str, kill_switch: bool, updated_by: str
) -> EnforcementState:
    """Update the singleton enforcement_state (mode + kill_switch)."""
    state = get_state(db)
    state.mode = mode
    state.kill_switch = kill_switch
    state.updated_by = updated_by
    db.add(state)
    db.commit()
    db.refresh(state)
    return state


# --- actions: query + lifecycle transitions -------------------------------

def list_actions(
    db: Session, status: Optional[str] = None, limit: int = 100
) -> list[ResponseAction]:
    """List response_actions (newest first), optionally filtered by status."""
    q = db.query(ResponseAction)
    if status is not None:
        q = q.filter(ResponseAction.status == status)
    return q.order_by(ResponseAction.ts.desc()).limit(limit).all()


def _get_action(db: Session, action_id: int) -> Optional[ResponseAction]:
    return db.query(ResponseAction).filter(ResponseAction.id == action_id).first()


def _append_audit(action: ResponseAction, **entries) -> None:
    """Merge fields into the JSONB audit blob without dropping prior context.

    Reassigns the attribute (rather than mutating in place) so SQLAlchemy detects
    the change on a plain JSONB column.
    """
    audit = dict(action.audit or {})
    audit.update(entries)
    action.audit = audit


def approve(db: Session, action_id: int, user_email: str) -> ResponseAction:
    """Operator approves a pending recommendation: pending -> active.

    Sets expires_at for enforced actions so the reconciler can expire them.
    `created_by` stays 'auto' (the decision origin); the approver is recorded in
    the audit trail. Raises ValueError if the action doesn't exist or isn't
    pending.
    """
    action = _get_action(db, action_id)
    if action is None:
        raise ValueError(f"Action {action_id} not found")
    if action.status != ActionStatus.PENDING:
        raise ValueError(
            f"Action {action_id} is '{action.status}', not pending — cannot approve"
        )

    action.status = ActionStatus.ACTIVE
    if action.action_type in ActionType.ENFORCED and action.expires_at is None:
        action.expires_at = _now() + timedelta(seconds=_ttl_seconds(action.params))
    _append_audit(action, approved_by=f"analyst:{user_email}", approved_at=_now().isoformat())
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


def reject(db: Session, action_id: int, user_email: str) -> ResponseAction:
    """Operator declines a pending recommendation: pending -> rejected."""
    action = _get_action(db, action_id)
    if action is None:
        raise ValueError(f"Action {action_id} not found")
    if action.status != ActionStatus.PENDING:
        raise ValueError(
            f"Action {action_id} is '{action.status}', not pending — cannot reject"
        )

    action.status = ActionStatus.REJECTED
    _append_audit(action, rejected_by=f"analyst:{user_email}", rejected_at=_now().isoformat())
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


def revert(db: Session, action_id: int, user_email: str) -> ResponseAction:
    """Operator undoes an active action: active -> reverted.

    Only flips the row's status + records who/when; the reconciler removes it
    from the firewall on its next pass (the backend never touches the firewall).
    """
    action = _get_action(db, action_id)
    if action is None:
        raise ValueError(f"Action {action_id} not found")
    if action.status != ActionStatus.ACTIVE:
        raise ValueError(
            f"Action {action_id} is '{action.status}', not active — cannot revert"
        )

    action.status = ActionStatus.REVERTED
    action.reverted_at = _now()
    _append_audit(action, reverted_by=f"analyst:{user_email}", reverted_at=_now().isoformat())
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


# --- allowlist CRUD -------------------------------------------------------

def list_allowlist(db: Session) -> list[Allowlist]:
    return db.query(Allowlist).order_by(Allowlist.id.asc()).all()


def add_allowlist(
    db: Session, cidr: str, reason: Optional[str], created_by: str
) -> Allowlist:
    """Add a CIDR to the allowlist. Raises ValueError on a duplicate cidr."""
    existing = db.query(Allowlist).filter(Allowlist.cidr == cidr).first()
    if existing is not None:
        raise ValueError(f"Allowlist entry for '{cidr}' already exists")
    entry = Allowlist(cidr=cidr, reason=reason, created_by=created_by)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def delete_allowlist(db: Session, allowlist_id: int) -> None:
    """Delete an allowlist entry. Raises ValueError if not found."""
    entry = db.query(Allowlist).filter(Allowlist.id == allowlist_id).first()
    if entry is None:
        raise ValueError(f"Allowlist entry {allowlist_id} not found")
    db.delete(entry)
    db.commit()


# --- policy rule CRUD -----------------------------------------------------

def list_policies(db: Session) -> list[PolicyRule]:
    """List policy rules in evaluation order (priority asc, id asc)."""
    return (
        db.query(PolicyRule)
        .order_by(PolicyRule.priority.asc(), PolicyRule.id.asc())
        .all()
    )


def create_policy(db: Session, **fields) -> PolicyRule:
    """Create a policy rule from validated field values."""
    rule = PolicyRule(**fields)
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def update_policy(db: Session, rule_id: int, **fields) -> PolicyRule:
    """Patch a policy rule. Only keys present in `fields` are changed.

    Raises ValueError if the rule doesn't exist.
    """
    rule = db.query(PolicyRule).filter(PolicyRule.id == rule_id).first()
    if rule is None:
        raise ValueError(f"Policy rule {rule_id} not found")
    for key, value in fields.items():
        setattr(rule, key, value)
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def delete_policy(db: Session, rule_id: int) -> None:
    """Delete a policy rule. Raises ValueError if not found."""
    rule = db.query(PolicyRule).filter(PolicyRule.id == rule_id).first()
    if rule is None:
        raise ValueError(f"Policy rule {rule_id} not found")
    db.delete(rule)
    db.commit()
