"""Autonomous-response API (Agent B), CONTRACTS.md §5.

Admin-gated control plane for the response system: read/set global mode + kill
switch, manage the allowlist and policy rules, and review/approve/reject/revert
recorded actions. Read endpoints are analyst+; every mutation is admin-only.

This router is a thin HTTP layer over `services.response.service` — it validates
input (mode/action against the contract enums), maps service ValueErrors to 400,
and missing ids to 404.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.schemas import (
    AllowlistCreate,
    AllowlistOut,
    PolicyRuleCreate,
    PolicyRuleOut,
    PolicyRuleUpdate,
    ResponseActionOut,
    StateOut,
    StateUpdate,
)
from app.services.response import service
from app.services.response.types import ActionStatus, ActionType, Mode
from app.utils.dependencies import get_current_admin, get_current_analyst

router = APIRouter(prefix="/response", tags=["Response"])


# --- validation helpers ---------------------------------------------------

def _validate_mode(mode: str) -> None:
    if mode not in Mode.ALL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid mode '{mode}'. Allowed: {', '.join(Mode.ALL)}",
        )


def _validate_action(action: str) -> None:
    if action not in ActionType.ALL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action '{action}'. Allowed: {', '.join(ActionType.ALL)}",
        )


def _validate_status(status_filter: Optional[str]) -> None:
    if status_filter is not None and status_filter not in ActionStatus.ALL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{status_filter}'. Allowed: {', '.join(ActionStatus.ALL)}",
        )


# --- enforcement state ----------------------------------------------------

@router.get("/state", response_model=StateOut)
def get_state(
    current_user=Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    """Current global mode + kill switch."""
    return service.get_state(db)


@router.put("/state", response_model=StateOut)
def update_state(
    payload: StateUpdate,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Set the global mode and kill switch (admin only)."""
    _validate_mode(payload.mode)
    return service.set_state(
        db,
        mode=payload.mode,
        kill_switch=payload.kill_switch,
        updated_by=f"analyst:{current_user.email}",
    )


# --- allowlist ------------------------------------------------------------

@router.get("/allowlist", response_model=list[AllowlistOut])
def list_allowlist(
    current_user=Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    """All allowlist (never-act) CIDRs."""
    return service.list_allowlist(db)


@router.post("/allowlist", response_model=AllowlistOut, status_code=status.HTTP_201_CREATED)
def add_allowlist(
    payload: AllowlistCreate,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Add a CIDR the response system must never act on (admin only)."""
    try:
        return service.add_allowlist(
            db,
            cidr=payload.cidr,
            reason=payload.reason,
            created_by=f"analyst:{current_user.email}",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.delete("/allowlist/{allowlist_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_allowlist(
    allowlist_id: int,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Remove an allowlist entry (admin only)."""
    try:
        service.delete_allowlist(db, allowlist_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# --- policy rules ---------------------------------------------------------

@router.get("/policy", response_model=list[PolicyRuleOut])
def list_policy(
    current_user=Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    """All policy rules in evaluation order (priority asc, id asc)."""
    return service.list_policies(db)


@router.post("/policy", response_model=PolicyRuleOut, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyRuleCreate,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Create a policy rule (admin only)."""
    _validate_action(payload.action)
    if payload.mode_override is not None:
        _validate_mode(payload.mode_override)
    return service.create_policy(db, **payload.model_dump())


@router.put("/policy/{rule_id}", response_model=PolicyRuleOut)
def update_policy(
    rule_id: int,
    payload: PolicyRuleUpdate,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Patch a policy rule (admin only). Only supplied fields change."""
    # exclude_unset so an omitted field isn't overwritten with None.
    fields = payload.model_dump(exclude_unset=True)
    if "action" in fields and fields["action"] is not None:
        _validate_action(fields["action"])
    if "mode_override" in fields and fields["mode_override"] is not None:
        _validate_mode(fields["mode_override"])
    try:
        return service.update_policy(db, rule_id, **fields)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.delete("/policy/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    rule_id: int,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Delete a policy rule (admin only)."""
    try:
        service.delete_policy(db, rule_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# --- actions: audit + lifecycle ------------------------------------------

@router.get("/actions", response_model=list[ResponseActionOut])
def list_actions(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=1000),
    current_user=Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    """Recorded actions (audit + would-have view), newest first.

    Optional ?status= filters to a single lifecycle state.
    """
    _validate_status(status_filter)
    return service.list_actions(db, status=status_filter, limit=limit)


@router.post("/actions/{action_id}/approve", response_model=ResponseActionOut)
def approve_action(
    action_id: int,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Approve a pending recommendation: pending -> active (admin only)."""
    return _transition(service.approve, db, action_id, current_user.email)


@router.post("/actions/{action_id}/reject", response_model=ResponseActionOut)
def reject_action(
    action_id: int,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Reject a pending recommendation: pending -> rejected (admin only)."""
    return _transition(service.reject, db, action_id, current_user.email)


@router.post("/actions/{action_id}/revert", response_model=ResponseActionOut)
def revert_action(
    action_id: int,
    current_user=Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Revert an active action: active -> reverted (admin only).

    The reconciler removes it from the firewall on its next pass.
    """
    return _transition(service.revert, db, action_id, current_user.email)


def _transition(fn, db: Session, action_id: int, user_email: str):
    """Run a service lifecycle transition, mapping its ValueError.

    The service raises ValueError both for missing ids and invalid state
    transitions; we distinguish them so the client gets 404 vs 400 per §5.
    """
    try:
        return fn(db, action_id, user_email)
    except ValueError as exc:
        message = str(exc)
        if "not found" in message:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
