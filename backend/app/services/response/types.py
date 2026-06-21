"""Shared contract types for the autonomous response system.

The stable seam every layer (enforcement, policy, API) builds against. Keep this
stdlib-only so any layer can import it without pulling in heavy deps.
See docs/CONTRACTS.md for the authoritative specification.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


# --- String enums (stored as plain strings in the DB, matching the codebase
#     convention used for user.role / analysis_task.status) ---

class Mode:
    OFF = "off"
    DRY_RUN = "dry_run"
    RECOMMEND = "recommend"
    AUTO = "auto"
    ALL = (OFF, DRY_RUN, RECOMMEND, AUTO)


class ActionType:
    BLOCK = "block"
    THROTTLE = "throttle"
    ALERT = "alert"
    HOST = "host"
    ALL = (BLOCK, THROTTLE, ALERT, HOST)
    # Actions that touch traffic at the firewall (handled by the reconciler/adapter).
    ENFORCED = (BLOCK, THROTTLE)


class ActionStatus:
    WOULD_APPLY = "would_apply"   # dry_run: logged, never touches the firewall
    PENDING = "pending"           # recommend: awaiting operator approval
    ACTIVE = "active"             # applied (or queued to apply) at the firewall
    EXPIRED = "expired"           # TTL elapsed, removed
    REVERTED = "reverted"         # manually undone
    REJECTED = "rejected"         # operator declined a recommendation
    FAILED = "failed"             # adapter error on apply
    ALL = (WOULD_APPLY, PENDING, ACTIVE, EXPIRED, REVERTED, REJECTED, FAILED)


# --- Enforcement adapter value objects (Agent A) ---

@dataclass
class ActionResult:
    ok: bool
    detail: str = ""


@dataclass
class ActiveEntry:
    ip: str
    action_type: str
    expires_at: Optional[datetime] = None


@dataclass
class AdapterHealth:
    ok: bool
    backend: str
    detail: str = ""


# --- Policy engine value objects (Agent B) ---

@dataclass
class DetectionEvent:
    """Built at ingest, post-predict, and handed to the policy engine."""
    src_ip: Optional[str]
    raw_class: str
    verdict: str
    confidence: float
    ts: datetime
    sensor_id: Optional[int] = None
    dst_port: Optional[int] = None
    triggering_log_id: Optional[int] = None


@dataclass
class ActionDecision:
    action_type: str
    params: dict
    rule_id: Optional[int]
    mode: str
    reason: str
