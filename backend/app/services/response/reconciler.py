"""Reconciler — the root-owned loop that makes the firewall match the DB (Agent A).

CONTRACTS §2: the web backend (user ``opt``) NEVER touches the firewall. It only
writes ``response_actions`` rows. This service — running as root so it can call
``nft`` — is the only thing that mutates real enforcement state. It continuously
drives the firewall toward the DB's intent:

  (a) APPLY   active+unapplied rows  -> push to firewall (re-checking allowlist)
  (b) EXPIRE  active rows past TTL   -> remove from firewall, mark expired
  (c) REVERT  reverted rows          -> remove from firewall (operator undid it)
  (d) DRIFT   firewall entries with  -> remove (recover from manual edits /
              no backing active row     reconciler downtime / box restart)

Everything is convergent and idempotent: a missed cycle, a crash, or a manual
``nft`` edit is healed on the next ``run_once``. ``run_once`` is the unit-testable
core (pass it a db + adapter); ``main`` is the production loop.

Only ActionType.ENFORCED actions (block/throttle) are handled here — ``alert``
and ``host`` never touch traffic, so the reconciler ignores them entirely.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from app.core.config import settings
from app.db.database import SessionLocal
from app.services.response import guards
from app.services.response.adapters import get_adapter
from app.services.response.adapters.base import EnforcementAdapter
from app.services.response.types import ActionResult, ActionStatus, ActionType
from app.db.models import ResponseAction

logger = logging.getLogger(__name__)


def _now() -> datetime:
    """UTC-aware now (DB timestamps are timezone=True)."""
    return datetime.now(timezone.utc)


def _apply_one(action: ResponseAction, adapter: EnforcementAdapter):
    """Dispatch an apply to the right adapter method based on action_type.

    Returns the ActionResult. TTL comes from params, falling back to the
    configured default; throttle additionally needs a ``rate``.
    """
    params = action.params or {}
    ttl = int(params.get("ttl_seconds") or settings.RESPONSE_DEFAULT_BLOCK_TTL_SECONDS)

    if action.action_type == ActionType.BLOCK:
        return adapter.apply_block(action.src_ip, ttl)
    if action.action_type == ActionType.THROTTLE:
        rate = str(params.get("rate") or "10/s")
        return adapter.apply_throttle(action.src_ip, rate, ttl)
    # Defensive: should be filtered out by the ENFORCED query, but never trust it.
    return ActionResult(ok=False, detail=f"unhandled action_type {action.action_type!r}")


def _remove_one(action: ResponseAction, adapter: EnforcementAdapter):
    """Dispatch a removal to the right adapter method based on action_type."""
    if action.action_type == ActionType.BLOCK:
        return adapter.remove_block(action.src_ip)
    if action.action_type == ActionType.THROTTLE:
        return adapter.remove_throttle(action.src_ip)
    return ActionResult(ok=False, detail=f"unhandled action_type {action.action_type!r}")


def run_once(db, adapter: EnforcementAdapter) -> dict:
    """One reconciliation pass. Returns counts for observability/tests.

    Safe to call repeatedly; each phase is independent and idempotent. We commit
    once at the end so a crash mid-pass leaves the DB unchanged and the next
    pass simply redoes the work.
    """
    counts = {"applied": 0, "expired": 0, "reverted": 0, "drift_removed": 0, "failed": 0}
    now = _now()

    # Only the two traffic-affecting action types are our concern.
    enforced = list(ActionType.ENFORCED)

    # --- (a) APPLY: active rows not yet pushed to the firewall ------------
    to_apply = (
        db.query(ResponseAction)
        .filter(
            ResponseAction.status == ActionStatus.ACTIVE,
            ResponseAction.action_type.in_(enforced),
            ResponseAction.applied_at.is_(None),
        )
        .all()
    )
    for action in to_apply:
        # Fail-safe re-check: the allowlist may have changed since the row was
        # written. Duplicates the policy-engine check on purpose (CONTRACTS #2).
        if guards.is_allowlisted(action.src_ip, db):
            action.status = ActionStatus.FAILED
            action.error = "allowlisted"
            counts["failed"] += 1
            logger.warning("Refusing to apply %s on allowlisted IP %s", action.id, action.src_ip)
            continue
        result = _apply_one(action, adapter)
        if result.ok:
            action.applied_at = now
            counts["applied"] += 1
            logger.info("Applied action %s (%s %s)", action.id, action.action_type, action.src_ip)
        else:
            action.status = ActionStatus.FAILED
            action.error = result.detail
            counts["failed"] += 1
            logger.error("Apply failed for action %s: %s", action.id, result.detail)

    # --- (b) EXPIRE: active rows past their TTL ---------------------------
    to_expire = (
        db.query(ResponseAction)
        .filter(
            ResponseAction.status == ActionStatus.ACTIVE,
            ResponseAction.action_type.in_(enforced),
            ResponseAction.expires_at.isnot(None),
            ResponseAction.expires_at < now,
        )
        .all()
    )
    for action in to_expire:
        result = _remove_one(action, adapter)
        # Even if the adapter removal reports a problem we still mark expired:
        # nftables auto-expires elements itself, so the DB intent (no longer
        # enforced) is authoritative and we don't want a stuck "active" row.
        action.status = ActionStatus.EXPIRED
        if not result.ok:
            action.error = f"expire-remove: {result.detail}"
            logger.warning("Expire-remove issue for action %s: %s", action.id, result.detail)
        counts["expired"] += 1
        logger.info("Expired action %s (%s %s)", action.id, action.action_type, action.src_ip)

    # --- (c) REVERTED cleanup: operator undid it, still on firewall -------
    # Reverted rows were applied (applied_at set) but not yet torn down. Only
    # those still enforced (applied_at set, reverted_at maybe set by the API)
    # need a removal call; the removal is idempotent so re-running is harmless.
    to_revert = (
        db.query(ResponseAction)
        .filter(
            ResponseAction.status == ActionStatus.REVERTED,
            ResponseAction.action_type.in_(enforced),
            ResponseAction.applied_at.isnot(None),
        )
        .all()
    )
    for action in to_revert:
        result = _remove_one(action, adapter)
        if result.ok:
            # Mark it torn down so we don't keep re-issuing removals every cycle.
            action.applied_at = None
            counts["reverted"] += 1
            logger.info("Reverted action %s removed from firewall (%s)", action.id, action.src_ip)
        else:
            action.error = f"revert-remove: {result.detail}"
            logger.warning("Revert-remove failed for action %s: %s", action.id, result.detail)

    # --- (d) DRIFT: firewall entries with no backing active row ----------
    # Recover from manual edits, a reconciler restart, or a box reboot. Anything
    # the firewall enforces that we have no ACTIVE+applied row for is removed.
    active_ips = {
        ip
        for (ip,) in db.query(ResponseAction.src_ip)
        .filter(
            ResponseAction.status == ActionStatus.ACTIVE,
            ResponseAction.action_type.in_(enforced),
            ResponseAction.applied_at.isnot(None),
        )
        .all()
        if ip
    }
    try:
        live = adapter.list_active()
    except Exception as exc:  # adapter must never crash the loop
        live = []
        logger.error("adapter.list_active() failed: %s", exc)
    for entry in live:
        if entry.ip in active_ips:
            continue
        # Never "drift-remove" a protected IP via a block call (no-op anyway),
        # and skip ones we legitimately own.
        if entry.action_type == ActionType.THROTTLE:
            result = adapter.remove_throttle(entry.ip)
        else:
            result = adapter.remove_block(entry.ip)
        if result.ok:
            counts["drift_removed"] += 1
            logger.info("Drift: removed unbacked firewall entry %s", entry.ip)
        else:
            logger.warning("Drift removal failed for %s: %s", entry.ip, result.detail)

    db.commit()
    return counts


def main() -> None:
    """Production loop: build the configured adapter and reconcile forever."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [reconciler] %(message)s",
    )
    adapter = get_adapter()
    health = adapter.health()
    logger.info(
        "Reconciler starting: adapter=%s healthy=%s detail=%s interval=%ss",
        adapter.name, health.ok, health.detail, settings.RESPONSE_RECONCILE_INTERVAL_SECONDS,
    )
    if not health.ok:
        # Don't exit — a misconfigured/unprivileged box should keep the service
        # alive (Restart=always would just thrash) and log loudly each cycle.
        logger.error("Enforcement adapter unhealthy; actions will fail until fixed.")

    interval = max(int(settings.RESPONSE_RECONCILE_INTERVAL_SECONDS), 1)
    while True:
        db = SessionLocal()
        try:
            counts = run_once(db, adapter)
            if any(counts.values()):
                logger.info("Reconcile pass: %s", counts)
        except Exception as exc:
            # Never let one bad pass kill the loop; roll back and retry next tick.
            logger.exception("Reconcile pass crashed: %s", exc)
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            db.close()
        time.sleep(interval)


if __name__ == "__main__":
    main()
