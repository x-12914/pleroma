"""DryRunAdapter — the universal, always-safe default (Agent A).

This is what the system ships with (RESPONSE_ENFORCEMENT_ADAPTER="dryrun") and
what every deployment falls back to if a real backend can't be loaded. It never
touches the system: apply/remove just *log* what they WOULD do and report
success. ``list_active`` is always empty, so the reconciler's drift step has
nothing to remove. This lets the full pipeline — policy → response_actions →
reconciler — run end to end and produce a complete "would-have" audit trail
without any risk to traffic.
"""
from __future__ import annotations

import logging

from app.services.response.adapters.base import EnforcementAdapter
from app.services.response.types import (
    ActionResult,
    ActiveEntry,
    AdapterHealth,
)

logger = logging.getLogger(__name__)


class DryRunAdapter(EnforcementAdapter):
    """No-op adapter that only logs intended actions."""

    name = "dryrun"

    def apply_block(self, ip: str, ttl_seconds: int) -> ActionResult:
        # Self-protect even though we do nothing: keeps behaviour identical to
        # real adapters so a dry_run audit reflects what auto mode would refuse.
        refusal = self._refuse_if_never_block(ip)
        if refusal is not None:
            logger.warning("DRY-RUN refused block on protected IP %s", ip)
            return refusal
        logger.info("DRY-RUN would BLOCK %s for %ss", ip, ttl_seconds)
        return ActionResult(ok=True, detail=f"dry-run: would block {ip} for {ttl_seconds}s")

    def remove_block(self, ip: str) -> ActionResult:
        logger.info("DRY-RUN would REMOVE BLOCK on %s", ip)
        return ActionResult(ok=True, detail=f"dry-run: would remove block on {ip}")

    def apply_throttle(self, ip: str, rate: str, ttl_seconds: int) -> ActionResult:
        refusal = self._refuse_if_never_block(ip)
        if refusal is not None:
            logger.warning("DRY-RUN refused throttle on protected IP %s", ip)
            return refusal
        logger.info("DRY-RUN would THROTTLE %s to %s for %ss", ip, rate, ttl_seconds)
        return ActionResult(
            ok=True, detail=f"dry-run: would throttle {ip} to {rate} for {ttl_seconds}s"
        )

    def remove_throttle(self, ip: str) -> ActionResult:
        logger.info("DRY-RUN would REMOVE THROTTLE on %s", ip)
        return ActionResult(ok=True, detail=f"dry-run: would remove throttle on {ip}")

    def list_active(self) -> list[ActiveEntry]:
        # The dry-run backend holds no state, so nothing is ever "active" on it.
        return []

    def health(self) -> AdapterHealth:
        return AdapterHealth(ok=True, backend=self.name, detail="dry-run: no system access")
