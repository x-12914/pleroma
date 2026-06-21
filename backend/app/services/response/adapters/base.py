"""Enforcement adapter interface (Agent A) — see docs/CONTRACTS.md §2.

One interface, many backends. The reconciler talks ONLY to this ABC, so the
firewall mechanism (dryrun / nftables / iptables / cloud SG) is swappable per
tenant via RESPONSE_ENFORCEMENT_ADAPTER without touching the loop logic.

Safety invariant (CONTRACTS design invariant #2): the adapter is the *lowest*
layer and the last line of defence against self-lockout. Even though the
reconciler already runs the full DB allowlist check before calling us, every
``apply_*`` MUST independently refuse to act on a never-block IP (loopback,
link-local, unparseable). The allowlist check is deliberately duplicated:
policy engine fails fast, adapter fails safe. If one layer has a bug the other
still protects the operator.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from app.services.response import guards
from app.services.response.types import (
    ActionResult,
    ActiveEntry,
    AdapterHealth,
)


class EnforcementAdapter(ABC):
    """Abstract base for all enforcement backends.

    Concrete adapters implement the firewall-specific mechanics; the contract
    (return types, allowlist self-protection) is enforced here. ``name`` is a
    short stable identifier used in logs and AdapterHealth.backend.
    """

    #: short stable backend identifier (e.g. "dryrun", "nftables")
    name: str = "base"

    # --- helpers ----------------------------------------------------------

    @staticmethod
    def _refuse_if_never_block(ip: str) -> ActionResult | None:
        """Last-resort fail-safe shared by every concrete apply_*.

        Returns a failing ActionResult if ``ip`` is in a never-block range
        (loopback / link-local / unparseable), else None. Concrete adapters
        call this FIRST in each apply_* and bail out on a non-None result so a
        buggy/compromised upper layer can never make us lock the operator out.
        Note this is the hard, table-independent guard only; the full DB
        allowlist is checked by the reconciler before we are ever called.
        """
        if guards.is_never_block(ip):
            return ActionResult(
                ok=False,
                detail=f"refused: {ip!r} is in a protected never-block range",
            )
        return None

    # --- block ------------------------------------------------------------

    @abstractmethod
    def apply_block(self, ip: str, ttl_seconds: int) -> ActionResult:
        """Block all traffic from ``ip`` for ``ttl_seconds`` (auto-expiring)."""
        raise NotImplementedError

    @abstractmethod
    def remove_block(self, ip: str) -> ActionResult:
        """Remove an existing block on ``ip`` (idempotent: ok if not present)."""
        raise NotImplementedError

    # --- throttle ---------------------------------------------------------

    @abstractmethod
    def apply_throttle(self, ip: str, rate: str, ttl_seconds: int) -> ActionResult:
        """Rate-limit ``ip`` to ``rate`` (e.g. "10/s") for ``ttl_seconds``."""
        raise NotImplementedError

    @abstractmethod
    def remove_throttle(self, ip: str) -> ActionResult:
        """Remove an existing throttle on ``ip`` (idempotent)."""
        raise NotImplementedError

    # --- introspection ----------------------------------------------------

    @abstractmethod
    def list_active(self) -> list[ActiveEntry]:
        """Return what the firewall *actually* enforces right now.

        Source of truth for drift detection: the reconciler compares this
        against the DB's active rows and removes anything with no backing row
        (recovering from manual edits or a reconciler restart).
        """
        raise NotImplementedError

    @abstractmethod
    def health(self) -> AdapterHealth:
        """Cheap liveness/usability probe (binary present, table creatable)."""
        raise NotImplementedError
