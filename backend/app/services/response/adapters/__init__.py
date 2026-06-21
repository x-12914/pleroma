"""Enforcement adapter package + factory (Agent A).

``get_adapter`` is the single place the rest of the system asks for an
enforcement backend. It maps the per-tenant config string to a concrete adapter
and — crucially — falls back to the always-safe DryRunAdapter on any unknown
name. Safe-by-default (CONTRACTS invariant #1): a typo in config must never
arm a real firewall, and it must never crash the reconciler at startup.
"""
from __future__ import annotations

import logging

from app.core.config import settings
from app.services.response.adapters.base import EnforcementAdapter
from app.services.response.adapters.dryrun import DryRunAdapter
from app.services.response.adapters.nftables import NftablesAdapter

logger = logging.getLogger(__name__)

# name -> adapter class. Add iptables/firewalld/cloud here as they ship.
_ADAPTERS: dict[str, type[EnforcementAdapter]] = {
    "dryrun": DryRunAdapter,
    "nftables": NftablesAdapter,
}


def get_adapter(name: str | None = None) -> EnforcementAdapter:
    """Return an enforcement adapter instance.

    ``name`` defaults to settings.RESPONSE_ENFORCEMENT_ADAPTER. An unknown or
    empty name logs a warning and falls back to DryRunAdapter so we fail closed
    (no enforcement) rather than open (wrong/no protection or a crash).
    """
    chosen = (name or settings.RESPONSE_ENFORCEMENT_ADAPTER or "dryrun").strip().lower()
    adapter_cls = _ADAPTERS.get(chosen)
    if adapter_cls is None:
        logger.warning(
            "Unknown enforcement adapter %r; falling back to DryRunAdapter", chosen
        )
        adapter_cls = DryRunAdapter
    return adapter_cls()


__all__ = [
    "EnforcementAdapter",
    "DryRunAdapter",
    "NftablesAdapter",
    "get_adapter",
]
