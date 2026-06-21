"""Autonomous response subsystem (Phase 2).

Layers (see docs/CONTRACTS.md):
  - types.py      shared value objects / string enums (dependency-light seam)
  - bootstrap.py  idempotent startup seeding (state, allowlist, default policy)
  - policy.py     decision engine: DetectionEvent -> ActionDecision        [Agent B]
  - service.py    record decisions, approve/reject/revert helpers           [Agent B]
  - adapters/     pluggable enforcement backends (dryrun, nftables, ...)    [Agent A]
  - reconciler.py root-owned loop that applies/expires actions              [Agent A]

Safe-by-default: ships in dry_run; nothing touches the firewall until an
operator explicitly enables auto AND a non-dryrun adapter is configured.
"""
