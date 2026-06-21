"""Idempotent startup seeding for the response system.

Ensures the singleton enforcement_state row exists (safe-by-default: dry_run),
seeds the allowlist with never-block defaults + the operator's admin CIDRs, and
installs a small set of sensible default policy rules. Called from
app.db.database.init_db(); safe to run on every boot.
"""
from __future__ import annotations

from app.core.config import settings

# Loopback is also covered by guards._NEVER_BLOCK, but seeding it makes the
# allowlist self-documenting in the UI.
_DEFAULT_ALLOWLIST = [
    ("127.0.0.0/8", "loopback (never block)"),
    ("::1/128", "loopback v6 (never block)"),
]

# Default policy rules. All harmless while the system is in dry_run (they only
# produce would_apply audit rows). The scan-probe rules require many repeats in
# a window so a single stray SYN never escalates — see docs/CONTRACTS.md.
_DEFAULT_POLICIES = [
    dict(name="Alert on Malicious verdicts", enabled=True, priority=100,
         match_raw_class=None, match_verdict="Malicious", min_confidence=0.0,
         min_repeats=1, window_seconds=600, action="alert", action_params=None,
         mode_override=None),
    dict(name="Block repeat port scanners (ScanProbe)", enabled=True, priority=50,
         match_raw_class="ScanProbe-heuristic", match_verdict=None, min_confidence=0.0,
         min_repeats=10, window_seconds=600, action="block",
         action_params={"ttl_seconds": 3600}, mode_override=None),
    dict(name="Block repeat PortScan", enabled=True, priority=50,
         match_raw_class="PortScan", match_verdict=None, min_confidence=0.0,
         min_repeats=5, window_seconds=600, action="block",
         action_params={"ttl_seconds": 3600}, mode_override=None),
]


def bootstrap_response(db) -> None:
    from app.db.models import EnforcementState, Allowlist, PolicyRule  # local: avoid cycle

    # 1. Singleton enforcement_state — safe-by-default.
    if db.query(EnforcementState).first() is None:
        db.add(EnforcementState(
            mode=settings.RESPONSE_DEFAULT_MODE, kill_switch=False, updated_by="bootstrap"))
        db.commit()

    # 2. Allowlist seed (idempotent by cidr): defaults + operator admin CIDRs.
    existing = {c for (c,) in db.query(Allowlist.cidr).all()}
    seeds = list(_DEFAULT_ALLOWLIST)
    for cidr in (settings.RESPONSE_ADMIN_ALLOWLIST or "").split(","):
        cidr = cidr.strip()
        if cidr:
            seeds.append((cidr, "operator admin CIDR (RESPONSE_ADMIN_ALLOWLIST)"))
    changed = False
    for cidr, reason in seeds:
        if cidr not in existing:
            db.add(Allowlist(cidr=cidr, reason=reason, created_by="bootstrap"))
            existing.add(cidr)
            changed = True
    if changed:
        db.commit()

    # 3. Default policy rules (idempotent by name).
    existing_names = {n for (n,) in db.query(PolicyRule.name).all()}
    changed = False
    for spec in _DEFAULT_POLICIES:
        if spec["name"] not in existing_names:
            db.add(PolicyRule(**spec))
            changed = True
    if changed:
        db.commit()
