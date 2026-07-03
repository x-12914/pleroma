"""Idempotent startup seeding for the response system.

Ensures the singleton enforcement_state row exists (safe-by-default: dry_run),
seeds the allowlist with never-block defaults + the operator's admin CIDRs, and
installs a small set of sensible default policy rules. Called from
app.db.database.init_db(); safe to run on every boot.
"""
from __future__ import annotations

import socket

from app.core.config import settings


def _detect_own_ipv4s() -> list[str]:
    """Best-effort list of the box's own IPv4 addresses, so it never blocks its
    own traffic. Uses a routing lookup (no packets sent) + hostname resolution."""
    ips: set[str] = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no data sent — just resolves the outbound iface
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    return sorted(ip for ip in ips if ip and not ip.startswith("127."))

# Loopback is also covered by guards._NEVER_BLOCK, but seeding it makes the
# allowlist self-documenting in the UI.
_DEFAULT_ALLOWLIST = [
    ("127.0.0.0/8", "loopback (never block)"),
    ("::1/128", "loopback v6 (never block)"),
]

# Default policy rules. All harmless while the system is in dry_run (they only
# produce would_apply audit rows).
#
# IMPORTANT tuning note (repeat_count vs dedup): policy.repeat_count() counts
# detection_logs rows, but ingest dedups to ~1 row per (sensor, src_ip, raw_class)
# per 10 min. So min_repeats effectively counts *distinct 10-min buckets* within
# `window_seconds` — a rule with window <= 600 can never exceed a count of ~1.
# Hence the scan rules use window_seconds=3600 (up to ~6 buckets/hr) with a low
# min_repeats. Also note the live diagnostic: scan traffic is a long tail of
# ~12.7k distinct IPs each hitting infrequently, so per-IP repeat-counting only
# catches the *persistent* scanners. These seeds are a STARTING POINT to generate
# dry-run data; tune them (or move to block-on-first-probe / subnet aggregation /
# a dedicated counter table) from observed `response_actions` once deployed.
_DEFAULT_POLICIES = [
    dict(name="Alert on Malicious verdicts", enabled=True, priority=100,
         match_raw_class=None, match_verdict="Malicious", min_confidence=0.0,
         min_repeats=1, window_seconds=600, action="alert", action_params=None,
         mode_override=None),
    dict(name="Block repeat port scanners (ScanProbe)", enabled=True, priority=50,
         match_raw_class="ScanProbe-heuristic", match_verdict=None, min_confidence=0.0,
         min_repeats=2, window_seconds=3600, action="block",
         action_params={"ttl_seconds": 3600}, mode_override=None),
    dict(name="Block repeat PortScan", enabled=True, priority=50,
         match_raw_class="PortScan", match_verdict=None, min_confidence=0.0,
         min_repeats=2, window_seconds=3600, action="block",
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
    if settings.RESPONSE_AUTOALLOWLIST_OWN_IP:
        for ip in _detect_own_ipv4s():
            seeds.append((f"{ip}/32", "auto-detected: box's own IP (never block self)"))
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
