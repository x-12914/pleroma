"""Never-block guards shared by the policy engine (fail fast) and the
enforcement adapters (fail safe).

Centralizing this prevents the two layers from diverging on what is safe to act
on. The #1 risk of autonomous response is locking the operator out of their own
box, so these checks are deliberately conservative: anything unparseable or in a
protected range is treated as NOT actionable.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

# Always-protected ranges, independent of the allowlist table. Acting on any of
# these is never permitted (self-lockout / infrastructure collateral).
_NEVER_BLOCK = [
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("::1/128"),         # loopback v6
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("fe80::/10"),       # link-local v6
]


def parse_ip(ip: Optional[str]):
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip.strip())
    except ValueError:
        return None


def is_never_block(ip: Optional[str]) -> bool:
    addr = parse_ip(ip)
    if addr is None:
        return True  # unparseable -> treat as protected (never act)
    return any(addr in net for net in _NEVER_BLOCK)


def is_allowlisted(ip: Optional[str], db) -> bool:
    """True if the IP must NOT be acted on: unparseable, in a never-block range,
    or matched by any CIDR in the allowlist table."""
    if is_never_block(ip):
        return True
    addr = parse_ip(ip)
    if addr is None:
        return True
    from app.db.models import Allowlist  # local import avoids import cycle
    for (cidr,) in db.query(Allowlist.cidr).all():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
