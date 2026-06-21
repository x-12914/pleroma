"""NftablesAdapter — real Linux enforcement via the ``nft`` command (Agent A).

Strategy: we keep ONE dedicated nftables set, ``pleroma_block`` in table
``inet pleroma``, holding the IPs we currently block. Blocking == adding the
IP as a set element with a per-element ``timeout``; nftables then expires it on
its own. This gives us the CONTRACTS invariant "always reversible / auto-expire"
for free even if the reconciler is down, and keeps our rules isolated from the
operator's other firewall config (we never flush their tables).

Why a set + interval/timeout flags:
  - ``timeout``  → per-element TTL so blocks self-heal without us.
  - ``interval`` → lets the set hold ranges too (future-proofing) and is
                   required for some kernels when mixing element timeouts.

We deliberately do NOT install the actual drop rule here automatically beyond
ensuring the set + a matching rule exist (see ``_ensure_table``). The reconciler
runs as root (see deploy/pleroma-reconciler.service) so we call ``nft`` directly
with no sudo.

Throttle is intentionally NOT implemented yet (returns ok=False). Doing it
safely needs a per-IP ``limit`` construction (nft meters) whose semantics we
haven't validated against real traffic — half-implementing it could silently
fail open or lock the box. Tracked as a TODO; CONTRACTS §"Open questions" calls
this out (nft ``limit`` vs ``tc``).
"""
from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timedelta, timezone

from app.services.response.adapters.base import EnforcementAdapter
from app.services.response.types import (
    ActionResult,
    ActiveEntry,
    AdapterHealth,
)

logger = logging.getLogger(__name__)

# Our isolated namespace inside nftables. "inet" family covers both v4 and v6
# rule evaluation, but the set below is ipv4-only for now (see TODO on v6).
_TABLE_FAMILY = "inet"
_TABLE = "pleroma"
_SET = "pleroma_block"

# Hard cap on every nft invocation so a hung command can't wedge the reconciler.
_NFT_TIMEOUT_SECONDS = 5


class NftablesAdapter(EnforcementAdapter):
    """Enforce blocks through an nftables set managed by the ``nft`` binary."""

    name = "nftables"

    def __init__(self) -> None:
        # Lazily ensure the table/set exist on first use rather than at import,
        # so importing this module on a non-root / non-Linux box is harmless.
        self._ensured = False

    # --- low-level nft plumbing ------------------------------------------

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        """Run ``nft <args>`` defensively.

        Always returns a CompletedProcess (never raises): a missing binary,
        timeout, or OS error is converted into a synthetic non-zero result so
        callers can branch on ``.returncode`` uniformly. The reconciler must
        keep looping even if the firewall tool is broken.
        """
        cmd = ["nft", *args]
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_NFT_TIMEOUT_SECONDS,
                check=False,
            )
        except FileNotFoundError:
            return subprocess.CompletedProcess(cmd, 127, "", "nft binary not found")
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(cmd, 124, "", "nft command timed out")
        except OSError as exc:  # permission denied, etc.
            return subprocess.CompletedProcess(cmd, 1, "", f"nft exec error: {exc}")

    def _ensure_table(self) -> ActionResult:
        """Idempotently create table, set, and a drop rule referencing the set.

        Runs once per process (cached via ``self._ensured``) unless it fails, in
        which case we retry on the next call. ``nft add`` is idempotent for
        tables/sets/chains, so re-running is safe. We add a chain + rule so that
        membership in the set actually drops traffic; without the rule the set
        would be inert.
        """
        if self._ensured:
            return ActionResult(ok=True)

        # add table (no-op if it exists)
        r = self._run(["add", "table", _TABLE_FAMILY, _TABLE])
        if r.returncode != 0:
            return ActionResult(ok=False, detail=f"create table failed: {r.stderr.strip()}")

        # add set with interval + timeout support
        r = self._run(
            [
                "add", "set", _TABLE_FAMILY, _TABLE, _SET,
                "{", "type", "ipv4_addr", ";",
                "flags", "interval,timeout", ";", "}",
            ]
        )
        if r.returncode != 0:
            return ActionResult(ok=False, detail=f"create set failed: {r.stderr.strip()}")

        # input chain hooked at filter/priority 0 (only created if absent)
        r = self._run(
            [
                "add", "chain", _TABLE_FAMILY, _TABLE, "input",
                "{", "type", "filter", "hook", "input",
                "priority", "0", ";", "}",
            ]
        )
        if r.returncode != 0:
            return ActionResult(ok=False, detail=f"create chain failed: {r.stderr.strip()}")

        # drop rule: if source IP is in our set, drop. Adding this every start
        # would duplicate it, so guard with a comment-tagged existence check.
        if not self._drop_rule_exists():
            r = self._run(
                [
                    "add", "rule", _TABLE_FAMILY, _TABLE, "input",
                    "ip", "saddr", "@" + _SET, "drop",
                ]
            )
            if r.returncode != 0:
                return ActionResult(ok=False, detail=f"create rule failed: {r.stderr.strip()}")

        self._ensured = True
        return ActionResult(ok=True)

    def _drop_rule_exists(self) -> bool:
        """Best-effort check that our saddr->drop rule is already installed."""
        r = self._run(["list", "chain", _TABLE_FAMILY, _TABLE, "input"])
        if r.returncode != 0:
            return False
        return ("@" + _SET) in r.stdout and "drop" in r.stdout

    # --- block ------------------------------------------------------------

    def apply_block(self, ip: str, ttl_seconds: int) -> ActionResult:
        # Fail-safe: never act on a protected IP even if asked to.
        refusal = self._refuse_if_never_block(ip)
        if refusal is not None:
            logger.warning("nft refused block on protected IP %s", ip)
            return refusal

        ensured = self._ensure_table()
        if not ensured.ok:
            return ensured

        # Add the element with a per-element timeout so nftables auto-expires it.
        # "add element" is idempotent on membership but resets the timeout, which
        # is exactly what we want when a block is re-applied/extended.
        ttl = max(int(ttl_seconds), 1)
        r = self._run(
            [
                "add", "element", _TABLE_FAMILY, _TABLE, _SET,
                "{", ip, "timeout", f"{ttl}s", "}",
            ]
        )
        if r.returncode != 0:
            return ActionResult(ok=False, detail=f"add element failed: {r.stderr.strip()}")
        logger.info("nft BLOCK %s for %ss", ip, ttl)
        return ActionResult(ok=True, detail=f"blocked {ip} for {ttl}s")

    def remove_block(self, ip: str) -> ActionResult:
        refusal = self._refuse_if_never_block(ip)
        if refusal is not None:
            # Shouldn't happen (we never block these), but stay consistent.
            return refusal

        ensured = self._ensure_table()
        if not ensured.ok:
            return ensured

        r = self._run(
            ["delete", "element", _TABLE_FAMILY, _TABLE, _SET, "{", ip, "}"]
        )
        if r.returncode != 0:
            # Not present is fine — removal is idempotent. nft says "No such file
            # or directory" / "does not exist" when the element is already gone.
            stderr = r.stderr.lower()
            if "no such" in stderr or "does not exist" in stderr or "not contained" in stderr:
                return ActionResult(ok=True, detail=f"{ip} already absent")
            return ActionResult(ok=False, detail=f"delete element failed: {r.stderr.strip()}")
        logger.info("nft REMOVE BLOCK %s", ip)
        return ActionResult(ok=True, detail=f"removed block on {ip}")

    # --- throttle (not yet supported) ------------------------------------

    def apply_throttle(self, ip: str, rate: str, ttl_seconds: int) -> ActionResult:
        # TODO: implement via nft per-IP `limit`/meter once validated against
        # real traffic. Refuse rather than half-implement something that could
        # fail open. See module docstring + CONTRACTS open questions.
        return ActionResult(ok=False, detail="throttle not yet supported by nftables adapter")

    def remove_throttle(self, ip: str) -> ActionResult:
        # Nothing was ever applied, so removal is a trivial no-op success — this
        # keeps the reconciler's cleanup path from spuriously failing.
        return ActionResult(ok=True, detail="throttle not supported; nothing to remove")

    # --- introspection ----------------------------------------------------

    def list_active(self) -> list[ActiveEntry]:
        """Parse the live set into ActiveEntry rows for drift detection.

        Prefers ``nft -j`` (stable JSON) and falls back to the text format if
        JSON isn't available. Any parse problem yields an empty list rather than
        raising, so a malformed dump can't crash the reconciler (it would simply
        skip drift cleanup that cycle).
        """
        if not self._ensured:
            # If we've never set things up, there can't be anything we own.
            ensured = self._ensure_table()
            if not ensured.ok:
                return []

        entries = self._list_active_json()
        if entries is not None:
            return entries
        return self._list_active_text()

    def _list_active_json(self) -> list[ActiveEntry] | None:
        r = self._run(["-j", "list", "set", _TABLE_FAMILY, _TABLE, _SET])
        if r.returncode != 0 or not r.stdout.strip():
            return None
        try:
            doc = json.loads(r.stdout)
        except json.JSONDecodeError:
            return None

        entries: list[ActiveEntry] = []
        now = datetime.now(timezone.utc)
        # nft -j shape: {"nftables": [..., {"set": {"elem": [...]}}]}
        for obj in doc.get("nftables", []):
            set_obj = obj.get("set") if isinstance(obj, dict) else None
            if not set_obj:
                continue
            for elem in set_obj.get("elem", []) or []:
                ip, expires_at = self._parse_json_elem(elem, now)
                if ip is None:
                    continue
                entries.append(
                    ActiveEntry(ip=ip, action_type="block", expires_at=expires_at)
                )
        return entries

    @staticmethod
    def _parse_json_elem(elem, now: datetime):
        """Extract (ip, expires_at) from one nft -j set element.

        Elements come either as a bare string (no timeout) or as
        {"elem": {"val": "1.2.3.4", "expires": <seconds-remaining>}}.
        """
        # bare value, no timeout metadata
        if isinstance(elem, str):
            return elem, None
        if isinstance(elem, dict):
            inner = elem.get("elem", elem)
            if isinstance(inner, str):
                return inner, None
            if isinstance(inner, dict):
                val = inner.get("val")
                expires = inner.get("expires")
                expires_at = None
                if isinstance(expires, (int, float)):
                    expires_at = now + timedelta(seconds=float(expires))
                if isinstance(val, str):
                    return val, expires_at
        return None, None

    def _list_active_text(self) -> list[ActiveEntry]:
        """Fallback parser for the human-readable ``nft list set`` output."""
        r = self._run(["list", "set", _TABLE_FAMILY, _TABLE, _SET])
        if r.returncode != 0:
            return []
        entries: list[ActiveEntry] = []
        # The elements live inside an "elements = { ... }" block; tokens are
        # comma-separated, each like "1.2.3.4 timeout 1h expires 59m58s".
        text = r.stdout
        start = text.find("elements = {")
        if start == -1:
            return entries
        body = text[start + len("elements = {"):]
        end = body.find("}")
        if end != -1:
            body = body[:end]
        for token in body.split(","):
            token = token.strip()
            if not token:
                continue
            ip = token.split()[0]
            if ip:
                entries.append(ActiveEntry(ip=ip, action_type="block", expires_at=None))
        return entries

    # --- health -----------------------------------------------------------

    def health(self) -> AdapterHealth:
        # Is the binary even there?
        probe = self._run(["--version"])
        if probe.returncode != 0:
            detail = probe.stderr.strip() or "nft not available"
            return AdapterHealth(ok=False, backend=self.name, detail=detail)
        # Can we actually create/own our table+set? (catches non-root / no NET_ADMIN)
        ensured = self._ensure_table()
        if not ensured.ok:
            return AdapterHealth(ok=False, backend=self.name, detail=ensured.detail)
        return AdapterHealth(ok=True, backend=self.name, detail="nftables ready")
