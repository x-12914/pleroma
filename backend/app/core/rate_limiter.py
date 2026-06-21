"""Rate-limiter keyed on the real client IP.

The app runs behind nginx, which proxies to 127.0.0.1. slowapi's default
`get_remote_address` would therefore see every request as coming from the proxy
(127.0.0.1) and lump all clients into one bucket — making per-client limits
useless. nginx sets `X-Real-IP` to the real client ($remote_addr) and appends it
to `X-Forwarded-For`, so we key on those instead.

Note: this trusts X-Real-IP / X-Forwarded-For, which is only safe because the
app is reachable *only* via the local nginx (it binds 127.0.0.1:8000). If the
app is ever exposed directly, these headers become client-spoofable.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request


def client_ip(request: Request) -> str:
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # First hop is the original client (nginx appends the connecting IP).
        return forwarded.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(key_func=client_ip)
