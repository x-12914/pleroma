#!/usr/bin/env bash
# lab/attacks/portscan.sh — TCP SYN port scan.  Label: PortScan
# RUN FROM THE ATTACKER HOST. Pair with:
#   sudo bash lab/capture.sh --label "PortScan" --duration 120 --attacker-ip <this host>
set -euo pipefail
TARGET="${1:?usage: portscan.sh <target> [ports]}"
PORTS="${2:-1-2000}"
command -v nmap >/dev/null || { echo "need nmap"; exit 1; }
echo "SYN-scanning $TARGET ports $PORTS ..."
nmap -sS -T4 -p "$PORTS" "$TARGET"
echo "done — stop the capture (or let its timer elapse)."
