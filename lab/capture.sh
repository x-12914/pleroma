#!/usr/bin/env bash
# lab/capture.sh — capture labeled flows via the sensor's dump mode.
#
# RUN ON THE VPS (capture host) AS ROOT (raw sockets). Pairs with an attack
# generator fired from a separate attacker host. See lab/README.md.
#
# Usage:
#   sudo bash lab/capture.sh --label "PortScan" --duration 90 [--attacker-ip 1.2.3.4] [--out path]
#
# Steps: stop the live sensor -> run the sensor in dump mode for --duration
# (auto-stops + flushes; the dump file is line-buffered so no rows are lost) ->
# restart the live sensor -> optionally filter to the attacker IP (clean labels).
set -euo pipefail

LABEL=""; DURATION=60; ATTACKER_IP=""; OUT=""
SENSOR_VENV="${SENSOR_VENV:-/opt/pleroma-sensor/.venv}"
AGENT="${AGENT:-/opt/pleroma-sensor/agent.py}"
BASE_DIR="${BASE_DIR:-/opt/pleroma/ml/data/base}"

while [ $# -gt 0 ]; do case "$1" in
  --label)       LABEL="$2"; shift 2;;
  --duration)    DURATION="$2"; shift 2;;
  --attacker-ip) ATTACKER_IP="$2"; shift 2;;
  --out)         OUT="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done

[ -n "$LABEL" ] || { echo "ERROR: --label required" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "ERROR: must run as root (raw sockets)" >&2; exit 1; }

mkdir -p "$BASE_DIR"
slug=$(printf '%s' "$LABEL" | tr ' /' '__' | tr -cd 'A-Za-z0-9_-')
ts=$(date +%Y%m%d-%H%M%S)
RAW="$BASE_DIR/.raw-$slug-$ts.csv"
[ -n "$OUT" ] || OUT="$BASE_DIR/$slug-$ts.csv"

echo "== capture: label='$LABEL' duration=${DURATION}s out=$OUT =="
echo "stopping live sensor..."; systemctl stop pleroma-sensor || true

echo "capturing for ${DURATION}s — FIRE THE ATTACK NOW from the attacker host..."
timeout --signal=TERM "$DURATION" env \
  PLEROMA_DUMP_CSV="$RAW" PLEROMA_DUMP_LABEL="$LABEL" \
  "$SENSOR_VENV/bin/python" "$AGENT" || true

echo "restarting live sensor..."; systemctl start pleroma-sensor || true

if [ ! -s "$RAW" ]; then echo "WARNING: no rows captured ($RAW empty)"; exit 0; fi

if [ -n "$ATTACKER_IP" ]; then
  echo "filtering to attacker IP $ATTACKER_IP (removing background noise)..."
  python3 "$(dirname "$0")/filter_by_ip.py" "$RAW" "$OUT" "$ATTACKER_IP"
  rm -f "$RAW"
else
  echo "WARNING: no --attacker-ip; CSV may include public-IP background noise"
  mv "$RAW" "$OUT"
fi

rows=$(( $(wc -l < "$OUT") - 1 ))
echo "== captured $rows labeled '$LABEL' rows -> $OUT =="
echo "retrain reads all *.csv in $BASE_DIR. New class? add it to VERDICT_MAPPING"
echo "in backend/app/services/network/engine.py, then retrain + restart backend."
