#!/usr/bin/env bash
# deploy/onboard.sh — automate per-customer calibration of Pleroma.
#
# Run ON THE CUSTOMER BOX as the `opt` user AFTER install (DEPLOY.md done + the
# sensor running). It collects a benign-learning window, retrains the model to
# THIS network's baseline, prints the anomaly-threshold report, and leaves the
# system in dry_run for operator review. It does NOT enable enforcement —
# graduation is a deliberate sign-off (see deploy/ONBOARDING.md).
#
# Usage:
#   bash deploy/onboard.sh [--learn-minutes N] [--boost-rate R] [--set-threshold]
#     --learn-minutes  benign collection window (default 120; longer = better)
#     --boost-rate     BENIGN_SAMPLE_RATE during the window (default 1.0)
#     --set-threshold  auto-apply the suggested NETWORK_ANOMALY_THRESHOLD
#
# Safe to re-run. Boosts benign sampling only for the window, then restores it.
set -uo pipefail

BACKEND="${PLEROMA_BACKEND:-/opt/pleroma/backend}"
VENV="${PLEROMA_VENV:-/opt/pleroma/.venv}"
PY="$VENV/bin/python"
ENV_FILE="$BACKEND/.env"
LEARN_MINUTES=120; BOOST_RATE=1.0; SET_THRESHOLD=0

while [ $# -gt 0 ]; do case "$1" in
  --learn-minutes) LEARN_MINUTES="$2"; shift 2;;
  --boost-rate)    BOOST_RATE="$2"; shift 2;;
  --set-threshold) SET_THRESHOLD=1; shift;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done

cd "$BACKEND" 2>/dev/null || { echo "ERROR: backend dir $BACKEND not found"; exit 1; }
log(){ echo "[$(date +%H:%M:%S)] $*"; }
setenv(){ if grep -q "^$1=" "$ENV_FILE"; then sed -i "s#^$1=.*#$1=$2#" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi; }
getenv(){ grep "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-; }
benign(){ "$PY" -c "from app.db.database import SessionLocal; from sqlalchemy import text; db=SessionLocal(); print(db.execute(text(\"select count(*) from training_samples where label='Benign'\")).scalar())" 2>/dev/null | tail -1; }

log "== Pleroma onboarding / calibration =="

# 1. Pre-flight — hard-fail on a mock engine or unreachable DB.
log "Pre-flight..."
"$PY" - <<'PY'
import sys
ok = True
try:
    from app.services.analysis_service import network_engine as e
    if e.is_mock:
        print("  engine: MOCK — model artifacts missing (fix before onboarding)"); ok = False
    else:
        print(f"  engine: OK ({len(e.feature_names)} features, classes={list(e.encoder.classes_)})")
except Exception as ex:
    print("  engine: import FAIL", ex); ok = False
try:
    from app.db.database import SessionLocal
    from sqlalchemy import text
    SessionLocal().execute(text("select 1")); print("  db: reachable")
except Exception as ex:
    print("  db: FAIL", ex); ok = False
sys.exit(0 if ok else 1)
PY
if [ $? -ne 0 ]; then echo "Pre-flight failed — resolve the above and re-run."; exit 1; fi
if systemctl is-active --quiet pleroma-sensor; then log "  sensor: active"; else log "  sensor: NOT active — start pleroma-sensor so flows arrive"; fi

# 2. Allowlist sanity — must protect admin + own IP before any enforcement.
log "Allowlist (never-block):"
"$PY" -c "from app.db.database import SessionLocal; from sqlalchemy import text; db=SessionLocal(); [print('   ',r[0],'-',r[1]) for r in db.execute(text('select cidr,reason from allowlist order by id'))]" 2>/dev/null

# 3. Benign-learning window.
ORIG_RATE="$(getenv BENIGN_SAMPLE_RATE)"; ORIG_RATE="${ORIG_RATE:-0.02}"
log "Boost BENIGN_SAMPLE_RATE $ORIG_RATE -> $BOOST_RATE; restarting backend"
setenv BENIGN_SAMPLE_RATE "$BOOST_RATE"
sudo systemctl restart pleroma-backend; sleep 8
B0="$(benign)"
log "Benign now=$B0. Learning ${LEARN_MINUTES} min — generate/allow NORMAL customer traffic (browse the app, real users) during this window."
sleep $((LEARN_MINUTES * 60))
B1="$(benign)"
log "Benign collected: $B0 -> $B1"
log "Restore BENIGN_SAMPLE_RATE -> $ORIG_RATE"
setenv BENIGN_SAMPLE_RATE "$ORIG_RATE"

# 4. Retrain to this network's baseline (safe gate + atomic deploy + rollback).
log "Retraining..."
"$PY" -c "from app.services.network import retrain; retrain.run_retrain_and_record(); r=retrain.read_last_result(); m=r.get('metrics') or {}; print('  deployed:',r.get('deployed'),'| macro_f1:',m.get('macro_f1'),'| classes:',m.get('classes')); (print('  reasons:',r.get('reasons')) if not r.get('deployed') else None)" 2>&1 | grep -vE "UserWarning|warnings.warn|delayed"
sudo systemctl restart pleroma-backend; sleep 8

# 5. Anomaly threshold report (+ optional apply).
log "Anomaly threshold report:"
"$PY" anomaly_report.py 2>/dev/null | sed 's/^/   /'
if [ "$SET_THRESHOLD" = "1" ]; then
  THR="$("$PY" anomaly_report.py 2>/dev/null | grep -i "NETWORK_ANOMALY_THRESHOLD" | grep -oE '\-?[0-9]+\.[0-9]+' | tail -1)"
  if [ -n "$THR" ]; then log "Applying NETWORK_ANOMALY_THRESHOLD=$THR"; setenv NETWORK_ANOMALY_THRESHOLD "$THR"; sudo systemctl restart pleroma-backend; sleep 6; fi
fi

# 6. Summary.
"$PY" -c "from app.db.database import SessionLocal; from sqlalchemy import text; db=SessionLocal(); s=db.execute(text('select mode,kill_switch from enforcement_state')).first(); print('enforcement mode:',s[0],'| kill_switch:',s[1])" 2>/dev/null
cat <<'EOF'

== Calibration complete — system is in dry_run (observing, enforcing nothing). ==
Next (operator + customer):
  1) Review Detections + Response > Actions (would_apply) in the dashboard for ~1 day.
  2) Graduate dry_run -> recommend -> auto with customer sign-off (deploy/ONBOARDING.md).
  3) Install pleroma-reconciler.service + set RESPONSE_ENFORCEMENT_ADAPTER=nftables for real enforcement.
EOF
