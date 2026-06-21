#!/usr/bin/env python3
"""Report the IsolationForest anomaly-score distribution over recent network
flows, to help choose NETWORK_ANOMALY_THRESHOLD.

Why: the engine flags a flow as "Anomaly-novel" (→ Suspicious) when the
IsolationForest decision_function score is below NETWORK_ANOMALY_THRESHOLD. If
the model was trained on traffic unlike production, almost everything scores
negative and the dashboard fills with Suspicious noise. This prints where real
scores actually fall so you can pick a threshold — or decide to retrain.

Usage (on the VPS):
    cd /opt/pleroma/backend
    /opt/pleroma/.venv/bin/python anomaly_report.py [SAMPLE_SIZE]
"""
from __future__ import annotations

import os
import sys

sys.path.append(os.getcwd())

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from app.core.config import settings
from app.db.database import SessionLocal
from app.db.models import DetectionLog

DATA_DIR = Path("app/services/network/data")


def main(sample_size: int = 5000) -> int:
    feats = list(joblib.load(DATA_DIR / "feature_names.joblib"))
    scaler = joblib.load(DATA_DIR / "scaler.joblib")
    iforest_path = DATA_DIR / "iforest.joblib"
    if not iforest_path.exists():
        print("No iforest.joblib — anomaly layer disabled, nothing to report.")
        return 0
    iforest = joblib.load(iforest_path)

    with SessionLocal() as db:
        rows = (
            db.query(DetectionLog.report_data)
            .filter(
                DetectionLog.category == "NETWORK_TRAFFIC",
                DetectionLog.report_data.isnot(None),
            )
            .order_by(DetectionLog.id.desc())
            .limit(sample_size)
            .all()
        )

    records = [(rd or {}).get("raw_input") for (rd,) in rows]
    records = [r for r in records if r]
    if not records:
        print("No stored network flows with raw_input found.")
        return 0

    df = pd.DataFrame(records).reindex(columns=feats)
    for c in feats:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype("float32")
    scores = iforest.decision_function(scaler.transform(df))

    cur = settings.NETWORK_ANOMALY_THRESHOLD
    print(f"Sampled {len(scores):,} stored network flows")
    print(f"Current NETWORK_ANOMALY_THRESHOLD = {cur}")

    print("\nScore distribution (lower = more anomalous):")
    for p in (1, 5, 10, 25, 50, 75, 90, 95, 99):
        print(f"  p{p:<2} = {np.percentile(scores, p): .4f}")
    print(f"  min = {scores.min(): .4f}   max = {scores.max(): .4f}   mean = {scores.mean(): .4f}")

    print("\nFraction flagged ('novel') at candidate thresholds:")
    for t in (0.0, -0.02, -0.05, -0.10, -0.15, -0.20, -0.30):
        pct = (scores < t).mean() * 100
        mark = "   <- current" if abs(t - cur) < 1e-9 else ""
        print(f"  threshold {t:>6} -> {pct:5.1f}% flagged{mark}")

    target = float(np.percentile(scores, 10))
    print(f"\nTo flag ~10% of this traffic, set NETWORK_ANOMALY_THRESHOLD ≈ {target:.3f}")
    print("NOTE: these flows were already deemed non-Benign, so this is a rough")
    print("guide. The real fix is retraining on representative benign traffic")
    print("(see deploy/CAPTURE.md).")
    return 0


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    sys.exit(main(n))
