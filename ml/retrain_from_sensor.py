#!/usr/bin/env python3
"""Retrain the network engine on flows captured by OUR sensor agent.

The original train.py used CIC-IDS2018 CSVs produced by the Java
CICFlowMeter. The Phase 4 sensor uses a Scapy-based feature
implementation whose values don't exactly match — enough that live
flows are out-of-distribution relative to that training set and the
model classifies everything as Benign.

This script retrains on flows captured BY OUR AGENT, eliminating the
distribution mismatch by definition.

Capture sessions (on the VPS):

    sudo systemctl stop pleroma-sensor    # stop the running daemon

    # Session 1: 5-10 min of normal browsing / background traffic
    sudo env PLEROMA_DUMP_CSV=/tmp/sensor-benign.csv PLEROMA_DUMP_LABEL=Benign \\
        /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
    # Ctrl+C when done

    # Session 2: 1-2 min while running a curl flood from your laptop
    sudo env PLEROMA_DUMP_CSV=/tmp/sensor-hulk.csv PLEROMA_DUMP_LABEL="DoS attacks-Hulk" \\
        /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
    # In a separate terminal on your Windows PC:
    #   for i in {1..200}; do curl -s -o /dev/null --max-time 5 \\
    #     https://pleroma-aicds.duckdns.org/ & done; wait
    # Ctrl+C the agent when done

Use any CIC label name you want (Benign, DoS attacks-Hulk, Bot, etc.)
— the engine's VERDICT_MAPPING maps known names to Normal/Suspicious/
Malicious, unknown names default to Suspicious.

Then run:

    /opt/pleroma/.venv/bin/python /opt/pleroma/ml/retrain_from_sensor.py \\
        /tmp/sensor-benign.csv /tmp/sensor-hulk.csv

And deploy:

    sudo cp /opt/pleroma/ml/artifacts/*.joblib \\
        /opt/pleroma/backend/app/services/network/data/
    sudo systemctl restart pleroma-backend
    sudo systemctl start pleroma-sensor
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

OUT_DIR = Path(__file__).resolve().parent / "artifacts"
TEST_SIZE = 0.2
RANDOM_STATE = 42


def load_csvs(paths: list[str]) -> pd.DataFrame:
    frames = []
    for p in paths:
        path = Path(p)
        if not path.exists():
            print(f"WARN: skipping missing file {path}", file=sys.stderr)
            continue
        try:
            df = pd.read_csv(path)
        except Exception as exc:
            print(f"WARN: failed to read {path}: {exc}", file=sys.stderr)
            continue
        if "Label" not in df.columns:
            print(f"WARN: {path} has no Label column — skipping", file=sys.stderr)
            continue
        print(f"  {path.name:<40} {len(df):>10,} rows  label={df['Label'].iloc[0] if len(df) else '?'}")
        frames.append(df)
    if not frames:
        raise SystemExit("ERROR: no usable input CSVs found")
    return pd.concat(frames, ignore_index=True)


def main(args: list[str]) -> int:
    if not args:
        print(__doc__, file=sys.stderr)
        return 2

    print(f"Loading {len(args)} CSV(s)...")
    df = load_csvs(args)
    print(f"\nCombined: {len(df):,} rows × {len(df.columns)} cols")

    # Coerce non-Label columns to numeric; drop rows with NaN/inf.
    for col in df.columns:
        if col == "Label":
            continue
        df[col] = pd.to_numeric(df[col], errors="coerce")
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    if before != len(df):
        print(f"Dropped {before - len(df):,} rows with NaN/inf")

    print("\nLabel distribution:")
    counts = df["Label"].value_counts()
    for lbl, n in counts.items():
        print(f"  {lbl:<32} {n:>10,}")

    if df["Label"].nunique() < 2:
        print("\nERROR: need at least 2 distinct labels to classify", file=sys.stderr)
        return 1

    # Enforce a minimum per-class count so the stratified split + class
    # weight balancing have something to work with.
    too_few = counts[counts < 20]
    if not too_few.empty:
        print(
            f"\nWARN: these classes have < 20 samples and may produce "
            f"unreliable splits: {dict(too_few)}",
            file=sys.stderr,
        )

    X = df.drop(columns=["Label"])
    y = df["Label"]
    feature_names = X.columns.tolist()

    print("\nEncoding labels ...")
    encoder = LabelEncoder()
    y_enc = encoder.fit_transform(y)

    print(f"\nStratified train/test split ({1 - TEST_SIZE:.0%} / {TEST_SIZE:.0%}) ...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y_enc,
    )
    print(f"  train={len(X_train):,}  test={len(X_test):,}")

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    print("\nTraining RandomForest (100 trees, max_depth=20, balanced) ...")
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    model.fit(X_train_s, y_train)
    print(f"  done in {time.time() - t0:.1f}s")
    if hasattr(model, "verbose"):
        model.verbose = 0  # silence per-predict spam at inference

    print("\nClassification report on held-out test set:")
    y_pred = model.predict(X_test_s)
    print(classification_report(
        y_test, y_pred,
        target_names=encoder.classes_,
        zero_division=0,
    ))

    print("Confusion matrix (rows=true, cols=predicted):")
    cm = confusion_matrix(y_test, y_pred)
    header = "true \\ pred"
    print(f"{header:<32}", end="")
    for cls in encoder.classes_:
        print(f"{cls[:12]:>13}", end="")
    print()
    for i, cls in enumerate(encoder.classes_):
        print(f"{cls:<32}", end="")
        for j in range(len(encoder.classes_)):
            print(f"{cm[i, j]:>13,}", end="")
        print()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUT_DIR / "model.joblib", compress=3)
    joblib.dump(scaler, OUT_DIR / "scaler.joblib")
    joblib.dump(encoder, OUT_DIR / "label_encoder.joblib")
    joblib.dump(feature_names, OUT_DIR / "feature_names.joblib")

    print(f"\nArtifacts saved to {OUT_DIR}:")
    for name in ("model.joblib", "scaler.joblib", "label_encoder.joblib", "feature_names.joblib"):
        p = OUT_DIR / name
        print(f"  {p.name:<24} {p.stat().st_size / 1e6:>6.2f} MB")

    print("\nDeploy:")
    print(f"  sudo cp {OUT_DIR}/*.joblib /opt/pleroma/backend/app/services/network/data/")
    print( "  sudo systemctl restart pleroma-backend")
    print( "  sudo systemctl start pleroma-sensor")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
