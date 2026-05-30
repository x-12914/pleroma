#!/usr/bin/env python3
"""Train a RandomForest classifier on cleaned CIC-IDS2018 flow data.

Loads the parquet from ml/clean.py, downsamples Benign to keep the
training matrix tractable on a 6GB VPS, fits a StandardScaler + a
class-balanced RandomForest, evaluates on a stratified test split, and
saves model/scaler/encoder/feature_names to ml/artifacts/ for
engine.py to consume.

Outputs:
    ml/artifacts/model.joblib            — trained RandomForestClassifier
    ml/artifacts/scaler.joblib           — fitted StandardScaler
    ml/artifacts/label_encoder.joblib    — fitted LabelEncoder (int <-> label)
    ml/artifacts/feature_names.joblib    — ordered list[str] of input columns
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

CLEAN_FILE = Path("/opt/pleroma/ml/data/clean/cicids2018_clean.parquet")
OUT_DIR = Path("/opt/pleroma/ml/artifacts")
MODEL_FILE = OUT_DIR / "model.joblib"
SCALER_FILE = OUT_DIR / "scaler.joblib"
ENCODER_FILE = OUT_DIR / "label_encoder.joblib"
FEATURES_FILE = OUT_DIR / "feature_names.joblib"

# Downsample Benign from ~3.2M to this to keep the design matrix
# in-memory and training time bounded. The class_weight='balanced'
# downstream still re-weights losses to compensate for remaining
# imbalance — we just stop spending 80% of training time on the
# already-easy Benign class.
BENIGN_SUBSAMPLE = 500_000

RANDOM_STATE = 42
TEST_SIZE = 0.2

# RF hyperparameters — chosen to fit comfortably in 6GB while still
# giving each rare attack class enough capacity to learn from.
# max_depth=20 caps tree size (deeper trees on 1M+ samples balloon
# memory). n_estimators=100 is the sklearn default and well-tested.
RF_PARAMS = dict(
    n_estimators=100,
    max_depth=20,
    class_weight="balanced",
    n_jobs=-1,
    random_state=RANDOM_STATE,
    verbose=1,
)


def main() -> int:
    if not CLEAN_FILE.exists():
        print(f"ERROR: clean parquet not found at {CLEAN_FILE}", file=sys.stderr)
        print("Run ml/clean.py first.", file=sys.stderr)
        return 1

    print(f"Loading {CLEAN_FILE.name} ...")
    t0 = time.time()
    df = pd.read_parquet(CLEAN_FILE)
    print(f"  loaded {len(df):,} rows × {len(df.columns)} cols in {time.time() - t0:.1f}s")
    print(f"  in-memory size: {df.memory_usage(deep=True).sum() / 1e6:.0f} MB")

    # Downsample Benign while keeping every attack row.
    benign_mask = df["Label"] == "Benign"
    n_benign = int(benign_mask.sum())
    if n_benign > BENIGN_SUBSAMPLE:
        print(f"\nDownsampling Benign: {n_benign:,} → {BENIGN_SUBSAMPLE:,}")
        benign = df[benign_mask].sample(n=BENIGN_SUBSAMPLE, random_state=RANDOM_STATE)
        attacks = df[~benign_mask]
        df = pd.concat([benign, attacks], ignore_index=True)
        del benign, attacks
        print(f"  combined: {len(df):,} rows")

    print("\nFinal label distribution:")
    counts = df["Label"].value_counts()
    for lbl, cnt in counts.items():
        print(f"  {lbl:<32} {cnt:>10,}")

    # Split features / label
    X = df.drop(columns=["Label"])
    y = df["Label"]
    feature_names = X.columns.tolist()
    print(f"\nFeatures: {len(feature_names)} columns")
    del df

    # Encode labels (int) — sklearn classifiers want numeric targets,
    # engine.py uses encoder.inverse_transform to decode predictions.
    print("\nEncoding labels ...")
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)
    print(f"  {len(encoder.classes_)} classes:")
    for i, cls in enumerate(encoder.classes_):
        print(f"    {i}  →  {cls}")
    del y

    # Stratified train/test split so the rare classes appear proportionally
    # in both sides (otherwise SQL Injection's 53 rows could end up entirely
    # in train, leaving no test signal).
    print(f"\nStratified train/test split ({1 - TEST_SIZE:.0%} / {TEST_SIZE:.0%}) ...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y_encoded,
    )
    print(f"  train: {len(X_train):,}  test: {len(X_test):,}")
    del X, y_encoded

    # Fit scaler on train only (don't leak test stats into the
    # normalization parameters).
    print("\nFitting StandardScaler ...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    del X_train, X_test

    # Train the RandomForest.
    print(f"\nTraining RandomForest ({RF_PARAMS['n_estimators']} trees, "
          f"max_depth={RF_PARAMS['max_depth']}, balanced) ...")
    t0 = time.time()
    model = RandomForestClassifier(**RF_PARAMS)
    model.fit(X_train_scaled, y_train)
    print(f"  trained in {time.time() - t0:.1f}s")
    del X_train_scaled, y_train

    # Evaluate on the held-out test set.
    print("\nEvaluating on held-out test set ...")
    y_pred = model.predict(X_test_scaled)

    print("\nClassification report (per-class precision/recall/f1):")
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
        print(f"{cls[:10]:>11}", end="")
    print()
    for i, cls in enumerate(encoder.classes_):
        print(f"{cls:<32}", end="")
        for j in range(len(encoder.classes_)):
            print(f"{cm[i, j]:>11,}", end="")
        print()

    # Save artifacts. Compress the model — RF pickles get big.
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\nSaving artifacts to {OUT_DIR} ...")
    joblib.dump(model, MODEL_FILE, compress=3)
    joblib.dump(scaler, SCALER_FILE)
    joblib.dump(encoder, ENCODER_FILE)
    joblib.dump(feature_names, FEATURES_FILE)

    print(f"  model:           {MODEL_FILE.stat().st_size / 1e6:>7.1f} MB")
    print(f"  scaler:          {SCALER_FILE.stat().st_size / 1e6:>7.1f} MB")
    print(f"  label_encoder:   {ENCODER_FILE.stat().st_size / 1e6:>7.1f} MB")
    print(f"  feature_names:   {FEATURES_FILE.stat().st_size / 1e6:>7.1f} MB")

    print("\nDone. Stage into the backend with:")
    print(f"  cp {MODEL_FILE} /opt/pleroma/backend/app/services/network/data/")
    print(f"  cp {SCALER_FILE} /opt/pleroma/backend/app/services/network/data/")
    print(f"  cp {ENCODER_FILE} /opt/pleroma/backend/app/services/network/data/")
    print(f"  cp {FEATURES_FILE} /opt/pleroma/backend/app/services/network/data/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
