#!/usr/bin/env python3
"""Clean the CIC-IDS2018 daily CSVs into a single parquet file.

Reads every *.csv in ml/data/raw/CIC-IDS2018/ and writes a concatenated,
cleaned, dtype-optimized parquet at ml/data/clean/cicids2018_clean.parquet
for fast loading from train.py.

Handles the known CIC-IDS2018 quirks:
- Embedded duplicate header rows (e.g. in Friday-16-02-2018)
- ±inf values in Flow Byts/s and Flow Pkts/s when Flow Duration == 0
- NaN values scattered through numeric columns
- Memory pressure on a 6GB VPS — downcasts float64 to float32 to halve RAM
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

RAW_DIR = Path("/opt/pleroma/ml/data/raw/CIC-IDS2018")
OUT_DIR = Path("/opt/pleroma/ml/data/clean")
OUT_FILE = OUT_DIR / "cicids2018_clean.parquet"

# Columns we drop before training. Timestamp is a human-readable string —
# useful for time-based splits during exploration, useless as a numeric
# feature, and harmful if the model latches onto it as a key.
DROP_COLS = ["Timestamp"]


def clean_one(path: Path) -> pd.DataFrame:
    print(f"  loading {path.name} ...", flush=True)
    df = pd.read_csv(path, low_memory=False)

    # Defensive: strip whitespace from headers (CIC-IDS2017 had this bug;
    # 2018 doesn't, but no cost to belt-and-braces it.)
    df.columns = df.columns.str.strip()

    # Drop the rogue header rows that appear mid-file in some daily CSVs.
    if "Label" in df.columns:
        before = len(df)
        df = df[df["Label"] != "Label"].copy()
        if before != len(df):
            print(f"    dropped {before - len(df)} embedded-header rows", flush=True)

    # Drop columns we don't use as features.
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

    # Coerce every non-Label column to numeric. Bad strings become NaN
    # (which the next step drops).
    for col in df.columns:
        if col == "Label":
            continue
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Replace +/- inf with NaN, then drop any row with a NaN. inf shows
    # up in Flow Byts/s and Flow Pkts/s when Flow Duration == 0.
    before = len(df)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    if before != len(df):
        print(f"    dropped {before - len(df)} rows with NaN/inf", flush=True)

    # Downcast float64 → float32 to halve memory.
    for col in df.columns:
        if col == "Label":
            continue
        if df[col].dtype == "float64":
            df[col] = df[col].astype("float32")
        elif df[col].dtype == "int64":
            # Most int columns fit in int32 (port numbers max 65535,
            # packet counts rarely exceed billions).
            df[col] = df[col].astype("int32")

    print(f"    kept {len(df):,} rows", flush=True)
    return df


def main() -> int:
    if not RAW_DIR.exists():
        print(f"ERROR: raw directory {RAW_DIR} does not exist", file=sys.stderr)
        return 1

    csvs = sorted(RAW_DIR.glob("*.csv"))
    if not csvs:
        print(f"ERROR: no CSVs found in {RAW_DIR}", file=sys.stderr)
        return 1

    print(f"Found {len(csvs)} CSV file(s) in {RAW_DIR}")

    dfs = []
    for csv in csvs:
        dfs.append(clean_one(csv))

    print("\nConcatenating ...", flush=True)
    df = pd.concat(dfs, ignore_index=True)
    del dfs  # free memory before parquet write

    print(f"\nFinal shape: {df.shape}")
    print(f"Approx in-memory size: {df.memory_usage(deep=True).sum() / 1e6:.1f} MB")

    print("\nLabel distribution:")
    print(df["Label"].value_counts())

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\nWriting parquet → {OUT_FILE} ...", flush=True)
    df.to_parquet(OUT_FILE, compression="snappy", index=False)
    print(f"Done. Parquet on disk: {OUT_FILE.stat().st_size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
