#!/usr/bin/env python3
"""Clean the CIC-IDS2018 daily CSVs into a single parquet file.

Streams chunks of 200K rows at a time and writes them directly into a
growing parquet file via pyarrow.parquet.ParquetWriter. Avoids holding
all daily DataFrames in memory at once — the previous concat-based
approach OOM'd on a 6GB VPS during the third file's read.

Handles the known CIC-IDS2018 quirks:
- Embedded duplicate header rows (e.g. in Friday-16-02-2018)
- +/- inf in Flow Byts/s and Flow Pkts/s when Flow Duration == 0
- Scattered NaN values
- 80-column float64 inflation (downcast to float32 inside each chunk)

Peak memory stays around 300-500 MB regardless of input dataset size.
"""
from __future__ import annotations

import gc
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

RAW_DIR = Path("/opt/pleroma/ml/data/raw/CIC-IDS2018")
OUT_DIR = Path("/opt/pleroma/ml/data/clean")
OUT_FILE = OUT_DIR / "cicids2018_clean.parquet"

# Drop Timestamp (string, useless as ML feature, harmful if model latches).
DROP_COLS = ["Timestamp"]

# Tuned for ~6GB VPS: each chunk ~200K rows × 80 cols × float32 ≈ 64MB,
# plus pandas/arrow overhead → ~200MB peak per chunk.
CHUNK_SIZE = 200_000


def clean_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    """Apply all cleaning steps to a single chunk.

    Returns a possibly-empty DataFrame; caller skips writes when empty.
    """
    # Defensive: strip whitespace from headers (CIC-IDS2017 had this bug;
    # 2018 doesn't, but no cost).
    chunk.columns = chunk.columns.str.strip()

    # Drop rogue mid-file header rows (Friday-16-02-2018 has one).
    if "Label" in chunk.columns:
        chunk = chunk[chunk["Label"] != "Label"]

    # Drop columns we don't use as features.
    chunk = chunk.drop(columns=[c for c in DROP_COLS if c in chunk.columns])

    # Coerce non-Label columns to numeric (bad strings → NaN, dropped next).
    for col in chunk.columns:
        if col == "Label":
            continue
        chunk[col] = pd.to_numeric(chunk[col], errors="coerce")

    # Replace +/- inf with NaN, then drop NaN rows. inf appears in
    # Flow Byts/s and Flow Pkts/s when Flow Duration == 0.
    chunk = chunk.replace([np.inf, -np.inf], np.nan).dropna()

    # Force every non-Label column to float32 unconditionally. This is
    # less efficient than preserving int dtypes (~50 MB extra on disk for
    # the int columns) but guarantees identical schema across every chunk
    # and every input file — without it, pandas auto-types the same
    # column as int32 in one chunk and float32 in another based on whether
    # that chunk happened to contain fractional values, which makes the
    # parquet writer reject schema-mismatched appends.
    for col in chunk.columns:
        if col == "Label":
            continue
        chunk[col] = chunk[col].astype("float32")

    return chunk


def main() -> int:
    if not RAW_DIR.exists():
        print(f"ERROR: raw directory {RAW_DIR} does not exist", file=sys.stderr)
        return 1

    csvs = sorted(RAW_DIR.glob("*.csv"))
    if not csvs:
        print(f"ERROR: no CSVs found in {RAW_DIR}", file=sys.stderr)
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # If a previous partial run left a parquet behind, remove it so the
    # ParquetWriter starts fresh and downstream code sees a clean file.
    if OUT_FILE.exists():
        OUT_FILE.unlink()

    print(f"Found {len(csvs)} CSV file(s). Streaming chunks of {CHUNK_SIZE:,} rows → parquet ...\n")

    writer: pq.ParquetWriter | None = None
    total_rows = 0
    label_counts: dict[str, int] = {}

    try:
        for csv in csvs:
            print(f"  {csv.name}", flush=True)
            file_rows = 0
            for chunk_idx, chunk in enumerate(
                pd.read_csv(csv, chunksize=CHUNK_SIZE, low_memory=False)
            ):
                chunk = clean_chunk(chunk)
                if chunk.empty:
                    continue

                # Tally labels for the final summary.
                for lbl, cnt in chunk["Label"].value_counts().items():
                    label_counts[lbl] = label_counts.get(lbl, 0) + int(cnt)

                # First chunk seeds the writer's schema; subsequent ones append.
                table = pa.Table.from_pandas(chunk, preserve_index=False)
                if writer is None:
                    writer = pq.ParquetWriter(
                        OUT_FILE, table.schema, compression="snappy"
                    )
                writer.write_table(table)

                file_rows += len(chunk)
                total_rows += len(chunk)

                # Explicitly release before the next chunk to keep memory flat.
                del chunk, table
                gc.collect()

            print(f"    kept {file_rows:,} rows", flush=True)
    finally:
        if writer is not None:
            writer.close()

    print(f"\nTotal rows written: {total_rows:,}")
    print("\nLabel distribution:")
    for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"  {lbl:<32} {cnt:>12,}")

    print(f"\nParquet on disk: {OUT_FILE.stat().st_size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
