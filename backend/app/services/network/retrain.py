"""Safe retraining for the network engine — one code path for the admin
endpoint and the CLI. Replaces the NSL-KDD trainer.py (which trained an
incompatible 41-feature model and would brick the live engine).

Data sources, all aligned to the live feature_names.joblib:
  1. Base capture CSVs in settings.NETWORK_BASE_DATASET_DIR (ground-truth
     benign + attacks recorded via the sensor's dump mode).
  2. Auto-sampled Benign flows from the training_samples table.
  3. Analyst feedback corrections (feedback + detection_logs).

A new model deploys ONLY if it passes the safety gate; deployment is atomic
(backup -> swap -> hot-reload -> rollback if the engine comes back mock).
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from app.core.config import settings
from app.db.database import SessionLocal
from app.db.models import DetectionLog, Feedback, TrainingSample

DATA_DIR = Path(__file__).resolve().parent / "data"
FEATURES_PATH = DATA_DIR / "feature_names.joblib"
STATUS_PATH = DATA_DIR / "last_retrain.json"
ARTIFACT_NAMES = (
    "model.joblib", "scaler.joblib", "label_encoder.joblib",
    "feature_names.joblib", "iforest.joblib",
)

MIN_TOTAL_ROWS = 400
MIN_PER_CLASS = 40
MIN_CLASSES = 2
MIN_MACRO_F1 = 0.80
RANDOM_STATE = 42
TEST_SIZE = 0.2


def _feature_names() -> list[str]:
    if not FEATURES_PATH.exists():
        raise FileNotFoundError(f"{FEATURES_PATH} missing — cannot align training data")
    return list(joblib.load(FEATURES_PATH))


def _align(df: pd.DataFrame, feats: list[str]) -> pd.DataFrame:
    """Keep only feature columns, in order; coerce numeric; fill missing 0.0.

    Drops _src_ip/_dst_ip and anything not in the model's feature set —
    mirrors engine.preprocess so training data matches what inference feeds
    the model.
    """
    X = df.reindex(columns=feats)
    for c in feats:
        X[c] = pd.to_numeric(X[c], errors="coerce")
    return X.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype("float32")


def _from_base_csvs(feats: list[str]) -> list[pd.DataFrame]:
    base = Path(settings.NETWORK_BASE_DATASET_DIR)
    frames: list[pd.DataFrame] = []
    if base.is_dir():
        for csv in sorted(base.glob("*.csv")):
            try:
                df = pd.read_csv(csv)
            except Exception:
                continue
            if "Label" not in df.columns:
                continue
            X = _align(df, feats)
            X["Label"] = df["Label"].astype(str).values
            frames.append(X)
    return frames


def _from_training_samples(feats: list[str]):
    with SessionLocal() as db:
        rows = db.query(TrainingSample).all()
    if not rows:
        return None
    X = _align(pd.DataFrame([r.features for r in rows]), feats)
    X["Label"] = [r.label for r in rows]
    return X


def _from_feedback(feats: list[str]):
    recs: list[dict] = []
    labels: list[str] = []
    with SessionLocal() as db:
        for e in (db.query(Feedback).join(DetectionLog)
                  .filter(DetectionLog.category == "NETWORK_TRAFFIC").all()):
            rd = e.log.report_data or {}
            ri = rd.get("raw_input") or {}
            label = rd.get("raw_class") if e.is_correct else (e.corrected_verdict or "").strip()
            if ri and label:
                recs.append(ri)
                labels.append(label)
    if not recs:
        return None
    X = _align(pd.DataFrame(recs), feats)
    X["Label"] = labels
    return X


# Attack classes we trust enough to mine from detection_logs.raw_input as
# (weakly-)labeled training data. These rows carry the sensor's own extracted
# features (stored at ingest), so they're aligned to feature_names by
# construction — this is the SAME pipeline, just an additional aligned source,
# not a second trainer (see README "History: the mixup").
#
# Deliberately EXCLUDED:
#   - "Brute Force -Web": historically ~5% precision; too noisy to train on.
#     Recapture it as ground truth instead (CAPTURE.md) before re-adding.
#   - "ScanProbe-heuristic" / "SlowHeaders-heuristic": rule tags, not model
#     classes. "Anomaly-novel": IsolationForest tag, label unknown.
#   - "Benign": never reliably present in detection_logs (ingest drops it);
#     benign comes from training_samples instead.
_MINEABLE_LOG_CLASSES = ("DoS attacks-Hulk", "PortScan")
# Cap per class so the huge attack volume can't swamp the benign set (which the
# anomaly layer needs to learn "normal"). Newest rows first.
_MINE_PER_CLASS_CAP = 2000


def _from_detection_logs(feats: list[str]) -> list[pd.DataFrame]:
    frames: list[pd.DataFrame] = []
    with SessionLocal() as db:
        for cls in _MINEABLE_LOG_CLASSES:
            rows = (
                db.query(DetectionLog)
                .filter(DetectionLog.category == "NETWORK_TRAFFIC")
                .filter(DetectionLog.report_data["raw_class"].astext == cls)
                .order_by(DetectionLog.timestamp.desc())
                .limit(_MINE_PER_CLASS_CAP)
                .all()
            )
            recs = [
                (r.report_data or {}).get("raw_input") or {}
                for r in rows
            ]
            recs = [ri for ri in recs if ri]
            if not recs:
                continue
            X = _align(pd.DataFrame(recs), feats)
            X["Label"] = cls
            frames.append(X)
    return frames


def build_training_frame():
    feats = _feature_names()
    frames = list(_from_base_csvs(feats))
    # Mined attack examples (DoS-Hulk / PortScan) from prior detections.
    frames.extend(_from_detection_logs(feats))
    for loader in (_from_training_samples, _from_feedback):
        f = loader(feats)
        if f is not None and len(f):
            frames.append(f)
    if not frames:
        return None, feats
    return pd.concat(frames, ignore_index=True), feats


def _data_sufficient(df: pd.DataFrame):
    reasons: list[str] = []
    counts = df["Label"].value_counts().to_dict()
    if len(df) < MIN_TOTAL_ROWS:
        reasons.append(f"only {len(df)} rows (< {MIN_TOTAL_ROWS})")
    if len(counts) < MIN_CLASSES:
        reasons.append(f"only {len(counts)} class(es)")
    if "Benign" not in counts:
        reasons.append("no Benign samples — would wreck benign precision")
    too_few = {k: v for k, v in counts.items() if v < MIN_PER_CLASS}
    if too_few:
        reasons.append(f"classes under {MIN_PER_CLASS}: {too_few}")
    return not reasons, reasons


def train_and_evaluate(df: pd.DataFrame, feats: list[str]):
    X = df[feats].astype("float32")
    y = df["Label"].astype(str)
    enc = LabelEncoder()
    y_enc = enc.fit_transform(y)
    Xtr, Xte, ytr, yte = train_test_split(
        X, y_enc, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_enc)
    scaler = StandardScaler()
    Xtr_s = scaler.fit_transform(Xtr)
    Xte_s = scaler.transform(Xte)
    model = RandomForestClassifier(
        n_estimators=100, max_depth=20, class_weight="balanced",
        n_jobs=-1, random_state=RANDOM_STATE)
    model.fit(Xtr_s, ytr)
    if hasattr(model, "verbose"):
        model.verbose = 0
    yp = model.predict(Xte_s)
    iforest = IsolationForest(
        n_estimators=200, contamination="auto",
        random_state=RANDOM_STATE, n_jobs=-1)
    iforest.fit(Xtr_s)
    metrics = {
        "macro_f1": float(f1_score(yte, yp, average="macro")),
        "classes": list(enc.classes_),
        "n_train": int(len(Xtr)),
        "n_test": int(len(Xte)),
        "iforest_flagged_pct": float((iforest.decision_function(Xte_s) < 0).mean() * 100),
        "per_class": classification_report(
            yte, yp, target_names=enc.classes_, zero_division=0, output_dict=True),
    }
    artifacts = {
        "model.joblib": model,
        "scaler.joblib": scaler,
        "label_encoder.joblib": enc,
        "feature_names.joblib": feats,
        "iforest.joblib": iforest,
    }
    return artifacts, metrics


def atomic_deploy(artifacts: dict) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = DATA_DIR / f"backup-{ts}"
    backup.mkdir(parents=True, exist_ok=True)
    for n in ARTIFACT_NAMES:
        if (DATA_DIR / n).exists():
            shutil.copy2(DATA_DIR / n, backup / n)
    tmp = DATA_DIR / f".tmp-{ts}"
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        for n, obj in artifacts.items():
            joblib.dump(obj, tmp / n, compress=3 if n in ("model.joblib", "iforest.joblib") else 0)
        for n in artifacts:
            shutil.move(str(tmp / n), str(DATA_DIR / n))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # Hot-reload the running engine and verify it came back healthy.
    from app.services.analysis_service import network_engine
    network_engine.load_artifacts()
    if network_engine.is_mock:  # new model unhealthy -> roll back
        for n in ARTIFACT_NAMES:
            if (backup / n).exists():
                shutil.copy2(backup / n, DATA_DIR / n)
        network_engine.load_artifacts()
        raise RuntimeError("reloaded engine went mock; rolled back to backup")
    return str(backup)


def perform_retraining() -> dict:
    """Run the full retrain. Never raises into production — returns a report."""
    df, feats = build_training_frame()
    if df is None or df.empty:
        return {"deployed": False, "reasons": ["no training data found"]}
    ok, reasons = _data_sufficient(df)
    if not ok:
        return {"deployed": False, "reasons": reasons, "rows": int(len(df))}
    artifacts, metrics = train_and_evaluate(df, feats)
    if metrics["macro_f1"] < MIN_MACRO_F1:
        return {
            "deployed": False,
            "reasons": [f"macro-F1 {metrics['macro_f1']:.3f} < {MIN_MACRO_F1}"],
            "metrics": metrics,
        }
    backup = atomic_deploy(artifacts)
    return {"deployed": True, "metrics": metrics, "backup": backup}


# ---- background + status (the endpoint uses these) ----

def _record(d: dict) -> None:
    try:
        STATUS_PATH.write_text(json.dumps(d, default=str, indent=2))
    except Exception:
        pass


def read_last_result() -> dict:
    if STATUS_PATH.exists():
        try:
            return json.loads(STATUS_PATH.read_text())
        except Exception:
            return {"status": "unknown"}
    return {"status": "never_run"}


def run_retrain_and_record() -> None:
    _record({"status": "running", "started_at": time.strftime("%Y-%m-%d %H:%M:%S")})
    try:
        result = perform_retraining()
    except Exception as e:
        result = {"deployed": False, "error": str(e)}
    result["status"] = "done"
    result["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    if result.get("deployed"):
        result["note"] = "Run `systemctl restart pleroma-backend` to apply to all workers."
    _record(result)


if __name__ == "__main__":
    import pprint
    pprint.pprint(perform_retraining())
