# Network detection engine — authoritative reference

This is the single source of truth for how the network intrusion detector is
trained and served. Read it before touching anything in this directory or the
sensor. It exists because a past mixup (two divergent training pipelines) once
bricked detection — see **"History: the mixup"** at the bottom.

## What it is

A per-flow classifier that turns one network flow into a verdict:

```
sensor (Scapy) ─78 features→ /ingest/flow ─→ NetworkEngine.predict() ─→ verdict
                                                  │
                          heuristics → IsolationForest → RandomForest
```

- **verdict**: `Normal` | `Suspicious` | `Malicious` | `Error`
- **raw_class**: the underlying label (`DoS attacks-Hulk`, `PortScan`,
  `Brute Force -Web`, `Benign`, or a `*-heuristic` / `Anomaly-novel` tag)

## Feature extraction is the contract

The **Scapy sensor** ([`sensor/agent.py`](../../../../../sensor/agent.py),
`Flow.to_features()`) is the *only* place features are computed. It emits **78
CIC-IDS-shaped features** in a fixed order. The model is **trained and served on
these same features**, so there is no train/serve skew by construction.

> ⚠️ The features are CIC-IDS-*shaped* (same names) but **not** identical to the
> Java CICFlowMeter values. Do **not** train this model on the public
> CIC-IDS2017/2018 CSVs and serve it against the Scapy sensor — the value
> distributions differ and the model will misclassify everything. Train on
> flows captured by *our* sensor. (The CIC parquet on the VPS is historical.)

## Artifacts (`data/`)

Five files, all produced together by one retrain. `engine.py` loads them; if any
of the first four is missing it falls back to **mock mode** (every flow →
`Error`) so the rest of the backend keeps running.

| File | What |
|---|---|
| `model.joblib` | RandomForestClassifier (multiclass) |
| `scaler.joblib` | StandardScaler fit on the training features |
| `label_encoder.joblib` | LabelEncoder (class index ↔ label) |
| `feature_names.joblib` | ordered list of the 78 expected columns |
| `iforest.joblib` | IsolationForest novelty detector (optional) |

`backup-<ts>/` and `last_retrain.json` are written by the retrain pipeline.

## Inference order (`engine.py` → `predict`)

1. **Heuristic overrides** — explicit shapes (single-SYN scan, slow-headers).
2. **IsolationForest** — score below `NETWORK_ANOMALY_THRESHOLD` → `Anomaly-novel`
   (Suspicious) before the RF forces it into a known class.
3. **RandomForest** — multiclass; a `Malicious` call below
   `NETWORK_CONFIDENCE_THRESHOLD` is downgraded to `Suspicious`.

### Thresholds

Both are configurable in the environment (defaults in
[`config.py`](../../core/config.py)); changing them needs only a backend
restart:

- `NETWORK_ANOMALY_THRESHOLD` (default `-0.05`)
- `NETWORK_CONFIDENCE_THRESHOLD` (default `0.60`)

If the dashboard is flooded with `Suspicious` / `Anomaly-novel`, the IForest was
trained on traffic unlike production. Measure the real score distribution with
[`backend/anomaly_report.py`](../../../anomaly_report.py), then either lower the
threshold or (better) retrain on representative benign traffic.

## Training / retraining — ONE pipeline

All (re)training goes through [`retrain.py`](retrain.py). It is the only training
code path; it is called by both the admin endpoint and the CLI:

- **App**: `POST /api/v1/analysis/network/retrain` (admin), poll
  `GET /api/v1/analysis/network/retrain/status`.
- **CLI**: `python -m app.services.network.retrain` from `backend/`.

Data sources, all aligned to the live `feature_names.joblib`:

1. **Base capture CSVs** in `settings.NETWORK_BASE_DATASET_DIR`
   (`/opt/pleroma/ml/data/base/`) — ground-truth benign + attacks recorded with
   the sensor's dump mode.
2. **Auto-sampled benign** — `training_samples` table (benign is never written to
   `detection_logs`, so without this a retrain has no benign coverage).
3. **Analyst feedback** — corrections from the UI.

Retraining is **safe**: a new model is deployed only if it passes the data +
quality gate (min rows / per-class count / Benign present / macro-F1 floor), and
deployment is atomic (backup → swap → hot-reload → rollback if the engine returns
to mock mode). The full capture + retrain runbook is
[`deploy/CAPTURE.md`](../../../../deploy/CAPTURE.md).

> Multi-worker note: the backend runs `--workers 2`. A retrain hot-reloads the
> engine in one worker only; `systemctl restart pleroma-backend` propagates to
> both.

## History: the mixup (do not repeat)

The original prototype used **NSL-KDD** (41 features, labels like `neptune.`).
The project moved to the **Scapy/CIC-shaped 78-feature** model but left the old
`trainer.py` wired to the admin "Retrain" button. Clicking it overwrote
`model.joblib`/`scaler.joblib` with a 41-feature NSL-KDD model, which the
78-feature engine couldn't use → every flow returned `Error` until artifacts
were restored by hand. The feedback loop feeding it also read NSL-KDD field names
out of CIC `raw_input`, so corrections became all-zero rows.

`trainer.py` is deleted. **There must be exactly one training pipeline
(`retrain.py`), and it must always align to the live `feature_names.joblib`.** Do
not add a second trainer with a different schema.
