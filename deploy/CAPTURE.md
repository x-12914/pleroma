# Capturing training data + retraining the network model

The network model is trained on flows captured by **our own Scapy sensor**, so
train-time and inference-time features match by construction. To improve the
model you give it more (and more representative) labeled flows, then retrain.

Two data sources feed a retrain, both aligned to the live `feature_names.joblib`:

1. **Base capture CSVs** in `/opt/pleroma/ml/data/base/` — ground-truth benign
   and attack captures you record here, with the sensor's dump mode.
2. **Auto-sampled benign** — the backend now persists a small random sample of
   benign flows to the `training_samples` table at ingest (benign is never
   written to `detection_logs`, so without this a retrain has no benign
   coverage). This fills in benign between manual captures automatically.
3. **Analyst feedback** — corrections submitted in the UI.

> Why this matters: the model was originally trained on only a few minutes of
> simulated traffic, so the IsolationForest flags ~92% of live flows as
> `Anomaly-novel` (Suspicious). A longer, representative **benign** capture is
> the single biggest fix for that noise.

## 1. Record base captures

```bash
mkdir -p /opt/pleroma/ml/data/base
sudo systemctl stop pleroma-sensor          # free the interface

# Benign — 15-30 min of real traffic (longer is better). Browse, hit the app,
# let background traffic flow.
sudo env PLEROMA_DUMP_CSV=/opt/pleroma/ml/data/base/benign.csv PLEROMA_DUMP_LABEL=Benign \
    /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
# Ctrl+C when done.

# One CSV per attack, replayed from your laptop while the agent captures.
# Use the SAME label strings the model already knows so VERDICT_MAPPING applies:
#   Benign, DoS attacks-Hulk, PortScan, Brute Force -Web
sudo env PLEROMA_DUMP_CSV=/opt/pleroma/ml/data/base/hulk.csv     PLEROMA_DUMP_LABEL="DoS attacks-Hulk"  /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
sudo env PLEROMA_DUMP_CSV=/opt/pleroma/ml/data/base/portscan.csv PLEROMA_DUMP_LABEL="PortScan"          /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
sudo env PLEROMA_DUMP_CSV=/opt/pleroma/ml/data/base/bruteweb.csv PLEROMA_DUMP_LABEL="Brute Force -Web"  /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py

sudo systemctl start pleroma-sensor
```

Example attack generators (run from your own machine, against the VPS):

```bash
# Hulk-style flood
for i in $(seq 1 300); do curl -s -o /dev/null --max-time 5 https://pleroma-aicds.duckdns.org/ & done; wait
# Port scan
nmap -sS -T4 -p 1-1000 pleroma-aicds.duckdns.org
```

> `/opt/pleroma/ml/data/base/` is on persistent disk — unlike `/tmp`, these
> survive reboots, so the base set keeps growing instead of being lost.

## 2. Retrain

From the UI as an **admin**, or:

```bash
# kick off (returns immediately)
curl -X POST https://pleroma-aicds.duckdns.org/api/v1/analysis/network/retrain \
     -H "Authorization: Bearer <admin-jwt>"

# poll status / metrics
curl https://pleroma-aicds.duckdns.org/api/v1/analysis/network/retrain/status \
     -H "Authorization: Bearer <admin-jwt>"
```

The retrain is **safe**:

- It only deploys if the data is sufficient (≥400 rows, ≥40 per class, Benign
  present) **and** the new model beats a macro-F1 floor (0.80). Otherwise it
  reports `"deployed": false` with reasons and leaves the live model untouched.
- Deployment is atomic: current artifacts are copied to `data/backup-<ts>/`,
  the new ones are swapped in, the engine hot-reloads, and if it comes back in
  mock mode it auto-restores the backup.

## 3. Apply to all workers

The backend runs with `--workers 2`. A retrain hot-reloads the engine in the
worker that ran it; the other keeps the old model until:

```bash
sudo systemctl restart pleroma-backend
```

The status response includes this reminder when a deploy succeeds.
