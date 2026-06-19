# Capturing training data + retraining the network model

End-to-end runbook for teaching the network model what traffic looks like on
this box and safely deploying the result. The model is trained on flows captured
by **our own Scapy sensor**, so train-time and inference-time features match by
construction. Authoritative model reference:
[../backend/app/services/network/README.md](../backend/app/services/network/README.md).

A retrain draws from three sources, all aligned to the live `feature_names.joblib`:

1. **Base capture CSVs** in `/opt/pleroma/ml/data/base/` — ground-truth benign +
   attack captures you record here with the sensor's dump mode.
2. **Auto-sampled benign** — the backend persists a small random sample of benign
   flows to the `training_samples` table at ingest (benign is never written to
   `detection_logs`, so without this a retrain has no benign coverage).
3. **Analyst feedback** — corrections submitted in the UI.

> **Why this matters.** The model was originally trained on only a few minutes of
> simulated traffic, so the IsolationForest flags ~92% of live flows as
> `Anomaly-novel` (→ Suspicious). A longer, representative **benign** capture is
> the single biggest fix for that noise.

Paths used throughout: backend `/opt/pleroma/backend`, venv
`/opt/pleroma/.venv`, sensor venv `/opt/pleroma-sensor/.venv`, base dataset
`/opt/pleroma/ml/data/base/`. Run as user `opt`.

---

## 0. Prerequisites — deploy the safe pipeline (once)

The safe retrain pipeline + auto-benign sampling ship on branch
`fix/safe-retrain-pipeline` (merge to `main` when ready). Model artifacts are no
longer git-tracked, so deploys never fight the live model — but **always back it
up first**.

```bash
cd /opt/pleroma

# 1. Back up the live model (never operate near it without a backup)
sudo cp -a backend/app/services/network/data /opt/pleroma-model-backup-$(date +%F-%H%M)
mkdir -p /tmp/live-model && cp backend/app/services/network/data/*.joblib /tmp/live-model/

# 2. Pull the code (use origin/main once merged)
git fetch origin
git checkout -f -B fix/safe-retrain-pipeline origin/fix/safe-retrain-pipeline

# 3. Restore the live artifacts (now untracked — git won't touch them)
cp /tmp/live-model/{model,scaler,label_encoder,feature_names,iforest}.joblib \
   backend/app/services/network/data/

# 4. Restart (creates training_samples table, loads new code + thresholds)
sudo systemctl restart pleroma-backend
sleep 3 && sudo journalctl -u pleroma-backend -n 15 --no-pager
# Expect: "NetworkEngine: CIC-IDS2018 RF + IsolationForest loaded (78 features, 4 classes)"
# If it says "Using mock mode", the artifacts didn't restore — copy them back from
# /opt/pleroma-model-backup-* and restart again.
```

---

## 1. Capture benign (the important part)

```bash
mkdir -p /opt/pleroma/ml/data/base
sudo systemctl stop pleroma-sensor

sudo env PLEROMA_DUMP_CSV=/opt/pleroma/ml/data/base/benign.csv PLEROMA_DUMP_LABEL=Benign \
    /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
# Let it run ~20-30 min while you DRIVE NORMAL TRAFFIC (below), then Ctrl+C.
```

### How to drive normal traffic

"Normal" = legitimate flows in/out of the box, low-rate and well-formed. Mix
these during the window (best first):

**a) Use the app from your browser** — the most representative traffic. Log in,
click every page (Dashboard, Logs, Sensors), leave a tab auto-refreshing, and run
several **URL scans on safe sites** (e.g. `https://wikipedia.org`,
`https://github.com`). Each scan exercises inbound API → the box's outbound
scrape + Groq/Serper calls → DB — rich, varied benign flow.

**b) Paced benign load from your laptop** — steady, human-paced, well-formed
requests. The `sleep`s matter: benign traffic is slow and closes cleanly. Do
**not** remove them or it starts to look like the Hulk flood.

```bash
SITE=https://pleroma-aicds.duckdns.org
end=$(( $(date +%s) + 1800 ))            # run 30 min
while [ $(date +%s) -lt $end ]; do
  curl -s -o /dev/null "$SITE/"                      # homepage
  sleep $((RANDOM % 6 + 3))                          # 3-8s pause
  curl -s -o /dev/null "$SITE/api/v1/"              # health
  sleep $((RANDOM % 8 + 4))                          # 4-11s pause
done
```

**c) Normal outbound from the VPS** (another SSH tab on the box):

```bash
sudo apt update                  # package metadata fetch (DNS + HTTPS)
dig openai.com; dig github.com   # DNS lookups
curl -s -o /dev/null https://www.google.com https://en.wikipedia.org
git -C /opt/pleroma fetch        # normal git traffic
ping -c 20 1.1.1.1               # steady ICMP
```

**The golden rule:** keep it paced, varied, and clean — real connections, real
payloads, normal close. Avoid anything bursty (looks like DoS) or sequential-port
(looks like a scan); that's for the labeled attack captures below. Letting the box
idle is fine too — its background (duckdns cron, certbot timer, the capturing
agent's own ingest POSTs) is legitimate and recorded automatically.

> Public-IP caveat: some inbound bot/scan noise will land in "benign." Driving
> real traffic yourself keeps it a minority — and the biggest part of the flood is
> usually the box's own legit chatter, which this correctly teaches as normal.

A few hundred to a few thousand benign flows is plenty:
`wc -l /opt/pleroma/ml/data/base/benign.csv`.

---

## 2. Capture the attacks (short bursts)

A retrain needs ≥2 labeled classes (≥40 rows each). Recapture each attack so the
model keeps its 4 classes. Run the agent line on the **VPS**, fire the matching
generator from your **laptop**, `Ctrl+C` when the burst ends. Use the exact label
strings the model knows so `VERDICT_MAPPING` applies.

```bash
# PortScan
sudo env PLEROMA_DUMP_CSV=/opt/pleroma/ml/data/base/portscan.csv PLEROMA_DUMP_LABEL="PortScan" \
    /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
#   laptop:  nmap -sS -T4 -p 1-2000 pleroma-aicds.duckdns.org

# DoS attacks-Hulk
sudo env PLEROMA_DUMP_CSV=/opt/pleroma/ml/data/base/hulk.csv PLEROMA_DUMP_LABEL="DoS attacks-Hulk" \
    /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
#   laptop:  for i in $(seq 1 400); do curl -s -o /dev/null --max-time 5 https://pleroma-aicds.duckdns.org/ & done; wait

# Brute Force -Web
sudo env PLEROMA_DUMP_CSV=/opt/pleroma/ml/data/base/bruteweb.csv PLEROMA_DUMP_LABEL="Brute Force -Web" \
    /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
#   laptop:  for i in $(seq 1 300); do curl -s -o /dev/null --max-time 5 \
#              -d "username=admin@x.com&password=wrong$i" \
#              https://pleroma-aicds.duckdns.org/api/v1/auth/login & done; wait

sudo systemctl start pleroma-sensor          # resume live monitoring
wc -l /opt/pleroma/ml/data/base/*.csv        # each should be well over 40 rows
```

> `/opt/pleroma/ml/data/base/` is on persistent disk — unlike `/tmp`, these
> survive reboots, so the base set keeps growing instead of being lost.

---

## 3. Retrain

From the UI as an **admin**, or by API / CLI:

```bash
# API (needs an admin JWT)
curl -X POST https://pleroma-aicds.duckdns.org/api/v1/analysis/network/retrain \
     -H "Authorization: Bearer <admin-jwt>"
curl https://pleroma-aicds.duckdns.org/api/v1/analysis/network/retrain/status \
     -H "Authorization: Bearer <admin-jwt>"

# CLI (no token needed)
cd /opt/pleroma/backend
/opt/pleroma/.venv/bin/python -m app.services.network.retrain
```

The retrain is **safe**:

- Deploys only if the data is sufficient (≥400 rows, ≥40 per class, Benign
  present) **and** the new model beats a macro-F1 floor (0.80). Otherwise it
  reports `"deployed": false` with reasons and leaves the live model untouched.
- Deployment is atomic: current artifacts → `data/backup-<ts>/`, new ones swapped
  in, engine hot-reloads, and if it comes back mock the backup is auto-restored.

---

## 4. Apply to all workers

The backend runs `--workers 2`. A retrain hot-reloads the engine in the worker
that ran it; the other keeps the old model until:

```bash
sudo systemctl restart pleroma-backend
```

The status response includes this reminder when a deploy succeeds.

---

## 5. Verify + tune the anomaly threshold

Check whether the Suspicious/`Anomaly-novel` flood actually dropped:

```bash
cd /opt/pleroma/backend
/opt/pleroma/.venv/bin/python anomaly_report.py
```

It prints the IsolationForest score distribution over recent flows and the
fraction flagged at candidate thresholds. If too much is still flagged, set a
more-negative threshold in `/opt/pleroma/backend/.env` and restart:

```env
# flag fewer flows as novel (pick a value from anomaly_report.py)
NETWORK_ANOMALY_THRESHOLD=-0.15
```

```bash
sudo systemctl restart pleroma-backend
```

Other tunable (same file): `NETWORK_CONFIDENCE_THRESHOLD` (default `0.60`) —
below this top-class probability a `Malicious` verdict is downgraded to
`Suspicious`. Lowering the threshold only **masks** noise; the real fix is a
better benign capture + retrain.

---

## Rollback

If a retrain ever makes things worse, restore the most recent backup and restart:

```bash
cd /opt/pleroma/backend/app/services/network/data
ls -d backup-*                       # pick the latest
cp backup-<ts>/*.joblib .            # or restore from /opt/pleroma-model-backup-*
sudo systemctl restart pleroma-backend
```
