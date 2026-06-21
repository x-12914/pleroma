# Pleroma

AI-driven network intrusion detection: a sensor/server NIDS paired with an
LLM-powered URL threat scanner.

## Status

Live. The network classifier is a RandomForest + IsolationForest trained on
**flows captured by our own Scapy sensor** (78 CIC-IDS-shaped features). The
NSL-KDD prototype and the public CIC-IDS datasets are no longer used to train
the live model — see
[backend/app/services/network/README.md](backend/app/services/network/README.md)
for the authoritative model reference and the history of why.

## Layout

- `backend/` — FastAPI server: REST API, ML inference, database access, URL
  scanner. Network model docs:
  [app/services/network/README.md](backend/app/services/network/README.md).
- `frontend/` — React + Vite SPA: dashboard, sensor management, logs.
- `sensor/` — sensor agent: a self-contained **Scapy** flow tracker that
  extracts 78 features and ships them to `/ingest/flow` (no CICFlowMeter).
- `ml/` — offline data-prep / training scripts (historical CIC pipeline). The
  live retrain path is `backend/app/services/network/retrain.py`; the capture +
  retrain runbook is [deploy/CAPTURE.md](deploy/CAPTURE.md).

## Deploy target

Single VPS (no Docker). nginx serves the built frontend and reverse-proxies the
API to uvicorn on `127.0.0.1:8000` (see [deploy/](deploy/)). A sensor runs on
the VPS (and/or elsewhere) and ships flow records to `/api/v1/ingest/flow` over
HTTPS with an `X-Sensor-Key`.

## Local development

Each subdirectory has its own README. Start with [backend/README.md](backend/README.md)
and [sensor/README.md](sensor/README.md); deployment is in [deploy/DEPLOY.md](deploy/DEPLOY.md).
