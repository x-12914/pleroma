# Pleroma

AI-driven network intrusion detection: a sensor/server NIDS paired with an
LLM-powered URL threat scanner.

## Status

Under active redevelopment. The classifier is being migrated from NSL-KDD to
CIC-IDS2017, and a real packet-capture sensor is being built to replace the
original prototype's manual feature-entry UI.

## Layout

- `backend/` — FastAPI server: REST API, ML inference, database access, URL
  scanner.
- `frontend/` — React + Vite SPA: dashboard, sensor management, logs.
- `sensor/` — sensor agent (CICFlowMeter wrapper + ship-to-server). Populated
  in Phase 4.
- `ml/` — model training scripts and notebooks. Populated in Phase 2.

## Deploy target

Single VPS (no Docker). Caddy serves the built frontend and reverse-proxies
the API. Sensors live elsewhere (e.g. a laptop on a home network) and ship
flow records to the VPS over HTTPS.

## Local development

Each subdirectory has its own setup; see per-directory READMEs once those
land in their respective phases.
