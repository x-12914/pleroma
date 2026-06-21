# Pleroma — Memory

_Last updated: 2026-06-21_

AI-driven Network Intrusion Detection System (NIDS) on a single VPS
(`opt@157.250.205.174` / `pleroma-aicds.duckdns.org`): FastAPI backend +
React/Vite frontend + self-contained Scapy sensor (78 CIC-shaped features) +
RandomForest + IsolationForest model. Also an LLM-powered URL threat scanner.
Live classes: `Benign`, `Brute Force -Web`, `DoS attacks-Hulk`, `PortScan`.

**End goal:** software that detects AND autonomously *handles* network threats
(NIDS → autonomous NIPS/SOAR). Autonomy model: auto-execute only reversible,
high-confidence actions (TTL'd firewall block, rate-limit); recommend-and-wait
for higher-blast-radius/host actions; alert/notify always-on. Response scope in
scope: firewall IP blocking, rate-limiting, alert/notify, host/service actions.

**Productization:** intended to be SOLD to agencies who run it on their OWN
different servers (heterogeneous, on-prem, we won't have access). This reframes
everything: model must self-calibrate per environment (no shippable golden
model), enforcement must be pluggable (not VPS-specific), safe-by-default +
recoverable-without-vendor, packaged install + updates + licensing, and product
security/supply-chain become customer-facing. The current VPS becomes the
reference/demo/dev deployment.

## Completed
- ✅ Phase 8b — IsolationForest anomaly layer between heuristics and RF (commit 4bc6206)
- ✅ Safe retrain pipeline — single `retrain.py`, data+quality gate (≥400 rows, ≥40/class, Benign present, macro-F1 ≥0.80), atomic deploy with auto-rollback; killed the NSL-KDD `trainer.py` footgun (commit 9b45914)
- ✅ Auto-benign sampling into `training_samples` table at ingest (commit 9b45914)
- ✅ Configurable network thresholds (`NETWORK_ANOMALY_THRESHOLD`, `NETWORK_CONFIDENCE_THRESHOLD`) + `anomaly_report.py` diagnostic (commit b86edb3)
- ✅ Stopped git-tracking model artifacts — server-only now (commit 5ac957e)
- ✅ Expanded `deploy/CAPTURE.md` into full capture+retrain runbook (commit a1cb8f8)
- ✅ Direct VPS access wired up — SSH key login + scoped passwordless sudo (systemctl/journalctl) (2026-06-21)
- ✅ Phase 1 Step 0 — deployed safe pipeline to live VPS (now on `fix/safe-retrain-pipeline`, model backed up + preserved, engine real mode, `training_samples` table created, configurable thresholds live) (2026-06-21)

## In Progress
- 🔄 Product strategy locked — see [ROADMAP.md](ROADMAP.md): hybrid (cloud control plane + local data plane), 5-phase program, parallel build-agent workstreams. Architecture tension to confirm: pure SaaS vs hybrid (raw data local) — proceeding on hybrid.
- 🔄 Branch `fix/safe-retrain-pipeline` — 4 commits ahead of `main`, NOT yet merged. Decide merge timing.
- 🔄 Phase 1 (Detection trust) — Step 0 DONE (safe pipeline deployed, benign auto-accumulating, loop verified). Scan-probe flood DIAGNOSED: it's genuine internet background scanning (12,765 distinct src IPs/7d, single-SYN to telnet/SMB/RDP/MSSQL ports) — TRUE POSITIVES, heuristic is correct, do NOT weaken it. So the flood is a volume/triage problem, not a detection bug. Fix = response-layer repeat-offender suppression (ideal FIRST autonomous-response use case; detection already trustworthy here) + UI/storage aggregation of scan campaigns. Separate: `Anomaly-novel` 16% still needs benign+attack capture → retrain (sudoers widen for Scapy) + `anomaly_report.py` threshold tuning.
- 🔄 Phase 2 contracts drafted — [docs/CONTRACTS.md](docs/CONTRACTS.md) (response_actions/policy_rules/allowlist/enforcement_state schemas, enforcement-adapter interface, policy engine, API). Awaiting review before agent fan-out.

## Planned / Future
- ⬜ Capture representative benign + recapture 3 attack classes on VPS, run safe retrain, tune `NETWORK_ANOMALY_THRESHOLD` via `anomaly_report.py` (the primary fix for the flood). Needs sudoers widened for Scapy raw-socket capture.
- ⬜ Merge `fix/safe-retrain-pipeline` → `main` (give PR URL; `gh` not installed locally)
- ⬜ Security: SSRF in URL scanner (`intelligence/engine.py _scrape_url`)
- ⬜ Security: rate limiter broken behind nginx (`get_remote_address` sees 127.0.0.1)
- ⬜ Security: IDOR on `/logs/{id}/feedback`
- ⬜ Infra: no Alembic migrations; durable job queue for retrain
- ⬜ Hardening: nginx security headers; move JWT tokens out of localStorage
