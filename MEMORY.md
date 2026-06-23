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
- ✅ Security hardening round 1 (2026-06-22, deployed): fixed SSRF in URL scanner (_scrape_url resolves host, blocks private/loopback/link-local/metadata IPs, manual redirect re-validation — verified blocks 169.254.169.254/127.0.0.1/192.168.x, allows public); IDOR on /logs/{id}/feedback (ownership 404/403, no raw-error leak); rate-limiter keyed on real client IP (X-Real-IP, was 127.0.0.1) + added auth limits (login 5/min, register 3/min) — verified 429s fire. nginx security headers (CSP/HSTS/X-Frame-Options/nosniff/Referrer-Policy/Permissions-Policy) applied to live config + verified (6/6 headers, homepage 200, CSP safe for the Vite build). Remaining security items below.
- ✅ Tier A lab-capture harness built — [lab/](lab/) (`capture.sh` VPS-side root capture w/ attacker-IP filter for clean labels, `filter_by_ip.py`, `attacks/*.sh`: portscan/web-brute/ssh-brute/slowloris/slowhttptest/hulk/syn-flood). Execution pending: needs an attacker host (separate Linux IP) + sudoers widened for the sensor python. New classes also need a `VERDICT_MAPPING` entry in engine.py. (2026-06-21)

## In Progress
- 🔄 Product strategy locked — see [ROADMAP.md](ROADMAP.md): hybrid (cloud control plane + local data plane), 5-phase program, parallel build-agent workstreams. Architecture tension to confirm: pure SaaS vs hybrid (raw data local) — proceeding on hybrid.
- ✅ Merged `feat/autonomous-response` → `main` (merge commit 6c94db1, pushed 2026-06-22); VPS now tracks `main`. Brings in safe-retrain pipeline, Phase 2 response (dry_run), Phase 1 4-class retrain, lab harness, all docs. (`fix/safe-retrain-pipeline` work is included via this merge.)
- 🔄 Phase 1 (Detection trust) — RETRAIN DEPLOYED 2026-06-22 (4-class, macro-F1 0.99, backup data/backup-20260621-230850, rollback-safe). Training data: ground-truth captures via lab harness (PortScan 4054, Brute-Web 898, Hulk 92, attacker-IP-filtered) + log-mined DoS-Hulk/PortScan (2000 ea) + 969 auto-benign. Wins: Brute-Web precision ~5%→0.99; all classes 0.98-1.00; held-out BENIGN-flagged rate 3.6% (was ~16% live Anomaly-novel). LIVE RESULT (2026-06-22, ~2h post-retrain): Anomaly-novel ~2.45/min (was ~4.5/min — roughly HALVED in absolute terms) but ~31% of logged (share UP because scan traffic is lighter right now — variance, not model). KEY INSIGHT: retrain's real wins are the CLASSIFIER (Brute-Web fixed, 4 clean classes) + halved novel rate; it does NOT fix the dashboard flood, which is a VOLUME/TRIAGE problem (true-positive scan background + genuinely-novel traffic), not a model error. Dashboard fix = response-layer auto-suppression + UI aggregation (→ Phase 2 graduation), NOT more model work. Optional further reduction: tune NETWORK_ANOMALY_THRESHOLD more negative, or broaden benign (current set narrow — driven curl loops). Scan-probe flood (~75%, ScanProbe-heuristic) is TRUE-POSITIVE internet background — unaffected by retrain; fix via response-layer suppression + UI aggregation.
- 🔄 Phase 2 (Autonomous response) BUILT + code-reviewed + DEPLOYED to VPS in dry_run (branch `feat/autonomous-response`, commit 4288442). Foundation (4 tables, types, guards, bootstrap, config) + 3 agent layers: enforcement adapters (dryrun default / nftables) + root reconciler (NOT installed yet), policy engine + /response API (13 routes) + non-fatal ingest hook, React control panel. Verified: imports clean on VPS venv, frontend tsc clean, backend active in real mode, tables seeded (enforcement_state=dry_run, allowlist=loopback+102.212.253.0/24+157.250.205.174/32, 3 policy rules), `response_actions` filling with `would_apply` rows from live traffic (nothing enforced).
  - Review fix: scan rules used min_repeats=10/window=600 which the 10-min ingest dedup made unfireable → changed to window=3600/min_repeats=2; documented that real scan suppression likely needs block-on-first / subnet aggregation (12.7k distinct scanner IPs, long tail).
  - Dry-run CAUGHT a safety gap: the VPS's own public IP (157.250.205.174) appeared as a detection src — added to allowlist so auto mode can never block self.
  - DRY-RUN DECISIONS REVIEWED (2026-06-22, 391 over ~3h): 353 blocks of repeat scanners (ScanProbe 333 + PortScan 20, 158 distinct external IPs) + 38 DoS-Hulk alerts — all sane, no legit traffic caught. Allowlist VERIFIED working: own IP only in 2 stale rows from the 2-min window before it was allowlisted (21:05-06 vs allowlist 21:07), zero since; admin IP 0 ever. Policy ready to graduate. GRADUATION (2026-06-23): mode flipped to `recommend` (verified — new blocks route to `pending`; stale own-IP rows cleaned); `RESPONSE_ENFORCEMENT_ADAPTER=nftables` set in .env. STILL NON-ENFORCING — the root reconciler isn't installed yet. Root reconciler INSTALLED + running (nftables, healthy). ENFORCEMENT VALIDATED end-to-end (2026-06-23): approved block → nft rule applied AND persists → TTL expiry removes it. Caught+fixed a reconciler bug (commit dcd0edf: db.flush() before drift check — autoflush=False made just-applied blocks look unbacked and get drift-removed same-pass). Current mode = `recommend` (blocks queue as pending → human approves in UI → enforced). GRADUATED TO AUTO (2026-06-23, mode=auto, updated_by claude-graduate): fully autonomous enforcement LIVE. Auto-blocks repeat scanners (ScanProbe/PortScan 2/3600s) + DoS-Hulk (new rule pri 40, 1/600s); DoS verdict also alerted. Enforcement path proven end-to-end (recommend test: apply persists + expire). CONFIRMED live: within minutes of going auto, 8 autonomous blocks applied to nft (6 scanners + 2 DoS-Hulk), all external, none allowlisted — full loop detect→decide→auto-block→auto-expire verified on real traffic. Safety verified: allowlist (own/admin/loopback) + TTL auto-expiry + kill switch + manual revert; no allowlisted IP ever actioned. KILL SWITCH: set enforcement_state.kill_switch=true (or mode=off) to instantly disable. THE END-GOAL (autonomous detect+respond) IS NOW LIVE on the reference VPS.

## Planned / Future
- ⬜ Response Phase 2 graduation: after observing dry-run `would_apply` data, tune policies, install `deploy/pleroma-reconciler.service` (root) + switch `RESPONSE_ENFORCEMENT_ADAPTER=nftables`, then move mode dry_run→recommend→auto. Widen sudoers for the reconciler (root nft) — or run it as a root systemd unit (no sudo needed).
- ⬜ Response productization: guards must AUTO-detect & allowlist the box's own interface IPs per deployment (dry-run caught the VPS's own IP as a detection src — hardcoding won't scale to customers). Also implement throttle in nftables adapter, alert delivery (webhook) + lifecycle, and a real repeat-counter (the detection_logs proxy is dedup-limited).
- ⬜ Threat-coverage expansion — see [docs/THREAT-COVERAGE.md](docs/THREAT-COVERAGE.md). Sensor is flow-statistical (strong on volumetric/behavioral, blind to payload). Add order: Tier A (brute-force family, DoS family, floods, scan/amp variants — ground-truth capturable now via a reusable lab harness), then Tier D (threat-intel IOC blocklists + MITRE ATT&CK tagging — cheap/high-value), then Tier B behavioral (C2/exfil/cryptomining/lateral), then Tier C new sensor capabilities (DNS parsing, TLS/JA3, L7/DPI sidecar). Anomaly layer covers unknowns meanwhile.
- ⬜ Capture representative benign + recapture Brute-Force (ground truth) on VPS; tune `NETWORK_ANOMALY_THRESHOLD` via `anomaly_report.py`. Needs sudoers widened for Scapy raw-socket capture (lab harness).
- ⬜ Merge `fix/safe-retrain-pipeline` → `main` (give PR URL; `gh` not installed locally)
- ⬜ Security: rate limiting now functional (per-real-IP) but per-worker (slowapi in-memory, --workers 2 → ~2x). Robust exact cap = nginx `limit_req` on /api/v1/auth/* OR Redis-backed slowapi store. Follow-up.
- ⬜ Security: JWT in localStorage → migrate to httpOnly cookie + CSRF (larger auth-flow change, front+back). Follow-up.
- ⬜ Security (product): open registration creates accounts freely — consider invite/admin-only for agency deployments.
- ⬜ Infra: no Alembic migrations; durable job queue for retrain
