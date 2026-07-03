# Customer onboarding runbook (managed service)

The repeatable playbook for standing Pleroma up on a **customer's** server and
getting it to autonomous enforcement *safely*. This is the services-first path:
we deploy, calibrate to their network, and operate it.

The #1 rule: **the model is calibrated per network.** A fresh install will flag a
new customer's normal traffic until it learns their baseline. So every customer
goes dry-run → recommend → auto, never straight to blocking.

Reference deployment mechanics live in [DEPLOY.md](DEPLOY.md) and
[CAPTURE.md](CAPTURE.md); this file is the customer-facing sequence + the bits
that differ per customer.

---

## 0. Pre-engagement (before touching their box)
- [ ] **Written sign-off** that Pleroma will *autonomously block traffic*, starting
      in observe-only and graduating with their approval. (Liability: a false block
      can drop their traffic — make this explicit in the contract/SOW.)
- [ ] Collect their **admin/office/VPN source IPs or CIDRs**, monitoring/uptime
      checkers, and any partner IPs that must NEVER be blocked → the allowlist seed.
- [ ] Confirm server: Linux, root/sudo, a public IP, ports 80/443 reachable, and
      where the sensor will see traffic (the host itself / a SPAN port for multi-host).
- [ ] Decide DB: their Postgres, or one we provision. (Per-customer isolation —
      never share a DB across customers.)

## 1. Install (per DEPLOY.md, customer-specific values)
- [ ] Ship code, create venv, install deps (DEPLOY.md §1–2).
- [ ] `backend/.env`: **generate a fresh `SECRET_KEY`**, set their `DATABASE_URL`,
      a real `GROQ_API_KEY` (URL scanner), and:
      `RESPONSE_DEFAULT_MODE=dry_run` (safe default),
      `RESPONSE_ADMIN_ALLOWLIST=<their admin CIDRs>` (from step 0).
- [ ] systemd backend (DEPLOY.md §4), nginx vhost + **security headers**
      (nginx-pleroma.conf) + certbot TLS for their domain (DEPLOY.md §6–7).
- [ ] Build + ship frontend (DEPLOY.md §5).
- [ ] Create the customer's **admin account**; hand off credentials securely.

## 2. Sensor + baseline collection
- [ ] Register a sensor in the UI, install + start `pleroma-sensor` on the host(s).
- [ ] Confirm flows are arriving (Sensors page shows last-seen; `detection_logs`
      growing). System is in **dry_run** — it observes, records `would_apply`
      decisions, enforces nothing.
- [ ] Let it run a **benign-learning window** (≈24–48h of the customer's real
      traffic). Auto-benign sampling fills `training_samples`; temporarily raise
      `BENIGN_SAMPLE_RATE` if their volume is low.

## 3. Calibrate the model to THEIR network  → automated by `onboard.sh`
- [ ] Run `bash deploy/onboard.sh --learn-minutes 120` (as `opt`). It pre-flights,
      runs the benign-learning window, retrains to their baseline, and prints the
      anomaly-threshold report — leaving the system in dry_run. Add `--set-threshold`
      to auto-apply the suggested `NETWORK_ANOMALY_THRESHOLD`.
- [ ] (Optional, higher quality) before the retrain, capture labeled attacks against
      their box from a controlled host via the [lab harness](../lab/README.md) → base CSVs.
- [ ] Verify the `Anomaly-novel`/Suspicious rate on their dashboard is sane.

## 4. Seed safety rails (BEFORE any enforcement)
- [ ] Allowlist contains: loopback, **the box's own public IP(s)**, the customer's
      admin/office/VPN CIDRs, monitors. Double-check via the Response page.
- [ ] Confirm the **kill switch** is reachable by the customer (Response page) and
      they know how to hit it.
- [ ] Review the seeded **policy rules** with the customer (what gets blocked, TTLs).

## 5. Graduate enforcement (with the customer)
1. **dry_run** (days): review the `would_apply` decisions together — confirm it
   would only block real attackers, nothing of theirs.
2. **recommend**: customer approves/rejects blocks from the UI for a few days.
3. Install the **root reconciler** (`pleroma-reconciler.service`) + set
   `RESPONSE_ENFORCEMENT_ADAPTER=nftables` (or their firewall). Do ONE controlled
   approved block end-to-end (verify apply + auto-expire).
4. **auto**: flip to autonomous for high-confidence reversible blocks, with sign-off.
   Host/ambiguous actions stay human-gated.

## 6. Handover + ongoing ops (the recurring service)
- [ ] Customer has: dashboard access, kill switch, the "what we block & why" summary.
- [ ] We retain: monitoring of their instance, monthly tuning/retrain, updates,
      incident review. (This is what the retainer pays for.)
- [ ] Schedule a weekly check-in for the first month, then monthly.

---

## Per-customer config quick reference
| Setting | Where | Per-customer? |
|---|---|---|
| `SECRET_KEY` | backend/.env | yes — unique |
| `DATABASE_URL` | backend/.env | yes — isolated DB |
| `RESPONSE_ADMIN_ALLOWLIST` | backend/.env | yes — their admin CIDRs |
| `RESPONSE_DEFAULT_MODE` | backend/.env | start `dry_run` always |
| `NETWORK_ANOMALY_THRESHOLD` | backend/.env | tuned to their traffic |
| Model artifacts | `data/` | retrained on their baseline |
| Allowlist / policy rules | DB (Response UI) | yes |

## Still-manual gaps to automate next (productization backlog)
- One-shot **installer script** (steps 1–2) instead of hand-running DEPLOY.md.
- ✅ **Calibration automation** — `deploy/onboard.sh` (benign window + retrain +
  threshold report; leaves dry_run).
- ✅ **Own-IP auto-detect** for the allowlist seed (bootstrap now auto-allowlists
  the box's own IPs; `RESPONSE_AUTOALLOWLIST_OWN_IP`).
- Central **control plane** for licensing + multi-customer monitoring + updates.
