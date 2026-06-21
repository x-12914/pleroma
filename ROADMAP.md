# Pleroma — Product Architecture & Roadmap

_Last updated: 2026-06-21_

**Goal:** autonomous network threat detection **and response** (NIDS →
NIPS/SOAR), sold to agencies who run it on their own heterogeneous servers.

**Deployment model (LOCKED 2026-06-21):** hybrid — **multi-tenant cloud control
plane (vendor-hosted)** + **local data plane (customer-hosted)**. **Data-local by
default**: raw network data stays on the customer box; only opt-in, scrubbed
telemetry / federated model updates leave ("SaaS-managed, data-local"). A
vendor-hosted **"managed cloud" tier is opt-in only**, for non-sensitive
customers who explicitly want us to host — never the default, so agency/gov
buyers (who forbid data egress) are never locked out.

---

## Two planes

### Data plane — customer-hosted (local, private)
- Sensors with a **pluggable capture path** (Scapy now → AF_PACKET/eBPF/Suricata
  later for high throughput).
- Local detection engine (RandomForest + IsolationForest), **self-calibrated to
  the customer's own network** (no shippable golden model).
- Local **policy/decision engine**.
- **Pluggable enforcement adapter**: nftables / iptables / firewalld / cloud
  security groups / dry-run. Dry-run is the universal default.
- Local data store + management/console server. **Single-box OR console+fleet**,
  configurable (sensor enrollment, keys, per-sensor health/policy).
- Raw network data **never leaves** without explicit opt-in.

### Control plane — vendor-hosted (cloud, multi-tenant)
- Tenant + **license/entitlement** management.
- **Fleet/sensor enrollment** & key management.
- **Model distribution + signed update channel + rollback.**
- **Opt-in, scrubbed telemetry** + health/observability (support boxes we can't
  SSH into).
- Optional **federated model improvement** — improve shared *attack* detection
  across customers without moving raw data.
- Central admin dashboards.

---

## Cross-cutting principles (design in from day one)
- **Safe-by-default**: ships in dry-run/recommend; customer explicitly opts into
  auto. Auto only for reversible + high-confidence actions (TTL'd block,
  rate-limit); host/service + low-confidence are recommend-and-wait.
- **Never self-lock-out**: allowlist + admin/SSH/own-box protection enforced at
  the lowest enforcement layer, for the *customer's* admins. Local kill switch
  the customer can hit without the vendor.
- **Per-tenant config store** (not hand-edited .env): policy, thresholds,
  allowlist, response scope, autonomy mode — managed from the UI.
- **Versioned feature contract**: the 78-feature schema is versioned and checked
  at runtime so sensor/model version skew can't silently brick detection.
- **Self-calibrating onboarding** ("learning mode") per deployment.
- **Product security** (it holds root on customer networks → supply-chain crown
  jewel): signed releases; fix SSRF (URL scanner), IDOR (/logs/{id}/feedback),
  rate limiter behind nginx, JWT-in-localStorage before any external sale.
- **Model-poisoning guardrails** on the local feedback/retrain loop.

---

## Phased program

| Phase | What | Status |
|---|---|---|
| 1. Detection trust + self-calibration | Fix anomaly flood on reference VPS; productize as per-customer learning mode | ⬜ next |
| 2. Response system, built dark | Contracts → enforcement adapter + root reconciler + policy engine + UI controls; dry-run on live box | ⬜ |
| 3. Productize data plane | Packaging/containers, per-tenant config, onboarding, versioned feature contract, fleet enrollment, security hardening | ⬜ |
| 4. Cloud control plane | Licensing, update channel, telemetry, central mgmt, federated learning | ⬜ |
| 5. Enable graduated autonomy | Flip dry-run → auto for reversible/high-confidence, per-tenant | ⬜ |

## Parallel build-agent workstreams (after shared contracts are locked)
- **A** — enforcement adapter + root reconciler + safety rails
- **B** — policy/decision engine + ingest integration
- **C** — frontend control panel (kill switch, blocklist, approvals, audit, dry-run view)
- **D** — detection / self-calibration track (reference VPS) — *can start now*
- **E** — packaging + signed update channel (later)
- **F** — cloud control plane (later; largest net-new)
- **G** — security hardening (later, before external sale)

## Reference deployment
The current VPS (`opt@157.250.205.174`) is the **reference / demo / dev** box —
where each piece is proven in dry-run before it's productized.
