# Threat Coverage Roadmap

_Last updated: 2026-06-21 · status: planning_

What Pleroma detects today, what to add, and how — to make it a comprehensive,
sellable NIDS/NIPS. Read alongside [ROADMAP.md](../ROADMAP.md) and the model
reference (`backend/app/services/network/README.md`).

## The governing constraint: a flow-statistics sensor

The sensor emits **78 CIC-shaped flow features** — counts, durations, inter-arrival
times, byte/packet-size stats, TCP-flag tallies, per-direction rates. Consequences:

- **Strong at volumetric + behavioral attacks** (rate, timing, shape): DoS/DDoS,
  scans, brute-force, beaconing, exfiltration, amplification.
- **Blind to payload content**: it cannot see a SQLi/XSS string, a malware blob,
  or an exploit. Those need L7/DPI or a content engine.
- **Four detection strategies, used together:**
  1. **Heuristics** — cheap, unambiguous shapes (single-SYN probe, slow-headers).
  2. **RandomForest** — supervised multiclass for *known, labeled* attack classes.
  3. **IsolationForest (anomaly layer)** — the catch-all for *unknown/novel* traffic
     (zero-days, anything we never trained). This is why we don't need to enumerate
     every attack — the anomaly layer covers the long tail.
  4. **Out-of-band engines** — the LLM **URL scanner** (web/content threats) and a
     future **threat-intel** module (known-bad IPs/domains). These cover what flow
     features can't.

Every new *RF class* must be trained on flows **captured by our own sensor**
(ground truth or log-mined) — never on foreign PCAPs/CSVs (feature skew bricks it).

## Current coverage

| Class | How | Quality |
|---|---|---|
| Benign | RF + auto-sampled | being rebuilt (Phase 1 retrain) |
| DoS attacks-Hulk | RF (log-mined) | good |
| PortScan | RF (log-mined) | good |
| Brute Force -Web | RF | poor (~5% precision) → ground-truth recapture |
| ScanProbe / SlowHeaders | heuristics | reliable shapes |
| Anomaly-novel | IsolationForest | needs representative benign (Phase 1) |

---

## Tier A — add now (flow-detectable, ground-truth capturable with simple tools)

These extend the RF with classes the sensor can clearly separate. Each is
generated from a controlled host and captured via the sensor's dump mode → clean
labels. Priority order:

| Priority | Class(es) | Generate with | Notes |
|---|---|---|---|
| 1 | **Brute Force -Web** (recapture) | `hydra`/custom login flood | already planned; fixes the noisy class |
| 2 | **SSH / FTP / RDP brute force** | `hydra`, `medusa` | very common on public + internal; distinct repeated-short-auth flows |
| 3 | **DoS: GoldenEye, Slowloris, SlowHTTPTest** | `slowhttptest`, `goldeneye` | complete the DoS family (already in VERDICT_MAPPING) |
| 4 | **Volumetric floods: SYN / UDP / ICMP flood** | `hping3` | classic DDoS primitives; very strong flow signal |
| 5 | **DDoS (distributed)** | multi-source flood sim | scale variant of above |
| 6 | **Scan variants: host sweep, vuln scan, aggressive nmap** | `nmap`, `nikto`, `masscan` | broaden recon coverage beyond PortScan |
| 7 | **Amplification: DNS / NTP / memcached** | lab reflectors | volumetric, distinctive; relevant to ISP/gov |

## Tier B — behavioral (flow-detectable, but need realistic generation)

| Class | Signal | Generate with |
|---|---|---|
| **Botnet / C2 beaconing** | periodic small symmetric flows | Caldera, Atomic Red Team, lab C2 (Sliver/Mythic) |
| **Data exfiltration** | large/sustained unusual outbound | scripted bulk transfer to external host |
| **Cryptomining** | persistent pool connections, steady flows | miner against a test pool |
| **Lateral movement / internal recon** | internal SMB/scan patterns | enterprise-segment only; lab AD env |

These matter most to **enterprise/gov** buyers (insider + post-compromise);
public-server buyers care more about Tier A.

## Tier C — needs NEW sensor capability (payload / protocol awareness)

Honest gaps — the flow sensor can't do these without added extraction:

| Capability | What it unlocks | Approach |
|---|---|---|
| **DNS parsing** | DNS tunneling/exfil, DGA domains, amplification detail | add DNS feature extraction to the sensor |
| **TLS/JA3(S) fingerprinting** | malware C2 over TLS, tool identification | add TLS handshake features (no decryption needed) |
| **L7 / DPI signatures** | SQLi, XSS, exploit payloads, web shells | Suricata/Zeek **sidecar** feeding Pleroma, or lean on the URL scanner |
| **L2 visibility** | ARP spoofing / MITM | requires the sensor on the right span/tap |

## Tier D — intelligence & framework (high value, mostly non-ML)

| Item | Value | Effort |
|---|---|---|
| **Threat-intel IP/domain blocklists** (IOC matching at ingest) | instant high-confidence blocks of known-bad; great demo | low — IOC feed + lookup; feeds the response layer directly |
| **MITRE ATT&CK technique mapping** on every detection | agencies expect it; turns alerts into a kill-chain story | low-med — tag each class/heuristic with technique IDs |
| **GeoIP / ASN enrichment** | context for triage + policy (e.g. block by geo) | low |
| **Reputation/aging of repeat offenders** | smarter auto-response thresholds | med — ties into the policy engine |

---

## Data acquisition strategy (the bottleneck)

- **Ground-truth capture** (best): generate the attack from a controlled host,
  capture via the sensor's dump mode with the exact label → clean rows aligned to
  `feature_names`. Codify a reusable **lab harness** (a script per attack using the
  tools above) so any deployment can regenerate/refresh classes.
- **Log-mining** (cheap, for reliable classes): pull `raw_input` from
  `detection_logs` for high-precision classes (as we now do for DoS-Hulk/PortScan).
- **Safe malware simulation**: use Atomic Red Team / Caldera / open C2 frameworks
  in an isolated lab — never live malware in production.
- **Per-customer self-calibration**: each deployment learns its own *benign* and
  can enable the class library relevant to its environment (public vs enterprise).

## Response mapping (each class → policy default)

| Severity | Classes | Default action (when graduated) |
|---|---|---|
| High, reversible | volumetric DoS/DDoS, floods, amplification, confirmed C2 | auto **block** (TTL) |
| Medium | scans, brute-force, beaconing | **throttle** → block on repeat |
| Payload/web | SQLi/XSS/web (Tier C) | **alert** + URL-scanner correlation |
| Unknown | Anomaly-novel | alert/recommend; feed triage + retrain |

## Suggested sequencing

1. **Finish Phase 1** (benign + DoS-Hulk + PortScan retrain; kill the flood).
2. **Tier A 1–4** (brute-force family + DoS family + floods) — biggest coverage
   gain, simplest capture; build the reusable lab-capture harness here.
3. **Tier D threat-intel + ATT&CK tagging** — cheap, high perceived value for sales.
4. **Tier B behavioral** (C2/exfil) — differentiator for enterprise/gov.
5. **Tier C capabilities** (DNS, TLS/JA3, DPI sidecar) — larger engineering; do as
   target segments demand.

> The anomaly layer means we ship value before this list is complete — unknown
> attacks still surface as `Anomaly-novel`. This roadmap is about converting the
> long tail into *named, explained, auto-actionable* detections over time.
