# Lab capture harness — ground-truth attack data for retraining

Reusable tooling to generate Tier-A attacks and capture them — labeled and
aligned to the sensor's feature schema — for the network model retrain. See
[../docs/THREAT-COVERAGE.md](../docs/THREAT-COVERAGE.md) for the class roadmap and
[../deploy/CAPTURE.md](../deploy/CAPTURE.md) for the benign-capture runbook.

## Why this exists
The model must be trained on flows captured by **our own sensor** (foreign PCAPs
skew the features and brick detection). This harness produces clean, labeled CSVs
in `/opt/pleroma/ml/data/base/`, which `retrain.py` reads automatically.

## Two roles
- **Capture host = the VPS** (where the sensor runs). Runs `capture.sh` as root.
- **Attacker host = a separate Linux box** (a throwaway VM, or your laptop via
  WSL/Docker). Runs the `attacks/*.sh` generators against the VPS's public IP.

> Don't attack from the VPS against itself — the kernel short-circuits same-host
> traffic to loopback, so the flows look nothing like a real network attack (and
> loopback is allowlisted). Use a distinct source IP.

## The label-quality trick
On a public IP the box is hammered by background scanners 24/7. A naive capture
window would mislabel that noise. `capture.sh --attacker-ip <IP>` filters the dump
to flows whose source is the attacker, giving **clean single-class data**. Always
pass it.

## Prerequisites (once, on the VPS)
The capture needs root (raw sockets) and to bounce the live sensor. Either run
`capture.sh` under interactive `sudo`, or widen the passwordless sudoers
(`/etc/sudoers.d/pleroma`) to add:
```
opt ALL=(ALL) NOPASSWD: /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
```
(systemctl start/stop pleroma-sensor is already allowed.)

Attacker tools (install on the attacker host as needed):
`nmap`, `hydra`, `slowhttptest`, `hping3` (+ `curl`, already present).

## Usage — pair a capture window with an attack
On the **VPS** start the capture (it runs for `--duration` then auto-stops):
```bash
sudo bash lab/capture.sh --label "PortScan" --duration 90 --attacker-ip <ATTACKER_IP>
```
Immediately on the **attacker host**, fire the matching generator:
```bash
bash lab/attacks/portscan.sh pleroma-aicds.duckdns.org
```
`capture.sh` restarts the live sensor and writes `PortScan-<ts>.csv` to the base
dir. Repeat per class; each run adds a timestamped CSV (nothing is overwritten).

## Attack catalogue (Tier A)

| Script | Label string | Tool | Impact |
|---|---|---|---|
| `attacks/portscan.sh` | `PortScan` | nmap | low |
| `attacks/web-brute.sh` | `Brute Force -Web` | curl | low |
| `attacks/ssh-brute.sh` | `Brute Force -SSH` | hydra | low |
| `attacks/dos-slowloris.sh` | `DoS attacks-Slowloris` | slowhttptest | medium |
| `attacks/dos-slowhttptest.sh` | `DoS attacks-SlowHTTPTest` | slowhttptest | medium |
| `attacks/dos-hulk.sh` | `DoS attacks-Hulk` | curl flood | **high** (CONFIRM=yes) |
| `attacks/flood-syn.sh` | `DoS-SYNFlood` | hping3 | **high** (CONFIRM=yes) |

UDP/ICMP floods, GoldenEye, and amplification follow the same pattern — copy a
script and swap the generator. Keep label strings EXACT and consistent.

## After capturing: wire new classes into the engine
`retrain.py` will pick up the CSVs automatically. But a brand-new class (e.g.
`Brute Force -SSH`, `DoS-SYNFlood`) also needs a verdict mapping, or the engine
defaults it to `Suspicious`:
- add it to `VERDICT_MAPPING` in `backend/app/services/network/engine.py`
  (DoS/flood → `Malicious`; brute/scan → `Suspicious` or `Malicious` per policy),
- then retrain and `systemctl restart pleroma-backend`.

## Safety
- High-impact scripts (`dos-hulk`, `flood-syn`) refuse to run without `CONFIRM=yes`
  and default to short bursts. They hit a **live** box — keep windows short, off
  peak, and only against infrastructure you own.
- Captures briefly stop the live sensor (so two sensors don't fight the NIC); it's
  restarted automatically. Detection is paused for the capture window only.
