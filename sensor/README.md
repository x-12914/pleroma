# Pleroma sensor agent

A long-running daemon that captures network flows on a Linux host,
extracts CIC-IDS-shaped statistical features, and ships them in
batches to a pleroma backend for classification.

It is a **self-contained Scapy flow tracker** — it does *not* wrap
CICFlowMeter. The third-party `cicflowmeter` package sniffs fine on
Python 3.14 but never flushes its CSV, so `agent.py` reimplements the 78
CIC features directly on Scapy. Those 78 features are the contract the
model is trained and served on; see
[backend/app/services/network/README.md](../backend/app/services/network/README.md).

## Architecture

```
       network NIC (eth0/wlan0/…)
                │  raw packets
                ▼
     agent.py — Scapy sniff           flow grouping + 78-feature extraction
     (this directory)                 (Flow.to_features) + batching + retry
                │  HTTPS POST + X-Sensor-Key
                ▼
   /api/v1/ingest/flow  →  heuristics → IsolationForest → RandomForest
                                              │  (only non-Benign persisted)
                                              ▼
                                       DetectionLog → dashboard / logs page
```

## Install

On the host you want to monitor (Linux only — packet capture is
platform-specific and the Python rewrite of CICFlowMeter relies on
libpcap):

```bash
# Clone the pleroma repo (or just download the sensor/ directory)
git clone https://github.com/<you>/pleroma.git
cd pleroma/sensor

# Run the installer (asks for server URL, interface, API key)
sudo ./install.sh

# Start the agent
sudo systemctl start pleroma-sensor

# Watch it
sudo journalctl -u pleroma-sensor -f
```

The installer:

- Installs system deps (`python3-venv`, `python3-pip`, `tcpdump`, `libpcap`)
- Creates an isolated venv at `/opt/pleroma-sensor/.venv` and pip-installs `scapy` + `requests`
- Copies `agent.py` to `/opt/pleroma-sensor/`
- Writes a launcher shim to `/usr/local/bin/pleroma-sensor`
- Prompts for server URL, network interface, and API key
- Installs and enables a systemd unit at `/etc/systemd/system/pleroma-sensor.service`

## Get an API key

In the pleroma dashboard:

1. Log in
2. Sidebar → **Sensors**
3. **Register** a new sensor (any descriptive name, e.g. `home-laptop`)
4. The reveal modal shows the plaintext key **once** — copy it now, it
   is unrecoverable. The installer will prompt you to paste it.

## Configuration

`/etc/pleroma-sensor/config` (world-readable, no secrets):

```ini
PLEROMA_SERVER=https://pleroma-aicds.duckdns.org
PLEROMA_INTERFACE=eth0
PLEROMA_BATCH_SIZE=50        # flows per HTTP request
PLEROMA_BATCH_INTERVAL=10    # seconds; flush partial batch after this long
PLEROMA_VERIFY_TLS=true      # set false for self-signed cert dev envs
```

`/etc/pleroma-sensor/key` (mode 600, root-owned):

```
pleroma_<43-char URL-safe random>
```

Env vars override both. Useful for testing without root:

```bash
PLEROMA_SENSOR_KEY=pleroma_xyz... \
PLEROMA_INTERFACE=lo \
sudo -E /opt/pleroma-sensor/.venv/bin/python /opt/pleroma-sensor/agent.py
```

## Verify flows are arriving

After starting the agent and generating a little traffic (browse the web,
ping somewhere, run `nmap localhost`):

```bash
# Local check — agent prints batch summaries
sudo journalctl -u pleroma-sensor -n 20

# Expected: lines like
#   sensor: shipped batch=12 logged=2  total_shipped=12 total_logged=2
```

In the dashboard, the **Sensors** page should show `last_seen` ticking
forward every batch interval. The **Logs** page should fill up with
`NETWORK_TRAFFIC` entries for any non-Benign verdict.

To force a clearly-malicious-looking flow:

```bash
# A simple TCP SYN scan against your own host should trigger
# DoS or scan-shaped flows
sudo nmap -sS -p 1-1000 127.0.0.1

# A SYN flood (only against your own host!) — definitely Malicious
sudo hping3 -S -p 80 --flood -c 5000 127.0.0.1
```

## Tuning

- **Too noisy in logs?** Raise `PLEROMA_BATCH_SIZE` so each shipment
  covers more flows; reduces logging volume.
- **Slow to surface threats?** Lower `PLEROMA_BATCH_INTERVAL` so partial
  batches flush sooner.
- **Wrong interface?** Edit `/etc/pleroma-sensor/config` and
  `sudo systemctl restart pleroma-sensor`.

## Uninstall

```bash
sudo systemctl disable --now pleroma-sensor
sudo rm /etc/systemd/system/pleroma-sensor.service
sudo rm /usr/local/bin/pleroma-sensor
sudo rm -rf /opt/pleroma-sensor /etc/pleroma-sensor
sudo systemctl daemon-reload
```

Revoke the API key in the pleroma dashboard's Sensors page so a leaked
key can't be re-used.

## Security notes

- The agent runs as **root** because raw packet capture requires
  `CAP_NET_RAW` + `CAP_NET_ADMIN`. The systemd unit applies
  `NoNewPrivileges`, `ProtectKernelTunables`, and friends to limit blast
  radius if cicflowmeter or the agent itself is ever compromised.
- The API key is stored at `/etc/pleroma-sensor/key` with mode 600,
  root:root. Don't `cat` it into shell history.
- Captured features include `Dst Port` but **not** payload contents.
  Source/dest IP addresses are sent to the backend (so the operator can
  see *where* a threat came from) but are not retained in the model —
  they're not in the feature set the RandomForest was trained on.
