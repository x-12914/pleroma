#!/usr/bin/env python3
"""Pleroma sensor agent.

Captures network flows via cicflowmeter (Python rewrite of the CIC tool),
extracts CIC-IDS2018-shaped feature vectors, and ships them in batches to
a pleroma backend's /api/v1/ingest/flow endpoint authenticated with an
X-Sensor-Key header.

Config priority (highest first):
    1. environment variables (PLEROMA_SERVER, PLEROMA_INTERFACE, PLEROMA_BATCH_SIZE, ...)
    2. /etc/pleroma-sensor/config        (KEY=VALUE per line)
    3. built-in defaults

The sensor key is read from /etc/pleroma-sensor/key (mode 600) so the
config file itself can be world-readable for debugging without leaking
the credential.

Architecture:
    cicflowmeter (subprocess)  →  /tmp/pleroma-flows.csv (append-only)
                                          ↓
                                  agent.py tails the CSV
                                          ↓
                                  batch (size or time threshold)
                                          ↓
                                  POST /api/v1/ingest/flow
"""
from __future__ import annotations

import csv
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


# ---------- Config ----------

CONFIG_DIR = Path("/etc/pleroma-sensor")
CONFIG_FILE = CONFIG_DIR / "config"
KEY_FILE = CONFIG_DIR / "key"
CSV_PATH = Path("/tmp/pleroma-flows.csv")

DEFAULTS: dict[str, str] = {
    "PLEROMA_SERVER": "https://pleroma-aicds.duckdns.org",
    "PLEROMA_INTERFACE": "eth0",
    "PLEROMA_BATCH_SIZE": "50",
    "PLEROMA_BATCH_INTERVAL": "10",  # seconds between flushes regardless of size
    "PLEROMA_VERIFY_TLS": "true",
}


def load_config() -> dict[str, str]:
    cfg: dict[str, str] = dict(DEFAULTS)

    # config file overrides defaults
    if CONFIG_FILE.exists():
        for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")

    # env overrides config file
    for k in list(DEFAULTS):
        if k in os.environ:
            cfg[k] = os.environ[k]

    # API key from dedicated file OR env
    key: str | None = None
    if KEY_FILE.exists():
        key = KEY_FILE.read_text(encoding="utf-8").strip()
    if "PLEROMA_SENSOR_KEY" in os.environ:
        key = os.environ["PLEROMA_SENSOR_KEY"].strip()
    if not key:
        print(
            f"ERROR: no sensor key. Write it to {KEY_FILE} (mode 600) "
            f"or set PLEROMA_SENSOR_KEY in the environment.",
            file=sys.stderr,
        )
        sys.exit(1)
    cfg["PLEROMA_SENSOR_KEY"] = key
    return cfg


# ---------- cicflowmeter subprocess ----------

def _find_cicflowmeter() -> str:
    """Locate the cicflowmeter CLI.

    The agent is normally launched via the venv's Python interpreter
    (sys.executable points to /opt/pleroma-sensor/.venv/bin/python).
    The cicflowmeter CLI installed by pip lives in the same bin dir,
    so check there first — that path is NOT on the subprocess's PATH
    by default since the shim doesn't activate the venv. Fall back to
    a PATH lookup for cases where someone runs the agent with system
    python and a globally-installed cicflowmeter.
    """
    venv_bin = Path(sys.executable).parent
    candidate = venv_bin / "cicflowmeter"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate)
    on_path = shutil.which("cicflowmeter")
    if on_path:
        return on_path
    print(
        "ERROR: 'cicflowmeter' not found next to "
        f"{sys.executable} or on PATH. Install with: "
        "pip install cicflowmeter",
        file=sys.stderr,
    )
    sys.exit(1)


def start_cicflowmeter(interface: str, output_csv: Path) -> subprocess.Popen:
    """Launch cicflowmeter as a subprocess writing rows to output_csv.

    cicflowmeter handles all the Scapy plumbing for live sniffing,
    flow grouping, and feature extraction. We just consume its CSV.
    """
    cic_cmd = _find_cicflowmeter()

    # Wipe any stale CSV so we start clean.
    if output_csv.exists():
        output_csv.unlink()

    # cicflowmeter writes the header on first row. -i = interface, -c = csv file.
    cmd = [cic_cmd, "-i", interface, "-c", str(output_csv)]
    print(f"sensor: starting {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    # Give it a moment to bind to the interface and start producing.
    time.sleep(2)
    if proc.poll() is not None:
        print(
            f"ERROR: cicflowmeter exited immediately (code {proc.returncode}). "
            f"Likely a permission issue — sniffing raw packets needs CAP_NET_RAW or root.",
            file=sys.stderr,
        )
        sys.exit(1)
    return proc


# ---------- CSV tail ----------

def tail_csv(path: Path) -> Iterable[dict]:
    """Yield each new row as a dict, blocking when no new data."""
    while not path.exists():
        time.sleep(0.5)

    with open(path, "r", encoding="utf-8") as f:
        header: list[str] | None = None
        buffer = ""
        while True:
            chunk = f.read()
            if chunk:
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    fields = next(csv.reader(io.StringIO(line)))
                    if header is None:
                        header = fields
                        continue
                    if len(fields) != len(header):
                        # Skip malformed rows defensively.
                        continue
                    yield dict(zip(header, fields))
            else:
                time.sleep(0.5)


# ---------- Ship ----------

def ship_batch(
    server: str, key: str, flows: list[dict], verify_tls: bool
) -> tuple[int, int] | None:
    url = f"{server.rstrip('/')}/api/v1/ingest/flow"
    headers = {"X-Sensor-Key": key, "Content-Type": "application/json"}
    try:
        resp = requests.post(
            url,
            headers=headers,
            json={"flows": flows},
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        print(f"sensor: ingest failed ({exc.__class__.__name__}): {exc}", file=sys.stderr)
        return None

    if resp.status_code != 200:
        print(
            f"sensor: ingest HTTP {resp.status_code}: {resp.text[:200]}",
            file=sys.stderr,
        )
        return None

    try:
        data = resp.json()
        return int(data.get("processed", 0)), int(data.get("logged", 0))
    except (ValueError, KeyError, TypeError) as exc:
        print(f"sensor: bad response from server: {exc}", file=sys.stderr)
        return None


# ---------- Coerce ----------

def coerce_row(row: dict) -> dict:
    """Convert all values to floats where possible, drop non-numeric keys.

    The engine accepts both Title-Case and snake_case keys (it normalizes
    server-side), so we don't need to rename anything here — just clean
    the values.
    """
    out: dict = {}
    for k, v in row.items():
        if v is None or v == "":
            continue
        try:
            out[k] = float(v)
        except (ValueError, TypeError):
            # Skip non-numeric columns like src_ip, timestamp.
            pass
    return out


# ---------- Main loop ----------

def main() -> int:
    cfg = load_config()
    server = cfg["PLEROMA_SERVER"]
    key = cfg["PLEROMA_SENSOR_KEY"]
    interface = cfg["PLEROMA_INTERFACE"]
    batch_size = int(cfg["PLEROMA_BATCH_SIZE"])
    batch_interval = float(cfg["PLEROMA_BATCH_INTERVAL"])
    verify_tls = cfg["PLEROMA_VERIFY_TLS"].lower() not in ("false", "0", "no")

    print(
        f"sensor: target={server} iface={interface} "
        f"batch_size={batch_size} batch_interval={batch_interval}s",
        flush=True,
    )

    cic = start_cicflowmeter(interface, CSV_PATH)

    # SIGTERM / SIGINT: kill cicflowmeter cleanly so it doesn't outlive us.
    def shutdown(_sig: int, _frm) -> None:
        print("sensor: shutting down", flush=True)
        try:
            cic.terminate()
            cic.wait(timeout=5)
        except Exception:
            cic.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    batch: list[dict] = []
    last_flush = time.monotonic()
    sent_total = 0
    logged_total = 0

    try:
        for row in tail_csv(CSV_PATH):
            cleaned = coerce_row(row)
            if cleaned:
                batch.append(cleaned)

            now = time.monotonic()
            should_flush = len(batch) >= batch_size or (
                batch and (now - last_flush) >= batch_interval
            )
            if not should_flush:
                continue

            result = ship_batch(server, key, batch, verify_tls)
            if result is not None:
                processed, logged = result
                sent_total += processed
                logged_total += logged
                print(
                    f"sensor: shipped batch={processed} "
                    f"logged={logged}  total_shipped={sent_total} total_logged={logged_total}",
                    flush=True,
                )
                batch.clear()
                last_flush = now
            else:
                # On failure, keep the batch — but cap it so we don't OOM
                # if the server is down for hours. Drop oldest if over 10×.
                if len(batch) > batch_size * 10:
                    dropped = len(batch) - batch_size * 10
                    batch = batch[-batch_size * 10:]
                    print(
                        f"sensor: server unreachable; dropped {dropped} oldest "
                        f"flows from local buffer",
                        file=sys.stderr,
                    )
                time.sleep(5)  # brief backoff
    finally:
        shutdown(0, None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
