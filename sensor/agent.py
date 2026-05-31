#!/usr/bin/env python3
"""Pleroma sensor agent — self-contained Scapy flow tracker.

We tried wrapping the third-party `cicflowmeter` package (v0.3 and v0.4)
but it sniffs packets fine on Python 3.14 and never writes flow rows to
its CSV output. Rather than pin Python or fork the package, this
reimplements the 78 CIC-IDS2018 features directly on top of Scapy.

Flow definition: standard 5-tuple. First packet seen establishes the
"forward" direction; all subsequent packets are forward or backward
relative to that.

Expiration policy:
  - RST flag seen → expire immediately
  - Both sides have FIN'd → expire on next packet / next GC
  - Idle for PLEROMA_FLOW_IDLE_TIMEOUT seconds → GC
  - Active for PLEROMA_FLOW_ACTIVE_TIMEOUT seconds → forced emit
"""
from __future__ import annotations

import os
import signal
import statistics
import sys
import threading
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    from scapy.all import IP, TCP, UDP, sniff
except ImportError:
    print("ERROR: 'scapy' not installed. pip install scapy", file=sys.stderr)
    sys.exit(1)


# ---------- Config ----------

CONFIG_DIR = Path("/etc/pleroma-sensor")
CONFIG_FILE = CONFIG_DIR / "config"
KEY_FILE = CONFIG_DIR / "key"

DEFAULTS: dict[str, str] = {
    "PLEROMA_SERVER": "https://pleroma-aicds.duckdns.org",
    "PLEROMA_INTERFACE": "eth0",
    "PLEROMA_BATCH_SIZE": "50",
    "PLEROMA_BATCH_INTERVAL": "10",
    "PLEROMA_VERIFY_TLS": "true",
    "PLEROMA_FLOW_IDLE_TIMEOUT": "60",     # secs since last packet → GC
    "PLEROMA_FLOW_ACTIVE_TIMEOUT": "120",  # secs since first packet → forced emit
    "PLEROMA_GC_INTERVAL": "5",            # secs between GC sweeps
}


def load_config() -> dict[str, str]:
    cfg: dict[str, str] = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k in list(DEFAULTS):
        if k in os.environ:
            cfg[k] = os.environ[k]
    key: str | None = None
    if KEY_FILE.exists():
        key = KEY_FILE.read_text(encoding="utf-8").strip()
    if "PLEROMA_SENSOR_KEY" in os.environ:
        key = os.environ["PLEROMA_SENSOR_KEY"].strip()
    if not key:
        print(
            f"ERROR: no sensor key in {KEY_FILE} or PLEROMA_SENSOR_KEY env",
            file=sys.stderr,
        )
        sys.exit(1)
    cfg["PLEROMA_SENSOR_KEY"] = key
    return cfg


# ---------- Flow tracker ----------

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80


class Flow:
    """Per-flow state. Records every packet; computes features on demand."""

    __slots__ = (
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "fwd_key", "start_time", "last_time", "last_pkt_time",
        "fwd_packets", "bwd_packets",
        "fwd_psh", "bwd_psh", "fwd_urg", "bwd_urg",
        "fin_cnt", "syn_cnt", "rst_cnt", "psh_cnt",
        "ack_cnt", "urg_cnt", "cwr_cnt", "ece_cnt",
        "init_fwd_win", "init_bwd_win",
        "idle_periods", "fwd_header_min",
        "fwd_fin", "bwd_fin",
    )

    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol, first_pkt_time):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        # The "forward" direction is the first packet's direction; later
        # packets matching this 4-tuple are forward, otherwise backward.
        self.fwd_key = (src_ip, src_port, dst_ip, dst_port)
        self.start_time = first_pkt_time
        self.last_time = first_pkt_time
        self.last_pkt_time = first_pkt_time

        # Per-packet records: (ts, payload_len, header_len, flags_or_None, window)
        self.fwd_packets: list[tuple] = []
        self.bwd_packets: list[tuple] = []

        self.fwd_psh = 0
        self.bwd_psh = 0
        self.fwd_urg = 0
        self.bwd_urg = 0
        self.fin_cnt = 0
        self.syn_cnt = 0
        self.rst_cnt = 0
        self.psh_cnt = 0
        self.ack_cnt = 0
        self.urg_cnt = 0
        self.cwr_cnt = 0
        self.ece_cnt = 0

        self.init_fwd_win = -1
        self.init_bwd_win = -1

        # Idle gaps > 1s
        self.idle_periods: list[float] = []
        self.fwd_header_min: int | None = None

        self.fwd_fin = False
        self.bwd_fin = False

    def add(self, pkt_time, payload_len, header_len, flags, window, is_forward):
        # Idle tracking — gaps > 1s between packets
        gap = pkt_time - self.last_pkt_time
        if gap > 1.0:
            self.idle_periods.append(gap)
        self.last_pkt_time = pkt_time
        self.last_time = pkt_time

        record = (pkt_time, payload_len, header_len, flags, window)
        if is_forward:
            self.fwd_packets.append(record)
            if self.init_fwd_win == -1 and window is not None:
                self.init_fwd_win = window
            if self.fwd_header_min is None or header_len < self.fwd_header_min:
                self.fwd_header_min = header_len
        else:
            self.bwd_packets.append(record)
            if self.init_bwd_win == -1 and window is not None:
                self.init_bwd_win = window

        if flags is not None:
            if flags & FIN:
                self.fin_cnt += 1
                if is_forward:
                    self.fwd_fin = True
                else:
                    self.bwd_fin = True
            if flags & SYN: self.syn_cnt += 1
            if flags & RST: self.rst_cnt += 1
            if flags & PSH:
                self.psh_cnt += 1
                if is_forward:
                    self.fwd_psh += 1
                else:
                    self.bwd_psh += 1
            if flags & ACK: self.ack_cnt += 1
            if flags & URG:
                self.urg_cnt += 1
                if is_forward:
                    self.fwd_urg += 1
                else:
                    self.bwd_urg += 1
            if flags & ECE: self.ece_cnt += 1
            if flags & CWR: self.cwr_cnt += 1

    def is_complete(self) -> bool:
        """Both directions FIN'd, or any RST seen."""
        return self.rst_cnt > 0 or (self.fwd_fin and self.bwd_fin)

    def to_features(self) -> dict:
        def mean(xs): return statistics.mean(xs) if xs else 0.0
        def std(xs):  return statistics.stdev(xs) if len(xs) > 1 else 0.0
        def smax(xs): return max(xs) if xs else 0.0
        def smin(xs): return min(xs) if xs else 0.0
        def svar(xs): return statistics.variance(xs) if len(xs) > 1 else 0.0

        fwd_lens = [p[1] for p in self.fwd_packets]
        bwd_lens = [p[1] for p in self.bwd_packets]
        all_lens = fwd_lens + bwd_lens

        fwd_hdr = [p[2] for p in self.fwd_packets]
        bwd_hdr = [p[2] for p in self.bwd_packets]

        fwd_times = sorted(p[0] for p in self.fwd_packets)
        bwd_times = sorted(p[0] for p in self.bwd_packets)
        all_times = sorted(p[0] for p in self.fwd_packets + self.bwd_packets)

        def iats(times):
            return [t2 - t1 for t1, t2 in zip(times, times[1:])]

        fwd_iat = iats(fwd_times)
        bwd_iat = iats(bwd_times)
        all_iat = iats(all_times)

        flow_dur_us = max((self.last_time - self.start_time) * 1_000_000, 1.0)
        flow_dur_sec = max(self.last_time - self.start_time, 1e-6)

        tot_fwd = len(self.fwd_packets)
        tot_bwd = len(self.bwd_packets)
        totlen_fwd = sum(fwd_lens)
        totlen_bwd = sum(bwd_lens)

        sum_idle = sum(self.idle_periods)
        total_t = self.last_time - self.start_time
        active_dur = max(total_t - sum_idle, 0.0)
        active_list = [active_dur] if active_dur > 0 else []

        return {
            "Dst Port": self.dst_port or 0,
            "Protocol": self.protocol or 0,
            "Flow Duration": flow_dur_us,
            "Tot Fwd Pkts": tot_fwd,
            "Tot Bwd Pkts": tot_bwd,
            "TotLen Fwd Pkts": totlen_fwd,
            "TotLen Bwd Pkts": totlen_bwd,
            "Fwd Pkt Len Max": smax(fwd_lens),
            "Fwd Pkt Len Min": smin(fwd_lens),
            "Fwd Pkt Len Mean": mean(fwd_lens),
            "Fwd Pkt Len Std": std(fwd_lens),
            "Bwd Pkt Len Max": smax(bwd_lens),
            "Bwd Pkt Len Min": smin(bwd_lens),
            "Bwd Pkt Len Mean": mean(bwd_lens),
            "Bwd Pkt Len Std": std(bwd_lens),
            "Flow Byts/s": (totlen_fwd + totlen_bwd) / flow_dur_sec,
            "Flow Pkts/s": (tot_fwd + tot_bwd) / flow_dur_sec,
            "Flow IAT Mean": mean(all_iat) * 1_000_000,
            "Flow IAT Std": std(all_iat) * 1_000_000,
            "Flow IAT Max": smax(all_iat) * 1_000_000,
            "Flow IAT Min": smin(all_iat) * 1_000_000,
            "Fwd IAT Tot": sum(fwd_iat) * 1_000_000,
            "Fwd IAT Mean": mean(fwd_iat) * 1_000_000,
            "Fwd IAT Std": std(fwd_iat) * 1_000_000,
            "Fwd IAT Max": smax(fwd_iat) * 1_000_000,
            "Fwd IAT Min": smin(fwd_iat) * 1_000_000,
            "Bwd IAT Tot": sum(bwd_iat) * 1_000_000,
            "Bwd IAT Mean": mean(bwd_iat) * 1_000_000,
            "Bwd IAT Std": std(bwd_iat) * 1_000_000,
            "Bwd IAT Max": smax(bwd_iat) * 1_000_000,
            "Bwd IAT Min": smin(bwd_iat) * 1_000_000,
            "Fwd PSH Flags": self.fwd_psh,
            "Bwd PSH Flags": self.bwd_psh,
            "Fwd URG Flags": self.fwd_urg,
            "Bwd URG Flags": self.bwd_urg,
            "Fwd Header Len": sum(fwd_hdr),
            "Bwd Header Len": sum(bwd_hdr),
            "Fwd Pkts/s": tot_fwd / flow_dur_sec,
            "Bwd Pkts/s": tot_bwd / flow_dur_sec,
            "Pkt Len Min": smin(all_lens),
            "Pkt Len Max": smax(all_lens),
            "Pkt Len Mean": mean(all_lens),
            "Pkt Len Std": std(all_lens),
            "Pkt Len Var": svar(all_lens),
            "FIN Flag Cnt": self.fin_cnt,
            "SYN Flag Cnt": self.syn_cnt,
            "RST Flag Cnt": self.rst_cnt,
            "PSH Flag Cnt": self.psh_cnt,
            "ACK Flag Cnt": self.ack_cnt,
            "URG Flag Cnt": self.urg_cnt,
            "CWE Flag Count": self.cwr_cnt,  # CIC dataset spells it CWE; same as CWR bit
            "ECE Flag Cnt": self.ece_cnt,
            "Down/Up Ratio": (tot_bwd / tot_fwd) if tot_fwd > 0 else 0,
            "Pkt Size Avg": mean(all_lens),
            "Fwd Seg Size Avg": mean(fwd_lens),
            "Bwd Seg Size Avg": mean(bwd_lens),
            # Bulk transfer features — left at 0; CIC training data also
            # had 0 for these on most non-bulk flows.
            "Fwd Byts/b Avg": 0, "Fwd Pkts/b Avg": 0, "Fwd Blk Rate Avg": 0,
            "Bwd Byts/b Avg": 0, "Bwd Pkts/b Avg": 0, "Bwd Blk Rate Avg": 0,
            # Subflow = total when there's only one subflow (the common case)
            "Subflow Fwd Pkts": tot_fwd, "Subflow Fwd Byts": totlen_fwd,
            "Subflow Bwd Pkts": tot_bwd, "Subflow Bwd Byts": totlen_bwd,
            "Init Fwd Win Byts": self.init_fwd_win,
            "Init Bwd Win Byts": self.init_bwd_win,
            "Fwd Act Data Pkts": sum(1 for p in self.fwd_packets if p[1] > 0),
            "Fwd Seg Size Min": self.fwd_header_min or 0,
            "Active Mean": mean(active_list) * 1_000_000,
            "Active Std": std(active_list) * 1_000_000,
            "Active Max": smax(active_list) * 1_000_000,
            "Active Min": smin(active_list) * 1_000_000,
            "Idle Mean": mean(self.idle_periods) * 1_000_000,
            "Idle Std": std(self.idle_periods) * 1_000_000,
            "Idle Max": smax(self.idle_periods) * 1_000_000,
            "Idle Min": smin(self.idle_periods) * 1_000_000,
        }


class FlowTracker:
    def __init__(self, idle_timeout: float, active_timeout: float):
        self.flows: dict[tuple, Flow] = {}
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.lock = threading.Lock()
        self.completed: list[Flow] = []

    @staticmethod
    def _key(src_ip, src_port, dst_ip, dst_port, proto):
        """Bidirectional key — sorts endpoints so both directions match."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port, proto)
        return (dst_ip, dst_port, src_ip, src_port, proto)

    def on_packet(self, pkt) -> None:
        try:
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            src_ip, dst_ip, proto = ip.src, ip.dst, ip.proto

            if pkt.haslayer(TCP):
                t = pkt[TCP]
                src_port, dst_port = int(t.sport), int(t.dport)
                flags = int(t.flags)
                window = int(t.window)
                header_len = int(t.dataofs) * 4
                payload_len = len(t.payload)
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                src_port, dst_port = int(u.sport), int(u.dport)
                flags, window = None, None
                header_len, payload_len = 8, len(u.payload)
            else:
                return

            pkt_time = float(pkt.time)
            key = self._key(src_ip, src_port, dst_ip, dst_port, proto)

            with self.lock:
                flow = self.flows.get(key)
                if flow is None:
                    flow = Flow(src_ip, src_port, dst_ip, dst_port, proto, pkt_time)
                    self.flows[key] = flow
                is_fwd = (src_ip, src_port, dst_ip, dst_port) == flow.fwd_key
                flow.add(pkt_time, payload_len, header_len, flags, window, is_fwd)
                if flow.is_complete():
                    self.completed.append(flow)
                    del self.flows[key]
        except Exception as exc:
            print(f"sensor: packet error: {exc}", file=sys.stderr, flush=True)

    def gc(self) -> None:
        now = time.time()
        with self.lock:
            for key in list(self.flows.keys()):
                flow = self.flows[key]
                if (now - flow.last_time) > self.idle_timeout or \
                   (flow.last_time - flow.start_time) > self.active_timeout:
                    self.completed.append(flow)
                    del self.flows[key]

    def drain(self) -> list[Flow]:
        with self.lock:
            out, self.completed = self.completed, []
            return out

    def force_flush_all(self) -> list[Flow]:
        """On shutdown, treat every in-flight flow as complete."""
        with self.lock:
            out = self.completed + list(self.flows.values())
            self.completed = []
            self.flows = {}
            return out


# ---------- Ship ----------

def ship_batch(server, key, flows_list, verify_tls):
    url = f"{server.rstrip('/')}/api/v1/ingest/flow"
    headers = {"X-Sensor-Key": key, "Content-Type": "application/json"}
    try:
        r = requests.post(url, headers=headers, json={"flows": flows_list},
                          timeout=15, verify=verify_tls)
    except requests.RequestException as exc:
        print(f"sensor: ship error: {exc}", file=sys.stderr, flush=True)
        return None
    if r.status_code != 200:
        print(f"sensor: ship HTTP {r.status_code}: {r.text[:200]}",
              file=sys.stderr, flush=True)
        return None
    try:
        d = r.json()
        return int(d.get("processed", 0)), int(d.get("logged", 0))
    except Exception:
        return None


# ---------- Main ----------

def main() -> int:
    cfg = load_config()
    print(
        f"sensor: target={cfg['PLEROMA_SERVER']} iface={cfg['PLEROMA_INTERFACE']} "
        f"batch_size={cfg['PLEROMA_BATCH_SIZE']} batch_interval={cfg['PLEROMA_BATCH_INTERVAL']}s "
        f"idle_timeout={cfg['PLEROMA_FLOW_IDLE_TIMEOUT']}s",
        flush=True,
    )

    tracker = FlowTracker(
        idle_timeout=float(cfg["PLEROMA_FLOW_IDLE_TIMEOUT"]),
        active_timeout=float(cfg["PLEROMA_FLOW_ACTIVE_TIMEOUT"]),
    )
    batch_size = int(cfg["PLEROMA_BATCH_SIZE"])
    batch_interval = float(cfg["PLEROMA_BATCH_INTERVAL"])
    verify_tls = cfg["PLEROMA_VERIFY_TLS"].lower() not in ("false", "0", "no")
    gc_interval = float(cfg["PLEROMA_GC_INTERVAL"])

    stop = threading.Event()

    def _shutdown(_sig, _frm):
        print("sensor: shutting down", flush=True)
        stop.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    def background():
        last_flush = time.monotonic()
        last_gc = time.monotonic()
        pending: list[dict] = []
        sent_total = 0
        logged_total = 0

        while not stop.is_set():
            now = time.monotonic()
            if now - last_gc >= gc_interval:
                tracker.gc()
                last_gc = now

            for flow in tracker.drain():
                pending.append(flow.to_features())

            should_flush = len(pending) >= batch_size or (
                pending and now - last_flush >= batch_interval
            )
            if should_flush:
                result = ship_batch(
                    cfg["PLEROMA_SERVER"], cfg["PLEROMA_SENSOR_KEY"],
                    pending, verify_tls,
                )
                if result is not None:
                    p, l = result
                    sent_total += p
                    logged_total += l
                    print(
                        f"sensor: shipped batch={p} logged={l}  "
                        f"total_shipped={sent_total} total_logged={logged_total}",
                        flush=True,
                    )
                    pending = []
                    last_flush = now
                else:
                    if len(pending) > batch_size * 10:
                        pending = pending[-batch_size * 10:]
                    time.sleep(5)
            else:
                time.sleep(0.5)

        # Final flush on shutdown
        for flow in tracker.force_flush_all():
            pending.append(flow.to_features())
        if pending:
            print(f"sensor: final flush of {len(pending)} flows", flush=True)
            ship_batch(
                cfg["PLEROMA_SERVER"], cfg["PLEROMA_SENSOR_KEY"],
                pending, verify_tls,
            )

    bg = threading.Thread(target=background, daemon=True)
    bg.start()

    print(f"sensor: starting Scapy sniff on {cfg['PLEROMA_INTERFACE']}", flush=True)
    try:
        sniff(
            iface=cfg["PLEROMA_INTERFACE"],
            prn=tracker.on_packet,
            store=False,
            stop_filter=lambda _x: stop.is_set(),
        )
    except Exception as exc:
        print(f"sensor: sniff error: {exc}", file=sys.stderr, flush=True)
        stop.set()

    bg.join(timeout=10)
    return 0


if __name__ == "__main__":
    sys.exit(main())
