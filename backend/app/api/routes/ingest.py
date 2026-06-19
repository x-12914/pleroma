"""Flow ingestion endpoint for sensor agents.

Accepts a batch of CIC-IDS2018-shaped feature dicts, runs each through
the NetworkEngine, and persists non-Benign flows to DetectionLog with
a 10-minute per-(sensor, src_ip, raw_class) dedup window — without
that, a public-facing VPS being probed by internet-wide scanners
produces hundreds of nearly-identical scan log rows per minute and
the dashboard becomes unreadable. Returns per-flow verdicts so the
sensor can keep its own local log of everything classified.
"""
from __future__ import annotations

import random
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from threading import Lock

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limiter import limiter
from app.db.database import get_db
from app.db.models import Sensor, TrainingSample
from app.schemas.schemas import IngestFlowResult, IngestRequest, IngestResponse
from app.services.analysis_service import network_engine
from app.services.log_service import LogService
from app.utils.dependencies import get_current_sensor

router = APIRouter(prefix="/ingest", tags=["Ingest"])


# ---------- Dedup window ----------
# In-memory only — resets on restart, which is fine. Keyed by the tuple
# (sensor_id, src_ip, raw_class). If we've logged that exact combo in
# the last DEDUP_WINDOW, the next occurrence is suppressed. Anything
# new (different attacker IP, different attack family, or a >10 min
# gap from the same source) produces a fresh row.
DEDUP_WINDOW = timedelta(minutes=10)
_DEDUP_MAX_KEYS = 50_000  # cap so a long-running process can't leak memory

_recent_events: "OrderedDict[tuple, datetime]" = OrderedDict()
_recent_lock = Lock()


def _should_log(sensor_id: int, src_ip: str | None, raw_class: str) -> bool:
    """Return True if this (sensor, src_ip, raw_class) combo should be
    persisted now. False if we logged it less than DEDUP_WINDOW ago."""
    if not src_ip:
        # No IP attached (manual curl test, agent older than dedup
        # support, etc.) — fall back to always-log so we don't silently
        # drop legitimate events.
        return True

    now = datetime.now(timezone.utc)
    key = (sensor_id, src_ip, raw_class)

    with _recent_lock:
        last = _recent_events.get(key)
        if last is not None and (now - last) < DEDUP_WINDOW:
            # Touch order so this entry is "fresh" in the LRU sense.
            _recent_events.move_to_end(key)
            return False

        _recent_events[key] = now
        _recent_events.move_to_end(key)
        while len(_recent_events) > _DEDUP_MAX_KEYS:
            _recent_events.popitem(last=False)
        return True


def _maybe_sample_benign(db: Session, features: dict) -> None:
    """Persist a small random sample of benign flows for retraining.

    Benign is never written to detection_logs, so without this the retrain
    set has no benign coverage. Strips '_'-prefixed keys (src/dst IP) so the
    stored row is a clean feature dict, and opportunistically prunes back to
    BENIGN_SAMPLE_CAP newest rows so the table can't grow unbounded.
    """
    if random.random() >= settings.BENIGN_SAMPLE_RATE:
        return
    clean = {k: v for k, v in features.items() if not k.startswith("_")}
    db.add(TrainingSample(label="Benign", source="benign_auto", features=clean))
    db.commit()
    if random.random() < 0.01:
        stale_ids = [
            r.id for r in db.query(TrainingSample.id)
            .filter(TrainingSample.label == "Benign")
            .order_by(TrainingSample.created_at.desc())
            .offset(settings.BENIGN_SAMPLE_CAP)
            .all()
        ]
        if stale_ids:
            db.query(TrainingSample).filter(
                TrainingSample.id.in_(stale_ids)
            ).delete(synchronize_session=False)
            db.commit()


@router.post("/flow", response_model=IngestResponse)
@limiter.limit("120/minute")
def ingest_flow(
    request: Request,
    payload: IngestRequest,
    sensor: Sensor = Depends(get_current_sensor),
    db: Session = Depends(get_db),
):
    # Heartbeat: update last_seen so the UI can show sensor liveness.
    sensor.last_seen = datetime.now(timezone.utc)
    db.add(sensor)
    db.commit()

    processed = 0
    logged = 0
    results: list[IngestFlowResult] = []

    for features in payload.flows:
        verdict, confidence, raw_class = network_engine.predict(features)
        processed += 1
        results.append(
            IngestFlowResult(
                verdict=verdict,
                confidence=float(confidence),
                raw_class=raw_class,
            )
        )

        # Persist only non-Benign flows. On a real network most flows are
        # benign and writing them all would balloon Postgres for no signal.
        # We do keep a small random sample for retraining benign coverage.
        if raw_class == "Benign":
            _maybe_sample_benign(db, features)
            continue

        # Dedup window: suppress repeat events from the same
        # (sensor, src_ip, raw_class) within the last 10 minutes.
        # A public VPS sees the same bot scanners hammer the same
        # ports continuously; without this every refresh of the
        # dashboard shows fresh-but-identical detections.
        src_ip = features.get("_src_ip")
        if not _should_log(sensor.id, src_ip, raw_class):
            continue

        LogService.create_log(
            db=db,
            user_id=sensor.user_id,
            category="NETWORK_TRAFFIC",
            target=f"sensor:{sensor.name}",
            verdict=verdict,
            score=float(confidence),
            report={
                "raw_class": raw_class,
                "sensor_id": sensor.id,
                "sensor_name": sensor.name,
                "src_ip": src_ip,
                "dst_ip": features.get("_dst_ip"),
                "raw_input": features,
            },
        )
        logged += 1

    return IngestResponse(processed=processed, logged=logged, results=results)
