"""Flow ingestion endpoint for sensor agents.

Accepts a batch of CIC-IDS2018-shaped feature dicts, runs each through
the NetworkEngine, and persists only non-Benign flows to DetectionLog
(otherwise the database fills with normal traffic from any moderately
busy network). Returns per-flow verdicts so the sensor can keep its own
local log of what got flagged.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.rate_limiter import limiter
from app.db.database import get_db
from app.db.models import Sensor
from app.schemas.schemas import IngestFlowResult, IngestRequest, IngestResponse
from app.services.analysis_service import network_engine
from app.services.log_service import LogService
from app.utils.dependencies import get_current_sensor

router = APIRouter(prefix="/ingest", tags=["Ingest"])


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
        if raw_class != "Benign":
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
                    "raw_input": features,
                },
            )
            logged += 1

    return IngestResponse(processed=processed, logged=logged, results=results)
