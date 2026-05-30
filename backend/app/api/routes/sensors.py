"""Sensor management — CRUD endpoints for registered sensor agents.

A sensor is a long-running agent (typically CICFlowMeter wrapper on some
host) that authenticates against /ingest/flow with an API key. Keys are
generated server-side, returned to the user once at creation, and stored
only as SHA-256 hashes — there is no recovery flow.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import Sensor
from app.schemas.schemas import SensorCreate, SensorCreated, SensorOut
from app.utils.dependencies import get_current_user

router = APIRouter(prefix="/sensors", tags=["Sensors"])


@router.post("/", response_model=SensorCreated, status_code=status.HTTP_201_CREATED)
def create_sensor(
    payload: SensorCreate,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Sensor name cannot be empty.")

    # Generate the plaintext key — 32 bytes URL-safe random, prefixed
    # so it's obvious in logs/configs what kind of secret it is.
    plaintext_key = f"pleroma_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()

    sensor = Sensor(
        user_id=current_user.id,
        name=name,
        api_key_hash=key_hash,
    )
    db.add(sensor)
    try:
        db.commit()
        db.refresh(sensor)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"A sensor named '{name}' already exists for this account.",
        )

    return SensorCreated(
        id=sensor.id,
        name=sensor.name,
        created_at=sensor.created_at,
        last_seen=sensor.last_seen,
        api_key=plaintext_key,
    )


@router.get("/", response_model=List[SensorOut])
def list_sensors(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(Sensor)
        .filter(Sensor.user_id == current_user.id)
        .order_by(Sensor.created_at.desc())
        .all()
    )


@router.delete("/{sensor_id}")
def delete_sensor(
    sensor_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sensor = (
        db.query(Sensor)
        .filter(Sensor.id == sensor_id, Sensor.user_id == current_user.id)
        .first()
    )
    if sensor is None:
        raise HTTPException(status_code=404, detail="Sensor not found.")
    name = sensor.name
    db.delete(sensor)
    db.commit()
    return {"deleted": sensor_id, "name": name}
