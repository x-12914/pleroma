from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.db.database import get_db
from app.db.models import DetectionLog
from app.services.log_service import LogService
from app.schemas.schemas import LogOut, DashboardStats, FeedbackRequest, FeedbackOut, ScanSourceOut
from app.utils.dependencies import get_current_user

router = APIRouter(prefix="/logs", tags=["Analysis Logs"])

@router.get("/", response_model=List[LogOut])
def get_my_logs(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return LogService.get_user_logs(db, user_id=current_user.id, limit=limit, offset=offset)

@router.get("/stats", response_model=DashboardStats)
def get_my_stats(current_user = Depends(get_current_user), db: Session = Depends(get_db)):
    return LogService.get_stats(db, user_id=current_user.id)

@router.get("/sources", response_model=List[ScanSourceOut])
def get_scan_sources(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(100, ge=1, le=500),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Network detections grouped by source IP (scan-campaign view), noisiest first."""
    return LogService.get_scan_sources(db, user_id=current_user.id, hours=hours, limit=limit)

@router.post("/{log_id}/feedback/", response_model=FeedbackOut)
async def create_log_feedback(
    log_id: int,
    feedback_in: FeedbackRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    # IDOR guard: only allow feedback on a log the caller owns. Without this
    # any authenticated user could write feedback against another user's logs
    # (and a missing log leaked a 500 with the raw exception text).
    log = db.query(DetectionLog).filter(DetectionLog.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=404, detail="Log not found")
    if log.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized for this log")

    return LogService.create_feedback(
        db=db,
        log_id=log_id,
        feedback_data=feedback_in,
        user_id=current_user.id,
    )