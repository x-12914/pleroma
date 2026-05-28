from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.db.database import get_db
from app.services.log_service import LogService
from app.schemas.schemas import LogOut, DashboardStats, FeedbackRequest, FeedbackOut
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

@router.post("/{log_id}/feedback/", response_model=FeedbackOut)
async def create_log_feedback(
    log_id: int,
    feedback_in: FeedbackRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    try:
        feedback = LogService.create_feedback(
            db=db,
            log_id=log_id,
            feedback_data=feedback_in,
            user_id=current_user.id,
        )
        return feedback
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))