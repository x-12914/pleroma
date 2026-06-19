from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.core.rate_limiter import limiter
from app.db.database import get_db
from app.db import models
from app.schemas.schemas import (
    URLAnalysisRequest,
    NetworkAnalysisRequest,
    TaskCreated,
    TaskStatus,
)
from app.services.analysis_service import AnalysisService
from app.utils.dependencies import get_current_user, get_current_admin, get_current_analyst
from app.services.network import retrain

router = APIRouter(prefix="/analysis", tags=["Analysis"])

@router.post("/url", response_model=TaskCreated)
@limiter.limit("5/minute")
def analyze_url(
    request: Request,
    payload: URLAnalysisRequest,
    background_tasks: BackgroundTasks,
    # analyst+ — viewers can't initiate scans
    current_user = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    target_url = str(payload.url)
    # 1. Create task in Neon DB (Persistent)
    task_id = AnalysisService.create_task(db, "URL_SCAN", target_url, current_user.id)
    # 2. Schedule background job
    background_tasks.add_task(AnalysisService.schedule_url_analysis, task_id, target_url, current_user.id)
    return {"task_id": task_id, "message": "Processing started"}

@router.post("/network", response_model=TaskCreated)
@limiter.limit("30/minute")
def analyze_network(
    request: Request,
    payload: NetworkAnalysisRequest,
    background_tasks: BackgroundTasks,
    # analyst+ — viewers can't run ad-hoc network analysis
    current_user = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    # 1. Create task in Neon DB (Persistent)
    task_id = AnalysisService.create_task(db, "NETWORK_TRAFFIC", "network_record", current_user.id)
    # 2. Schedule background job
    background_tasks.add_task(AnalysisService.schedule_network_analysis, task_id, payload.record, current_user.id)
    return {"task_id": task_id, "message": "Processing started"}

@router.get("/status/{task_id}", response_model=TaskStatus)
def get_task_status(
    task_id: str, 
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Query Neon for the task status
    task = db.query(models.AnalysisTask).filter(models.AnalysisTask.id == task_id).first()
    
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    
    # Security: Ensure users can only see their own tasks
    if task.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this task")
    
    return {
        "task_id": task.id,
        "status": task.status,
        "result": task.result,
        "created_at": task.created_at
    }

@router.post("/network/retrain")
@limiter.limit("4/hour")
def trigger_retraining(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_admin),  # Only Admins!
):
    """Retrain the network model from captured flows (base CSVs + auto-sampled
    benign + analyst feedback).

    Runs in the background and is safe: the new model is only deployed if it
    passes the data/quality gate, and deployment is atomic with rollback.
    Poll GET /network/retrain/status for the result and metrics.
    """
    background_tasks.add_task(retrain.run_retrain_and_record)
    return {"message": "Retraining started. Poll /api/v1/analysis/network/retrain/status."}


@router.get("/network/retrain/status")
def retrain_status(current_user = Depends(get_current_admin)):
    """Last retrain's status, metrics, and deploy/rollback outcome."""
    return retrain.read_last_result()