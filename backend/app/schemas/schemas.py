from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional, Any, Dict
from datetime import datetime

# --- AUTH SCHEMAS ---


class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None


# --- DETECTION LOG SCHEMAS ---

class LogBase(BaseModel):
    category: str
    target: str
    verdict: str
    score: float
    report_data: Optional[dict] = None

class LogOut(LogBase):
    id: int
    timestamp: datetime
    user_id: int

    class Config:
        from_attributes = True


# --- ANALYSIS / BACKGROUND TASK MODELS ---

class URLAnalysisRequest(BaseModel):
    url: HttpUrl

class NetworkAnalysisRequest(BaseModel):
    record: Dict[str, Any]

class TaskCreated(BaseModel):
    task_id: str
    message: str

from typing import Optional # Ensure this is imported

class TaskStatus(BaseModel):
    task_id: str
    status: str
    category: Optional[str] = None  # <--- Add Optional and = None
    target: Optional[str] = None    # <--- Add Optional and = None
    result: Optional[dict] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FeedbackRequest(BaseModel):
    is_correct: bool
    corrected_verdict: str


class FeedbackOut(BaseModel):
    id: int
    log_id: int
    is_correct: bool
    corrected_verdict: str
    user_id: int
    timestamp: datetime

    class Config:
        from_attributes = True


# --- DASHBOARD / STATS SCHEMAS ---

class DashboardStats(BaseModel):
    total_scans: int
    threats_detected: int
    clean_scans: int


# --- SENSOR SCHEMAS ---

class SensorCreate(BaseModel):
    name: str

class SensorOut(BaseModel):
    id: int
    name: str
    created_at: datetime
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True

class SensorCreated(SensorOut):
    """Returned only at creation — contains the plaintext API key that
    the user must copy immediately; it can't be retrieved later."""
    api_key: str


# --- INGEST SCHEMAS ---

class IngestRequest(BaseModel):
    """Batch payload from a sensor: a list of CIC feature dicts."""
    flows: list[Dict[str, Any]]

class IngestFlowResult(BaseModel):
    verdict: str
    confidence: float
    raw_class: str

class IngestResponse(BaseModel):
    processed: int
    logged: int   # how many flows produced a DetectionLog (non-Benign)
    results: list[IngestFlowResult]