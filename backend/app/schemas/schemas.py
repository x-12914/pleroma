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


class ScanSourceOut(BaseModel):
    """One row of the 'by source' aggregated view — a scan campaign per IP."""
    src_ip: str
    detections: int
    classes: list[str]
    ports: int
    verdict: str
    first_seen: datetime
    last_seen: datetime


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


# --- AUTONOMOUS RESPONSE SCHEMAS (Phase 2, CONTRACTS.md §5) ---
# Pydantic v2; *Out models read straight off the SQLAlchemy rows via
# from_attributes. Enum validation (mode/action against Mode.ALL/ActionType.ALL)
# is done in the router so error messages match the contract wording.

class StateOut(BaseModel):
    id: int
    mode: str
    kill_switch: bool
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class StateUpdate(BaseModel):
    """Body for PUT /response/state."""
    mode: str
    kill_switch: bool = False


class AllowlistOut(BaseModel):
    id: int
    cidr: str
    reason: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AllowlistCreate(BaseModel):
    cidr: str
    reason: Optional[str] = None


class PolicyRuleOut(BaseModel):
    id: int
    name: str
    enabled: bool
    priority: int
    match_raw_class: Optional[str] = None
    match_verdict: Optional[str] = None
    min_confidence: float
    min_repeats: int
    window_seconds: int
    action: str
    action_params: Optional[dict] = None
    mode_override: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PolicyRuleCreate(BaseModel):
    """Body for POST /response/policy. Defaults mirror the model columns."""
    name: str
    enabled: bool = True
    priority: int = 100
    match_raw_class: Optional[str] = None
    match_verdict: Optional[str] = None
    min_confidence: float = 0.0
    min_repeats: int = 1
    window_seconds: int = 600
    action: str
    action_params: Optional[dict] = None
    mode_override: Optional[str] = None


class PolicyRuleUpdate(BaseModel):
    """Body for PUT /response/policy/{id}. All fields optional — only the
    ones supplied (exclude_unset) are patched."""
    name: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    match_raw_class: Optional[str] = None
    match_verdict: Optional[str] = None
    min_confidence: Optional[float] = None
    min_repeats: Optional[int] = None
    window_seconds: Optional[int] = None
    action: Optional[str] = None
    action_params: Optional[dict] = None
    mode_override: Optional[str] = None


class ResponseActionOut(BaseModel):
    id: int
    ts: Optional[datetime] = None
    src_ip: Optional[str] = None
    action_type: str
    params: Optional[dict] = None
    reason: Optional[str] = None
    raw_class: Optional[str] = None
    confidence: Optional[float] = None
    triggering_log_id: Optional[int] = None
    policy_rule_id: Optional[int] = None
    mode: str
    status: str
    expires_at: Optional[datetime] = None
    created_by: Optional[str] = None
    applied_at: Optional[datetime] = None
    reverted_at: Optional[datetime] = None
    error: Optional[str] = None
    audit: Optional[dict] = None

    class Config:
        from_attributes = True