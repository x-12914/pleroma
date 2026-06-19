from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base
from pgvector.sqlalchemy import Vector # Ensure 'pip install pgvector' is done

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    # Roles, ascending in privilege:
    #   viewer  — read-only on detections + dashboard; can't run scans or manage sensors
    #   analyst — viewer + run URL scans + register/revoke own sensors
    #   admin   — analyst + trigger classifier retraining (only destructive action)
    # is_admin retained for backwards compat; kept in sync via require_role and
    # the role-init migration in database.py.
    role = Column(String, nullable=False, default='viewer', index=True)
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    logs = relationship("DetectionLog", back_populates="owner")
    tasks = relationship("AnalysisTask", back_populates="owner")
    feedback = relationship("Feedback", back_populates="user")
    sensors = relationship("Sensor", back_populates="owner", cascade="all, delete-orphan")

class DetectionLog(Base):
    __tablename__ = "detection_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    category = Column(String, index=True)
    target = Column(String, index=True)
    verdict = Column(String)
    score = Column(Float)
    report_data = Column(JSONB, nullable=True) 
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="logs")
    feedback_entries = relationship("Feedback", back_populates="log")

class AnalysisTask(Base):
    """
    Tracks the lifecycle of an AI analysis job.
    """
    __tablename__ = "analysis_tasks"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    category = Column(String, index=True) 
    target = Column(String)               
    
    # Status: 'pending', 'processing', 'completed', 'failed'
    status = Column(String, default="pending", index=True)
    result = Column(JSONB, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

    owner = relationship("User", back_populates="tasks")

class ThreatMemory(Base):
    """
    Vector storage for RAG (Retrieval-Augmented Generation).
    Stores past threats to give the AI 'long-term memory'.
    """
    __tablename__ = "threat_memory"
    
    id = Column(Integer, primary_key=True)
    content = Column(String) 
    # 384 dimensions is standard for the 'all-MiniLM-L6-v2' embedding model
    embedding = Column(Vector(384)) 
    metadata_info = Column(JSONB) 
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True)
    log_id = Column(Integer, ForeignKey("detection_logs.id"))
    is_correct = Column(Boolean)
    corrected_verdict = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    log = relationship("DetectionLog", back_populates="feedback_entries")
    user = relationship("User", back_populates="feedback")


class Sensor(Base):
    """A registered sensor agent (e.g. CICFlowMeter wrapper on a host).

    Each sensor belongs to one user and has a unique API key (we store
    only the SHA-256 hash; the plaintext key is shown to the user once
    at creation and never recoverable). The /api/v1/ingest/flow endpoint
    authenticates via X-Sensor-Key header.
    """
    __tablename__ = "sensors"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    api_key_hash = Column(String, unique=True, index=True, nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="sensors")

    # Prevent a single user from registering two sensors with the same name.
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_sensor_user_name"),
    )


class TrainingSample(Base):
    """Durably-stored flows for retraining.

    Benign flows are never written to detection_logs (ingest drops them), so
    without this table a retrain has no benign coverage. The ingest endpoint
    persists a small random sample of benign flows here; retrain.py reads them
    back alongside the base capture CSVs and analyst feedback.
    """
    __tablename__ = "training_samples"

    id = Column(Integer, primary_key=True)
    label = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, default="benign_auto")
    features = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)